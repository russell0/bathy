# bathy M2 — Evidence Store & Scan State — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give the engine durable, immutable memory — a content-addressed store for raw response bytes, a gap-free append-only event log, and a SQLite task store that makes scans idempotent, cancellable, and resumable.

**Architecture:** Evidence is written before the event that references it, so a dangling `EvidenceRef` is impossible. The event log is the only source of truth for what was observed; SQLite holds only mutable task state and the resumption cursor, and can be rebuilt from the log. Time and identifier generation are injected via a `Clock` trait so every test is deterministic.

**Tech Stack:** rusqlite (bundled), serde_json, ulid, blake3, tempfile, tokio (for the async append path only).

**Read first:** `2026-07-31-bathy-v0.1-overview.md` Global Constraints, and M1 Tasks 2 and 5 for `Digest`, `ScanId`, and `Event`.

---

### Task 1: Injectable clock and identifier source

**Files:**
- Create: `crates/bathy-types/src/clock.rs`
- Create: `crates/bathy-store/Cargo.toml`, `crates/bathy-store/src/lib.rs`

> **Layering note.** `Clock` lives in `bathy-types`, not `bathy-store`. `bathy-evidence` needs it for `EventLog::append` and sits *below* `bathy-store` in the layer order, so putting `Clock` in `bathy-store` would make `xtask check-deps` fail. The trait is pure — no I/O, no internal dependencies — so `bathy-types` is its correct home.

**Interfaces:**
- Consumes: `ScanId`, `EventId` from `bathy-types`.
- Produces: `trait Clock { fn now_rfc3339(&self) -> String; fn new_scan_id(&self) -> ScanId; fn new_event_id(&self) -> EventId; }`, `SystemClock`, `FixedClock::new(&str, seed: u64)`.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_clock_is_reproducible() {
        let a = FixedClock::new("2026-08-01T15:04:31.182Z", 7);
        let b = FixedClock::new("2026-08-01T15:04:31.182Z", 7);
        assert_eq!(a.now_rfc3339(), b.now_rfc3339());
        assert_eq!(a.new_scan_id(), b.new_scan_id());
        assert_eq!(a.new_scan_id(), b.new_scan_id(), "second draw must also match");
    }

    #[test]
    fn fixed_clock_ids_are_distinct_within_a_run() {
        let c = FixedClock::new("2026-08-01T15:04:31.182Z", 7);
        let first = c.new_scan_id();
        let second = c.new_scan_id();
        assert_ne!(first, second);
    }

    #[test]
    fn system_clock_emits_rfc3339_utc_with_milliseconds() {
        let s = SystemClock.now_rfc3339();
        assert!(s.ends_with('Z'), "got {s}");
        assert_eq!(s.len(), 24, "expected YYYY-MM-DDTHH:MM:SS.mmmZ, got {s}");
        assert_eq!(&s[4..5], "-");
        assert_eq!(&s[10..11], "T");
        assert_eq!(&s[19..20], ".");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p bathy-types clock`
Expected: FAIL — `Clock` not found.

- [ ] **Step 3: Write the implementation**

```rust
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use bathy_types::ids::{EventId, ScanId};

/// All time and identifier generation flows through this trait.
///
/// Nothing in the workspace may call `SystemTime::now()` or `Ulid::new()`
/// directly. Injecting them is what makes event logs byte-comparable between
/// a recorded run and a replayed one.
pub trait Clock: Send + Sync {
    fn now_rfc3339(&self) -> String;
    fn new_scan_id(&self) -> ScanId;
    fn new_event_id(&self) -> EventId;
}

/// NOTE: `Ulid::new()` was REMOVED in ulid 3.x. Random generation goes through
/// `ulid::Generator`, whose `generate` is fallible (monotonic overflow within
/// the same millisecond) and takes `&mut self` — hence the mutex. Verify
/// `Generator`'s exact signature against the installed source before writing
/// this; do not copy ulid 1.x examples.
pub struct SystemClock {
    generator: std::sync::Mutex<ulid::Generator>,
}

impl Default for SystemClock {
    fn default() -> Self {
        Self { generator: std::sync::Mutex::new(ulid::Generator::new()) }
    }
}

impl SystemClock {
    fn next_ulid(&self) -> ulid::Ulid {
        let mut g = self.generator.lock().expect("ulid generator poisoned");
        // Monotonic overflow means >2^80 ids in one millisecond, which cannot
        // happen here; fall back rather than panic in a library path.
        g.generate().unwrap_or_else(|_| {
            ulid::Ulid::from_parts(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("clock before epoch")
                    .as_millis() as u64,
                0,
            )
        })
    }
}

impl Clock for SystemClock {
    fn now_rfc3339(&self) -> String {
        let d = SystemTime::now().duration_since(UNIX_EPOCH).expect("clock before epoch");
        format_rfc3339_millis(d.as_secs() as i64, d.subsec_millis())
    }
    fn new_scan_id(&self) -> ScanId {
        ScanId::from_ulid(self.next_ulid())
    }
    fn new_event_id(&self) -> EventId {
        EventId::from_ulid(self.next_ulid())
    }
}

/// Civil-time conversion without a date dependency, using the days-from-civil
/// algorithm. Valid for all years we care about; UTC only, by construction.
fn format_rfc3339_millis(epoch_secs: i64, millis: u32) -> String {
    let days = epoch_secs.div_euclid(86_400);
    let secs_of_day = epoch_secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        y,
        m,
        d,
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60,
        millis
    )
}

/// Deterministic clock for tests and for evidence replay.
pub struct FixedClock {
    now: String,
    counter: AtomicU64,
    seed: u64,
}

impl FixedClock {
    pub fn new(now: &str, seed: u64) -> Self {
        Self { now: now.to_owned(), counter: AtomicU64::new(0), seed }
    }
    fn next_ulid(&self) -> ulid::Ulid {
        let n = self.counter.fetch_add(1, Ordering::SeqCst);
        ulid::Ulid::from_parts(self.seed, n as u128)
    }
}

impl Clock for FixedClock {
    fn now_rfc3339(&self) -> String {
        self.now.clone()
    }
    fn new_scan_id(&self) -> ScanId {
        ScanId::from_ulid(self.next_ulid())
    }
    fn new_event_id(&self) -> EventId {
        EventId::from_ulid(self.next_ulid())
    }
}
```

Note: the "reproducible" test draws IDs from two *separate* `FixedClock` instances, each with its own counter starting at zero — that is why draw 1 matches draw 1 and draw 2 matches draw 2, while draws within one instance differ.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p bathy-types clock` — expected 3 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/bathy-types crates/bathy-store
git commit -m "feat(types): injectable Clock so event logs are reproducible in tests"
```

**Acceptance criteria:**
- **AC-2.1** No source file in the workspace outside `crates/bathy-types/src/clock.rs` calls `SystemTime::now()` or constructs a random ULID (`ulid::Generator`, or `Ulid::new()` should a future version reintroduce it). Enforce with a CI grep covering both `SystemTime::now` and `ulid::Generator`.
- **AC-2.2** Two `FixedClock`s built with identical arguments yield identical timestamp and identifier sequences.
- **AC-2.3** `SystemClock::now_rfc3339` emits exactly `YYYY-MM-DDTHH:MM:SS.mmmZ` (24 characters, UTC).

---

### Task 2: Content-addressed evidence store

**Files:**
- Create: `crates/bathy-evidence/Cargo.toml`, `crates/bathy-evidence/src/lib.rs`, `crates/bathy-evidence/src/store.rs`

**Interfaces:**
- Consumes: `Digest`.
- Produces: `EvidenceStore::open(&Path) -> Result<Self>`, `put(&[u8]) -> Result<Digest>`, `put_capped(&[u8], cap: usize) -> Result<(Digest, bool)>` (bool = truncated), `get(&Digest) -> Result<Vec<u8>>`, `contains(&Digest) -> bool`.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn store() -> (tempfile::TempDir, EvidenceStore) {
        let dir = tempfile::tempdir().unwrap();
        let s = EvidenceStore::open(dir.path()).unwrap();
        (dir, s)
    }

    #[test]
    fn round_trips_bytes_through_a_digest() {
        let (_d, s) = store();
        let digest = s.put(b"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n").unwrap();
        assert_eq!(s.get(&digest).unwrap(), b"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n");
    }

    #[test]
    fn identical_bytes_deduplicate_to_one_object() {
        let (dir, s) = store();
        let a = s.put(b"same").unwrap();
        let b = s.put(b"same").unwrap();
        assert_eq!(a, b);
        let count = walkdir_count_files(dir.path());
        assert_eq!(count, 1, "identical content must not be stored twice");
    }

    #[test]
    fn get_of_an_unknown_digest_is_an_error_not_a_panic() {
        let (_d, s) = store();
        let unknown = bathy_types::ids::Digest::of_bytes(b"never stored");
        assert!(s.get(&unknown).is_err());
    }

    #[test]
    fn capped_put_truncates_and_reports_truncation() {
        let (_d, s) = store();
        let big = vec![b'x'; 100];
        let (digest, truncated) = s.put_capped(&big, 10).unwrap();
        assert!(truncated);
        assert_eq!(s.get(&digest).unwrap().len(), 10);
    }

    #[test]
    fn capped_put_under_the_cap_reports_no_truncation() {
        let (_d, s) = store();
        let (_, truncated) = s.put_capped(b"short", 4096).unwrap();
        assert!(!truncated);
    }

    #[test]
    fn stored_bytes_verify_against_their_digest_on_read() {
        let (dir, s) = store();
        let digest = s.put(b"authentic").unwrap();
        // Corrupt the blob on disk, simulating bit rot or tampering.
        let path = blob_path(dir.path(), &digest);
        std::fs::write(&path, b"tampered").unwrap();
        assert!(s.get(&digest).is_err(), "must detect content that does not match its digest");
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p bathy-evidence store`
Expected: FAIL — `EvidenceStore` not found.

- [ ] **Step 3: Write the implementation**

```rust
use std::fs;
use std::path::{Path, PathBuf};

use bathy_types::ids::Digest;

#[derive(Debug, thiserror::Error)]
pub enum EvidenceError {
    #[error("evidence io at {path}: {source}")]
    Io { path: PathBuf, #[source] source: std::io::Error },
    #[error("no evidence stored for {0}")]
    NotFound(Digest),
    #[error("stored bytes for {digest} do not hash to their digest; store is corrupt")]
    Corrupt { digest: Digest },
}

/// Immutable, content-addressed blob store.
///
/// Evidence is always written *before* the event that references it, so an
/// `evidence_refs` entry can never dangle. Because the key is the hash,
/// writes are idempotent and identical responses across hosts cost one copy.
pub struct EvidenceStore {
    root: PathBuf,
}

pub fn blob_path(root: &Path, digest: &Digest) -> PathBuf {
    let hex = digest.to_string();
    let hex = hex.strip_prefix("blake3:").expect("digest renders with prefix");
    // Two-level fan-out keeps directory sizes manageable on ext4 and APFS.
    root.join("blobs").join(&hex[0..2]).join(&hex[2..4]).join(hex)
}

impl EvidenceStore {
    pub fn open(root: &Path) -> Result<Self, EvidenceError> {
        fs::create_dir_all(root.join("blobs"))
            .map_err(|source| EvidenceError::Io { path: root.to_owned(), source })?;
        Ok(Self { root: root.to_owned() })
    }

    pub fn put(&self, bytes: &[u8]) -> Result<Digest, EvidenceError> {
        let digest = Digest::of_bytes(bytes);
        let path = blob_path(&self.root, &digest);
        if path.exists() {
            return Ok(digest); // content-addressed: already have exactly these bytes
        }
        let parent = path.parent().expect("blob path has a parent");
        fs::create_dir_all(parent)
            .map_err(|source| EvidenceError::Io { path: parent.to_owned(), source })?;
        // Write to a temp name then rename, so a crash never leaves a partial
        // blob visible under a digest that does not describe it.
        let tmp = parent.join(format!(".tmp-{}", std::process::id()));
        fs::write(&tmp, bytes)
            .map_err(|source| EvidenceError::Io { path: tmp.clone(), source })?;
        fs::rename(&tmp, &path)
            .map_err(|source| EvidenceError::Io { path: path.clone(), source })?;
        Ok(digest)
    }

    pub fn put_capped(&self, bytes: &[u8], cap: usize) -> Result<(Digest, bool), EvidenceError> {
        let truncated = bytes.len() > cap;
        let slice = if truncated { &bytes[..cap] } else { bytes };
        Ok((self.put(slice)?, truncated))
    }

    pub fn contains(&self, digest: &Digest) -> bool {
        blob_path(&self.root, digest).exists()
    }

    pub fn get(&self, digest: &Digest) -> Result<Vec<u8>, EvidenceError> {
        let path = blob_path(&self.root, digest);
        let bytes = match fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(EvidenceError::NotFound(*digest));
            }
            Err(source) => return Err(EvidenceError::Io { path, source }),
        };
        // Verify on read. The whole provenance claim rests on this check.
        if Digest::of_bytes(&bytes) != *digest {
            return Err(EvidenceError::Corrupt { digest: *digest });
        }
        Ok(bytes)
    }
}
```

Add a `walkdir_count_files` helper in the test module using `walkdir` as a dev-dependency, counting only files under `blobs/` whose name does not start with `.tmp-`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p bathy-evidence store` — expected 6 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/bathy-evidence
git commit -m "feat(evidence): content-addressed store with read-time digest verification"
```

**Acceptance criteria:**
- **AC-2.4** Storing identical bytes twice yields one digest and exactly one on-disk object.
- **AC-2.5** `get` recomputes the digest of the bytes it read and returns `Corrupt` when they disagree. Tampering with a blob is detected, not served.
- **AC-2.6** `get` of an unstored digest returns `NotFound`, never panics.
- **AC-2.7** `put_capped` truncates at the cap and reports truncation, so `evidence_level: full` cannot be turned into unbounded disk use by a hostile response.
- **AC-2.8** Blob writes are atomic (temp file plus rename); a partial write is never visible under a valid digest.

---

### Task 3: Append-only event log

**Files:**
- Create: `crates/bathy-evidence/src/log.rs`

**Interfaces:**
- Consumes: `Event`, `ScanId`, `EvidenceStore`.
- Produces: `EventLog::open(&Path, ScanId) -> Result<Self>`, `append(&mut self, EventBody, &dyn Clock, engine_version: &str) -> Result<Event>`, `read_from(sequence: u64) -> Result<Vec<Event>>`, `last_sequence() -> u64`.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sequences_start_at_one_and_are_gap_free() {
        let (_d, mut log) = log();
        for expected in 1..=5 {
            let e = log.append(progress(expected), &clock(), "0.1.0").unwrap();
            assert_eq!(e.sequence, expected);
        }
        assert_eq!(log.last_sequence(), 5);
    }

    #[test]
    fn reopening_resumes_the_sequence_rather_than_restarting_it() {
        let dir = tempfile::tempdir().unwrap();
        let id = scan_id();
        {
            let mut log = EventLog::open(dir.path(), id).unwrap();
            log.append(progress(1), &clock(), "0.1.0").unwrap();
            log.append(progress(2), &clock(), "0.1.0").unwrap();
        }
        let mut log = EventLog::open(dir.path(), id).unwrap();
        assert_eq!(log.last_sequence(), 2);
        assert_eq!(log.append(progress(3), &clock(), "0.1.0").unwrap().sequence, 3);
    }

    #[test]
    fn read_from_returns_only_events_after_the_given_sequence() {
        let (_d, mut log) = log();
        for i in 1..=5 {
            log.append(progress(i), &clock(), "0.1.0").unwrap();
        }
        let tail = log.read_from(3).unwrap();
        assert_eq!(tail.len(), 2);
        assert_eq!(tail[0].sequence, 4);
        assert_eq!(tail[1].sequence, 5);
    }

    #[test]
    fn a_truncated_trailing_line_is_reported_not_silently_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let id = scan_id();
        {
            let mut log = EventLog::open(dir.path(), id).unwrap();
            log.append(progress(1), &clock(), "0.1.0").unwrap();
        }
        let path = dir.path().join(format!("{id}.jsonl"));
        let mut raw = std::fs::read(&path).unwrap();
        raw.truncate(raw.len() - 12); // chop the tail mid-record
        std::fs::write(&path, raw).unwrap();
        assert!(EventLog::open(dir.path(), id).is_err());
    }

    #[test]
    fn each_record_is_exactly_one_line() {
        let (dir, mut log) = log();
        log.append(progress(1), &clock(), "0.1.0").unwrap();
        log.append(progress(2), &clock(), "0.1.0").unwrap();
        let raw = std::fs::read_to_string(dir.path().join(format!("{}.jsonl", log.scan_id()))).unwrap();
        assert_eq!(raw.lines().count(), 2);
        assert!(raw.ends_with('\n'));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p bathy-evidence log`
Expected: FAIL — `EventLog` not found.

- [ ] **Step 3: Write the implementation**

```rust
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use bathy_types::clock::Clock;
use bathy_types::event::{Event, EventBody};
use bathy_types::ids::ScanId;

#[derive(Debug, thiserror::Error)]
pub enum LogError {
    #[error("event log io at {path}: {source}")]
    Io { path: PathBuf, #[source] source: std::io::Error },
    #[error("event log {path} line {line} is malformed: {detail}")]
    Malformed { path: PathBuf, line: usize, detail: String },
    #[error("event log {path} has a sequence gap: expected {expected}, found {found}")]
    SequenceGap { path: PathBuf, expected: u64, found: u64 },
}

/// One append-only JSONL file per scan.
///
/// The log is the source of truth. SQLite state is a derived index and can be
/// rebuilt from here; the reverse is not true. Sequences are gap-free because
/// `scan.resume` replays from `last_sequence`, so a gap means lost observations
/// and is treated as corruption rather than tolerated.
pub struct EventLog {
    path: PathBuf,
    scan_id: ScanId,
    file: File,
    last_sequence: u64,
}

impl EventLog {
    pub fn open(dir: &Path, scan_id: ScanId) -> Result<Self, LogError> {
        std::fs::create_dir_all(dir)
            .map_err(|source| LogError::Io { path: dir.to_owned(), source })?;
        let path = dir.join(format!("{scan_id}.jsonl"));
        let last_sequence = Self::scan_existing(&path)?;
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|source| LogError::Io { path: path.clone(), source })?;
        Ok(Self { path, scan_id, file, last_sequence })
    }

    fn scan_existing(path: &Path) -> Result<u64, LogError> {
        if !path.exists() {
            return Ok(0);
        }
        let f = File::open(path)
            .map_err(|source| LogError::Io { path: path.to_owned(), source })?;
        let mut expected = 1u64;
        for (i, line) in BufReader::new(f).lines().enumerate() {
            let line = line.map_err(|source| LogError::Io { path: path.to_owned(), source })?;
            if line.is_empty() {
                continue;
            }
            let event: Event = serde_json::from_str(&line).map_err(|e| LogError::Malformed {
                path: path.to_owned(),
                line: i + 1,
                detail: e.to_string(),
            })?;
            if event.sequence != expected {
                return Err(LogError::SequenceGap {
                    path: path.to_owned(),
                    expected,
                    found: event.sequence,
                });
            }
            expected += 1;
        }
        Ok(expected - 1)
    }

    pub fn scan_id(&self) -> ScanId {
        self.scan_id
    }
    pub fn last_sequence(&self) -> u64 {
        self.last_sequence
    }

    pub fn append(
        &mut self,
        body: EventBody,
        clock: &dyn Clock,
        engine_version: &str,
    ) -> Result<Event, LogError> {
        let event = Event {
            scan_id: self.scan_id,
            sequence: self.last_sequence + 1,
            timestamp: clock.now_rfc3339(),
            engine_version: engine_version.to_owned(),
            body,
        };
        let mut line = serde_json::to_string(&event).expect("event serializes");
        line.push('\n');
        self.file
            .write_all(line.as_bytes())
            .map_err(|source| LogError::Io { path: self.path.clone(), source })?;
        self.file
            .flush()
            .map_err(|source| LogError::Io { path: self.path.clone(), source })?;
        self.last_sequence = event.sequence;
        Ok(event)
    }

    pub fn read_from(&self, after_sequence: u64) -> Result<Vec<Event>, LogError> {
        let f = File::open(&self.path)
            .map_err(|source| LogError::Io { path: self.path.clone(), source })?;
        let mut out = Vec::new();
        for (i, line) in BufReader::new(f).lines().enumerate() {
            let line = line.map_err(|source| LogError::Io { path: self.path.clone(), source })?;
            if line.is_empty() {
                continue;
            }
            let event: Event = serde_json::from_str(&line).map_err(|e| LogError::Malformed {
                path: self.path.clone(),
                line: i + 1,
                detail: e.to_string(),
            })?;
            if event.sequence > after_sequence {
                out.push(event);
            }
        }
        Ok(out)
    }
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p bathy-evidence log` — expected 5 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/bathy-evidence
git commit -m "feat(evidence): gap-free append-only JSONL event log"
```

**Acceptance criteria:**
- **AC-2.9** Sequences begin at 1, increase by exactly 1, and continue correctly across a close and reopen.
- **AC-2.10** A sequence gap in an existing log is an error on open, not a silently accepted state.
- **AC-2.11** A truncated trailing record causes `open` to fail with `Malformed` naming the line number.
- **AC-2.12** `read_from(n)` returns exactly the events with `sequence > n`, in order. This is the primitive `scan.events` streaming is built on.
- **AC-2.13** Each event occupies exactly one line and the file always ends with a newline.

---

### Task 4: SQLite task store with idempotency

**Files:**
- Create: `crates/bathy-store/src/schema.sql`, `crates/bathy-store/src/tasks.rs`

**Interfaces:**
- Consumes: `Clock`, `ScanId`, `Digest`, `TaskStatus`, `Budgets`, `ScopeId`.
- Produces: `TaskStore::open(&Path) -> Result<Self>`, `start_or_reuse(&StartRequest) -> Result<StartOutcome>`, `get(ScanId)`, `set_status(ScanId, TaskStatus)`, `list(filter)`.

- [ ] **Step 1: Write the schema**

`crates/bathy-store/src/schema.sql`:
```sql
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS scans (
    scan_id           TEXT PRIMARY KEY,
    plan_hash         TEXT NOT NULL,
    idempotency_key   TEXT NOT NULL,
    scope_id          TEXT NOT NULL,
    status            TEXT NOT NULL,
    request_json      TEXT NOT NULL,
    estimated_targets INTEGER NOT NULL,
    estimated_probes  INTEGER NOT NULL,
    packets_spent     INTEGER NOT NULL DEFAULT 0,
    last_sequence     INTEGER NOT NULL DEFAULT 0,
    created_at        TEXT NOT NULL,
    updated_at        TEXT NOT NULL
);

-- The idempotency guarantee, enforced by the database rather than by a
-- read-then-write race in application code.
CREATE UNIQUE INDEX IF NOT EXISTS scans_idempotency
    ON scans (idempotency_key);

CREATE INDEX IF NOT EXISTS scans_status ON scans (status);

-- Resumption cursor: which units of the deterministic plan are finished.
-- The plan is regenerated from request_json on resume, so only the index is
-- stored, never the expanded target list.
CREATE TABLE IF NOT EXISTS unit_progress (
    scan_id     TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    unit_index  INTEGER NOT NULL,
    PRIMARY KEY (scan_id, unit_index)
) WITHOUT ROWID;
```

- [ ] **Step 2: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_key_starts_a_new_scan() {
        let (_d, store) = store();
        let out = store.start_or_reuse(&req("key-a", hash_a())).unwrap();
        assert!(matches!(out, StartOutcome::Started { .. }));
    }

    #[test]
    fn the_same_key_with_the_same_plan_returns_the_original_task() {
        let (_d, store) = store();
        let StartOutcome::Started { scan_id, .. } =
            store.start_or_reuse(&req("key-a", hash_a())).unwrap()
        else {
            panic!("expected Started")
        };
        let second = store.start_or_reuse(&req("key-a", hash_a())).unwrap();
        assert!(
            matches!(second, StartOutcome::Reused { scan_id: s, .. } if s == scan_id),
            "a repeated identical call must not launch a second scan"
        );
    }

    #[test]
    fn the_same_key_with_a_different_plan_is_a_conflict() {
        let (_d, store) = store();
        store.start_or_reuse(&req("key-a", hash_a())).unwrap();
        let second = store.start_or_reuse(&req("key-a", hash_b()));
        assert!(
            matches!(second, Err(StoreError::IdempotencyConflict { .. })),
            "reusing a key for a different plan must be refused, not silently accepted"
        );
    }

    #[test]
    fn different_keys_with_the_same_plan_are_two_scans() {
        let (_d, store) = store();
        let a = store.start_or_reuse(&req("key-a", hash_a())).unwrap();
        let b = store.start_or_reuse(&req("key-b", hash_a())).unwrap();
        assert_ne!(a.scan_id(), b.scan_id());
    }

    #[test]
    fn completed_units_are_recorded_and_survive_reopening() {
        let dir = tempfile::tempdir().unwrap();
        let id;
        {
            let store = TaskStore::open(dir.path(), Box::new(clock())).unwrap();
            let out = store.start_or_reuse(&req("key-a", hash_a())).unwrap();
            id = out.scan_id();
            store.mark_units_done(id, &[0, 1, 2, 5]).unwrap();
        }
        let store = TaskStore::open(dir.path(), Box::new(clock())).unwrap();
        let done = store.completed_units(id).unwrap();
        assert_eq!(done, vec![0, 1, 2, 5]);
        assert_eq!(store.next_pending_unit(id, 8).unwrap(), Some(3));
    }

    #[test]
    fn marking_a_unit_done_twice_is_idempotent() {
        let (_d, store) = store();
        let id = store.start_or_reuse(&req("key-a", hash_a())).unwrap().scan_id();
        store.mark_units_done(id, &[7]).unwrap();
        store.mark_units_done(id, &[7]).unwrap();
        assert_eq!(store.completed_units(id).unwrap(), vec![7]);
    }

    #[test]
    fn status_transitions_are_persisted() {
        let (_d, store) = store();
        let id = store.start_or_reuse(&req("key-a", hash_a())).unwrap().scan_id();
        store.set_status(id, TaskStatus::Running).unwrap();
        store.set_status(id, TaskStatus::Cancelled).unwrap();
        assert_eq!(store.get(id).unwrap().unwrap().status, TaskStatus::Cancelled);
    }
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test -p bathy-store tasks`
Expected: FAIL — `TaskStore` not found.

- [ ] **Step 4: Write the implementation**

Key structures and the idempotency rule:

```rust
use std::path::Path;

use rusqlite::{Connection, OptionalExtension, params};
use bathy_types::ids::{Digest, ScanId, ScopeId};
use bathy_types::task::TaskStatus;

use crate::clock::Clock;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error(
        "idempotency key `{key}` was already used for plan {existing}; \
         this request has plan {incoming}. Use a new key or an identical plan."
    )]
    IdempotencyConflict { key: String, existing: Digest, incoming: Digest },
    #[error("no scan {0}")]
    NotFound(ScanId),
}

pub struct StartRequest {
    pub idempotency_key: String,
    pub plan_hash: Digest,
    pub scope_id: ScopeId,
    pub request_json: String,
    pub estimated_targets: u64,
    pub estimated_probes: u64,
}

#[derive(Debug, PartialEq)]
pub enum StartOutcome {
    Started { scan_id: ScanId },
    Reused { scan_id: ScanId, status: TaskStatus },
}

impl StartOutcome {
    pub fn scan_id(&self) -> ScanId {
        match self {
            Self::Started { scan_id } | Self::Reused { scan_id, .. } => *scan_id,
        }
    }
}

impl TaskStore {
    /// The idempotency rule, in one place:
    ///
    /// - key unseen                     → start a new scan
    /// - key seen, same plan_hash       → return the existing task, do not rescan
    /// - key seen, different plan_hash  → refuse with a conflict
    ///
    /// The third case is the important one. Silently starting a second scan
    /// because the plan drifted is how an agent retry loop turns into an
    /// unintended flood.
    pub fn start_or_reuse(&self, req: &StartRequest) -> Result<StartOutcome, StoreError> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let tx = conn.unchecked_transaction()?;
        let existing: Option<(String, String, String)> = tx
            .query_row(
                "SELECT scan_id, plan_hash, status FROM scans WHERE idempotency_key = ?1",
                params![req.idempotency_key],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;

        if let Some((scan_id, plan_hash, status)) = existing {
            let existing_hash: Digest = plan_hash.parse().expect("stored digest is valid");
            if existing_hash != req.plan_hash {
                return Err(StoreError::IdempotencyConflict {
                    key: req.idempotency_key.clone(),
                    existing: existing_hash,
                    incoming: req.plan_hash,
                });
            }
            return Ok(StartOutcome::Reused {
                scan_id: scan_id.parse().expect("stored id is valid"),
                status: serde_json::from_value(serde_json::Value::String(status))
                    .expect("stored status is valid"),
            });
        }

        let scan_id = self.clock.new_scan_id();
        let now = self.clock.now_rfc3339();
        tx.execute(
            "INSERT INTO scans (scan_id, plan_hash, idempotency_key, scope_id, status,
                                request_json, estimated_targets, estimated_probes,
                                created_at, updated_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?9)",
            params![
                scan_id.to_string(),
                req.plan_hash.to_string(),
                req.idempotency_key,
                req.scope_id.to_string(),
                "pending",
                req.request_json,
                req.estimated_targets,
                req.estimated_probes,
                now,
            ],
        )?;
        tx.commit()?;
        Ok(StartOutcome::Started { scan_id })
    }

    /// Lowest index below `total` that is not yet recorded complete.
    /// Resumption regenerates the deterministic plan and skips these.
    pub fn next_pending_unit(&self, scan_id: ScanId, total: u64) -> Result<Option<u64>, StoreError> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut stmt = conn.prepare(
            "SELECT unit_index FROM unit_progress WHERE scan_id = ?1 ORDER BY unit_index",
        )?;
        let done: Vec<u64> = stmt
            .query_map(params![scan_id.to_string()], |r| r.get(0))?
            .collect::<Result<_, _>>()?;
        let mut iter = done.into_iter().peekable();
        for candidate in 0..total {
            match iter.peek() {
                Some(&d) if d == candidate => {
                    iter.next();
                }
                _ => return Ok(Some(candidate)),
            }
        }
        Ok(None)
    }

    pub fn mark_units_done(&self, scan_id: ScanId, units: &[u64]) -> Result<(), StoreError> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let tx = conn.unchecked_transaction()?;
        {
            let mut stmt = tx.prepare(
                "INSERT OR IGNORE INTO unit_progress (scan_id, unit_index) VALUES (?1, ?2)",
            )?;
            for u in units {
                stmt.execute(params![scan_id.to_string(), u])?;
            }
        }
        tx.commit()?;
        Ok(())
    }
}
```

Implement `open` (create dir, open `state.sqlite`, execute `schema.sql` via `execute_batch`), `get`, `set_status`, `completed_units`, and `list` following the same pattern.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p bathy-store tasks` — expected 7 passed.

- [ ] **Step 6: Commit**

```bash
git add crates/bathy-store
git commit -m "feat(store): SQLite task state with database-enforced idempotency and resume cursor"
```

**Acceptance criteria:**
- **AC-2.14** A repeated `start_or_reuse` with the same key and same `plan_hash` returns `Reused` with the original `ScanId` and starts no second scan.
- **AC-2.15** The same key with a *different* `plan_hash` returns `IdempotencyConflict`. It never silently starts a scan and never silently returns the old one.
- **AC-2.16** Idempotency is enforced by a `UNIQUE` index in the schema, not only by application logic.
- **AC-2.17** `mark_units_done` is idempotent; recording the same unit twice leaves one row.
- **AC-2.18** `next_pending_unit` correctly finds the first gap in a sparse completed set (e.g. `[0,1,2,5]` with total 8 → `3`).
- **AC-2.19** Completed units and task status survive closing and reopening the store.
- **AC-2.20** Only the plan *index* is persisted, never the expanded target list — resume regenerates targets from `request_json`.

---

## Milestone Exit Criteria

- [ ] `cargo test --workspace` green; clippy clean.
- [ ] AC-2.1 through AC-2.20 each demonstrated by a named passing test.
- [ ] A CI grep proves no `SystemTime::now()` or `Ulid::new()` outside `crates/bathy-types/src/clock.rs`.
- [ ] `cargo run -p xtask -- check-deps` passes, confirming `bathy-evidence` does not depend on `bathy-store`.
- [ ] An integration test writes evidence, appends an event referencing its digest, closes everything, reopens, and reads both back intact.
- [ ] `bathy-evidence` and `bathy-store` are both usable without `tokio` in a synchronous test.
