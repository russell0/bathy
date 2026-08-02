//! [`TaskStore`]: one SQLite database per scan directory, holding scan state
//! and the resumption cursor.
//!
//! # The idempotency contract
//!
//! [`TaskStore::start_or_reuse`] has exactly three cases:
//!
//! | Key       | Plan hash            | Behaviour                          |
//! |-----------|-----------------------|-------------------------------------|
//! | unseen    | --                     | start a new scan                    |
//! | seen      | same as stored         | return the existing task, start nothing |
//! | seen      | different from stored  | refuse with a conflict              |
//!
//! The third case is the one that matters: silently starting a second scan
//! because the plan drifted is how an agent retry loop turns into an
//! unintended flood, and silently returning the old task is equally wrong --
//! the caller asked for different work and would believe it got it.
//!
//! This is enforced by `scans_idempotency`, a `UNIQUE` index on
//! `idempotency_key` in `schema.sql`, not only by the lookup-then-insert
//! logic below. A single `TaskStore`'s [`std::sync::Mutex`] already
//! serializes every call through this method for that one connection, but
//! the index is what keeps the guarantee true even if that were ever
//! bypassed -- e.g. two `TaskStore`s opened against the same database file
//! from independent connections, which is exactly what
//! `two_independent_connections_racing_on_the_same_key_still_yield_exactly_one_scan`
//! below exercises with real threads. When an `INSERT` loses that race, the
//! `UNIQUE` violation is caught and translated back into the same
//! `Reused`/`IdempotencyConflict` vocabulary the non-racing path uses -- see
//! `is_unique_violation` and its call site.
//!
//! # The `foreign_keys` pragma trap
//!
//! `PRAGMA foreign_keys = ON;` is per-*connection* in SQLite, defaults OFF
//! on a stock/system build, and carries no persisted state in the database
//! file (unlike `journal_mode`, which is a property of the file itself once
//! set). A connection that never (re-)issues it will silently ignore `ON
//! DELETE CASCADE` -- the delete succeeds, the child rows just never go
//! away. [`TaskStore::open`] re-runs the *entire* `schema.sql`, pragmas
//! included, on every call, not only when the database file is first
//! created, so this is reasserted on every connection this type ever hands
//! out.
//!
//! T1 (whole-branch review): this crate's actual dependency -- `bundled`
//! `libsqlite3-sys` -- is compiled with `-DSQLITE_DEFAULT_FOREIGN_KEYS=1`,
//! so a brand new connection already reports `foreign_keys = 1` before
//! `schema.sql` ever runs against it (see
//! `this_projects_bundled_sqlite_defaults_foreign_keys_on_correcting_the_dispatchs_stated_fact`).
//! That means every test that only ever opens *fresh* connections through
//! `TaskStore::open` -- which was every test in this cluster before T1 --
//! cannot tell "`schema.sql`'s pragma reasserted this" apart from "the
//! compiled-in default was already on and nothing needed to reassert
//! anything." Concretely: deleting `PRAGMA foreign_keys = ON;` from
//! `schema.sql` left all five of those tests green. The previous version of
//! this doc comment claimed they "prove both halves of that claim
//! concretely rather than assuming them" -- backwards; they proved only the
//! compile flag. `schema_sql_reasserts_foreign_keys_on_even_when_the_connection_had_it_off`
//! is the one test that actually depends on `schema.sql`'s own pragma: it
//! forces a single connection's `foreign_keys` OFF *first*, runs
//! `schema.sql` against that exact connection, and only then checks the
//! pragma -- it can pass only if executing `schema.sql` genuinely flipped
//! it back to ON, independent of whatever a fresh connection's compiled-in
//! default happens to be. `cascade_delete_does_nothing_when_foreign_keys_is_explicitly_off_the_pragma_trap`
//! remains valuable as a demonstration of the underlying mechanism (a
//! cascade delete silently doing nothing with the pragma off), but tests
//! that mechanism in the abstract, not this crate's own reassertion of it.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use rusqlite::{Connection, OptionalExtension, Row, params};

use bathy_types::clock::Clock;
use bathy_types::ids::{Digest, ScanId, ScopeId};
use bathy_types::task::TaskStatus;

const SCHEMA_SQL: &str = include_str!("schema.sql");

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// Smaller item m1 (whole-branch review): the only `#[from]` in this
    /// crate's three error enums, so every `?` on a `rusqlite` call
    /// widens this type's public error surface with whatever
    /// `rusqlite::Error` variant the underlying call happened to produce,
    /// and -- unlike [`Self::Io`] and `bathy-evidence`'s `EvidenceError`/
    /// `LogError` `Io` variants -- with no added path or key context.
    /// Deliberately kept this way rather than wrapped, for two reasons
    /// specific to this crate (not a general claim that `#[from]` is
    /// always fine): (1) a `TaskStore` operates on exactly one
    /// `state.sqlite` file for its whole lifetime, fixed at
    /// [`TaskStore::open`] -- unlike `EvidenceStore`, which touches a
    /// different blob path on every call and where "which path"
    /// genuinely disambiguates one failure from another, there is only
    /// ever one path here, already known to whatever caller is holding
    /// this `TaskStore`; and (2) `rusqlite::Error`'s own `Display`
    /// already carries the SQLite extended error code and, for most
    /// variants, the failing statement or column -- context a bare
    /// `path` field would not add much to. `StoreError::NotFound` and
    /// `IdempotencyConflict` already exist as dedicated variants for the
    /// two cases in this crate where the caller genuinely needs
    /// structured context (which scan, which key) rather than an opaque
    /// error string.
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("store io at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// The third case of the idempotency contract: `key` was already used to
    /// start a scan planned as `existing`, and this call asked for the same
    /// key with a different plan (`incoming`). Refused outright -- see the
    /// module doc comment.
    #[error(
        "idempotency key `{key}` was already used for plan {existing}; \
         this request has plan {incoming}. Use a new key or an identical plan."
    )]
    IdempotencyConflict {
        key: String,
        existing: Digest,
        incoming: Digest,
    },
    #[error("no scan {0}")]
    NotFound(ScanId),
}

/// What `start_or_reuse` needs to either start a new scan or recognize a
/// repeat of one already started.
pub struct StartRequest {
    pub idempotency_key: String,
    pub plan_hash: Digest,
    pub scope_id: ScopeId,
    pub request_json: String,
    pub estimated_targets: u64,
    pub estimated_probes: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

/// A full row from `scans`, as returned by [`TaskStore::get`] and
/// [`TaskStore::list`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskRecord {
    pub scan_id: ScanId,
    pub plan_hash: Digest,
    pub idempotency_key: String,
    pub scope_id: ScopeId,
    pub status: TaskStatus,
    pub request_json: String,
    pub estimated_targets: u64,
    pub estimated_probes: u64,
    pub packets_spent: u64,
    /// Wall-clock runtime, in whole seconds, spent across every run of this
    /// scan so far -- see `record_progress`'s own doc comment.
    pub elapsed_seconds: u64,
    pub last_sequence: u64,
    pub created_at: String,
    pub updated_at: String,
}

/// `TaskStore::list`'s filter. `status: None` returns every scan; the
/// `scans_status` index in `schema.sql` exists to keep a `Some(_)` filter
/// cheap.
#[derive(Debug, Clone, Copy, Default)]
pub struct ListFilter {
    pub status: Option<TaskStatus>,
}

/// The SQLite-backed task store described in the module doc comment.
///
/// `conn` is behind a single [`Mutex`] rather than a connection pool:
/// `start_or_reuse`'s lookup-then-insert must run as one atomic unit for a
/// given store instance, and a `Mutex` held across that whole method is what
/// gives that for free. `Connection` is `Send` but not `Sync` (it wraps a
/// `RefCell`), so this is also what makes `TaskStore` itself safe to share
/// across threads (`Mutex<T>` is `Sync` whenever `T: Send`).
pub struct TaskStore {
    conn: Mutex<Connection>,
    clock: Arc<dyn Clock>,
}

impl TaskStore {
    /// Opens (creating if necessary) `state.sqlite` inside `dir`.
    ///
    /// Always executes the full `schema.sql`, including both pragmas, even
    /// when the database file already exists: the `CREATE TABLE`/`CREATE
    /// INDEX` statements are idempotent via `IF NOT EXISTS`, but
    /// `PRAGMA foreign_keys = ON` is not persisted anywhere and must be
    /// reissued on every connection -- see the module doc comment.
    ///
    /// `clock` is `Arc<dyn Clock>`, not `Box<dyn Clock>` (C2): a `Box` can
    /// only ever be owned by this one `TaskStore`, so a caller that also
    /// needs a `Clock` elsewhere -- most concretely, the SAME scan's
    /// `bathy_evidence::EventLog`, whose `append` takes `&dyn Clock` per
    /// call -- would be forced to construct a second, independent clock.
    /// Two independent `SystemClock`s means two independent instances of
    /// `ulid`'s `Generator` type (no shared monotonicity guarantee across a scan);
    /// two `FixedClock`s built with the same seed produce byte-identical id
    /// sequences, which is exactly what forced this module's own
    /// cross-connection race test to use disjoint seeds as a workaround
    /// (see `two_independent_connections_racing_on_the_same_key_still_yield_exactly_one_scan`
    /// below). `Arc` lets one clock instance be shared: `TaskStore` holds a
    /// clone for its own lifetime, and `&*shared`/`shared.as_ref()` still
    /// gives an `EventLog` caller the `&dyn Clock` it needs from the exact
    /// same instance.
    pub fn open(dir: &Path, clock: Arc<dyn Clock>) -> Result<Self, StoreError> {
        std::fs::create_dir_all(dir).map_err(|source| StoreError::Io {
            path: dir.to_owned(),
            source,
        })?;
        let path = dir.join("state.sqlite");
        let conn = Connection::open(&path).map_err(StoreError::Sqlite)?;
        // Concurrent writers (e.g. two `TaskStore`s against the same file,
        // as in the cross-connection race test below) block for a bounded
        // time on SQLite's write lock instead of failing immediately with
        // `SQLITE_BUSY`.
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        conn.execute_batch(SCHEMA_SQL)?;
        Ok(Self {
            conn: Mutex::new(conn),
            clock,
        })
    }

    /// The idempotency rule, in one place -- see the module doc comment for
    /// the full contract and why the `UNIQUE` index, not this method's own
    /// lookup-then-insert shape, is what actually makes it hold under
    /// concurrent, independently-connected callers.
    pub fn start_or_reuse(&self, req: &StartRequest) -> Result<StartOutcome, StoreError> {
        let conn = self.conn.lock().expect("store mutex poisoned");

        if let Some(outcome) = Self::lookup(&conn, &req.idempotency_key, req.plan_hash)? {
            return Ok(outcome);
        }

        let scan_id = self.clock.new_scan_id();
        let now = self.clock.now_rfc3339();
        let tx = conn.unchecked_transaction()?;
        let inserted = tx.execute(
            "INSERT INTO scans (scan_id, plan_hash, idempotency_key, scope_id, status,
                                request_json, estimated_targets, estimated_probes,
                                created_at, updated_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?9)",
            params![
                scan_id.to_string(),
                req.plan_hash.to_string(),
                req.idempotency_key,
                req.scope_id.to_string(),
                status_to_db(TaskStatus::Pending),
                req.request_json,
                req.estimated_targets,
                req.estimated_probes,
                now,
            ],
        );

        match inserted {
            Ok(_) => {
                tx.commit()?;
                Ok(StartOutcome::Started { scan_id })
            }
            Err(e) if is_unique_violation(&e) => {
                // Another connection's insert of the same idempotency_key
                // won the race between our lookup above and this insert.
                // `tx` never commits and rolls back on drop. The UNIQUE
                // index caught it; translate that DB-level rejection into
                // the same Reused/Conflict vocabulary the non-racing path
                // above uses, rather than surfacing a raw SQLite error for
                // what is, from the caller's point of view, exactly the
                // "key seen" case.
                drop(tx);
                match Self::lookup(&conn, &req.idempotency_key, req.plan_hash)? {
                    Some(outcome) => Ok(outcome),
                    // The row that caused the violation must now be
                    // visible; if it somehow isn't, surface the original
                    // error rather than inventing a result.
                    None => Err(StoreError::Sqlite(e)),
                }
            }
            Err(e) => Err(e.into()),
        }
    }

    /// The three-case idempotency lookup: `Ok(None)` (key unseen), `Ok(Some(Reused))`
    /// (key seen, same plan), or `Err(IdempotencyConflict)` (key seen, different
    /// plan). Shared between the non-racing path in `start_or_reuse` and its
    /// lost-the-race fallback above, so both resolve a "key already exists"
    /// row identically.
    fn lookup(
        conn: &Connection,
        key: &str,
        incoming: Digest,
    ) -> Result<Option<StartOutcome>, StoreError> {
        let existing: Option<(String, String, String)> = conn
            .query_row(
                "SELECT scan_id, plan_hash, status FROM scans WHERE idempotency_key = ?1",
                params![key],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .optional()?;
        let Some((scan_id, plan_hash, status)) = existing else {
            return Ok(None);
        };
        let existing_hash: Digest = plan_hash.parse().expect("stored digest is valid");
        if existing_hash != incoming {
            return Err(StoreError::IdempotencyConflict {
                key: key.to_owned(),
                existing: existing_hash,
                incoming,
            });
        }
        Ok(Some(StartOutcome::Reused {
            scan_id: scan_id.parse().expect("stored id is valid"),
            status: status_from_db(&status),
        }))
    }

    pub fn get(&self, scan_id: ScanId) -> Result<Option<TaskRecord>, StoreError> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        conn.query_row(
            "SELECT scan_id, plan_hash, idempotency_key, scope_id, status, request_json,
                    estimated_targets, estimated_probes, packets_spent, elapsed_seconds,
                    last_sequence, created_at, updated_at
             FROM scans WHERE scan_id = ?1",
            params![scan_id.to_string()],
            row_to_record,
        )
        .optional()
        .map_err(StoreError::from)
    }

    pub fn set_status(&self, scan_id: ScanId, status: TaskStatus) -> Result<(), StoreError> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let now = self.clock.now_rfc3339();
        let changed = conn.execute(
            "UPDATE scans SET status = ?1, updated_at = ?2 WHERE scan_id = ?3",
            params![status_to_db(status), now, scan_id.to_string()],
        )?;
        if changed == 0 {
            return Err(StoreError::NotFound(scan_id));
        }
        Ok(())
    }

    /// C4: the resumption cursor's writer. `scans.last_sequence` and
    /// `scans.packets_spent` are `NOT NULL DEFAULT 0`, are SELECTed by
    /// [`Self::get`]/[`Self::list`], and `log.rs`'s and this crate's own
    /// module docs describe `last_sequence` as the value `scan.resume`
    /// replays from -- but before this method existed, nothing in this
    /// crate ever wrote either column, so they stayed permanently `0` and a
    /// resume would silently replay an entire scan from the start (`0` is
    /// indistinguishable from "a fresh scan legitimately hasn't progressed
    /// yet").
    ///
    /// `elapsed_seconds` (M3 Task 7 fix round 1, CRITICAL-2) joined this
    /// method's signature for the same reason: without it, nothing persists
    /// how much wall-clock runtime a scan has already used across its
    /// previous runs, so a resumed scan's `maximum_runtime_seconds` ceiling
    /// could be defeated by a cancel/resume loop exactly the way
    /// `packets_spent` could before this method existed at all. Read back
    /// via [`Self::get`] and fed into `bathy_scope::budget::BudgetLedger::resumed`.
    ///
    /// Every value is taken as an absolute counter set by the caller (whoever
    /// is driving the scan and reading `EventLog::last_sequence`/tracking
    /// packet spend/elapsed runtime), not incremented here -- this method has
    /// no way to know whether a given call represents new progress or a
    /// resume re-recording state already on disk, so it always writes
    /// exactly what it is given, the same way `set_status` always writes
    /// exactly the status it is given.
    pub fn record_progress(
        &self,
        scan_id: ScanId,
        last_sequence: u64,
        packets_spent: u64,
        elapsed_seconds: u64,
    ) -> Result<(), StoreError> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let now = self.clock.now_rfc3339();
        let changed = conn.execute(
            "UPDATE scans SET last_sequence = ?1, packets_spent = ?2, elapsed_seconds = ?3, \
             updated_at = ?4 WHERE scan_id = ?5",
            params![
                last_sequence,
                packets_spent,
                elapsed_seconds,
                now,
                scan_id.to_string()
            ],
        )?;
        if changed == 0 {
            return Err(StoreError::NotFound(scan_id));
        }
        Ok(())
    }

    pub fn list(&self, filter: &ListFilter) -> Result<Vec<TaskRecord>, StoreError> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        const BASE: &str = "SELECT scan_id, plan_hash, idempotency_key, scope_id, status,
                                    request_json, estimated_targets, estimated_probes,
                                    packets_spent, elapsed_seconds, last_sequence,
                                    created_at, updated_at
                             FROM scans";
        match filter.status {
            Some(status) => {
                let mut stmt =
                    conn.prepare(&format!("{BASE} WHERE status = ?1 ORDER BY created_at"))?;
                let rows = stmt.query_map(params![status_to_db(status)], row_to_record)?;
                rows.collect::<Result<Vec<_>, _>>()
                    .map_err(StoreError::from)
            }
            None => {
                let mut stmt = conn.prepare(&format!("{BASE} ORDER BY created_at"))?;
                let rows = stmt.query_map([], row_to_record)?;
                rows.collect::<Result<Vec<_>, _>>()
                    .map_err(StoreError::from)
            }
        }
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

    pub fn completed_units(&self, scan_id: ScanId) -> Result<Vec<u64>, StoreError> {
        let conn = self.conn.lock().expect("store mutex poisoned");
        let mut stmt = conn.prepare(
            "SELECT unit_index FROM unit_progress WHERE scan_id = ?1 ORDER BY unit_index",
        )?;
        let rows = stmt.query_map(params![scan_id.to_string()], |r| r.get(0))?;
        rows.collect::<Result<Vec<u64>, _>>()
            .map_err(StoreError::from)
    }

    /// Lowest index below `total` that is not yet recorded complete, or
    /// `None` if every index in `0..total` is done. `total = 0` always
    /// yields `None` (there is nothing to do); a completed index at or
    /// beyond `total` is simply irrelevant to this query, since only indices
    /// `< total` are ever considered candidates.
    pub fn next_pending_unit(
        &self,
        scan_id: ScanId,
        total: u64,
    ) -> Result<Option<u64>, StoreError> {
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
}

fn row_to_record(r: &Row<'_>) -> rusqlite::Result<TaskRecord> {
    let scan_id: String = r.get(0)?;
    let plan_hash: String = r.get(1)?;
    let scope_id: String = r.get(3)?;
    let status: String = r.get(4)?;
    Ok(TaskRecord {
        scan_id: scan_id.parse().expect("stored id is valid"),
        plan_hash: plan_hash.parse().expect("stored digest is valid"),
        idempotency_key: r.get(2)?,
        scope_id: scope_id.parse().expect("stored id is valid"),
        status: status_from_db(&status),
        request_json: r.get(5)?,
        estimated_targets: r.get(6)?,
        estimated_probes: r.get(7)?,
        packets_spent: r.get(8)?,
        elapsed_seconds: r.get(9)?,
        last_sequence: r.get(10)?,
        created_at: r.get(11)?,
        updated_at: r.get(12)?,
    })
}

/// `TaskStatus` round-trips through `serde` as a bare snake_case string
/// (`"pending"`, `"running"`, ...), so the `scans.status` column stores
/// exactly that string. Going through `serde_json` for both directions
/// (rather than hand-writing a second copy of the variant list here) is what
/// keeps this in lockstep with `TaskStatus`'s own `#[serde(rename_all =
/// "snake_case")]` -- a hand-written match arm list would silently drift if
/// that ever changed.
fn status_to_db(status: TaskStatus) -> String {
    match serde_json::to_value(status).expect("TaskStatus serializes") {
        serde_json::Value::String(s) => s,
        other => unreachable!("TaskStatus must serialize to a JSON string, got {other:?}"),
    }
}

fn status_from_db(raw: &str) -> TaskStatus {
    serde_json::from_value(serde_json::Value::String(raw.to_owned()))
        .unwrap_or_else(|e| panic!("stored status `{raw}` is not a valid TaskStatus: {e}"))
}

/// Whether `e` is a `UNIQUE` constraint violation specifically -- not just
/// any constraint violation (a `NOT NULL` or `FOREIGN KEY` failure has the
/// same primary `ErrorCode::ConstraintViolation` but a different extended
/// code, and must not be silently reinterpreted as "the idempotency key was
/// already taken").
fn is_unique_violation(e: &rusqlite::Error) -> bool {
    matches!(
        e,
        rusqlite::Error::SqliteFailure(inner, _)
            if inner.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use bathy_types::clock::FixedClock;

    fn clock() -> FixedClock {
        FixedClock::new("2026-08-01T15:04:31.182Z", 7).unwrap()
    }

    fn store() -> (tempfile::TempDir, TaskStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = TaskStore::open(dir.path(), Arc::new(clock())).unwrap();
        (dir, store)
    }

    fn scope_id() -> ScopeId {
        "scope_01ARZ3NDEKTSV4RRFFQ69G5FAV".parse().unwrap()
    }

    fn hash_a() -> Digest {
        Digest::of_bytes(b"plan-a")
    }

    fn hash_b() -> Digest {
        Digest::of_bytes(b"plan-b")
    }

    fn req(key: &str, hash: Digest) -> StartRequest {
        StartRequest {
            idempotency_key: key.to_string(),
            plan_hash: hash,
            scope_id: scope_id(),
            request_json: "{}".to_string(),
            estimated_targets: 10,
            estimated_probes: 100,
        }
    }

    // --- Brief's Step 2 tests, verbatim ---

    #[test]
    fn a_fresh_key_starts_a_new_scan() {
        let (_d, store) = store();
        let out = store.start_or_reuse(&req("key-a", hash_a())).unwrap();
        assert!(matches!(out, StartOutcome::Started { .. }));
    }

    #[test]
    fn the_same_key_with_the_same_plan_returns_the_original_task() {
        let (_d, store) = store();
        let StartOutcome::Started { scan_id } =
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
            let store = TaskStore::open(dir.path(), Arc::new(clock())).unwrap();
            let out = store.start_or_reuse(&req("key-a", hash_a())).unwrap();
            id = out.scan_id();
            store.mark_units_done(id, &[0, 1, 2, 5]).unwrap();
        }
        let store = TaskStore::open(dir.path(), Arc::new(clock())).unwrap();
        let done = store.completed_units(id).unwrap();
        assert_eq!(done, vec![0, 1, 2, 5]);
        assert_eq!(store.next_pending_unit(id, 8).unwrap(), Some(3));
    }

    #[test]
    fn marking_a_unit_done_twice_is_idempotent() {
        let (_d, store) = store();
        let id = store
            .start_or_reuse(&req("key-a", hash_a()))
            .unwrap()
            .scan_id();
        store.mark_units_done(id, &[7]).unwrap();
        store.mark_units_done(id, &[7]).unwrap();
        assert_eq!(store.completed_units(id).unwrap(), vec![7]);
    }

    #[test]
    fn status_transitions_are_persisted() {
        let (_d, store) = store();
        let id = store
            .start_or_reuse(&req("key-a", hash_a()))
            .unwrap()
            .scan_id();
        store.set_status(id, TaskStatus::Running).unwrap();
        store.set_status(id, TaskStatus::Cancelled).unwrap();
        assert_eq!(
            store.get(id).unwrap().unwrap().status,
            TaskStatus::Cancelled
        );
    }

    // --- AC-2.19: the brief's own `status_transitions_are_persisted` above
    // never actually closes and reopens the store -- it only proves a status
    // update is visible via `get` within the same session, which
    // `completed_units_are_recorded_and_survive_reopening` already implies
    // is true of a live connection regardless of persistence. This is the
    // AC's actual claim: status, and the idempotency record itself, survive
    // a real close/reopen, the same way completed units are proven to
    // above. ---

    #[test]
    fn status_survives_closing_and_reopening_the_store() {
        let dir = tempfile::tempdir().unwrap();
        let id;
        {
            let store = TaskStore::open(dir.path(), Arc::new(clock())).unwrap();
            id = store
                .start_or_reuse(&req("key-a", hash_a()))
                .unwrap()
                .scan_id();
            store.set_status(id, TaskStatus::Running).unwrap();
            store.set_status(id, TaskStatus::Cancelled).unwrap();
        }
        let store = TaskStore::open(dir.path(), Arc::new(clock())).unwrap();
        assert_eq!(
            store.get(id).unwrap().unwrap().status,
            TaskStatus::Cancelled,
            "status must survive a real close and reopen, not just remain visible within one session"
        );
    }

    #[test]
    fn idempotency_records_survive_closing_and_reopening_the_store() {
        let dir = tempfile::tempdir().unwrap();
        let id;
        {
            let store = TaskStore::open(dir.path(), Arc::new(clock())).unwrap();
            id = store
                .start_or_reuse(&req("key-a", hash_a()))
                .unwrap()
                .scan_id();
        }
        let store = TaskStore::open(dir.path(), Arc::new(clock())).unwrap();

        let reused = store.start_or_reuse(&req("key-a", hash_a())).unwrap();
        assert!(
            matches!(reused, StartOutcome::Reused { scan_id, .. } if scan_id == id),
            "the same key and plan, after a reopen, must still resolve to the original scan"
        );

        let conflict = store.start_or_reuse(&req("key-a", hash_b()));
        assert!(
            matches!(conflict, Err(StoreError::IdempotencyConflict { .. })),
            "the conflict rule must also still hold after a reopen"
        );
    }

    // --- AC-2.18: next_pending_unit on a sparse set, plus the edge cases
    // beyond the brief's single [0,1,2,5] -> 3 example. ---

    #[test]
    fn next_pending_unit_with_no_completed_units_is_zero() {
        let (_d, store) = store();
        let id = store
            .start_or_reuse(&req("key-a", hash_a()))
            .unwrap()
            .scan_id();
        assert_eq!(store.next_pending_unit(id, 5).unwrap(), Some(0));
    }

    #[test]
    fn next_pending_unit_when_fully_complete_is_none() {
        let (_d, store) = store();
        let id = store
            .start_or_reuse(&req("key-a", hash_a()))
            .unwrap()
            .scan_id();
        store.mark_units_done(id, &[0, 1, 2]).unwrap();
        assert_eq!(store.next_pending_unit(id, 3).unwrap(), None);
    }

    #[test]
    fn next_pending_unit_ignores_a_completed_index_at_or_beyond_total() {
        let (_d, store) = store();
        let id = store
            .start_or_reuse(&req("key-a", hash_a()))
            .unwrap()
            .scan_id();
        // Both indices are >= total = 3, so neither counts toward completion
        // of the first 3 units.
        store.mark_units_done(id, &[3, 5]).unwrap();
        assert_eq!(store.next_pending_unit(id, 3).unwrap(), Some(0));
    }

    #[test]
    fn next_pending_unit_with_zero_total_is_none() {
        let (_d, store) = store();
        let id = store
            .start_or_reuse(&req("key-a", hash_a()))
            .unwrap()
            .scan_id();
        assert_eq!(store.next_pending_unit(id, 0).unwrap(), None);
    }

    // --- AC-2.20: only the plan index is ever persisted, never an expanded
    // target. Proven structurally against the actual on-disk schema, not
    // just asserted in a comment: `unit_progress`'s column set is exactly
    // `(scan_id, unit_index)`. If a future change added a column to "cache"
    // a resolved address for a unit, this test catches it immediately. ---

    #[test]
    fn unit_progress_persists_only_the_index_never_an_expanded_target() {
        let (_d, store) = store();
        let conn = store.conn.lock().unwrap();
        let mut stmt = conn.prepare("PRAGMA table_info(unit_progress)").unwrap();
        let columns: Vec<String> = stmt
            .query_map([], |r| r.get::<_, String>(1))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();
        assert_eq!(
            columns,
            vec!["scan_id".to_string(), "unit_index".to_string()],
            "unit_progress must carry only the resumption cursor (scan_id, unit_index), \
             never a column that could hold an expanded target"
        );
    }

    // --- AC-2.16: the UNIQUE index is load-bearing, not decorative. ---
    //
    // Two halves, both against raw SQL that bypasses `start_or_reuse`'s own
    // application logic entirely:
    // 1. With the real schema, a second `INSERT` reusing an
    //    `idempotency_key` fails with a UNIQUE constraint violation.
    // 2. With the exact same statements run against a schema that has the
    //    `scans_idempotency` index stripped out, the exact same duplicate
    //    insert *succeeds* -- proving (1) isn't passing for some unrelated
    //    reason (a stray PRIMARY KEY collision, a typo'd column, etc.) and
    //    that the index really is what's catching it.

    fn try_insert_raw_scan(
        conn: &Connection,
        scan_id: &str,
        key: &str,
        hash: &str,
    ) -> rusqlite::Result<usize> {
        conn.execute(
            "INSERT INTO scans (scan_id, plan_hash, idempotency_key, scope_id, status,
                                request_json, estimated_targets, estimated_probes,
                                created_at, updated_at)
             VALUES (?1, ?2, ?3, 'scope_x', 'pending', '{}', 0, 0, 't', 't')",
            params![scan_id, hash, key],
        )
    }

    /// `schema.sql` with any statement mentioning `scans_idempotency` (i.e.
    /// the `CREATE UNIQUE INDEX` statement, and only it) removed. Splits on
    /// `;` rather than matching the exact multi-line text of the brief's
    /// schema, so this stays correct even if `schema.sql`'s formatting
    /// changes.
    fn schema_without_unique_index() -> String {
        SCHEMA_SQL
            .split(';')
            .filter(|stmt| !stmt.contains("scans_idempotency"))
            .collect::<Vec<_>>()
            .join(";")
    }

    #[test]
    fn the_unique_index_is_load_bearing_not_decorative() {
        let dir = tempfile::tempdir().unwrap();
        let store = TaskStore::open(dir.path(), Arc::new(clock())).unwrap();
        let conn = store.conn.lock().unwrap();
        try_insert_raw_scan(&conn, "scan_a", "dup-key", &hash_a().to_string()).unwrap();
        let err = try_insert_raw_scan(&conn, "scan_b", "dup-key", &hash_b().to_string())
            .expect_err("a second row reusing an idempotency_key must be rejected by the schema");
        assert!(
            is_unique_violation(&err),
            "expected a UNIQUE constraint violation, got {err}"
        );
        drop(conn);
        drop(store);

        // Mutation check: the identical statements against a database built
        // from a schema with the index stripped out must NOT be rejected.
        let dir2 = tempfile::tempdir().unwrap();
        let conn2 = Connection::open(dir2.path().join("state.sqlite")).unwrap();
        conn2.execute_batch(&schema_without_unique_index()).unwrap();
        try_insert_raw_scan(&conn2, "scan_a", "dup-key", &hash_a().to_string()).unwrap();
        try_insert_raw_scan(&conn2, "scan_b", "dup-key", &hash_b().to_string()).expect(
            "without scans_idempotency, nothing else in the schema stops a duplicate \
             idempotency_key -- if this now fails too, the rejection above was never \
             actually caused by the UNIQUE index",
        );
    }

    // --- Real threads, not reasoning. Two concurrent calls into ONE store
    // (one Mutex<Connection>, so this proves the public API behaves
    // correctly under contention, not that the index alone is doing the
    // work -- that's the cross-connection test further down). ---

    #[test]
    fn concurrent_start_or_reuse_same_key_same_plan_yields_one_started_one_reused() {
        let (_d, store) = store();
        let barrier = std::sync::Barrier::new(2);
        let (r1, r2) = std::thread::scope(|scope| {
            let h1 = scope.spawn(|| {
                barrier.wait();
                store.start_or_reuse(&req("key-a", hash_a()))
            });
            let h2 = scope.spawn(|| {
                barrier.wait();
                store.start_or_reuse(&req("key-a", hash_a()))
            });
            (h1.join().unwrap(), h2.join().unwrap())
        });
        let r1 = r1.unwrap();
        let r2 = r2.unwrap();
        let outcomes = [r1, r2];
        let started = outcomes
            .iter()
            .filter(|o| matches!(o, StartOutcome::Started { .. }))
            .count();
        let reused = outcomes
            .iter()
            .filter(|o| matches!(o, StartOutcome::Reused { .. }))
            .count();
        assert_eq!(started, 1, "outcomes: {outcomes:?}");
        assert_eq!(reused, 1, "outcomes: {outcomes:?}");
        assert_eq!(r1.scan_id(), r2.scan_id());

        let count: i64 = store
            .conn
            .lock()
            .unwrap()
            .query_row("SELECT COUNT(*) FROM scans", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1, "exactly one row, regardless of which thread won");
    }

    #[test]
    fn concurrent_start_or_reuse_same_key_different_plan_yields_at_most_one_started() {
        let (_d, store) = store();
        let barrier = std::sync::Barrier::new(2);
        let (r1, r2) = std::thread::scope(|scope| {
            let h1 = scope.spawn(|| {
                barrier.wait();
                store.start_or_reuse(&req("key-a", hash_a()))
            });
            let h2 = scope.spawn(|| {
                barrier.wait();
                store.start_or_reuse(&req("key-a", hash_b()))
            });
            (h1.join().unwrap(), h2.join().unwrap())
        });
        let outcomes = [r1, r2];
        let started = outcomes
            .iter()
            .filter(|o| matches!(o, Ok(StartOutcome::Started { .. })))
            .count();
        let conflicts = outcomes
            .iter()
            .filter(|o| matches!(o, Err(StoreError::IdempotencyConflict { .. })))
            .count();
        assert!(started <= 1, "outcomes: {outcomes:?}");
        assert_eq!(
            started + conflicts,
            2,
            "every outcome must be either Started or a conflict: {outcomes:?}"
        );
        assert_eq!(conflicts, 1, "outcomes: {outcomes:?}");

        let count: i64 = store
            .conn
            .lock()
            .unwrap()
            .query_row("SELECT COUNT(*) FROM scans", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 1, "never two rows for one idempotency_key");
    }

    // --- The cross-connection version: two independently-opened `TaskStore`s
    // against the SAME database file, so there is no shared Mutex between
    // them at all -- the only thing that can still prevent a duplicate row
    // is the UNIQUE index itself. Looped, with a fresh key each iteration
    // (once a key exists, every later call resolves deterministically via
    // the lookup, which would no longer exercise the INSERT-time race). ---
    //
    // `store_a` and `store_b` are given *different* clock seeds
    // deliberately, not just two `clock()` fixture instances: two
    // `FixedClock`s built with the identical seed and timestamp (this
    // fixture's default) are reproducible BY DESIGN (that is the whole
    // point of `FixedClock`, per `bathy-types`'s own
    // `fixed_clock_is_reproducible` test) -- so with identical seeds, both
    // stores would draw the exact same `ScanId` sequence, and a genuine
    // `idempotency_key` race would then also collide on `scans`'s
    // `scan_id` PRIMARY KEY at the same time, for an unrelated reason. This
    // was caught empirically: an earlier version of this test used
    // `clock()` for both stores and failed intermittently under
    // `cargo test --workspace`'s parallel load with `UNIQUE constraint
    // failed: scans.scan_id` (extended code 1555, PRIMARY KEY -- not 2067,
    // the `idempotency_key` UNIQUE index this test exists to exercise).
    // Distinct seeds make the two stores' `ScanId` sequences disjoint, so
    // the only constraint either connection's `INSERT` can ever violate is
    // `scans_idempotency`.
    #[test]
    fn two_independent_connections_racing_on_the_same_key_still_yield_exactly_one_scan() {
        let dir = tempfile::tempdir().unwrap();
        let store_a = TaskStore::open(
            dir.path(),
            Arc::new(FixedClock::new("2026-08-01T15:04:31.182Z", 7).unwrap()),
        )
        .unwrap();
        let store_b = TaskStore::open(
            dir.path(),
            Arc::new(FixedClock::new("2026-08-01T15:04:31.182Z", 8).unwrap()),
        )
        .unwrap();

        for i in 0..25 {
            let key = format!("race-key-{i}");
            let barrier = std::sync::Barrier::new(2);
            let (ra, rb) = std::thread::scope(|scope| {
                let ha = scope.spawn(|| {
                    barrier.wait();
                    store_a.start_or_reuse(&req(&key, hash_a()))
                });
                let hb = scope.spawn(|| {
                    barrier.wait();
                    store_b.start_or_reuse(&req(&key, hash_a()))
                });
                (ha.join().unwrap(), hb.join().unwrap())
            });
            let ra = ra.unwrap();
            let rb = rb.unwrap();
            assert_eq!(ra.scan_id(), rb.scan_id(), "iteration {i}");
            let started = [ra, rb]
                .iter()
                .filter(|o| matches!(o, StartOutcome::Started { .. }))
                .count();
            assert_eq!(
                started, 1,
                "iteration {i}: exactly one of two independently-connected \
                 stores may win the race"
            );
            let count: i64 = store_a
                .conn
                .lock()
                .unwrap()
                .query_row(
                    "SELECT COUNT(*) FROM scans WHERE idempotency_key = ?1",
                    params![key],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(
                count, 1,
                "iteration {i}: the UNIQUE index, not a shared Mutex \
                 (store_a and store_b share none), is what prevents a \
                 duplicate row here"
            );
        }
    }

    // --- list / set_status: not covered by the brief's own test list at
    // all, despite being part of this task's "Produces" interface. ---

    #[test]
    fn list_with_no_filter_returns_every_scan() {
        let (_d, store) = store();
        store.start_or_reuse(&req("key-a", hash_a())).unwrap();
        store.start_or_reuse(&req("key-b", hash_a())).unwrap();
        assert_eq!(store.list(&ListFilter::default()).unwrap().len(), 2);
    }

    #[test]
    fn list_filters_by_status() {
        let (_d, store) = store();
        let a = store
            .start_or_reuse(&req("key-a", hash_a()))
            .unwrap()
            .scan_id();
        let b = store
            .start_or_reuse(&req("key-b", hash_a()))
            .unwrap()
            .scan_id();
        store.set_status(a, TaskStatus::Running).unwrap();

        let running = store
            .list(&ListFilter {
                status: Some(TaskStatus::Running),
            })
            .unwrap();
        assert_eq!(running.len(), 1);
        assert_eq!(running[0].scan_id, a);

        let pending = store
            .list(&ListFilter {
                status: Some(TaskStatus::Pending),
            })
            .unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].scan_id, b);
    }

    #[test]
    fn set_status_on_an_unknown_scan_is_not_found() {
        let (_d, store) = store();
        let bogus = clock().new_scan_id();
        assert!(matches!(
            store.set_status(bogus, TaskStatus::Running),
            Err(StoreError::NotFound(_))
        ));
    }

    #[test]
    fn get_of_an_unknown_scan_is_none_not_an_error() {
        let (_d, store) = store();
        let bogus = clock().new_scan_id();
        assert!(store.get(bogus).unwrap().is_none());
    }

    // --- C4: `last_sequence`/`packets_spent` have a real writer now. Every
    // test below goes through `record_progress` and `get` only -- the
    // public API a resume path would actually use -- never a raw SQL
    // UPDATE, so these prove the same thing a resuming caller would
    // observe. ---

    #[test]
    fn record_progress_defaults_to_zero_before_it_is_ever_called() {
        let (_d, store) = store();
        let id = store
            .start_or_reuse(&req("key-a", hash_a()))
            .unwrap()
            .scan_id();
        let record = store.get(id).unwrap().unwrap();
        assert_eq!(record.last_sequence, 0);
        assert_eq!(record.packets_spent, 0);
        assert_eq!(record.elapsed_seconds, 0);
    }

    #[test]
    fn record_progress_is_visible_immediately_via_get() {
        let (_d, store) = store();
        let id = store
            .start_or_reuse(&req("key-a", hash_a()))
            .unwrap()
            .scan_id();
        store.record_progress(id, 42, 1_000, 17).unwrap();
        let record = store.get(id).unwrap().unwrap();
        assert_eq!(record.last_sequence, 42);
        assert_eq!(record.packets_spent, 1_000);
        assert_eq!(record.elapsed_seconds, 17);
    }

    #[test]
    fn record_progress_survives_closing_and_reopening_the_store() {
        // AC-shape mirrors `status_survives_closing_and_reopening_the_store`
        // above: the resume path's whole reason to exist is a value that
        // outlives the process that wrote it, so a live-connection check
        // alone would not prove the actual claim.
        let dir = tempfile::tempdir().unwrap();
        let id;
        {
            let store = TaskStore::open(dir.path(), Arc::new(clock())).unwrap();
            id = store
                .start_or_reuse(&req("key-a", hash_a()))
                .unwrap()
                .scan_id();
            store.record_progress(id, 17, 250, 9).unwrap();
        }
        let store = TaskStore::open(dir.path(), Arc::new(clock())).unwrap();
        let record = store.get(id).unwrap().unwrap();
        assert_eq!(
            record.last_sequence, 17,
            "last_sequence must survive a real close and reopen"
        );
        assert_eq!(
            record.packets_spent, 250,
            "packets_spent must survive a real close and reopen"
        );
        assert_eq!(
            record.elapsed_seconds, 9,
            "elapsed_seconds must survive a real close and reopen"
        );
    }

    #[test]
    fn record_progress_overwrites_the_previous_value_not_accumulates() {
        // `record_progress` takes an absolute cursor, not a delta: a caller
        // resuming from `EventLog::last_sequence()` always has the true
        // current value in hand and must be able to write it directly.
        let (_d, store) = store();
        let id = store
            .start_or_reuse(&req("key-a", hash_a()))
            .unwrap()
            .scan_id();
        store.record_progress(id, 5, 50, 2).unwrap();
        store.record_progress(id, 9, 90, 6).unwrap();
        let record = store.get(id).unwrap().unwrap();
        assert_eq!(record.last_sequence, 9);
        assert_eq!(record.packets_spent, 90);
        assert_eq!(
            record.elapsed_seconds, 6,
            "elapsed_seconds is also an absolute write, not accumulated here"
        );
    }

    #[test]
    fn record_progress_resume_path_reads_back_exactly_what_was_written() {
        // The concrete scenario C4 names: a resumed scan reads
        // `last_sequence` back to know where to continue replaying from --
        // and, per CRITICAL-2 (M3 Task 7 fix round 1), `packets_spent` and
        // `elapsed_seconds` back too, to seed `BudgetLedger::resumed`.
        let dir = tempfile::tempdir().unwrap();
        let id;
        {
            let store = TaskStore::open(dir.path(), Arc::new(clock())).unwrap();
            id = store
                .start_or_reuse(&req("key-a", hash_a()))
                .unwrap()
                .scan_id();
            store.record_progress(id, 3, 30, 1).unwrap();
            store.record_progress(id, 8, 80, 4).unwrap();
        }
        // Simulates the resume path: reopen the store as a fresh process
        // would, then read the cursor back before doing anything else.
        let resumed = TaskStore::open(dir.path(), Arc::new(clock())).unwrap();
        let record = resumed.get(id).unwrap().unwrap();
        assert_eq!(
            record.last_sequence, 8,
            "resume must read back the last value actually written, not 0"
        );
        assert_eq!(
            record.packets_spent, 80,
            "resume must read back packets_spent, to seed BudgetLedger::resumed"
        );
        assert_eq!(
            record.elapsed_seconds, 4,
            "resume must read back elapsed_seconds, to seed BudgetLedger::resumed's runtime baseline"
        );
    }

    #[test]
    fn record_progress_on_an_unknown_scan_is_not_found() {
        let (_d, store) = store();
        let bogus = clock().new_scan_id();
        assert!(matches!(
            store.record_progress(bogus, 1, 1, 1),
            Err(StoreError::NotFound(_))
        ));
    }

    // --- Pragma verification: WAL and foreign_keys are actually applied on
    // every connection, not just asserted to be in schema.sql. ---

    #[test]
    fn journal_mode_is_wal() {
        let (_d, store) = store();
        let conn = store.conn.lock().unwrap();
        let mode: String = conn
            .query_row("PRAGMA journal_mode", [], |r| r.get(0))
            .unwrap();
        assert_eq!(mode.to_lowercase(), "wal");
    }

    #[test]
    fn foreign_keys_is_on_on_a_freshly_opened_store() {
        let (_d, store) = store();
        let conn = store.conn.lock().unwrap();
        let fk: i64 = conn
            .query_row("PRAGMA foreign_keys", [], |r| r.get(0))
            .unwrap();
        assert_eq!(fk, 1);
    }

    #[test]
    fn foreign_keys_is_reasserted_on_every_reopen_not_only_the_first_open() {
        let dir = tempfile::tempdir().unwrap();
        {
            let store = TaskStore::open(dir.path(), Arc::new(clock())).unwrap();
            let conn = store.conn.lock().unwrap();
            let fk: i64 = conn
                .query_row("PRAGMA foreign_keys", [], |r| r.get(0))
                .unwrap();
            assert_eq!(
                fk, 1,
                "setup: foreign_keys must be on immediately after the first open"
            );
        }
        // A brand new `Connection` under the hood. Absent `TaskStore::open`
        // re-running `PRAGMA foreign_keys = ON` on every call (not only when
        // the file is first created), this would default back to OFF.
        let store = TaskStore::open(dir.path(), Arc::new(clock())).unwrap();
        let conn = store.conn.lock().unwrap();
        let fk: i64 = conn
            .query_row("PRAGMA foreign_keys", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            fk, 1,
            "foreign_keys must be ON again after reopening, not just on first creation"
        );
    }

    // The dispatch's stated environment fact is "`foreign_keys` is
    // per-connection and defaults OFF." That is true of a stock/system
    // SQLite build, but empirically NOT true of this crate's actual
    // dependency: `libsqlite3-sys`'s `bundled` feature (which the dispatch
    // itself directs this crate to use, "so no system SQLite is required")
    // compiles the vendored `sqlite3.c` with `-DSQLITE_DEFAULT_FOREIGN_KEYS=1`
    // (`libsqlite3-sys-0.38.1/build.rs`, the `cfg.flag(...)` chain in
    // `build_bundled::main`) -- confirmed by the test below, which was
    // originally written to expect `0` per the dispatch and failed with `1`
    // instead. This is a corrected fact about the brief's stated
    // environment, not a defect in this crate: `schema.sql`'s explicit
    // `PRAGMA foreign_keys = ON`, reasserted by `TaskStore::open` on every
    // call, remains the right thing to do regardless -- it is exactly what
    // stops a cascade delete from silently doing nothing the moment this
    // crate ever links a system SQLite instead (dropping the `bundled`
    // feature, or a platform where `pkg-config`/`vcpkg` wins), which
    // reverts to the documented upstream default of OFF. See the task
    // report for the full trace.

    #[test]
    fn this_projects_bundled_sqlite_defaults_foreign_keys_on_correcting_the_dispatchs_stated_fact()
    {
        // A brand new connection to a brand new file -- no schema.sql
        // involved at all -- to isolate the compiled-in default from
        // anything TaskStore::open does.
        let dir = tempfile::tempdir().unwrap();
        let raw = Connection::open(dir.path().join("bare.sqlite")).unwrap();
        let fk: i64 = raw
            .query_row("PRAGMA foreign_keys", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            fk, 1,
            "this crate's bundled SQLite is compiled with \
             SQLITE_DEFAULT_FOREIGN_KEYS=1; a stock/system SQLite build \
             would report 0 here instead"
        );
    }

    #[test]
    fn cascade_delete_does_nothing_when_foreign_keys_is_explicitly_off_the_pragma_trap() {
        // The mechanism itself, proven directly rather than relied upon by
        // way of this build's compiled-in default (which happens to be ON,
        // per the test above): a connection that explicitly turns
        // foreign_keys OFF -- exactly the state a stock/system SQLite build
        // would silently be in on every new connection, absent
        // schema.sql's pragma -- makes ON DELETE CASCADE a no-op.
        let dir = tempfile::tempdir().unwrap();
        let id;
        {
            let store = TaskStore::open(dir.path(), Arc::new(clock())).unwrap();
            id = store
                .start_or_reuse(&req("key-a", hash_a()))
                .unwrap()
                .scan_id();
            store.mark_units_done(id, &[0, 1]).unwrap();
        }
        let raw = Connection::open(dir.path().join("state.sqlite")).unwrap();
        raw.execute_batch("PRAGMA foreign_keys = OFF;").unwrap();
        let fk: i64 = raw
            .query_row("PRAGMA foreign_keys", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            fk, 0,
            "setup: this connection's foreign_keys must genuinely be off"
        );

        raw.execute(
            "DELETE FROM scans WHERE scan_id = ?1",
            params![id.to_string()],
        )
        .unwrap();
        let remaining: i64 = raw
            .query_row(
                "SELECT COUNT(*) FROM unit_progress WHERE scan_id = ?1",
                params![id.to_string()],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            remaining, 2,
            "with foreign_keys off, ON DELETE CASCADE silently does nothing -- \
             exactly the trap TaskStore::open's unconditional pragma reassertion \
             exists to prevent"
        );
    }

    // --- T1: the honest test. Everything above this point that mentions
    // `foreign_keys` opens a fresh connection through `TaskStore::open` (or,
    // for the "bare" test, `Connection::open` with no schema at all) --
    // which this build's bundled SQLite already reports `foreign_keys = 1`
    // for before `schema.sql` ever runs, per
    // `SQLITE_DEFAULT_FOREIGN_KEYS=1`. None of those tests can distinguish
    // "schema.sql's pragma did this" from "it was already this way." This
    // one forces a single connection's `foreign_keys` OFF first, then runs
    // `schema.sql` against that SAME connection, so it can only pass if
    // `schema.sql`'s own `PRAGMA foreign_keys = ON;` genuinely ran and took
    // effect.

    #[test]
    fn schema_sql_reasserts_foreign_keys_on_even_when_the_connection_had_it_off() {
        let dir = tempfile::tempdir().unwrap();
        let conn = Connection::open(dir.path().join("state.sqlite")).unwrap();
        conn.execute_batch("PRAGMA foreign_keys = OFF;").unwrap();
        let fk: i64 = conn
            .query_row("PRAGMA foreign_keys", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            fk, 0,
            "setup: this connection's foreign_keys must genuinely start off, \
             not merely be assumed off"
        );

        conn.execute_batch(SCHEMA_SQL).unwrap();

        let fk: i64 = conn
            .query_row("PRAGMA foreign_keys", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            fk, 1,
            "running schema.sql against a connection that had foreign_keys \
             OFF must turn it back ON -- unlike the tests above, this holds \
             regardless of what a brand new connection's compiled-in \
             default happens to be"
        );
    }

    #[test]
    fn cascade_delete_via_taskstores_own_connection_removes_unit_progress() {
        let (_d, store) = store();
        let id = store
            .start_or_reuse(&req("key-a", hash_a()))
            .unwrap()
            .scan_id();
        store.mark_units_done(id, &[0, 1]).unwrap();
        {
            let conn = store.conn.lock().unwrap();
            let fk: i64 = conn
                .query_row("PRAGMA foreign_keys", [], |r| r.get(0))
                .unwrap();
            assert_eq!(
                fk, 1,
                "setup: TaskStore's own connection must have foreign_keys on"
            );
            conn.execute(
                "DELETE FROM scans WHERE scan_id = ?1",
                params![id.to_string()],
            )
            .unwrap();
        }
        assert_eq!(
            store.completed_units(id).unwrap().len(),
            0,
            "cascade delete must remove unit_progress rows once the parent scan is \
             deleted, given foreign_keys is genuinely on for this connection"
        );
    }
}
