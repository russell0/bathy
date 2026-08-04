//! The append-only, per-scan JSONL event log: the source of truth for
//! everything a scan observed.
//!
//! SQLite state (`bathy-store`, a later M2 task) is a derived index and can
//! always be rebuilt by replaying this log from sequence 0; the reverse is
//! not true. Four properties carry that claim:
//!
//! 1. **Sequences are gap-free and monotonic per scan.** `scan.resume`
//!    replays from `last_sequence`, so any deviation from "the next record
//!    is always exactly one more than the last" -- a hole in the middle, a
//!    repeated number, two records swapped out of order -- means an
//!    observation is unaccounted for. All three shapes are treated as the
//!    same corruption ([`LogError::SequenceGap`]) and are hard errors on
//!    [`EventLog::open`], never silently repaired or skipped.
//! 2. **One event per line, always newline-terminated.** A record that
//!    parses as valid JSON but is missing its trailing newline is *still*
//!    rejected on open (see [`EventLog::scan_existing`]): tolerating it
//!    would let a future `append` glue a new record onto the end of that
//!    unterminated line, corrupting a record that was fine on its own. This
//!    is what makes [`EventLog::read_from`] a cheap streaming primitive --
//!    `scan.events` in M5 is built directly on it -- because every line
//!    boundary in the file can be trusted without re-validating it.
//! 3. **Durable by default (C1, whole-branch review).** [`EventLog::append`]
//!    `fsync`s (`sync_data`) every record before returning `Ok`, so a
//!    resumed scan's `last_sequence` can never be ahead of what a real
//!    crash actually left on disk. See
//!    [`EventLog::open_without_durability_barrier`] for the explicit,
//!    named opt-out.
//! 4. **One writer at a time (C5, whole-branch review).** [`EventLog::open`]
//!    takes an exclusive advisory lock on the file, so a second concurrent
//!    opener for the same scan fails cleanly with [`LogError::Locked`]
//!    instead of interleaving appends with the first and silently violating
//!    property 1 above.
//!
//! Property 4 is about *writers*. [`EventLogReader`] is the read-only,
//! lock-free view a second process needs to tail a scan that is still
//! running -- `bathy scan events --follow` is exactly that situation, and
//! through [`EventLog::open`] it would fail with [`LogError::Locked`] every
//! time. See that type's doc comment for what it does and does not tolerate.

use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use bathy_types::clock::Clock;
use bathy_types::event::{Event, EventBody};
use bathy_types::ids::ScanId;

#[derive(Debug, thiserror::Error)]
pub enum LogError {
    #[error("event log io at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("event log {path} line {line} is malformed: {detail}")]
    Malformed {
        path: PathBuf,
        line: usize,
        detail: String,
    },
    /// Covers every way an existing log's sequence numbers can fail to be
    /// exactly `1, 2, 3, ...` with no repeats and no reordering: a hole in
    /// the middle of the file (not just a missing tail), a sequence number
    /// that repeats, or two records whose sequence goes backwards. All three
    /// are the same violation of the same invariant -- "the next record is
    /// always exactly one more than the last" -- so they share one variant
    /// rather than three that a caller would have no different remediation
    /// for. See `a_gap_in_the_middle_of_the_log_is_rejected`,
    /// `a_duplicate_sequence_is_rejected`, and
    /// `an_out_of_order_sequence_is_rejected` below.
    #[error("event log {path} has a sequence gap: expected {expected}, found {found}")]
    SequenceGap {
        path: PathBuf,
        expected: u64,
        found: u64,
    },
    /// C5: another `EventLog` already has `path` open for writing.
    /// `EventLog::open` used to let two concurrent openers both succeed and
    /// both append, which produces interleaved, duplicated sequence numbers
    /// on disk (observed concretely: `["1","1","2"]`) -- and per this
    /// module's own `SequenceGap` handling, that log is then permanently
    /// unopenable and, by design, never repairable. This variant is
    /// returned instead of letting the second opener anywhere near the
    /// file.
    #[error("event log {path} is already open for writing by another process or handle")]
    Locked { path: PathBuf },
    /// [`EventLog::release_writer_lock`] was called and then `append` was
    /// tried anyway. Distinct from [`Self::Locked`], which is about a *second*
    /// opener: this one is about *this* handle, which gave up its claim and
    /// therefore no longer knows that `last_sequence + 1` is still free.
    #[error("event log {path} was released by this writer and cannot be appended to")]
    Released { path: PathBuf },
}

/// One append-only JSONL file per scan.
///
/// The log is the source of truth. SQLite state is a derived index and can
/// be rebuilt from here; the reverse is not true. Sequences are gap-free
/// because `scan.resume` replays from `last_sequence`, so any deviation from
/// strict `+1` continuity means lost or reordered observations and is
/// treated as corruption rather than tolerated. See the module doc comment.
#[derive(Debug)]
pub struct EventLog {
    path: PathBuf,
    scan_id: ScanId,
    file: File,
    last_sequence: u64,
    /// `offsets[i]` is the byte offset in the file where the record for
    /// sequence `i + 1` begins. Built once from the single validating scan
    /// `open` already has to do, and extended in `append`. This is what lets
    /// `read_from` seek straight to the first requested record instead of
    /// re-reading and re-parsing everything before it -- see `read_from`'s
    /// own doc comment for why that matters.
    offsets: Vec<u64>,
    /// Current on-disk length of `path`. Tracked here (rather than queried
    /// via `self.file.metadata()` on every `append`) because it is already
    /// known for free from the scan `open` performs, and updating a local
    /// counter after each write is cheaper and does not depend on the
    /// append-mode file descriptor's internal seek position, which is not
    /// guaranteed to reflect end-of-file until at least one write has
    /// happened through it.
    end_offset: u64,
    /// C1: whether `append` pays for an `fsync` after every write. See
    /// [`Self::open`] vs [`Self::open_without_durability_barrier`].
    durable: bool,
    /// Count of real `sync_data()` syscalls this handle has issued, across
    /// both `append`'s own per-record barrier (when `durable`) and any
    /// explicit [`Self::sync`] call. M3 Task 7 fix round 1, IMPORTANT-1: a
    /// caller batching barriers on top of this type
    /// (`bathy_engine::durable_log::GroupCommitLog`) needs a way to prove,
    /// in a test, that real syscalls were actually batched -- its own
    /// internal "how many events are pending" counter cannot: if that
    /// caller were accidentally handed a `durable` `EventLog` (this crate's
    /// own per-event barrier still firing on every `append`, independent of
    /// whatever batching decision the wrapper makes on top), the wrapper's
    /// internal counter would look identical either way. This field is the
    /// ground truth a test can check instead.
    sync_calls: std::sync::atomic::AtomicU64,
    /// Set by [`Self::release_writer_lock`]. Once set, this handle has given
    /// up the exclusive claim it took in `open` and another opener may
    /// already hold it, so [`Self::append`] must refuse rather than write
    /// into a file a second writer is now numbering records in. Reads
    /// ([`Self::read_from`], [`Self::last_sequence`]) stay available: they
    /// never needed the lock in the first place -- `EventLogReader` takes
    /// none.
    released: bool,
}

impl EventLog {
    /// The default, durable constructor: every [`Self::append`] calls
    /// `File::sync_data` before returning, so once `append` returns `Ok`
    /// the record is actually durable on disk, not merely handed to the
    /// OS's page cache (`File::flush`, what this used to call, is a no-op
    /// for `std::fs::File` -- there is no userspace buffer for it to flush).
    /// See [`Self::open_without_durability_barrier`] for the explicit
    /// opt-out.
    ///
    /// Also acquires an exclusive advisory lock on the log file (C5): a
    /// second concurrent `open` for the same `scan_id`, whether from
    /// another thread, another `EventLog` in this process, or a wholly
    /// separate process, fails with [`LogError::Locked`] instead of being
    /// allowed to interleave appends with this handle's. The lock is
    /// acquired here, before [`Self::scan_existing`] reads any existing
    /// content, specifically so no opener's view of `last_sequence` can go
    /// stale between validating the file and appending to it -- acquiring
    /// it any later would leave exactly that window open. It is released
    /// by the OS when this `EventLog`'s underlying file handle is closed,
    /// including on an abnormal process exit (see
    /// `writer_lock_is_released_when_the_holder_is_killed_not_just_dropped`
    /// in `tests/`), not only on an orderly `Drop`.
    pub fn open(dir: &Path, scan_id: ScanId) -> Result<Self, LogError> {
        Self::open_with_durability(dir, scan_id, true)
    }

    /// C1's explicit, named opt-out: skips the `sync_data` call on every
    /// `append`, trading the durability guarantee for throughput on a
    /// high-rate scan (see the fix wave report for measured numbers). The
    /// writer-exclusion lock from [`Self::open`] still applies unconditionally
    /// -- that is a correctness property, not a durability/throughput
    /// tradeoff, so there is no way to opt out of it.
    pub fn open_without_durability_barrier(dir: &Path, scan_id: ScanId) -> Result<Self, LogError> {
        Self::open_with_durability(dir, scan_id, false)
    }

    fn open_with_durability(dir: &Path, scan_id: ScanId, durable: bool) -> Result<Self, LogError> {
        std::fs::create_dir_all(dir).map_err(|source| LogError::Io {
            path: dir.to_owned(),
            source,
        })?;
        let path = dir.join(format!("{scan_id}.jsonl"));
        // `create(true).append(true)`, never `.truncate(true)`: opening an
        // existing log for more appends must never rewrite or shorten what
        // is already on disk.
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|source| LogError::Io {
                path: path.clone(),
                source,
            })?;
        // C5: lock BEFORE `scan_existing` reads the file, not after. If the
        // lock were acquired later, two openers could both validate the
        // same on-disk state, then both proceed to append -- the exact
        // interleaving this lock exists to prevent. Non-blocking
        // (`try_lock`, not `lock`): a second opener must fail fast with
        // `Locked`, not hang waiting for the first to finish an entire scan.
        //
        // Called via UFCS (`fs4::FileExt::try_lock`, not `file.try_lock()`)
        // deliberately: `std::fs::File` gained its own inherent
        // `try_lock`/`TryLockError` in Rust 1.89, and on any toolchain at or
        // above that, plain method-call syntax would silently resolve to
        // std's method (shadowing the trait method) instead of `fs4`'s --
        // which behave equivalently at runtime, but return a *different*
        // `TryLockError` type than the `fs4::TryLockError` matched below,
        // and this crate's MSRV floor (1.88) is below 1.89, so relying on
        // std's version at all here would not even compile there.
        fs4::FileExt::try_lock(&file).map_err(|e| match e {
            fs4::TryLockError::WouldBlock => LogError::Locked { path: path.clone() },
            fs4::TryLockError::Error(source) => LogError::Io {
                path: path.clone(),
                source,
            },
        })?;
        let (last_sequence, offsets, end_offset) = Self::scan_existing(&path)?;
        Ok(Self {
            path,
            scan_id,
            file,
            last_sequence,
            offsets,
            end_offset,
            durable,
            sync_calls: std::sync::atomic::AtomicU64::new(0),
            released: false,
        })
    }

    /// Gives up the exclusive writer lock `open` took, without closing the
    /// file or dropping this handle.
    ///
    /// This exists because "the lock is released when the handle is dropped"
    /// is not a schedulable event: a caller that has finished writing cannot
    /// say *when* the drop happens relative to anything else it does. M5 Task
    /// 4's fix review found the consequence -- a scheduler published
    /// `cancelled` to the task store while its own log handle was still
    /// alive several statements (and, detached, a whole `eprintln!` to a
    /// pipe) away from being dropped, so an agent that polled for `cancelled`
    /// and immediately resumed raced the release and was told
    /// `log_unavailable`. An explicit release is orderable; a drop is not.
    ///
    /// After this returns, [`Self::append`] refuses with
    /// [`LogError::Released`] -- the handle is no longer entitled to number
    /// records, because someone else may now be doing so. Idempotent.
    pub fn release_writer_lock(&mut self) -> Result<(), LogError> {
        if self.released {
            return Ok(());
        }
        // UFCS for the reason `open` uses it -- see the comment there.
        fs4::FileExt::unlock(&self.file).map_err(|source| LogError::Io {
            path: self.path.clone(),
            source,
        })?;
        self.released = true;
        Ok(())
    }

    /// Validates an existing log file (if any) in one pass and returns
    /// `(last_sequence, offsets, end_offset)`:
    ///
    /// - `last_sequence`: the highest sequence number present, or `0` for a
    ///   missing or empty file.
    /// - `offsets`: `offsets[i]` is the byte offset where sequence `i + 1`'s
    ///   record starts, used by `read_from` to seek directly to a tail.
    /// - `end_offset`: the file's total byte length, so `append` knows where
    ///   the next record will land without an extra syscall.
    ///
    /// Two things make an existing file corrupt, both hard errors:
    ///
    /// - The file has content but does not end with `\n`. This is checked
    ///   for whichever line turns out to be the last one, deliberately: a
    ///   trailing record that happens to be syntactically valid JSON but was
    ///   never terminated is still rejected, because leaving it
    ///   un-terminated would let the next `append` glue a new record onto
    ///   its line. A missing-newline tail and a mid-record truncation (the
    ///   brief's own test) are the same failure by the time they reach this
    ///   check -- the last line does not end in `\n` -- and are reported the
    ///   same way. A *blank* trailing line (the file ends in `\n\n`) is the
    ///   opposite case and is tolerated: every real record before it is
    ///   already complete and terminated, so there is nothing to lose by
    ///   skipping it -- and this holds for a blank line anywhere in the
    ///   file, not only at the end.
    /// - Any two consecutive (non-blank) records' sequence numbers are not
    ///   exactly `expected, expected + 1`. This one check, applied uniformly
    ///   line by line, is what catches a gap in the middle of the file, a
    ///   duplicated sequence, and an out-of-order sequence alike -- see
    ///   `LogError::SequenceGap`'s doc comment.
    ///
    /// Smaller item D (whole-branch review): streams the file through a
    /// `BufReader` one line at a time, tracking `pos` as a running byte
    /// offset, rather than reading the whole file into a `Vec<u8>` up
    /// front. The plan explicitly forbids the whole-file-read shape this
    /// used to have: at the project's stated 1M-event ceiling this file can
    /// reach roughly 240-330 MiB, and `scan_existing` runs on the **resume**
    /// path -- i.e. right after a crash, exactly when memory is already
    /// under the most pressure. `BufRead::read_until` (not `read_line`) is
    /// used specifically so a line's raw bytes are validated as UTF-8 by
    /// this function itself (see the `from_utf8` call below) and reported
    /// as `LogError::Malformed`, matching this function's previous
    /// behavior, rather than surfacing as a generic `io::Error` the way
    /// `read_line`'s own built-in UTF-8 check would.
    fn scan_existing(path: &Path) -> Result<(u64, Vec<u64>, u64), LogError> {
        scan_records(path, TailPolicy::RejectPartial)
    }

    pub fn scan_id(&self) -> ScanId {
        self.scan_id
    }
}

/// What [`scan_records`] does with a final line that has no terminating
/// newline.
///
/// The two answers are both correct, for different callers, and the
/// difference is not a stylistic one:
///
/// - [`TailPolicy::RejectPartial`] is [`EventLog`]'s. A writer that accepted
///   an unterminated tail would glue its next record onto that line and
///   corrupt a record that was fine on its own (this module's property 2).
/// - [`TailPolicy::SkipPartial`] is [`EventLogReader`]'s. A reader holds no
///   lock and is expected to run *while* a writer is appending, so an
///   unterminated tail is the ordinary sight of a record mid-write, not
///   corruption. Skipping it yields the records that are complete; the next
///   poll picks the rest up. Rejecting it would make `scan events --follow`
///   fail intermittently against a healthy scan.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum TailPolicy {
    RejectPartial,
    SkipPartial,
}

/// Validate a log file in one pass and return `(last_sequence, offsets,
/// end_offset)` -- see [`EventLog::scan_existing`] for what each means and
/// what counts as corruption, and [`TailPolicy`] for the one behavioural
/// difference between the writer's and the reader's use of this.
///
/// `end_offset` counts only bytes belonging to complete lines, so a skipped
/// partial tail is never included in it.
fn scan_records(path: &Path, tail: TailPolicy) -> Result<(u64, Vec<u64>, u64), LogError> {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok((0, Vec::new(), 0));
        }
        Err(source) => {
            return Err(LogError::Io {
                path: path.to_owned(),
                source,
            });
        }
    };
    let mut reader = BufReader::new(file);
    let mut offsets = Vec::new();
    let mut expected = 1u64;
    let mut pos: u64 = 0;
    let mut line_number = 0usize;
    let mut raw_line = Vec::new();
    loop {
        raw_line.clear();
        let n = reader
            .read_until(b'\n', &mut raw_line)
            .map_err(|source| LogError::Io {
                path: path.to_owned(),
                source,
            })?;
        if n == 0 {
            // True end of file: nothing left to read, not even a blank
            // trailing line (that would have come through as a single
            // `\n` byte, `n == 1`, handled by the ordinary loop body
            // below instead).
            break;
        }
        line_number += 1;
        if raw_line.last() != Some(&b'\n') {
            // Only ever true on the FINAL call to `read_until` (every
            // earlier line, by definition, kept reading until it found
            // a `\n`), so `line_number` here is exactly "count of
            // already-complete lines + 1" -- the same value the
            // previous whole-file-read version computed by counting
            // `\n` bytes across the entire file up front.
            if tail == TailPolicy::SkipPartial {
                break;
            }
            return Err(LogError::Malformed {
                path: path.to_owned(),
                line: line_number,
                detail: "record is not newline-terminated (truncated or an interrupted write)"
                    .to_string(),
            });
        }
        let line_len = raw_line.len() as u64;
        let content = &raw_line[..raw_line.len() - 1]; // strip the trailing `\n`
        if !content.is_empty() {
            let text = std::str::from_utf8(content).map_err(|e| LogError::Malformed {
                path: path.to_owned(),
                line: line_number,
                detail: e.to_string(),
            })?;
            let event: Event = serde_json::from_str(text).map_err(|e| LogError::Malformed {
                path: path.to_owned(),
                line: line_number,
                detail: e.to_string(),
            })?;
            if event.sequence != expected {
                return Err(LogError::SequenceGap {
                    path: path.to_owned(),
                    expected,
                    found: event.sequence,
                });
            }
            offsets.push(pos);
            expected += 1;
        }
        pos += line_len;
    }
    Ok((expected - 1, offsets, pos))
}

impl EventLog {
    pub fn last_sequence(&self) -> u64 {
        self.last_sequence
    }

    /// Appends one record and returns the fully-populated [`Event`],
    /// including the sequence number it was assigned.
    ///
    /// `timestamp` always comes from `clock.now_rfc3339()` -- never read
    /// directly from the system clock, which is what lets a recorded run and
    /// a replayed one produce byte-identical logs (CI's "no direct time/id
    /// generation outside Clock" grep enforces this workspace-wide).
    pub fn append(
        &mut self,
        body: EventBody,
        clock: &dyn Clock,
        engine_version: &str,
    ) -> Result<Event, LogError> {
        if self.released {
            return Err(LogError::Released {
                path: self.path.clone(),
            });
        }
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
            .map_err(|source| LogError::Io {
                path: self.path.clone(),
                source,
            })?;
        if self.durable {
            // C1: `File::flush()` (what this called before) is a no-op for
            // `std::fs::File` -- there is no userspace buffer to flush, so
            // it verified nothing about durability. `sync_data` asks the OS
            // to actually flush the file's data to durable storage before
            // returning; `sync_data` rather than `sync_all` because this
            // append never changes the file's metadata (size growth via
            // `append`-mode writes is itself data the filesystem journal
            // already has to account for; unlike `EvidenceStore::put`'s
            // fresh temp file, there is no separately-durable metadata
            // change like a rename to also cover here).
            self.raw_sync()?;
        }
        self.offsets.push(self.end_offset);
        self.end_offset += line.len() as u64;
        self.last_sequence = event.sequence;
        Ok(event)
    }

    /// Forces a durability barrier (`sync_data`) on whatever has been
    /// written so far, independent of whether `self` is `durable`.
    ///
    /// This is the primitive M3's group-commit scheduler
    /// (`bathy_engine::durable_log::GroupCommitLog`) is built on: it opens
    /// its log via [`Self::open_without_durability_barrier`] (so `append`
    /// never pays a per-event `fsync`) and calls this method itself on a
    /// bounded trigger -- whichever of *N* events or *T* milliseconds comes
    /// first, plus unconditionally on a terminal event. See that module's
    /// doc comment for the full crash contract this enables: a crash loses
    /// at most the last *N* events or *T* milliseconds, never a
    /// partially-written record (every `append` still fully writes and
    /// newline-terminates its record before returning, regardless of
    /// `durable`; only *when* that write is asked to survive a crash is
    /// deferred).
    ///
    /// A no-op in the sense that it never fails to be safe to call on a
    /// `durable` log too (every `append` there has already synced), just
    /// redundant.
    pub fn sync(&self) -> Result<(), LogError> {
        self.raw_sync()
    }

    /// The one place that actually issues `sync_data()`, shared by
    /// `append`'s own conditional barrier and the public [`Self::sync`], so
    /// [`Self::sync_calls`] counts every real syscall regardless of which
    /// caller triggered it.
    fn raw_sync(&self) -> Result<(), LogError> {
        self.sync_calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.file.sync_data().map_err(|source| LogError::Io {
            path: self.path.clone(),
            source,
        })
    }

    /// See [`Self`]'s own doc comment on the `sync_calls` field.
    pub fn sync_calls(&self) -> u64 {
        self.sync_calls.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Returns every event with `sequence > after_sequence`, in order.
    ///
    /// This is the primitive `scan.events` streaming (M5) is built on, so it
    /// must stay cheap on a scan with a large history: it seeks directly to
    /// the byte offset of the first requested record (via the `offsets`
    /// index built in `open`/`append`) and reads forward from there. It does
    /// **not** re-read or re-parse any record at or before `after_sequence`
    /// -- `read_from_does_not_reparse_records_before_the_requested_tail`
    /// below proves this concretely, by corrupting the on-disk bytes of an
    /// earlier record and confirming `read_from` still succeeds, which would
    /// be impossible if it fell back to scanning from the start of the file
    /// the way a naive `File::open` + filter implementation would.
    pub fn read_from(&self, after_sequence: u64) -> Result<Vec<Event>, LogError> {
        read_records_from(
            &self.path,
            &self.offsets,
            self.last_sequence,
            after_sequence,
        )
    }
}

/// The tail read shared by [`EventLog::read_from`] and
/// [`EventLogReader::read_from`]. See the former's doc comment for the
/// seek-don't-rescan contract this implements.
fn read_records_from(
    path: &Path,
    offsets: &[u64],
    last_sequence: u64,
    after_sequence: u64,
) -> Result<Vec<Event>, LogError> {
    if after_sequence >= last_sequence {
        return Ok(Vec::new());
    }
    let start_offset = offsets[after_sequence as usize];
    let mut file = File::open(path).map_err(|source| LogError::Io {
        path: path.to_owned(),
        source,
    })?;
    file.seek(SeekFrom::Start(start_offset))
        .map_err(|source| LogError::Io {
            path: path.to_owned(),
            source,
        })?;
    let wanted = last_sequence - after_sequence;
    let mut out = Vec::with_capacity(wanted as usize);
    // Line numbers in any `Malformed` error here are relative to
    // `after_sequence`'s record, not the whole file: correct under this
    // type's own writing (append never emits a blank line), which is
    // the only way this path is ever populated.
    for (i, line) in BufReader::new(file).lines().enumerate() {
        // Stop at the snapshot this read was scoped to, before the next
        // line is even parsed. For [`EventLog`] that is simply the end of
        // the file. For [`EventLogReader`] the file is being extended
        // underneath us, and the very next line may be a record caught
        // mid-write: `open` already decided (see [`TailPolicy`]) that such
        // a line is not this reader's to report, and parsing it here would
        // turn a healthy live scan into a `Malformed` error.
        if out.len() as u64 == wanted {
            break;
        }
        let line = line.map_err(|source| LogError::Io {
            path: path.to_owned(),
            source,
        })?;
        if line.is_empty() {
            continue;
        }
        let event: Event = serde_json::from_str(&line).map_err(|e| LogError::Malformed {
            path: path.to_owned(),
            line: after_sequence as usize + i + 1,
            detail: e.to_string(),
        })?;
        // Defensive, not load-bearing for correctness under normal
        // operation (the seek above should already land exactly on
        // sequence `after_sequence + 1`): costs nothing extra, since
        // every event in the tail is parsed anyway, and it turns any
        // future bug in how `offsets` is built or indexed into a
        // dropped record instead of a duplicated or out-of-range one.
        //
        // It is load-bearing for [`EventLogReader`], which reads a file a
        // writer is still extending: `last_sequence` is a snapshot taken at
        // `open`, and the bytes past it that arrived since must not be
        // returned as if this reader had counted them.
        if event.sequence > after_sequence && event.sequence <= last_sequence {
            out.push(event);
        }
    }
    Ok(out)
}

/// A **read-only, lock-free** view of one scan's event log.
///
/// [`EventLog::open`] is the writer, and property 4 in this module's doc
/// comment is why it takes an exclusive advisory lock for its whole
/// lifetime. That lock is exactly what makes reading through `EventLog`
/// impossible while a scan is running: `bathy scan events --follow`, and
/// `scan status`/`result query` against a live scan, are a *second process*
/// reading a file the scanning process still holds open. Through
/// [`EventLog::open`] every one of them would fail with
/// [`LogError::Locked`].
///
/// This type is that reader. It cannot append -- there is no method to --
/// so it needs no lock to preserve the single-writer invariant, and it is
/// the only supported way to read a log this process is not itself writing.
/// Reading the JSONL file directly instead would put a second parser for
/// the source of truth outside the crate that owns it.
///
/// `last_sequence` is a snapshot taken at [`Self::open`]. A live log grows
/// past it; call `open` again to advance. That is what `--follow` does, and
/// it is why an in-progress record at the tail is skipped rather than
/// treated as corruption (see [`TailPolicy`]).
#[derive(Debug)]
pub struct EventLogReader {
    path: PathBuf,
    scan_id: ScanId,
    last_sequence: u64,
    offsets: Vec<u64>,
}

impl EventLogReader {
    /// Opens `dir/<scan_id>.jsonl` for reading.
    ///
    /// A log file that does not exist is an error, **not** an empty log --
    /// unlike [`EventLog::open`], which creates one. A caller asking to read
    /// a scan that was never written has almost certainly mistyped a scan
    /// id, and answering "this scan observed nothing" would be a wrong
    /// answer rather than a missing one.
    pub fn open(dir: &Path, scan_id: ScanId) -> Result<Self, LogError> {
        let path = dir.join(format!("{scan_id}.jsonl"));
        if !path.exists() {
            return Err(LogError::Io {
                path: path.clone(),
                source: std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "no event log for this scan",
                ),
            });
        }
        let (last_sequence, offsets, _end) = scan_records(&path, TailPolicy::SkipPartial)?;
        Ok(Self {
            path,
            scan_id,
            last_sequence,
            offsets,
        })
    }

    pub fn scan_id(&self) -> ScanId {
        self.scan_id
    }

    /// The highest sequence this reader saw *when it opened*. See the type's
    /// doc comment.
    pub fn last_sequence(&self) -> u64 {
        self.last_sequence
    }

    /// Every complete event with `sequence > after_sequence`, in order --
    /// the same contract as [`EventLog::read_from`], bounded above by
    /// [`Self::last_sequence`].
    pub fn read_from(&self, after_sequence: u64) -> Result<Vec<Event>, LogError> {
        read_records_from(
            &self.path,
            &self.offsets,
            self.last_sequence,
            after_sequence,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bathy_types::clock::FixedClock;

    fn scan_id() -> ScanId {
        "scan_01ARZ3NDEKTSV4RRFFQ69G5FAV".parse().unwrap()
    }

    fn clock() -> FixedClock {
        FixedClock::new("2026-08-01T15:04:31.182Z", 7).unwrap()
    }

    fn progress(n: u64) -> EventBody {
        EventBody::Progress {
            probes_sent: n,
            probes_total: 10,
            packets_spent: n,
        }
    }

    fn log() -> (tempfile::TempDir, EventLog) {
        let dir = tempfile::tempdir().unwrap();
        let log = EventLog::open(dir.path(), scan_id()).unwrap();
        (dir, log)
    }

    fn log_path(dir: &Path, id: ScanId) -> PathBuf {
        dir.join(format!("{id}.jsonl"))
    }

    // --- Brief's Step 1 tests, verbatim ---

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
        assert_eq!(
            log.append(progress(3), &clock(), "0.1.0").unwrap().sequence,
            3
        );
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
        let path = log_path(dir.path(), id);
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
        let raw =
            std::fs::read_to_string(dir.path().join(format!("{}.jsonl", log.scan_id()))).unwrap();
        assert_eq!(raw.lines().count(), 2);
        assert!(raw.ends_with('\n'));
    }

    // --- Beyond the brief: the three corruption shapes AC-2.10 covers ---
    //
    // The brief's Step 1 tests never actually exercise AC-2.10 ("a sequence
    // gap in an existing log is an error on open") -- every other AC in this
    // brief has a test that fails without the corresponding behavior, but
    // this one does not. See the task report for why this is flagged as a
    // brief defect rather than fixed by silently adding coverage. The three
    // tests below close that gap and additionally distinguish the shape the
    // brief's own name ("gap") suggests from the two the dispatch calls out
    // as easy to miss: a duplicate and an out-of-order pair. All three are
    // corruption for the same reason (see `LogError::SequenceGap`'s doc
    // comment) and all three must be rejected by the exact same check.

    /// Writes `n` real records through `EventLog::append`, closes it, and
    /// returns the raw file's lines as owned `String`s -- a fixture the
    /// three corruption tests below use to build a specific malformed
    /// ordering by reassembling those lines differently, rather than
    /// hand-writing JSON event bodies (which would need to satisfy every
    /// field `Event`/`EventBody` require).
    fn append_n_and_read_raw_lines(dir: &Path, id: ScanId, n: u64) -> Vec<String> {
        {
            let mut log = EventLog::open(dir, id).unwrap();
            for i in 1..=n {
                log.append(progress(i), &clock(), "0.1.0").unwrap();
            }
        }
        std::fs::read_to_string(log_path(dir, id))
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    #[test]
    fn a_gap_in_the_middle_of_the_log_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let id = scan_id();
        let mut kept = append_n_and_read_raw_lines(dir.path(), id, 5);
        // Drop the line for sequence 3 (index 2), leaving 1, 2, 4, 5 -- a
        // hole in the middle, not just a missing tail.
        kept.remove(2);
        let mut content = kept.join("\n");
        content.push('\n');
        std::fs::write(log_path(dir.path(), id), content).unwrap();

        let err = EventLog::open(dir.path(), id).unwrap_err();
        assert!(
            matches!(
                err,
                LogError::SequenceGap {
                    expected: 3,
                    found: 4,
                    ..
                }
            ),
            "expected a mid-file gap (expected 3, found 4), got {err:?}"
        );
    }

    #[test]
    fn a_duplicate_sequence_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let id = scan_id();
        let lines = append_n_and_read_raw_lines(dir.path(), id, 3);
        // Replace the line for sequence 3 with a second copy of sequence 2's
        // line, so the file reads 1, 2, 2 -- a repeated sequence number
        // rather than a missing one.
        let content = format!("{}\n{}\n{}\n", lines[0], lines[1], lines[1]);
        // Guard against `format!` accidentally producing valid content
        // (e.g. if the fixture ever changes shape): the third line must
        // literally duplicate the second.
        assert!(content.matches(&lines[1]).count() >= 2);
        std::fs::write(log_path(dir.path(), id), &content).unwrap();

        let err = EventLog::open(dir.path(), id).unwrap_err();
        assert!(
            matches!(
                err,
                LogError::SequenceGap {
                    expected: 3,
                    found: 2,
                    ..
                }
            ),
            "expected a duplicate sequence (expected 3, found 2), got {err:?}"
        );
    }

    #[test]
    fn an_out_of_order_sequence_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let id = scan_id();
        let lines = append_n_and_read_raw_lines(dir.path(), id, 3);
        // Swap sequences 2 and 3, so the file reads 1, 3, 2 -- present and
        // accounted for, just not in order.
        let content = format!("{}\n{}\n{}\n", lines[0], lines[2], lines[1]);
        std::fs::write(log_path(dir.path(), id), content).unwrap();

        let err = EventLog::open(dir.path(), id).unwrap_err();
        assert!(
            matches!(
                err,
                LogError::SequenceGap {
                    expected: 2,
                    found: 3,
                    ..
                }
            ),
            "expected an out-of-order sequence (expected 2, found 3), got {err:?}"
        );
    }

    // --- Beyond the brief: the two trailing-line shapes the brief's own
    // truncation test does not distinguish ---
    //
    // The brief truncates mid-record, which happens to also strip the
    // trailing newline -- so that one test alone cannot tell whether `open`
    // is rejecting the missing newline or the broken JSON. The two tests
    // below separate those causes deliberately: a trailing line that is
    // syntactically valid JSON but simply unterminated (still corruption --
    // see `scan_existing`'s doc comment for why), and a trailing *blank*
    // line, which is the opposite case and must be tolerated.

    #[test]
    fn a_syntactically_valid_but_unterminated_trailing_record_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let id = scan_id();
        {
            let mut log = EventLog::open(dir.path(), id).unwrap();
            log.append(progress(1), &clock(), "0.1.0").unwrap();
            log.append(progress(2), &clock(), "0.1.0").unwrap();
        }
        let path = log_path(dir.path(), id);
        let mut raw = std::fs::read(&path).unwrap();
        assert_eq!(
            *raw.last().unwrap(),
            b'\n',
            "setup: the file must genuinely end in a newline before we remove it"
        );
        raw.pop(); // remove ONLY the trailing newline; the JSON before it is intact
        std::fs::write(&path, &raw).unwrap();

        // Confirm the removal really did leave valid JSON behind, so this
        // test is proving the newline check specifically, not accidentally
        // re-testing the truncated-JSON case the brief already covers.
        let last_line = std::str::from_utf8(&raw)
            .unwrap()
            .rsplit('\n')
            .next()
            .unwrap();
        assert!(
            serde_json::from_str::<Event>(last_line).is_ok(),
            "setup: the unterminated last line must itself be valid JSON"
        );

        let err = EventLog::open(dir.path(), id).unwrap_err();
        assert!(
            matches!(err, LogError::Malformed { line: 2, .. }),
            "expected Malformed naming line 2, got {err:?}"
        );
    }

    #[test]
    fn a_trailing_blank_line_is_tolerated() {
        let dir = tempfile::tempdir().unwrap();
        let id = scan_id();
        {
            let mut log = EventLog::open(dir.path(), id).unwrap();
            log.append(progress(1), &clock(), "0.1.0").unwrap();
            log.append(progress(2), &clock(), "0.1.0").unwrap();
        }
        let path = log_path(dir.path(), id);
        let mut raw = std::fs::read(&path).unwrap();
        raw.push(b'\n'); // an extra blank line after the last real record
        std::fs::write(&path, raw).unwrap();

        let mut log = EventLog::open(dir.path(), id).unwrap();
        assert_eq!(
            log.last_sequence(),
            2,
            "the blank line must not count as a record"
        );
        assert_eq!(
            log.append(progress(3), &clock(), "0.1.0").unwrap().sequence,
            3,
            "the sequence must continue correctly past a tolerated blank line"
        );
    }

    // Smaller item F (whole-branch review): `scan_existing`'s own doc
    // comment claims a blank line is tolerated anywhere, not only at EOF --
    // but until this test, only the EOF case (above) was actually
    // exercised. This inserts a blank line strictly BETWEEN two real
    // records and confirms open still succeeds, `last_sequence` still
    // reflects the real records only, and (crucially) the byte offsets used
    // by `read_from` still land correctly on every record after the blank
    // line, not just before it.
    #[test]
    fn a_blank_line_in_the_middle_of_the_file_is_tolerated() {
        let dir = tempfile::tempdir().unwrap();
        let id = scan_id();
        {
            let mut log = EventLog::open(dir.path(), id).unwrap();
            log.append(progress(1), &clock(), "0.1.0").unwrap();
            log.append(progress(2), &clock(), "0.1.0").unwrap();
        }
        let path = log_path(dir.path(), id);
        let raw = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<&str> = raw.lines().collect();
        assert_eq!(lines.len(), 2, "setup: expected exactly two real records");
        // Splice a blank line in between the two real records.
        lines.insert(1, "");
        let content = format!("{}\n", lines.join("\n"));

        std::fs::write(&path, &content).unwrap();

        let mut log = EventLog::open(dir.path(), id).unwrap();
        assert_eq!(
            log.last_sequence(),
            2,
            "a mid-file blank line must not count as a record or break sequence tracking"
        );
        // The real test of the offsets index: append a third record and
        // confirm `read_from` can still find sequences 2 and 3 correctly,
        // which only holds if the byte offset recorded for sequence 2
        // accounted for the blank line's byte(s) landing before it.
        log.append(progress(3), &clock(), "0.1.0").unwrap();
        let tail = log.read_from(1).unwrap();
        assert_eq!(
            tail.iter().map(|e| e.sequence).collect::<Vec<_>>(),
            vec![2, 3],
            "records after a mid-file blank line must still be readable at \
             their correct offsets"
        );
    }

    // Smaller item D (whole-branch review): `scan_existing` now streams the
    // file through a `BufReader` with a running byte position instead of
    // reading it whole into memory (the plan explicitly forbids the latter
    // at this project's stated 1M-event ceiling). This can't directly
    // assert peak memory from a unit test, but a few thousand records is
    // enough to catch an off-by-one in the running `pos`/offset bookkeeping
    // that a handful of records would not reliably exercise -- in
    // particular, an offset error would surface here as `read_from` seeking
    // to the wrong byte and returning a `Malformed`/wrong-sequence record,
    // not silently succeeding.
    #[test]
    fn scan_existing_streams_correctly_across_many_records() {
        let dir = tempfile::tempdir().unwrap();
        let id = scan_id();
        const COUNT: u64 = 3_000;
        {
            // The durability barrier (C1) is orthogonal to what this test
            // checks (offset/line-number bookkeeping in `scan_existing`),
            // so the non-durable constructor is used here purely to keep a
            // 3,000-record append loop fast; `open_without_durability_barrier`
            // has its own dedicated coverage in `store.rs`/here elsewhere.
            let mut log = EventLog::open_without_durability_barrier(dir.path(), id).unwrap();
            for i in 1..=COUNT {
                log.append(progress(i), &clock(), "0.1.0").unwrap();
            }
        }
        // Reopening forces a full `scan_existing` pass over every record
        // written above.
        let log = EventLog::open(dir.path(), id).unwrap();
        assert_eq!(log.last_sequence(), COUNT);

        let tail = log.read_from(COUNT - 5).unwrap();
        assert_eq!(
            tail.iter().map(|e| e.sequence).collect::<Vec<_>>(),
            ((COUNT - 4)..=COUNT).collect::<Vec<_>>(),
            "the offsets index built while streaming must still point at \
             exactly the right bytes for records near the end of a large file"
        );

        let all = log.read_from(0).unwrap();
        assert_eq!(all.len(), COUNT as usize);
        assert_eq!(all[0].sequence, 1);
        assert_eq!(all.last().unwrap().sequence, COUNT);
    }

    // --- Beyond the brief: `read_from` must be a real seek, not a full scan ---

    #[test]
    fn read_from_does_not_reparse_records_before_the_requested_tail() {
        let (dir, mut log) = log();
        for i in 1..=5 {
            log.append(progress(i), &clock(), "0.1.0").unwrap();
        }
        // Corrupt the on-disk bytes of the FIRST record only, preserving its
        // exact byte length so every later record's offset is unaffected.
        // If `read_from` ever fell back to scanning from the start of the
        // file (the way `File::open` + `BufReader::lines()` + filter, the
        // brief's own reference shape, would), this would surface as a
        // `Malformed` error even though we only asked for the tail after
        // sequence 3.
        let path = log_path(dir.path(), log.scan_id());
        let mut content = std::fs::read_to_string(&path).unwrap();
        let first_line_end = content.find('\n').unwrap();
        let corrupted = "x".repeat(first_line_end);
        content.replace_range(0..first_line_end, &corrupted);
        std::fs::write(&path, &content).unwrap();
        assert!(
            serde_json::from_str::<Event>(&corrupted).is_err(),
            "setup: the corrupted first line must genuinely fail to parse"
        );

        let tail = log.read_from(3).unwrap();
        assert_eq!(tail.len(), 2);
        assert_eq!(tail[0].sequence, 4);
        assert_eq!(tail[1].sequence, 5);
    }

    #[test]
    fn read_from_zero_returns_every_event() {
        let (_d, mut log) = log();
        for i in 1..=3 {
            log.append(progress(i), &clock(), "0.1.0").unwrap();
        }
        let all = log.read_from(0).unwrap();
        assert_eq!(all.len(), 3);
        assert_eq!(
            all.iter().map(|e| e.sequence).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
    }

    #[test]
    fn read_from_a_sequence_at_or_beyond_the_end_returns_nothing() {
        let (_d, mut log) = log();
        log.append(progress(1), &clock(), "0.1.0").unwrap();
        assert!(log.read_from(1).unwrap().is_empty());
        assert!(log.read_from(1000).unwrap().is_empty());
    }

    #[test]
    fn read_from_survives_a_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let id = scan_id();
        {
            let mut log = EventLog::open(dir.path(), id).unwrap();
            log.append(progress(1), &clock(), "0.1.0").unwrap();
            log.append(progress(2), &clock(), "0.1.0").unwrap();
        }
        let mut log = EventLog::open(dir.path(), id).unwrap();
        log.append(progress(3), &clock(), "0.1.0").unwrap();
        let tail = log.read_from(1).unwrap();
        assert_eq!(
            tail.iter().map(|e| e.sequence).collect::<Vec<_>>(),
            vec![2, 3],
            "the offsets index rebuilt on reopen must line up with records \
             written before AND after the reopen"
        );
    }

    // --- Beyond the brief: reopen must not truncate or rewrite existing bytes ---

    #[test]
    fn reopening_and_appending_does_not_alter_previously_written_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let id = scan_id();
        let path = log_path(dir.path(), id);
        {
            let mut log = EventLog::open(dir.path(), id).unwrap();
            log.append(progress(1), &clock(), "0.1.0").unwrap();
            log.append(progress(2), &clock(), "0.1.0").unwrap();
        }
        let before = std::fs::read(&path).unwrap();

        let mut log = EventLog::open(dir.path(), id).unwrap();
        log.append(progress(3), &clock(), "0.1.0").unwrap();
        let after = std::fs::read(&path).unwrap();

        assert!(
            after.starts_with(&before),
            "reopening and appending must never rewrite bytes already on disk"
        );
        assert!(after.len() > before.len());
    }

    // --- Beyond the brief: `Clock` is actually the source of the timestamp ---

    #[test]
    fn append_uses_the_injected_clock_for_the_timestamp() {
        let (_d, mut log) = log();
        let e = log.append(progress(1), &clock(), "0.1.0").unwrap();
        assert_eq!(e.timestamp, "2026-08-01T15:04:31.182Z");
    }

    // --- C1: the durability opt-out is explicit and named, and does not
    // affect correctness under normal (non-crash) operation. ---

    // --- `sync`: the group-commit primitive M3's scheduler is built on ---

    #[test]
    fn sync_on_a_non_durable_log_is_callable_and_leaves_appends_readable() {
        let dir = tempfile::tempdir().unwrap();
        let id = scan_id();
        let mut log = EventLog::open_without_durability_barrier(dir.path(), id).unwrap();
        log.append(progress(1), &clock(), "0.1.0").unwrap();
        log.append(progress(2), &clock(), "0.1.0").unwrap();
        // Before any explicit `sync`, the bytes are still visible to a
        // read within the same process (this is what lets group commit
        // batch fsyncs without batching visibility) -- `read_from` opens
        // its own fresh file handle, so this also proves `sync` is not a
        // prerequisite for `read_from` to see prior appends.
        assert_eq!(log.read_from(0).unwrap().len(), 2);
        log.sync().unwrap();
        // Still correct after the explicit sync.
        assert_eq!(log.read_from(0).unwrap().len(), 2);
        assert_eq!(log.last_sequence(), 2);
    }

    #[test]
    fn sync_on_a_durable_log_is_harmless() {
        let (_d, mut log) = log();
        log.append(progress(1), &clock(), "0.1.0").unwrap();
        // Every append on a durable log has already synced; calling this
        // again must not error or otherwise disturb the log.
        log.sync().unwrap();
        log.sync().unwrap();
        assert_eq!(log.last_sequence(), 1);
    }

    #[test]
    fn sync_with_nothing_appended_yet_is_a_harmless_no_op() {
        let (_d, log) = log();
        log.sync().unwrap();
        assert_eq!(log.last_sequence(), 0);
    }

    // --- `sync_calls`: the real-syscall ground truth (M3 Task 7 fix round
    // 1, IMPORTANT-1) that a batching wrapper's own internal bookkeeping
    // cannot substitute for. ---

    #[test]
    fn a_non_durable_log_issues_no_sync_calls_until_sync_is_called_explicitly() {
        let dir = tempfile::tempdir().unwrap();
        let id = scan_id();
        let mut log = EventLog::open_without_durability_barrier(dir.path(), id).unwrap();
        assert_eq!(log.sync_calls(), 0);
        log.append(progress(1), &clock(), "0.1.0").unwrap();
        log.append(progress(2), &clock(), "0.1.0").unwrap();
        assert_eq!(
            log.sync_calls(),
            0,
            "append on a non-durable log must not issue a real sync_data() call"
        );
        log.sync().unwrap();
        assert_eq!(log.sync_calls(), 1);
        log.sync().unwrap();
        assert_eq!(log.sync_calls(), 2);
    }

    #[test]
    fn a_durable_log_issues_exactly_one_sync_call_per_append() {
        let (_d, mut log) = log();
        assert_eq!(log.sync_calls(), 0);
        for expected in 1..=5u64 {
            log.append(progress(expected), &clock(), "0.1.0").unwrap();
            assert_eq!(log.sync_calls(), expected);
        }
    }

    #[test]
    fn the_durability_opt_out_still_round_trips_correctly() {
        let dir = tempfile::tempdir().unwrap();
        let id = scan_id();
        {
            let mut log = EventLog::open_without_durability_barrier(dir.path(), id).unwrap();
            log.append(progress(1), &clock(), "0.1.0").unwrap();
            log.append(progress(2), &clock(), "0.1.0").unwrap();
        }
        let log = EventLog::open(dir.path(), id).unwrap();
        assert_eq!(log.last_sequence(), 2);
        let all = log.read_from(0).unwrap();
        assert_eq!(
            all.iter().map(|e| e.sequence).collect::<Vec<_>>(),
            vec![1, 2]
        );
    }

    // --- C5: `EventLog::open` must refuse a second concurrent opener ---
    //
    // Before this fix, two `EventLog::open` calls for the same scan both
    // succeeded with no lock at all; interleaved appends from both produced
    // on-disk sequences like `["1","1","2"]`, and the next `open` then
    // returned `SequenceGap` -- a log that is, by this module's own design,
    // never repairable. These tests prove the second open is refused
    // cleanly instead, that the lock is released on an orderly `Drop`, and
    // (in `tests/writer_lock_released_on_abnormal_exit.rs`, a separate
    // integration test) that it is released after the holder is killed, not
    // just dropped.

    #[test]
    fn a_second_concurrent_open_of_the_same_log_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let id = scan_id();
        let _first = EventLog::open(dir.path(), id).unwrap();
        let second = EventLog::open(dir.path(), id);
        assert!(
            matches!(second, Err(LogError::Locked { .. })),
            "a second concurrent opener must be refused with Locked, not \
             silently allowed to interleave appends: {second:?}"
        );
    }

    #[test]
    fn the_writer_lock_is_released_once_the_first_handle_is_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let id = scan_id();
        {
            let _first = EventLog::open(dir.path(), id).unwrap();
        } // dropped here -- closes the fd, which releases the OS-level lock
        let second = EventLog::open(dir.path(), id);
        assert!(
            second.is_ok(),
            "the lock must be released once the first handle is dropped: {second:?}"
        );
    }

    #[test]
    fn a_second_opener_locked_out_can_open_once_it_gets_a_turn() {
        // Beyond the brief's own single-collision check: confirms the lock
        // is genuinely per-file, not process-global -- a DIFFERENT scan's
        // log is completely unaffected by another scan's lock being held.
        let dir = tempfile::tempdir().unwrap();
        let id_a = scan_id();
        let id_b: ScanId = "scan_01ARZ3NDEKTSV4RRFFQ69G5FAW".parse().unwrap();
        let _held = EventLog::open(dir.path(), id_a).unwrap();
        let other = EventLog::open(dir.path(), id_b);
        assert!(
            other.is_ok(),
            "a lock on one scan's log must not block a different scan's log: {other:?}"
        );
    }

    #[test]
    fn locked_open_does_not_leave_a_stale_offsets_view_the_winner_could_race_against() {
        // The specific hazard the lock-before-scan_existing ordering
        // guards against, made concrete: if the second `open` had managed
        // to validate the file BEFORE the first opener's later appends
        // landed, its in-memory `last_sequence` would be stale. Since the
        // second open is refused outright here, there is no stale view to
        // race against at all -- the winner's own state stays authoritative
        // for as long as it holds the lock.
        let dir = tempfile::tempdir().unwrap();
        let id = scan_id();
        let mut first = EventLog::open(dir.path(), id).unwrap();
        first.append(progress(1), &clock(), "0.1.0").unwrap();

        assert!(EventLog::open(dir.path(), id).is_err());
        first.append(progress(2), &clock(), "0.1.0").unwrap();
        assert_eq!(first.last_sequence(), 2);

        drop(first);
        let reopened = EventLog::open(dir.path(), id).unwrap();
        assert_eq!(
            reopened.last_sequence(),
            2,
            "no state was lost or duplicated across the locked-out window"
        );
    }

    // --- `EventLogReader`: the lock-free reader (M5 Task 3). ---
    //
    // `scan events --follow` is a second process reading a log the scanning
    // process still holds locked. Every test below is about that situation
    // specifically, because through `EventLog::open` alone it is not
    // expressible at all.

    #[test]
    fn a_reader_opens_a_log_the_writer_still_holds_locked() {
        let dir = tempfile::tempdir().unwrap();
        let id = scan_id();
        let mut writer = EventLog::open(dir.path(), id).unwrap();
        writer.append(progress(1), &clock(), "0.1.0").unwrap();
        writer.append(progress(2), &clock(), "0.1.0").unwrap();

        // The premise: the writer's lock is real and still held.
        assert!(
            EventLog::open(dir.path(), id).is_err(),
            "test premise: a second writer must still be locked out"
        );

        let reader = EventLogReader::open(dir.path(), id).unwrap();
        assert_eq!(reader.last_sequence(), 2);
        assert_eq!(reader.scan_id(), id);
        let events = reader.read_from(0).unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].sequence, 1);
        assert_eq!(events[1].sequence, 2);
    }

    #[test]
    fn a_reader_takes_no_lock_of_its_own_so_the_writer_keeps_appending() {
        // The inverse of the test above, and the one that actually matters
        // for a live tail: opening a reader must not lock the writer out of
        // its own log, nor a second reader out.
        let dir = tempfile::tempdir().unwrap();
        let id = scan_id();
        let mut writer = EventLog::open(dir.path(), id).unwrap();
        writer.append(progress(1), &clock(), "0.1.0").unwrap();

        let first = EventLogReader::open(dir.path(), id).unwrap();
        let second = EventLogReader::open(dir.path(), id).unwrap();
        assert_eq!(first.last_sequence(), 1);
        assert_eq!(second.last_sequence(), 1);

        writer.append(progress(2), &clock(), "0.1.0").unwrap();
        assert_eq!(writer.last_sequence(), 2);

        // A reader opened before the append still reports its own snapshot;
        // a freshly opened one sees the new record. This is the whole
        // `--follow` contract.
        assert_eq!(first.read_from(0).unwrap().len(), 1);
        assert_eq!(
            EventLogReader::open(dir.path(), id)
                .unwrap()
                .read_from(1)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn a_reader_skips_an_unterminated_tail_record_that_the_writer_rejects() {
        // A record caught mid-write is the ordinary sight for a lock-free
        // reader and corruption for a writer. Both behaviours are asserted
        // here on the same bytes, so neither can be changed without this
        // failing.
        let dir = tempfile::tempdir().unwrap();
        let id = scan_id();
        {
            let mut writer = EventLog::open(dir.path(), id).unwrap();
            writer.append(progress(1), &clock(), "0.1.0").unwrap();
        }
        let path = log_path(dir.path(), id);
        let mut text = std::fs::read_to_string(&path).unwrap();
        text.push_str("{\"sequence\":2,\"partial");
        std::fs::write(&path, &text).unwrap();

        let reader = EventLogReader::open(dir.path(), id).unwrap();
        assert_eq!(
            reader.last_sequence(),
            1,
            "a half-written record must not be counted"
        );
        assert_eq!(reader.read_from(0).unwrap().len(), 1);

        assert!(
            matches!(
                EventLog::open(dir.path(), id),
                Err(LogError::Malformed { .. })
            ),
            "the writer must still refuse the same file: it would glue its next record on"
        );
    }

    #[test]
    fn a_reader_refuses_a_log_with_a_sequence_gap_exactly_as_the_writer_does() {
        // Tolerating a partial *tail* is not tolerating corruption. A hole
        // in the middle is still an unaccounted-for observation.
        let dir = tempfile::tempdir().unwrap();
        let id = scan_id();
        {
            let mut writer = EventLog::open(dir.path(), id).unwrap();
            for i in 1..=3 {
                writer.append(progress(i), &clock(), "0.1.0").unwrap();
            }
        }
        let path = log_path(dir.path(), id);
        let text = std::fs::read_to_string(&path).unwrap();
        let kept: Vec<&str> = text
            .lines()
            .enumerate()
            .filter(|(i, _)| *i != 1)
            .map(|(_, l)| l)
            .collect();
        std::fs::write(&path, format!("{}\n", kept.join("\n"))).unwrap();

        assert!(matches!(
            EventLogReader::open(dir.path(), id),
            Err(LogError::SequenceGap { .. })
        ));
    }

    #[test]
    fn a_reader_on_a_log_that_does_not_exist_is_an_error_not_an_empty_scan() {
        // `EventLog::open` creates a missing log, which is right for a
        // writer and a wrong *answer* for a reader: a mistyped scan id must
        // never read as "this scan observed nothing".
        let dir = tempfile::tempdir().unwrap();
        let err = EventLogReader::open(dir.path(), scan_id()).unwrap_err();
        assert!(
            matches!(&err, LogError::Io { source, .. } if source.kind() == std::io::ErrorKind::NotFound),
            "{err}"
        );
        assert!(
            !log_path(dir.path(), scan_id()).exists(),
            "a reader must not create the file it failed to find"
        );
    }
}
