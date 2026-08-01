//! The append-only, per-scan JSONL event log: the source of truth for
//! everything a scan observed.
//!
//! SQLite state (`bathy-store`, a later M2 task) is a derived index and can
//! always be rebuilt by replaying this log from sequence 0; the reverse is
//! not true. Two properties carry that claim:
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
}

impl EventLog {
    pub fn open(dir: &Path, scan_id: ScanId) -> Result<Self, LogError> {
        std::fs::create_dir_all(dir).map_err(|source| LogError::Io {
            path: dir.to_owned(),
            source,
        })?;
        let path = dir.join(format!("{scan_id}.jsonl"));
        let (last_sequence, offsets, end_offset) = Self::scan_existing(&path)?;
        // `create(true).append(true)`, never `.truncate(true)`: opening an
        // existing log for more appends must never rewrite or shorten what
        // is already on disk. `scan_existing` above has already run (and
        // would have returned `Err` without ever reaching this line) for any
        // content that fails validation, so a corrupt log is never silently
        // reopened for writing either.
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|source| LogError::Io {
                path: path.clone(),
                source,
            })?;
        Ok(Self {
            path,
            scan_id,
            file,
            last_sequence,
            offsets,
            end_offset,
        })
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
    ///   *before* any JSON parsing, deliberately: a trailing record that
    ///   happens to be syntactically valid JSON but was never terminated is
    ///   still rejected, because leaving it un-terminated would let the next
    ///   `append` glue a new record onto its line. A missing-newline tail
    ///   and a mid-record truncation (the brief's own test) are the same
    ///   failure by the time they reach this check -- the file does not end
    ///   in `\n` -- and are reported the same way. A *blank* trailing line
    ///   (the file ends in `\n\n`) is the opposite case and is tolerated:
    ///   every real record before it is already complete and terminated, so
    ///   there is nothing to lose by skipping it.
    /// - Any two consecutive (non-blank) records' sequence numbers are not
    ///   exactly `expected, expected + 1`. This one check, applied uniformly
    ///   line by line, is what catches a gap in the middle of the file, a
    ///   duplicated sequence, and an out-of-order sequence alike -- see
    ///   `LogError::SequenceGap`'s doc comment.
    fn scan_existing(path: &Path) -> Result<(u64, Vec<u64>, u64), LogError> {
        if !path.exists() {
            return Ok((0, Vec::new(), 0));
        }
        let bytes = std::fs::read(path).map_err(|source| LogError::Io {
            path: path.to_owned(),
            source,
        })?;
        if bytes.is_empty() {
            // A log file that exists but has never had a record appended to
            // it (e.g. a prior `open` created it and the process exited
            // before the first `append`). Nothing to validate.
            return Ok((0, Vec::new(), 0));
        }
        if *bytes.last().expect("checked non-empty above") != b'\n' {
            // Count of already-complete lines (each ending in `\n`) tells us
            // which line number the unterminated tail is.
            let line = bytes.iter().filter(|&&b| b == b'\n').count() + 1;
            return Err(LogError::Malformed {
                path: path.to_owned(),
                line,
                detail: "record is not newline-terminated (truncated or an interrupted write)"
                    .to_string(),
            });
        }

        let mut offsets = Vec::new();
        let mut expected = 1u64;
        let mut start = 0usize;
        let mut line_number = 0usize;
        while start < bytes.len() {
            // Safe: every position `< bytes.len()` has a `\n` somewhere
            // after it, because the file's very last byte is `\n` (checked
            // above).
            let newline_at = bytes[start..]
                .iter()
                .position(|&b| b == b'\n')
                .expect("file ends with a newline")
                + start;
            let raw_line = &bytes[start..newline_at];
            line_number += 1;
            if !raw_line.is_empty() {
                let text = std::str::from_utf8(raw_line).map_err(|e| LogError::Malformed {
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
                offsets.push(start as u64);
                expected += 1;
            }
            start = newline_at + 1;
        }
        Ok((expected - 1, offsets, bytes.len() as u64))
    }

    pub fn scan_id(&self) -> ScanId {
        self.scan_id
    }

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
        self.file.flush().map_err(|source| LogError::Io {
            path: self.path.clone(),
            source,
        })?;
        self.offsets.push(self.end_offset);
        self.end_offset += line.len() as u64;
        self.last_sequence = event.sequence;
        Ok(event)
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
        if after_sequence >= self.last_sequence {
            return Ok(Vec::new());
        }
        let start_offset = self.offsets[after_sequence as usize];
        let mut file = File::open(&self.path).map_err(|source| LogError::Io {
            path: self.path.clone(),
            source,
        })?;
        file.seek(SeekFrom::Start(start_offset))
            .map_err(|source| LogError::Io {
                path: self.path.clone(),
                source,
            })?;
        let mut out = Vec::with_capacity((self.last_sequence - after_sequence) as usize);
        // Line numbers in any `Malformed` error here are relative to
        // `after_sequence`'s record, not the whole file: correct under this
        // type's own writing (append never emits a blank line), which is
        // the only way this path is ever populated.
        for (i, line) in BufReader::new(file).lines().enumerate() {
            let line = line.map_err(|source| LogError::Io {
                path: self.path.clone(),
                source,
            })?;
            if line.is_empty() {
                continue;
            }
            let event: Event = serde_json::from_str(&line).map_err(|e| LogError::Malformed {
                path: self.path.clone(),
                line: after_sequence as usize + i + 1,
                detail: e.to_string(),
            })?;
            // Defensive, not load-bearing for correctness under normal
            // operation (the seek above should already land exactly on
            // sequence `after_sequence + 1`): costs nothing extra, since
            // every event in the tail is parsed anyway, and it turns any
            // future bug in how `offsets` is built or indexed into a
            // dropped record instead of a duplicated or out-of-range one.
            if event.sequence > after_sequence {
                out.push(event);
            }
        }
        Ok(out)
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
        FixedClock::new("2026-08-01T15:04:31.182Z", 7)
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
}
