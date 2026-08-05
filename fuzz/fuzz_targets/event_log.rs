#![no_main]
#![forbid(unsafe_code)]

//! Fuzzes the JSONL event-log reader -- AC-7.7.
//!
//! An event log is untrusted input for a reason that is easy to miss: it is
//! not written by a peer, it is written by *us*, but by a build that may be
//! months old, may have crashed mid-record, may have been truncated by a
//! full disk, or may have been edited. `bathy scan events`, `scan status`,
//! `result query` and `result diff` all read one, and this repository has
//! already shipped one log-format defect that made a log written last week
//! unloadable today.
//!
//! The target goes through the real reader (`EventLogReader`), not through
//! `serde_json::from_str::<Event>` directly. Reading the JSONL by hand here
//! would put a second parser for the source of truth outside the crate that
//! owns it, which is the thing `EventLogReader`'s own doc comment forbids --
//! and it would skip the part most likely to be wrong: the offset index
//! `scan_records` builds and `read_from` then indexes with.
//!
//! It does not stop at parsing. `bathy_query::fold_events` is what every
//! consumer does next, and it only ever sees events that came out of these
//! bytes, so it is fuzzed in the same execution.

use std::path::PathBuf;
use std::sync::OnceLock;

use bathy_evidence::log::{EventLogReader, LogError};
use bathy_fuzz::Stats;
use bathy_query::{diff, fold_events};
use bathy_types::ids::ScanId;
use libfuzzer_sys::fuzz_target;

const OPENED: usize = 0;
const REJECTED: usize = 1;
const EVENTS: usize = 2;
const TAIL_READS: usize = 3;
const FOLDED_ENDPOINTS: usize = 4;
const FOLDED_OBSERVATIONS: usize = 5;
const OPENED_EMPTY: usize = 6;
const OPENED_ONE: usize = 7;
const OPENED_MANY: usize = 8;

const LABELS: &[&str] = &[
    // Weaker than it reads, and named here so a report cannot lead with it
    // without the next three: an EMPTY file opens successfully with zero
    // events, so this counts "the reader did not reject it", not "a log was
    // parsed". A measured run had opened=93,728 against events_parsed=6,610
    // -- 0.07 events per opened log, so the overwhelming majority of
    // "opened" inputs carried no records at all. `events_parsed`,
    // `opened_multi_record` and `folded_endpoints` are the load-bearing
    // figures for this target.
    "opened",
    "rejected",
    "events_parsed",
    "tail_reads",
    "folded_endpoints",
    "folded_observations",
    // The `ok:` flags below say each of these happened at least once; these
    // say how often, which is the difference between "the corpus can reach a
    // multi-record log" and "the corpus is multi-record logs".
    "opened_empty",
    "opened_one_record",
    "opened_multi_record",
];

/// Which outcomes the corpus has actually produced. A run that only ever
/// reaches `Malformed` has not exercised the sequence-continuity logic, and
/// the sequence-continuity logic is where the interesting indexing lives.
///
/// `LogError::Io`, `LogError::Locked` and `LogError::Released` are
/// deliberately collapsed into `err:unexpected` rather than given bits of
/// their own: none is reachable through this door (the file is written
/// immediately before it is opened, `EventLogReader` takes no lock by design,
/// and `Released` is about a *writer* that gave up its claim), so listing
/// them would make the denominator a target nothing could ever hit and every
/// report read as under-covered. If `err:unexpected` ever appears, that is
/// itself the finding. The collapsing is written out variant by variant in
/// the `match` below rather than as `_`, so a new variant breaks the build.
const FLAGS: &[&str] = &[
    "err:malformed",
    "err:sequence_gap",
    "err:unexpected",
    "ok:empty_log",
    "ok:single_record",
    "ok:multi_record",
];

static STATS: Stats = Stats::new("event_log", LABELS, FLAGS);

/// One directory per process, reused across executions.
///
/// A fresh `tempfile::TempDir` per execution would cost two syscalls and a
/// directory create/remove per input and would dominate the run; the file
/// itself is rewritten (truncating) every time, so no state carries over.
fn log_dir() -> &'static PathBuf {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    DIR.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!("bathy-fuzz-event-log-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("fuzz scratch directory");
        dir
    })
}

fn scan_id() -> ScanId {
    "scan_01ARZ3NDEKTSV4RRFFQ69G5FAV"
        .parse()
        .expect("fixed, valid scan id")
}

fuzz_target!(|data: &[u8]| {
    let dir = log_dir();
    let path = dir.join(format!("{}.jsonl", scan_id()));
    // `write` truncates, so the previous execution's log cannot leak into
    // this one.
    if std::fs::write(&path, data).is_err() {
        STATS.tick();
        return;
    }

    let reader = match EventLogReader::open(dir, scan_id()) {
        Ok(reader) => reader,
        Err(e) => {
            STATS.bump(REJECTED);
            // Exhaustive, with no `_` arm. `Io`, `Locked` and `Released` are
            // collapsed into `err:unexpected` deliberately and for the reason
            // FLAGS gives -- but written out, so a sixth `LogError` variant
            // breaks this build instead of landing silently in a catch-all
            // and reading as covered. `manifest`'s equivalent match was
            // already exhaustive; this one was `_ => 2`.
            STATS.flag(match e {
                LogError::Malformed { .. } => 0,
                LogError::SequenceGap { .. } => 1,
                LogError::Io { .. }
                | LogError::Locked { .. }
                | LogError::Released { .. }
                // `Unrecordable` is about *writing* a record (M7 panic-lint
                // widening: the `expect("event serializes")` and the unchecked
                // offset arithmetic in `append`). This target only reads, so
                // it joins the same collapsed bucket for the same reason.
                | LogError::Unrecordable { .. } => 2,
            });
            STATS.tick();
            return;
        }
    };
    STATS.bump(OPENED);

    let events = match reader.read_from(0) {
        Ok(events) => events,
        // Opening succeeded, so the whole file already parsed once; a
        // failure on the second pass over the same unchanged bytes would be
        // a real inconsistency, not merely a rejected input.
        Err(e) => panic!("a log that opened cleanly failed to read back: {e}"),
    };
    STATS.add(EVENTS, events.len() as u64);
    match events.len() {
        0 => {
            STATS.flag(3);
            STATS.bump(OPENED_EMPTY);
        }
        1 => {
            STATS.flag(4);
            STATS.bump(OPENED_ONE);
        }
        _ => {
            STATS.flag(5);
            STATS.bump(OPENED_MANY);
        }
    }

    // The reader's own contract: sequences are exactly 1..=last_sequence,
    // ascending with no repeats. Everything downstream (resumption cursors,
    // `scan.events` streaming, the fold below) assumes it.
    assert_eq!(
        events.len() as u64,
        reader.last_sequence(),
        "read_from(0) returned {} event(s) for a log whose last_sequence is {}",
        events.len(),
        reader.last_sequence()
    );
    for (i, event) in events.iter().enumerate() {
        assert_eq!(
            event.sequence,
            i as u64 + 1,
            "event {i} carries sequence {}; a log that opened must be contiguous from 1",
            event.sequence
        );
    }

    // Tail reads from cursors the caller chose. `after_sequence` is not
    // derived from the log: it arrives from outside the process, as
    // `bathy scan events --after-sequence <n>` and as the `scan.events` MCP
    // tool's cursor, and `read_records_from` used to bounds-check it against
    // `last_sequence` and then index `offsets` with it -- two different
    // values.
    //
    // The cursor used to be `data.len() % (last_sequence + 2)` alone: always
    // inside `0..=last_sequence + 1`, and a function of the input's *length*
    // rather than its content. That covers the in-range boundary and nothing
    // else. Three additions, each one a shape the old cursor could not reach:
    // a cursor taken from the input bytes (so the fuzzer can steer it),
    // `u64::MAX`, and a value above `u32::MAX` -- the last because
    // `after_sequence as usize` silently *truncates* on a 32-bit target,
    // turning `2^32 + 3` into a valid-looking index 3.
    let last = reader.last_sequence();
    let mut cursors = vec![
        (data.len() as u64) % last.saturating_add(2),
        u64::from_le_bytes(std::array::from_fn(|i| data.get(i).copied().unwrap_or(0))),
        u64::MAX,
        (1u64 << 32).saturating_add(u64::from(data.first().copied().unwrap_or(0))),
    ];
    cursors.dedup();
    for after in cursors {
        match reader.read_from(after) {
            Ok(tail) => {
                STATS.bump(TAIL_READS);
                assert!(
                    tail.iter().all(|e| e.sequence > after),
                    "read_from({after}) returned an event at or before its cursor"
                );
                assert_eq!(
                    tail.len() as u64,
                    last.saturating_sub(after),
                    "read_from({after}) returned {} of the {} event(s) past its cursor",
                    tail.len(),
                    last.saturating_sub(after)
                );
            }
            Err(e) => panic!("a log that opened cleanly failed a tail read from {after}: {e}"),
        }
    }

    // The first thing every consumer does with a parsed log. It sees only
    // events these bytes produced, so it is part of the same attack
    // surface.
    let fold = fold_events(&events);
    STATS.add(FOLDED_ENDPOINTS, fold.endpoints.len() as u64);
    STATS.add(
        FOLDED_OBSERVATIONS,
        fold.endpoints
            .values()
            .filter(|e| e.observation.is_some())
            .count() as u64,
    );

    // A fold diffed against itself: every endpoint is present on both sides
    // with identical content, so there is nothing for the classifier to
    // find and nothing for it to call one-sided. Any change or
    // `undetermined` entry here is one the differ invented. (Note what is
    // deliberately *not* asserted: `absence_was_evidence()`. A fuzz-produced
    // log usually has no `scan.started`, so both sides carry
    // `plan_hash: None` and the pair is legitimately undecidable -- which
    // changes nothing about the two assertions below, because no endpoint is
    // one-sided in the first place.)
    let self_diff = diff(&fold, &fold);
    assert!(
        self_diff.changes.is_empty(),
        "diffing a fold against itself invented {} change(s): {:?}",
        self_diff.changes.len(),
        self_diff.changes
    );
    assert!(
        self_diff.undetermined.is_empty(),
        "diffing a fold against itself left {} endpoint(s) undetermined",
        self_diff.undetermined.len()
    );
    assert_eq!(
        self_diff.unchanged as usize,
        fold.endpoints.len(),
        "diffing a fold against itself accounted for {} of its {} endpoint(s)",
        self_diff.unchanged,
        fold.endpoints.len()
    );

    STATS.tick();
});
