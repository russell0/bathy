//! All time and identifier generation flows through [`Clock`].
//!
//! Nothing else in the workspace may call `SystemTime::now()` or construct a
//! random ULID directly (`ulid::Generator`, or `Ulid::new()` should a future
//! version of the `ulid` crate reintroduce it). Injecting both through one
//! trait is what makes an event log byte-comparable between a recorded run
//! and a replayed one -- the foundation of this project's
//! reproducible-interpretation claim. CI enforces the "nowhere else" half of
//! that with a grep over `crates/` and `xtask/` excluding this file (see
//! `.github/workflows/ci.yml`, "no direct time/id generation outside Clock").

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::ids::{EventId, ScanId};

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

/// `Ulid::new()` was REMOVED in ulid 3.x. Random generation goes through
/// `ulid::Generator`, whose `generate` is fallible (monotonic overflow within
/// the same millisecond) and takes `&mut self` -- hence the mutex. Verified
/// against `ulid-3.0.0/src/generator.rs`: `Generator::generate(&mut self) ->
/// Result<Ulid, Overflow<'_>>`.
///
/// Not a unit struct, despite the brief's test examples calling
/// `SystemClock.now_rfc3339()` as if it were one: the `generator` field is
/// exactly what makes ids monotonically increasing across calls (see the
/// paragraph above -- state has to persist between calls, hence a field, not
/// a fresh `Generator::new()` each time). Construct via `SystemClock::default()`.
pub struct SystemClock {
    generator: std::sync::Mutex<ulid::Generator>,
}

impl Default for SystemClock {
    fn default() -> Self {
        Self {
            generator: std::sync::Mutex::new(ulid::Generator::new()),
        }
    }
}

impl SystemClock {
    fn next_ulid(&self) -> ulid::Ulid {
        let mut g = self.generator.lock().expect("ulid generator poisoned");
        // Monotonic overflow means >2^80 ids generated within one
        // millisecond, which cannot happen on any real workload this project
        // runs; fall back to a fresh non-monotonic id derived straight from
        // the current time rather than panicking in a library path.
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
        let d = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock before epoch");
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
/// algorithm (Howard Hinnant's `civil_from_days`, run in the encode
/// direction). Valid for all years we care about; UTC only, by construction
/// (there is no timezone parameter to get wrong).
///
/// Cross-checked against known epochs in the test module below -- the Unix
/// epoch, a leap day, both sides of a century year-boundary (2000 is a leap
/// year under the div-400 rule; 1900 is not), and a pre-1970 date -- each
/// verified independently against both `date -u` and Python's `datetime`,
/// not by round-tripping this function against itself.
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
///
/// `seed` is fed into `Ulid::from_parts` as the 48-bit timestamp field, which
/// masks off any bits above bit 47 (`ulid::Ulid::from_parts`'s own doc: "Any
/// overflow bits in the given args are discarded"). A `u64::MAX` seed's low
/// 48 bits are all `1`, making `2^48 - 1` the single largest reachable
/// timestamp value; its top 3 bits (which become the id's first Crockford
/// character -- see the proof on `from_ulid` in `ids.rs`) are `0b111`, so `7`
/// is the largest reachable first character, still inside the canonical
/// `0`-`7` range `ScanId::from_str` requires. That is exercised concretely by
/// `fixed_clock_max_seed_produces_canonical_round_tripping_id` below: no
/// seed, however large, can ever produce a non-canonical id.
pub struct FixedClock {
    now: String,
    counter: AtomicU64,
    seed: u64,
}

impl FixedClock {
    pub fn new(now: &str, seed: u64) -> Self {
        Self {
            now: now.to_owned(),
            counter: AtomicU64::new(0),
            seed,
        }
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

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    // --- Brief's Step 1 tests, verbatim ---

    #[test]
    fn fixed_clock_is_reproducible() {
        let a = FixedClock::new("2026-08-01T15:04:31.182Z", 7);
        let b = FixedClock::new("2026-08-01T15:04:31.182Z", 7);
        assert_eq!(a.now_rfc3339(), b.now_rfc3339());
        assert_eq!(a.new_scan_id(), b.new_scan_id());
        assert_eq!(
            a.new_scan_id(),
            b.new_scan_id(),
            "second draw must also match"
        );
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
        let s = SystemClock::default().now_rfc3339();
        assert!(s.ends_with('Z'), "got {s}");
        assert_eq!(s.len(), 24, "expected YYYY-MM-DDTHH:MM:SS.mmmZ, got {s}");
        assert_eq!(&s[4..5], "-");
        assert_eq!(&s[10..11], "T");
        assert_eq!(&s[19..20], ".");
    }

    // --- AC-2.2: two `FixedClock`s built with identical arguments yield
    // identical timestamp AND identifier *sequences*, not just a single
    // matching draw. `fixed_clock_is_reproducible` above already checks two
    // draws; this extends to a longer sequence to rule out the counter
    // itself drifting between instances after the first couple of calls. ---

    #[test]
    fn fixed_clock_sequences_match_over_many_draws() {
        let a = FixedClock::new("2026-08-01T15:04:31.182Z", 7);
        let b = FixedClock::new("2026-08-01T15:04:31.182Z", 7);
        let a_ids: Vec<ScanId> = (0..50).map(|_| a.new_scan_id()).collect();
        let b_ids: Vec<ScanId> = (0..50).map(|_| b.new_scan_id()).collect();
        assert_eq!(a_ids, b_ids);

        let a_events: Vec<EventId> = (0..50).map(|_| a.new_event_id()).collect();
        let b_events: Vec<EventId> = (0..50).map(|_| b.new_event_id()).collect();
        assert_eq!(a_events, b_events);
    }

    #[test]
    fn fixed_clock_with_different_seed_diverges() {
        // Negative control for AC-2.2: identical arguments must match, but
        // this doesn't mean the seed is ignored entirely.
        let a = FixedClock::new("2026-08-01T15:04:31.182Z", 7);
        let b = FixedClock::new("2026-08-01T15:04:31.182Z", 8);
        assert_ne!(a.new_scan_id(), b.new_scan_id());
    }

    // --- AC-2.3: exact RFC3339-with-milliseconds shape, character by
    // character, beyond the brief's spot checks. ---

    #[test]
    fn system_clock_rfc3339_is_fully_well_formed() {
        let s = SystemClock::default().now_rfc3339();
        assert_eq!(s.len(), 24, "got {s}");
        let bytes = s.as_bytes();
        for i in [0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18, 20, 21, 22] {
            assert!(
                bytes[i].is_ascii_digit(),
                "byte {i} of {s} should be a digit, got {}",
                bytes[i] as char
            );
        }
        assert_eq!(bytes[4], b'-');
        assert_eq!(bytes[7], b'-');
        assert_eq!(bytes[10], b'T');
        assert_eq!(bytes[13], b':');
        assert_eq!(bytes[16], b':');
        assert_eq!(bytes[19], b'.');
        assert_eq!(bytes[23], b'Z');
    }

    // --- Civil-time conversion, cross-checked against known epochs rather
    // than round-tripped against itself. Every expected string below was
    // independently verified with both `date -u -j -f "%Y-%m-%dT%H:%M:%SZ"
    // <input> +%s` (BSD date, this machine) and Python's
    // `datetime.strptime(...).replace(tzinfo=timezone.utc).timestamp()`
    // before being pasted in here; the two agreed on every case. ---

    #[test]
    fn format_rfc3339_millis_unix_epoch() {
        assert_eq!(format_rfc3339_millis(0, 0), "1970-01-01T00:00:00.000Z");
    }

    #[test]
    fn format_rfc3339_millis_leap_day() {
        // 2024-02-29T12:00:00Z -> 1709208000 (2024 is a leap year: divisible
        // by 4, not by 100).
        assert_eq!(
            format_rfc3339_millis(1_709_208_000, 250),
            "2024-02-29T12:00:00.250Z"
        );
    }

    #[test]
    fn format_rfc3339_millis_century_leap_year_boundary() {
        // 2000-01-01T00:00:00Z -> 946684800. 2000 is a leap year (divisible
        // by 400), which is the case the plain "divisible by 4" rule gets
        // wrong and the days-from-civil algorithm must get right via its
        // `doe/146_096` era-boundary term.
        assert_eq!(
            format_rfc3339_millis(946_684_800, 0),
            "2000-01-01T00:00:00.000Z"
        );
        // One second earlier must land on the last second of 1999, still
        // inside February's non-leap boundary from the *previous* year.
        assert_eq!(
            format_rfc3339_millis(946_684_799, 999),
            "1999-12-31T23:59:59.999Z"
        );
    }

    #[test]
    fn format_rfc3339_millis_century_non_leap_year() {
        // 1900-03-01T00:00:00Z -> -2203891200 (negative: pre-epoch). 1900 is
        // divisible by 100 but not by 400, so it is NOT a leap year --
        // February 1900 has 28 days. Also exercises the negative-epoch path
        // (`div_euclid`/`rem_euclid`).
        assert_eq!(
            format_rfc3339_millis(-2_203_891_200, 0),
            "1900-03-01T00:00:00.000Z"
        );
    }

    #[test]
    fn format_rfc3339_millis_pre_1970_negative_epoch() {
        // 1969-07-20T20:17:00Z -> -14182980 (Apollo 11 landing, chosen only
        // for being an easy-to-verify well-known pre-epoch timestamp).
        assert_eq!(
            format_rfc3339_millis(-14_182_980, 0),
            "1969-07-20T20:17:00.000Z"
        );
    }

    #[test]
    fn format_rfc3339_millis_recent_timestamp() {
        // 2026-07-31T18:22:05Z -> 1785522125.
        assert_eq!(
            format_rfc3339_millis(1_785_522_125, 500),
            "2026-07-31T18:22:05.500Z"
        );
    }

    // --- The real requirement per the M2 Task 1 dispatch: a `ScanId`
    // produced by `SystemClock` and by `FixedClock` must always round-trip
    // through `to_string()` -> `parse()`. This is what would have caught the
    // `from_ulid`-has-no-validation gap, independent of whether `from_ulid`
    // itself happens to be provably total. ---

    #[test]
    fn system_clock_scan_and_event_ids_round_trip() {
        let c = SystemClock::default();
        for _ in 0..25 {
            let scan = c.new_scan_id();
            assert_eq!(ScanId::from_str(&scan.to_string()).unwrap(), scan);
            let evt = c.new_event_id();
            assert_eq!(EventId::from_str(&evt.to_string()).unwrap(), evt);
        }
    }

    #[test]
    fn fixed_clock_scan_and_event_ids_round_trip_across_seeds() {
        // Sweep seeds including the extremes (0 and u64::MAX) and a spread
        // of bit patterns, and draw enough ids from each to cross a few
        // counter values too.
        for seed in [
            0u64,
            1,
            7,
            u64::MAX,
            u64::MAX >> 1,
            0xFFFF_0000_0000_0000, // top 16 bits set, low 48 clear
            0x0000_FFFF_FFFF_FFFF, // low 48 bits set, top 16 clear
        ] {
            let c = FixedClock::new("2026-08-01T15:04:31.182Z", seed);
            for _ in 0..10 {
                let scan = c.new_scan_id();
                assert_eq!(
                    ScanId::from_str(&scan.to_string()).unwrap(),
                    scan,
                    "seed={seed:#x} must round-trip: {scan}"
                );
                let evt = c.new_event_id();
                assert_eq!(
                    EventId::from_str(&evt.to_string()).unwrap(),
                    evt,
                    "seed={seed:#x} must round-trip: {evt}"
                );
            }
        }
    }

    #[test]
    fn fixed_clock_max_seed_produces_canonical_round_tripping_id() {
        // The specific case the dispatch calls out: a seed large enough that
        // its bits would land in the timestamp position. `from_parts` masks
        // `seed: u64` to 48 bits, so `u64::MAX`'s low 48 bits (all 1) give
        // the single largest reachable timestamp, `2^48 - 1`, whose top 3
        // bits are `0b111` -- '7' is the largest reachable first character,
        // still canonical. This pins that as defined, observable behaviour
        // rather than an accident nobody verified.
        let c = FixedClock::new("2026-08-01T15:04:31.182Z", u64::MAX);
        let id = c.new_scan_id();
        let s = id.to_string();
        assert!(
            s.starts_with("scan_7"),
            "expected the largest reachable first character '7', got {s}"
        );
        assert_eq!(
            ScanId::from_str(&s).unwrap(),
            id,
            "must round-trip at the maximal seed: {s}"
        );
    }
}
