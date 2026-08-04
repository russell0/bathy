//! All time and identifier generation flows through [`Clock`].
//!
//! Nothing else in the workspace may call `SystemTime::now()` or construct a
//! random ULID directly (`ulid::Generator`, or `Ulid::new()` should a future
//! version of the `ulid` crate reintroduce it). Injecting both through one
//! trait is what makes an event log byte-comparable between a recorded run
//! and a replayed one -- the foundation of this project's
//! reproducible-interpretation claim. CI enforces the "nowhere else" half of
//! that with a scan over `crates/` and `xtask/` excluding this file --
//! `cargo run -p xtask -- check-phrases`, rule `clock-only-time-and-ids`
//! (AC-2.1), which `.github/workflows/ci.yml` invokes rather than
//! reimplementing.

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

    /// The same instant as [`Clock::now_rfc3339`], as milliseconds since the
    /// Unix epoch.
    ///
    /// Exists because not every consumer of "now" is writing a timestamp into
    /// an event. `bathy-mcp`'s approval gate needs a *duration* comparison --
    /// has this token's time-to-live elapsed -- and arithmetic on a formatted
    /// RFC 3339 string is not that. Before this method existed it called
    /// `SystemTime::now()` directly, which is the one thing this trait exists
    /// to prevent: the AC-2.1 check was red from `89142bf` to the M5 blocker
    /// wave because a wall-clock need had no injected answer. Adding the
    /// method is the fix; exempting the call site would have been the
    /// band-aid, because an un-injected clock is un-injected whether it lands
    /// in a log record or in an expiry decision.
    ///
    /// Pre-epoch instants saturate to `0`. [`FixedClock`] accepts any
    /// shape-valid RFC 3339 timestamp, including `1969-…`, and this is a
    /// count of milliseconds *since* the epoch; a test clock set before it has
    /// no meaningful positive value and none is invented.
    fn now_unix_millis(&self) -> u64;
}

/// C2: the whole-branch review found no `Clock for Arc<T>` (or `Box<T>`,
/// `&T`) anywhere in this crate, and `bathy-store::TaskStore::open` took
/// `clock: Box<dyn Clock>` *by value* -- which means it could never be
/// handed the same clock instance a caller was also using for an
/// `EventLog`. Two independently-constructed `SystemClock`s means two
/// independent `ulid::Generator`s, so ULID monotonicity across a scan is
/// lost; two `FixedClock`s built with the same seed produce
/// byte-identical id sequences, which is exactly what forced
/// `bathy-store`'s own cross-connection race test to use disjoint seeds as
/// a workaround (see `tasks.rs`'s
/// `two_independent_connections_racing_on_the_same_key_still_yield_exactly_one_scan`).
///
/// `Arc<T>` is the shape that actually lets one clock be handed to more
/// than one owner: `TaskStore` needs to hold its clock for its whole
/// lifetime (so `Box<dyn Clock>`, not a borrow), while an `EventLog` caller
/// needs `&dyn Clock` per call. `Arc<dyn Clock>` satisfies both --
/// `TaskStore` can own a clone, and `&*shared`/`shared.as_ref()` hands out
/// the `&dyn Clock` `EventLog::append` wants -- and this blanket impl is
/// what lets `Arc<dyn Clock>` itself satisfy a generic `C: Clock` bound
/// too, not just get used through explicit deref.
impl<T: Clock + ?Sized> Clock for std::sync::Arc<T> {
    fn now_rfc3339(&self) -> String {
        (**self).now_rfc3339()
    }
    fn new_scan_id(&self) -> ScanId {
        (**self).new_scan_id()
    }
    fn new_event_id(&self) -> EventId {
        (**self).new_event_id()
    }
    fn now_unix_millis(&self) -> u64 {
        (**self).now_unix_millis()
    }
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
        // runs. Smaller item A (whole-branch review): the previous fallback
        // hand-rolled `Ulid::from_parts(now_ms, 0)` from a fresh
        // `SystemTime::now()` read taken *outside* the generator -- which
        // works, but bypasses the generator's own overflow-handling state,
        // leaving `self.previous` stale (still pointing at the id that just
        // overflowed) instead of advancing it to the id actually returned.
        // `Overflow::commit_overflow_random` (`ulid-3.0.0/src/generator.rs:168-175`)
        // is the generator's own resolution for exactly this case: it
        // advances into the next millisecond via the SAME `previous`-state
        // machinery `generate()` itself uses, so the fallback path and the
        // normal path stay in sync instead of the fallback silently
        // desyncing the generator for whichever call comes after it.
        g.generate()
            .unwrap_or_else(|overflow| overflow.commit_overflow_random())
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
    fn now_unix_millis(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_millis().min(u128::from(u64::MAX)) as u64)
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
///
/// Smaller item C (whole-branch review): the 24-byte
/// `YYYY-MM-DDTHH:MM:SS.mmmZ` shape this function promises breaks for years
/// `<= -1000`, because `{:04}` only zero-pads and does not truncate --
/// `y = -1000` renders as `-1000`, five digits, not four. Not reachable via
/// [`SystemClock`], the only caller in this crate: `epoch_secs` there always
/// comes from `SystemTime::now()`, i.e. the present day, many millennia
/// inside the safe domain. Documented rather than fixed because the fix
/// (deciding how a five-digit year should even render in this format) is a
/// design question with no caller that needs an answer today.
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
    /// `now`, as milliseconds since the Unix epoch. Computed once in
    /// [`FixedClock::new`], after `now` has been validated, so
    /// [`Clock::now_unix_millis`] cannot disagree with
    /// [`Clock::now_rfc3339`]: both are derived from the same validated
    /// string rather than from two independent readings.
    now_millis: u64,
    counter: AtomicU64,
    seed: u64,
}

/// C3: the Global Constraint promises RFC 3339 UTC with milliseconds for
/// every timestamp, and `event.rs`'s own doc comment on `Event::timestamp`
/// names this exact type as the place that obligation was deferred to
/// ("`Clock` ... is created in M2 Task 1, and that is the right place to
/// validate it"). Before this fix `FixedClock::new` stored its `now`
/// argument verbatim with no check at all -- `FixedClock::new("banana", _)`
/// constructed successfully, and "banana" then wrote straight through
/// `EventLog::append` into an on-disk event's `timestamp` field.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ClockError {
    #[error(
        "timestamp {input:?} is not RFC 3339 UTC with milliseconds \
         (expected exactly YYYY-MM-DDTHH:MM:SS.mmmZ, e.g. 2026-08-01T15:04:31.182Z)"
    )]
    InvalidTimestamp { input: String },
}

/// Mirrors the exact shape `format_rfc3339_millis` above always produces:
/// 24 bytes, digits everywhere but four fixed punctuation positions, and
/// (per this function's own extra checks, beyond pure shape) each numeric
/// field inside the range that shape allows. This is a format check, not
/// full calendar arithmetic -- it does not reject `2026-02-30` the way a
/// real calendar library would -- because the concrete defect C3 closes is
/// a value that is not a timestamp at all (`"banana"`, an empty string, a
/// Unix timestamp typed in by mistake) silently reaching an event's
/// `timestamp` field, not calendar correctness for well-formed-looking
/// input.
fn validate_rfc3339_millis(s: &str) -> Result<(), ClockError> {
    let err = || ClockError::InvalidTimestamp {
        input: s.to_owned(),
    };
    let b = s.as_bytes();
    if b.len() != 24 {
        return Err(err());
    }
    for i in [0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18, 20, 21, 22] {
        if !b[i].is_ascii_digit() {
            return Err(err());
        }
    }
    if b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b[19] != b'.'
        || b[23] != b'Z'
    {
        return Err(err());
    }
    let two = |i: usize| -> u32 { s[i..i + 2].parse().expect("checked ascii digits above") };
    let month = two(5);
    let day = two(8);
    let hour = two(11);
    let minute = two(14);
    let second = two(17);
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || hour > 23
        || minute > 59
        // 60 tolerates a leap second; `format_rfc3339_millis` itself never
        // emits one, but rejecting a real leap second reading would be a
        // false negative this check has no reason to introduce.
        || second > 60
    {
        return Err(err());
    }
    Ok(())
}

/// The inverse of [`format_rfc3339_millis`], for a string that has already
/// passed [`validate_rfc3339_millis`].
///
/// Uses Howard Hinnant's `days_from_civil` -- the decode direction of the
/// `civil_from_days` algorithm `format_rfc3339_millis` runs in the encode
/// direction -- so the two are the same calendar, not two calendars that
/// happen to agree on the dates anyone tested. The tests below check absolute
/// values obtained independently (Python's `datetime`), not only that the pair
/// round-trips against itself, because a matched pair of inverse errors
/// round-trips perfectly.
///
/// Saturates to `0` before the epoch: the result is a count of milliseconds
/// *since* 1970, and `FixedClock` will accept `1969-12-31T23:59:59.999Z`.
fn epoch_millis_from_rfc3339(s: &str) -> u64 {
    let n = |i: usize, len: usize| -> i64 {
        s[i..i + len]
            .parse()
            .expect("validated as ascii digits before this is called")
    };
    let (year, month, day) = (n(0, 4), n(5, 2), n(8, 2));
    let (hour, minute, second, millis) = (n(11, 2), n(14, 2), n(17, 2), n(20, 3));

    // `days_from_civil`: March-based year, so a leap day is the last day of
    // the internal year and needs no special case anywhere.
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;

    let secs = days * 86_400 + hour * 3_600 + minute * 60 + second;
    let total = secs
        .checked_mul(1_000)
        .and_then(|ms| ms.checked_add(millis));
    u64::try_from(total.unwrap_or(0)).unwrap_or(0)
}

impl FixedClock {
    pub fn new(now: &str, seed: u64) -> Result<Self, ClockError> {
        validate_rfc3339_millis(now)?;
        Ok(Self {
            now: now.to_owned(),
            now_millis: epoch_millis_from_rfc3339(now),
            counter: AtomicU64::new(0),
            seed,
        })
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
    fn now_unix_millis(&self) -> u64 {
        self.now_millis
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    // --- Brief's Step 1 tests, verbatim ---

    #[test]
    fn fixed_clock_is_reproducible() {
        let a = FixedClock::new("2026-08-01T15:04:31.182Z", 7).unwrap();
        let b = FixedClock::new("2026-08-01T15:04:31.182Z", 7).unwrap();
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
        let c = FixedClock::new("2026-08-01T15:04:31.182Z", 7).unwrap();
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
        let a = FixedClock::new("2026-08-01T15:04:31.182Z", 7).unwrap();
        let b = FixedClock::new("2026-08-01T15:04:31.182Z", 7).unwrap();
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
        let a = FixedClock::new("2026-08-01T15:04:31.182Z", 7).unwrap();
        let b = FixedClock::new("2026-08-01T15:04:31.182Z", 8).unwrap();
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
            let c = FixedClock::new("2026-08-01T15:04:31.182Z", seed).unwrap();
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

    // --- C2: `Arc<dyn Clock>` must itself satisfy `Clock`, both through a
    // generic bound and behaviorally (delegating to the wrapped clock, not
    // some independent state of its own). ---

    #[test]
    fn arc_of_a_clock_satisfies_a_generic_clock_bound() {
        fn assert_is_clock<C: Clock>(_: &C) {}
        let shared: std::sync::Arc<dyn Clock> =
            std::sync::Arc::new(FixedClock::new("2026-08-01T15:04:31.182Z", 7).unwrap());
        assert_is_clock(&shared);
    }

    #[test]
    fn arc_of_a_clock_delegates_to_the_wrapped_clock_not_a_copy() {
        let inner = FixedClock::new("2026-08-01T15:04:31.182Z", 7);
        let shared: std::sync::Arc<dyn Clock> = std::sync::Arc::new(inner.unwrap());
        assert_eq!(shared.now_rfc3339(), "2026-08-01T15:04:31.182Z");

        // Two clones of the SAME `Arc` must draw from the SAME underlying
        // counter -- proving `Clock for Arc<T>` delegates through to the one
        // wrapped instance rather than each clone somehow getting its own
        // state.
        let a = std::sync::Arc::clone(&shared);
        let b = std::sync::Arc::clone(&shared);
        let ids: Vec<_> = [a, b].iter().map(|c| c.new_scan_id()).collect();
        assert_ne!(
            ids[0], ids[1],
            "two clones of one shared Arc<dyn Clock> must draw distinct, \
             monotonically advancing ids from the one underlying generator"
        );
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
        let c = FixedClock::new("2026-08-01T15:04:31.182Z", u64::MAX).unwrap();
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

    // --- C3: `FixedClock::new` must reject a timestamp that is not RFC
    // 3339 UTC with milliseconds, not just store whatever string it is
    // handed. The concrete case named in the finding is `"banana"`. ---

    #[test]
    fn fixed_clock_rejects_banana() {
        match FixedClock::new("banana", 7) {
            Err(e) => assert_eq!(
                e,
                ClockError::InvalidTimestamp {
                    input: "banana".to_string()
                }
            ),
            Ok(_) => panic!("\"banana\" must not construct a FixedClock"),
        }
    }

    #[test]
    fn fixed_clock_accepts_a_well_formed_timestamp() {
        assert!(FixedClock::new("2026-08-01T15:04:31.182Z", 7).is_ok());
    }

    #[test]
    fn fixed_clock_rejects_an_empty_string() {
        assert!(FixedClock::new("", 7).is_err());
    }

    #[test]
    fn fixed_clock_rejects_a_timestamp_missing_milliseconds() {
        // RFC 3339 alone would accept this; the Global Constraint requires
        // milliseconds specifically, and `format_rfc3339_millis` never
        // produces anything shorter than 24 bytes.
        assert!(FixedClock::new("2026-08-01T15:04:31Z", 7).is_err());
    }

    #[test]
    fn fixed_clock_rejects_a_non_utc_offset() {
        // A real timezone offset instead of `Z` is well-formed RFC 3339 in
        // general, but not the UTC-with-milliseconds shape this crate
        // publishes and `format_rfc3339_millis` always emits.
        assert!(FixedClock::new("2026-08-01T15:04:31.182+02:00", 7).is_err());
    }

    #[test]
    fn fixed_clock_rejects_a_bare_unix_timestamp() {
        // The other realistic mistake this guards against: a caller passing
        // an epoch-seconds integer (as a string) instead of an RFC 3339
        // stamp.
        assert!(FixedClock::new("1785522125", 7).is_err());
    }

    #[test]
    fn fixed_clock_rejects_out_of_range_calendar_fields() {
        for bad in [
            "2026-13-01T00:00:00.000Z", // month 13
            "2026-00-01T00:00:00.000Z", // month 0
            "2026-01-32T00:00:00.000Z", // day 32
            "2026-01-00T00:00:00.000Z", // day 0
            "2026-01-01T24:00:00.000Z", // hour 24
            "2026-01-01T00:60:00.000Z", // minute 60
            "2026-01-01T00:00:61.000Z", // second 61
        ] {
            assert!(
                FixedClock::new(bad, 7).is_err(),
                "{bad} must be rejected as an invalid timestamp"
            );
        }
    }

    #[test]
    fn fixed_clock_accepts_a_leap_second_reading() {
        // Format-valid and within the tolerated range (`second <= 60`) even
        // though `format_rfc3339_millis` itself never emits one.
        assert!(FixedClock::new("2026-01-01T00:00:60.000Z", 7).is_ok());
    }

    #[test]
    fn every_string_system_clock_or_format_rfc3339_millis_can_produce_is_accepted() {
        // Negative-control sweep for the validator: it must never reject a
        // shape this crate's own encoder actually produces, across a spread
        // of epochs (including the negative/pre-1970 ones already exercised
        // above) and millisecond values.
        for (secs, millis) in [
            (0, 0),
            (1_709_208_000, 250),
            (946_684_800, 0),
            (946_684_799, 999),
            (-2_203_891_200, 0),
            (-14_182_980, 0),
            (1_785_522_125, 500),
        ] {
            let s = format_rfc3339_millis(secs, millis);
            assert!(
                FixedClock::new(&s, 7).is_ok(),
                "format_rfc3339_millis produced {s:?}, which the validator rejected"
            );
        }
    }

    /// Absolute values, obtained from Python's `datetime` rather than from
    /// this file's own encoder. A decoder tested only against its own inverse
    /// passes with both halves wrong in the same direction.
    #[test]
    fn fixed_clock_unix_millis_match_values_computed_outside_this_file() {
        for (stamp, expected) in [
            ("1970-01-01T00:00:00.000Z", 0_u64),
            ("2026-08-01T15:04:31.182Z", 1_785_596_671_182),
            ("2000-02-29T12:00:00.500Z", 951_825_600_500),
            ("2026-08-04T00:00:00.001Z", 1_785_801_600_001),
            ("9999-12-31T23:59:59.999Z", 253_402_300_799_999),
        ] {
            assert_eq!(
                FixedClock::new(stamp, 7).unwrap().now_unix_millis(),
                expected,
                "{stamp}"
            );
        }
    }

    #[test]
    fn a_fixed_clock_reports_one_instant_two_ways_not_two_instants() {
        for stamp in [
            "1970-01-01T00:00:00.000Z",
            "2026-08-01T15:04:31.182Z",
            "2000-02-29T12:00:00.500Z",
            "2038-01-19T03:14:07.999Z",
        ] {
            let c = FixedClock::new(stamp, 7).unwrap();
            let ms = c.now_unix_millis();
            assert_eq!(
                format_rfc3339_millis((ms / 1_000) as i64, (ms % 1_000) as u32),
                c.now_rfc3339(),
                "the two accessors must name the same instant"
            );
        }
    }

    #[test]
    fn a_pre_epoch_fixed_clock_saturates_at_zero_rather_than_wrapping() {
        // `u64` cannot hold a negative count of milliseconds since 1970, and
        // wrapping would put a test clock set to 1969 roughly 584 million
        // years in the future -- which would make every time-to-live in the
        // workspace look unexpired forever.
        for stamp in ["1969-12-31T23:59:59.999Z", "1900-01-01T00:00:00.000Z"] {
            assert_eq!(FixedClock::new(stamp, 7).unwrap().now_unix_millis(), 0);
        }
    }

    #[test]
    fn a_system_clock_reports_one_instant_two_ways_not_two_instants() {
        let c = SystemClock::default();
        let ms = c.now_unix_millis();
        let from_string = epoch_millis_from_rfc3339(&c.now_rfc3339());
        // Two separate readings of a running clock, so not equality -- but a
        // `now_unix_millis` returning seconds, microseconds, or a value from
        // a different epoch is off by orders of magnitude, not by a second.
        assert!(
            from_string.abs_diff(ms) < 5_000,
            "now_unix_millis()={ms} and now_rfc3339()={} disagree by more than five seconds",
            c.now_rfc3339()
        );
    }
}
