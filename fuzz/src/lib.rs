#![forbid(unsafe_code)]

//! Shared instrumentation for bathy's fuzz targets.
//!
//! # Why a fuzz target needs counters
//!
//! This project has already shipped one coverage claim that was false. A
//! property-test strategy over `interpret` was audited at 4096 cases and
//! found to produce **6 non-empty results and 0 spans past byte 6** -- it
//! had never once reached the offset arithmetic it claimed to guard, and
//! nothing about the test said so, because a passing test that reaches
//! nothing looks exactly like a passing test that reaches everything. (The
//! replacement strategy, and the direct measurement that backs it, are in
//! `crates/bathy-interpret/src/interpret.rs`'s test module.)
//!
//! A fuzz target has the same failure mode and fewer defences: libFuzzer
//! reports executions and edge counts for the *whole process*, which
//! includes `serde_json`'s parser, the allocator, and the harness itself.
//! "2.4M execs, 1831 edges" is entirely consistent with every single input
//! bouncing off the first `if` in the parser under test.
//!
//! So each target counts what it actually reached, in its own terms -- how
//! many inputs produced a *match* rather than an empty vector, how many
//! produced a span deep enough to have gone through a rule's own offset
//! arithmetic, which rules fired at all -- and prints those counts on
//! demand. The numbers are the evidence; the exec rate is not.
//!
//! # Turning it on
//!
//! Set `BATHY_FUZZ_STATS=1`. A line goes to stderr every
//! `BATHY_FUZZ_STATS_EVERY` executions (default 100000). Set that to `1`
//! when replaying a finite corpus with `-runs=0`, where the last line
//! printed is the total.
//!
//! Nothing is printed when the variable is unset, so a CI fuzz run stays
//! quiet and an interactive one can be made to talk.

use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

/// Upper bound on named counters per target. Raising it costs 8 bytes of
/// static per slot; it is fixed only so `Stats::new` can be a `const fn`
/// and live in a `static`, which is what makes the counters free of any
/// initialisation branch on the hot path.
pub const MAX_COUNTERS: usize = 16;

/// Upper bound on `flags` -- the "did this ever happen at all" bitset, used
/// for things there is one of per named case rather than a count: which
/// interpretation rules fired, which error variants were reached.
pub const MAX_FLAGS: usize = 64;

/// One target's instrumentation.
pub struct Stats {
    target: &'static str,
    /// Names for `counts`, in index order. `counts[i]` is `labels[i]`.
    labels: &'static [&'static str],
    /// Names for the bits of `flags`, in bit order, when they are known at
    /// compile time.
    flag_labels: &'static [&'static str],
    /// Names for the bits of `flags` when they are not: `interpret`'s flags
    /// are one per registered rule, and the rule registry is a runtime
    /// iterator by design (`bathy_interpret::all_rules`), precisely so a
    /// new rule cannot be added without every consumer that enumerates
    /// rules seeing it. Copying the ids into a `const` here would recreate
    /// the staleness that registry exists to prevent.
    named_flags: OnceLock<Vec<&'static str>>,
    execs: AtomicU64,
    counts: [AtomicU64; MAX_COUNTERS],
    flags: AtomicU64,
}

impl Stats {
    pub const fn new(
        target: &'static str,
        labels: &'static [&'static str],
        flag_labels: &'static [&'static str],
    ) -> Self {
        Self {
            target,
            labels,
            flag_labels,
            named_flags: OnceLock::new(),
            execs: AtomicU64::new(0),
            counts: [const { AtomicU64::new(0) }; MAX_COUNTERS],
            flags: AtomicU64::new(0),
        }
    }

    /// Adds one to counter `index`. Indices are `const`s declared next to
    /// the target's `LABELS`, so this is a store to a fixed address rather
    /// than a name lookup.
    #[inline]
    pub fn bump(&self, index: usize) {
        self.add(index, 1);
    }

    #[inline]
    pub fn add(&self, index: usize, n: u64) {
        if index < MAX_COUNTERS {
            self.counts[index].fetch_add(n, Ordering::Relaxed);
        }
    }

    /// Records that case `bit` was reached at least once.
    #[inline]
    pub fn flag(&self, bit: usize) {
        if bit < MAX_FLAGS {
            self.flags.fetch_or(1u64 << bit, Ordering::Relaxed);
        }
    }

    /// Supplies the flag-bit names for a target whose cases are a runtime
    /// registry rather than a `const` list. First call wins; later calls
    /// are ignored, so this is safe to call from a lazy initialiser.
    pub fn name_flags(&self, names: Vec<&'static str>) {
        let _ = self.named_flags.set(names);
    }

    /// Call once per fuzz execution, last. Increments the execution count
    /// and prints a summary every `BATHY_FUZZ_STATS_EVERY` executions.
    #[inline]
    pub fn tick(&self) {
        let n = self.execs.fetch_add(1, Ordering::Relaxed) + 1;
        let Some(every) = reporting_interval() else {
            return;
        };
        if n.is_multiple_of(every) {
            self.report(n);
        }
    }

    fn report(&self, execs: u64) {
        let mut line = format!("[fuzz-stats {}] execs={execs}", self.target);
        for (i, label) in self.labels.iter().enumerate() {
            let v = self.counts[i].load(Ordering::Relaxed);
            line.push_str(&format!(" {label}={v}"));
        }
        let flags = self.flags.load(Ordering::Relaxed);
        let flag_labels: &[&str] = self
            .named_flags
            .get()
            .map_or(self.flag_labels, Vec::as_slice);
        if !flag_labels.is_empty() {
            let reached: Vec<&str> = flag_labels
                .iter()
                .enumerate()
                .filter(|(bit, _)| flags & (1u64 << bit) != 0)
                .map(|(_, name)| *name)
                .collect();
            line.push_str(&format!(
                " reached={}/{} [{}]",
                reached.len(),
                flag_labels.len(),
                reached.join(",")
            ));
        }
        // `eprintln!` and not `stderr().write_all`: this is a fuzz binary,
        // not a libtest test, so nothing is capturing stdio and there is no
        // passing-test capture to be discarded by. (The rule that forbids
        // the print-macro form -- `captured-skip-message` in
        // `xtask/src/phrases.rs` -- is about a *skip reason in a test*, and
        // its roots are `crates` and `xtask`, not this directory.)
        eprintln!("{line}");
    }
}

/// `None` when stats are off. Read once: this is on the hot path.
fn reporting_interval() -> Option<u64> {
    static INTERVAL: OnceLock<Option<u64>> = OnceLock::new();
    *INTERVAL.get_or_init(|| {
        std::env::var_os("BATHY_FUZZ_STATS")?;
        let every = std::env::var("BATHY_FUZZ_STATS_EVERY")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|v| *v > 0)
            .unwrap_or(100_000);
        Some(every)
    })
}
