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
        // `eprintln!` and not `stderr().write_all`: this is a fuzz binary,
        // not a libtest test, so nothing is capturing stdio and there is no
        // passing-test capture to be discarded by. (The rule that forbids
        // the print-macro form -- `captured-skip-message` in
        // `xtask/src/phrases.rs` -- is about a *skip reason in a test*, and
        // its roots are `crates` and `xtask`, not this directory.)
        eprintln!("{}", self.report_line(execs));
    }

    /// The reported line, as a value.
    ///
    /// Split out from the printing so it can be asserted. An instrument
    /// whose output nothing checks is the thing this module exists to
    /// argue against, and its most important output -- `reached=0/N` --
    /// is the one no ordinary run ever shows a reader.
    pub fn report_line(&self, execs: u64) -> String {
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
        line
    }
}

/// Whether any object in `text` carries the same key twice.
///
/// # Why this is a scanner and not a `serde_json` call
///
/// `serde_json::Value` keeps the last of a repeated key, so by the time a
/// document is a `Value` the evidence is gone -- which is exactly why a
/// duplicate key is the one input shape whose canonical output is not a
/// permutation of the input's own tokens, and worth counting.
///
/// The first version of this counted punctuation: `opens > 0 &&
/// colons > commas + opens - 1`. A review fed it `{"a":"x:y"}` -- one object,
/// no duplicate key anywhere -- and the `duplicate_keys` flag came up set. So
/// the reported "9/9 JSON shapes" was 8 shapes plus a heuristic that any
/// colon inside a string value satisfies: a coverage claim a decoration input
/// meets, which is the defect class the whole instrumentation argues against.
///
/// # What it assumes
///
/// That `text` is already valid JSON -- every caller checks that first, by
/// parsing it. A scanner is allowed to be simple about malformed input
/// because malformed input never reaches it; what it may NOT be is wrong
/// about the shapes it names. Keys are compared *unescaped*, because `"a"`
/// and `"a"` are the same key and `serde_json` collapses them.
pub fn has_duplicate_keys(text: &str) -> bool {
    // One frame per open `{` or `[`. `Some(keys)` is an object.
    let mut stack: Vec<Option<Vec<String>>> = Vec::new();
    let mut expecting_key = false;
    let mut chars = text.char_indices().peekable();
    while let Some((_, c)) = chars.next() {
        match c {
            '{' => {
                stack.push(Some(Vec::new()));
                expecting_key = true;
            }
            '[' => {
                stack.push(None);
                expecting_key = false;
            }
            '}' | ']' => {
                stack.pop();
                expecting_key = false;
            }
            // Whether this comma separates members or array elements is
            // decided by the frame, at the point of use, and not here: an
            // extra `matches!` on the frame at this line is a second copy of
            // the same decision, and a copy no fixture can make disagree
            // with the original is a branch nothing tests.
            ',' => expecting_key = true,
            '"' => {
                let mut key = String::new();
                while let Some((_, c)) = chars.next() {
                    match c {
                        '"' => break,
                        '\\' => match chars.next().map(|(_, e)| e) {
                            Some('u') => {
                                let mut hex = String::new();
                                for _ in 0..4 {
                                    if let Some((_, h)) = chars.next() {
                                        hex.push(h);
                                    }
                                }
                                let unit = u32::from_str_radix(&hex, 16).unwrap_or(0xFFFD);
                                // A surrogate pair is one character; a lone
                                // surrogate cannot occur in valid JSON, and
                                // is folded to the replacement character
                                // rather than guessed at.
                                let decoded = if (0xD800..0xDC00).contains(&unit) {
                                    let mut low = String::new();
                                    if chars.peek().map(|(_, c)| *c) == Some('\\') {
                                        chars.next();
                                        chars.next();
                                        for _ in 0..4 {
                                            if let Some((_, h)) = chars.next() {
                                                low.push(h);
                                            }
                                        }
                                    }
                                    u32::from_str_radix(&low, 16)
                                        .ok()
                                        .map(|low| {
                                            0x10000 + ((unit - 0xD800) << 10) + (low - 0xDC00)
                                        })
                                        .unwrap_or(0xFFFD)
                                } else {
                                    unit
                                };
                                key.push(char::from_u32(decoded).unwrap_or('\u{FFFD}'));
                            }
                            Some('b') => key.push('\u{8}'),
                            Some('f') => key.push('\u{c}'),
                            Some('n') => key.push('\n'),
                            Some('r') => key.push('\r'),
                            Some('t') => key.push('\t'),
                            Some(other) => key.push(other),
                            None => break,
                        },
                        other => key.push(other),
                    }
                }
                if expecting_key && let Some(Some(keys)) = stack.last_mut() {
                    if keys.contains(&key) {
                        return true;
                    }
                    keys.push(key);
                    expecting_key = false;
                }
            }
            _ => {}
        }
    }
    false
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_and_flags_are_reported_under_their_own_names() {
        static S: Stats = Stats::new("t", &["parsed", "loaded"], &["ok:a", "ok:b"]);
        S.bump(0);
        S.add(1, 7);
        S.flag(1);
        assert_eq!(
            S.report_line(3),
            "[fuzz-stats t] execs=3 parsed=1 loaded=7 reached=1/2 [ok:b]"
        );
    }

    /// The case the instrument exists for. A target that reached nothing
    /// must SAY it reached nothing: `reached=0/2` is the most important
    /// value this line can carry, and a report that omits the clause
    /// entirely when the count is zero goes quiet in exactly the situation
    /// it was built to make visible.
    /// Each case names a way the punctuation heuristic this replaced was
    /// wrong, or a way a naive scanner would be. The first is the review's
    /// own reproduction.
    #[test]
    fn duplicate_keys_are_the_thing_detected_and_not_a_colon() {
        for (json, expected) in [
            (r#"{"a":"x:y"}"#, false),
            (r#"{"a":1,"a":2}"#, true),
            // Same key in two DIFFERENT objects is not a duplicate.
            (r#"{"a":{"b":1},"c":{"b":2}}"#, false),
            // Nested inside an array, which a depth-blind scanner misses.
            (r#"{"a":[{"b":1,"b":2}]}"#, true),
            // A key equal only after unescaping. `serde_json` collapses
            // these, so the canonical form is short one member.
            (r#"{"a":1,"a":2}"#, true),
            // Braces, colons, commas and quotes inside a STRING VALUE are
            // not structure. This is the shape a text heuristic reads as a
            // duplicated key.
            (r#"{"a":"{\"b\":1,\"b\":2}"}"#, false),
            (r#"{"a:b":1,"c":2}"#, false),
            // An array of objects that each repeat nothing.
            (r#"[{"a":1},{"a":2}]"#, false),
            // Array ELEMENTS are not keys, however many times they repeat --
            // three of them, because two can pass a scanner that starts
            // recording one element late.
            (r#"{"k":["a","a"]}"#, false),
            (r#"["a","a","a"]"#, false),
            // A nested object must be POPPED: the outer `"b"` here belongs to
            // the outer object, which does not have one, and a scanner that
            // never closes a frame reads it as a repeat of the inner one.
            (r#"{"a":{"b":1},"b":2}"#, false),
            // A value equal to its own key is not a repeated key.
            (r#"{"a":"a"}"#, false),
            (r#"{}"#, false),
            (r#""just a string""#, false),
            (r#"{"a":1,"b":{"c":2,"c":3}}"#, true),
        ] {
            assert_eq!(has_duplicate_keys(json), expected, "{json}");
        }
    }

    #[test]
    fn a_target_that_reached_nothing_still_reports_the_denominator() {
        static S: Stats = Stats::new("t", &[], &["ok:a", "ok:b"]);
        let line = S.report_line(1);
        assert!(line.contains("reached=0/2 []"), "{line}");
    }
}
