#![no_main]
#![forbid(unsafe_code)]

//! Fuzzes `bathy_interpret::interpret` -- AC-7.7 and AC-7.9.
//!
//! Interpretation consumes attacker-controlled bytes by definition: its
//! whole input is the response side of a probe, sent by the thing being
//! scanned. A panic here is a denial of service triggered by the target.
//!
//! # Why the span assertion is the point of this target
//!
//! `Interpretation::matched_span` is a byte range into `capture.response`,
//! and every consumer treats it as one: `explain`-style output slices the
//! response with it to show the operator the bytes that justified a claim.
//! An out-of-range span is therefore not a cosmetic defect, it is a panic
//! in someone else's code.
//!
//! This has already happened here. `bathy-interpret` was found citing the
//! wrong bytes because offsets computed over `String::from_utf8_lossy`
//! output were used as indices into the *original* slice -- U+FFFD is three
//! bytes where the byte it replaced was one, so a single stray `0x80`
//! anywhere in a response shifted every subsequent span. Seven
//! span-corrupting mutants were found across three review rounds. The
//! assertion below is the one that dies on all of them, and it slices the
//! real response rather than only comparing integers, because slicing is
//! what a consumer does.

use std::sync::OnceLock;

use bathy_fuzz::Stats;
use bathy_interpret::{all_rules, explain, interpret, known_probe_ids};
use bathy_types::{ProbeCapture, Transport};
use libfuzzer_sys::fuzz_target;

const CAPTURES: usize = 0;
const NON_EMPTY_INPUTS: usize = 1;
const INTERPRETATIONS: usize = 2;
const DEEP_SPANS: usize = 3;
const NAMED_PRODUCT: usize = 4;
const NAMED_VERSION: usize = 5;

const LABELS: &[&str] = &[
    // Inputs are counted by libFuzzer; these are what the input *reached*.
    "captures",
    // The number that decides whether this target is worth anything: how
    // many inputs produced at least one interpretation rather than landing
    // in `interpret`'s empty-vector path (AC-4.13's "never guess").
    "matched_inputs",
    "interpretations",
    // A span ending past byte 6 cannot come from a rule that matched only a
    // fixed short prefix; it means the input reached a rule's own offset
    // arithmetic -- the exact code the seven historical span mutants lived
    // in. This is the same discriminator `crates/bathy-interpret`'s own
    // strategy-quality test uses, for the same reason.
    "deep_spans",
    "named_product",
    "named_version",
];

/// Which rules fired at all, as a bitset over `all_rules()` order. An
/// `interpret` fuzz run that reaches only `http.protocol.bare.v1` has
/// covered one thirteenth of the matching code and should not be reported
/// as having fuzzed interpretation.
fn rule_ids() -> &'static [&'static str] {
    static IDS: OnceLock<Vec<&'static str>> = OnceLock::new();
    IDS.get_or_init(|| {
        let ids: Vec<&'static str> = all_rules().map(|d| d.id).collect();
        STATS.name_flags(ids.clone());
        ids
    })
}

static STATS: Stats = Stats::new("interpret", LABELS, &[]);

fuzz_target!(|data: &[u8]| {
    // Once per execution, BEFORE anything can fail to match. `rule_ids()` is
    // what supplies `Stats` with its flag labels, and it used to be called
    // only from inside the `for i in &out` loop below -- so a run in which
    // nothing ever matched left `flag_labels` empty and `Stats::report`
    // skipped the whole `reached=` clause. The instrument built to make
    // "this target reached nothing" visible printed nothing in exactly that
    // case, and `fuzz/README.md` calls `reached=13/13` the load-bearing
    // figure. Zero is the most important value it can report.
    let rules = rule_ids();

    // Every probe id the rule set knows, read from the rule set itself
    // rather than written out here. A ninth protocol added in v0.2 is
    // fuzzed by this target the day it lands; a hard-coded list would have
    // gone stale silently, which is the failure mode this repository has
    // hit repeatedly in other registries.
    for probe_id in known_probe_ids() {
        let capture = ProbeCapture {
            probe_id,
            transport: Transport::Tcp,
            // `interpret` does not read `port` today. Deriving it from the
            // input rather than fixing it at 80 means a future port-gated
            // rule is fuzzed over more than one value without this target
            // needing to be remembered.
            port: u16::from_be_bytes([
                data.first().copied().unwrap_or(0),
                data.get(1).copied().unwrap_or(0),
            ]),
            request: None,
            response: data.to_vec(),
            elapsed_micros: 0,
            truncated: false,
        };

        let out = interpret(&capture);
        STATS.bump(CAPTURES);
        if !out.is_empty() {
            STATS.bump(NON_EMPTY_INPUTS);
        }
        STATS.add(INTERPRETATIONS, out.len() as u64);

        for i in &out {
            // AC-7.9, in three escalating forms. The first two are the
            // range arithmetic; the third is what a consumer actually does
            // with the span, and is the only one that would also catch a
            // span that is in range but not on the bytes it claims.
            assert!(
                i.matched_span.start <= i.matched_span.end,
                "rule {} produced an inverted span {:?} over {} response byte(s)",
                i.rule_id,
                i.matched_span,
                capture.response.len()
            );
            assert!(
                i.matched_span.end <= capture.response.len(),
                "rule {} produced span {:?}, which runs past the {} response byte(s) it \
                 was computed from -- a consumer slicing the response with this panics",
                i.rule_id,
                i.matched_span,
                capture.response.len()
            );
            let matched = &capture.response[i.matched_span.clone()];
            assert!(
                matched.len() == i.matched_span.end - i.matched_span.start,
                "slicing the response with rule {}'s span did not yield the span's own length",
                i.rule_id
            );

            // AC-4.12: every rule that can fire must be explainable. A
            // finding whose `rule_id` resolves to nothing is a finding no
            // operator can audit, and it is reachable only from here --
            // through a real match.
            assert!(
                explain(i.rule_id).is_some(),
                "rule {} fired but `explain` does not resolve it",
                i.rule_id
            );

            if i.matched_span.end > 6 {
                STATS.bump(DEEP_SPANS);
            }
            if i.observation.product.is_some() {
                STATS.bump(NAMED_PRODUCT);
            }
            if i.observation.version.is_some() {
                STATS.bump(NAMED_VERSION);
            }
            if let Some(bit) = rules.iter().position(|id| *id == i.rule_id) {
                STATS.flag(bit);
            }
        }
    }
    STATS.tick();
});
