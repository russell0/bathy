//! One input per rule whose match ends at the last byte it is allowed to,
//! checked in milliseconds on every pull request.
//!
//! # Why this file exists
//!
//! `fuzz/fuzz_targets/interpret.rs` asserts that no `matched_span` runs past
//! the response it was computed from (AC-7.9), and that assertion is correct
//! and rule-agnostic. What is *not* uniform across rules is how long a
//! fuzzer takes to find an input that violates it. M7 Task 2's review
//! corrupted one rule's span arithmetic by a single byte
//! (`dns.version_bind.txt_chaos.v1`, `txt_end` -> `txt_end + 1`) and
//! measured:
//!
//! | Run | Outcome |
//! |---|---|
//! | seed replay over `fuzz/seeds/interpret` | **not caught** |
//! | 120 s / 2,964,533 executions | **not caught** |
//! | 600 s / 6,560,722 executions | caught at roughly 276 s |
//! | one hand-built 33-byte input | **caught instantly** |
//!
//! **CI's per-pull-request fuzz budget is 60 seconds per target.** So the
//! seven historical span mutants' own defect class -- a one-byte widening --
//! would have shipped green through every pull request and been caught, if
//! at all, by the nightly. The reason is visible in the committed seeds:
//! they are whole recorded responses, so almost every rule's match sits
//! comfortably mid-buffer, and a span that is one byte too long is still
//! inside the buffer and still slices fine. Nothing notices.
//!
//! The fix is not a longer fuzz run. It is an input per rule whose match
//! ends exactly where the response does, so that "one byte too long" is
//! "one byte past the end" for **every** rule rather than for HTTP alone.
//! Those inputs are committed under `fuzz/seeds/interpret/span-edge-*.bin`
//! -- they are seeds, so libFuzzer replays them at the start of every fuzz
//! run too -- and this test is what makes them a *gate*: it runs in
//! `cargo test --workspace`, needs no nightly, no `cargo-fuzz` and no
//! corpus, and takes about a millisecond.
//!
//! # Why `slack`
//!
//! One rule of the thirteen cannot have a match that ends at the last byte,
//! because its own grammar forbids it (MySQL's version string is found by
//! looking for the NUL that terminates it, so there is always a NUL after
//! the span). Pretending otherwise would mean committing an input that does
//! not exercise the edge at all. `slack` declares how many bytes must follow
//! the match and why. The assertion is an **equality** either way --
//! `span.end == len - slack` -- so a one-byte widening fails for a
//! `slack: 1` rule exactly as it does for a `slack: 0` one; that is
//! mutation-verified against MySQL as well as against DNS.
//!
//! # What breaks this test
//!
//! - Any rule whose span arithmetic gains or loses a byte.
//! - A new rule with no edge input: `every_rule_has_one` fails, naming it.
//!   The list is derived from `all_rules()`, so it cannot go stale quietly
//!   -- which is the same reason `known_probe_ids()` is used below rather
//!   than a written-out list of probe ids.

use std::path::PathBuf;

use bathy_interpret::{all_rules, interpret, known_probe_ids};
use bathy_types::{ProbeCapture, Transport};

/// Bytes that must follow the match because the rule's own grammar requires
/// them. Zero for every rule not named here.
///
/// Anything on this list is a claim about a matcher, so each entry says
/// which line makes it true.
fn slack(rule_id: &str) -> usize {
    match rule_id {
        // `mysql_handshake_v10` finds its version string by searching for
        // the terminating NUL (`rest.iter().position(|&b| b == 0)?`) and
        // sets `span = VERSION_STRING_START..version_end`, where
        // `version_end` is the NUL's own offset. The NUL is therefore always
        // present and always outside the span: an input whose match ended at
        // the last byte would be an input with no NUL, which does not match
        // at all.
        "mysql.handshake.v10.v1" => 1,
        _ => 0,
    }
}

fn corpus_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fuzz/seeds/interpret")
}

fn edge_input(rule_id: &str) -> PathBuf {
    corpus_dir().join(format!("span-edge-{rule_id}.bin"))
}

/// The corpus is complete, and stays complete: a rule added without an edge
/// input fails here rather than being quietly uncovered.
#[test]
fn every_rule_has_one() {
    let missing: Vec<&str> = all_rules()
        .filter(|rule| !edge_input(rule.id).is_file())
        .map(|rule| rule.id)
        .collect();
    assert!(
        missing.is_empty(),
        "no span-edge input for {missing:?}. Each rule needs one input whose match ends \
         at the last byte it can (see this file's header for why a 60-second fuzz run \
         does not find these on its own). Write it to {}, and if the rule's grammar \
         forces trailing bytes, add it to `slack` with the line that proves it.",
        corpus_dir().display()
    );
}

/// The assertion itself: every committed edge input still ends where it is
/// supposed to end. This is what dies on a one-byte span change in any rule.
#[test]
fn every_edge_input_still_ends_where_the_response_does() {
    for rule in all_rules() {
        let path = edge_input(rule.id);
        let Ok(response) = std::fs::read(&path) else {
            continue; // `every_rule_has_one` owns this failure.
        };
        let slack = slack(rule.id);
        let expected_end = response
            .len()
            .checked_sub(slack)
            .expect("an edge input longer than its rule's required trailing bytes");

        // Every probe id, because which one dispatches a given rule is
        // `rules_for`'s business and not something this corpus should
        // restate. A rule that fires under none of them is a failure.
        let mut seen = None;
        for probe_id in known_probe_ids() {
            let capture = ProbeCapture {
                probe_id,
                transport: Transport::Tcp,
                port: 0,
                request: None,
                response: response.clone(),
                elapsed_micros: 0,
                truncated: false,
            };
            for i in interpret(&capture) {
                if i.rule_id == rule.id {
                    seen = Some(i.matched_span.clone());
                }
            }
        }

        let span = seen.unwrap_or_else(|| {
            panic!(
                "{} no longer produces a `{}` match at all, so nothing about its span is \
                 being checked -- which reads as coverage while guarding nothing",
                path.display(),
                rule.id
            )
        });
        assert_eq!(
            span.end,
            expected_end,
            "rule {} matched {:?} in a {}-byte input whose match must end at byte {} \
             (slack {}). A span one byte too long is the exact shape of the seven \
             historical span mutants, and it is invisible to a fuzz run of this length \
             on any input that is not this one.",
            rule.id,
            span,
            response.len(),
            expected_end,
            slack,
        );
        assert_eq!(
            response[span.clone()].len(),
            span.end - span.start,
            "slicing the response with rule {}'s span did not yield the span's own \
             length -- which is what a consumer does with it",
            rule.id
        );
    }
}

/// ...and nothing in the corpus belongs to no rule. A stale edge input for a
/// deleted rule is a file nothing runs, which is how a corpus stops being
/// evidence.
#[test]
fn no_edge_input_belongs_to_a_rule_that_no_longer_exists() {
    let ids: Vec<&str> = all_rules().map(|rule| rule.id).collect();
    let orphans: Vec<String> = std::fs::read_dir(corpus_dir())
        .expect("the seed corpus directory")
        .filter_map(Result::ok)
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            let rule = name.strip_prefix("span-edge-")?.strip_suffix(".bin")?;
            (!ids.contains(&rule)).then_some(name)
        })
        .collect();
    assert!(
        orphans.is_empty(),
        "span-edge inputs for no known rule: {orphans:?}"
    );
}
