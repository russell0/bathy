#![no_main]
#![forbid(unsafe_code)]

//! Fuzzes RFC 8785 canonicalization and `plan_digest` -- AC-7.7.
//!
//! `canonical_json` is what every hash in this project is computed over, so
//! it is load-bearing twice: a panic here is a denial of service, and a
//! *non-idempotent* result here silently breaks idempotency and resumption
//! (the same logical plan would hash two ways). The values it sees come from
//! `ScanRequest`s supplied by a calling agent, which the threat model treats
//! as possibly confused or adversarial.
//!
//! The assertions are the two properties the function's own doc comment
//! claims, checked over inputs nobody chose:
//!
//! 1. **Idempotence.** Canonicalizing the canonical form reproduces it byte
//!    for byte. A key-ordering or escaping bug that is stable but wrong
//!    survives a round-trip test and dies here only if the *re-parse* is
//!    included, which it is.
//! 2. **Digest agreement.** `plan_digest` is defined as the digest of the
//!    canonical form. Asserting that relationship rather than trusting it is
//!    what catches a future fast path that forgets to canonicalize.
//!
//! `write_canonical` is recursive, so deep nesting is the obvious way to
//! blow the stack. `serde_json`'s own 128-level recursion limit bounds what
//! can reach it through this door -- which is a property of `serde_json`'s
//! configuration, not of this crate, and is exactly the kind of assumption
//! that should be under a fuzzer rather than in a comment.

use bathy_fuzz::Stats;
use bathy_types::canonical::{CanonicalError, canonical_json, plan_digest};
use libfuzzer_sys::fuzz_target;
use serde_json::Value;

const PARSED: usize = 0;
const CANONICALIZED: usize = 1;
const REJECTED_NON_INTEGER: usize = 2;
const CANONICAL_BYTES: usize = 3;

const LABELS: &[&str] = &[
    // Inputs that were valid JSON at all. If this stays near zero the
    // corpus is not reaching the canonicalizer, only `serde_json`'s lexer.
    "parsed",
    "canonicalized",
    "rejected_non_integer",
    "canonical_bytes",
];

/// Which JSON shapes the corpus has actually produced. `canonical_json` has
/// a distinct arm for each, and the object arm -- the one that sorts keys --
/// is the only one where ordering can be wrong.
const FLAGS: &[&str] = &[
    "null",
    "bool",
    "number",
    "string",
    "array",
    "object",
    "nested_object",
    "non_ascii_string",
    "duplicate_keys",
];

static STATS: Stats = Stats::new("canonical_json", LABELS, FLAGS);

fn note_shape(value: &Value, depth: usize) {
    match value {
        Value::Null => STATS.flag(0),
        Value::Bool(_) => STATS.flag(1),
        Value::Number(_) => STATS.flag(2),
        Value::String(s) => {
            STATS.flag(3);
            if !s.is_ascii() {
                STATS.flag(7);
            }
        }
        Value::Array(items) => {
            STATS.flag(4);
            for item in items {
                note_shape(item, depth + 1);
            }
        }
        Value::Object(map) => {
            STATS.flag(5);
            if depth > 0 {
                STATS.flag(6);
            }
            for v in map.values() {
                note_shape(v, depth + 1);
            }
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let Ok(value) = serde_json::from_slice::<Value>(data) else {
        STATS.tick();
        return;
    };
    STATS.bump(PARSED);
    note_shape(&value, 0);
    // `serde_json` keeps the last of a repeated key, so a canonical form can
    // never carry one. Worth counting: it is the one input shape where the
    // canonical output is not a permutation of the input's own tokens.
    //
    // This was `opens > 0 && colons > commas + opens - 1` -- a punctuation
    // count that `{"a":"x:y"}` alone satisfies, with no duplicate key
    // anywhere, so `reached=9/9` was eight shapes and one heuristic. The
    // scanner behind `has_duplicate_keys` measures what the flag is named
    // after, and has its own unit tests (`cargo run -p xtask --
    // check-fuzz-crate`), including that exact input.
    if let Ok(text) = std::str::from_utf8(data)
        && bathy_fuzz::has_duplicate_keys(text)
    {
        STATS.flag(8);
    }

    let canonical = match canonical_json(&value) {
        Ok(canonical) => canonical,
        Err(CanonicalError::NonIntegerNumber) => {
            STATS.bump(REJECTED_NON_INTEGER);
            STATS.tick();
            return;
        }
        // M7 panic-lint widening: the two `.expect("string encodes")` calls
        // in `write_canonical` became this variant. It is unreachable through
        // `serde_json` for any `&str` -- which is exactly why it used to be an
        // `expect` -- so reaching it here is a finding about `serde_json`, not
        // about the input, and this target says so rather than counting it as
        // an ordinary rejection. Written out with no `_` arm, so a third
        // `CanonicalError` variant breaks this build.
        Err(e @ CanonicalError::StringNotEncodable { .. }) => {
            panic!("serde_json refused to encode a string it produced: {e}: {value:?}")
        }
    };
    STATS.bump(CANONICALIZED);
    STATS.add(CANONICAL_BYTES, canonical.len() as u64);

    // Property 1: the canonical form is itself canonical.
    let reparsed: Value = serde_json::from_str(&canonical)
        .unwrap_or_else(|e| panic!("canonical output is not valid JSON: {e}: {canonical:?}"));
    let again = canonical_json(&reparsed).unwrap_or_else(|e| {
        panic!("canonical output failed to canonicalize a second time: {e}: {canonical:?}")
    });
    assert_eq!(
        canonical, again,
        "canonicalization is not idempotent; two hashes for one logical value"
    );

    // Property 2: `plan_digest` is the digest OF the canonical form, not of
    // something adjacent to it.
    let digest = plan_digest(&value).expect("a value that canonicalized has a digest");
    let expected = bathy_types::ids::Digest::of_bytes(canonical.as_bytes());
    assert_eq!(
        digest, expected,
        "plan_digest disagreed with the digest of canonical_json's own output"
    );

    STATS.tick();
});
