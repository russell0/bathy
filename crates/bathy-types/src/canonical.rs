use serde_json::Value;

use crate::ids::Digest;

/// Canonicalization is a restricted profile of RFC 8785 (JCS: JSON
/// Canonicalization Scheme).
///
/// Two departures from full JCS, both deliberate:
///
/// - **Numbers.** We reject anything that isn't representable as `i64` or
///   `u64` rather than implement JCS's ECMAScript number-to-string algorithm.
///   Everything this crate hashes is a scan plan, which contains only
///   strings, integers, booleans, arrays and objects -- a well-formed plan
///   never contains a float, so the restriction costs nothing in practice
///   and removes the single hardest source of cross-platform hash
///   instability (subtle cross-implementation differences in
///   float-to-string formatting are exactly what JCS's ECMAScript-number
///   algorithm exists to pin down; refusing floats sidesteps needing that
///   algorithm at all). This is representation-based, not value-based: a
///   JSON literal written with a decimal point or exponent (e.g. `1.0`) is
///   stored by `serde_json` as a float internally and is rejected even
///   though its mathematical value is an integer -- see
///   `float_literal_with_integral_value_is_still_rejected` below. Keying off
///   representation rather than re-deriving "is this value integral" is
///   itself part of what avoids reintroducing the ambiguity JCS number
///   handling exists to solve.
/// - **Key sort order.** JCS section 3.2.3 orders object keys by comparing
///   their UTF-16 code unit sequences. This implementation sorts
///   `&str`/`String` with Rust's own `Ord`, which compares the underlying
///   UTF-8 bytes. For any two valid UTF-8 strings that happens to produce
///   the same order as comparing Unicode *codepoints*, and codepoint order
///   agrees with UTF-16 code-unit order for every character in the Basic
///   Multilingual Plane. The two orders diverge only for supplementary-plane
///   characters (codepoint >= U+10000): UTF-16 represents those as a
///   surrogate pair whose lead unit (0xD800-0xDBFF) is numerically *below*
///   the BMP characters in 0xE000-0xFFFF that codepoint order would place
///   after them. This crate's object keys are all ASCII field names, so the
///   divergence cannot occur today. It is called out here rather than
///   silently relied upon, because nothing in the type system enforces that
///   keys stay ASCII.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum CanonicalError {
    #[error("non-integer numbers are not canonicalizable in this profile")]
    NonIntegerNumber,
}

/// Serializes `value` as canonical JSON: object keys sorted, no
/// insignificant whitespace, and no floating-point numbers.
///
/// Byte-stable for a given logical value regardless of the key order or
/// formatting of whatever produced `value` -- this is what lets
/// [`plan_digest`] hash a scan plan independently of how the caller phrased
/// the request. Array element order is *not* touched: arrays are ordered
/// data (e.g. `targets`), so reordering one changes the canonical form (and
/// therefore the digest) on purpose.
pub fn canonical_json(value: &Value) -> Result<String, CanonicalError> {
    let mut out = String::new();
    write_canonical(value, &mut out)?;
    Ok(out)
}

fn write_canonical(value: &Value, out: &mut String) -> Result<(), CanonicalError> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                out.push_str(&i.to_string());
            } else if let Some(u) = n.as_u64() {
                out.push_str(&u.to_string());
            } else {
                return Err(CanonicalError::NonIntegerNumber);
            }
        }
        Value::String(s) => out.push_str(&serde_json::to_string(s).expect("string encodes")),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            // `serde_json::Map`'s own iteration order depends on whether the
            // `preserve_order` feature is enabled anywhere in the dependency
            // graph (insertion order if so; alphabetical, via an internal
            // `BTreeMap`, if not). Sort explicitly here rather than trusting
            // that, so this function's output is stable regardless of what
            // some unrelated crate's feature flags happen to be. Confirmed
            // for this workspace as of this task: `preserve_order` is *not*
            // active (no `indexmap` appears anywhere in `Cargo.lock`), so the
            // map already iterates alphabetically today -- but relying on
            // that would make correctness an accident of the current
            // dependency graph rather than a property of this function.
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_unstable();
            out.push('{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(k).expect("key encodes"));
                out.push(':');
                write_canonical(&map[*k], out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// The content digest of a scan plan's canonical JSON form.
///
/// Two `Value`s that describe the same plan phrased with different key order
/// (different serializer, different field declaration order, a hand-built
/// request from a different agent, ...) hash identically. Two plans that
/// differ in any array's element order hash *differently* -- array order is
/// significant, see [`canonical_json`]'s doc comment. This is the property
/// that makes idempotency and resumption meaningful: the same logical scan
/// request produces the same `plan_hash` no matter how the caller phrased it.
pub fn plan_digest(plan: &Value) -> Result<Digest, CanonicalError> {
    Ok(Digest::of_bytes(canonical_json(plan)?.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // --- Brief's Step 1 tests, verbatim ---

    #[test]
    fn object_keys_are_sorted_so_hashing_is_order_independent() {
        let a = json!({"b": 1, "a": 2});
        let b = json!({"a": 2, "b": 1});
        assert_eq!(canonical_json(&a).unwrap(), canonical_json(&b).unwrap());
        assert_eq!(canonical_json(&a).unwrap(), r#"{"a":2,"b":1}"#);
    }

    #[test]
    fn array_order_is_significant() {
        assert_ne!(
            canonical_json(&json!([1, 2])).unwrap(),
            canonical_json(&json!([2, 1])).unwrap()
        );
    }

    #[test]
    fn floats_are_rejected_because_their_text_form_is_not_portable() {
        assert!(canonical_json(&json!({"x": 1.5})).is_err());
    }

    #[test]
    fn nesting_is_canonicalized_recursively() {
        let v = json!({"z": {"b": [ {"d": 1, "c": 2} ]}, "a": true});
        assert_eq!(
            canonical_json(&v).unwrap(),
            r#"{"a":true,"z":{"b":[{"c":2,"d":1}]}}"#
        );
    }

    #[test]
    fn plan_digest_is_stable_across_key_order() {
        let a = json!({"targets": ["10.0.0.0/24"], "ports": [22, 80]});
        let b = json!({"ports": [22, 80], "targets": ["10.0.0.0/24"]});
        assert_eq!(plan_digest(&a).unwrap(), plan_digest(&b).unwrap());
    }

    // --- AC-1.23's other half: plan_digest is not just stable under key
    // reordering, it must also actually change when array order changes.
    // The brief only spells out the invariance direction; without this test
    // a `plan_digest` that (bug) canonicalized arrays the same way it
    // canonicalizes objects -- i.e. sorted them -- would still pass every
    // brief test while silently breaking the "array order is meaningful"
    // half of the contract. ---

    #[test]
    fn plan_digest_is_sensitive_to_array_reordering() {
        let a = json!({"targets": ["10.0.0.0/24", "10.0.1.0/24"]});
        let b = json!({"targets": ["10.0.1.0/24", "10.0.0.0/24"]});
        assert_ne!(plan_digest(&a).unwrap(), plan_digest(&b).unwrap());
    }

    #[test]
    fn plan_digest_propagates_the_float_rejection() {
        assert_eq!(
            plan_digest(&json!({"x": 1.5})),
            Err(CanonicalError::NonIntegerNumber)
        );
    }

    // --- Edge cases beyond the brief's minimal test list (dispatch's
    // "verification beyond the brief" ask) ---

    #[test]
    fn empty_object_canonicalizes_to_empty_braces() {
        assert_eq!(canonical_json(&json!({})).unwrap(), "{}");
    }

    #[test]
    fn empty_array_canonicalizes_to_empty_brackets() {
        assert_eq!(canonical_json(&json!([])).unwrap(), "[]");
    }

    #[test]
    fn null_canonicalizes_to_the_literal_null() {
        assert_eq!(canonical_json(&json!(null)).unwrap(), "null");
    }

    #[test]
    fn nested_empties_are_preserved_not_collapsed_or_dropped() {
        let v = json!({"z": [], "a": {}});
        assert_eq!(canonical_json(&v).unwrap(), r#"{"a":{},"z":[]}"#);
    }

    // `1.0` is mathematically an integer, but the JSON source used a decimal
    // point, so `serde_json` stores it as a float internally regardless of
    // its value -- and this profile keys off that stored representation, not
    // the mathematical value, so it is rejected exactly like `1.5`. See the
    // doc comment on `CanonicalError` for why keying off representation
    // (rather than "is this float integral") is the deliberate choice.
    #[test]
    fn float_literal_with_integral_value_is_still_rejected() {
        assert!(canonical_json(&json!(1.0)).is_err());
    }

    #[test]
    fn integer_boundaries_u64_max_and_i64_min_are_accepted() {
        assert_eq!(
            canonical_json(&json!(u64::MAX)).unwrap(),
            u64::MAX.to_string()
        );
        assert_eq!(
            canonical_json(&json!(i64::MIN)).unwrap(),
            i64::MIN.to_string()
        );
    }

    // Two keys that render identically to a human but are different Rust
    // `String`s (different byte sequences) because they use different
    // Unicode normalization forms. RFC 8785 itself does not specify any
    // normalization step -- keys are opaque UTF-8 byte sequences to JCS --
    // and this implementation matches that: no normalization is performed,
    // so both keys survive as distinct entries. A producer that considers
    // these the "same" key and emits both gets two keys on the wire and in
    // the digest, not silent deduplication.
    #[test]
    fn keys_differing_only_by_unicode_normalization_are_distinct_not_merged() {
        let nfc = "caf\u{e9}"; // "café", precomposed (NFC): 'é' is U+00E9.
        let nfd = "cafe\u{301}"; // "cafe" + combining acute accent (NFD).
        assert_ne!(
            nfc, nfd,
            "fixture sanity: NFC and NFD forms differ as Rust strings"
        );

        let mut map = serde_json::Map::new();
        map.insert(nfc.to_string(), json!(1));
        map.insert(nfd.to_string(), json!(2));

        let out = canonical_json(&Value::Object(map)).unwrap();

        let nfd_pos = out.find(nfd).expect("NFD-form key present in output");
        let nfc_pos = out.find(nfc).expect("NFC-form key present in output");
        // NFD's first codepoint is plain 'e' (U+0065); NFC's first (and
        // only) codepoint for that character is 'é' (U+00E9). U+0065 <
        // U+00E9, so the NFD form sorts first under this profile's
        // UTF-8-byte-order key sort.
        assert!(
            nfd_pos < nfc_pos,
            "expected the NFD-form key to sort before the NFC-form key, got: {out}"
        );
    }

    // Non-ASCII keys: confirm they sort correctly against ASCII keys (every
    // ASCII byte is < every UTF-8 lead byte for a non-ASCII codepoint, so
    // ASCII keys always sort first), and that `serde_json`'s default string
    // escaping already matches what JCS requires here -- non-ASCII
    // characters are emitted as literal UTF-8, not `\uXXXX`-escaped.
    #[test]
    fn non_ascii_keys_sort_after_ascii_keys_and_are_not_escaped() {
        let v = json!({"\u{30dd}\u{30fc}\u{30c8}": 1, "a": 2}); // "ポート" ("port"), and "a"
        assert_eq!(
            canonical_json(&v).unwrap(),
            "{\"a\":2,\"\u{30dd}\u{30fc}\u{30c8}\":1}"
        );
    }

    // Keys (and values) that require JSON string escaping -- a quote, a
    // backslash, and a control character -- come out correctly escaped.
    // This isn't this module's own logic (it delegates to
    // `serde_json::to_string`), but it is part of the canonical contract:
    // an escaped-wrong key would still break byte-stability.
    #[test]
    fn keys_requiring_json_escaping_are_escaped_correctly() {
        let mut map = serde_json::Map::new();
        map.insert("quote\"here".to_string(), json!(1));
        map.insert("back\\slash".to_string(), json!(2));
        map.insert("tab\ttab".to_string(), json!(3));
        let out = canonical_json(&Value::Object(map)).unwrap();
        assert!(out.contains(r#""quote\"here":1"#), "got {out}");
        assert!(out.contains(r#""back\\slash":2"#), "got {out}");
        assert!(out.contains(r#""tab\ttab":3"#), "got {out}");
    }

    // The canonical form is, itself, valid JSON that reparses to the same
    // logical value -- canonicalization must not corrupt the document, only
    // reformat it.
    #[test]
    fn canonical_output_is_itself_valid_json_that_reparses_equal() {
        let v = json!({
            "z": {"b": [1, 2, 3]},
            "a": [true, false, null],
            "s": "with \"quotes\" and \\ backslash and\ttab",
        });
        let out = canonical_json(&v).unwrap();
        let reparsed: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(reparsed, v);
    }
}
