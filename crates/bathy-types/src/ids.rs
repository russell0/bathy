use std::fmt;
use std::str::FromStr;

use schemars::JsonSchema;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A BLAKE3 content digest, rendered as `blake3:<64 lowercase hex>`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Digest([u8; 32]);

impl Digest {
    pub fn of_bytes(bytes: &[u8]) -> Self {
        Self(*blake3::hash(bytes).as_bytes())
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "blake3:")?;
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self}")
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum IdError {
    #[error("expected algorithm prefix `blake3:`")]
    WrongAlgorithm,
    #[error("expected 64 hex characters, found {0}")]
    BadDigestLength(usize),
    /// Also returned for otherwise-valid hex that isn't lowercase (e.g.
    /// `A`-`F`): this type deliberately accepts only what its published
    /// JSON Schema pattern allows, so "wrong case" and "not hex at all"
    /// share this variant rather than splitting into a `NonLowercaseHex`
    /// case a caller would have no different remediation for.
    #[error("invalid hex in digest")]
    BadHex,
    #[error("expected identifier prefix `{expected}_`")]
    WrongPrefix { expected: &'static str },
    #[error("invalid ULID")]
    BadUlid,
}

impl FromStr for Digest {
    type Err = IdError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let hex = s.strip_prefix("blake3:").ok_or(IdError::WrongAlgorithm)?;
        if hex.len() != 64 {
            return Err(IdError::BadDigestLength(hex.len()));
        }
        // Deliberately strict: only lowercase hex digits are accepted, to
        // match this type's published JSON Schema pattern exactly
        // (`^blake3:[0-9a-f]{64}$`). `u8::from_str_radix(_, 16)` below is
        // case-insensitive on its own and would otherwise accept
        // uppercase/mixed-case hex, which the schema forbids -- a document
        // that fails schema validation must not be accepted by this type.
        // Do not relax this by swapping in `is_ascii_hexdigit()`.
        if !hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(IdError::BadHex);
        }
        let mut out = [0u8; 32];
        // `chunks_exact(2)` rather than `&hex[i * 2..i * 2 + 2]`: the string
        // slicing was in bounds (the length was checked above) but `i * 2 + 2`
        // is unchecked arithmetic, and *string* indexing is invisible to
        // `clippy::indexing_slicing` -- so the bound was held by the reader's
        // attention in both directions. Pairing the output bytes with the
        // input pairs makes the two lengths agree by construction; `zip` stops
        // at the shorter, and `hex.len() == 64 == out.len() * 2` is what makes
        // them the same length.
        for (byte, pair) in out.iter_mut().zip(hex.as_bytes().chunks_exact(2)) {
            let pair = std::str::from_utf8(pair).map_err(|_| IdError::BadHex)?;
            *byte = u8::from_str_radix(pair, 16).map_err(|_| IdError::BadHex)?;
        }
        Ok(Self(out))
    }
}

impl Serialize for Digest {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

// Verified against the installed schemars 1.2.2 source
// (~/.cargo/registry/src/*/schemars-1.2.2/src/lib.rs, macros.rs, schema.rs,
// generate.rs): `JsonSchema::schema_name` returns `Cow<'static, str>`,
// `JsonSchema::json_schema` takes `&mut schemars::SchemaGenerator` and
// returns `schemars::Schema` (a thin wrapper around `serde_json::Value`),
// and `json_schema!({ ... })` builds a `Schema` from a JSON object literal
// via `TryFrom<serde_json::Value>`. This matches the brief's code exactly;
// no deviation from the 0.8 builder API (`into_object()`, `.string().pattern`,
// `schemars::gen::SchemaGenerator`) was needed because that API does not
// exist in this dependency tree.
impl JsonSchema for Digest {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "Digest".into()
    }
    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "type": "string",
            "pattern": "^blake3:[0-9a-f]{64}$",
            "description": "BLAKE3 content digest of stored evidence bytes.",
        })
    }
}

/// Declares a prefixed ULID newtype. Prefixes make identifiers self-describing
/// in logs and prevent a scope id being passed where a scan id is expected.
macro_rules! prefixed_id {
    ($name:ident, $prefix:literal, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(ulid::Ulid);

        impl $name {
            pub const PREFIX: &'static str = $prefix;

            /// Builds an id straight from a `Ulid`, with no validation --
            /// unlike `FromStr` above, which rejects any first Crockford
            /// character above `7` (see C2). That looks like the same hole
            /// reopened: could a caller hand this a `Ulid` whose canonical
            /// string this type's own `FromStr` would then reject?
            ///
            /// No -- and the reason is structural, not incidental. `Ulid`
            /// wraps a `u128` (`ulid::Ulid(pub u128)`). Its `Display` impl
            /// (`ulid-3.0.0/src/base32.rs::encode_to_array`) walks the value
            /// 5 bits at a time for 26 characters, most-significant group
            /// first: `buffer[0] = (value >> 125) & 0x1f` is the first
            /// character. 26 * 5 = 130 bits requested from a value that only
            /// *has* 128, so that top group can supply at most
            /// 128 - 25*5 = 3 real bits (positions 125-127); the two bit
            /// positions above that (128, 129) don't exist in a `u128`, so
            /// there is nothing there to ever set. Consequently, for *every*
            /// possible `u128` value -- not just ones reachable through
            /// `Generator::generate()` or `Ulid::from_parts`, but literally
            /// `Ulid(u128::MAX)` -- `value >> 125 < 2^3 = 8`, so the first
            /// character always lands in `0..=7`. Encoding is total onto the
            /// range `FromStr` accepts; there is no bit pattern that can ever
            /// violate it. The `debug_assert!` below pins that as an
            /// executable invariant (checked on every debug-mode call, so a
            /// future change to `ulid`'s encoding would be caught
            /// immediately rather than drifting quietly), and
            /// `from_ulid_round_trips_for_every_reachable_first_character`
            /// and the `Clock`-level tests in `clock.rs` pin it with
            /// concrete extreme values.
            ///
            /// This is option (b) from the M2 Task 1 dispatch, not (a)
            /// (`try_from_ulid`): a fallible constructor would be a
            /// vocabulary lie here, forcing every caller (including
            /// `Clock::new_scan_id`, which must be infallible) to handle an
            /// error case that provably cannot occur.
            pub fn from_ulid(u: ulid::Ulid) -> Self {
                debug_assert!(
                    u.to_string()
                        .as_bytes()
                        .first()
                        .is_some_and(|b| (b'0'..=b'7').contains(b)),
                    "ulid::Ulid's Display must always start with a canonical \
                     (0-7) Crockford character -- see the comment on \
                     `from_ulid` above; if this fires, the upstream `ulid` \
                     encoding changed and this reasoning must be redone \
                     before release"
                );
                Self(u)
            }

            pub fn as_ulid(&self) -> ulid::Ulid {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}_{}", $prefix, self.0)
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{self}")
            }
        }

        impl FromStr for $name {
            type Err = IdError;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                let rest = s
                    .strip_prefix(concat!($prefix, "_"))
                    .ok_or(IdError::WrongPrefix { expected: $prefix })?;
                // Deliberately strict, mirroring `Digest::from_str` above
                // (see its comment for the same shape of bug): the
                // published JSON Schema pattern for this type is
                // uppercase-only Crockford base32
                // (`^..._[0-9A-HJKMNP-TV-Z]{26}$`), but `ulid::Ulid::
                // from_string` is case-insensitive on its own -- it folds
                // lowercase onto the same lookup table as uppercase, so
                // e.g. `scan_01arz3ndektsv4rrffq69g5fav` parses
                // successfully today even though it fails schema
                // validation. A document that fails schema validation
                // must not be accepted by this type.
                if rest.bytes().any(|b| b.is_ascii_lowercase()) {
                    return Err(IdError::BadUlid);
                }
                // C2: 26 Crockford characters carry 130 bits into a
                // 128-bit `Ulid`; `ulid` 3.x's decoder silently discards
                // the two overflow bits (`value = (value << 5) | val`,
                // repeated 26 times over a `u128` -- see
                // `ulid::base32::decode`), so on its own it is not
                // injective. Concretely: a first character's decoded
                // value only survives mod 8, so any first character above
                // `7` aliases the same `Ulid` as some character in
                // `0`-`7` -- e.g. `scan_81ARZ...` and `scan_01ARZ...`
                // parse to the same id today (8 mod 8 == 0), as do
                // `scan_Z1ARZ...` and `scan_71ARZ...` (31 mod 8 == 7).
                // Only `0`-`7` are canonical first characters; rejecting
                // anything else makes parsing injective and guarantees
                // round-tripping. The published pattern's first character
                // class is tightened to match (`[0-7]`, not the full
                // alphabet) so schema and runtime agree.
                if !rest
                    .as_bytes()
                    .first()
                    .is_some_and(|b| (b'0'..=b'7').contains(b))
                {
                    return Err(IdError::BadUlid);
                }
                Ok(Self(
                    ulid::Ulid::from_string(rest).map_err(|_| IdError::BadUlid)?,
                ))
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.collect_str(self)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                let s = String::deserialize(d)?;
                s.parse().map_err(serde::de::Error::custom)
            }
        }

        impl JsonSchema for $name {
            fn schema_name() -> std::borrow::Cow<'static, str> {
                stringify!($name).into()
            }
            fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
                schemars::json_schema!({
                    "type": "string",
                    // First character restricted to `0`-`7`, not the full
                    // Crockford alphabet: only those 8 values keep parsing
                    // injective (see C2's comment on `FromStr` above).
                    "pattern": concat!("^", $prefix, "_[0-7][0-9A-HJKMNP-TV-Z]{25}$"),
                    "description": $doc,
                })
            }
        }
    };
}

prefixed_id!(ScanId, "scan", "Identifies one scan task.");
prefixed_id!(EventId, "evt", "Identifies one immutable event.");
prefixed_id!(
    ScopeId,
    "scope",
    "Identifies an authorization scope manifest."
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_renders_with_algorithm_prefix() {
        let d = Digest::of_bytes(b"hello");
        let s = d.to_string();
        assert!(s.starts_with("blake3:"), "got {s}");
        assert_eq!(s.len(), "blake3:".len() + 64);
        assert_eq!(s, s.to_lowercase());
    }

    #[test]
    fn digest_roundtrips_through_string() {
        let d = Digest::of_bytes(b"hello");
        assert_eq!(d, d.to_string().parse::<Digest>().unwrap());
    }

    #[test]
    fn digest_rejects_wrong_algorithm() {
        let bad = format!("sha256:{}", "a".repeat(64));
        assert_eq!(bad.parse::<Digest>().unwrap_err(), IdError::WrongAlgorithm);
    }

    #[test]
    fn digest_rejects_missing_algorithm_prefix() {
        // A bare 64-hex string with no prefix at all must still be
        // rejected. This is exactly the case that goes unnoticed if the
        // `strip_prefix("blake3:").ok_or(...)` check is ever removed or
        // weakened to a fallback (see `digest_rejects_wrong_algorithm`'s
        // history: that test alone did not catch such a regression,
        // because a 71-character `sha256:`-prefixed string happens to
        // fail the length check instead once the prefix check is gone).
        let bad = "a".repeat(64);
        assert_eq!(bad.parse::<Digest>().unwrap_err(), IdError::WrongAlgorithm);
    }

    #[test]
    fn scan_id_has_type_prefix() {
        let id = ScanId::from_ulid(ulid::Ulid::from_parts(0, 1));
        assert!(id.to_string().starts_with("scan_"), "got {id}");
    }

    #[test]
    fn scan_id_rejects_foreign_prefix() {
        assert!(
            "scope_01ARZ3NDEKTSV4RRFFQ69G5FAV"
                .parse::<ScanId>()
                .is_err()
        );
    }

    // --- Additional coverage beyond the brief's minimal test list ---

    #[test]
    fn digest_rejects_wrong_length() {
        let bad = format!("blake3:{}", "a".repeat(63));
        assert_eq!(bad.parse::<Digest>(), Err(IdError::BadDigestLength(63)));
    }

    #[test]
    fn digest_rejects_invalid_hex() {
        let bad = format!("blake3:{}", "z".repeat(64));
        assert_eq!(bad.parse::<Digest>(), Err(IdError::BadHex));
    }

    // --- Strictness: the Rust type must accept exactly what the
    // published JSON Schema pattern `^blake3:[0-9a-f]{64}$` allows, no
    // more. `u8::from_str_radix(_, 16)` is case-insensitive by itself, so
    // this is deliberately over-and-above what parsing alone would give.

    #[test]
    fn digest_accepts_lowercase_hex_via_from_str() {
        // Belt-and-suspenders alongside `digest_roundtrips_through_string`:
        // spells out that a hand-written (not just self-rendered)
        // lowercase-hex string parses successfully.
        let hex = "0f".repeat(32);
        assert!(format!("blake3:{hex}").parse::<Digest>().is_ok());
    }

    #[test]
    fn digest_rejects_uppercase_hex_via_from_str() {
        let bad = format!("blake3:{}", "A".repeat(64));
        assert_eq!(bad.parse::<Digest>(), Err(IdError::BadHex));
    }

    #[test]
    fn digest_rejects_mixed_case_hex_via_from_str() {
        let mut hex = "a".repeat(63);
        hex.push('F');
        let bad = format!("blake3:{hex}");
        assert_eq!(bad.parse::<Digest>(), Err(IdError::BadHex));
    }

    #[test]
    fn digest_accepts_lowercase_hex_via_deserialize() {
        let hex = "0f".repeat(32);
        let json = format!("\"blake3:{hex}\"");
        let d: Digest = serde_json::from_str(&json).unwrap();
        assert_eq!(d.to_string(), format!("blake3:{hex}"));
    }

    #[test]
    fn digest_rejects_uppercase_hex_via_deserialize() {
        let json = format!("\"blake3:{}\"", "A".repeat(64));
        assert!(serde_json::from_str::<Digest>(&json).is_err());
    }

    #[test]
    fn digest_rejects_mixed_case_hex_via_deserialize() {
        let mut hex = "a".repeat(63);
        hex.push('F');
        let json = format!("\"blake3:{hex}\"");
        assert!(serde_json::from_str::<Digest>(&json).is_err());
    }

    #[test]
    fn event_id_and_scope_id_have_type_prefixes_and_roundtrip() {
        let u = ulid::Ulid::from_parts(0, 1);

        let evt = EventId::from_ulid(u);
        assert!(evt.to_string().starts_with("evt_"), "got {evt}");
        assert_eq!(evt.to_string().parse::<EventId>().unwrap(), evt);

        let scope = ScopeId::from_ulid(u);
        assert!(scope.to_string().starts_with("scope_"), "got {scope}");
        assert_eq!(scope.to_string().parse::<ScopeId>().unwrap(), scope);
    }

    #[test]
    fn event_id_rejects_scan_prefix() {
        assert!(
            "scan_01ARZ3NDEKTSV4RRFFQ69G5FAV"
                .parse::<EventId>()
                .is_err()
        );
    }

    #[test]
    fn scope_id_rejects_evt_prefix() {
        assert!("evt_01ARZ3NDEKTSV4RRFFQ69G5FAV".parse::<ScopeId>().is_err());
    }

    #[test]
    fn scan_id_rejects_garbage_ulid_body() {
        assert!(matches!(
            "scan_not-a-ulid".parse::<ScanId>(),
            Err(IdError::BadUlid)
        ));
    }

    // --- C1: the published pattern for `ScanId`/`EventId`/`ScopeId` is
    // uppercase-only Crockford (see the schema tests below for the exact
    // pattern), and this type must accept exactly what it publishes -- the
    // same rule already
    // enforced for `Digest` above (`digest_rejects_uppercase_hex_via_*`,
    // `digest_rejects_mixed_case_hex_via_*`), now applied to the
    // `prefixed_id!` macro too. One generic helper, monomorphized over all
    // three types, so the three don't silently drift out of sync with each
    // other the way the macro itself did with `Digest`.

    fn assert_rejects_non_uppercase_ulid<T>(prefix: &str, valid_uppercase_body: &str)
    where
        T: FromStr<Err = IdError> + for<'de> Deserialize<'de> + std::fmt::Debug,
    {
        // Positive control: the unmodified uppercase id must still parse,
        // via both FromStr and Deserialize -- otherwise the rejections
        // below would trivially "pass" for the wrong reason (nothing of
        // this shape ever parses).
        let ok = format!("{prefix}_{valid_uppercase_body}");
        assert!(ok.parse::<T>().is_ok(), "{ok} via FromStr");
        assert!(
            serde_json::from_str::<T>(&format!("\"{ok}\"")).is_ok(),
            "{ok} via Deserialize"
        );

        let lower = format!("{prefix}_{}", valid_uppercase_body.to_lowercase());
        assert_eq!(
            lower.parse::<T>().unwrap_err(),
            IdError::BadUlid,
            "{lower} via FromStr"
        );
        assert!(
            serde_json::from_str::<T>(&format!("\"{lower}\"")).is_err(),
            "{lower} via Deserialize"
        );

        let mut mixed = valid_uppercase_body.to_string();
        // Flip exactly one letter to lowercase -- e.g. the ULID's last
        // character -- so this is genuinely "mixed", not "all lowercase".
        let last = mixed.pop().unwrap();
        mixed.push(last.to_ascii_lowercase());
        let mixed = format!("{prefix}_{mixed}");
        assert_eq!(
            mixed.parse::<T>().unwrap_err(),
            IdError::BadUlid,
            "{mixed} via FromStr"
        );
        assert!(
            serde_json::from_str::<T>(&format!("\"{mixed}\"")).is_err(),
            "{mixed} via Deserialize"
        );
    }

    #[test]
    fn scan_id_rejects_non_uppercase_ulid() {
        assert_rejects_non_uppercase_ulid::<ScanId>("scan", "01ARZ3NDEKTSV4RRFFQ69G5FAV");
    }

    #[test]
    fn event_id_rejects_non_uppercase_ulid() {
        assert_rejects_non_uppercase_ulid::<EventId>("evt", "01ARZ3NDEKTSV4RRFFQ69G5FAV");
    }

    #[test]
    fn scope_id_rejects_non_uppercase_ulid() {
        assert_rejects_non_uppercase_ulid::<ScopeId>("scope", "01ARZ3NDEKTSV4RRFFQ69G5FAV");
    }

    #[test]
    fn digest_serde_roundtrips_through_json() {
        let d = Digest::of_bytes(b"hello");
        let json = serde_json::to_string(&d).unwrap();
        assert_eq!(json, format!("\"{d}\""));
        let back: Digest = serde_json::from_str(&json).unwrap();
        assert_eq!(back, d);
    }

    #[test]
    fn scan_id_serde_roundtrips_through_json() {
        let id = ScanId::from_ulid(ulid::Ulid::from_parts(0, 1));
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, format!("\"{id}\""));
        let back: ScanId = serde_json::from_str(&json).unwrap();
        assert_eq!(back, id);
    }

    // --- AC-1.8: JSON Schema exposes a `pattern` constraining the format ---
    // Proven concretely by generating the schema, serializing it to JSON,
    // and asserting the exact `pattern` string is present -- a JsonSchema
    // impl that compiles but forgets to set `pattern` would otherwise pass
    // unnoticed.

    #[test]
    fn digest_json_schema_has_expected_pattern() {
        let schema = schemars::schema_for!(Digest);
        let value = serde_json::to_value(&schema).unwrap();
        assert_eq!(
            value.get("pattern").and_then(|v| v.as_str()),
            Some("^blake3:[0-9a-f]{64}$"),
            "schema was {value:#}"
        );
        assert_eq!(value.get("type").and_then(|v| v.as_str()), Some("string"));
    }

    #[test]
    fn scan_id_json_schema_has_expected_pattern() {
        let schema = schemars::schema_for!(ScanId);
        let value = serde_json::to_value(&schema).unwrap();
        assert_eq!(
            value.get("pattern").and_then(|v| v.as_str()),
            Some("^scan_[0-7][0-9A-HJKMNP-TV-Z]{25}$"),
            "schema was {value:#}"
        );
        assert_eq!(value.get("type").and_then(|v| v.as_str()), Some("string"));
    }

    #[test]
    fn event_id_and_scope_id_json_schemas_have_expected_patterns() {
        let evt_value = serde_json::to_value(schemars::schema_for!(EventId)).unwrap();
        assert_eq!(
            evt_value.get("pattern").and_then(|v| v.as_str()),
            Some("^evt_[0-7][0-9A-HJKMNP-TV-Z]{25}$")
        );

        let scope_value = serde_json::to_value(schemars::schema_for!(ScopeId)).unwrap();
        assert_eq!(
            scope_value.get("pattern").and_then(|v| v.as_str()),
            Some("^scope_[0-7][0-9A-HJKMNP-TV-Z]{25}$")
        );
    }

    #[test]
    fn ulid_pattern_excludes_ambiguous_crockford_characters() {
        // Crockford base32 excludes I, L, O, U to avoid visual confusion
        // with 1, 1, 0, V. Confirm the character class the pattern
        // *actually publishes* really omits them, and only them, from the
        // alphabet -- reading the pattern out of the generated schema
        // rather than an independent hand-written character list, which
        // would not catch the published pattern drifting out of sync with
        // the code that produces it (e.g. C2's `[0-7]` first-character
        // restriction landing here as a copy-paste of the full alphabet
        // instead).
        let schema = schemars::schema_for!(ScanId);
        let value = serde_json::to_value(&schema).unwrap();
        let pattern = value
            .get("pattern")
            .and_then(|v| v.as_str())
            .expect("ScanId schema must have a pattern");
        let classes = char_classes_in(pattern);
        // `[0-7]` (C2's canonical-first-character restriction), then the
        // full Crockford alphabet for the remaining 25 characters.
        assert_eq!(
            classes.len(),
            2,
            "expected exactly two bracket character classes in {pattern:?}"
        );
        let full_alphabet = &classes[1];
        for excluded in ['I', 'L', 'O', 'U'] {
            assert!(
                !full_alphabet.contains(&excluded),
                "pattern character class must not contain {excluded}: {pattern:?}"
            );
        }
        // 26 allowed letters minus the 4 excluded = 22, plus 10 digits = 32.
        assert_eq!(
            full_alphabet.len(),
            32,
            "expected 32 Crockford symbols, got {full_alphabet:?} from {pattern:?}"
        );
    }

    /// Extracts every bracket (`[...]`) character class out of a regex
    /// pattern string, expanding each into its member characters (so
    /// `A-H` becomes `A`, `B`, ..., `H`), without relying on a regex engine
    /// dependency. Used to read a published pattern's actual alphabet back
    /// out, rather than hand-writing an independent copy of it that could
    /// silently drift out of sync with the code that generates the pattern.
    fn char_classes_in(pattern: &str) -> Vec<Vec<char>> {
        let mut classes = Vec::new();
        let mut chars = pattern.chars().peekable();
        while let Some(c) = chars.next() {
            if c != '[' {
                continue;
            }
            let mut class_chars = Vec::new();
            let mut inside: Vec<char> = Vec::new();
            for c2 in chars.by_ref() {
                if c2 == ']' {
                    break;
                }
                inside.push(c2);
            }
            let mut i = 0;
            while i < inside.len() {
                if i + 2 < inside.len() && inside[i + 1] == '-' {
                    class_chars.extend(inside[i]..=inside[i + 2]);
                    i += 3;
                } else {
                    class_chars.push(inside[i]);
                    i += 1;
                }
            }
            classes.push(class_chars);
        }
        classes
    }

    // --- C2: 26 Crockford characters carry 130 bits into a 128-bit `Ulid`;
    // `ulid` 3.x's decoder silently discards the two overflow bits, so on
    // its own it is not injective. Only a first character in `0`-`7` keeps
    // parsing injective; verified above (`digest_rejects_...` for the case
    // rule) and here for the first-character restriction. ---

    #[test]
    fn scan_id_rejects_first_ulid_char_above_seven() {
        for bad in [
            "scan_81ARZ3NDEKTSV4RRFFQ69G5FAV",
            "scan_91ARZ3NDEKTSV4RRFFQ69G5FAV",
            "scan_Z1ARZ3NDEKTSV4RRFFQ69G5FAV",
            "scan_A1ARZ3NDEKTSV4RRFFQ69G5FAV",
        ] {
            assert_eq!(
                bad.parse::<ScanId>(),
                Err(IdError::BadUlid),
                "{bad} must be rejected: only 0-7 are canonical first characters"
            );
        }
        // Positive control: 0-7 themselves remain accepted.
        for ok_first in ['0', '1', '7'] {
            let ok = format!("scan_{ok_first}1ARZ3NDEKTSV4RRFFQ69G5FAV");
            assert!(ok.parse::<ScanId>().is_ok(), "{ok} should still parse");
        }
    }

    #[test]
    fn ulid_parse_is_injective_previously_aliasing_inputs_no_longer_collide() {
        // Before this fix: `scan_81ARZ3NDEKTSV4RRFFQ69G5FAV` parsed
        // successfully and was `==` to `scan_01ARZ3NDEKTSV4RRFFQ69G5FAV`
        // (8 mod 8 == 0); `scan_Z1ARZ3NDEKTSV4RRFFQ69G5FAV` parsed
        // successfully and was `==` to `scan_71ARZ3NDEKTSV4RRFFQ69G5FAV`
        // (31 mod 8 == 7) -- verified empirically against `ulid` 3.0.0's
        // decoder before writing this fix. Both previously-aliasing first
        // characters are now rejected outright, so distinct wire strings
        // are never silently collapsed to the same id.
        assert_eq!(
            "scan_81ARZ3NDEKTSV4RRFFQ69G5FAV".parse::<ScanId>(),
            Err(IdError::BadUlid)
        );
        assert!("scan_01ARZ3NDEKTSV4RRFFQ69G5FAV".parse::<ScanId>().is_ok());
        assert_eq!(
            "scan_Z1ARZ3NDEKTSV4RRFFQ69G5FAV".parse::<ScanId>(),
            Err(IdError::BadUlid)
        );
        assert!("scan_71ARZ3NDEKTSV4RRFFQ69G5FAV".parse::<ScanId>().is_ok());
    }

    // --- M2 Task 1: `from_ulid` takes a `Ulid` with no validation, unlike
    // `FromStr` above. These pin the bit-level proof on `from_ulid`'s doc
    // comment that this can never actually produce a string `FromStr` would
    // reject: encoding a `u128` onto 26 Crockford characters structurally
    // cannot set the first character above `7`, for *any* `u128` whatsoever.
    // ---

    #[test]
    fn from_ulid_round_trips_for_every_reachable_first_character() {
        // The largest possible 128-bit value: `Ulid`'s field is public
        // (`pub struct Ulid(pub u128)`), so this bypasses `from_parts` and
        // `Generator` entirely and constructs the single most adversarial
        // bit pattern directly -- every bit set, not just the ones those
        // constructors happen to reach.
        let max = ScanId::from_ulid(ulid::Ulid(u128::MAX));
        let s = max.to_string();
        assert!(s.starts_with("scan_7"), "got {s}");
        assert_eq!(s.parse::<ScanId>().unwrap(), max, "must round-trip: {s}");

        // The nil ulid: every bit zero.
        let nil = ScanId::from_ulid(ulid::Ulid(0));
        let s = nil.to_string();
        assert!(s.starts_with("scan_0"), "got {s}");
        assert_eq!(s.parse::<ScanId>().unwrap(), nil, "must round-trip: {s}");

        // Every value reachable via `from_parts` with a maxed-out 48-bit
        // timestamp and maxed-out 80-bit random component -- the largest
        // value the *documented* constructor path can produce, distinct
        // from the raw-tuple case above.
        let from_parts_max = ScanId::from_ulid(ulid::Ulid::from_parts(u64::MAX, u128::MAX));
        let s = from_parts_max.to_string();
        assert!(s.starts_with("scan_7"), "got {s}");
        assert_eq!(
            s.parse::<ScanId>().unwrap(),
            from_parts_max,
            "must round-trip: {s}"
        );

        // Sweep every one of the 8 canonical first-character values
        // directly, by shifting a 3-bit pattern into the timestamp's top
        // bits, confirming each is reachable and round-trips.
        for top3 in 0u64..=7 {
            let timestamp_ms = top3 << 45; // bits 45-47 are the top 3 of 48
            let u = ulid::Ulid::from_parts(timestamp_ms, 0);
            let id = ScanId::from_ulid(u);
            let s = id.to_string();
            assert_eq!(
                &s[5..6],
                top3.to_string(),
                "top3={top3} should encode to first char {top3}, got {s}"
            );
            assert_eq!(s.parse::<ScanId>().unwrap(), id, "must round-trip: {s}");
        }
    }
}
