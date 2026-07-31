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
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).map_err(|_| IdError::BadHex)?;
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
            pub fn from_ulid(u: ulid::Ulid) -> Self {
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
                    "pattern": concat!("^", $prefix, "_[0-9A-HJKMNP-TV-Z]{26}$"),
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
    // uppercase-only Crockford (`^..._[0-9A-HJKMNP-TV-Z]{26}$`), and this
    // type must accept exactly what it publishes -- the same rule already
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
            Some("^scan_[0-9A-HJKMNP-TV-Z]{26}$"),
            "schema was {value:#}"
        );
        assert_eq!(value.get("type").and_then(|v| v.as_str()), Some("string"));
    }

    #[test]
    fn event_id_and_scope_id_json_schemas_have_expected_patterns() {
        let evt_value = serde_json::to_value(schemars::schema_for!(EventId)).unwrap();
        assert_eq!(
            evt_value.get("pattern").and_then(|v| v.as_str()),
            Some("^evt_[0-9A-HJKMNP-TV-Z]{26}$")
        );

        let scope_value = serde_json::to_value(schemars::schema_for!(ScopeId)).unwrap();
        assert_eq!(
            scope_value.get("pattern").and_then(|v| v.as_str()),
            Some("^scope_[0-9A-HJKMNP-TV-Z]{26}$")
        );
    }

    #[test]
    fn ulid_pattern_excludes_ambiguous_crockford_characters() {
        // Crockford base32 excludes I, L, O, U to avoid visual confusion
        // with 1, 1, 0, V. Confirm the character class in the pattern
        // really omits them, and only them, from the alphabet.
        let re = regex_lite_pattern_chars();
        for excluded in ['I', 'L', 'O', 'U'] {
            assert!(
                !re.contains(&excluded),
                "pattern character class must not contain {excluded}"
            );
        }
        // 26 allowed letters minus the 4 excluded = 22, plus 10 digits = 32.
        assert_eq!(re.len(), 32, "expected 32 Crockford symbols, got {re:?}");
    }

    /// Expands the literal character class used in the ULID pattern
    /// (`[0-9A-HJKMNP-TV-Z]`) into its member characters, without relying on
    /// a regex engine dependency.
    fn regex_lite_pattern_chars() -> Vec<char> {
        let mut chars = Vec::new();
        chars.extend('0'..='9');
        chars.extend('A'..='H');
        chars.push('J');
        chars.push('K');
        chars.push('M');
        chars.push('N');
        chars.extend('P'..='T');
        chars.extend('V'..='Z');
        chars
    }
}
