use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ids::ScopeId;
use crate::nonempty::NonEmpty;
use crate::request::Budgets;

/// Wire/schema mirror of `sonde_scope::manifest::ScopeManifest`'s on-disk
/// JSON form.
///
/// Lives here, not in `sonde-scope`, purely so `sonde_types::schema::all()`
/// can publish `scope-manifest.json` without `sonde-types` -- a
/// zero-internal-dependency, pure contract crate -- taking on `ipnet`'s
/// CIDR-parsing behavior as a dependency. Accordingly, `allowed_cidrs` and
/// `denied_cidrs` are plain strings here, not `ipnet::IpNet`: this type
/// describes the wire *shape*, it does not validate that each string is a
/// syntactically valid CIDR (that validation, and the reserved-range and
/// deny-beats-allow policy `ScopeManifestDto` deliberately says nothing
/// about, live in `sonde_scope::manifest::ScopeManifest::load`, which is the
/// only code path that may ever decide whether a packet is authorized).
///
/// `allowed_cidrs` still uses `NonEmpty<String>` rather than `Vec<String>`,
/// for the same reason `ScanRequest::targets` and
/// `PortSelection::Explicit::explicit` do (see `request.rs`): a
/// `#[schemars(length(min = 1))]` attribute alone only shows up in the
/// *published* schema, it does not stop `{"allowed_cidrs": []}` from
/// deserializing through this type. `sonde_scope::manifest::Raw` (a
/// separate, unrelated deserialization target) enforces the same "at least
/// one allowed CIDR" rule independently via its own explicit empty check,
/// since `ScopeManifest::load` does not deserialize through this DTO at
/// all -- keep both in sync by hand if the rule ever changes.
///
/// This type is a schema/documentation artifact, not part of any runtime
/// authorization path. `sonde_scope::manifest::ScopeManifest` is the sole
/// authority on what a manifest means; this mirror must be kept in sync
/// with it by hand.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScopeManifestDto {
    pub id: ScopeId,
    pub description: String,
    /// RFC 3339 instant after which the manifest is no longer valid.
    // C3: pinned in the published schema via `format: "date-time"` below so
    // the contract is at least honest, mirroring every other invariant in
    // this crate. `sonde_scope::manifest::ScopeManifest::load` (the sole
    // runtime authority) already parses and validates this at load time --
    // see `ManifestError::BadExpiry`; this DTO is schema/documentation
    // only and adds no new runtime parsing.
    #[schemars(extend("format" = "date-time"))]
    pub not_after: String,
    /// CIDR strings, e.g. `"10.30.0.0/24"`. Parsed and validated by
    /// `sonde-scope` at load time, not by this type.
    pub allowed_cidrs: NonEmpty<String>,
    /// CIDR strings. Deny always beats allow, regardless of specificity.
    #[serde(default)]
    pub denied_cidrs: Vec<String>,
    pub budget_ceiling: Budgets,
    /// Reserved for v0.2 detached-signature verification; accepted on the
    /// wire but NOT cryptographically verified by this version. See
    /// `sonde_scope::manifest::ScopeManifest::signature_verified`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = r#"{
      "id": "scope_01ARZ3NDEKTSV4RRFFQ69G5FAV",
      "description": "Lab subnet, August 2026 inventory",
      "not_after": "2026-09-01T00:00:00.000Z",
      "allowed_cidrs": ["10.30.0.0/24"],
      "denied_cidrs": ["10.30.0.1/32"],
      "budget_ceiling": {
        "maximum_packets": 1000000,
        "maximum_runtime_seconds": 3600,
        "maximum_packets_per_second": 20000
      }
    }"#;

    #[test]
    fn parses_the_canonical_example_manifest() {
        let dto: ScopeManifestDto = serde_json::from_str(EXAMPLE).unwrap();
        assert_eq!(dto.allowed_cidrs.len(), 1);
        assert_eq!(dto.denied_cidrs, vec!["10.30.0.1/32".to_string()]);
        assert!(dto.signature.is_none());
    }

    #[test]
    fn empty_allowed_cidrs_is_rejected() {
        let empty = EXAMPLE.replace(
            r#""allowed_cidrs": ["10.30.0.0/24"],"#,
            r#""allowed_cidrs": [],"#,
        );
        assert!(serde_json::from_str::<ScopeManifestDto>(&empty).is_err());
    }

    #[test]
    fn denied_cidrs_defaults_to_empty_when_omitted() {
        let no_deny = EXAMPLE.replace(r#""denied_cidrs": ["10.30.0.1/32"],"#, "");
        let dto: ScopeManifestDto = serde_json::from_str(&no_deny).unwrap();
        assert!(dto.denied_cidrs.is_empty());
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let extra = EXAMPLE.replace(r#""description""#, r#""stealth_mode": true, "description""#);
        assert!(serde_json::from_str::<ScopeManifestDto>(&extra).is_err());
    }

    #[test]
    fn signature_round_trips_when_present() {
        let with_sig = EXAMPLE.replace(
            r#""budget_ceiling""#,
            r#""signature": "deadbeef", "budget_ceiling""#,
        );
        let dto: ScopeManifestDto = serde_json::from_str(&with_sig).unwrap();
        assert_eq!(dto.signature.as_deref(), Some("deadbeef"));
        let json = serde_json::to_value(&dto).unwrap();
        assert_eq!(json["signature"], "deadbeef");
    }

    #[test]
    fn signature_is_omitted_from_serialized_output_when_absent() {
        let dto: ScopeManifestDto = serde_json::from_str(EXAMPLE).unwrap();
        let json = serde_json::to_value(&dto).unwrap();
        assert!(
            json.get("signature").is_none(),
            "signature key should be entirely absent, not null: {json:#}"
        );
    }

    // --- Schema carries the same `minItems: 1` guarantee on allowed_cidrs
    // that ScanRequest::targets carries (see request.rs's equivalent test),
    // proven through the $ref rather than assumed. ---

    #[test]
    fn allowed_cidrs_schema_carries_min_items_one_through_ref() {
        let schema = schemars::schema_for!(ScopeManifestDto);
        let value = serde_json::to_value(&schema).unwrap();
        let ref_path = value["properties"]["allowed_cidrs"]["$ref"]
            .as_str()
            .expect("allowed_cidrs should be a $ref, not an inline schema")
            .strip_prefix("#/$defs/")
            .unwrap();
        assert_eq!(
            value["$defs"][ref_path]["minItems"].as_u64(),
            Some(1),
            "schema was {value:#}"
        );
        assert_eq!(
            value.get("additionalProperties").and_then(|v| v.as_bool()),
            Some(false),
            "schema was {value:#}"
        );
        let required: Vec<&str> = value["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert!(required.contains(&"allowed_cidrs"));
        assert!(required.contains(&"id"));
        assert!(required.contains(&"not_after"));
        assert!(required.contains(&"budget_ceiling"));
        // denied_cidrs and signature both have defaults, so must not be
        // required -- otherwise the schema would be stricter than the type.
        assert!(!required.contains(&"denied_cidrs"));
        assert!(!required.contains(&"signature"));
    }

    // --- C3: the Global Constraint promises RFC 3339 UTC with milliseconds
    // for every timestamp; the published schema must actually say so. See
    // `event::tests::event_timestamp_schema_declares_date_time_format` for
    // the same proof on `Event.timestamp`. ---

    #[test]
    fn not_after_schema_declares_date_time_format() {
        let schema = schemars::schema_for!(ScopeManifestDto);
        let value = serde_json::to_value(&schema).unwrap();
        assert_eq!(
            value["properties"]["not_after"]["format"].as_str(),
            Some("date-time"),
            "schema was {value:#}"
        );
        assert_eq!(
            value["properties"]["not_after"]["type"].as_str(),
            Some("string"),
            "schema was {value:#}"
        );
    }
}
