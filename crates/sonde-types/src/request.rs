use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ids::ScopeId;

/// What the caller is trying to learn. Objectives are a closed set so the
/// planner can map each to a bounded strategy; free-text goals belong to the
/// agent layer, which compiles them into one of these.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum Objective {
    /// Which hosts are up.
    HostInventory,
    /// Which services are listening and what they are.
    InventoryExposedServices,
    /// Re-observe a previous scan's endpoints to detect change.
    ChangeDetection,
    /// Re-probe only endpoints whose prior confidence was low.
    ConfidenceRefinement,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum EvidenceLevel {
    /// Record only the derived observation. Smallest storage.
    None,
    /// Record protocol banners and response headers. Default.
    Headers,
    /// Record full response bodies up to the per-response cap.
    Full,
}

// `rename_all = "kebab-case"` alone is NOT enough to make `Common1000` and
// `Top100` serialize/deserialize as `"common-1000"` / `"top-100"`, which is
// what the canonical example request (and AC-1.11, which requires it to
// parse "without modification") requires. Verified empirically: serde's
// case converter inserts a separator only at a lowercase-to-uppercase (or
// letter-to-digit-run-following-a-new-word) transition detected in the
// *identifier's* casing, and `Common1000`/`Top100` each contain exactly one
// such word before the trailing digits, so the whole identifier is treated
// as a single word and lowercased with no hyphen: `Common1000` ->
// `"common1000"`, `Top100` -> `"top100"`. `cargo run` against a throwaway
// probe crate on this machine's schemars/serde versions confirmed this
// directly (`serde_json::to_string(&PortPreset::Common1000)` prints
// `"common1000"`, and `"common-1000"` fails to deserialize as
// `unknown variant`). The brief's literal Step 3 code, taken as written,
// therefore cannot parse the brief's own literal Step 1 `EXAMPLE` --
// `parses_the_canonical_example_request` would fail. The explicit
// `#[serde(rename = "...")]` overrides below are the fix: they pin the wire
// value to what the design's canonical example actually uses, without
// touching the enum's Rust-side name or the `rename_all` container
// attribute for the one variant (`All`) that already round-trips fine.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub enum PortPreset {
    /// The 100 most commonly listening TCP ports, from our own dataset.
    #[serde(rename = "top-100")]
    Top100,
    /// The 1000 most commonly listening TCP ports, from our own dataset.
    #[serde(rename = "common-1000")]
    Common1000,
    /// All 65535 TCP ports. Requires a budget large enough to cover them.
    All,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields, untagged)]
pub enum PortSelection {
    Preset {
        preset: PortPreset,
    },
    /// Explicit ports and inclusive ranges, e.g. `["22", "80", "8000-8100"]`.
    Explicit {
        #[schemars(length(min = 1))]
        explicit: Vec<String>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, try_from = "RawServiceDetection")]
pub struct ServiceDetection {
    pub enabled: bool,
    /// 0-9. Higher values authorize more probes per endpoint, not more hosts.
    #[schemars(range(min = 0, max = 9))]
    pub intensity: u8,
}

impl Default for ServiceDetection {
    fn default() -> Self {
        Self {
            enabled: true,
            intensity: 4,
        }
    }
}

// `#[schemars(range(...))]` on `ServiceDetection::intensity` above affects
// only the *generated schema*, and only ever for the Serialize-contract
// branch schemars emits when a container carries `#[serde(try_from = ...)]`
// -- see the longer note above `RawBudgets` below, which explains why. It
// never runs at deserialization: serde has no built-in concept of a numeric
// range. Real parse-time rejection comes only from `TryFrom<RawServiceDetection>`
// below. `RawServiceDetection` mirrors every field so `deny_unknown_fields`
// keeps applying to this nested object, and duplicates the `range` attribute
// so the *default* (Deserialize-contract) schema `schema_for!` produces --
// which is what a schema consumer actually sees -- also carries `maximum: 9`,
// not just the Serialize-contract copy.
#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct RawServiceDetection {
    enabled: bool,
    #[schemars(range(min = 0, max = 9))]
    intensity: u8,
}

impl TryFrom<RawServiceDetection> for ServiceDetection {
    type Error = String;
    fn try_from(r: RawServiceDetection) -> Result<Self, String> {
        if r.intensity > 9 {
            return Err(format!("intensity must be <= 9, got {}", r.intensity));
        }
        Ok(Self {
            enabled: r.enabled,
            intensity: r.intensity,
        })
    }
}

/// Hard ceilings. The scheduler aborts the scan when any is exhausted; these
/// are not advisory hints. Every field is mandatory: an unbounded scan is not
/// an expressible request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields, try_from = "RawBudgets")]
pub struct Budgets {
    #[schemars(range(min = 1))]
    pub maximum_packets: u64,
    #[schemars(range(min = 1))]
    pub maximum_runtime_seconds: u64,
    #[schemars(range(min = 1))]
    pub maximum_packets_per_second: u32,
}

// Validating `range`/`length` at *deserialization* time is not automatic in
// serde -- `#[schemars(range(...))]` only feeds the JSON Schema generator.
// `RawBudgets` + `TryFrom` is the shim that gets real parse-time rejection
// (`serde(try_from = "RawBudgets")` on `Budgets` above routes every
// deserialize through this type first).
//
// Deriving `JsonSchema` on `Budgets` while it also carries
// `#[serde(try_from = "RawBudgets")]` requires `RawBudgets: JsonSchema` to
// even compile: schemars_derive 1.2.2's `expr_for_container`
// (schemars_derive-1.2.2/src/schema_exprs.rs) sets
// `type_from = serde_attrs.type_from().or(serde_attrs.type_try_from())`, so
// a bare `try_from` (no `into`) still makes `type_from` `Some(RawBudgets)`.
// The generated `json_schema()` body is then
// `if generator.contract().is_deserialize() { <RawBudgets as
// JsonSchema>::json_schema(generator) } else { <Budgets's own field-based
// schema> }`, and `SchemaGenerator::default()` (what `schema_for!` uses,
// confirmed in generate.rs) defaults `contract` to `Contract::Deserialize`.
// So the schema `schema_for!(Budgets)` actually returns comes from
// `RawBudgets`'s own `JsonSchema` impl, not from the `#[schemars(range(...))]`
// attributes on `Budgets`'s own fields above -- confirmed empirically with a
// throwaway probe crate against this workspace's exact schemars 1.2.2 before
// relying on it. The `#[schemars(range(min = 1))]` attributes are therefore
// duplicated onto `RawBudgets`'s fields below (not just left on `Budgets`'s),
// so the schema `schema_for!` produces by default still carries the `minimum`
// bound. Leaving them only on `Budgets` (as the brief's literal Step 3 code
// does) would compile, satisfy the `JsonSchema` trait, and silently emit an
// unconstrained schema -- exactly the schema/runtime divergence class of bug
// called out as Important in Task 2's review.
#[derive(Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
struct RawBudgets {
    #[schemars(range(min = 1))]
    maximum_packets: u64,
    #[schemars(range(min = 1))]
    maximum_runtime_seconds: u64,
    #[schemars(range(min = 1))]
    maximum_packets_per_second: u32,
}

impl TryFrom<RawBudgets> for Budgets {
    type Error = String;
    fn try_from(r: RawBudgets) -> Result<Self, String> {
        if r.maximum_packets == 0
            || r.maximum_runtime_seconds == 0
            || r.maximum_packets_per_second == 0
        {
            return Err("every budget must be greater than zero".into());
        }
        Ok(Self {
            maximum_packets: r.maximum_packets,
            maximum_runtime_seconds: r.maximum_runtime_seconds,
            maximum_packets_per_second: r.maximum_packets_per_second,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScanRequest {
    /// CIDRs, single addresses, or inclusive `a.b.c.d-e.f.g.h` ranges.
    #[schemars(length(min = 1))]
    pub targets: Vec<String>,
    /// The manifest authorizing this scan. Without it there is no scan.
    pub authorization_scope_id: ScopeId,
    pub objective: Objective,
    pub ports: PortSelection,
    #[serde(default)]
    pub service_detection: ServiceDetection,
    pub budgets: Budgets,
    #[serde(default = "default_evidence_level")]
    pub evidence_level: EvidenceLevel,
    /// Repeating a call with the same key and an identical plan returns the
    /// original task instead of starting a second scan.
    pub idempotency_key: String,
}

fn default_evidence_level() -> EvidenceLevel {
    EvidenceLevel::Headers
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = r#"{
      "targets": ["10.30.0.0/24"],
      "authorization_scope_id": "scope_01ARZ3NDEKTSV4RRFFQ69G5FAV",
      "objective": "inventory_exposed_services",
      "ports": { "preset": "common-1000" },
      "service_detection": { "enabled": true, "intensity": 4 },
      "budgets": {
        "maximum_packets": 200000,
        "maximum_runtime_seconds": 900,
        "maximum_packets_per_second": 5000
      },
      "evidence_level": "headers",
      "idempotency_key": "asset-inventory-2026-08-01"
    }"#;

    #[test]
    fn parses_the_canonical_example_request() {
        let r: ScanRequest = serde_json::from_str(EXAMPLE).unwrap();
        assert_eq!(r.targets.len(), 1);
        assert_eq!(r.objective, Objective::InventoryExposedServices);
        assert_eq!(r.budgets.maximum_packets, 200_000);
        assert_eq!(r.evidence_level, EvidenceLevel::Headers);
        assert_eq!(r.service_detection.intensity, 4);
    }

    #[test]
    fn budgets_are_mandatory() {
        let no_budget = EXAMPLE.replace(
            r#""budgets": {
        "maximum_packets": 200000,
        "maximum_runtime_seconds": 900,
        "maximum_packets_per_second": 5000
      },"#,
            "",
        );
        assert!(serde_json::from_str::<ScanRequest>(&no_budget).is_err());
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let extra = EXAMPLE.replace(r#""targets""#, r#""stealth_mode": true, "targets""#);
        assert!(serde_json::from_str::<ScanRequest>(&extra).is_err());
    }

    #[test]
    fn zero_budget_is_rejected() {
        let zero = EXAMPLE.replace("\"maximum_packets\": 200000", "\"maximum_packets\": 0");
        assert!(serde_json::from_str::<ScanRequest>(&zero).is_err());
    }

    #[test]
    fn intensity_above_nine_is_rejected() {
        let hot = EXAMPLE.replace("\"intensity\": 4", "\"intensity\": 12");
        assert!(serde_json::from_str::<ScanRequest>(&hot).is_err());
    }

    // --- Additional coverage beyond the brief's minimal test list ---

    // AC-1.11: also try `PortPreset::Top100` and `PortPreset::All`, and a
    // round trip, to prove the canonical example isn't the *only* preset
    // value that survives the kebab-case rename fix documented above
    // `PortPreset`.
    #[test]
    fn all_port_presets_round_trip_through_kebab_case_wire_values() {
        for (preset, wire) in [
            (PortPreset::Top100, "\"top-100\""),
            (PortPreset::Common1000, "\"common-1000\""),
            (PortPreset::All, "\"all\""),
        ] {
            assert_eq!(serde_json::to_string(&preset).unwrap(), wire, "{preset:?}");
            let back: PortPreset = serde_json::from_str(wire).unwrap();
            assert_eq!(back, preset);
        }
    }

    // AC-1.12: every individual budget field being zero is rejected, not
    // just `maximum_packets` (the brief's own `zero_budget_is_rejected`
    // only exercises one field).
    #[test]
    fn each_budget_field_is_individually_checked_for_zero() {
        for zeroed in [
            "\"maximum_packets\": 0,\n        \"maximum_runtime_seconds\": 900,\n        \"maximum_packets_per_second\": 5000",
            "\"maximum_packets\": 200000,\n        \"maximum_runtime_seconds\": 0,\n        \"maximum_packets_per_second\": 5000",
            "\"maximum_packets\": 200000,\n        \"maximum_runtime_seconds\": 900,\n        \"maximum_packets_per_second\": 0",
        ] {
            let json = EXAMPLE.replace(
                "\"maximum_packets\": 200000,\n        \"maximum_runtime_seconds\": 900,\n        \"maximum_packets_per_second\": 5000",
                zeroed,
            );
            assert!(
                serde_json::from_str::<ScanRequest>(&json).is_err(),
                "expected rejection for {zeroed}"
            );
        }
    }

    #[test]
    fn budgets_at_the_minimum_boundary_are_accepted() {
        let min = EXAMPLE.replace(
            "\"maximum_packets\": 200000,\n        \"maximum_runtime_seconds\": 900,\n        \"maximum_packets_per_second\": 5000",
            "\"maximum_packets\": 1,\n        \"maximum_runtime_seconds\": 1,\n        \"maximum_packets_per_second\": 1",
        );
        assert!(serde_json::from_str::<ScanRequest>(&min).is_ok());
    }

    // AC-1.14: `intensity == 9` (the boundary) is accepted, `intensity == 10`
    // (one past it) is rejected. The brief's own test only tries 12.
    #[test]
    fn intensity_nine_is_accepted_and_ten_is_rejected() {
        let nine = EXAMPLE.replace("\"intensity\": 4", "\"intensity\": 9");
        assert!(serde_json::from_str::<ScanRequest>(&nine).is_ok());

        let ten = EXAMPLE.replace("\"intensity\": 4", "\"intensity\": 10");
        assert!(serde_json::from_str::<ScanRequest>(&ten).is_err());
    }

    // AC-1.13: unknown fields are rejected not just at the top level (the
    // brief's own test) but inside every nested `deny_unknown_fields`
    // struct too -- each of these goes through a different code path
    // (`Budgets`/`ServiceDetection` via the raw-mirror `try_from` shim,
    // `ScanRequest` via a plain derive).
    #[test]
    fn unknown_fields_are_rejected_inside_budgets() {
        let extra_in_budgets = EXAMPLE.replace(
            "\"maximum_packets\": 200000,",
            "\"maximum_packets\": 200000, \"stealth_mode\": true,",
        );
        assert!(serde_json::from_str::<ScanRequest>(&extra_in_budgets).is_err());
    }

    #[test]
    fn unknown_fields_are_rejected_inside_service_detection() {
        let extra_in_service_detection = EXAMPLE.replace(
            "\"service_detection\": { \"enabled\": true, \"intensity\": 4 }",
            "\"service_detection\": { \"enabled\": true, \"intensity\": 4, \"stealth_mode\": true }",
        );
        assert!(serde_json::from_str::<ScanRequest>(&extra_in_service_detection).is_err());
    }

    // AC-1.15: `authorization_scope_id` must be present, and must be a
    // syntactically valid `ScopeId` (not just any string).
    #[test]
    fn missing_authorization_scope_id_is_rejected() {
        let no_scope = EXAMPLE.replace(
            "\"authorization_scope_id\": \"scope_01ARZ3NDEKTSV4RRFFQ69G5FAV\",",
            "",
        );
        assert!(serde_json::from_str::<ScanRequest>(&no_scope).is_err());
    }

    #[test]
    fn malformed_authorization_scope_id_is_rejected() {
        let bad_scope = EXAMPLE.replace(
            "scope_01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "scan_01ARZ3NDEKTSV4RRFFQ69G5FAV", // wrong prefix: a ScanId, not a ScopeId
        );
        assert!(serde_json::from_str::<ScanRequest>(&bad_scope).is_err());
    }

    // `service_detection` and `evidence_level` are the only two fields with
    // defaults; confirm omitting them still parses and produces the
    // documented defaults.
    #[test]
    fn service_detection_and_evidence_level_default_when_omitted() {
        let json = r#"{
          "targets": ["10.30.0.0/24"],
          "authorization_scope_id": "scope_01ARZ3NDEKTSV4RRFFQ69G5FAV",
          "objective": "host_inventory",
          "ports": { "preset": "top-100" },
          "budgets": {
            "maximum_packets": 1,
            "maximum_runtime_seconds": 1,
            "maximum_packets_per_second": 1
          },
          "idempotency_key": "x"
        }"#;
        let r: ScanRequest = serde_json::from_str(json).unwrap();
        assert_eq!(r.service_detection, ServiceDetection::default());
        assert_eq!(r.evidence_level, EvidenceLevel::Headers);
    }

    // `PortSelection` is `untagged`: prove both variants parse to the right
    // shape, and that ambiguous/empty objects are rejected rather than
    // silently picked as one variant or the other.
    #[test]
    fn port_selection_preset_variant_parses() {
        let ps: PortSelection = serde_json::from_str(r#"{"preset": "common-1000"}"#).unwrap();
        assert_eq!(
            ps,
            PortSelection::Preset {
                preset: PortPreset::Common1000
            }
        );
    }

    #[test]
    fn port_selection_explicit_variant_parses() {
        let ps: PortSelection = serde_json::from_str(r#"{"explicit": ["22", "80"]}"#).unwrap();
        assert_eq!(
            ps,
            PortSelection::Explicit {
                explicit: vec!["22".to_string(), "80".to_string()]
            }
        );
    }

    #[test]
    fn port_selection_empty_object_is_rejected() {
        let err = serde_json::from_str::<PortSelection>("{}").unwrap_err();
        // Untagged enums fail confusingly by default (a bare "data did not
        // match any variant" with no field-level detail); assert on the
        // actual message so a future serde upgrade that changes wording
        // doesn't silently make this assertion meaningless, and so anyone
        // reading the test knows exactly what an agent client will see.
        assert!(
            err.to_string().contains("did not match any variant"),
            "got: {err}"
        );
    }

    #[test]
    fn port_selection_ambiguous_object_with_both_fields_is_rejected() {
        let err = serde_json::from_str::<PortSelection>(
            r#"{"preset": "common-1000", "explicit": ["22"]}"#,
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("did not match any variant"),
            "got: {err}"
        );
    }

    #[test]
    fn port_selection_explicit_with_empty_array_is_rejected() {
        // `explicit: []` fails the untagged match (neither variant's own
        // deny_unknown_fields/shape rejects it directly -- `length(min=1)`
        // is schema-only, so this is really exercising that an empty
        // `explicit` array is still structurally valid JSON for the
        // `Explicit` variant and therefore *does* parse; documented here so
        // the schema-only nature of that constraint (see `targets` below)
        // isn't mistaken for a runtime guarantee).
        let ps: PortSelection = serde_json::from_str(r#"{"explicit": []}"#).unwrap();
        assert_eq!(ps, PortSelection::Explicit { explicit: vec![] });
    }

    // --- Schema/runtime agreement (the dispatch's explicit ask): prove the
    // emitted schema for `ScanRequest` and its nested types matches what
    // `serde_json::from_str` actually enforces above, not just that a
    // `JsonSchema` impl exists and compiles. ---

    #[test]
    fn scan_request_schema_has_budgets_required_and_denies_additional_properties() {
        let schema = schemars::schema_for!(ScanRequest);
        let value = serde_json::to_value(&schema).unwrap();
        let required: Vec<&str> = value["required"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert!(required.contains(&"budgets"), "required was {required:?}");
        assert!(
            required.contains(&"authorization_scope_id"),
            "required was {required:?}"
        );
        // service_detection and evidence_level have defaults, so they must
        // NOT be required -- if they were, the schema would be stricter
        // than the type actually is.
        assert!(!required.contains(&"service_detection"));
        assert!(!required.contains(&"evidence_level"));
        assert_eq!(
            value.get("additionalProperties").and_then(|v| v.as_bool()),
            Some(false),
            "schema was {value:#}"
        );
    }

    #[test]
    fn budgets_schema_has_minimum_one_on_every_field() {
        let schema = schemars::schema_for!(Budgets);
        let value = serde_json::to_value(&schema).unwrap();
        for field in [
            "maximum_packets",
            "maximum_runtime_seconds",
            "maximum_packets_per_second",
        ] {
            assert_eq!(
                value["properties"][field]["minimum"].as_u64(),
                Some(1),
                "field {field} in schema {value:#}"
            );
        }
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
        assert!(required.contains(&"maximum_packets"));
        assert!(required.contains(&"maximum_runtime_seconds"));
        assert!(required.contains(&"maximum_packets_per_second"));
    }

    #[test]
    fn service_detection_schema_has_intensity_bound_zero_to_nine() {
        let schema = schemars::schema_for!(ServiceDetection);
        let value = serde_json::to_value(&schema).unwrap();
        assert_eq!(
            value["properties"]["intensity"]["minimum"].as_u64(),
            Some(0)
        );
        assert_eq!(
            value["properties"]["intensity"]["maximum"].as_u64(),
            Some(9)
        );
        assert_eq!(
            value.get("additionalProperties").and_then(|v| v.as_bool()),
            Some(false),
            "schema was {value:#}"
        );
    }
}
