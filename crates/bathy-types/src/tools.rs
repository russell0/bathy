//! The typed input and output shapes of the agent-facing tool surface.
//!
//! Every one of these derives `JsonSchema` and is committed under `schemas/`,
//! because the server publishes the *derived* schema as each tool's
//! `inputSchema`/`outputSchema` rather than a hand-written one. A tool whose
//! schema is written by hand is a second spelling of the contract, and the
//! two spellings drift.
//!
//! # The two absences
//!
//! Nothing here has a `command`, `args`, `flags`, `argv` or `raw` field: an
//! agent cannot construct a command line through this surface, and the way
//! that is guaranteed is that there is no field to put one in.
//!
//! Nothing here has a `manifest_json`, `manifest`, `scope_manifest`,
//! `scope_id` or `allowed_cidrs` *input* field either. A scope is named by a
//! path -- `manifest_path`, exactly what `--scope <PATH>` takes -- and the
//! server loads the document. A caller that can pass an inline manifest can
//! author its own authorization, so the manifest arrives out of band, from an
//! operator, as a file the agent did not write.
//!
//! `ScanRequestSpec` is why `ScanRequest` itself is not an input type.
//! `ScanRequest::authorization_scope_id` is the identity of the manifest that
//! authorized the scan; it is filled by the server from the manifest it
//! loaded. Accepting a `ScanRequest` would put a scope id in an input schema
//! and leave a validation step where an absence does the job.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ids::{Digest, ScanId, ScopeId};
use crate::nonempty::NonEmpty;
use crate::request::{
    Budgets, EvidenceLevel, Objective, PortSelection, ScanRequest, ServiceDetection,
};
use crate::task::{PolicyDecisionTag, TaskHandle, TaskStatus};

// ---------------------------------------------------------------------------
// The request, minus the one field the server owns.
// ---------------------------------------------------------------------------

/// A scan request as a caller may state it.
///
/// This is every field of a scan request except the identity of the manifest
/// that authorizes it, which the server fills in from the document it loaded
/// at `manifest_path`. The budget fields are optional and default to the
/// manifest's own ceiling: the ceiling is a hard limit an operator already
/// wrote down, and the alternative -- a built-in default -- would be a number
/// this program invented for someone else's network.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScanRequestSpec {
    /// CIDRs, single addresses, or inclusive `a.b.c.d-e.f.g.h` ranges.
    pub targets: NonEmpty<String>,
    /// What this scan is for.
    pub objective: Objective,
    /// A named preset, or an explicit list of ports and inclusive ranges.
    pub ports: PortSelection,
    #[serde(default)]
    pub service_detection: ServiceDetection,
    #[serde(default = "default_evidence_level")]
    pub evidence_level: EvidenceLevel,
    /// Hard packet ceiling. Defaults to the manifest's own ceiling.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_packets: Option<u64>,
    /// Hard runtime ceiling in seconds. Defaults to the manifest's own ceiling.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_runtime_seconds: Option<u64>,
    /// Hard packets-per-second ceiling. Defaults to the manifest's own ceiling.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_packets_per_second: Option<u32>,
    /// Names this attempt. Repeating it with an identical plan returns the
    /// original scan; repeating it with a different plan is refused.
    pub idempotency_key: String,
}

fn default_evidence_level() -> EvidenceLevel {
    EvidenceLevel::Headers
}

/// Why a spec could not be turned into a request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpecError {
    pub code: &'static str,
    pub detail: String,
}

impl std::fmt::Display for SpecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.detail)
    }
}

impl std::error::Error for SpecError {}

impl ScanRequestSpec {
    /// Fill in the manifest identity and the budgets the caller left to the
    /// ceiling, producing the request the planner actually hashes.
    pub fn into_request(
        self,
        scope_id: ScopeId,
        ceiling: Budgets,
    ) -> Result<ScanRequest, SpecError> {
        let budgets = Budgets {
            maximum_packets: self.max_packets.unwrap_or(ceiling.maximum_packets),
            maximum_runtime_seconds: self
                .max_runtime_seconds
                .unwrap_or(ceiling.maximum_runtime_seconds),
            maximum_packets_per_second: self
                .max_packets_per_second
                .unwrap_or(ceiling.maximum_packets_per_second),
        };
        if budgets.maximum_packets == 0
            || budgets.maximum_runtime_seconds == 0
            || budgets.maximum_packets_per_second == 0
        {
            return Err(SpecError {
                code: "bad_budget",
                detail: "every budget must be greater than zero".into(),
            });
        }
        if self.service_detection.intensity > 9 {
            return Err(SpecError {
                code: "bad_intensity",
                detail: format!(
                    "intensity must be 0-9, got {}",
                    self.service_detection.intensity
                ),
            });
        }
        Ok(ScanRequest {
            targets: self.targets,
            authorization_scope_id: scope_id,
            objective: self.objective,
            ports: self.ports,
            service_detection: self.service_detection,
            budgets,
            evidence_level: self.evidence_level,
            idempotency_key: self.idempotency_key,
        })
    }
}

// ---------------------------------------------------------------------------
// scope.validate
// ---------------------------------------------------------------------------

/// Load a scope manifest and report what it authorizes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScopeValidateInput {
    /// Filesystem path to the scope manifest document.
    pub manifest_path: String,
    /// Addresses, CIDRs or inclusive ranges to check against the manifest.
    /// An empty list checks the manifest alone.
    #[serde(default)]
    pub targets: Vec<String>,
}

/// The ceilings a manifest sets on any scan it authorizes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BudgetCeiling {
    pub maximum_packets: u64,
    pub maximum_runtime_seconds: u64,
    pub maximum_packets_per_second: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScopeValidateOutput {
    /// `approved` only if the manifest is usable *and* every supplied target
    /// is inside its allow set and outside its deny set.
    pub decision: PolicyDecisionTag,
    /// A stable code, present exactly when `decision` is `denied`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// The identity this manifest declares. It is what a started scan
    /// records on every event it writes.
    pub scope_id: ScopeId,
    pub description: String,
    /// True when the manifest's expiry has passed. An expired manifest
    /// authorizes nothing.
    pub expired: bool,
    /// How many of the supplied targets, after expansion, are inside the
    /// allow set and outside the deny set.
    pub in_scope_count: u64,
    /// The supplied targets that are not, as written by the caller.
    pub out_of_scope: Vec<String>,
    pub budget_ceiling: BudgetCeiling,
    /// True when the document carries a signature field. Signatures are not
    /// verified in this version, so a present one grants nothing.
    pub signature_present: bool,
    pub signature_verified: bool,
}

// ---------------------------------------------------------------------------
// scan.preview
// ---------------------------------------------------------------------------

/// Compute a plan and a policy decision without emitting a packet.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScanPreviewInput {
    /// Filesystem path to the scope manifest authorizing this scan.
    pub manifest_path: String,
    pub request: ScanRequestSpec,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScanPreviewOutput {
    pub policy_decision: PolicyDecisionTag,
    /// The hash of the plan this request expands to. Present only when the
    /// scan was approved, so it matches what the command-line surface
    /// reports for the same request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan_hash: Option<Digest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub estimated_targets: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub estimated_probes: Option<u64>,
    /// A lower bound: the probe count divided by the packets-per-second
    /// ceiling, rounded up. Probe latency and connection limits can only
    /// make a real run slower than this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub estimated_runtime_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope_id: Option<ScopeId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

// ---------------------------------------------------------------------------
// scan.start
// ---------------------------------------------------------------------------

/// Admit a scan and begin it. Returns immediately with a handle.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScanStartInput {
    /// Filesystem path to the scope manifest authorizing this scan.
    pub manifest_path: String,
    pub request: ScanRequestSpec,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScanStartOutput {
    pub policy_decision: PolicyDecisionTag,
    /// Present exactly when `policy_decision` is `approved`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle: Option<TaskHandle>,
    /// A stable code, present exactly when `policy_decision` is `denied`.
    /// No packet was emitted and no scan record was created.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason_code: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// True when this key already named a scan and that scan was returned
    /// instead of a second one being started.
    pub reused: bool,
}

// ---------------------------------------------------------------------------
// scan.status / scan.events / scan.cancel / scan.resume
// ---------------------------------------------------------------------------

/// Report a scan's stored lifecycle record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScanStatusInput {
    pub scan_id: ScanId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScanStatusOutput {
    pub scan_id: ScanId,
    pub status: TaskStatus,
    /// Probe units whose result has been durably written.
    pub units_completed: u64,
    /// Probe units the plan contains.
    pub units_total: u64,
    pub packets_spent: u64,
    pub elapsed_seconds: u64,
    /// The highest sequence number written to this scan's event log.
    pub last_sequence: u64,
    pub plan_hash: Digest,
    pub scope_id: ScopeId,
    pub idempotency_key: String,
    pub created_at: String,
    pub updated_at: String,
}

/// Read a page of a scan's event log.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScanEventsInput {
    pub scan_id: ScanId,
    /// Return only events with a sequence number strictly greater than this.
    /// Start at 0; then pass the previous page's `next_cursor`.
    #[serde(default)]
    pub after_sequence: u64,
    /// How many events to return at most. 1 to 1000.
    #[serde(default = "default_event_limit")]
    #[schemars(range(min = 1, max = 1000))]
    pub limit: u32,
}

fn default_event_limit() -> u32 {
    200
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScanEventsOutput {
    pub events: Vec<crate::event::Event>,
    /// The sequence number to pass as the next call's `after_sequence`.
    /// Unchanged from the request when the page is empty.
    pub next_cursor: u64,
    /// True when the log already holds events beyond this page. False does
    /// not mean the scan is over -- a running scan appends more.
    pub has_more: bool,
}

/// Ask a running scan to stop. In-flight probes are drained, not dropped.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScanCancelInput {
    pub scan_id: ScanId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScanCancelOutput {
    pub scan_id: ScanId,
    /// The status at the moment cancellation was requested. A scan that was
    /// still running reaches `cancelled` shortly after this returns.
    pub status: TaskStatus,
    pub units_completed: u64,
    /// True when unfinished units remain, so a later resume has work to do.
    pub resumable: bool,
    pub cancellation_requested: bool,
}

/// Continue a scan that stopped before its plan was exhausted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScanResumeInput {
    /// Filesystem path to the scope manifest authorizing this scan. It is
    /// evaluated again: a manifest that has expired or narrowed since the
    /// scan started refuses the resume.
    pub manifest_path: String,
    pub scan_id: ScanId,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ScanResumeOutput {
    pub scan_id: ScanId,
    pub status: TaskStatus,
    /// The plan index work restarted at.
    pub resumed_from_unit: u64,
    pub units_total: u64,
    /// False when the scan had no unfinished units and nothing was started.
    pub resumed: bool,
}

// ---------------------------------------------------------------------------
// result.diff
// ---------------------------------------------------------------------------

/// Compare two finished scans.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ResultDiffInput {
    pub before_scan_id: ScanId,
    pub after_scan_id: ScanId,
    /// Keep changes where only the confidence moved. Confidence wobbles
    /// between runs, so these are separated from substantive change and
    /// dropped by default.
    #[serde(default)]
    pub include_confidence_only: bool,
}

// ---------------------------------------------------------------------------
// evidence.get
// ---------------------------------------------------------------------------

/// Fetch the exact bytes a finding cited.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvidenceGetInput {
    /// A `blake3:<64 hex>` digest, as cited by an event's `evidence_refs`.
    pub digest: Digest,
    /// Return at most this many bytes. Absent returns all of them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_bytes: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EvidenceGetOutput {
    pub digest: Digest,
    /// The stored length, before any truncation this call applied.
    pub length: u64,
    /// True when `max_bytes` cut the returned value short.
    pub truncated: bool,
    /// The bytes, lowercase hex, two characters per byte. Hex rather than
    /// base64 because a human comparing a short banner against a packet
    /// capture can read it, and because the digest that names it is written
    /// the same way. The returned bytes were verified against that digest
    /// before this value was built.
    pub bytes_hex: String,
}

// ---------------------------------------------------------------------------
// fingerprint.explain
// ---------------------------------------------------------------------------

/// Explain an interpretation rule: what it looks for, and where the claim
/// comes from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FingerprintExplainInput {
    /// The rule identifier an observation cites.
    pub rule_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FingerprintExplainOutput {
    pub rule_id: String,
    /// The service name the rule concludes.
    pub service: String,
    /// How specific the conclusion is: a bare protocol, a product, or a
    /// product and version.
    pub specificity: String,
    /// What the rule looks for in the response bytes.
    pub rationale: String,
    /// Where the claim comes from: a standards section, vendor
    /// documentation, or a capture this project took itself.
    pub source: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec() -> ScanRequestSpec {
        ScanRequestSpec {
            targets: NonEmpty::try_from(vec!["10.30.0.0/30".to_string()]).unwrap(),
            objective: Objective::InventoryExposedServices,
            ports: PortSelection::Explicit {
                explicit: NonEmpty::try_from(vec!["80".to_string()]).unwrap(),
            },
            service_detection: ServiceDetection::default(),
            evidence_level: EvidenceLevel::Headers,
            max_packets: None,
            max_runtime_seconds: None,
            max_packets_per_second: None,
            idempotency_key: "k".into(),
        }
    }

    fn ceiling() -> Budgets {
        Budgets {
            maximum_packets: 1_000,
            maximum_runtime_seconds: 60,
            maximum_packets_per_second: 100,
        }
    }

    fn scope() -> ScopeId {
        "scope_01ARZ3NDEKTSV4RRFFQ69G5FAV".parse().unwrap()
    }

    #[test]
    fn an_unstated_budget_falls_back_to_the_manifests_own_ceiling() {
        let r = spec().into_request(scope(), ceiling()).unwrap();
        assert_eq!(r.budgets, ceiling());
        assert_eq!(r.authorization_scope_id, scope());
    }

    #[test]
    fn a_stated_budget_wins_over_the_ceiling_field_by_field() {
        let mut s = spec();
        s.max_packets = Some(7);
        let r = s.into_request(scope(), ceiling()).unwrap();
        assert_eq!(r.budgets.maximum_packets, 7);
        assert_eq!(
            r.budgets.maximum_runtime_seconds,
            ceiling().maximum_runtime_seconds
        );
    }

    #[test]
    fn a_zero_budget_is_refused_rather_than_silently_raised() {
        let mut s = spec();
        s.max_packets_per_second = Some(0);
        assert_eq!(
            s.into_request(scope(), ceiling()).unwrap_err().code,
            "bad_budget"
        );
    }

    /// The absence AC-5.38 pins, asserted over the schema of every input
    /// type this module defines rather than over a validation step.
    #[test]
    fn no_input_schema_names_a_scope_by_anything_but_a_path() {
        for (name, schema) in super::super::schema::all() {
            if !name.starts_with("mcp-") || !name.ends_with("-input") {
                continue;
            }
            let rendered = serde_json::to_string(&schema).unwrap();
            for forbidden in [
                "\"manifest_json\"",
                "\"manifest\"",
                "\"scope_manifest\"",
                "\"scope_id\"",
                "\"allowed_cidrs\"",
            ] {
                assert!(
                    !rendered.contains(forbidden),
                    "{name} exposes {forbidden}: a caller that can pass a manifest \
                     can authorize itself"
                );
            }
        }
    }

    #[test]
    fn no_input_schema_lets_an_agent_build_a_command_line() {
        for (name, schema) in super::super::schema::all() {
            if !name.starts_with("mcp-") || !name.ends_with("-input") {
                continue;
            }
            let rendered = serde_json::to_string(&schema).unwrap();
            for forbidden in [
                "\"command\"",
                "\"args\"",
                "\"flags\"",
                "\"argv\"",
                "\"raw\"",
            ] {
                assert!(!rendered.contains(forbidden), "{name} exposes {forbidden}");
            }
        }
    }

    #[test]
    fn a_scan_request_spec_carries_no_authorization_scope_id_at_all() {
        // The field is not merely ignored on input: there is no place to put
        // it, so `deny_unknown_fields` refuses a caller that tries.
        let json = serde_json::json!({
            "targets": ["10.30.0.0/30"],
            "authorization_scope_id": "scope_01ARZ3NDEKTSV4RRFFQ69G5FAV",
            "objective": "inventory_exposed_services",
            "ports": { "explicit": ["80"] },
            "idempotency_key": "k"
        });
        assert!(serde_json::from_value::<ScanRequestSpec>(json).is_err());
    }

    #[test]
    fn every_input_schema_is_an_object_with_properties() {
        for (name, schema) in super::super::schema::all() {
            if !name.starts_with("mcp-") || !name.ends_with("-input") {
                continue;
            }
            assert_eq!(schema["type"], "object", "{name}: {schema:#}");
            assert!(schema.get("properties").is_some(), "{name}: {schema:#}");
        }
    }
}
