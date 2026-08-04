//! `scope.validate`.

use bathy_plan::expand_targets;
use bathy_types::DenyReason;
use bathy_types::task::PolicyDecisionTag;
use bathy_types::tools::{BudgetCeiling, ScopeValidateInput, ScopeValidateOutput};

use crate::engine::{MAX_TARGETS, load_manifest};
use crate::error::ToolResult;

pub fn validate(input: ScopeValidateInput, now_rfc3339: &str) -> ToolResult<ScopeValidateOutput> {
    let manifest = load_manifest(&input.manifest_path)?;
    let ceiling = manifest.ceiling();
    let expired = manifest.is_expired(now_rfc3339);

    // Each written target is expanded on its own, so the answer can name the
    // range the caller typed rather than an address inside it. A range that
    // does not parse is reported as out of scope: it authorizes nothing, and
    // saying so is the same answer a scan of it would get.
    let mut in_scope_count: u64 = 0;
    let mut out_of_scope = Vec::new();
    for spec in &input.targets {
        match expand_targets(std::slice::from_ref(spec), MAX_TARGETS) {
            Ok(addresses) => {
                let allowed = addresses.iter().all(|ip| manifest.allows(*ip));
                if allowed && !addresses.is_empty() {
                    in_scope_count += addresses.len() as u64;
                } else {
                    out_of_scope.push(spec.clone());
                }
            }
            Err(_) => out_of_scope.push(spec.clone()),
        }
    }

    // An expired manifest authorizes nothing, so reporting it as a successful
    // validation would be the wrong answer rather than an incomplete one. It
    // outranks the target check: a target inside the allow set of a manifest
    // that has lapsed is still not authorized.
    let (decision, reason_code, detail) = if expired {
        (
            PolicyDecisionTag::Denied,
            Some(DenyReason::ScopeExpired.code().to_string()),
            Some(format!(
                "manifest {} expired before {now_rfc3339}",
                manifest.id()
            )),
        )
    } else if !out_of_scope.is_empty() {
        (
            PolicyDecisionTag::Denied,
            Some(DenyReason::TargetOutOfScope.code().to_string()),
            Some(format!(
                "{} of {} target(s) are not authorized by manifest {}",
                out_of_scope.len(),
                input.targets.len(),
                manifest.id()
            )),
        )
    } else {
        (PolicyDecisionTag::Approved, None, None)
    };

    Ok(ScopeValidateOutput {
        decision,
        reason_code,
        detail,
        scope_id: manifest.id(),
        description: manifest.description().to_string(),
        expired,
        in_scope_count,
        out_of_scope,
        budget_ceiling: BudgetCeiling {
            maximum_packets: ceiling.maximum_packets,
            maximum_runtime_seconds: ceiling.maximum_runtime_seconds,
            maximum_packets_per_second: ceiling.maximum_packets_per_second,
        },
        signature_present: manifest.had_signature(),
        signature_verified: manifest.signature_verified(),
    })
}
