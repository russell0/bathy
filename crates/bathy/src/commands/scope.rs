//! `bathy scope validate`.

use std::path::Path;
use std::sync::Arc;

use bathy_scope::ScopeManifest;
use bathy_types::clock::Clock;
use bathy_types::task::PolicyDecisionTag;
use bathy_types::tools::ScopeValidateInput;

use crate::emit::Emitter;
use crate::exit::{CliError, ExitCode};

/// Load a manifest document from disk.
///
/// Shared by every command that takes `--scope`, so there is one answer to
/// "what does `--scope` accept". It is a **path**: v0.1 has no manifest
/// registry to resolve an id against, and accepting an id-shaped string
/// silently as a filename would fail with a confusing I/O error rather than
/// a clear one.
pub fn load_manifest(path: &Path) -> Result<Arc<ScopeManifest>, CliError> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        CliError::operational("scope_unreadable", format!("{}: {e}", path.display()))
    })?;
    let manifest = ScopeManifest::load(&text)
        .map_err(|e| CliError::operational("scope_invalid", format!("{}: {e}", path.display())))?;
    Ok(Arc::new(manifest))
}

/// `bathy scope validate --scope PATH [--targets ...]`.
///
/// The answer is computed by the same function the `scope.validate` tool
/// calls, and rendered from the same type. Two implementations of one
/// question is how two surfaces come to disagree about authorization, and
/// this is the question where disagreeing matters most.
pub fn validate(
    path: &Path,
    targets: &[String],
    clock: &dyn Clock,
    emitter: &Emitter,
) -> Result<ExitCode, CliError> {
    let now = clock.now_rfc3339();
    let out = bathy_mcp::tools::scope::validate(
        ScopeValidateInput {
            manifest_path: path.display().to_string(),
            targets: targets.to_vec(),
        },
        &now,
    )
    .map_err(|f| CliError::operational(f.error, f.detail))?;

    // A manifest that authorizes nothing -- expired, or asked about a target
    // it does not cover -- is a policy refusal (exit 2) carrying the same
    // reason code the engine's own evaluation would produce, not a successful
    // validation with a discouraging field in it.
    if out.decision == PolicyDecisionTag::Denied {
        return Err(CliError::Denied {
            reason_code: reason_code_of(&out),
            detail: out.detail.unwrap_or_default(),
        });
    }

    let ceiling = &out.budget_ceiling;
    let human = format!(
        "{} \"{}\"\n  valid at {now}\n  ceiling {}pkt / {}s / {}pps\n  \
         {} target(s) in scope\n  signature: {}",
        out.scope_id,
        out.description,
        ceiling.maximum_packets,
        ceiling.maximum_runtime_seconds,
        ceiling.maximum_packets_per_second,
        out.in_scope_count,
        if out.signature_present {
            "present but NOT verified in this version"
        } else {
            "none"
        }
    );
    let value =
        serde_json::to_value(&out).map_err(|e| CliError::operational("encode_failed", e))?;
    emitter.result(value, human);
    Ok(ExitCode::Success)
}

/// Map the reported reason back onto one of the engine's stable codes.
///
/// `CliError::Denied` holds a `&'static str` because these four codes are a
/// closed set the whole program shares; anything outside it would be a code
/// this surface invented, so it is refused rather than passed through.
fn reason_code_of(out: &bathy_types::tools::ScopeValidateOutput) -> &'static str {
    let reported = out.reason_code.as_deref().unwrap_or_default();
    for reason in [
        bathy_types::DenyReason::ScopeMismatch,
        bathy_types::DenyReason::ScopeExpired,
        bathy_types::DenyReason::TargetOutOfScope,
        bathy_types::DenyReason::BudgetExceedsCeiling,
    ] {
        if reason.code() == reported {
            return reason.code();
        }
    }
    bathy_types::DenyReason::TargetOutOfScope.code()
}
