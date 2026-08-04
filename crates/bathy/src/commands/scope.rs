//! `bathy scope validate`.

use std::path::Path;

use bathy_types::clock::Clock;
use bathy_types::task::PolicyDecisionTag;
use bathy_types::tools::ScopeValidateInput;

use crate::emit::Emitter;
use crate::exit::{CliError, ExitCode};

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
    .map_err(CliError::from_tool)?;

    // A manifest that authorizes nothing -- expired, or asked about a target
    // it does not cover -- is a policy refusal (exit 2) carrying the same
    // reason code the engine's own evaluation would produce, not a successful
    // validation with a discouraging field in it.
    if out.decision == PolicyDecisionTag::Denied {
        return Err(CliError::from_tool(bathy_mcp::error::ToolFailure::new(
            out.reason_code.clone().unwrap_or_default(),
            out.detail.clone().unwrap_or_default(),
        )));
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
