//! `bathy scope validate`.

use std::path::Path;
use std::sync::Arc;

use bathy_scope::ScopeManifest;
use bathy_types::clock::Clock;

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

pub fn validate(path: &Path, clock: &dyn Clock, emitter: &Emitter) -> Result<ExitCode, CliError> {
    let manifest = load_manifest(path)?;
    let now = clock.now_rfc3339();
    let expired = manifest.is_expired(&now);
    let ceiling = manifest.ceiling();

    // An expired manifest authorizes nothing, so reporting it as a
    // successful validation would be the wrong answer, not merely an
    // incomplete one. It is a policy refusal (exit 2) with the same
    // `scope_expired` code `bathy_scope::evaluate` would produce.
    if expired {
        return Err(CliError::Denied {
            reason_code: bathy_types::DenyReason::ScopeExpired.code(),
            detail: format!("manifest {} expired before {now}", manifest.id()),
        });
    }

    let value = serde_json::json!({
        "scope_id": manifest.id().to_string(),
        "description": manifest.description(),
        "expired": expired,
        "signature_present": manifest.had_signature(),
        "signature_verified": manifest.signature_verified(),
        "budget_ceiling": {
            "maximum_packets": ceiling.maximum_packets,
            "maximum_runtime_seconds": ceiling.maximum_runtime_seconds,
            "maximum_packets_per_second": ceiling.maximum_packets_per_second,
        },
    });
    let human = format!(
        "{} \"{}\"\n  valid at {now}\n  ceiling {}pkt / {}s / {}pps\n  signature: {}",
        manifest.id(),
        manifest.description(),
        ceiling.maximum_packets,
        ceiling.maximum_runtime_seconds,
        ceiling.maximum_packets_per_second,
        if manifest.had_signature() {
            "present but NOT verified in this version"
        } else {
            "none"
        }
    );
    emitter.result(value, human);
    Ok(ExitCode::Success)
}
