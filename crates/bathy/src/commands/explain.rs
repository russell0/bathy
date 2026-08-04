//! `bathy explain`: what an interpretation rule looks for, and where the
//! claim comes from.
//!
//! `source` is not decoration. Every rule in `bathy-interpret` must cite an
//! RFC section, vendor documentation, or a capture from this project's own
//! lab, and this command is how an operator checks that claim without
//! reading the crate.

use bathy_interpret::all_rules;
use bathy_mcp::tools;
use bathy_types::tools::{FingerprintExplainInput, FingerprintExplainOutput};

use crate::emit::Emitter;
use crate::exit::{CliError, ExitCode};

/// The `fingerprint.explain` tool function, rendered.
///
/// It used to be a second `json!` literal with the same five keys, which is
/// the shape M5 Task 4's review found six of: one question, two spellings,
/// agreeing until one of them changes.
fn explain_one(rule_id: &str) -> Result<FingerprintExplainOutput, CliError> {
    tools::fingerprint::explain(FingerprintExplainInput {
        rule_id: rule_id.to_string(),
    })
    .map_err(CliError::from_tool)
}

fn document(out: &FingerprintExplainOutput) -> Result<serde_json::Value, CliError> {
    serde_json::to_value(out).map_err(|e| CliError::operational("encode_failed", e))
}

pub fn run(rule_id: Option<&str>, list: bool, emitter: &Emitter) -> Result<ExitCode, CliError> {
    if list {
        for doc in all_rules() {
            let out = explain_one(doc.id)?;
            emitter.result(
                document(&out)?,
                format!("{}  {}  {}", out.rule_id, out.service, out.source),
            );
        }
        return Ok(ExitCode::Success);
    }
    let rule_id = rule_id.ok_or_else(|| {
        CliError::operational("no_rule_id", "give a rule id, or --list to see them all")
    })?;
    let out = explain_one(rule_id)?;
    let human = format!(
        "{}\n  service: {}\n  rationale: {}\n  source: {}",
        out.rule_id, out.service, out.rationale, out.source
    );
    emitter.result(document(&out)?, human);
    Ok(ExitCode::Success)
}
