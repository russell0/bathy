//! `bathy explain`: what an interpretation rule looks for, and where the
//! claim comes from.
//!
//! `source` is not decoration. Every rule in `bathy-interpret` must cite an
//! RFC section, vendor documentation, or a capture from this project's own
//! lab, and this command is how an operator checks that claim without
//! reading the crate.

use bathy_interpret::{RuleDoc, all_rules, explain as explain_rule};

use crate::emit::Emitter;
use crate::exit::{CliError, ExitCode};

fn document(doc: &RuleDoc) -> serde_json::Value {
    serde_json::json!({
        "rule_id": doc.id,
        "service": doc.service,
        "specificity": format!("{:?}", doc.specificity),
        "rationale": doc.rationale,
        "source": doc.source,
    })
}

pub fn run(rule_id: Option<&str>, list: bool, emitter: &Emitter) -> Result<ExitCode, CliError> {
    if list {
        for doc in all_rules() {
            emitter.result(
                document(doc),
                format!("{}  {}  {}", doc.id, doc.service, doc.source),
            );
        }
        return Ok(ExitCode::Success);
    }
    let rule_id = rule_id.ok_or_else(|| {
        CliError::operational("no_rule_id", "give a rule id, or --list to see them all")
    })?;
    let doc = explain_rule(rule_id).ok_or_else(|| {
        CliError::operational("no_such_rule", format!("no rule `{rule_id}`; try --list"))
    })?;
    emitter.result(
        document(doc),
        format!(
            "{}\n  service: {}\n  rationale: {}\n  source: {}",
            doc.id, doc.service, doc.rationale, doc.source
        ),
    );
    Ok(ExitCode::Success)
}
