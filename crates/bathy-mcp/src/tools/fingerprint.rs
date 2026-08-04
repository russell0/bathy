//! `fingerprint.explain`.
//!
//! `source` is not decoration. Every rule must cite a standards section,
//! vendor documentation, or a capture this project took itself, and this tool
//! is how an agent -- or an operator reading its transcript -- checks that
//! claim without reading the engine.

use bathy_interpret::{RuleDoc, explain as explain_rule};
use bathy_types::tools::{FingerprintExplainInput, FingerprintExplainOutput};

use crate::error::{ToolFailure, ToolResult};

fn document(doc: &RuleDoc) -> FingerprintExplainOutput {
    FingerprintExplainOutput {
        rule_id: doc.id.to_string(),
        service: doc.service.to_string(),
        specificity: format!("{:?}", doc.specificity),
        rationale: doc.rationale.to_string(),
        source: doc.source.to_string(),
    }
}

pub fn explain(input: FingerprintExplainInput) -> ToolResult<FingerprintExplainOutput> {
    let doc = explain_rule(&input.rule_id).ok_or_else(|| {
        ToolFailure::new(
            "no_such_rule",
            format!("no rule `{}` in this build", input.rule_id),
        )
    })?;
    Ok(document(doc))
}

#[cfg(test)]
mod tests {
    use bathy_interpret::all_rules;

    use super::*;

    #[test]
    fn every_rule_this_build_can_produce_is_explainable_with_a_source() {
        let mut seen = 0;
        for doc in all_rules() {
            let out = explain(FingerprintExplainInput {
                rule_id: doc.id.to_string(),
            })
            .unwrap_or_else(|e| panic!("{} is unexplainable: {e:?}", doc.id));
            assert!(!out.rationale.is_empty(), "{}", doc.id);
            assert!(
                !out.source.is_empty(),
                "{} cites no source; an identification nobody can check is a guess",
                doc.id
            );
            assert!(!out.service.is_empty(), "{}", doc.id);
            assert!(!out.specificity.is_empty(), "{}", doc.id);
            seen += 1;
        }
        assert!(seen > 0, "this build has no rules at all");
    }

    #[test]
    fn an_unknown_rule_is_a_typed_refusal() {
        assert_eq!(
            explain(FingerprintExplainInput {
                rule_id: "no.such.rule".into()
            })
            .unwrap_err()
            .error,
            "no_such_rule"
        );
    }
}
