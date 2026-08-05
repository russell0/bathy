use std::collections::BTreeMap;

use serde_json::Value;

/// Every type that crosses a public wire boundary, keyed by the filename it
/// is committed under in `schemas/`.
///
/// # AC-1.22: the four-schema milestone requirement
///
/// `ScanRequest`, `Event`, `ScopeManifestDto`, and `TaskHandle` (added in
/// Task 8, the last of the four -- `schemars::schema_for!` requires a
/// concrete, already-defined type, so it could not be referenced here any
/// earlier). This completes AC-1.22.
pub fn all() -> BTreeMap<&'static str, Value> {
    let mut m = BTreeMap::new();
    m.insert(
        "scan-request",
        to_value(schemars::schema_for!(crate::request::ScanRequest)),
    );
    m.insert(
        "event",
        to_value(schemars::schema_for!(crate::event::Event)),
    );
    m.insert(
        "scope-manifest",
        to_value(schemars::schema_for!(crate::scope_dto::ScopeManifestDto)),
    );
    m.insert(
        "task-handle",
        to_value(schemars::schema_for!(crate::task::TaskHandle)),
    );

    // M5 Task 4: the agent-facing tool surface. Every tool's input and output
    // type is committed here so `check-schemas` covers the MCP surface with
    // the same gate as the first four, and so the server can publish the
    // *derived* schema rather than a hand-written one. A tool whose schema is
    // written by hand is a second spelling of the contract.
    //
    // `result.diff`'s output is deliberately absent: it is `ScanDiff`, whose
    // schema `bathy-query` already publishes as `scan-diff.json`. Committing
    // a second copy here would be the two-spellings failure this list exists
    // to avoid. `result.query`'s pair is published by `bathy-query` for the
    // same reason -- its output is stated in terms of a fold entry.
    m.insert(
        "mcp-scope-validate-input",
        to_value(schemars::schema_for!(crate::tools::ScopeValidateInput)),
    );
    m.insert(
        "mcp-scope-validate-output",
        to_value(schemars::schema_for!(crate::tools::ScopeValidateOutput)),
    );
    m.insert(
        "mcp-scan-preview-input",
        to_value(schemars::schema_for!(crate::tools::ScanPreviewInput)),
    );
    m.insert(
        "mcp-scan-preview-output",
        to_value(schemars::schema_for!(crate::tools::ScanPreviewOutput)),
    );
    m.insert(
        "mcp-scan-start-input",
        to_value(schemars::schema_for!(crate::tools::ScanStartInput)),
    );
    m.insert(
        "mcp-scan-start-output",
        to_value(schemars::schema_for!(crate::tools::ScanStartOutput)),
    );
    m.insert(
        "mcp-scan-status-input",
        to_value(schemars::schema_for!(crate::tools::ScanStatusInput)),
    );
    m.insert(
        "mcp-scan-status-output",
        to_value(schemars::schema_for!(crate::tools::ScanStatusOutput)),
    );
    m.insert(
        "mcp-scan-events-input",
        to_value(schemars::schema_for!(crate::tools::ScanEventsInput)),
    );
    m.insert(
        "mcp-scan-events-output",
        to_value(schemars::schema_for!(crate::tools::ScanEventsOutput)),
    );
    m.insert(
        "mcp-scan-cancel-input",
        to_value(schemars::schema_for!(crate::tools::ScanCancelInput)),
    );
    m.insert(
        "mcp-scan-cancel-output",
        to_value(schemars::schema_for!(crate::tools::ScanCancelOutput)),
    );
    m.insert(
        "mcp-scan-resume-input",
        to_value(schemars::schema_for!(crate::tools::ScanResumeInput)),
    );
    m.insert(
        "mcp-scan-resume-output",
        to_value(schemars::schema_for!(crate::tools::ScanResumeOutput)),
    );
    m.insert(
        "mcp-result-diff-input",
        to_value(schemars::schema_for!(crate::tools::ResultDiffInput)),
    );
    m.insert(
        "mcp-evidence-get-input",
        to_value(schemars::schema_for!(crate::tools::EvidenceGetInput)),
    );
    m.insert(
        "mcp-evidence-get-output",
        to_value(schemars::schema_for!(crate::tools::EvidenceGetOutput)),
    );
    m.insert(
        "mcp-fingerprint-explain-input",
        to_value(schemars::schema_for!(crate::tools::FingerprintExplainInput)),
    );
    m.insert(
        "mcp-fingerprint-explain-output",
        to_value(schemars::schema_for!(
            crate::tools::FingerprintExplainOutput
        )),
    );
    m
}

/// `schemars::Schema` is a newtype over `serde_json::Value`, so this is a
/// move, not a serialization.
///
/// It used to be `serde_json::to_value(schema).expect("schema serializes")` --
/// a round trip through a fallible API to recover a value the type was already
/// holding. `Schema::to_value` (`schemars-1.2.2/src/schema.rs`) hands it back
/// directly and cannot fail, so the panic is gone by removing the work rather
/// than by justifying it.
fn to_value(schema: schemars::Schema) -> Value {
    schema.to_value()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_returns_exactly_the_four_milestone_schemas_and_the_tool_surface() {
        let schemas = all();
        let mut names: Vec<&str> = schemas.keys().copied().collect();
        names.sort_unstable();
        assert_eq!(
            names,
            vec![
                "event",
                "mcp-evidence-get-input",
                "mcp-evidence-get-output",
                "mcp-fingerprint-explain-input",
                "mcp-fingerprint-explain-output",
                "mcp-result-diff-input",
                "mcp-scan-cancel-input",
                "mcp-scan-cancel-output",
                "mcp-scan-events-input",
                "mcp-scan-events-output",
                "mcp-scan-preview-input",
                "mcp-scan-preview-output",
                "mcp-scan-resume-input",
                "mcp-scan-resume-output",
                "mcp-scan-start-input",
                "mcp-scan-start-output",
                "mcp-scan-status-input",
                "mcp-scan-status-output",
                "mcp-scope-validate-input",
                "mcp-scope-validate-output",
                "scan-request",
                "scope-manifest",
                "task-handle",
            ]
        );
    }

    /// Ten of the eleven tools publish their output type here; the eleventh
    /// two (`result.diff`, `result.query`) publish theirs where the type they
    /// return is defined. Every tool this set names must therefore have both
    /// halves, or exactly one half with a stated reason.
    #[test]
    fn every_tool_input_published_here_has_an_output_beside_it_except_result_diff() {
        let names: Vec<&str> = all().keys().copied().collect();
        for name in names.iter().filter(|n| n.ends_with("-input")) {
            let output = name.replace("-input", "-output");
            if *name == "mcp-result-diff-input" {
                assert!(
                    !names.contains(&output.as_str()),
                    "result.diff returns ScanDiff, whose schema is already published \
                     as scan-diff.json; a second copy would be two spellings of one \
                     contract"
                );
                continue;
            }
            assert!(
                names.contains(&output.as_str()),
                "{name} has no {output}: a tool that declares an input shape and \
                 no output shape cannot populate structuredContent"
            );
        }
    }

    #[test]
    fn each_schema_is_a_non_trivial_json_object() {
        for (name, schema) in all() {
            assert!(
                schema.is_object(),
                "{name}'s schema was not a JSON object: {schema:#}"
            );
            assert!(
                schema.get("properties").is_some() || schema.get("oneOf").is_some(),
                "{name}'s schema has neither `properties` nor `oneOf`: {schema:#}"
            );
        }
    }
}
