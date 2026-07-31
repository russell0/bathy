use std::collections::BTreeMap;

use serde_json::Value;

/// Every type that crosses a public wire boundary, keyed by the filename it
/// is committed under in `schemas/`.
///
/// # Task 6 scope (controller resolution of an ordering conflict)
///
/// The full set this milestone promises (AC-1.22) is four schemas:
/// `ScanRequest`, `Event`, `TaskHandle`, and `ScopeManifestDto`. Only the
/// first two exist in this crate as of this task -- `TaskHandle` is created
/// in Task 8 and `ScopeManifestDto` in Task 7 -- and `schemars::schema_for!`
/// requires a concrete, already-defined type, so referencing either here now
/// would not compile. AC-1.22's four-schema requirement is therefore a
/// **milestone** exit criterion, satisfied by the end of Milestone 1, not a
/// Task 6 obligation; the two not-yet-existing types are deliberately not
/// stubbed.
///
/// Extension point for Tasks 7 and 8: add one `m.insert(...)` line each,
/// following the pattern of the two calls already below, for:
///   - Task 7: `crate::scope_dto::ScopeManifestDto`, keyed `"scope-manifest"`
///   - Task 8: `crate::task::TaskHandle`, keyed `"task-handle"`
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
    // Task 7 adds: m.insert("scope-manifest", to_value(schemars::schema_for!(crate::scope_dto::ScopeManifestDto)));
    // Task 8 adds: m.insert("task-handle", to_value(schemars::schema_for!(crate::task::TaskHandle)));
    m
}

fn to_value(schema: schemars::Schema) -> Value {
    serde_json::to_value(schema).expect("schema serializes")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_returns_exactly_the_types_that_exist_as_of_this_task() {
        let schemas = all();
        let mut names: Vec<&str> = schemas.keys().copied().collect();
        names.sort_unstable();
        assert_eq!(names, vec!["event", "scan-request"]);
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
