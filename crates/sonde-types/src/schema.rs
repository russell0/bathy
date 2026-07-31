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
    m
}

fn to_value(schema: schemars::Schema) -> Value {
    serde_json::to_value(schema).expect("schema serializes")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_returns_exactly_the_four_milestone_schemas() {
        let schemas = all();
        let mut names: Vec<&str> = schemas.keys().copied().collect();
        names.sort_unstable();
        assert_eq!(
            names,
            vec!["event", "scan-request", "scope-manifest", "task-handle"]
        );
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
