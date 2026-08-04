//! The two published schemas this crate owns.
//!
//! Mirrors `bathy_types::schema::all()` exactly -- same signature, same
//! `to_value` helper, same filename-keyed map -- so `xtask`'s
//! `check-schemas`/`emit-schemas` treats these like every other committed
//! contract and no second drift-checking path exists.
//!
//! Why here rather than in `bathy-types`: `ScanFold` and `ScanDiff` are
//! defined in this crate, and `schemars::schema_for!` needs a concrete type.
//! Moving the types down into `bathy-types` to keep one schema module would
//! move the fold and the diff below the layer that owns them.

use std::collections::BTreeMap;

use serde_json::Value;

/// Every type this crate publishes on a wire boundary, keyed by the filename
/// it is committed under in `schemas/`.
pub fn all() -> BTreeMap<&'static str, Value> {
    let mut m = BTreeMap::new();
    m.insert(
        "scan-fold",
        to_value(schemars::schema_for!(crate::fold::ScanFold)),
    );
    m.insert(
        "scan-diff",
        to_value(schemars::schema_for!(crate::diff::ScanDiff)),
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
    fn all_returns_exactly_the_two_schemas_this_crate_publishes() {
        let mut names: Vec<&str> = all().keys().copied().collect();
        names.sort_unstable();
        assert_eq!(names, vec!["scan-diff", "scan-fold"]);
    }

    #[test]
    fn the_fold_schema_describes_an_entry_array_not_an_object() {
        // The defect the encoding exists to avoid, asserted against the
        // *published* document rather than against the Rust type: a derived
        // schema over `BTreeMap<(IpAddr, Endpoint), _>` describes a JSON
        // object, which `serde_json` then refuses to produce at runtime.
        let schema = &all()["scan-fold"];
        assert_eq!(schema["properties"]["endpoints"]["type"], "array");
        assert!(
            schema["properties"]["endpoints"]["items"]["$ref"]
                .as_str()
                .is_some_and(|r| r.ends_with("FoldEntry")),
            "entries must be FoldEntry objects: {schema:#}"
        );
    }

    #[test]
    fn every_property_of_every_type_this_crate_publishes_is_required() {
        // This crate's encoder never omits a field, and the schema has to say
        // so -- `schemars` marks `Option` fields optional by default, so each
        // type below states its own `required` list. This test is what makes
        // those lists maintainable: add a field, forget the list, and the
        // schema quietly promises less than the encoder delivers.
        //
        // Scoped to the types *this crate* defines. `Observation` and friends
        // are `bathy-types`', they legitimately omit absent fields
        // (`skip_serializing_if`), and their contract is not ours to restate.
        const OURS: &[&str] = &[
            "ScanFold",
            "ScanDiff",
            "FoldEntry",
            "EndpointState",
            "Change",
            "Undetermined",
        ];
        let mut seen: BTreeMap<&str, usize> = OURS.iter().map(|n| (*n, 0)).collect();

        for (file, schema) in all() {
            let root = schema["title"].as_str().unwrap_or(file).to_string();
            let mut nodes = vec![(root, schema.clone())];
            if let Some(defs) = schema["$defs"].as_object() {
                nodes.extend(defs.iter().map(|(k, v)| (k.clone(), v.clone())));
            }
            for (node_name, node) in nodes {
                let Some(&name) = OURS.iter().find(|n| **n == node_name) else {
                    continue;
                };
                *seen.get_mut(name).unwrap() += 1;
                let properties = node["properties"]
                    .as_object()
                    .unwrap_or_else(|| panic!("{name} has no properties: {node:#}"));
                let required: Vec<&str> = node["required"]
                    .as_array()
                    .map(|r| r.iter().filter_map(|v| v.as_str()).collect())
                    .unwrap_or_default();
                for property in properties.keys() {
                    assert!(
                        required.contains(&property.as_str()),
                        "{file}: {name}.{property} is not required, but the encoder \
                         always emits it"
                    );
                }
            }
        }

        for (name, hits) in seen {
            assert!(
                hits > 0,
                "{name} appears in neither published schema -- renamed, or dropped \
                 from the contract without this list being updated"
            );
        }
    }

    #[test]
    fn no_published_description_carries_maintainer_prose() {
        // A published `description` is contract text an agent reads. Rust doc
        // comments become exactly that, so the moment M5 Task 2 made these
        // types serializable, every `///` on them turned into a promise --
        // including the ones that cite source files, test names, plan
        // criteria and superseded revisions.
        //
        // This is the M5 Task 1 `$defs` sweep's rule (`///` for prose an
        // agent needs, `//` for prose a maintainer needs), enforced by a test
        // rather than by a reviewer with a regex, because the same leak
        // recurred here the first time these types were serialized. Scoped to
        // this crate's own descriptions is not possible -- a leak anywhere in
        // a document we publish is ours -- so it runs over everything the two
        // schemas contain, `bathy-types`' shared `$defs` included.
        const MARKERS: &[&str] = &[
            ".rs", "crate::", "AC-", "Task ", "schemars", "serde", "#[", "impl ", "()", "_v1",
        ];

        fn walk(node: &Value, path: &str, found: &mut Vec<String>) {
            match node {
                Value::Object(map) => {
                    if let Some(Value::String(description)) = map.get("description") {
                        for marker in MARKERS {
                            if description.contains(marker) {
                                found.push(format!("{path}: contains {marker:?}: {description}"));
                            }
                        }
                    }
                    for (key, value) in map {
                        walk(value, &format!("{path}/{key}"), found);
                    }
                }
                Value::Array(items) => {
                    for (index, value) in items.iter().enumerate() {
                        walk(value, &format!("{path}/{index}"), found);
                    }
                }
                _ => {}
            }
        }

        let mut found = Vec::new();
        for (name, schema) in all() {
            walk(&schema, name, &mut found);
        }
        assert!(
            found.is_empty(),
            "maintainer prose reached the published contract:\n{}",
            found.join("\n")
        );
    }

    #[test]
    fn the_fold_schema_documents_the_duplicate_sequence_ordering() {
        // AC-5.36: the decision is published where a consumer of the contract
        // can read it, not only in a doc comment in `fold.rs`.
        let description = all()["scan-fold"]["description"]
            .as_str()
            .expect("the fold schema documents itself")
            .to_string();
        assert!(
            description.contains("same `sequence`"),
            "the tiebreak must be described: {description}"
        );
        assert!(
            description.contains("stable across builds"),
            "and its guarantee stated: {description}"
        );
    }
}
