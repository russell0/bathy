//! Maintainer prose must not reach a published `description`.
//!
//! A published `description` is contract text an agent reads. Rust doc
//! comments become exactly that: the moment a type is given a `JsonSchema`
//! derive, every `///` on it turns into a promise -- including the ones that
//! cite source files, crate layout, test names, plan criteria and superseded
//! revisions. The rule the M5 Task 1 `$defs` sweep set is `///` for prose a
//! caller needs, `//` for prose a maintainer needs.
//!
//! This lives in `xtask`, over every file in `schemas/`, rather than in a
//! `#[cfg(test)]` module in one crate, because a leak is a property of the
//! *published document*, not of the crate that happened to generate it. M5
//! Task 2 first wrote this check as a unit test walking one crate's
//! `schema::all()`; it covered two of the six committed documents, and the
//! one live leak in the tree at the time was in one of the other four
//! (`scope-manifest.json`, which told an agent which crate the type lives in
//! and why). One mechanism, every document, at the point where
//! `check-schemas` already reads them.

use std::path::Path;

use serde_json::Value;

/// Substrings that never legitimately appear in contract text. Every one of
/// them is a way of naming something a caller cannot see: a source file, a
/// Rust path, a plan criterion, a task, a derive, an attribute, a function
/// call, or a superseded revision of a type.
const MARKERS: &[&str] = &[
    ".rs", "crate::", "AC-", "Task ", "schemars", "serde", "#[", "impl ", "()", "_v1",
];

/// Scan one parsed schema document, reporting every `description` that
/// carries a marker. `file` is the document's name and each message names it,
/// the type (or type and field) the description hangs off, the marker that
/// matched, and the offending text -- everything needed to find and fix the
/// doc comment without re-running the check by hand.
pub fn find_maintainer_prose(file: &str, schema: &Value) -> Vec<String> {
    let root = schema["title"].as_str().unwrap_or(file).to_string();
    let mut found = Vec::new();
    walk(schema, file, &root, &mut found);
    found
}

fn walk(node: &Value, file: &str, location: &str, found: &mut Vec<String>) {
    match node {
        Value::Object(map) => {
            if let Some(Value::String(description)) = map.get("description") {
                for marker in MARKERS {
                    if description.contains(marker) {
                        found.push(format!(
                            "{file}: {location}: description contains {marker:?}: {description}"
                        ));
                    }
                }
            }
            for (key, value) in map {
                match key.as_str() {
                    // A `$defs` entry is a type in its own right, and naming
                    // the root instead would send a maintainer to the wrong
                    // doc comment.
                    "$defs" | "definitions" => {
                        if let Some(defs) = value.as_object() {
                            for (name, def) in defs {
                                walk(def, file, name, found);
                            }
                        }
                    }
                    "properties" => {
                        if let Some(properties) = value.as_object() {
                            for (field, property) in properties {
                                walk(property, file, &format!("{location}.{field}"), found);
                            }
                        }
                    }
                    "description" => {}
                    // Anything else (`items`, `oneOf`, `anyOf`, ...) belongs
                    // to the type or field already named.
                    _ => walk(value, file, location, found),
                }
            }
        }
        Value::Array(items) => {
            for item in items {
                walk(item, file, location, found);
            }
        }
        _ => {}
    }
}

/// Run [`find_maintainer_prose`] over every `*.json` file in `dir`.
///
/// Reads the directory rather than the crates' `schema::all()` maps so that a
/// committed document no crate generates any more is still checked, and
/// errors rather than passing when the directory holds no schema at all -- a
/// check that is vacuously green over an empty directory is not a check.
pub fn check_dir(dir: &Path) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut files: Vec<std::path::PathBuf> = std::fs::read_dir(dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?
        .filter_map(|entry| entry.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .collect();
    files.sort();
    if files.is_empty() {
        return Err(format!("no schemas found in {}", dir.display()).into());
    }
    let mut found = Vec::new();
    for path in files {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let text =
            std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let schema: Value =
            serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
        found.extend(find_maintainer_prose(&name, &schema));
    }
    Ok(found)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_marker_in_a_root_description_names_the_file_the_type_and_the_text() {
        let schema = serde_json::json!({
            "title": "ScopeManifestDto",
            "description": "Lives here purely so `bathy_types::schema::all()` can publish it.",
        });
        let found = find_maintainer_prose("scope-manifest.json", &schema);
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("scope-manifest.json"), "{found:?}");
        assert!(found[0].contains("ScopeManifestDto"), "{found:?}");
        assert!(found[0].contains("\"()\""), "{found:?}");
        assert!(found[0].contains("Lives here purely"), "{found:?}");
    }

    #[test]
    fn a_marker_in_a_defs_description_names_the_def_not_the_root() {
        let schema = serde_json::json!({
            "title": "ScanFold",
            "$defs": {
                "FoldEntry": { "description": "See `crate::wire::FoldEntry`." },
            },
        });
        let found = find_maintainer_prose("scan-fold.json", &schema);
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("FoldEntry"), "{found:?}");
        assert!(
            !found[0].contains("ScanFold:"),
            "the root type is the wrong place to send a maintainer: {found:?}"
        );
    }

    #[test]
    fn a_marker_in_a_property_description_names_the_type_and_the_field() {
        let schema = serde_json::json!({
            "title": "ScanDiff",
            "properties": {
                "changes": { "description": "AC-5.7 says these are ordered." },
            },
        });
        let found = find_maintainer_prose("scan-diff.json", &schema);
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("ScanDiff.changes"), "{found:?}");
    }

    #[test]
    fn a_marker_nested_below_a_property_is_still_attributed_to_that_property() {
        // Enum variants and array items hang off `oneOf`/`items`, which are
        // not types of their own -- the doc comment to fix is the field's.
        let schema = serde_json::json!({
            "title": "ScanFold",
            "properties": {
                "terminal": {
                    "oneOf": [{ "description": "handled in `fold.rs`.", "const": "completed" }],
                },
            },
        });
        let found = find_maintainer_prose("scan-fold.json", &schema);
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("ScanFold.terminal"), "{found:?}");
    }

    #[test]
    fn ordinary_contract_text_is_not_flagged() {
        let schema = serde_json::json!({
            "title": "ScanDiff",
            "description": "What changed between two scans, and what could not be decided.",
            "properties": {
                "unchanged": {
                    "description": "Endpoints present in both scans with no difference.",
                },
            },
            "$defs": {
                "Endpoint": { "description": "A transport and a port on one host." },
            },
        });
        assert!(
            find_maintainer_prose("scan-diff.json", &schema).is_empty(),
            "contract prose must not be flagged"
        );
    }

    #[test]
    fn every_committed_schema_is_free_of_maintainer_prose() {
        // The check itself, over the real tree -- six documents, not the two
        // that one crate's `schema::all()` happens to return. This is the
        // test that fails when a `///` on any published type starts telling
        // an agent about our source layout.
        let schemas = Path::new(env!("CARGO_MANIFEST_DIR")).join("../schemas");
        let found = check_dir(&schemas).expect("schemas/ is readable");
        assert!(
            found.is_empty(),
            "maintainer prose reached a published contract:\n{}",
            found.join("\n")
        );
    }

    #[test]
    fn an_empty_directory_is_an_error_not_a_pass() {
        let dir = std::env::temp_dir().join(format!("xtask-prose-empty-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let err = check_dir(&dir).unwrap_err();
        assert!(err.to_string().contains("no schemas found"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
