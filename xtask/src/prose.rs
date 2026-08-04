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
//!
//! # What this enforces, and what it does not
//!
//! It matches a marker list against every published `description`. It does
//! not understand the sentences, so it is a filter, not the rule. See the
//! `WHAT STILL GETS THROUGH` list at the bottom of this file, written out in
//! the same spirit as `readme.rs`'s `NOT MECHANICALLY CHECKED`: a check whose
//! limits are known and stated is worth more than one assumed complete, and
//! this one has been defeated once already by a reviewer on his first
//! attempt.

use std::path::Path;
use std::sync::OnceLock;

use regex::Regex;
use serde_json::Value;

/// **Rust syntax.** Case-sensitive substrings: a source file, a path
/// separator, a plan criterion, a task, a derive, an attribute, a call.
///
/// `crate::` was here and is gone: `::` subsumes it, and `::` also catches
/// the rustdoc intra-doc links (`[`DenyReason::code`]`, `See
/// [`ScanDiff::before_terminal`]`) that rustdoc resolves and a JSON Schema
/// consumer receives as literal broken brackets. Both were in the committed
/// contract when this list was widened.
const SYNTAX_MARKERS: &[&str] = &[
    ".rs", "::", "AC-", "Task ", "schemars", "serde", "#[", "impl ", "()", "src/", ".toml", ".yml",
    ".md",
];

/// **Subject matter.** Case-insensitive substrings, and the half the first
/// version of this check did not have.
///
/// The M5 Task 2 fix re-review defeated the syntax list on its first attempt
/// with a paragraph that named two workspace crates, gave the layout
/// rationale, stated a hand-sync maintenance contract and cited a superseded
/// revision -- the four things this check exists to catch -- and tripped
/// nothing, because it spelled `bathy-scope` without backticks, `revision
/// two` instead of `_v1` and `the manifest loader` instead of
/// `ScopeManifest::load()`. Every marker below is subject matter rather than
/// syntax, and between them they catch all four.
///
/// `bathy-` is the one the reviewer singled out: naming a crate is the
/// commonest way to describe workspace layout, and it would have caught the
/// original `scope-manifest.json` leak on the leak's own words.
///
/// Not here, deliberately: `supersed`. `scan-diff.json` legitimately says
/// *"Superseded observations' evidence stays reachable"*, which is contract
/// text about the data. `revision` covers the maintainer sense on its own.
const SUBJECT_MARKERS: &[&str] = &[
    // Workspace layout: crate and module names a caller never sees.
    "bathy-",
    "bathy_",
    // A maintenance contract, which is an obligation on us and not on the
    // caller.
    "by hand",
    "in sync",
    "hand-sync",
    "maintainer",
    // Process and history.
    "milestone",
    "revision",
    "refactor",
    "rationale",
    "workspace",
    "see also",
    // Prose that dates itself.
    "for now",
    // A description is not a file to the caller, so nothing caller-facing
    // has occasion to say this. `R6` below defeats every marker above with
    // "lives beside this file, one directory up".
    "this file",
];

/// **Shapes**, as regular expressions, for the markers that need a word
/// boundary or a form rather than a literal.
///
/// Word boundaries matter: `internally tagged` and `deduplicated` and
/// `latest` are all legitimate contract text, and plain `internal` / `test`
/// substrings would flag them. Case-insensitive.
///
/// The three-underscore rule is the cheap way to catch a maintainer citing a
/// test or a function by name -- `every_required_property_is_physically_
/// present_in_a_maximally_null_document` is unmistakable, and no published
/// field name in this contract has more than one underscore.
const PATTERNS: &[&str] = &[
    // The whole vocabulary for "where this code lives". `crate` alone is
    // avoidable by anyone who knows the marker list -- `library` and
    // `package` are what the paraphrase reaches for next -- and none of the
    // four has any caller-facing use in a JSON Schema description.
    r"\bcrates?\b",
    r"\bmodules?\b",
    r"\blibrar(y|ies)\b",
    r"\bpackages?\b",
    r"\binternal\b",
    r"\btests?\b",
    r"\b(todo|fixme|xxx|hack)\b",
    // A tracker reference: an obligation the caller cannot see or follow.
    r"\b(issue|ticket|bug)s?\s+#?[0-9]",
    // A superseded revision of a type: `ScanFold_v1`, `_v2`.
    r"_v[0-9]",
    // A snake_case identifier with three or more underscores: a Rust item
    // name, not a wire field.
    r"\b\w*_\w*_\w*_\w*\b",
    // H1, closed. **An imperative maintenance obligation** -- an instruction
    // to whoever is editing this repository, sitting in a document read by a
    // caller who cannot act on it. That is the same harm as the original
    // `scope-manifest.json` leak, and it defeated every marker above.
    //
    // The shape, not the person. A previous round proposed bare `\byou\b`
    // and was right to reject it: a description legitimately says "you can
    // pass a digest", and legitimately says "if you change the port
    // selection the plan hash changes" -- a conditional about *the caller's*
    // input, not an instruction to edit a second file. What is never
    // caller-facing is the **second, imperative clause**: also change the
    // other thing. So the markers are the second clause and its idioms, not
    // the second person.
    //
    // `keep in sync` and `by hand` are already covered by SUBJECT_MARKERS;
    // these are the family's remaining spellings.
    r"\b(also|likewise) (change|update|edit|regenerate|re-generate)\b",
    r"\b(change|update|edit|regenerate|re-generate) (it|them|this|that|the [a-z-]{2,24}) too\b",
    r"\b(is|are) not generated from\b",
    r"\b(remember to|don'?t forget|do not forget)\b",
];

fn patterns() -> &'static [Regex] {
    static COMPILED: OnceLock<Vec<Regex>> = OnceLock::new();
    COMPILED.get_or_init(|| {
        PATTERNS
            .iter()
            .map(|p| {
                Regex::new(&format!("(?i){p}")).unwrap_or_else(|e| panic!("marker `{p}`: {e}"))
            })
            .collect()
    })
}

/// Every marker one description trips, named the way a maintainer can search
/// for it. Empty means the text is clean.
fn markers_in(description: &str) -> Vec<String> {
    let lower = description.to_lowercase();
    let mut hits = Vec::new();
    for marker in SYNTAX_MARKERS {
        if description.contains(marker) {
            hits.push(format!("{marker:?}"));
        }
    }
    for marker in SUBJECT_MARKERS {
        if lower.contains(marker) {
            hits.push(format!("{marker:?}"));
        }
    }
    for (source, compiled) in PATTERNS.iter().zip(patterns()) {
        if compiled.is_match(description) {
            hits.push(format!("/{source}/"));
        }
    }
    hits
}

/// Scan one parsed schema document, reporting every `description` that
/// carries a marker. `file` is the document's name and each message names it,
/// the type (or type and field) the description hangs off, every marker that
/// matched, and the offending text -- everything needed to find and fix the
/// doc comment without re-running the check.
///
/// One message per offending description, listing its markers, rather than
/// one message per marker: a maintainer paragraph trips several at once and
/// three copies of the same 700-character description is not three findings.
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
                let markers = markers_in(description);
                if !markers.is_empty() {
                    found.push(format!(
                        "{file}: {location}: description contains {}: {description}",
                        markers.join(", ")
                    ));
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

// ---------------------------------------------------------------------------
// WHAT STILL GETS THROUGH -- written out deliberately.
//
// This is a substring and pattern filter, not a reader. It catches the way
// maintainer prose is usually *spelled*, and a paragraph that avoids every
// spelling above still lands in the published contract at exit 0. Listing
// the defeats is the point: a green `check-schemas` means no description
// trips a marker, never that every description is contract text.
//
// The three below are the ones I could still write after widening the list.
// `tests::HOLES` holds them verbatim and
// `the_documented_holes_are_still_open_and_this_test_is_the_list` asserts
// they still pass, so this section cannot drift away from the code.
//
// **H1 was here and is closed** (M5 Task 3). It was "a maintenance
// obligation in the imperative": *"If you change this, change the loader
// too. They are not generated from one source."* The argument for leaving
// it open was that `\byou\b` is the obvious marker and is too broad --
// which is right -- and that any narrower marker would ship untested,
// which is not: `find_maintainer_prose` takes a synthetic value, and every
// marker in this file is tested that way. It is now closed by markers for
// the *second, imperative clause* rather than for the second person; see
// the H1 block in `PATTERNS`, and
// `the_imperative_maintenance_obligation_is_caught_and_ordinary_conditionals_are_not`
// for both directions.
//
//   - H2. **History as a date and a shape.** *"The two-field form used
//     before June is still accepted and will be dropped in the next
//     release."* `revision`, `_v[0-9]` and `milestone` all miss it.
//     Deliberately not chased: `scope-manifest.json` legitimately says
//     *"Reserved for v0.2 detached-signature verification"*, and a version
//     or a deprecation IS caller-facing, so the line between the two is
//     meaning, not spelling.
//   - H3. **A guard cited without naming it.** *"A property nobody may
//     break: it is checked on every build."* The three-underscore rule
//     catches a maintainer who names the test; nothing catches one who does
//     not. Low harm -- the sentence is merely useless rather than
//     misleading.
//   - H4. **Layout in a synonym nobody listed.** `crate`, `module`,
//     `library` and `package` are markers; *"the lower of the two
//     components"* is not, and neither is *"the other half of the
//     workspace"* spelled without the word. This family is closable only up
//     to the next synonym, which is the honest limit of a word list. The
//     four markers do cover every spelling actually used in this tree.
//
// And two structural limits that are not paraphrase attacks at all:
//
//   - **A `//` comment that should have been `///`.** The inverse defect --
//     contract text a caller needs, hidden from them -- is invisible here
//     and to every other check in the tree.
//   - **A description that is accurate, marker-free and simply wrong about
//     the behaviour.** Nothing mechanical reaches that; it is what review is
//     for.
// ---------------------------------------------------------------------------

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

    /// Real contract text, every line of it either committed today or of a
    /// shape the committed text uses, chosen because each one brushes a
    /// marker. This is the line between the two lists: the widening is only
    /// worth having if it leaves these alone.
    const LEGITIMATE: &[(&str, &str)] = &[
        // The task statement's own example. A description may name another
        // tool the agent can call.
        (
            "names another tool",
            "Fetch the bytes behind a digest with `evidence.get`.",
        ),
        (
            "field cross-reference",
            "See `before_terminal` for how the earlier scan ended.",
        ),
        // `internally` is JSON Schema vocabulary; `\binternal\b` must not
        // reach it.
        (
            "schema vocabulary",
            "On the wire this is an internally tagged object with an \
          `outcome` discriminator; unknown members are rejected.",
        ),
        // `Superseded` here is about the data, not about this type's own
        // history -- which is why `supersed` is not a marker.
        (
            "supersession as data",
            "Superseded observations' evidence stays reachable: the \
          digests accumulate rather than being replaced by the latest event's.",
        ),
        (
            "a reserved future field",
            "Reserved for v0.2 detached-signature verification; \
          accepted on the wire but NOT cryptographically checked today.",
        ),
        // `constructed`, `enumerated`, `deduplicated`, `latest` all contain a
        // marker as a substring and none of them is one.
        (
            "words that merely contain a marker",
            "A vector guaranteed to hold at least one \
          element, deduplicated and never enumerated; a Finding cannot be constructed \
          without evidence.",
        ),
    ];

    #[test]
    fn contract_text_that_brushes_a_marker_is_still_not_flagged() {
        // The entire false-positive half of this check is this list. An empty
        // one leaves the widening unopposed while still reporting `ok`, which
        // is the same shape the M5 close-out review found in
        // `FIELDS_ADDED_AFTER_THE_LOG_EXISTED`. The floor is the number of
        // marker *families* the list exists to defend against, so deleting
        // cases until only the easy ones remain fails here.
        assert!(
            LEGITIMATE.len() >= 5,
            "only {} legitimate-text cases remain; this list is the only thing \
             holding the marker lists back from flagging contract prose, and a \
             short one lets a widening land unopposed",
            LEGITIMATE.len()
        );
        for (label, text) in LEGITIMATE {
            let hits = markers_in(text);
            assert!(
                hits.is_empty(),
                "{label}: legitimate contract text was flagged by {hits:?}: {text}"
            );
        }
    }

    #[test]
    fn the_paragraph_that_defeated_the_first_version_is_caught() {
        // Verbatim from the M5 Task 2 fix re-review, section 2. It passed
        // `emit-schemas` and `check-schemas` at exit 0 and landed in the
        // published contract. It names two workspace crates, gives the
        // layout rationale, states a hand-sync contract and cites a
        // superseded revision, and the syntax-only list saw none of it.
        let text = "Defined in bathy-types rather than in bathy-scope so the contract crate \
                    stays free of internal dependencies; the CIDR fields are therefore plain \
                    strings. This mirror is kept in sync with the manifest loader by hand, and \
                    the loader wins if the two ever drift. Superseded revision two of this \
                    type is still accepted for one more milestone.";
        let hits = markers_in(text);
        // Each of the four things it leaks is caught by its own marker, so
        // deleting any one does not silently leave the paragraph passing.
        for expected in [
            "\"bathy-\"",       // the crate names
            "/\\bcrates?\\b/",  // the layout rationale
            "/\\binternal\\b/", //   "
            "\"in sync\"",      // the maintenance contract
            "\"by hand\"",      //   "
            "\"revision\"",     // the superseded revision
            "\"milestone\"",    // the process reference
        ] {
            assert!(
                hits.contains(&expected.to_string()),
                "{expected} missed: {hits:?}"
            );
        }
    }

    #[test]
    fn a_marker_is_caught_wherever_the_sentence_capitalises_it() {
        // The subject-matter list is matched case-insensitively precisely
        // because a maintainer sentence starts with its marker as often as
        // not, and a case-sensitive `contains` would miss every one.
        let hits = markers_in("Milestone five moved this. Revision one is gone. TODO: drop it.");
        assert!(hits.contains(&"\"milestone\"".to_string()), "{hits:?}");
        assert!(hits.contains(&"\"revision\"".to_string()), "{hits:?}");
        assert!(
            hits.iter().any(|h| h.contains("todo")),
            "an upper-case TODO must be caught: {hits:?}"
        );
    }

    #[test]
    fn a_rust_item_name_is_caught_by_its_shape_not_by_a_literal() {
        // Nobody can list the test names in advance; the shape is the rule.
        let hits =
            markers_in("Guarded by every_required_property_is_physically_present, which dies.");
        assert!(
            hits.iter().any(|h| h.contains('_')),
            "a snake_case item name must be caught by shape: {hits:?}"
        );
        // ...and a one-underscore wire field must not be.
        assert!(
            markers_in("`before_terminal` is null when the earlier scan never ended.").is_empty(),
            "a published field name is not a Rust item name"
        );
    }

    /// H1, closed. Both directions, because the whole objection to closing
    /// it was that the narrow marker would be too broad.
    #[test]
    fn the_imperative_maintenance_obligation_is_caught_and_ordinary_conditionals_are_not() {
        // The hole's own text, verbatim from what `WHAT STILL GETS THROUGH`
        // used to list. Each of its two sentences is caught by its own
        // marker, so deleting either one does not leave the paragraph
        // passing.
        let h1 = "If you change this, change the loader too. \
                  They are not generated from one source.";
        let hits = markers_in(h1);
        assert!(
            hits.iter().any(|h| h.contains("too")),
            "the imperative second clause must be caught: {hits:?}"
        );
        assert!(
            hits.iter().any(|h| h.contains("not generated from")),
            "the hand-sync admission must be caught: {hits:?}"
        );

        // ...through a real published document, not only through
        // `markers_in`: the same leak reaching a `$defs` description has to
        // be reported with its location.
        let schema = serde_json::json!({
            "title": "ScopeManifest",
            "$defs": {
                "Budgets": { "description": "If you change this, change the loader too." },
            },
        });
        let found = find_maintainer_prose("scope-manifest.json", &schema);
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].contains("Budgets"), "{found:?}");

        // And the direction the previous round was right about. Every line
        // below addresses the caller, or states a conditional about the
        // caller's own input, and none of them is a maintenance obligation.
        for text in [
            "You can pass a digest here instead of the bytes.",
            "If you change the port selection, the plan hash changes and this scan is \
             no longer comparable with the previous one.",
            "Change this only when the two scans covered the same ports.",
            "The value is generated from the request, canonicalized first.",
            "Update your manifest before the expiry in `not_after`.",
        ] {
            assert!(
                markers_in(text).is_empty(),
                "caller-facing text was flagged by {:?}: {text}",
                markers_in(text)
            );
        }
    }

    #[test]
    fn the_documented_holes_are_still_open_and_this_test_is_the_list() {
        // These are the paraphrases that survive the widened list, written
        // out in `WHAT STILL GETS THROUGH` below. The test asserts they
        // still pass, so the disclosure cannot quietly become wrong in
        // either direction: widening the markers until one of these is
        // caught fails here and forces the list to be edited.
        //
        // The name of this test claims it *is* the list, and the prose block
        // claims it "cannot drift away from the code" -- neither was true of
        // an empty or shortened `HOLES`, over which the loop below runs zero
        // times and reports success. So the count is pinned to the `- Hn.`
        // bullets in this file's own disclosure, read back through
        // `include_str!`: closing a hole means deleting both, and forgetting
        // either fails here.
        let disclosed = include_str!("prose.rs")
            .lines()
            .filter(|line| {
                let line = line.trim_start_matches('/').trim();
                line.starts_with("- H") && line[3..].starts_with(|c: char| c.is_ascii_digit())
            })
            .count();
        assert!(
            disclosed > 0,
            "the WHAT STILL GETS THROUGH disclosure lists no holes; either the check \
             became complete (it did not) or the bullets moved and this comparison \
             is now vacuous in both directions"
        );
        assert_eq!(
            HOLES.len(),
            disclosed,
            "`HOLES` has {} entries and the disclosure below lists {disclosed}; the \
             two are one statement written twice and they have drifted",
            HOLES.len()
        );
        for (label, text) in HOLES {
            assert!(
                markers_in(text).is_empty(),
                "{label} is no longer a hole -- update WHAT STILL GETS THROUGH: {text}"
            );
        }
    }

    /// The surviving defeats, kept next to the list that documents them.
    const HOLES: &[(&str, &str)] = &[
        (
            "H2 history as a date and a shape",
            "The two-field form used before June is still accepted and will be dropped in \
             the next release.",
        ),
        (
            "H3 a guard cited without naming it",
            "A property nobody may break: it is checked on every build.",
        ),
        (
            "H4 layout in a synonym nobody listed",
            "This shape is declared in the lower of the two components so the upper one \
             need not be built to read it.",
        ),
    ];

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
