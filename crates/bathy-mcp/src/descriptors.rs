//! The eleven advertised tools.
//!
//! Each descriptor's `inputSchema` and `outputSchema` are the schemas derived
//! from the types in `bathy-types`/`bathy-query` and committed under
//! `schemas/`. Nothing here writes a schema out by hand: a hand-written
//! schema is a second spelling of the contract, and the two drift.
//!
//! # Annotations
//!
//! Every tool sets all four hints explicitly. The specification's default for
//! an unannotated tool is already maximally cautious -- destructive,
//! non-idempotent, open-world -- so leaving them unset would produce a safe
//! posture by accident, and a posture held by accident is one a later edit
//! can lose without anything failing.
//!
//! Three tools are not read-only, not one:
//!
//! * `scan.start` puts packets on a third party's network.
//! * `scan.resume` does exactly the same thing, continuing from a cursor.
//!   The M5 plan's own criterion listed it among the read-only ten, which
//!   would have told a client that a tool which emits real traffic does not
//!   modify its environment. Understating what we put on someone else's wire
//!   is not a safe error.
//! * `scan.cancel` changes a running scan's state. It emits nothing, and it
//!   is not destructive -- `scan.resume` undoes it -- but it is not a read.

use std::sync::Arc;

use rmcp::model::{JsonObject, Tool, ToolAnnotations};

/// Every advertised tool name, in the order `tools/list` returns them.
///
/// Sorted, and asserted to be sorted, so the ordering guarantee the
/// specification asks for is intentional rather than an artefact of the order
/// somebody happened to type them in.
pub const TOOL_NAMES: &[&str] = &[
    "evidence.get",
    "fingerprint.explain",
    "result.diff",
    "result.query",
    "scan.cancel",
    "scan.events",
    "scan.preview",
    "scan.resume",
    "scan.start",
    "scan.status",
    "scope.validate",
];

/// How long a client may cache `tools/list`.
///
/// The tool set is compiled in and cannot change while the process runs, so
/// this is generous and the scope is public: two callers of the same build
/// get the same eleven tools.
pub const TOOLS_TTL_MS: u64 = 3_600_000;

fn object(schema: schemars::Schema) -> Arc<JsonObject> {
    let value = serde_json::to_value(schema).expect("a derived schema serializes");
    Arc::new(
        value
            .as_object()
            .expect("a derived schema is a JSON object")
            .clone(),
    )
}

fn read_only() -> ToolAnnotations {
    ToolAnnotations::new()
        .read_only(true)
        .destructive(false)
        .idempotent(true)
        .open_world(false)
}

/// A tool that emits packets at addresses a manifest authorized.
fn emits_packets(idempotent: bool) -> ToolAnnotations {
    ToolAnnotations::new()
        .read_only(false)
        .destructive(true)
        .idempotent(idempotent)
        .open_world(true)
}

/// A tool that changes local scan state and reaches nothing outside it.
fn changes_local_state() -> ToolAnnotations {
    ToolAnnotations::new()
        .read_only(false)
        .destructive(false)
        .idempotent(true)
        .open_world(false)
}

macro_rules! tool {
    (
        $name:literal, $title:literal, $description:expr,
        input = $input:ty, output = $output:ty, annotations = $annotations:expr $(,)?
    ) => {
        Tool::new($name, $description, object(schemars::schema_for!($input)))
            .with_title($title)
            .with_raw_output_schema(object(schemars::schema_for!($output)))
            .with_annotations($annotations)
    };
}

/// Build the eleven descriptors, in advertised order.
pub fn all() -> Vec<Tool> {
    use bathy_types::tools as t;

    let tools = vec![
        tool!(
            "evidence.get",
            "Fetch cited evidence",
            "Return the exact response bytes a finding cited, addressed by their BLAKE3 \
             digest. The bytes are verified against the digest before they are returned, \
             so what comes back is the evidence or it is an error, never something in \
             between. The value is lowercase hex, two characters per byte.",
            input = t::EvidenceGetInput,
            output = t::EvidenceGetOutput,
            annotations = read_only(),
        ),
        tool!(
            "fingerprint.explain",
            "Explain an identification rule",
            "Report what an interpretation rule looks for in a response, how specific its \
             conclusion is, and where the claim comes from -- a standards section, vendor \
             documentation, or a capture this project took itself. Every observation cites \
             the rule that produced it, so any identification can be checked without \
             reading the engine.",
            input = t::FingerprintExplainInput,
            output = t::FingerprintExplainOutput,
            annotations = read_only(),
        ),
        tool!(
            "result.diff",
            "Compare two scans",
            "Compare two finished scans endpoint by endpoint and classify what changed. \
             Confidence noise is separated from substantive change.\n\n\
             What this tool cannot always answer: an endpoint present in only one of the \
             two scans is reported as undetermined, not as having appeared or \
             disappeared, unless both scans ran the same plan to completion. A plan covers \
             budgets as well as targets and ports, so **lowering a rate limit, raising a \
             packet ceiling or extending a runtime cap between the two runs is enough on \
             its own** to make every one-sided endpoint undetermined and set the whole \
             comparison to `coverage_differs` -- even though the two scans looked at \
             exactly the same endpoints. Tuning a budget is a routine act; read \
             `coverage_differs` as \"the two runs were not the same authorization\", never \
             as \"the two runs did not cover the same ports\".",
            input = t::ResultDiffInput,
            output = bathy_query::ScanDiff,
            annotations = read_only(),
        ),
        tool!(
            "result.query",
            "Query a scan's endpoints",
            "Fold a scan's event log into one record per endpoint and return the records \
             matching a filter. Later observations supersede earlier ones, closed and \
             filtered endpoints are retained rather than dropped, and every identified \
             endpoint carries the evidence digests that justified it.",
            input = bathy_query::ResultQueryInput,
            output = bathy_query::ResultQueryOutput,
            annotations = read_only(),
        ),
        tool!(
            "scan.cancel",
            "Stop a running scan",
            "Ask a running scan to stop. Probes already in flight are drained rather than \
             dropped, so the results already obtained stay usable and the scan stays \
             resumable from where it left off. The request is recorded even if the scan is \
             running in another process. It returns as soon as the request is recorded, \
             not when the scan has stopped: to resume afterwards, wait for `scan.status` \
             to report `cancelled` first, which is the point at which the stopped run has \
             released the log and a resume can take it.",
            input = t::ScanCancelInput,
            output = t::ScanCancelOutput,
            annotations = changes_local_state(),
        ),
        tool!(
            "scan.events",
            "Read a scan's event log",
            "Read a page of a scan's append-only event log. Pages are addressed by \
             sequence number, so a caller polls by passing the previous page's cursor \
             back; pages never overlap. This is how a caller follows a running scan.",
            input = t::ScanEventsInput,
            output = t::ScanEventsOutput,
            annotations = read_only(),
        ),
        tool!(
            "scan.preview",
            "Plan a scan without running it",
            "Expand a request into a plan and evaluate it against a scope manifest, \
             reporting the plan hash, how many targets and probes it would take and \
             whether the manifest authorizes it. **No packet is emitted.** A refusal here \
             is the same refusal `scan.start` would give, obtained without touching the \
             network.",
            input = t::ScanPreviewInput,
            output = t::ScanPreviewOutput,
            annotations = read_only(),
        ),
        tool!(
            "scan.resume",
            "Continue an unfinished scan",
            "Continue a scan that stopped before its plan was exhausted, restarting at the \
             first unfinished unit. **This emits packets**, exactly as starting one does. \
             The manifest is evaluated again rather than trusted: a manifest that has \
             expired or narrowed since the scan began refuses the resume. Budgets already \
             spent carry over, so a resume cannot be used to escape a ceiling. A scan that \
             is still running cannot be resumed and is refused with `log_unavailable`; \
             that refusal changes nothing, so it is safe to retry, and waiting for \
             `scan.status` to report a terminal status is what makes it unnecessary.",
            input = t::ScanResumeInput,
            output = t::ScanResumeOutput,
            annotations = emits_packets(false),
        ),
        tool!(
            "scan.start",
            "Start an authorized scan",
            "Admit a scan and begin it. **This emits packets at real hosts.** It returns a \
             handle immediately and does not wait for the scan to finish; use \
             `scan.status` and `scan.events` to follow it.\n\n\
             Every address is checked against the scope manifest at `manifest_path` before \
             anything is sent, and a refusal creates no scan record and emits nothing. A \
             scan wider than this server's configured approval threshold does not begin \
             either: it answers asking for a human's approval, and only a retry carrying \
             that answer starts anything.\n\n\
             Repeating a call with the same `idempotency_key` and an identical plan returns \
             the original scan instead of starting a second one; repeating it with a \
             different plan is refused.",
            input = t::ScanStartInput,
            output = t::ScanStartOutput,
            annotations = emits_packets(true),
        ),
        tool!(
            "scan.status",
            "Report a scan's progress",
            "Report a scan's stored lifecycle record: its status, how much of the plan is \
             done, what it has spent against its budgets and how far its event log has \
             got. Works against a scan running in another process.",
            input = t::ScanStatusInput,
            output = t::ScanStatusOutput,
            annotations = read_only(),
        ),
        tool!(
            "scope.validate",
            "Check what a manifest authorizes",
            "Load a scope manifest and report what it authorizes: its identity, its expiry, \
             the budget ceilings it sets, and -- for any addresses supplied -- which of \
             them are inside its allow set and outside its deny set. **No packet is \
             emitted.** A manifest is a file an operator wrote; this tool reads one and \
             never accepts one inline, because a caller that can supply a manifest can \
             authorize itself.",
            input = t::ScopeValidateInput,
            output = t::ScopeValidateOutput,
            annotations = read_only(),
        ),
    ];
    debug_assert!(
        tools
            .iter()
            .map(|t| t.name.as_ref())
            .eq(TOOL_NAMES.iter().copied()),
        "the descriptor list and the advertised order must not disagree"
    );
    tools
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exactly_eleven_tools_with_exactly_the_designed_names_are_built() {
        let names: Vec<String> = all().iter().map(|t| t.name.to_string()).collect();
        assert_eq!(names.len(), 11);
        assert_eq!(names, TOOL_NAMES);
    }

    #[test]
    fn the_advertised_order_is_sorted_by_name() {
        let mut sorted = TOOL_NAMES.to_vec();
        sorted.sort_unstable();
        assert_eq!(TOOL_NAMES, sorted.as_slice());
        let built: Vec<String> = all().iter().map(|t| t.name.to_string()).collect();
        let mut built_sorted = built.clone();
        built_sorted.sort();
        assert_eq!(built, built_sorted);
    }

    #[test]
    fn every_tool_sets_all_four_annotations_rather_than_relying_on_a_default() {
        for tool in all() {
            let a = tool
                .annotations
                .as_ref()
                .unwrap_or_else(|| panic!("{} carries no annotations", tool.name));
            for (field, value) in [
                ("readOnlyHint", a.read_only_hint),
                ("destructiveHint", a.destructive_hint),
                ("idempotentHint", a.idempotent_hint),
                ("openWorldHint", a.open_world_hint),
            ] {
                assert!(
                    value.is_some(),
                    "{} leaves {field} unset; the cautious default must be chosen, \
                     not inherited",
                    tool.name
                );
            }
        }
    }

    #[test]
    fn the_three_tools_that_change_something_are_not_advertised_as_reads() {
        let all = all();
        let annotations = |name: &str| {
            all.iter()
                .find(|t| t.name == name)
                .unwrap()
                .annotations
                .clone()
                .unwrap()
        };
        for name in ["scan.start", "scan.resume"] {
            let a = annotations(name);
            assert_eq!(a.read_only_hint, Some(false), "{name}");
            assert_eq!(a.destructive_hint, Some(true), "{name}");
            assert_eq!(
                a.open_world_hint,
                Some(true),
                "{name} reaches an open world: it puts packets on someone else's network"
            );
        }
        let cancel = annotations("scan.cancel");
        assert_eq!(cancel.read_only_hint, Some(false));
        assert_eq!(cancel.open_world_hint, Some(false));

        for tool in &all {
            if matches!(
                tool.name.as_ref(),
                "scan.start" | "scan.resume" | "scan.cancel"
            ) {
                continue;
            }
            let a = tool.annotations.clone().unwrap();
            assert_eq!(a.read_only_hint, Some(true), "{}", tool.name);
            assert_eq!(a.open_world_hint, Some(false), "{}", tool.name);
        }
    }

    #[test]
    fn every_tool_declares_both_an_input_and_an_output_schema() {
        for tool in all() {
            assert_eq!(
                tool.input_schema.get("type").and_then(|v| v.as_str()),
                Some("object"),
                "{}: {:#?}",
                tool.name,
                tool.input_schema
            );
            assert!(
                tool.input_schema.contains_key("properties"),
                "{} has no properties",
                tool.name
            );
            let output = tool
                .output_schema
                .as_ref()
                .unwrap_or_else(|| panic!("{} declares no outputSchema", tool.name));
            assert!(
                output.contains_key("properties"),
                "{} has an outputSchema with no properties",
                tool.name
            );
        }
    }

    #[test]
    fn every_tool_carries_a_description_and_a_title() {
        for tool in all() {
            assert!(
                tool.description.as_ref().is_some_and(|d| d.len() > 40),
                "{} has no usable description",
                tool.name
            );
            assert!(tool.title.is_some(), "{} has no title", tool.name);
        }
    }

    #[test]
    fn the_diff_tool_tells_an_agent_that_a_budget_change_alone_makes_it_say_cannot_tell() {
        let all = all();
        let diff = all.iter().find(|t| t.name == "result.diff").unwrap();
        let description = diff.description.as_ref().unwrap();
        for phrase in ["budget", "rate limit", "coverage_differs", "same endpoints"] {
            assert!(
                description.contains(phrase),
                "result.diff's description does not name `{phrase}`; an agent choosing \
                 between \"nothing changed\" and \"we could not tell\" has to know that \
                 a budget change alone produces the second: {description}"
            );
        }
    }

    #[test]
    fn the_diff_tools_output_schema_is_the_committed_scan_diff_document_itself() {
        let all = all();
        let diff = all.iter().find(|t| t.name == "result.diff").unwrap();
        let advertised =
            serde_json::Value::Object((**diff.output_schema.as_ref().unwrap()).clone());
        let committed = &bathy_query::schema::all()["scan-diff"];
        assert_eq!(
            &advertised, committed,
            "result.diff must publish the committed diff contract, not a shape \
             re-derived here"
        );
    }

    #[test]
    fn no_published_input_schema_lets_an_agent_construct_a_command_line() {
        for tool in all() {
            let rendered = serde_json::to_string(&*tool.input_schema).unwrap();
            for forbidden in [
                "\"command\"",
                "\"args\"",
                "\"flags\"",
                "\"argv\"",
                "\"raw\"",
            ] {
                assert!(
                    !rendered.contains(forbidden),
                    "{} exposes {forbidden}; agents must never construct command strings",
                    tool.name
                );
            }
        }
    }

    #[test]
    fn no_published_input_schema_accepts_an_inline_manifest_or_a_scope_id() {
        for tool in all() {
            let rendered = serde_json::to_string(&*tool.input_schema).unwrap();
            for forbidden in [
                "\"manifest_json\"",
                "\"manifest\"",
                "\"scope_manifest\"",
                "\"scope_id\"",
                "\"allowed_cidrs\"",
            ] {
                assert!(
                    !rendered.contains(forbidden),
                    "{} exposes {forbidden}: a caller that can pass a manifest can \
                     authorize itself",
                    tool.name
                );
            }
        }
    }

    #[test]
    fn every_tool_that_names_a_scope_names_it_the_way_the_command_line_does() {
        let scope_taking = [
            "scope.validate",
            "scan.preview",
            "scan.start",
            "scan.resume",
        ];
        for tool in all() {
            let has = tool
                .input_schema
                .get("properties")
                .and_then(|p| p.as_object())
                .is_some_and(|p| p.contains_key("manifest_path"));
            assert_eq!(
                has,
                scope_taking.contains(&tool.name.as_ref()),
                "{} disagrees with the set of tools that take a manifest path",
                tool.name
            );
        }
    }
}
