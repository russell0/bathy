# bathy M5 — Query, Diff, CLI & MCP Server — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the agent-facing product — differential scanning, a human CLI, and an MCP server exposing exactly eleven typed tools that let an agent complete an authorized inventory workflow without ever constructing a command string or parsing XML.

**Architecture:** `bathy-query` folds event logs into a queryable endpoint state and diffs two folds. The CLI and the MCP server are both thin adapters over the same engine API — neither contains scanning logic, and anything the MCP server can do the CLI can do, so the tool surface is testable without an MCP client.

**Tech Stack:** rmcp (official Rust MCP SDK), clap (derive), tokio, serde_json.

**Read first:** the overview's Global Constraints; M2 Task 3 (`read_from`, the streaming primitive); M3 Task 3 (`plan_hash`).

> **Protocol verification gate.** This plan targets the MCP revision cited in the source design document (2026-07-28). Before implementing Task 4, open `modelcontextprotocol.io/specification` and confirm (a) that this revision exists and is current, (b) the exact tool-result shape for long-running work, and (c) whether human approval is expressed via **elicitation** (MCP) or a task state such as `input_required` (A2A). The design document conflates these two vocabularies. Record what you find in `docs/protocol-notes.md` and adjust Task 4's types to match reality rather than to match this plan.

---

### Task 1: Folding event logs into endpoint state

**Files:**
- Create: `crates/bathy-query/Cargo.toml`, `crates/bathy-query/src/lib.rs`, `crates/bathy-query/src/fold.rs`

**Interfaces:**
- Consumes: `Event`, `EventBody`.
- Produces: `fold_events(&[Event]) -> ScanFold`, `ScanFold { endpoints: BTreeMap<(IpAddr, Endpoint), EndpointState>, hosts_up: BTreeSet<IpAddr>, terminal: Option<Terminal> }`, `EndpointState { state: PortState, observation: Option<Observation>, evidence_refs: Vec<Digest>, probe_id: Option<String> }`.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folds_port_state_and_service_into_one_endpoint_record() {
        let f = fold_events(&[
            started(1), port_state(2, "10.0.0.1", 443, PortState::Open),
            service(3, "10.0.0.1", 443, "https", Some("nginx"), Some("1.26.0"), 0.95),
            completed(4),
        ]);
        let e = f.endpoints.get(&(ip("10.0.0.1"), tcp(443))).unwrap();
        assert_eq!(e.state, PortState::Open);
        assert_eq!(e.observation.as_ref().unwrap().product.as_deref(), Some("nginx"));
        assert_eq!(e.evidence_refs.len(), 1);
    }

    #[test]
    fn a_later_event_supersedes_an_earlier_one_for_the_same_endpoint() {
        let f = fold_events(&[
            port_state(1, "10.0.0.1", 80, PortState::Filtered),
            port_state(2, "10.0.0.1", 80, PortState::Open),
        ]);
        assert_eq!(f.endpoints[&(ip("10.0.0.1"), tcp(80))].state, PortState::Open);
    }

    #[test]
    fn folding_is_order_independent_given_sequence_numbers() {
        let events = vec![
            port_state(2, "10.0.0.1", 80, PortState::Open),
            port_state(1, "10.0.0.1", 80, PortState::Filtered),
        ];
        let mut shuffled = events.clone();
        shuffled.reverse();
        assert_eq!(fold_events(&events), fold_events(&shuffled));
    }

    #[test]
    fn the_terminal_event_is_captured() {
        let f = fold_events(&[started(1), completed(2)]);
        assert!(matches!(f.terminal, Some(Terminal::Completed { .. })));
        let g = fold_events(&[started(1)]);
        assert!(g.terminal.is_none(), "an unfinished scan has no terminal state");
    }

    #[test]
    fn closed_ports_are_folded_but_distinguishable_from_open() {
        let f = fold_events(&[
            port_state(1, "10.0.0.1", 80, PortState::Open),
            port_state(2, "10.0.0.1", 81, PortState::Closed),
        ]);
        assert_eq!(f.open_endpoints().count(), 1);
        assert_eq!(f.endpoints.len(), 2);
    }
}
```

- [ ] **Step 2: Run tests to verify they fail** — `cargo test -p bathy-query fold`.

- [ ] **Step 3: Implement the fold**

Sort events by `sequence` before folding — never trust caller ordering. For each `port.state`, upsert the endpoint's state; for each `service.observed`, upsert observation, `probe_id`, and evidence refs. Record `hosts_up` from `host.discovered`. Capture the last terminal event.

- [ ] **Step 4: Run tests to verify they pass** — expected 5 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/bathy-query
git commit -m "feat(query): sequence-ordered fold of event logs into endpoint state"
```

**Acceptance criteria:**
- **AC-5.1** Folding sorts by `sequence` internally, so the result is independent of input order.
- **AC-5.2** A later event for the same endpoint supersedes an earlier one.
- **AC-5.3** `Closed` and `Filtered` endpoints are retained in the fold, not discarded — they are the evidence a later diff needs to say "this port closed".

---

### Task 2: Differential scanning

**Files:**
- Create: `crates/bathy-query/src/diff.rs`

**Interfaces:**
- Produces: `diff(&ScanFold, &ScanFold) -> ScanDiff`, `ScanDiff { changes: Vec<Change>, unchanged: u64 }`, `Change { target, endpoint, kind: ChangeKind, before, after }`, `ChangeKind::{EndpointAppeared, EndpointDisappeared, StateChanged, ProductChanged, VersionChanged, ConfidenceOnly}`.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_newly_open_port_is_reported_as_appeared() {
        let d = diff(&fold_of(&[]), &fold_of(&[open("10.0.0.1", 8080)]));
        assert_eq!(d.changes.len(), 1);
        assert_eq!(d.changes[0].kind, ChangeKind::EndpointAppeared);
    }

    #[test]
    fn a_port_that_closed_is_reported_as_a_state_change_not_a_disappearance() {
        let before = fold_of(&[open("10.0.0.1", 80)]);
        let after = fold_of(&[closed("10.0.0.1", 80)]);
        let d = diff(&before, &after);
        assert_eq!(d.changes[0].kind, ChangeKind::StateChanged);
    }

    #[test]
    fn an_endpoint_absent_from_the_second_scan_disappeared() {
        let d = diff(&fold_of(&[open("10.0.0.1", 80)]), &fold_of(&[]));
        assert_eq!(d.changes[0].kind, ChangeKind::EndpointDisappeared);
    }

    #[test]
    fn a_version_bump_is_reported_as_a_version_change() {
        let before = fold_of(&[svc("10.0.0.1", 443, "nginx", "1.26.0", 0.95)]);
        let after = fold_of(&[svc("10.0.0.1", 443, "nginx", "1.27.1", 0.95)]);
        let d = diff(&before, &after);
        assert_eq!(d.changes[0].kind, ChangeKind::VersionChanged);
        assert_eq!(d.changes[0].after.as_ref().unwrap().version.as_deref(), Some("1.27.1"));
    }

    #[test]
    fn a_confidence_wobble_alone_is_classified_separately_from_a_real_change() {
        let before = fold_of(&[svc("10.0.0.1", 443, "nginx", "1.26.0", 0.95)]);
        let after = fold_of(&[svc("10.0.0.1", 443, "nginx", "1.26.0", 0.88)]);
        let d = diff(&before, &after);
        assert_eq!(
            d.changes[0].kind,
            ChangeKind::ConfidenceOnly,
            "confidence noise must be separable from substantive change"
        );
    }

    #[test]
    fn identical_scans_produce_no_changes() {
        let f = fold_of(&[svc("10.0.0.1", 443, "nginx", "1.26.0", 0.95), open("10.0.0.1", 80)]);
        let d = diff(&f, &f);
        assert!(d.changes.is_empty());
        assert_eq!(d.unchanged, 2);
    }

    #[test]
    fn changes_are_ordered_deterministically_by_target_then_port() {
        let after = fold_of(&[open("10.0.0.2", 80), open("10.0.0.1", 443), open("10.0.0.1", 80)]);
        let d = diff(&fold_of(&[]), &after);
        let keys: Vec<_> = d.changes.iter().map(|c| (c.target, c.endpoint.port)).collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted);
    }
}
```

- [ ] **Step 2: Run tests to verify they fail** — expected FAIL.

- [ ] **Step 3: Implement the diff**

```rust
/// Classify what changed between two folds.
///
/// `ConfidenceOnly` exists because confidence legitimately wobbles between
/// runs — a slow response, a truncated banner — and an operator asking "what
/// changed since Monday" does not want that in the same bucket as a version
/// bump. Separating it is the difference between a useful diff and an ignored
/// one.
pub fn diff(before: &ScanFold, after: &ScanFold) -> ScanDiff { /* … */ }
```

Classification order, first match wins: absent-then-present → `EndpointAppeared`; present-then-absent → `EndpointDisappeared`; `PortState` differs → `StateChanged`; `product` differs → `ProductChanged`; `version` differs → `VersionChanged`; only `confidence` differs → `ConfidenceOnly`; otherwise unchanged. Iterate over the union of keys from a `BTreeSet` so output order is sorted by `(target, transport, port)`.

- [ ] **Step 4: Run tests to verify they pass** — expected 7 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/bathy-query
git commit -m "feat(query): differential scanning with confidence noise separated from real change"
```

**Acceptance criteria:**
- **AC-5.4** All six `ChangeKind` variants are produced by the classifier under the appropriate conditions.
- **AC-5.5** A confidence-only difference is never reported as a product or version change.
- **AC-5.6** Diffing a fold against itself yields zero changes.
- **AC-5.7** Change ordering is deterministic, sorted by target then transport then port.

---

### Task 3: The CLI

**Files:**
- Create: `crates/bathy-cli/Cargo.toml`, `crates/bathy-cli/src/main.rs`, `crates/bathy-cli/src/commands/*.rs`

**Interfaces:**
- Produces: the `bathy` binary with subcommands `scope validate`, `scan preview`, `scan start`, `scan status`, `scan events`, `scan cancel`, `scan resume`, `result query`, `result diff`, `evidence get`, `explain`, `serve mcp`.

- [ ] **Step 1: Write the failing CLI test**

```rust
#[test]
fn preview_prints_a_plan_hash_and_estimates_without_sending_a_packet() {
    let out = bathy(&["scan", "preview", "--scope", scope_file(), "--targets", "10.30.0.0/30",
                      "--ports", "22,80", "--json"]).success();
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(v["plan_hash"].as_str().unwrap().starts_with("blake3:"));
    assert_eq!(v["estimated_targets"], 2);
    assert_eq!(v["estimated_probes"], 4);
    assert_eq!(v["policy_decision"], "approved");
}

#[test]
fn preview_of_an_out_of_scope_target_is_denied_with_a_reason_code_and_exit_2() {
    let out = bathy(&["scan", "preview", "--scope", scope_file(), "--targets", "8.8.8.8",
                      "--ports", "80", "--json"]).code(2);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["policy_decision"], "denied");
    assert_eq!(v["reason_code"], "target_out_of_scope");
}

#[test]
fn a_scan_without_a_scope_argument_is_refused_before_anything_else() {
    let out = bathy(&["scan", "start", "--targets", "10.30.0.1", "--ports", "80"]).failure();
    assert!(String::from_utf8_lossy(&out.stderr).contains("--scope"));
}

#[test]
fn json_output_is_line_delimited_and_parseable_for_every_command() {
    let out = bathy(&["scan", "events", "--scan", &completed_scan_id(), "--json"]).success();
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        serde_json::from_str::<serde_json::Value>(line).expect("every line is one JSON object");
    }
}

#[test]
fn human_output_never_claims_deterministic_results() {
    let out = bathy(&["--help"]).success();
    let text = String::from_utf8_lossy(&out.stdout).to_lowercase();
    assert!(!text.contains("deterministic results")); // [phrase-rule]
}
```

- [ ] **Step 2: Run tests to verify they fail** — expected FAIL.

- [ ] **Step 3: Implement the CLI**

Use `clap` derive. Rules:
- `--scope <PATH|ID>` is **required** on every command that can emit a packet. There is no default and no flag to skip it.
- `--json` switches every command to line-delimited JSON on stdout; diagnostics always go to stderr so stdout stays machine-parseable.
- Exit codes: `0` success, `1` operational error, `2` policy denial, `3` budget or time exhaustion, `4` idempotency conflict. Document these in `--help` — an agent shelling out branches on them.
- `scan start` prints the `TaskHandle` and returns immediately; it never blocks on completion.
- `scan events --follow` tails the log using `read_from(last_seen)`.

- [ ] **Step 4: Run tests to verify they pass** — expected 5 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/bathy-cli
git commit -m "feat(cli): bathy binary with mandatory scope and documented exit codes"
```

**Acceptance criteria:**
- **AC-5.8** Every packet-emitting subcommand requires `--scope`; omitting it fails before any network activity.
- **AC-5.9** `scan preview` computes `plan_hash`, target and probe estimates, and a policy decision **without emitting a packet**. Verify by running it with the network namespace isolated.
- **AC-5.10** `--json` output is line-delimited valid JSON on stdout, with all diagnostics on stderr.
- **AC-5.11** Exit codes 0–4 have the documented distinct meanings and appear in `--help`.
- **AC-5.12** `scan start` returns a `TaskHandle` immediately and does not block until completion.

---

### Task 4: The MCP server

**Files:**
- Create: `crates/bathy-mcp/Cargo.toml`, `crates/bathy-mcp/src/lib.rs`, `crates/bathy-mcp/src/tools/*.rs`
- Create: `docs/protocol-notes.md`

**Interfaces:**
- Produces: an MCP server exposing exactly eleven tools: `scope.validate`, `scan.preview`, `scan.start`, `scan.status`, `scan.events`, `scan.cancel`, `scan.resume`, `result.query`, `result.diff`, `evidence.get`, `fingerprint.explain`.

- [ ] **Step 1: Complete the protocol verification gate**

Read the current MCP specification. Write `docs/protocol-notes.md` recording: the revision implemented, the tool-result shape used for long-running work, and how human approval is expressed. If the spec's approval mechanism differs from `input_required`, use the spec's mechanism and note the deviation from the source design document — the spec wins.

- [ ] **Step 2: Write the failing test**

```rust
#[tokio::test]
async fn the_server_advertises_exactly_the_eleven_designed_tools() {
    let tools = test_server().list_tools().await.unwrap();
    let mut names: Vec<String> = tools.iter().map(|t| t.name.to_string()).collect();
    names.sort();
    assert_eq!(names, vec![
        "evidence.get", "fingerprint.explain", "result.diff", "result.query",
        "scan.cancel", "scan.events", "scan.preview", "scan.resume",
        "scan.start", "scan.status", "scope.validate",
    ]);
}

#[tokio::test]
async fn every_tool_publishes_an_input_schema_with_no_free_text_command_field() {
    for tool in test_server().list_tools().await.unwrap() {
        let schema = tool.input_schema.as_ref();
        assert_eq!(schema["type"], "object", "{} has no object schema", tool.name);
        assert!(schema.get("properties").is_some(), "{} has no properties", tool.name);
        let rendered = serde_json::to_string(schema).unwrap();
        for forbidden in ["\"command\"", "\"args\"", "\"flags\"", "\"argv\"", "\"raw\""] {
            assert!(
                !rendered.contains(forbidden),
                "{} exposes {forbidden}; agents must never construct command strings",
                tool.name
            );
        }
    }
}

#[tokio::test]
async fn scan_start_returns_a_task_handle_immediately_rather_than_blocking() {
    let t = tokio::time::Instant::now();
    let result = test_server().call("scan.start", large_scan_request()).await.unwrap();
    assert!(t.elapsed() < Duration::from_secs(2), "scan.start must not block on completion");
    let h: TaskHandle = serde_json::from_value(result).unwrap();
    assert_eq!(h.status, TaskStatus::Running);
    assert!(h.plan_hash.to_string().starts_with("blake3:"));
}

#[tokio::test]
async fn an_out_of_scope_start_is_denied_and_starts_no_task() {
    let before = test_server().task_count();
    let r = test_server().call("scan.start", out_of_scope_request()).await.unwrap();
    assert_eq!(r["policy_decision"], "denied");
    assert_eq!(r["reason_code"], "target_out_of_scope");
    assert_eq!(test_server().task_count(), before, "a denied request must create no task");
}

#[tokio::test]
async fn repeating_scan_start_with_the_same_key_and_plan_returns_the_same_task_id() {
    let s = test_server();
    let a: TaskHandle = serde_json::from_value(s.call("scan.start", req("k1")).await.unwrap()).unwrap();
    let b: TaskHandle = serde_json::from_value(s.call("scan.start", req("k1")).await.unwrap()).unwrap();
    assert_eq!(a.task_id, b.task_id);
}

#[tokio::test]
async fn scan_events_pages_from_a_cursor_without_replaying_the_whole_log() {
    let s = test_server();
    let id = s.completed_scan().await;
    let first = s.call("scan.events", json!({"scan_id": id, "after_sequence": 0, "limit": 5})).await.unwrap();
    assert_eq!(first["events"].as_array().unwrap().len(), 5);
    let cursor = first["next_cursor"].as_u64().unwrap();
    let second = s.call("scan.events", json!({"scan_id": id, "after_sequence": cursor, "limit": 5})).await.unwrap();
    let firsts: Vec<u64> = /* sequences of first page */;
    let seconds: Vec<u64> = /* sequences of second page */;
    assert!(seconds.iter().all(|s| !firsts.contains(s)), "pages must not overlap");
}

#[tokio::test]
async fn evidence_get_returns_the_exact_bytes_a_finding_cited() {
    let s = test_server();
    let (digest, expected) = s.scan_and_capture_one_evidence().await;
    let r = s.call("evidence.get", json!({"digest": digest.to_string()})).await.unwrap();
    assert_eq!(base64_decode(r["bytes"].as_str().unwrap()), expected);
}

#[tokio::test]
async fn fingerprint_explain_returns_the_rule_rationale_and_its_source() {
    let r = test_server().call("fingerprint.explain", json!({"rule_id": "http.server.nginx.v1"})).await.unwrap();
    assert!(r["rationale"].as_str().unwrap().contains("Server"));
    assert!(!r["source"].as_str().unwrap().is_empty());
}

#[tokio::test]
async fn a_scan_broader_than_the_approval_threshold_requires_human_confirmation() {
    let s = test_server_with_approval_threshold(64);
    let r = s.call("scan.start", request_covering_targets(256)).await.unwrap();
    assert_eq!(
        r["status"], "awaiting_approval",
        "scans above the threshold must not begin without a human decision"
    );
    assert!(s.pending_elicitations() == 1);
}

#[tokio::test]
async fn cancel_and_resume_round_trip_through_the_tool_surface() {
    let s = test_server();
    let h: TaskHandle = serde_json::from_value(s.call("scan.start", large_scan_request()).await.unwrap()).unwrap();
    s.call("scan.cancel", json!({"scan_id": h.task_id.to_string()})).await.unwrap();
    let status = s.call("scan.status", json!({"scan_id": h.task_id.to_string()})).await.unwrap();
    assert_eq!(status["status"], "cancelled");
    let resumed = s.call("scan.resume", json!({"scan_id": h.task_id.to_string()})).await.unwrap();
    assert_eq!(resumed["status"], "running");
    assert!(resumed["resumed_from_unit"].as_u64().unwrap() > 0);
}
```

- [ ] **Step 3: Run tests to verify they fail** — expected FAIL.

- [ ] **Step 4: Implement the tool surface**

Every tool's input and output type lives in `bathy-types` and derives `JsonSchema`; the server publishes those schemas rather than hand-written ones, so `xtask check-schemas` covers the MCP surface too.

Tool contracts:

| Tool | Input | Output |
|---|---|---|
| `scope.validate` | `{ scope_id \| manifest_json, targets[] }` | `{ decision, reason_code?, detail?, in_scope_count, out_of_scope[] }` |
| `scan.preview` | `ScanRequest` | `{ plan_hash, estimated_targets, estimated_probes, policy_decision, reason_code?, estimated_runtime_seconds }` |
| `scan.start` | `ScanRequest` | `TaskHandle` or `{ policy_decision: "denied", reason_code, detail }` or `{ status: "awaiting_approval", approval_id }` |
| `scan.status` | `{ scan_id }` | `{ status, units_completed, units_total, packets_spent, last_sequence, plan_hash }` |
| `scan.events` | `{ scan_id, after_sequence, limit }` | `{ events[], next_cursor, has_more }` |
| `scan.cancel` | `{ scan_id }` | `{ status, units_completed, resumable: bool }` |
| `scan.resume` | `{ scan_id }` | `{ status, resumed_from_unit }` |
| `result.query` | `{ scan_id, filter: { state?, service?, min_confidence?, port_range? } }` | `{ endpoints[], total }` |
| `result.diff` | `{ before_scan_id, after_scan_id, include_confidence_only: bool }` | `ScanDiff` |
| `evidence.get` | `{ digest, max_bytes? }` | `{ bytes (base64), length, truncated }` |
| `fingerprint.explain` | `{ rule_id }` | `{ rule_id, service, specificity, rationale, source }` |

`scan.start` above the configured approval threshold must return `awaiting_approval` and raise an elicitation (or the spec's equivalent) rather than beginning work. The threshold is server configuration, not a request field — an agent cannot raise its own threshold.

- [ ] **Step 5: Run tests to verify they pass** — expected 10 passed.

- [ ] **Step 6: Commit**

```bash
git add crates/bathy-mcp docs/protocol-notes.md
git commit -m "feat(mcp): eleven typed tools with task handles and human approval gate"
```

**Acceptance criteria:**
- **AC-5.13** Exactly eleven tools are advertised, with exactly the designed names.
- **AC-5.14** No tool's input schema contains a field named `command`, `args`, `flags`, `argv`, or `raw`. An agent cannot construct a command line through this surface. Asserted by a test over every published schema.
- **AC-5.15** Every tool publishes an object-typed JSON Schema derived from a Rust type in `bathy-types`, covered by `xtask check-schemas`.
- **AC-5.16** `scan.start` returns a `TaskHandle` in under two seconds regardless of scan size.
- **AC-5.17** A policy-denied `scan.start` creates no task record and emits no packet.
- **AC-5.18** Repeating `scan.start` with the same key and plan returns the same `task_id`.
- **AC-5.19** `scan.events` pages by cursor with non-overlapping pages and a `has_more` indicator.
- **AC-5.20** `evidence.get` returns the exact bytes a finding cited, verified by digest.
- **AC-5.21** `fingerprint.explain` returns a rationale and a non-empty source for every rule that can appear in a finding.
- **AC-5.22** A scan exceeding the server's approval threshold returns `awaiting_approval` and does not begin. The threshold is server-side configuration and is not settable from a request.
- **AC-5.23** `docs/protocol-notes.md` records the MCP revision actually implemented and any deviation from the source design document.

---

### Task 5: The ten-call workflow demonstration

**Files:**
- Create: `crates/bathy-mcp/tests/workflow.rs`
- Create: `docs/examples/agent-inventory-workflow.md`

This is the project's headline claim made executable: an agent completes an authorized inventory with a handful of typed calls and zero string construction.

- [ ] **Step 1: Write the test**

```rust
/// The comparative claim, as a test. If this ever needs more calls or any
/// string parsing, the claim in the README is no longer true and both must
/// change together.
#[tokio::test]
async fn an_agent_completes_an_authorized_inventory_in_ten_typed_calls() {
    let s = lab_server().await;
    let mut calls = 0;

    let validated = s.call("scope.validate", json!({"scope_id": LAB_SCOPE, "targets": ["10.30.0.0/29"]})).await.unwrap();
    calls += 1;
    assert_eq!(validated["decision"], "approved");

    let preview = s.call("scan.preview", lab_request()).await.unwrap();
    calls += 1;
    assert_eq!(preview["policy_decision"], "approved");

    let handle: TaskHandle = serde_json::from_value(s.call("scan.start", lab_request()).await.unwrap()).unwrap();
    calls += 1;

    let mut cursor = 0u64;
    let mut terminal = false;
    while !terminal && calls < 10 {
        let page = s.call("scan.events", json!({
            "scan_id": handle.task_id.to_string(), "after_sequence": cursor, "limit": 200
        })).await.unwrap();
        calls += 1;
        cursor = page["next_cursor"].as_u64().unwrap();
        terminal = page["events"].as_array().unwrap().iter().any(|e|
            e["event_type"] == "scan.completed" || e["event_type"] == "scan.failed");
        if !terminal { tokio::time::sleep(Duration::from_millis(200)).await; }
    }
    assert!(terminal, "scan did not finish within the call budget");

    let results = s.call("result.query", json!({
        "scan_id": handle.task_id.to_string(), "filter": {"state": "open"}
    })).await.unwrap();
    calls += 1;

    let endpoints = results["endpoints"].as_array().unwrap();
    assert!(!endpoints.is_empty(), "the lab exposes services; none were found");

    // Every finding must be explainable and evidence-backed.
    let first = &endpoints[0];
    let digest = first["evidence_refs"][0].as_str().unwrap();
    let evidence = s.call("evidence.get", json!({"digest": digest})).await.unwrap();
    calls += 1;
    assert!(!evidence["bytes"].as_str().unwrap().is_empty());

    assert!(calls <= 10, "took {calls} calls; the claim is ten");
}

#[tokio::test]
async fn the_workflow_involves_no_string_parsing_anywhere() {
    // Guard the claim structurally: the test above must not contain XML or
    // command-string handling. Checked by grep so it cannot rot silently.
    let src = include_str!("workflow.rs");
    for forbidden in ["from_str::<Xml", "quick_xml", "split_whitespace", "Command::new"] {
        assert!(!src.contains(forbidden), "workflow test uses {forbidden}");
    }
}
```

- [ ] **Step 2: Run against the M7 lab** — expected 2 passed.

- [ ] **Step 3: Write `docs/examples/agent-inventory-workflow.md`** transcribing the exact calls and responses from a real run.

- [ ] **Step 4: Commit**

```bash
git add crates/bathy-mcp/tests docs/examples
git commit -m "test(mcp): the ten-call authorized inventory workflow, as an executable claim"
```

**Acceptance criteria:**
- **AC-5.24** A complete authorized inventory — validate, preview, start, poll to terminal, query, fetch evidence — completes in ten or fewer typed tool calls against the lab.
- **AC-5.25** The workflow performs no XML parsing, no command-string construction, and no whitespace splitting, enforced by a source-level assertion.
- **AC-5.26** `docs/examples/agent-inventory-workflow.md` transcribes a real run, not an invented one.

---

## Milestone Exit Criteria

- [ ] `cargo test --workspace` green; clippy clean; `xtask check-deps` and `check-schemas` clean.
- [ ] AC-5.1 through AC-5.26 each demonstrated by a named passing test.
- [ ] `bathy serve mcp` connects to a real MCP client and lists eleven tools.
- [ ] `docs/protocol-notes.md` exists and names the verified spec revision.
- [ ] **This milestone ships the agent-facing product.** Tag `v0.1.0-beta.1`.
