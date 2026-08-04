# bathy M5 — Query, Diff, CLI & MCP Server — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the agent-facing product — differential scanning, a human CLI, and an MCP server exposing exactly eleven typed tools that let an agent complete an authorized inventory workflow without ever constructing a command string or parsing XML.

**Architecture:** `bathy-query` folds event logs into a queryable endpoint state and diffs two folds. The CLI and the MCP server are both thin adapters over the same engine API — neither contains scanning logic, and anything the MCP server can do the CLI can do, so the tool surface is testable without an MCP client.

**Tech Stack:** `rmcp` 3.1.0 (official Rust MCP SDK, MSRV 1.88, edition 2024 — pin it; see the protocol gate), clap (derive), tokio, serde_json.

**Read first:** the overview's Global Constraints; M2 Task 3 (`read_from`, the streaming primitive); M3 Task 3 (`plan_hash`).

> **Protocol verification gate — DISCHARGED 2026-08-03.** Findings and every source URL: `.superpowers/sdd/mcp-spec-research.md`. Re-read that before Task 4; the summary below is not a substitute.
>
> The design document's guess of revision **`2026-07-28` was right about the date and wrong about what the date means.** That revision is not an increment on the session-based MCP that most documentation, most tutorials and most model training data describe. It is a rewrite: **MCP dropped the `initialize` handshake and protocol-level sessions and became stateless and per-request.** Anything you already "know" about MCP is probably a description of the `2025-11-25`-and-earlier era, which the spec now calls **Legacy**. Check the spec, not your recall.
>
> What this changes for us, each of which lands as an acceptance criterion below:
>
> 1. **No handshake.** Protocol version and client capabilities ride in each request's `_meta`. Servers **MUST** implement `server/discover`. An unsupported version is answered with `UnsupportedProtocolVersionError` (`-32022`) carrying `data.supported`.
> 2. **Transport:** stdio for the local server we ship; Streamable HTTP is for remote. **HTTP+SSE is formally Deprecated**, `Mcp-Session-Id` and the persistent GET stream are **removed**, and SSE resumability (`Last-Event-ID`) is **gone** — a broken stream means the client re-issues the whole request. Do not design anything that depends on stream resume.
> 3. **Typed output is real and is exactly our premise.** Optional `outputSchema` on the tool definition, `structuredContent` on the `tools/call` result. Binding once declared: "Servers MUST provide structured results that conform to this schema." The spec still asks for a JSON text mirror in `content` for Legacy clients. We declare `outputSchema` on all eleven tools.
> 4. **Human approval works nothing like this plan assumed** — see Task 4 Step 1. This is the one substantive correction, and it is an implementation change, not a wording change.
> 5. **Long-running work:** the official `io.modelcontextprotocol/tasks` extension is the spec's own generalized `start`/`poll`/`cancel`, and the spec's "Stateful Tools" guidance explicitly endorses server-minted opaque handles passed as ordinary arguments, "because MCP has no protocol-level session." Our `TaskHandle` triple is therefore validated twice over, not merely tolerated. Progress notifications exist but require holding the response stream open, which the Tasks documentation itself says intermediaries time out past a few seconds — **not** suitable for multi-minute scans.
> 6. **Deprecated in this revision: Roots, Sampling, Logging.** We use none of them. Log to stderr, not the Logging capability.
>
> **SDK:** `rmcp` 3.1.0 (released 2026-07-31), official, MSRV **1.88** and edition 2024 — an exact match for our library tier, so `bathy-mcp` is a **1.88-tier** crate; add it to the `msrv` CI job, not `msrv-bathy-store`, and verify that at creation rather than assuming it (M3 found `bathy-plan` had sat unverified against its claimed floor since creation, and M4 reintroduced the same defect with `crates/bathy`). Caveat to record in `docs/protocol-notes.md`: the official MCP blog rates the Rust SDK's `2026-07-28` support **beta**, against Tier-1 for TypeScript/Python/Go/C#, while the SDK's own README says "stable". Trust the blog. Budget for rough edges specifically around MRTR, `server/discover` and the Tasks extension, and if the SDK cannot express something the spec requires, **report it as a finding rather than working around it silently.**

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

**"Terminal" means exactly what `bathy-engine` means by it: `scan.completed`, `scan.failed`, *and* `policy.denied`** — the three `durable_log.rs`'s `is_terminal` and `scheduler.rs`'s `already_terminated()` both match, and a refused scan's log is that one `policy.denied` event and nothing else. `Terminal` therefore has three variants, not two. This sentence exists because the first pass read "the last terminal event" as the two obvious ones, discarded `policy.denied`, and made a refused scan fold byte-identically to a scan that never ran — so Task 2's diff could only classify it as every endpoint on the host disappearing, off a one-line manifest expiry. `terminal: None` means "still running or cancelled mid-flight", and must never be reachable from a scan that finished in any way.

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
- Produces: `diff(&ScanFold, &ScanFold) -> ScanDiff`, `ScanDiff { changes: Vec<Change>, unchanged: u64, undetermined: Vec<Undetermined>, undecidable: Option<Undecidable>, before_terminal, after_terminal }`, `Change { target, endpoint, kind: ChangeKind, before: Option<EndpointState>, after: Option<EndpointState> }`, `ChangeKind::{EndpointAppeared, EndpointDisappeared, StateChanged, ServiceChanged, ProductChanged, VersionChanged, ConfidenceOnly}`.

  **Three corrections to this line, made during Task 2 and flagged as plan edits (defects in this task's own acceptance criteria).**

  1. **`ChangeKind` has seven variants, not six.** `ServiceChanged` was missing. Two folds whose `Observation.service` differs (`http` on Monday, `ssh` on Tuesday) but which carry no product or version on either side -- the ordinary shape for anything the probes identify by protocol alone -- compare equal on state, product, version and confidence, so the six-variant classifier reports them as **unchanged**. That is a real change hidden in silence, which is the same defect class as a phantom change pointing the other way ("manufactures work, or hides real change in noise"), and the six-variant list makes it unreachable rather than merely unlikely.
  2. **`Change::before`/`after` are `Option<EndpointState>`, not observations.** Step 1's sketch reads `d.changes[0].after.as_ref().unwrap().version`, which types `after` as an `Observation` and leaves a `StateChanged` with no way to say *from what to what*. The whole record on each side is what an operator acts on, and it is also the same spelling the fold publishes (one endpoint record, not two).
  3. **`ScanDiff` needs a place to put what it cannot decide.** `{ changes, unchanged }` forces every one-sided endpoint into one of the six kinds, which is precisely how a refused, cancelled, budget-exhausted or differently-planned scan becomes a wall of `EndpointDisappeared`. AC-5.34 makes the denied case binding; the same rule covers all four, so the shape carries `undetermined` (the endpoints), `undecidable` (why, once, for the pair) and both scans' terminals (what to tell the operator).

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
    fn changes_are_ordered_deterministically_by_target_then_transport_then_port() {
        // The key is `(c.target, c.endpoint)`, NOT `(c.target,
        // c.endpoint.port)`. `Endpoint`'s derived `Ord` is
        // transport-dominant (`bathy-types`, `b852259`), which is the order
        // Step 3's prose and AC-5.7 both specify and the order the fold's
        // own `BTreeMap` keys are in. Keying on `port` alone drops the
        // transport dimension entirely: it passes today only because every
        // fixture here is TCP, and it becomes a decoration for that
        // dimension the moment UDP exists. Include a UDP endpoint in the
        // fixture so the assertion is not vacuous.
        let after = fold_of(&[
            open("10.0.0.2", 80),
            open("10.0.0.1", 443),
            open("10.0.0.1", 80),
            open_udp("10.0.0.1", 53),
        ]);
        let d = diff(&fold_of(&[]), &after);
        let keys: Vec<_> = d.changes.iter().map(|c| (c.target, c.endpoint)).collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted);
    }

    #[test]
    fn a_first_observed_port_state_is_a_state_change_not_an_appearance() {
        // `EndpointState::state` is `Option<PortState>` (M5 Task 1 shipped it
        // that way deliberately: a `service.observed` with no preceding
        // `port.state` leaves reachability genuinely unknown, and neither
        // `Open` nor `Indeterminate` may impersonate that absence). So
        // `None -> Some(_)` is a real transition the classifier must decide
        // on purpose. The endpoint was already present in `before`, so it did
        // not appear; what changed is its state.
        let before = fold_of(&[svc_without_port_state("10.0.0.1", 443, "nginx", "1.26.0", 0.95)]);
        let after = fold_of(&[open("10.0.0.1", 443)]);
        let d = diff(&before, &after);
        assert_eq!(d.changes.len(), 1);
        assert_eq!(
            d.changes[0].kind,
            ChangeKind::StateChanged,
            "an endpoint already in the fold cannot 'appear'; a first-observed \
             port state is a transition out of unknown"
        );
    }

    #[test]
    fn a_denied_scan_does_not_diff_as_every_endpoint_disappearing() {
        // `Terminal::Denied` (M5 Task 1 fix round, CRITICAL-1). A refused
        // scan has zero endpoints because no packet was sent, not because
        // the services went away. The diff must be able to say so.
        let monday = fold_of(&[open("10.0.0.1", 80), open("10.0.0.1", 443)]);
        let tuesday = denied_fold(DenyReason::ScopeExpired);
        let d = diff(&monday, &tuesday);
        assert!(
            !d.changes.iter().all(|c| c.kind == ChangeKind::EndpointDisappeared),
            "a policy-denied scan must not be diffed as a total disappearance"
        );
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

Classification order, first match wins: absent-then-present → `EndpointAppeared`; present-then-absent → `EndpointDisappeared`; `PortState` differs → `StateChanged`; `service` differs → `ServiceChanged`; `product` differs → `ProductChanged`; `version` differs → `VersionChanged`; only `confidence` differs → `ConfidenceOnly`; otherwise unchanged. Iterate over the union of keys from a `BTreeSet` so output order is sorted by `(target, transport, port)`.

**The first two arms are conditional, and that is the whole task.** Absent-then-present is an `EndpointAppeared` only if the earlier scan proved it looked; present-then-absent is an `EndpointDisappeared` only if the later one did. "Proved it looked" is `Terminal::Completed` on both sides -- `bathy-engine` emits `scan.completed` on exactly one path, plan exhaustion, so a refused (`Denied`), failed or budget-exhausted (`Failed`) or cancelled/still-running (`None`) scan is a scan that stopped early -- **and** the same `plan_hash` on both sides, because two completed scans of different plans never looked at the same endpoints. Anything else goes to `undetermined`. An endpoint present in *both* folds is always decidable, whatever the terminals say: both scans demonstrably observed it.

Evidence digests and `probe_id` are deliberately **not** compared. The same conclusion reached from different bytes (an HTTP `Date` header moves every second) or by a different probe is the same conclusion, and comparing them would make a re-scan of an unchanged network a wall of changes.

`EndpointState::state` is `Option<PortState>`, so "`PortState` differs" includes `None → Some(_)` and `Some(_) → None`. Both are `StateChanged`, never `EndpointAppeared`/`EndpointDisappeared` — appearance and disappearance are decided by the endpoint's presence in `ScanFold::endpoints`, which is a different question. See AC-5.33.

- [ ] **Step 4: Run tests to verify they pass** — expected 9 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/bathy-query
git commit -m "feat(query): differential scanning with confidence noise separated from real change"
```

- [ ] **Step 6: Design and commit the wire shape for `ScanFold` and `ScanDiff`**

`ScanFold` is deliberately not `Serialize` today: its `endpoints` field is a `BTreeMap<(IpAddr, Endpoint), _>`, and a derived `Serialize` on that compiles and then fails at runtime for every `serde_json` caller, because JSON object keys must be strings. The fix is an **entry-array encoding** — `endpoints` as a JSON array of `{ target, endpoint: { transport, port }, state, observation, evidence_refs, probe_id }` objects in key order — designed here, alongside the per-entry `Change` shape this task has to invent anyway, and not deferred.

It is designed here rather than in Task 4 because Task 4 must declare `outputSchema` on eleven tools ("Servers MUST provide structured results that conform to this schema") against a beta-rated SDK and a rewritten protocol revision, which is the worst place in this milestone to be inventing a published contract. Both types get a `JsonSchema` impl, both schemas are emitted by `bathy_types::schema::all()`'s equivalent for this crate and committed under `schemas/`, and `xtask check-schemas` drift-checks them like every other published schema.

Two things the encoding must decide explicitly, both inherited from Task 1:

1. `Terminal` has **three** variants (`Completed`, `Failed`, `Denied`) and `terminal: null` means "still running or cancelled mid-flight" — not "refused". A wire shape that cannot distinguish those re-opens CRITICAL-1 one layer up.
2. Once a `ScanFold` is serializable, two builds can compare rendered folds. `fold_events`'s duplicate-`sequence` tiebreak is keyed on `Debug` output, which Rust does not promise is stable across releases, so the tie path becomes cross-release visible for the first time. It is unreachable from a `bathy-evidence` log (append-only, gap-free, monotonic), but the trade must be re-decided here and stated in the schema's own documentation rather than left in a doc comment in `fold.rs`.

**Acceptance criteria:**
- **AC-5.4** Every `ChangeKind` variant is produced by the classifier under the appropriate conditions. **Seven, not six** -- see the corrections under Interfaces: `ServiceChanged` was missing from the plan's list, and without it a service replaced by a different service on the same port is reported as unchanged.
- **AC-5.5** A confidence-only difference is never reported as a product or version change.
- **AC-5.6** Diffing a fold against itself yields zero changes.
- **AC-5.7** Change ordering is deterministic, sorted by target then transport then port. Closed by `changes_are_ordered_deterministically_by_target_then_transport_then_port`, whose sort key is `(c.target, c.endpoint)` and whose fixture contains at least one non-TCP endpoint — a fixture that is all TCP makes the transport half of this criterion untested.
- **AC-5.33** A first-observed port state (`state: None → Some(_)`) is classified as `StateChanged`, and an endpoint present in both folds is never classified as `EndpointAppeared` or `EndpointDisappeared`. Closed by `a_first_observed_port_state_is_a_state_change_not_an_appearance`. This is a criterion rather than a note because M5 Task 1's report identified the requirement and left it in a report file, and per the Global Constraint *manual verification does not close an acceptance criterion*, a requirement that lives only in prose gets re-derived under time pressure.
- **AC-5.34** A `ScanFold` whose `terminal` is `Terminal::Denied` is not diffed as every endpoint disappearing. The rule generalizes past the denied case, and Task 2 implemented the general form: **no scan that did not run its plan to completion, and no pair of scans that ran different plans, may produce an `EndpointAppeared` or `EndpointDisappeared`.** Reaching the same phantom change through a cancelled scan, a budget-exhausted one, or a narrower port list would otherwise be left open by a criterion that names only the refused case. Closed by `diffing_a_completed_scan_against_a_denied_one_reports_no_endpoint_disappeared`, which **must call `diff()`** and must fail if the denied terminal is ignored. The obvious name for this criterion — `a_denied_scan_does_not_diff_as_every_endpoint_disappearing` — is already taken by a test in Task 1's `fold.rs` that is green today and never calls `diff()`; naming the criterion after it would let AC-5.34 be closed by a test that cannot exercise the behaviour. This is the same shape as M3's tautological budget-ceiling test, which asserted on the ledger's own report.
- **AC-5.36** The duplicate-sequence tiebreak is re-decided before `ScanFold` is serialized. **Decided in Task 2: re-keyed**, on a typed projection of exactly the event fields the fold reads (`fold.rs`'s `tie_key`), which depends on this crate's own source and no rendering the project does not own -- so the fold's determinism claim is now unconditional across builds and toolchain releases, and the published `scan-fold` schema states it. Canonical JSON was *not* an available option and that is a fact about the profile rather than a preference: `bathy_types::canonical::canonical_json` rejects non-integer numbers, and every `service.observed` carries a `Confidence` that is one. Task 1 keyed it on `format!("{event:?}")` and scoped the determinism claim to a single build rather than re-keying, because canonical JSON would cost `bathy-query` the minimal dependency graph its purity claim rests on — a trade the Task 1 re-review ruled correct *while `ScanFold` was unserializable and no caller could observe it*. AC-5.35 ends that condition. Either re-key on something with a cross-release guarantee, or state in the published schema's documentation that the ordering of duplicate-sequence events is stable only within a build. Deciding by omission is what this criterion exists to prevent: the obligation was carried in Step 6 prose, and prose is exactly what AC-5.33 was created to escape.
- **AC-5.35** `ScanFold` and `ScanDiff` have a committed JSON Schema under `schemas/`, `xtask check-schemas` drift-checks it, and a round-trip test proves the entry-array encoding of `endpoints` deserializes back to an equal value — a `BTreeMap` with a tuple key serializes only through such an encoding, and a derived `Serialize` would compile and fail at runtime.

---

### Task 3: The CLI

**Files:**
- Create: `crates/bathy/Cargo.toml` (EXISTS — published as a name reservation at 0.1.0-alpha.1; add the binary to it), `crates/bathy/src/main.rs`, `crates/bathy/src/commands/*.rs`

**Interfaces:**
- Produces: the `bathy` binary with subcommands. **The crate is named `bathy`, not `bathy`** — it is already published as a lib-only reservation, so `cargo install bathy` gives users a `bathy` command directly, the way `ripgrep` publishes as `ripgrep`. Adding `[[bin]]` to the existing crate is the whole change `scope validate`, `scan preview`, `scan start`, `scan status`, `scan events`, `scan cancel`, `scan resume`, `result query`, `result diff`, `evidence get`, `explain`, `serve mcp`.

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
git add crates/bathy
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

The research is done — **do not redo it.** Read `.superpowers/sdd/mcp-spec-research.md`, then write `docs/protocol-notes.md` recording: the revision implemented (`2026-07-28`), the `rmcp` version and its beta caveat, the transport (stdio), the `structuredContent` mechanism, **the MRTR approval flow**, and the deliberate choice not to route through the `io.modelcontextprotocol/tasks` extension — bespoke typed tools instead — so a future reader does not mistake that omission for an oversight.

**The correction that matters.** This plan framed approval as a choice between "elicitation (MCP)" and "`input_required` (A2A)" and called the design document confused for mixing them. Both framings were wrong. **`input_required` IS the current MCP vocabulary**, and it *wraps* elicitation rather than competing with it. Under **Multi Round-Trip Requests (MRTR)**, the standalone server-to-client `elicitation/create` request is gone — it exists only embedded in an `InputRequiredResult`.

So `scan.start` above the approval threshold must return a `tools/call` result with `resultType: "input_required"` whose `inputRequests` map carries an `elicitation/create` describing the scan awaiting approval. **Not** a `resultType: "complete"` carrying a bespoke `{ status: "awaiting_approval", approval_id }` object — that shape matches nothing in the spec and no generic client would act on it. The client resolves the elicitation and **retries `scan.start`** with a new JSON-RPC id, `inputResponses`, and the server's opaque `requestState` echoed back unmodified. The retry is what mints the real `TaskHandle`.

**`requestState` is attacker-controlled.** It round-trips through the client, so treat it exactly as hostile input: authenticate it (HMAC or AEAD under a server-held key), bind it to the principal it was issued to, give it a TTL, and make it single-use against replay. A forgeable `requestState` is a **scope bypass** — it would let a caller hand back a state blob claiming approval for a scan a human never saw, which is the same class of defect as M3's unconsulted scope. Test forgery, cross-principal reuse, expiry and replay as adversarial cases, not as happy-path round-trips.

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
async fn a_scan_broader_than_the_approval_threshold_returns_input_required_and_starts_nothing() {
    let s = test_server_with_approval_threshold(64);
    let before = s.task_count();
    let r = s.call_raw("scan.start", request_covering_targets(256)).await.unwrap();

    assert_eq!(r["resultType"], "input_required",
        "the spec's approval mechanism is MRTR, not a bespoke status field");
    let reqs = r["inputRequests"].as_object().unwrap();
    assert!(reqs.values().any(|v| v["method"] == "elicitation/create"),
        "approval must be carried as an embedded elicitation/create");
    assert!(r["requestState"].as_str().is_some_and(|s| !s.is_empty()));

    assert_eq!(s.task_count(), before, "no task may exist before a human decides");
    assert_eq!(s.packets_emitted(), 0, "and no packet may be emitted");
}

#[tokio::test]
async fn retrying_with_the_approval_response_and_request_state_starts_the_scan() {
    let s = test_server_with_approval_threshold(64);
    let pending = s.call_raw("scan.start", request_covering_targets(256)).await.unwrap();
    let r = s.retry_with_inputs("scan.start", &pending, approval_granted()).await.unwrap();
    let h: TaskHandle = serde_json::from_value(r["structuredContent"].clone()).unwrap();
    assert_eq!(h.status, TaskStatus::Running);
}

#[tokio::test]
async fn a_forged_or_replayed_request_state_cannot_authorize_a_scan() {
    let s = test_server_with_approval_threshold(64);
    let pending = s.call_raw("scan.start", request_covering_targets(256)).await.unwrap();

    // 1. Forgery: flip one byte of the authenticated blob.
    let mut forged = pending.clone();
    forged["requestState"] = json!(flip_one_byte(pending["requestState"].as_str().unwrap()));
    assert!(s.retry_with_inputs("scan.start", &forged, approval_granted()).await.is_err());

    // 2. Replay: the same state used twice.
    s.retry_with_inputs("scan.start", &pending, approval_granted()).await.unwrap();
    assert!(s.retry_with_inputs("scan.start", &pending, approval_granted()).await.is_err(),
        "requestState must be single-use");

    // 3. Cross-principal: a state issued to A must not work for B.
    let for_a = s.as_principal("A").call_raw("scan.start", request_covering_targets(256)).await.unwrap();
    assert!(s.as_principal("B").retry_with_inputs("scan.start", &for_a, approval_granted()).await.is_err());

    assert_eq!(s.packets_emitted(), 0, "no rejected path may emit a packet");
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
| `scan.start` | `ScanRequest` | `TaskHandle` (in `structuredContent`) · or `{ policy_decision: "denied", reason_code, detail }` · or an MRTR `InputRequiredResult` (`resultType: "input_required"`) carrying an embedded `elicitation/create` plus an authenticated `requestState` |
| `scan.status` | `{ scan_id }` | `{ status, units_completed, units_total, packets_spent, last_sequence, plan_hash }` |
| `scan.events` | `{ scan_id, after_sequence, limit }` | `{ events[], next_cursor, has_more }` |
| `scan.cancel` | `{ scan_id }` | `{ status, units_completed, resumable: bool }` |
| `scan.resume` | `{ scan_id }` | `{ status, resumed_from_unit }` |
| `result.query` | `{ scan_id, filter: { state?, service?, min_confidence?, port_range? } }` | `{ endpoints[], total }` |
| `result.diff` | `{ before_scan_id, after_scan_id, include_confidence_only: bool }` | `ScanDiff` |
| `evidence.get` | `{ digest, max_bytes? }` | `{ bytes (base64), length, truncated }` |
| `fingerprint.explain` | `{ rule_id }` | `{ rule_id, service, specificity, rationale, source }` |

`scan.start` above the configured approval threshold must return an MRTR `InputRequiredResult` rather than beginning work. The threshold is server configuration, not a request field — an agent cannot raise its own threshold. The pending `ScanRequest` and the threshold that was exceeded are carried in the authenticated `requestState`, never in client-writable fields.

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
- **AC-5.22** A scan exceeding the server's approval threshold returns an MRTR `InputRequiredResult` and does not begin. The threshold is server-side configuration and is not settable from a request.
- **AC-5.23** `docs/protocol-notes.md` records the MCP revision actually implemented, the `rmcp` beta caveat, the deliberate decision not to route through the `io.modelcontextprotocol/tasks` extension, and any deviation from the source design document.

**Added after the protocol verification gate was discharged (2026-08-03). Every one of these follows from the `2026-07-28` rewrite, not from taste:**

- **AC-5.27** The server implements `server/discover`, advertising its supported protocol versions, capabilities and identity, and answers an unsupported version with `UnsupportedProtocolVersionError` (`-32022`) whose `data.supported` lists what it does support. There is no `initialize` handshake in this revision; a server that waits for one hangs against every Modern client.
- **AC-5.28** Every one of the eleven tools declares an `outputSchema` generated from its `bathy-types` result struct, and every `tools/call` result populates `structuredContent` conforming to it, with a JSON text mirror in `content` for Legacy clients. Asserted by validating each real result against its own published schema — not by asserting the schema merely exists.
- **AC-5.29** Every tool carries explicit annotations. `scan.start` is `readOnlyHint: false, destructiveHint: true, openWorldHint: true`; the ten read-only tools are `readOnlyHint: true`. The spec's default for an unannotated tool is already maximally cautious, so a test must prove these are *set*, not merely that the effective posture is safe.
- **AC-5.30** `requestState` is authenticated, principal-bound, TTL-limited and single-use. Forgery, cross-principal reuse, expiry and replay are each rejected, and no rejected path emits a packet or creates a task. **This is an authorization boundary, not a serialization detail** — a forgeable `requestState` is a scope bypass of the same class as M3's unconsulted emission path.
- **AC-5.31** `tools/list` returns tools in a stable order across calls and carries `ttlMs`/`cacheScope`. Ordering is intentional (sorted by name), not incidental.
- **AC-5.32** The shipped server speaks stdio. Nothing in the crate implements the deprecated HTTP+SSE transport, depends on `Mcp-Session-Id`, or assumes SSE resumability.

**Open decision for the implementer to make and justify:** whether to *also* advertise `io.modelcontextprotocol/tasks` alongside the bespoke `scan.status`/`scan.cancel` tools, so an agent host that understands only the standard Tasks extension still gets task semantics. The spec sanctions either. Recommendation: defer to M7 and record the deferral — eleven tools is a published contract and the extension is additive — but say whether shipping without it materially narrows who can drive bathy.

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
- [ ] AC-5.1 through AC-5.36 each demonstrated by a named passing test.
- [ ] `bathy serve mcp` connects to a real MCP client and lists eleven tools.
- [ ] `docs/protocol-notes.md` exists and names the verified spec revision.
- [ ] **This milestone ships the agent-facing product.** Tag `v0.1.0-beta.1`.
