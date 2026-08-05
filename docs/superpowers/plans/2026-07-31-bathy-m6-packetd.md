# bathy M6 — Privileged SYN Scanning (`packetd`) — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add half-open SYN scanning behind a tiny, separately privileged process that drops its capabilities before reading a single byte of input, and that enforces scope a second time, independently of the engine.

**Architecture:** `packetd` is deliberately the smallest component in the project — a few hundred reviewable lines. It opens raw sockets, immediately drops `CAP_NET_RAW`, receives an allowlist and a work stream over a pipe, and refuses anything outside that allowlist regardless of what the engine asked for. The engine treats it as an untrusted subordinate and `packetd` treats the engine as an untrusted caller. Everything else in the workspace stays unprivileged and `#![forbid(unsafe_code)]`.

**Tech Stack:** socket2, etherparse, caps (Linux capability manipulation), tokio.

**Read first:** the overview's Global Constraints — `packetd` is the **only** crate permitted `unsafe`, and every block must carry a safety comment.

> **Sequencing note.** This milestone is deliberately scheduled after M5 and M7's lab. SYN scanning is a performance optimization; the interface, the evidence model, and the verification story are the product. Do not start M6 until M3's connect scanner is proven correct against the lab — you need a known-good oracle to validate SYN results against.

---

### Task 1: The IPC protocol

**Files:**
- Create: `crates/bathy-packetd/Cargo.toml`, `crates/bathy-packetd/src/lib.rs` (plan edit #4), `crates/bathy-packetd/src/protocol.rs`, `fuzz/fuzz_targets/ipc.rs` + `fuzz/seeds/ipc/` (plan edit #5)
- Modify: `xtask/src/gates.rs`, `xtask/src/main.rs`, `xtask/src/readme.rs`, `.github/workflows/ci.yml`, `README.md`, the overview's "No panics in parsing paths" constraint (plan edits #5, #6)

**Interfaces:**
- Produces: `Request::{ Init { allowed_cidrs, denied_cidrs, packets_per_second, max_packets }, Probe { id, target, port }, Shutdown }`, `Response::{ Ready { dropped_capabilities: bool }, Result { id, state }, Refused { id, reason }, Fatal { detail } }`, all line-delimited JSON.

  **Six corrections to this task, made during Task 1 and flagged as plan edits. The first three are defects in the interface as written: one would have made this module fabricate a security claim, one would have made it tell the engine something untrue, and one describes a test that cannot prove what its own name says.**

  1. **`Session::new()` takes `dropped_capabilities: bool`.** `Response::Ready { dropped_capabilities }` is a claim about whether this process still holds `CAP_NET_RAW`. A `Session::new()` with no argument can only answer it with a constant, so the protocol layer would be *fabricating* a security-relevant value that nothing measured — the "claimed but never enforced" defect class this repository has paid for repeatedly, in the one component where it matters most. `main` (Task 2) measures it after `drop_all_capabilities()` and the session relays it. AC-6.5's `--self-check` is what verifies the measurement; this type's job is not to invent one. Pinned by `ready_reports_the_capability_state_it_was_given_rather_than_a_constant`, which drives both values.

  2. **`handle_line` returns `Option<Response>`.** The `Response` set in this task's own interface has no goodbye message, and `Shutdown` is a legal request after `Init`. A signature that must return a `Response` therefore forces `Shutdown` to be answered with `Ready` or with `Fatal`, both of which are this process telling the engine something untrue in order to satisfy a return type. `None` means "no response line", and it happens for exactly that one message. Every acceptance test reads `matches!(r, Some(Response::Fatal { .. }))`.

  3. **The oversized-line criterion needs a reader, and the plan's test cannot prove it.** `a_line_longer_than_the_cap_is_rejected_without_allocating_it` builds a 1 MiB `String` and hands it to `handle_line(&str)` — by which point the caller has already allocated the megabyte the test is named after. The cap that actually bounds memory has to live where the bytes are *read*, so this task also produces `protocol::read_line`, which refuses to grow its buffer past `MAX_LINE_BYTES` and copies nothing past it, and the test asserts `buf.len() <= MAX_LINE_BYTES` over a megabyte of input. `handle_line` keeps a length check as a second line of defence. Both halves have a narrowing control — a line of *exactly* the cap must be accepted — because a cap of zero passes every test that only checks the refusal.

  4. **A `lib.rs` is part of this task.** The crate needs a root to carry `#![forbid(unsafe_code)]` and the `#![cfg_attr(not(test), deny(...))]` panic lints; `main.rs` is Task 2's.

  5. **The `packetd-ipc-fuzz-target` deferral fires on this task and is discharged in the same commit.** `xtask`'s `DEFERRALS` registered, since M7 Task 2, that AC-7.7's fifth untrusted-input surface had no fuzz target because this crate did not exist. Creating `crates/bathy-packetd/Cargo.toml` makes it due, so `fuzz/fuzz_targets/ipc.rs` and ten seeds land here, the `ipc` entry in `gates::FUZZ_SURFACES` loses its `deferred`, and the deferral is deleted rather than left on the books. `bathy-packetd` also joins `PANIC_LINT_CRATES` and the overview's constraint sentence — the same checked, two-directional relationship every other untrusted-input crate is in — and the `msrv` job at 1.88, measured against real 1.88 and 1.95 toolchains before the line was written.

  6. **The 800-line exit criterion had no executable form, and now runs from this task rather than from close-out.** It is a design constraint on the only component that will hold `CAP_NET_RAW`, and a size constraint first measured at milestone close-out is measured when the code is already too big to move — the shape of the five gates M5 closed and of the MSRV membership rule with three recurrences. `cargo run -p xtask -- check-packetd` is a `ci.yml` step from Task 1. It also fixes what the criterion leaves undefined: the number counts non-blank, non-`//` lines before each file's trailing `#[cfg(test)]`, and reports the physical total beside it. Comments are outside the number on purpose — the cap exists to bound the logic a reviewer must follow, and counting comments against it would be a cap on the explanations that make the review possible. Task 1 measures **249/800**.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn init_must_be_the_first_message_and_carry_an_allowlist() {
        let probe = r#"{"type":"probe","id":1,"target":"10.0.0.1","port":80}"#;
        let mut session = Session::new();
        let r = session.handle_line(probe);
        assert!(
            matches!(r, Response::Fatal { .. }),
            "packetd must refuse to work before it has been told its scope"
        );
    }

    #[test]
    fn init_with_an_empty_allowlist_is_fatal() {
        let init = r#"{"type":"init","allowed_cidrs":[],"denied_cidrs":[],
                       "packets_per_second":100,"max_packets":1000}"#;
        assert!(matches!(Session::new().handle_line(init), Response::Fatal { .. }));
    }

    #[test]
    fn a_second_init_is_refused_so_scope_cannot_be_widened_mid_session() {
        let mut s = initialized_session();
        let wider = r#"{"type":"init","allowed_cidrs":["0.0.0.0/0"],"denied_cidrs":[],
                        "packets_per_second":100,"max_packets":1000}"#;
        assert!(matches!(s.handle_line(wider), Response::Fatal { .. }));
    }

    #[test]
    fn malformed_json_is_fatal_rather_than_ignored() {
        let mut s = initialized_session();
        assert!(matches!(s.handle_line("{not json"), Response::Fatal { .. }));
    }

    #[test]
    fn a_line_longer_than_the_cap_is_rejected_without_allocating_it() {
        let mut s = initialized_session();
        let huge = format!(r#"{{"type":"probe","id":1,"target":"{}","port":80}}"#, "A".repeat(1 << 20));
        assert!(matches!(s.handle_line(&huge), Response::Fatal { .. }));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail** — `cargo test -p bathy-packetd protocol`.

- [ ] **Step 3: Implement the protocol**

Line-delimited JSON over stdin/stdout. Hard rules encoded in `Session`:
- `Init` must arrive first and exactly once. Anything else first, or a second `Init`, is fatal and terminates the process. Scope is fixed for the process lifetime; a widening request is a bug or an attack, and neither deserves a partial response.
- Lines are capped at 8 KiB; a longer line terminates the session before the buffer grows.
- Any parse failure is fatal. `packetd` has no error-recovery mode — a confused privileged process should die, not guess.

- [ ] **Step 4: Run tests to verify they pass** — expected 5 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/bathy-packetd
git commit -m "feat(packetd): fail-closed line protocol with immutable session scope"
```

**Acceptance criteria:**
- **AC-6.1** `packetd` refuses all work before `Init`.
- **AC-6.2** A second `Init` is fatal; session scope cannot be widened after startup.
- **AC-6.3** `Init` with an empty allowlist is fatal.
- **AC-6.4** Malformed input and oversized lines are fatal, not recoverable.

---

### Task 2: Capability acquisition and immediate drop

**Files:**
- Create: `crates/bathy-packetd/src/privilege.rs`, `crates/bathy-packetd/src/main.rs`

**Interfaces:**
- Produces: `fn acquire_raw_sockets() -> Result<RawSockets, PrivilegeError>`, `fn drop_all_capabilities() -> Result<(), PrivilegeError>`, `fn capabilities_are_dropped() -> bool`.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(target_os = "linux")]
#[test]
fn capabilities_are_dropped_before_any_input_is_read() {
    // Run the real binary and assert on the ordering it reports.
    let out = std::process::Command::new(packetd_bin())
        .arg("--self-check")
        .output()
        .unwrap();
    let report: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["sockets_opened"], true);
    assert_eq!(report["capabilities_dropped"], true);
    assert_eq!(
        report["first_input_read_after_drop"], true,
        "packetd must not read attacker-influenced input while privileged"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn running_without_privilege_fails_cleanly_with_actionable_guidance() {
    let out = std::process::Command::new(packetd_bin()).arg("--self-check").output().unwrap();
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains("CAP_NET_RAW"));
        assert!(stderr.contains("bathy will fall back to connect scanning"));
    }
}

#[test]
fn every_unsafe_block_in_this_crate_carries_a_safety_comment() {
    for entry in walkdir::WalkDir::new("src") {
        let path = entry.unwrap().into_path();
        if path.extension().and_then(|e| e.to_str()) != Some("rs") { continue; }
        let src = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = src.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            if line.trim_start().starts_with("unsafe ") {
                let preceding = lines[i.saturating_sub(4)..i].join("\n");
                assert!(
                    preceding.contains("SAFETY:"),
                    "{}:{} unsafe block without a SAFETY comment",
                    path.display(), i + 1
                );
            }
        }
    }
}
```

- [ ] **Step 2: Run tests to verify they fail** — expected FAIL.

- [ ] **Step 3: Implement privilege handling**

Startup order is mandatory and must not be reordered:

```rust
fn main() -> std::process::ExitCode {
    // 1. Open every socket we will ever need, while still privileged.
    let sockets = match acquire_raw_sockets() {
        Ok(s) => s,
        Err(e) => {
            eprintln!(
                "packetd: cannot open raw sockets ({e}).\n\
                 Grant CAP_NET_RAW with:\n  \
                 sudo setcap cap_net_raw+ep $(which bathy-packetd)\n\
                 Without it, bathy will fall back to connect scanning, which is \
                 slower but needs no privilege."
            );
            return std::process::ExitCode::from(69);
        }
    };

    // 2. Drop everything, immediately, before touching any input.
    if let Err(e) = drop_all_capabilities() {
        eprintln!("packetd: refusing to run with capabilities still held: {e}");
        return std::process::ExitCode::FAILURE;
    }
    debug_assert!(capabilities_are_dropped());

    // 3. Only now read anything an attacker could influence.
    run_session(sockets)
}
```

The ordering is the entire security argument for this design: sockets are a capability we hold, not a privilege we retain. Anything that parses untrusted bytes runs unprivileged.

- [ ] **Step 4: Run tests to verify they pass** — expected 3 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/bathy-packetd
git commit -m "feat(packetd): acquire sockets then drop capabilities before reading input"
```

**Acceptance criteria:**
- **AC-6.5** Raw sockets are opened, then all capabilities dropped, and only then is any input read. Verified by the binary's own `--self-check` report.
- **AC-6.6** Running without `CAP_NET_RAW` fails with a message naming the capability, the exact `setcap` command, and the connect-scan fallback.
- **AC-6.7** Every `unsafe` block in the crate is preceded by a `SAFETY:` comment, asserted by a test that walks the source.
- **AC-6.8** No crate outside `bathy-packetd` contains `unsafe`, asserted in CI.

---

### Task 3: SYN probing with independent scope enforcement

**Files:**
- Create: `crates/bathy-packetd/src/syn.rs`

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn a_target_outside_the_session_allowlist_is_refused_without_emitting() {
    let mut s = session_allowing("10.30.0.0/24");
    let r = s.handle_probe(1, ip("8.8.8.8"), 80);
    assert!(matches!(&r, Response::Refused { reason, .. } if reason == "out_of_session_scope"));
    assert_eq!(s.packets_emitted(), 0, "a refused probe must emit nothing");
}

#[test]
fn the_session_denylist_overrides_its_allowlist() {
    let mut s = session_allowing_except("10.30.0.0/24", "10.30.0.1/32");
    let r = s.handle_probe(1, ip("10.30.0.1"), 80);
    assert!(matches!(r, Response::Refused { .. }));
}

#[test]
fn reserved_ranges_are_refused_even_if_the_allowlist_permits_them() {
    let mut s = session_allowing("0.0.0.0/0");
    for bad in ["127.0.0.1", "224.0.0.1", "255.255.255.255", "169.254.1.1"] {
        assert!(matches!(s.handle_probe(1, ip(bad), 80), Response::Refused { .. }), "{bad}");
    }
}

#[test]
fn the_session_packet_ceiling_is_enforced_independently_of_the_engine() {
    let mut s = session_allowing_with_max_packets("10.30.0.0/24", 5);
    for i in 0..5 { assert!(!matches!(s.handle_probe(i, ip("10.30.0.2"), 80), Response::Refused { .. })); }
    assert!(matches!(
        &s.handle_probe(6, ip("10.30.0.2"), 80),
        Response::Refused { reason, .. } if reason == "session_budget_exhausted"
    ));
}

#[test]
fn response_classification_matches_tcp_semantics() {
    assert_eq!(classify_reply(Reply::SynAck), PortState::Open);
    assert_eq!(classify_reply(Reply::Rst), PortState::Closed);
    assert_eq!(classify_reply(Reply::IcmpUnreachable), PortState::Filtered);
    assert_eq!(classify_reply(Reply::None), PortState::Filtered);
}

#[test]
fn an_open_port_receives_a_rst_so_no_half_open_connection_is_left_behind() {
    let mut s = session_allowing("127.0.0.0/8");
    let port = bind_listener();
    s.handle_probe(1, ip("127.0.0.1"), port);
    assert_eq!(s.rst_sent_count(), 1, "a SYN-ACK must be answered with RST, not abandoned");
}
```

- [ ] **Step 2: Run tests to verify they fail** — expected FAIL.

- [ ] **Step 3: Implement SYN probing**

```rust
/// Scope is checked here a second time, against the immutable session
/// allowlist, using logic that shares no code with `bathy-scope`.
///
/// This duplication is deliberate. `packetd` is the only component that can
/// emit an arbitrary packet, so it must not delegate the question of whether
/// it is allowed to. A bug in the engine's policy path should not become a
/// packet on the wire.
fn check_session_scope(&self, target: IpAddr) -> Result<(), &'static str> { /* … */ }
```

Behavior:
- Craft a SYN with a per-session random source port range and a sequence number derived from a session-local counter. Classify: SYN-ACK → `Open`, RST → `Closed`, ICMP unreachable → `Filtered`, silence past the deadline → `Filtered`.
- On SYN-ACK, **send an RST**. Leaving half-open connections on a target's listen queue is the antisocial part of SYN scanning, and there is no reason to do it.
- Enforce the session packet ceiling and rate independently of the engine's `BudgetLedger`.

- [ ] **Step 4: Run tests to verify they pass** — expected 6 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/bathy-packetd
git commit -m "feat(packetd): SYN probing with independent scope check and RST teardown"
```

**Acceptance criteria:**
- **AC-6.9** `packetd` enforces the session allowlist and denylist itself, with logic independent of `bathy-scope`. A refused target emits zero packets.
- **AC-6.10** Reserved ranges are refused even when the session allowlist is `0.0.0.0/0`.
- **AC-6.11** The session packet ceiling is enforced inside `packetd`, independently of the engine's ledger.
- **AC-6.12** SYN-ACK, RST, ICMP unreachable, and silence map to `Open`, `Closed`, `Filtered`, `Filtered`.
- **AC-6.13** Every SYN-ACK is answered with an RST; no half-open connection is left on a target.

---

### Task 4: Engine integration, fallback, and cross-validation

**Files:**
- Modify: `crates/bathy-engine/src/scheduler.rs`
- Create: `crates/bathy-engine/tests/syn_vs_connect.rs`

- [ ] **Step 1: Write the failing test**

```rust
/// The correctness argument for SYN scanning: it must agree with the connect
/// scanner, which M3 already proved correct against the lab. Where they
/// disagree, the SYN path is wrong.
#[tokio::test]
#[ignore = "requires CAP_NET_RAW and the lab; run in the privileged CI job"]
async fn syn_and_connect_scans_agree_on_every_lab_endpoint() {
    let connect = scan_lab(ScanMode::Connect).await;
    let syn = scan_lab(ScanMode::Syn).await;
    let mut disagreements = Vec::new();
    for (key, c) in &connect.endpoints {
        let s = syn.endpoints.get(key).expect("SYN scan missed an endpoint");
        if c.state != s.state {
            disagreements.push(format!("{key:?}: connect={:?} syn={:?}", c.state, s.state));
        }
    }
    assert!(disagreements.is_empty(), "SYN disagreed with connect on:\n{}", disagreements.join("\n"));
}

#[tokio::test]
async fn without_privilege_the_engine_falls_back_and_says_so_in_the_event_log() {
    let h = harness_forcing_syn_without_privilege();
    h.run_to_completion().await.unwrap();
    let events = h.log.read_from(0).unwrap();
    assert!(
        events.iter().any(|e| matches!(&e.body, EventBody::Progress { .. })),
        "the scan must still complete"
    );
    assert!(h.scan_mode_recorded() == "tcp-connect");
}

#[tokio::test]
async fn packetd_dying_mid_scan_fails_the_scan_rather_than_silently_degrading() {
    let h = harness_with_syn();
    h.kill_packetd_after(50).await;
    let summary = h.run_to_completion().await;
    assert!(summary.is_err() || h.terminal_reason() == "packetd_unavailable");
}
```

- [ ] **Step 2: Run tests to verify they fail** — expected FAIL.

- [ ] **Step 3: Implement integration**

- Spawn `packetd` once per scan, send `Init` derived from the *same* manifest the engine validated against, then stream probes.
- If `packetd` cannot start, log the reason and fall back to connect scanning, recording `scan_mode` on the `scan.started` event so results are self-describing.
- If `packetd` dies mid-scan, fail the scan with `packetd_unavailable`. Silently switching methods mid-scan would make the results incomparable with themselves.

- [ ] **Step 4: Run tests to verify they pass** — expected 3 passed (one ignored outside privileged CI).

- [ ] **Step 5: Commit**

```bash
git add crates/bathy-engine crates/bathy-packetd
git commit -m "feat(engine): packetd integration with connect fallback and cross-validation"
```

**Acceptance criteria:**
- **AC-6.14** SYN and connect scans agree on every endpoint state across the full lab. Disagreement fails CI.
- **AC-6.15** Absent privilege, the engine falls back to connect scanning, completes, and records `scan_mode` on `scan.started`.
- **AC-6.16** `packetd` dying mid-scan fails the scan with `packetd_unavailable` rather than silently changing method.
- **AC-6.17** `packetd`'s `Init` allowlist is derived from the same manifest the engine validated, never from the raw request.

---

### Task 5: ICMP echo host discovery

**Files:**
- Create: `crates/bathy-packetd/src/icmp.rs`
- Modify: `crates/bathy-engine/src/discovery.rs`

The source design document specifies "ICMP/TCP host discovery". M3 delivered the TCP half, which is all that is possible unprivileged. The ICMP half lands here because it requires the same raw-socket capability as SYN scanning.

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn an_echo_reply_marks_the_host_up_with_the_icmp_method() {
    let mut s = session_allowing("127.0.0.0/8");
    let r = s.handle_icmp_probe(1, ip("127.0.0.1"));
    assert!(matches!(&r, Response::Result { state, .. } if *state == HostState::Up));
    assert_eq!(s.last_method(), "icmp-echo-reply");
}

#[test]
fn icmp_probes_are_scope_checked_on_the_same_path_as_syn_probes() {
    let mut s = session_allowing("10.30.0.0/24");
    let r = s.handle_icmp_probe(1, ip("8.8.8.8"));
    assert!(matches!(&r, Response::Refused { reason, .. } if reason == "out_of_session_scope"));
    assert_eq!(s.packets_emitted(), 0);
}

#[test]
fn icmp_probes_are_charged_to_the_same_session_budget_as_syn_probes() {
    let mut s = session_allowing_with_max_packets("10.30.0.0/24", 2);
    s.handle_icmp_probe(1, ip("10.30.0.2"));
    s.handle_probe(2, ip("10.30.0.2"), 80);
    assert!(matches!(
        &s.handle_icmp_probe(3, ip("10.30.0.3")),
        Response::Refused { reason, .. } if reason == "session_budget_exhausted"
    ));
}

#[test]
fn a_destination_unreachable_reply_marks_the_host_down_not_merely_silent() {
    assert_eq!(classify_icmp(IcmpReply::EchoReply), HostState::Up);
    assert_eq!(classify_icmp(IcmpReply::DestinationUnreachable), HostState::Down);
    assert_eq!(classify_icmp(IcmpReply::None), HostState::Unknown);
}

#[tokio::test]
async fn combined_discovery_prefers_icmp_then_falls_back_to_tcp() {
    // ICMP costs one packet and answers most hosts; TCP is the fallback for
    // networks that filter ICMP, which is common enough that neither alone
    // is sufficient.
    let r = discover_host_combined(ip("10.30.0.18"), &cfg(), &limiter(), Some(&packetd())).await;
    assert!(r.up);
    assert!(r.method == "icmp-echo-reply" || r.method.starts_with("tcp-connect"));
}
```

- [ ] **Step 2: Run tests to verify they fail** — expected FAIL.

- [ ] **Step 3: Implement ICMP discovery**

Send an ICMP echo request with a session-local identifier and a per-probe sequence number, and classify: echo reply → `Up`, destination unreachable → `Down`, silence past the deadline → `Unknown`. Route the probe through the *same* `check_session_scope` and the same session budget as SYN probes — one enforcement path, not two.

In `bathy-engine`, `discover_host_combined` tries ICMP first when `packetd` is available and falls back to the M3 TCP method on `Unknown`. Record whichever method produced the answer on the `host.discovered` event.

- [ ] **Step 4: Run tests to verify they pass** — expected 5 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/bathy-packetd crates/bathy-engine
git commit -m "feat(packetd): ICMP echo discovery sharing the SYN scope and budget path"
```

**Acceptance criteria:**
- **AC-6.18** ICMP echo discovery classifies echo reply as up, destination unreachable as down, and silence as unknown.
- **AC-6.19** ICMP probes pass through the identical scope check and session budget as SYN probes — one code path, verified by a test that exhausts the budget using a mix of both probe types.
- **AC-6.20** Combined discovery tries ICMP first when privileged and falls back to TCP on an inconclusive result, recording the deciding method on the `host.discovered` event.

---

## Milestone Exit Criteria

- [ ] `cargo test --workspace` green; privileged CI job green including the cross-validation test.
- [ ] AC-6.1 through AC-6.20 each demonstrated by a named passing test.
- [ ] `bathy-packetd` is under 800 lines of non-test Rust. If it is larger, move logic out of the privileged process. **Enforced by `cargo run -p xtask -- check-packetd`, a `ci.yml` step since Task 1** — see plan edit #6 on Task 1 for what the number counts and why it is not measured for the first time here.
- [ ] Every `unsafe` block has a `SAFETY:` comment; no other crate has any.
- [ ] `docs/design-paper.md` contains a section explaining the two-layer scope enforcement and why the duplication is intentional.
