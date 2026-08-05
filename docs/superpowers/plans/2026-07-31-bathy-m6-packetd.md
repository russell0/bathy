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
- Produces: `fn acquire_raw_sockets() -> Result<RawSockets, PrivilegeError>`, `fn drop_all_capabilities() -> Result<(), PrivilegeError>`, `fn capabilities_are_dropped() -> bool`, `struct UnprivilegedInput<R>`, and `--self-check`.

  **Five corrections to this task, made during Task 2 and flagged as plan edits. Every one of them was found by *running* the criterion rather than by reading it.**

  1. **AC-6.5's test cannot fail when the order changes, which is the only thing it is for.** The test below reads the daemon's own `--self-check` report and asserts `first_input_read_after_drop == true`. A process reporting on its own ordering can be wrong about it in exactly the way that matters, and the Global Constraint on ordering guarantees is explicit that the test must fail when the order *changes*, not when a step is deleted. The replacement, `crates/bathy-packetd/tests/privilege.rs`, asks the daemon nothing: it holds the daemon's stdin open and **empty**, writes not one byte, and watches `/proc/<pid>/status` from the parent until `CapEff` reads all zeros — only then does it send the first line. A byte of input cannot exist until the drop has been observed by a process other than the one that performed it. Move the drop below the first read and the daemon blocks on a pipe nobody will write to, `CapEff` never empties, and the test fails on its deadline; move it above `acquire_raw_sockets` and the daemon exits 69 before reading, which the same loop reports. Measured: the swap fails at 15.00s, the deletion at 0.01s. The self-check report is kept — it is what an operator runs and what makes the *negative* (`raw_socket_after_drop_denied`) observable — but it closes no criterion.

  2. **AC-6.6's test asserts nothing on a machine that has the capability.** `if !out.status.success() { ... }` means that on any host where the raw socket opens, the test passes having checked nothing — the shape of every test in this repository that turned out to be checking nothing. Both branches now assert, and each is the other's narrowing control: privileged, the report's five claims are all true and stderr must *not* mention `setcap`; unprivileged, the exit status is 69 and stderr carries the capability, the copy-pasteable command and the fallback. `BATHY_PACKETD_PRIVILEGED_TESTS=1` turns the unprivileged branch into a failure, so the privileged run cannot silently take the easy path.

  3. **AC-6.7's test cannot see the block this task actually writes.** `line.trim_start().starts_with("unsafe ")` misses `let rc = unsafe { ... }`, which is the single most common spelling and is exactly the one block this crate contains — the first version of the checker reported "no block found" about the file containing it. It now scans the code portion of every line with word boundaries on both sides, so the lint attribute (`unsafe_code`) and identifiers (`is_unsafe`) are not blocks. Its four-line window is gone too: the marker must sit in the unbroken comment run directly above, which a marker belonging to something else cannot satisfy and which does not cap how long a safety argument may be — the one in this tree is twelve lines.

  4. **AC-6.7 is satisfied by a crate with no `unsafe` in it at all.** That is a gate ranging over nothing, the failure `check-packetd` already refuses for the line budget. The rule is now: blocks each with a marker, **or** no blocks and a crate-level `forbid` — the compiler making the statement instead. Related: the criterion assumes the sockets and the capability drop need `unsafe`, and they do not. `socket2::Socket::new` *is* `socket(2)` and `caps::clear` *is* `capset(2)`. The one syscall no crate in that process's graph exposes safely is `prctl(PR_SET_NO_NEW_PRIVS, ...)`, which the Global Constraint's "only for raw socket syscalls" did not cover and which the milestone's own design requires — a drop an `execve` can undo is not a drop. The constraint sentence was widened to name it and narrowed to name the one file it may appear in.

  5. **AC-6.8's check exists, is job-scoped, fires — and did not read `fuzz/`.** `check-phrases` is a step in `ci.yml`'s `test` job and its `unsafe-only-in-packetd` rule scanned `crates` and `xtask`. `fuzz/` is a separate cargo workspace with six Rust targets, every one driving a parser with attacker-shaped bytes, and the rule that says "no crate outside `bathy-packetd`" had never read a line of it. They were all clean, which is the point: nothing had checked. The required roots are now derived from the tree's own `Cargo.toml` files. AC-6.8 also had a half nothing enforced at all — the rule catches the keyword *appearing*, and nothing caught `#![forbid(unsafe_code)]` *going missing*, which is what happened to `crates/bathy/src/lib.rs` and stayed true for six milestones (`6142271`, found by a person re-reading a sentence). `check-packetd` now walks every crate target root — libs, bins, `src/bin`, fuzz targets — and fails on any without it.

  **Task 2 measures 646/800** (Task 1 was 249). `cargo run -p xtask -- packetd-privileged` runs this crate's suite in a container with `--cap-add=NET_RAW --user 0:0`, because AC-6.5's ordering test cannot run on macOS (no capabilities) and cannot run in `linux-gate` (deliberately non-root), and a test with no command is a test that never executes.

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
- Create: `crates/bathy-packetd/src/syn.rs`, `crates/bathy-packetd/tests/wire.rs` (plan edit #2)
- Modify: `crates/bathy-packetd/src/{lib,main,privilege,protocol}.rs`, `crates/bathy-packetd/Cargo.toml`, `README.md`

**Six corrections to this task, made during Task 3. The first is a criterion
that contradicts another criterion in the same list; the last is a measurement
that says this milestone's own exit criterion cannot be met as written.**

1. **AC-6.13's test probes an address AC-6.10 forbids.** Step 1's
   `an_open_port_receives_a_rst_so_no_half_open_connection_is_left_behind`
   builds `session_allowing("127.0.0.0/8")` and probes `127.0.0.1` — and
   `reserved_ranges_are_refused_even_if_the_allowlist_permits_them`, four tests
   above it, requires `127.0.0.1` to be refused. The two cannot both pass. Any
   implementation that satisfied the RST test would have had a loopback hole,
   which is the exact defect AC-6.10 exists to prevent, so this is not a typo
   in a fixture: it is a criterion that would have been closed by breaking
   another one. The replacement probes a real, non-reserved address — the
   test container's own primary address, so the packets are locally delivered
   and therefore *observable* — and the lab run in the task report probes
   `10.30.0.10`.

2. **`s.rst_sent_count()` counts an intention, not a packet.** A counter the
   prober increments is satisfied by an implementation that increments it; the
   criterion says "no half-open connection is left on a target", which is a
   statement about the wire. `crates/bathy-packetd/tests/wire.rs` opens its own
   raw socket and counts RSTs in what the kernel actually delivered. That
   turned out to need a discriminator: when a SYN-ACK arrives for a source port
   the host kernel has no socket on, **the kernel sends an RST of its own, with
   the same sequence number ours carries** — so "an RST was observed" is a
   claim a packet this code did not send would satisfy. Every emitted packet
   carries `PROBE_MARKER` (0xba71) in its IP identification field, and the
   capture in the task report shows the two side by side: `id 47729` (ours,
   win 1024) and `id 0` (the kernel's, win 0).

3. **AC-6.12's test is a table over an enum nothing produces.**
   `classify_reply(Reply::IcmpUnreachable)` closes nothing unless something
   constructs `Reply::IcmpUnreachable` from a real packet. The criterion
   therefore also requires the ICMP receive path — parsing the type, and
   attributing the unreachable by the datagram it *quotes* (RFC 792) rather
   than by the address it arrived from, which is a router's. Both halves had
   mutants that survived the plan's test and die against the added ones.

4. **AC-6.11 does not say what happens when both refusals apply, and the
   order matters.** Scope and the ceiling can both refuse the same probe. The
   ceiling asked first is a mutant that survives every test in Step 1, and it
   makes a privileged process answer "budget spent" about a target it was
   never authorized to touch. Scope is asked first, and
   `scope_is_decided_before_the_ceiling_is_consulted` asserts the interleaving
   rather than the presence of either.

5. **The teardown RST is exempt from the ceiling, and that is a decision the
   criteria do not make.** `max_packets` admits *probes*. Refusing to send the
   RST at the ceiling would leave a half-open connection on a third party —
   more harm, not less, for a tidier number — so the ceiling bounds new
   probes and the teardown of a connection already paid for is exempt.
   `packets_emitted()` counts every packet including RSTs, so the exemption is
   visible rather than hidden, and
   `at_the_ceiling_an_open_ports_teardown_rst_is_still_sent` pins it.

6. **The 800-line exit criterion cannot be met, and the remedy it names does
   not apply.** Measured: **919/800** at the end of this task —
   `syn.rs` 244, `protocol.rs` 250, `privilege.rs` 226, `main.rs` 176,
   `lib.rs` 23. Task 1 measured 249 and Task 2 measured 646, so **81% of the
   budget went to the line protocol and the capability drop before the packet
   path — the milestone's actual subject — existed.** Task 5's ICMP path is
   still to come.

   The criterion's remedy is "move logic out of the privileged process", and
   there is nothing here that can go. The packet path is a checksum, a header
   builder, a reply matcher and a reply classifier; a privileged process that
   accepted a caller-supplied packet buffer, or delegated the decision of
   which reply is a reply to this probe, would have given up the property the
   whole two-process design exists for. Moving it into a new crate would leave
   it linked into the same address space and is the loophole `check-packetd`'s
   own passing output already names ("it cannot see logic moved into a
   dependency"). This task therefore leaves `check-packetd` **red** rather
   than raising the number quietly, because a cap moved to fit the code is the
   defect class this repository has recorded six times.

   What the milestone owner has to choose between: (a) re-derive the number
   from what the component must actually do, and record the derivation where
   the constant is; (b) cut `--self-check`'s report or `UnprivilegedInput`,
   both of which are defence-in-depth and diagnostics rather than the mission,
   and neither of which this task will delete on its own authority; or (c)
   keep 800 and do not ship Task 5's ICMP path in this process. **Do not
   resolve it by editing `PACKETD_LINE_BUDGET` without also writing down which
   of the three this is.**

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
- Modify: `crates/bathy-engine/src/scheduler.rs`, `crates/bathy-types/src/event.rs`, `crates/bathy-scope/src/manifest.rs`, `xtask/src/{gates,visibility,main}.rs`, `.github/workflows/ci.yml`, `README.md`
- Create: `crates/bathy-engine/src/packetd.rs`, `crates/bathy-engine/tests/syn_vs_connect.rs`, `crates/bathy-engine/tests/packetd_integration.rs`

**Seven corrections to this task, made during Task 4. The first says this
task's own acceptance test cannot see the failure it is most for; the last
is the ruling on the 800-line cap and is recorded as a defect in the
criterion rather than as a concession.**

1. **AC-6.14 compares two things and needs three.** "SYN and connect agree
   on every endpoint" is satisfied by two scanners that agree with each
   other and are both wrong, and a two-column test cannot see it. That is
   not hypothetical here: M7 Task 1 found exactly that defect *in this
   lab's own oracle* (`10.30.0.17:443` recorded `product: null` because
   bathy reported nothing there). The test therefore compares SYN, connect
   and `lab/ground-truth.json` — derived from a 65535-port sweep run inside
   each container's netns by a Python script that shares no code with bathy
   — and prints all three columns for any disagreement, so the question is
   which one is wrong rather than which scanner to tune. It also asserts the
   oracle demands all three of `open`, `closed` and `filtered`, because a
   lab whose every endpoint had the same expected state would make agreement
   free.

2. **The engine has no way to record a degradation, and AC-6.15 asks it
   to.** "Records `scan_mode`" makes the *method* self-describing and leaves
   the reason nowhere: the process that knew it — `packetd`, with AC-6.6's
   `setcap` guidance on its stderr — has already exited by the time anyone
   reads the log. `EventBody::ScanStarted` therefore gained
   `scan_mode_detail` alongside `scan_mode`, present only when the mode is
   not the one that was asked for. Both are `Option` with
   `skip_serializing_if`, forever, on `docs/event-log-compatibility.md`'s
   rule: `EventBody` carries `deny_unknown_fields`, so a required field
   would make every log written before this task fail to replay.

3. **AC-6.16 names one failure and there are two.** `packetd` dying is one
   way the two halves stop agreeing; `packetd` *refusing* a probe is the
   other, and it is the more serious one — it means the engine asked a
   privileged process to touch something that process's own independent
   scope check (AC-6.9, AC-6.10) rejected. The criterion is silent on it,
   and the obvious implementations (record `indeterminate`, or skip the
   endpoint) both turn an authorization disagreement into a missing row. It
   fails the scan with `packetd_refused`, and
   `the_engine_records_which_method_actually_ran`'s privileged branch
   demonstrates it against a loopback target the engine's manifest permits
   and `packetd` refuses.

4. **AC-6.17 cannot be closed by a test alone, and does not need to be.**
   "Derived from the same manifest, never from the raw request" is a
   statement about what a function can see. `packetd::init_request` takes
   `&ScopeManifest` and has no second parameter, so there is no
   `ScanRequest` in scope for it to read; the test's job is then to falsify
   the plausible *wrong* implementation, which is an allowlist narrowed to
   the request's targets, and it does that by giving the request one host
   inside the manifest's /24 and requiring the /24 to come out. The session
   ceiling is the manifest's ceiling rather than the request's budget for
   the same reason AC-6.11 exists: a second bound derived from the first
   number is not a second bound.

5. **`Filtered` conflating ICMP-refused with silence is required by
   AC-6.14, not merely tolerated** (Task 3's concern 5). Task 3 suggested a
   reason field now that the engine is being wired. The decision is **no**,
   and the reason is this task's own criterion: the connect path folds
   `Unreachable` and `Filtered` together because a connect scan cannot tell
   them apart, so a SYN path that reported them distinctly would disagree
   with connect on every filtered endpoint and fail AC-6.14. The lost detail
   is real and it belongs on the evidence layer (`PortStateObserved`'s
   `evidence_refs`), not on `PortState`, whose four values are a published
   wire contract two scanners have to agree on. Recorded here rather than
   guessed at later.

6. **`packetd-privileged` had a command and no CI job, for two tasks**
   (Task 2's concern 3, Task 3's concern 2). Fixed, in two jobs rather than
   one: `packetd-privileged` on every push (one image, no lab), and
   `syn-cross-validation` on the same schedule as `lab-conformance`, because
   the lab is eight digest-pinned images and 2.8 GiB behind Docker Hub's
   anonymous pull limit. `packetd_privileged_argv` grew the `--network` Task
   3 flagged as missing, so AC-6.14's container joins `bathy-lab_labnet`
   instead of a person doing it by hand. `check-packetd` asserts both jobs
   **by name**, with `job_block`, because a step asserted to exist somewhere
   in `ci.yml` has already satisfied one of this project's checks while
   defending nothing.

7. **The 800-line exit criterion measures the wrong thing** — see the
   Milestone Exit Criteria below, which now states the property the number
   was standing in for. Task 3 left the gate red at 922/800 and escalated;
   the resolution is not a bigger number. `check-packetd` now measures the
   **privileged window** — `main.rs`'s statements from `main`'s own opening
   brace to `drop_all_capabilities()`, plus every crate function transitively
   reachable from them — because that is the code that runs while
   `CAP_NET_RAW` is held, and a crate-wide cap counted 780-odd lines that
   never do and could not see work moved *into* the window. **The window
   opens at process entry, not at `acquire_raw_sockets()`** — see the
   Milestone Exit Criteria below for why the first version of this measure
   got that boundary wrong and what it cost.
   Measured: **130 lines across 15 functions**, budgeted at 140/16. The
   crate total survives as what it honestly is, a review-burden bound, set
   from evidence at 1100 (922 measured, plus 178 for Task 5's ICMP path,
   derived as three quarters of `syn.rs`'s 244 — the same shape with an
   8-byte header, no pseudo-header checksum, no reply matching, no teardown,
   and AC-6.19's requirement that it reuse the existing scope and budget
   path). The falsifier is
   `moving_work_into_the_window_fails_the_check_and_names_it`: 200 lines
   after the drop pass, the same 200 lines before it fail, and the crate
   total is identical in both.

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

**Eight corrections to this task, made during Task 5. The first is a test
that cannot pass without breaking AC-6.10 — the same defect Task 3 found in
its own Step 1 — and the last says one third of AC-6.20 cannot be closed from
the files this task owns.**

1. **AC-6.18's first test probes an address AC-6.10 forbids.**
   `an_echo_reply_marks_the_host_up_with_the_icmp_method` builds
   `session_allowing("127.0.0.0/8")` and probes `127.0.0.1` — and AC-6.19
   requires that probe to go through the *same* `check_session_scope` that
   AC-6.10 makes refuse loopback under any allowlist. The two cannot both
   pass, and an implementation that satisfied the test would have had a
   loopback hole in the ICMP path: exactly the shape of Task 3's plan edit
   #1, repeated. The replacement asserts `Up` against fixtures that answer
   a *real*, non-reserved address, and `crates/bathy-packetd/tests/wire.rs`
   proves it on the wire against the test container's own primary address,
   which the host answers for real.

2. **`s.last_method()` is a second statement of a fact the response already
   carries.** `classify_icmp` is a bijection — echo reply, unreachable and
   silence map one-to-one onto `Up`, `Down` and `Unknown` — so a mutable
   `last_method` on the session is derivable state that can disagree with
   the answer it describes, in the process that holds `CAP_NET_RAW`. It is
   not built. The method string belongs where AC-6.20 puts it: on the
   engine's `DiscoveryResult`, derived from the `HostState` that came off
   the wire.

3. **`Response::Result` cannot carry a `HostState`.** Step 1's first test
   reads `matches!(r, Response::Result { state, .. } if *state ==
   HostState::Up)`, and `Response::Result`'s `state` is a `PortState` (Task
   1). Host discovery needs its own request/response pair, so the protocol
   gains `Request::IcmpProbe { id, target }` and `Response::HostResult { id,
   state }`. A `port: Option<u16>` on the existing `Probe` was rejected: a
   request whose *response type* depends on whether a field was null is a
   protocol two builds can disagree about silently.

4. **AC-6.20's `discover_host_combined` cannot return a bare
   `DiscoveryResult`.** Two of the three things `packetd` can answer with are
   terminal by Task 4's own plan edit #3 and by AC-6.16: a **refusal** means
   the daemon's independent scope check rejected a target the engine
   authorized, and a **death** means the method stopped working. A signature
   with no error channel forces both into a discovery result, and the only
   discovery result available is "ICMP said nothing, try TCP" — which is this
   engine sending connect probes at an address a privileged process just
   declined to touch. It returns `Result<DiscoveryResult, PacketdError>`, and
   `a_refused_icmp_probe_is_terminal_and_sends_no_tcp_probe` observes the
   absence of the TCP probe by asking the listener, rather than asserting it.

5. **AC-6.20's test passes whichever answer it gets.** `assert!(r.method ==
   "icmp-echo-reply" || r.method.starts_with("tcp-connect"))` is a
   disjunction over both possible outcomes and therefore closes nothing —
   the "satisfied by the wrong thing" shape this milestone has now found
   eight times. It is replaced by three tests, each of which arranges for the
   *other* method to give a different answer: the `Down` case's configured
   TCP port is one that WOULD answer, so an implementation that fell back on
   anything but `Unknown` reports the opposite finding.

6. **AC-6.19's mixed-budget test is necessary and not sufficient.** Scope and
   the ceiling are two questions, and a plausible wrong ICMP implementation
   passes the allowlist half by calling a CIDR test and reaches multicast and
   broadcast anyway. `reserved_ranges_are_refused_for_icmp_too` is the other
   half, with an in-scope control so `0.0.0.0/0` still means something, and
   `an_out_of_scope_icmp_probe_is_refused_for_scope_even_with_no_budget`
   pins the interleaving for ICMP that AC-6.11 pins for SYN.

7. **A second probe kind on one receive path creates cross-talk no criterion
   mentions.** Both kinds share `RawSockets::poll`, and an ICMP unreachable
   quoting an *echo request* carries 0x0800 (type 8, code 0) exactly where a
   quoted TCP segment carries its source port. Each matcher now checks the
   quoted datagram's protocol, and the test hands `match_reply` precisely the
   port numbers it would otherwise have read out of the echo header — so the
   guard's removal fails it rather than passing by arithmetic luck.

8. **AC-6.20 names the `host.discovered` event, and this task's own file list
   contains no file that can emit one.** The files are `icmp.rs` (create) and
   `discovery.rs` (modify); an emitter needs the event log, the evidence
   store — `EventBody::HostDiscovered::evidence_refs` is a
   `NonEmpty<Digest>`, so there is no event without a stored blob — and a
   decision about *when* discovery runs. **This task therefore closed the
   deciding-method half of AC-6.20 and left the event half open, recorded,
   rather than emitting the event from a default-off configuration flag that
   would be a production caller in name only.** That much was right.

   **The blocker this task named was not one, and the fix wave closed the
   criterion.** Task 5 gave the deciding reason as "`bathy_plan::ScanPlan`
   carries no `bathy_types::request::Objective`, so `scheduler` cannot tell a
   `HostInventory` scan from an `InventoryExposedServices` one". The first
   clause is true; the conclusion does not follow, because the scheduler does
   not take its request-derived configuration from `ScanPlan` and never has.
   `Scheduler::new` already accepted `service_detection` and `evidence_level`
   as direct parameters, both production call sites already read them off
   `authorized.request()` in the same argument list, and `Objective` is a
   `Copy` field on that same `ScanRequest`. It was a thirteenth parameter and
   two call-site lines, on a seam M4 built and had used twice since. Naming
   `ScanPlan` as the obstruction also pointed the next reader at the one
   structure that must not change -- its field set is what the plan hash is
   over. The wrong reason had been copied into `crates/bathy-engine/src/discovery.rs`,
   `README.md` and `docs/design-paper.md` before anyone checked it; all four
   copies are now corrected. What was genuinely left was the phase itself --
   evidence record, event emission, budget and pacing -- which is work rather
   than a missing primitive.

**Task 5 measures 1074/1100** (Task 3 measured 922, Task 4 added nothing), so
the ICMP path cost **152 of the 178 lines Task 4 reserved for it**. The
privileged window is **unchanged at 130/140 lines across 15/16 functions**:
`acquire_raw_sockets` already opened the ICMP receive socket, the sending
socket is `IPPROTO_RAW` with `IP_HDRINCL`, and every function in `icmp.rs`
runs after the drop.

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
- **AC-6.20** Combined discovery tries ICMP first when privileged and falls back to TCP on an inconclusive result, recording the deciding method on the `host.discovered` event. **Closed** by the fix wave. `Scheduler::run` gates a discovery phase on `Objective::HostInventory`, stores each `DiscoveryResult` and appends the `host.discovered` event citing that digest — the only production construction of `EventBody::HostDiscovered`. `a_host_inventory_scan_records_the_deciding_method_and_an_inventory_scan_records_nothing` is the named test, and its second half is the narrowing control that keeps the three `InventoryExposedServices` tests meaning what they meant.

  **This criterion was edited to read "Partially closed" while it was unmet, and that edit is the move this project has refused seven times.** M6's whole-branch review ruled it UNMET rather than two-thirds closed, on the ground that a criterion deferred out of the last implementation milestone is not deferred. See correction 8 above for the blocker that was not one.

---

## Milestone Exit Criteria

- [ ] `cargo test --workspace` green; the two privileged CI jobs green, including the cross-validation test.
- [ ] AC-6.1 through AC-6.20 each demonstrated by a named passing test.
- [ ] **The privileged window is small, enumerable, and measured rather than asserted.** The code that runs while `CAP_NET_RAW` is held is `main.rs`'s statements **from `main`'s opening brace** to `drop_all_capabilities()` plus the crate functions transitively reachable from them, and `cargo run -p xtask -- check-packetd` prints that set by name on every run and fails when it grows. Budget 140 lines across 16 functions, from a measurement of 130 across 15, of which **zero** run before `acquire_raw_sockets()`.

  **The window opens at process entry, and this sentence used to say it opens at the acquisition.** That was not a wording slip; it was the false fact the checker implemented. `bathy-packetd` is spawned with `CAP_NET_RAW` already in its permitted and effective sets — that is *why* `acquire_raw_sockets()` can succeed — so the process is privileged from its first instruction and everything `main` did before the acquisition ran privileged and uncounted. M6's whole-branch review demonstrated it by execution: it moved the argv parse above the acquisition and added an environment read beside it — attacker-influenced input parsed while the capability is held — and `check-packetd` reported the identical `130/140` over `15/16`, `cargo test -p bathy-packetd` passed 98+8+3+4, and the entire privileged container job stayed green against a byte-identical clean-tree control. The old boundary happened to coincide with the true one only because the acquisition is `main`'s first statement, which nothing enforced. Two rules now hold it: the window is measured from `main`'s brace, and **the prelude — the code between entering `main` and reaching the acquisition — must be zero lines**, because the reproduction was eight lines and the budget's ten lines of headroom would have absorbed it in silence.

  **This replaces "under 800 lines of non-test Rust", which was a defect in the criterion and not merely a number that had been outgrown.** It was written before the design existed, and its own stated purpose — in the checker's output — was to bound "the logic a reviewer must follow in the one process that will hold `CAP_NET_RAW`". Task 2 then established, by execution from a second process watching `/proc/<pid>/status`, that the capability is held only across those two calls: `read_line`, `handle_line`, all of `protocol.rs` and all of `syn.rs` run unprivileged, holding sockets that were already open. So the total counted 780-odd lines that never execute with a capability held, and — the failure that matters — **could not see work moved into the window**, because moving a line from after the drop to before it leaves the total unchanged. Task 3 left the gate red at 922/800 rather than raising it, which was right; the resolution is a criterion that tracks the property, not a bigger number. Verified the way everything else here is, in both directions of both boundaries: `moving_work_into_the_window_fails_the_check_and_names_it` moves 200 lines across the *drop* and asserts the check fails only one way, and `work_before_the_acquisition_is_privileged_and_fails_the_check` — the mirror the first version could not express, because `window_fixture` hardcoded the acquisition as `main`'s first statement and made the shape unrepresentable — replays the review's own four-line argv/environment reproduction, asserts it is inside the line budget so it is the prelude rule and not the budget that catches it, and carries the identical four lines below the drop as its narrowing control.

- [ ] `bathy-packetd` is under **1100** lines of non-test Rust — a bound on *review burden*, which is what a whole-crate count can honestly claim, and not a security boundary. Derived and recorded at the constant: 922 measured at the end of Task 3, plus 178 for Task 5's ICMP path (three quarters of `syn.rs`'s 244 — the same shape with an 8-byte header, no pseudo-header checksum, no sequence matching and no teardown, reusing `check_session_scope` and the session budget unchanged as AC-6.19 requires). Task 4 adds nothing to it: the engine-side integration is in `bathy-engine`. If it goes red, the remedy is still not a bigger number — it is either evidence the estimate was wrong, in which case replace the derivation, or work that does not belong in this crate. **Measured at the end of Task 5: 1074/1100.** The ICMP path cost 152 of the reserved 178, and 20 of those 152 are a `Prober::admit` and a `Session::handle_work` that *removed* a duplicate from the SYN path rather than adding one — the derivation held.
- [ ] Every `unsafe` block has a `SAFETY:` comment; no other crate has any.
- [ ] `docs/design-paper.md` contains a section explaining the scope enforcement and why the duplication is intentional. **Written as "the two-layer scope enforcement", and M6 makes that three** — Task 5 correctly added Layer 3 to §5's body and left the heading, this criterion and the same count in `docs/threat-model.md` and `SECURITY.md` saying two. All four now say three.
