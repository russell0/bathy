# bathy M7 — Integration Lab, Fuzzing, Benchmarks & Publication — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make every claim the project makes checkable by someone who does not trust us — a pinned Docker lab with known ground truth, fuzz targets over every parser, reproducible benchmarks against the incumbents, and the documentation and safety artifacts required before a public release.

**Architecture:** The lab is the oracle. Because we control the images and pin them by digest, we know exactly what is listening on every address and port, so correctness becomes an assertion against a checked-in ground-truth file rather than a judgement call. Benchmarks run against the same lab, which is what makes a comparison against another scanner meaningful rather than anecdotal.

**Tech Stack:** Docker Compose, cargo-fuzz (libFuzzer), criterion, cargo-deny.

**Read first:** the overview's Global Constraints and its Pre-Publication Gates — Task 6 discharges those gates.

---

### Task 1: The deterministic integration lab

**Files:**
- Create: `lab/docker-compose.yml`, `lab/ground-truth.json`, `lab/README.md`, `lab/run.sh`
- Create: `lab/scope.json`, `lab/tls/nginx-tls.conf`, `lab/verify-ground-truth.py` (see plan edits #2 and #4)
- Create: `crates/bathy/tests/lab_conformance.rs` — the plan named no home for Step 3's tests; `crates/bathy` is the top of the layer stack and already depends on every crate a whole-lab scan touches, so it needs no Cargo change
- Modify: `xtask/src/gates.rs`, `xtask/src/main.rs`, `.github/workflows/ci.yml` — AC-7.1 is a gate, and this project's standing rule is that a gate with no `cargo run -p xtask -- check-<something>` form is a gate that goes red and stays red
- Modify: `crates/bathy-probe/src/probes/tls.rs` (see plan edit #5)

  **Five corrections to this task, made during Task 1 and flagged as plan edits. The first two are defects in the acceptance surface itself: one AC could not fail, and the checked-in oracle was wrong.**

  1. **AC-7.4's drafted test is a decoration test.** `assert!(!fold.hosts_up.contains(&ip))` cannot fail on any v0.1 tree: `Scheduler` has no call to `discover_host` (unprivileged ICMP is impossible, so host discovery ships with `packetd` in M6 — the overview's Gap Register says so), which means `ScanFold::hosts_up` is empty after *every* scan. As written the criterion passes against a scanner that reports the whole subnet live. The property that is real in v0.1: every endpoint on an address with no host must be `Filtered` — never `Open` (a service we invented) and never `Closed` (a claim that an RST arrived, which is itself evidence a host is there). The shipped test asserts that, and separately asserts `hosts_up` **is** empty, so wiring host discovery in makes it fail and demand the stronger assertion rather than silently going vacuous again. AC-7.4 is restated below.

  2. **Step 2's ground truth was written by reading the compose file, and it is wrong.** Scored against it, a *correct* scanner reports four false positives: `mysql` also opens 33060 (X Protocol), `bind9` also opens 443 and 853 (DoH and DoT), and `boky/postfix` also opens 587. This is the failure the task's own architecture note warns about — a wrong oracle makes a real disagreement look like our bug — and it arrives precisely by asserting the ground truth instead of deriving it. `lab/verify-ground-truth.py` now sweeps all 65535 TCP ports on every lab address from inside `labnet`, using Python standard-library sockets only, and reads a banner from each open port so every `product`/`version` is transcribed from something observed. `lab/run.sh` gains a `verify` subcommand. **Nothing may be added to `ground-truth.json` that was not observed by a run of that sweep.**

  3. **The plan assumes the host can route to the lab subnet. On macOS it cannot,** so Step 5's "Run the suite — `lab/run.sh test`. Expected: 5 passed" is not achievable on a macOS developer machine. Docker Desktop runs the daemon in a VM whose bridges never enter the Mac's routing table; measured, not assumed (a container on a user-defined bridge answers neither ping nor a TCP connect from the host, and loopback aliasing is not a workaround because binding `127.0.0.2` needs root). This is consistent with the overview's "Linux first, macOS best-effort", and the consequence is that the *skip* behaviour is part of the deliverable rather than a nicety: see the restated AC-7.6 note and `lab/README.md`.

  4. **Step 1's `tls-web` cannot start.** It mounts `./tls` as `conf.d` with no certificate anywhere in the tree and no step that creates one. Committing a key is not an option — Task 6's own publish gate greps for `BEGIN … PRIVATE KEY`. A `tls-init` service now generates a throwaway self-signed key into a Docker volume at `up` time, using the one already-pinned image that ships `openssl`; `lab/run.sh down` passes `-v` so the key does not outlive the lab.

  5. **`cargo test --workspace -- --ignored`, which Step 4's `run.sh` runs, was not empty.** `bathy-probe`'s `tls_probe_against_a_real_nginx_tls_1_3_server` dialled `127.0.0.1:18543` and depended on a container described only in an M4 task report — un-runnable by anyone without that report open, and it would have failed `lab/run.sh test` on every machine. It now targets the lab's `tls-web`, with the same skip-or-require semantics.

- [ ] **Step 1: Write the compose file with digest-pinned images**

Every image is pinned by digest, never by tag. A tag that moves turns a green suite red for reasons unrelated to our code, and — worse — silently changes the banners our interpretation rules are tested against.

```yaml
name: bathy-lab
networks:
  labnet:
    ipam:
      config:
        - subnet: 10.30.0.0/24
services:
  web-nginx:
    image: nginx@sha256:PINNED
    networks: { labnet: { ipv4_address: 10.30.0.10 } }
  ssh-openssh:
    image: linuxserver/openssh-server@sha256:PINNED
    networks: { labnet: { ipv4_address: 10.30.0.11 } }
  db-postgres:
    image: postgres@sha256:PINNED
    environment: { POSTGRES_PASSWORD: labonly }
    networks: { labnet: { ipv4_address: 10.30.0.12 } }
  db-mysql:
    image: mysql@sha256:PINNED
    environment: { MYSQL_ROOT_PASSWORD: labonly }
    networks: { labnet: { ipv4_address: 10.30.0.13 } }
  cache-redis:
    image: redis@sha256:PINNED
    networks: { labnet: { ipv4_address: 10.30.0.14 } }
  mail-postfix:
    image: boky/postfix@sha256:PINNED
    networks: { labnet: { ipv4_address: 10.30.0.15 } }
  dns-bind:
    image: internetsystemsconsortium/bind9@sha256:PINNED
    networks: { labnet: { ipv4_address: 10.30.0.16 } }
  tls-web:
    image: nginx@sha256:PINNED
    volumes: [ "./tls:/etc/nginx/conf.d:ro" ]
    networks: { labnet: { ipv4_address: 10.30.0.17 } }
  # A host that exists but answers nothing, to exercise `filtered`.
  silent:
    image: alpine@sha256:PINNED
    command: ["sleep", "infinity"]
    networks: { labnet: { ipv4_address: 10.30.0.18 } }
```

- [ ] **Step 2: Write the ground truth file**

```json
{
  "subnet": "10.30.0.0/24",
  "hosts": [
    { "ip": "10.30.0.10", "up": true,
      "open": [{"port": 80, "service": "http", "product": "nginx"}] },
    { "ip": "10.30.0.11", "up": true,
      "open": [{"port": 2222, "service": "ssh", "product": "OpenSSH"}] },
    { "ip": "10.30.0.12", "up": true,
      "open": [{"port": 5432, "service": "postgresql"}] },
    { "ip": "10.30.0.18", "up": true, "open": [] }
  ],
  "absent": ["10.30.0.200", "10.30.0.201"]
}
```

- [ ] **Step 3: Write the failing conformance test**

```rust
#[tokio::test]
#[ignore = "requires the lab; run with `lab/run.sh test`"]
async fn the_scanner_finds_every_open_port_in_the_ground_truth() {
    let truth = load_ground_truth();
    let fold = scan_the_lab().await;
    let mut missing = Vec::new();
    for host in &truth.hosts {
        for expected in &host.open {
            let key = (host.ip, tcp(expected.port));
            match fold.endpoints.get(&key) {
                Some(e) if e.state == PortState::Open => {}
                other => missing.push(format!("{}:{} expected open, got {other:?}", host.ip, expected.port)),
            }
        }
    }
    assert!(missing.is_empty(), "false negatives:\n{}", missing.join("\n"));
}

#[tokio::test]
#[ignore = "requires the lab"]
async fn the_scanner_reports_no_open_port_that_is_not_in_the_ground_truth() {
    let truth = load_ground_truth();
    let fold = scan_the_lab().await;
    let false_positives: Vec<_> = fold.open_endpoints()
        .filter(|(ip, ep)| !truth.is_open(*ip, ep.port))
        .collect();
    assert!(false_positives.is_empty(), "false positives: {false_positives:?}");
}

#[tokio::test]
#[ignore = "requires the lab"]
async fn absent_addresses_are_reported_down_not_filtered_ambiguously() {
    let fold = scan_the_lab().await;
    for ip in load_ground_truth().absent {
        assert!(!fold.hosts_up.contains(&ip), "{ip} does not exist but was reported up");
    }
}

#[tokio::test]
#[ignore = "requires the lab"]
async fn service_identification_matches_the_ground_truth_products() {
    let truth = load_ground_truth();
    let fold = scan_the_lab().await;
    for host in &truth.hosts {
        for expected in host.open.iter().filter(|o| o.product.is_some()) {
            let obs = fold.endpoints[&(host.ip, tcp(expected.port))].observation.as_ref()
                .unwrap_or_else(|| panic!("{}:{} had no observation", host.ip, expected.port));
            assert_eq!(obs.product.as_deref(), expected.product.as_deref());
            assert!(obs.confidence.get() >= 0.70);
        }
    }
}

#[tokio::test]
#[ignore = "requires the lab"]
async fn two_consecutive_scans_of_the_static_lab_produce_an_empty_diff() {
    // The lab does not change between runs, so any diff is scanner noise.
    // This is the honest, testable version of the reproducibility claim.
    let a = scan_the_lab().await;
    let b = scan_the_lab().await;
    let d = diff(&a, &b);
    let substantive: Vec<_> = d.changes.iter()
        .filter(|c| c.kind != ChangeKind::ConfidenceOnly)
        .collect();
    assert!(substantive.is_empty(), "scanner produced unstable results: {substantive:?}");
}
```

- [ ] **Step 4: Write `lab/run.sh`**

```bash
#!/usr/bin/env bash
set -euo pipefail
case "${1:-up}" in
  up)   docker compose -f lab/docker-compose.yml up -d --wait ;;
  down) docker compose -f lab/docker-compose.yml down -v ;;
  test) "$0" up
        cargo test --workspace -- --ignored
        "$0" down ;;
  *) echo "usage: $0 {up|down|test}" >&2; exit 64 ;;
esac
```

- [ ] **Step 5: Run the suite** — `lab/run.sh test`. Expected: 5 passed.

- [ ] **Step 6: Commit**

```bash
git add lab
git commit -m "test(lab): digest-pinned Docker lab with checked-in ground truth"
```

**Acceptance criteria:**
- **AC-7.1** Every lab image is pinned by `sha256:` digest — the multi-architecture index digest, so the lab is not silently single-architecture. `cargo run -p xtask -- check-lab` reads the compose file and fails on any bare tag, on a digest of the wrong length or alphabet, and on a compose file with no `image:` line at all. It runs in CI, where there is no Docker, because it reads text. The same command holds `lab/ground-truth.json` to the address plan the compose file assigns, in both directions: **a wrong ground truth is worse than no lab.**
- **AC-7.2** Zero false negatives against the ground truth: every known-open port is found.
- **AC-7.3** Zero false positives: no port is reported open that the ground truth says is not. The ground truth must be *derived* by sweeping the running containers (plan edit #2), and the scanned port set must contain ports that are shut on hosts that are up — otherwise a scanner reporting everything it touched as open would pass. `check-lab` fails if that narrowing control is removed.
- **AC-7.4** Addresses with no host are never reported `Open` or `Closed`; every endpoint on one is `Filtered`. *Restated — see plan edit #1.* "Reported down" is not assertable in v0.1: `hosts_up` is empty after every scan because host discovery ships with `packetd` in M6, so the original wording named a test that could not fail.
- **AC-7.5** Service identification matches ground-truth products *and versions* at confidence ≥ 0.70, over every port whose ground-truth entry names a product. `product: null` in the ground truth means the lab does not establish one (the service volunteers nothing that names it), not that identification failed.
- **AC-7.6** Two consecutive scans of the static lab produce a diff containing no substantive changes. This is the reproducibility claim, stated in the only form that is actually true. The diff must first be shown *comparable* (`absence_was_evidence()`), or an empty change list means nothing.
- **AC-7.32** The suite has an honest answer everywhere it cannot run. `cargo test --workspace` lists the five conformance tests as **ignored** — not omitted, not passed — and runs the fixture guards that need no container. Run with `--ignored` against an unreachable lab, each test writes the reason and how to fix it straight to the process's stderr (bypassing libtest's capture, which discards output from a passing test) and returns. `lab/run.sh test` sets `BATHY_LAB_REQUIRED`, which turns that skip into a failure, so the one command whose purpose is to test the lab cannot pass without one.

  *Added during Task 1: the original criteria said nothing about the no-Docker case, and "silently passes on the CI runner" is the failure mode that leaves.* Numbered **7.32**, after this milestone's last published criterion, rather than 7.7 — the ACs are an audit surface that reports already cite by number, and renumbering six tasks' worth of identifiers to insert one is a worse defect than a non-contiguous list.

---

### Task 2: Fuzzing every parser

**Files:**
- Create: `fuzz/Cargo.toml`, `fuzz/fuzz_targets/{interpret,event_log,canonical_json,manifest}.rs` — `ipc.rs` is deferred, see plan edit #1
- Create: `fuzz/src/lib.rs`, `fuzz/seeds/**`, `fuzz/README.md`, `fuzz/.gitignore` (see plan edits #3 and #4)
- Modify: `xtask/src/gates.rs`, `xtask/src/main.rs`, `.github/workflows/ci.yml` — AC-7.10 is a gate, and this project's standing rule is that a gate with no `cargo run -p xtask -- check-<something>` form is a gate that goes red and stays red (see plan edit #5)

  **Five corrections to this task, made during Task 2 and flagged as plan edits. The first is a defect in the acceptance surface itself: AC-7.7 names a crate that cannot exist while this task runs.**

  1. **AC-7.7's fifth target has no code to fuzz.** The overview's recommended execution order is M1 → M5 → **M7** → M6, so `bathy-packetd` — and with it the IPC protocol AC-7.7 requires a target for — does not exist while this task runs. The two available moves were a stub target or a recorded deferral, and a stub is worse: it would fuzz nothing, register as coverage in every subsequent report, and be the exact "reaches nothing" shape this milestone measured and rejected in a property-test strategy. So the surface stays registered in `gates::FUZZ_SURFACES` marked `deferred`, and `packetd-ipc-fuzz-target` joins `xtask`'s `DEFERRALS`, which fails `check-deps` the day `crates/bathy-packetd/Cargo.toml` appears without `fuzz/fuzz_targets/ipc.rs` — and reports *itself* stale the day the target lands. **AC-7.7 is restated below**: four of the five surfaces are covered by a target, and the fifth is covered by a check that expires on its own. When M6 writes `ipc.rs` the assertion to hold it to is not "it does not panic": the IPC boundary is the one place in this repository where the parser runs *privileged*, so a parsing bug there is a privilege-escalation bug.

  2. **The drafted target does not compile, and its probe list would go stale.** `ProbeCapture` has a `transport` field the sketch omits. More substantively, the sketch hard-codes the eight probe ids; the shipped target iterates `bathy_interpret::known_probe_ids()`, which is the rule registry's own answer, so a ninth protocol is fuzzed the day it lands. This repository has found a hand-maintained second list of something going stale in five separate places, and a fuzz target is the worst place for it, because the symptom is silence.

  3. **The plan says nothing about a corpus, and a fuzz target without one proves nothing.** This milestone's own measurement is the argument: a property-test strategy over `interpret` produced **6 non-empty results in 4096 cases and 0 spans past byte 6** — it never once reached the code it claimed to cover. Structured parsers are not reachable from random bytes in useful time. `fuzz/seeds/` is committed and seeded from real recorded data (all 17 captures in `testdata/captures/`, three real event logs, all 27 committed schemas, every manifest document the test suite loads); `check-fuzz` fails a target whose seed directory is empty. Measured: the committed seeds alone reach **13 of `bathy-interpret`'s 13** rules on a `-runs=0` replay — 25 executions, `reached=13/13`. (This said *12 of 13* until M7 Task 2's fix round. The M7 Task 2 review re-measured it at 13/13 and this round reproduced that; understating was the safe direction, but a number in a permanent artifact that is checkable in four seconds should be the measured one.)

  4. **A fuzz run reports nothing about what it reached, so each target now counts it.** libFuzzer's execution and edge counts are process-wide and include `serde_json`'s lexer and the allocator; they are entirely consistent with every input bouncing off the first `if` in the parser under test. Each target carries named counters (`fuzz/src/lib.rs`, `BATHY_FUZZ_STATS=1`) reporting what it actually reached — for `interpret`, which of the thirteen rules fired, how many inputs matched at all, and how many produced a span deep enough to have gone through a rule's own offset arithmetic.

  5. **Step 3's "add a CI job" fails `check-ci` as written, twice over.** A `run:` step of `cargo fuzz run <target>` is neither an xtask subcommand nor a declared cargo built-in, and four such lines would be a second registry of targets living in a file nobody runs locally — which is the MSRV-membership defect that had no executable form and three recorded recurrences. The job runs `cargo run -p xtask -- fuzz --time <n>`, which iterates the one registry; `check-fuzz` holds the tree to it and additionally checks the things AC-7.10 asks for and nothing else would (that the corpus is cached, and that the job has no `if:` taking it off pull requests). `cargo install cargo-fuzz` stays a `run:` step under the same exemption the toolchain installs already have — a program that needs the tool cannot be what provides it.

- [ ] **Step 1: Write the fuzz targets**

```rust
// fuzz/fuzz_targets/interpret.rs
#![no_main]
use libfuzzer_sys::fuzz_target;

/// Interpretation consumes attacker-controlled bytes by definition — the
/// response side of every probe. It must never panic, never hang, and never
/// allocate proportionally to nothing.
fuzz_target!(|data: &[u8]| {
    for probe_id in ["http-get-v1", "tls-v1", "ssh-banner-v1", "smtp-banner-v1",
                     "dns-version-bind-v1", "postgres-startup-v1",
                     "mysql-greeting-v1", "redis-ping-v1"] {
        let capture = ProbeCapture {
            probe_id, port: 80, request: None,
            response: data.to_vec(), elapsed_micros: 0, truncated: false,
        };
        let out = bathy_interpret::interpret(&capture);
        // Any produced span must index real bytes — a bad span would panic a
        // consumer that slices with it.
        for i in &out {
            assert!(i.matched_span.end <= data.len());
            assert!(i.matched_span.start <= i.matched_span.end);
        }
    }
});
```

Four more targets, same discipline: `event_log` (parse arbitrary JSONL), `canonical_json` (canonicalize arbitrary `serde_json::Value`), `manifest` (load arbitrary manifest JSON), `ipc` (`packetd`'s line protocol).

- [ ] **Step 2: Run each target briefly**

Run: `cargo +nightly fuzz run interpret -- -max_total_time=120` for each target.
Expected: no crashes, no timeouts, no OOM. Commit any discovered input to `fuzz/corpus/` and fix the bug before proceeding.

- [ ] **Step 3: Wire a short fuzz run into CI**

Add a CI job running each target for 60 seconds on pull requests and 10 minutes nightly, with the corpus cached.

- [ ] **Step 4: Commit**

```bash
git add fuzz .github
git commit -m "test(fuzz): libFuzzer targets for every untrusted-input parser"
```

**Acceptance criteria:**
- **AC-7.7** Every function that consumes untrusted bytes is registered in `gates::FUZZ_SURFACES` and either has a fuzz target or has a registered deferral that expires by itself. Four have targets — interpretation, event log parsing, canonical JSON, manifest loading. Two are deferred with mechanical triggers: the `packetd` IPC protocol (the crate does not exist yet) and the MCP stdio boundary (`bathy_mcp::lifecycle::classify` is `pub(crate)`, so there is no entry point to fuzz — added in M7 Task 2's fix round, after the review named it as the one unregistered surface it could find). **Note what "every function" can and cannot mean here:** `FUZZ_SURFACES` is a hand-maintained list and nothing derives it from the code, so completeness is asserted by the list rather than proved by it — the same second-registry pattern this milestone objects to elsewhere, applied to the completeness claim itself. What is enforced is that every registered surface has a target or an expiring deferral, that every target has seeds, and that every declared `[[bin]]` is a registered surface. *Restated — see plan edit #1.* The original wording named a target for a crate that does not exist while this task runs, and the honest discharge is a check that fires when it does, not a stub that fuzzes nothing. `cargo run -p xtask -- check-fuzz` fails if a registered surface loses its target, if a target loses its seeds, if a `[[bin]]` appears that the registry does not name, or if the fuzz package rejoins the root workspace and drags nightly into the pinned build.
- **AC-7.8** Each target survives 120 seconds with no crash, hang, or OOM, **and reports what it reached while doing so.** *Extended — see plan edit #4.* A target that survives 120 seconds having never left the parser's first rejection branch satisfies the original wording exactly, and this milestone has already measured one instrument that did precisely that. `BATHY_FUZZ_STATS=1` makes each target print its own reach counters; the `interpret` figure that matters is which of the thirteen registered rules fired.
- **AC-7.9** `interpret`'s fuzz target asserts every returned `matched_span` is a valid index range into the input, in three forms: not inverted, not past the end, **and usable to slice the response** — which is what a consumer does with it. `check-fuzz` fails if any of the three assertions is removed, each tested separately. The assertion is shown to work by mutation, not by inspection: with `rules.rs`'s HTTP `Server:` span widened by one byte, the target found an out-of-range span in 22 seconds and named the rule and the offsets.
- **AC-7.10** CI runs every registered target on every pull request, with the corpus cached across runs. The job carries no `if:`; the nightly/PR difference is on the duration, not on whether it runs. `check-fuzz` asserts all three, because a caching step and a job-level condition are both one-line edits away from making this criterion silently untrue.

---

### Task 3: Reproducible benchmarks

**Files:**
- Create: `benches/lab_scan.rs`, `bench/compare.sh`, `docs/benchmarks.md`

- [ ] **Step 1: Write the comparison harness**

`bench/compare.sh` runs bathy, Nmap, Masscan, and RustScan against the identical lab subnet and port set, recording wall-clock time, packets emitted (from `/proc/net/snmp` deltas), and — the part that matters — **accuracy against the ground truth**.

Rules that make the comparison honest, and that must be stated in `docs/benchmarks.md`:
- Same target set, same port set, same timeout, same rate limit, on the same machine, in the same run.
- Report accuracy alongside speed. A scanner that is faster and wrong is not faster.
- Record every tool's exact version and full command line in the output.
- Where a tool is configured differently from its default, say so and say why.
- Where a competitor wins, print that it won. A benchmark suite that never loses is marketing, not measurement, and a reviewer will notice within five minutes.
- Nmap has 28 years of fingerprint coverage. Expect to lose the service-identification breadth comparison decisively, and publish that result rather than omitting the category.

- [ ] **Step 2: Write the criterion micro-benchmarks**

Benchmark the parts we control: `interpret` throughput over the replay corpus, `canonical_json` over representative plans, plan construction for a `/16`, and event log append throughput. These are regression detectors, not marketing numbers.

- [ ] **Step 3: Run and write `docs/benchmarks.md`**

Publish the real numbers from a real run, including the categories where bathy loses.

- [ ] **Step 4: Commit**

```bash
git add benches bench docs/benchmarks.md
git commit -m "bench: reproducible cross-scanner comparison with accuracy reported alongside speed"
```

**Acceptance criteria:**
- **AC-7.11** The comparison runs all four scanners against the identical lab, ports, timeout, and rate, on one machine in one run.
- **AC-7.12** Accuracy against ground truth is reported for every scanner, next to its timing.
- **AC-7.13** Every tool's version and full command line appears in the published output.
- **AC-7.14** `docs/benchmarks.md` reports at least one category where bathy loses, including service-identification breadth.
- **AC-7.15** Criterion benchmarks cover `interpret`, `canonical_json`, plan construction, and log append.

---

### Task 4: Documentation

**Files:**
- Create: `README.md`, `docs/design-paper.md`, `docs/platform-support.md`, `docs/threat-model.md`

- [ ] **Step 1: Write the README**

Required structure: what it is in two sentences; the authorized-use statement, above the fold; a 60-second quickstart that includes writing a scope manifest, because there is no way to scan without one; the eleven MCP tools; an honest limitations section.

The limitations section is not optional and must state plainly:
- Service-identification coverage is a fraction of Nmap's. Nmap has 28 years of community fingerprint contributions; bathy v0.1 has eight protocols.
- No OS detection, no UDP breadth, no traceroute, no IPv6 scanning, no Windows support in v0.1.
- Port presets are IANA-derived heuristics, not prevalence measurements.
- Observations are not reproducible; planning and interpretation are. Explain the distinction.

Positioning rules, binding: the README compares bathy to *tools*, never to *people*. No named individual appears in it. No claim that another project is bad, badly run, or obsolete. The argument is "here is an interface designed for a different consumer, here are the measurements" — and that argument is strictly stronger than any adjective.

- [ ] **Step 2: Write the design paper**

`docs/design-paper.md`, working title *Network Discovery After the CLI: Designing a Deterministic Planner for Autonomous Software Agents*. Sections: the integration gap between XML/CLI and typed tool calling; the evidence and provenance model; why planning is deterministic and observation is not; two-layer scope enforcement; the plugin sandboxing plan; measurements; **limitations and threats to validity**; a clean-room attestation.

- [ ] **Step 3: Write `docs/platform-support.md`**

Linux is supported. macOS is best-effort (BPF device permissions differ). Windows is out of scope for v0.1, and the reason is stated factually: the dominant packet-capture layer on Windows is Npcap, whose license terms are incompatible with the redistribution model we want. This is a licensing constraint, not a technical one, and it is not a criticism of anyone.

- [ ] **Step 4: Write `docs/threat-model.md`**

What bathy defends against (hostile responses from scanned endpoints, a confused or adversarial calling agent, an over-broad scope manifest), what it does not (a compromised host running `packetd`, a malicious operator with legitimate scope), and why the LLM is kept off the packet path.

- [ ] **Step 5: Commit**

```bash
git add README.md docs
git commit -m "docs: README, design paper, platform support, and threat model"
```

**Acceptance criteria:**
- **AC-7.16** The README's limitations section explicitly states that service-identification coverage is far below Nmap's and explains why.
- **AC-7.17** No document in the repository names an individual person in a comparative or critical context. Asserted by a CI grep over `docs/` and `README.md`.
- **AC-7.18** The README carries an authorized-use statement above the fold.
- **AC-7.19** The quickstart cannot be followed without creating a scope manifest, reflecting that the tool genuinely requires one.
- **AC-7.20** `docs/design-paper.md` contains a limitations section and a clean-room attestation.
- **AC-7.21** `docs/platform-support.md` states the Windows position factually as a licensing constraint.

---

### Task 5: Security policy and responsible defaults

**Files:**
- Create: `SECURITY.md`, `.github/ISSUE_TEMPLATE/`, `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`

- [ ] **Step 1: Write `SECURITY.md`**

Must contain: a disclosure contact and expected response time; a statement that bathy is intended for scanning networks the operator is authorized to scan; a description of the safety mechanisms (mandatory scope manifests, expiry, hard budgets, identifying User-Agent, no evasion features); and an explicit statement that detection-evasion and anonymization are **non-goals** and that feature requests for them will be declined.

- [ ] **Step 2: Write `CONTRIBUTING.md`**

Must contain the clean-room rule stated for contributors: do not submit code, probe strings, or fingerprint data derived from Nmap or any other project with incompatible licensing, and cite an RFC, vendor documentation, or a lab capture as the source for every new interpretation rule.

- [ ] **Step 3: Commit**

```bash
git add SECURITY.md CONTRIBUTING.md CODE_OF_CONDUCT.md .github
git commit -m "docs: security policy, contribution rules, and clean-room requirement"
```

**Acceptance criteria:**
- **AC-7.22** `SECURITY.md` names evasion and anonymization as explicit non-goals.
- **AC-7.23** `CONTRIBUTING.md` states the clean-room rule and requires a cited source for every new interpretation rule.
- **AC-7.24** A disclosure contact and response-time expectation are published.

---

### Task 6: Pre-publication gate

**Files:**
- Create: `xtask/src/publish_check.rs`
- Modify: `xtask/src/main.rs`

This task discharges the Pre-Publication Gates in the overview. Run it immediately before the repository is made public.

- [ ] **Step 1: Implement `xtask publish-check`**

```rust
/// Every check that must pass before this repository becomes public.
/// Each returns Err with an actionable message; none are advisory.
fn publish_check() -> Result<(), Box<dyn std::error::Error>> {
    let mut failures = Vec::new();

    // 1. No research artifacts. The saved Google Search page in the parent
    //    directory contains the owner's email, an inferred location, and a
    //    live session token. It must never be tracked.
    let tracked = git_ls_files()?;
    for f in &tracked {
        let l = f.to_lowercase();
        if l.contains("google search") || l.contains("fyodor") || l.ends_with(".html.orig") {
            failures.push(format!("research artifact tracked: {f}"));
        }
    }

    // 2. No secrets or personal identifiers.
    //
    // Generic patterns live here. Personal identifiers — the maintainer's own
    // email addresses, account handles, session-cookie names seen in local
    // research artifacts — go in `.publish-deny` , which is git-ignored so
    // that the checker never becomes the leak it exists to prevent.
    let mut patterns: Vec<String> = [
        "BEGIN RSA PRIVATE KEY",
        "BEGIN OPENSSH PRIVATE KEY",
        "BEGIN EC PRIVATE KEY",
        "AKIA",                 // AWS access key id prefix
        "ghp_", "gho_", "github_pat_",
        "xoxb-", "xoxp-",       // Slack
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    if let Ok(local) = std::fs::read_to_string(".publish-deny") {
        patterns.extend(
            local.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#'))
                 .map(str::to_owned),
        );
    }
    for pattern in &patterns {
        if let Some(hit) = grep_tracked(&tracked, pattern)? {
            failures.push(format!("`{pattern}` appears in {hit}"));
        }
    }

    // 3. No forbidden determinism claim. Lines carrying the `[phrase-rule]`
    //    marker state or enforce the rule itself and are exempt — see the
    //    overview's sentinel convention. Without this, the checker flags its
    //    own source.
    // Pattern is assembled so this source line does not itself contain the phrase.
    let phrase = concat!("deterministic", " ", "results");
    if let Some(hit) = grep_tracked_excluding_marked(&tracked, phrase)? {
        failures.push(format!("unscoped determinism claim in {hit}"));
    }

    // 4. No named individual in a comparative context.
    for name in ["Fyodor", "Gordon Lyon"] {
        if let Some(hit) = grep_tracked_docs(&tracked, name)? {
            failures.push(format!("`{name}` appears in documentation at {hit}; \
                                   positioning must compare tools, not people"));
        }
    }

    // 5. Placeholder repository URL not left in the manifests.
    if grep_tracked(&tracked, "github.com/OWNER/")?.is_some() {
        failures.push("placeholder `OWNER` remains in a manifest or user agent".into());
    }

    // 6. Licensing and dependency health.
    require_command_succeeds("cargo", &["deny", "check"], &mut failures);
    require_command_succeeds("cargo", &["test", "--workspace"], &mut failures);
    require_file_exists("LICENSE-APACHE", &mut failures);
    require_file_exists("LICENSE-MIT", &mut failures);
    require_file_exists("SECURITY.md", &mut failures);

    // 7. Every lab image pinned by digest.
    if std::fs::read_to_string("lab/docker-compose.yml")?.contains("image: ")
        && !all_images_digest_pinned("lab/docker-compose.yml")? {
        failures.push("lab image is not pinned by sha256 digest".into());
    }

    if failures.is_empty() { Ok(()) } else { Err(failures.join("\n").into()) }
}
```

- [ ] **Step 2: Write the test that the gate actually catches things**

```rust
#[test]
fn the_publish_gate_rejects_a_tracked_research_artifact() {
    let repo = fixture_repo_with_file("nmap fyodor - Google Search.html");
    assert!(publish_check_in(&repo).is_err());
}

#[test]
fn the_publish_gate_rejects_a_leftover_placeholder_owner() {
    let repo = fixture_repo_with_content("Cargo.toml", "repository = \"https://github.com/russell0/bathy\"");
    assert!(publish_check_in(&repo).is_err());
}

#[test]
fn the_publish_gate_rejects_an_unpinned_lab_image() {
    let repo = fixture_repo_with_content("lab/docker-compose.yml", "image: nginx:latest");
    assert!(publish_check_in(&repo).is_err());
}
```

- [ ] **Step 3: Run the gate** — `cargo run -p xtask -- publish-check`. Fix everything it reports.

- [ ] **Step 4: Confirm the name is available**

Before the first publish, verify `bathy` is free on crates.io, as a GitHub org or repo name, and as a domain. There is a plausible existing `bathy` crate in the DTrace/USDT space. If it is taken, rename now — the fallback order is `fathom` → `assay` → `reckon`, and the rename is a workspace-wide search-and-replace plus a `Cargo.toml` sweep. Renaming after publish breaks every existing link and install.

- [ ] **Step 5: Commit**

```bash
git add xtask
git commit -m "chore(xtask): publish-check gate for secrets, artifacts, licensing, and positioning"
```

**Acceptance criteria:**
- **AC-7.25** `xtask publish-check` fails when a research artifact is tracked, when any generic secret pattern (private keys, AWS/GitHub/Slack token prefixes) appears in tracked content, or when any pattern listed in the git-ignored `.publish-deny` file appears. Personal identifiers live only in `.publish-deny`, never in the checker's source — a leak-detector that hardcodes the thing it detects publishes it.
- **AC-7.26** It fails on the unscoped determinism phrase when unmarked, and passes over lines carrying the `[phrase-rule]` marker. Both directions tested. `[phrase-rule]`
- **AC-7.27** It fails when a named individual appears in `README.md` or `docs/`.
- **AC-7.28** It fails on a leftover `OWNER` placeholder.
- **AC-7.29** It fails on an unpinned lab image, a failing `cargo deny check`, a failing test suite, or a missing license or `SECURITY.md`.
- **AC-7.30** Three tests prove the gate actually rejects seeded violations rather than passing vacuously.
- **AC-7.31** Name availability on crates.io, GitHub, and DNS is confirmed and recorded before the first public push.

---

## Milestone Exit Criteria

- [ ] `cargo test --workspace` green; `lab/run.sh test` green; fuzz targets clean for 120s each.
- [ ] AC-7.1 through AC-7.31 each demonstrated by a named passing test or a recorded verification.
- [ ] `cargo run -p xtask -- publish-check` exits 0.
- [ ] `docs/benchmarks.md` published with real numbers, including at least one category bathy loses.
- [ ] README, SECURITY.md, CONTRIBUTING.md, design paper, platform support, and threat model all present.
- [ ] **Ready to publish.** Tag `v0.1.0`.
