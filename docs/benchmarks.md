# Benchmarks

What this project measures against the incumbents, on their own terms, and
where it comes off worse.

Two kinds of number live here and they answer different questions:

1. **A cross-scanner comparison** against the integration lab — bathy, Nmap,
   Masscan and RustScan, given the same addresses, the same ports, the same
   per-connection timeout and the same rate ceiling, in one run on one machine.
   Speed is reported *beside* accuracy, because a scanner that is faster and
   wrong is not faster.
2. **Criterion micro-benchmarks** over the parts this project controls:
   `interpret`, canonical JSON, plan construction and event-log append. Those
   are regression detectors, not marketing numbers, and they are described at
   the end.

Everything in the generated block below came from one execution of
`bench/compare.sh`. Nothing in it was typed by hand.

## How to reproduce it

```
lab/run.sh up
bench/compare.sh
```

`bench/compare.sh` brings the lab up, works out whether this host can route to
the lab's bridge network, and runs every scanner it can find — here if it can,
otherwise inside one Linux container attached to `labnet`. On macOS it is
always the container: Docker Desktop keeps the daemon in a VM whose bridges the
Mac's routing table never learns, so neither a Mac-built binary nor a
Mac-installed scanner can see the lab at all. That is a platform fact
established in M7 Task 1, not a choice made here.

**This does not run in CI, and that is deliberate.** Bringing the lab up pulls
about 2.8 GiB of digest-pinned images, and a wall-clock measurement taken on a
shared, oversubscribed runner is not a measurement. `cargo run -p xtask --
check-bench` *does* run in CI: it reads the committed `bench/results.json`, re-
renders the block below from it, and fails if the two have drifted apart — so
the published numbers cannot quietly stop being the numbers the run produced.

## What makes this a measurement rather than an anecdote

- **One lab, one port set, one timeout, one rate ceiling, one machine, one
  run.** The addresses and ports come from `lab/ground-truth.json` and the rate
  ceiling from `lab/scope.json`; every tool's argument vector is built from
  those same values by one function, and a unit test asserts that each tool was
  given them (`every_scanner_is_asked_about_exactly_the_same_ports`).
- **The timeout is read out of the scanner, not typed twice.** bathy's
  per-connection timeout is `SchedulerConfig::default`'s `connect_timeout` and
  is not exposed as a flag, so `xtask` reads the literal out of
  `crates/bathy-engine/src/scheduler.rs` and gives every other tool the same
  ceiling. If that default ever moves, `check-bench` fails and says the
  published run is stale — which it would be: every timing here was taken at
  the old ceiling.
- **Accuracy is scored against the lab, never against another scanner.**
  `lab/ground-truth.json` was derived by sweeping all 65535 TCP ports on every
  lab address from inside `labnet`, with a Python standard-library script that
  shares no code, no port table and no fingerprint data with any scanner here.
  Scoring one tool against another's output would make the more thorough tool
  look wrong and would make our own blind spots invisible by construction.
- **The narrowing controls are part of the target set.** Two of the scanned
  addresses have no host on them, one host answers on no port at all, port 22
  is shut on every host in the lab and is scanned anyway, and `tls-web` serves
  443 while `web-nginx` serves 80. A scanner that reported everything it
  touched as open scores badly here rather than perfectly.
- **Where a tool needs privilege it cannot have, the table says so** instead of
  comparing its unprivileged fallback against our connect scan as though they
  were the same operation. Masscan and Nmap's `-sS` both need raw sockets;
  bathy's only mode is an unprivileged connect scan, and those are different
  operations, not fast and slow versions of one.
- **Every tool that is not installed gets a row saying so**, with the command
  that would make it present. A reader must not be able to mistake a
  two-scanner comparison for a four-scanner one.

### Where each tool is configured away from its own defaults, and why

| Tool | Flag | Why |
|---|---|---|
| bathy | `--no-service-detection` | Only on the `bathy-ports-only` row, and it exists for fairness rather than for speed: `nmap -sT` performs port discovery and nothing else, so comparing it against bathy's default — which identifies services on every open port — would charge us for work the other tool was not asked to do. Both rows are published. |
| Nmap | `-Pn` | bathy performs no host discovery in v0.1 (unprivileged ICMP is impossible; it ships with `packetd`). Without `-Pn`, Nmap would solve a strictly harder problem and be charged for it. |
| Nmap | `-n` | bathy performs no reverse DNS. With resolution on, Nmap's wall clock would include lookups against addresses that have no PTR record. |
| Nmap | `--max-rtt-timeout` | Set to bathy's own fixed per-connection timeout, so neither tool is waiting longer than the other on the two addresses with no host. |
| Nmap, Masscan | `--max-rate` / `--rate` | Set to the rate ceiling `lab/scope.json` authorizes. No tool came close to it; the flag equalises the ceiling rather than the behaviour. |
| Masscan | `--wait` | Whole seconds, rounded **up** from the shared timeout. Rounding down would stop it listening while the other tools were still waiting. |
| RustScan | `-t` | Its per-connection timeout, in milliseconds, set to the shared value. |

Nmap is run three ways, because it is three different operations: `-sT` is the
one bathy performs, `-sS` is what Nmap itself does when it has privilege, and
`-sT -sV` is the one that attempts identification. Collapsing them into a
single row would have meant choosing which comparison to publish.

## The clean-room boundary

Running Nmap here is legitimate and is the only place in this project where it
is: it is a benchmark subject, and timing it is not deriving from its data.
Everything else about the rule is unchanged.

- No `nmap-service-probes`, `nmap-services` or `nmap-os-db` has been read.
- **No rule, probe or port list in this repository has been authored, corrected
  or tuned from Nmap's output.** Where Nmap identified something bathy did not,
  the miss is recorded as a miss below; we did not go and look at why.
- The XML parser that reads Nmap's results was written from the documented
  shape of `-oX` output, and its test fixture is synthetic — not one captured
  Nmap run is checked into this repository.

Installing Nmap necessarily puts its data files on the disk of whatever machine
runs this. That is unavoidable and is not the boundary; reading them is, and
they were not read.

<!-- BEGIN GENERATED: cargo run -p xtask -- bench-compare -->

*Everything between these markers is rendered from `bench/results.json` by `cargo run -p xtask -- bench-compare`. `check-bench` re-renders it in CI and fails on drift, so these numbers cannot quietly stop being the ones the run produced.*

## The run

| | |
|---|---|
| Observed at | 2026-08-04T21:34:46Z |
| Host | Linux aarch64 |
| Scanners ran in | a rust:1-bookworm container attached to bathy-lab_labnet (this host cannot route to it) |
| Raw-socket privilege there | yes (CAP_NET_RAW) |
| Repetitions per tool | 5 |
| Targets | 10.30.0.10, 10.30.0.11, 10.30.0.12, 10.30.0.13, 10.30.0.14, 10.30.0.15, 10.30.0.16, 10.30.0.17, 10.30.0.18, 10.30.0.200, 10.30.0.201 |
| Ports | 22, 25, 53, 80, 443, 587, 853, 2222, 3306, 5432, 6379, 8080, 33060 |
| Per-connection timeout | 2000 ms — `SchedulerConfig::default`'s `connect_timeout` in `crates/bathy-engine/src/scheduler.rs`, read rather than restated; bathy does not expose it as a flag, so every other tool is given the same ceiling |
| Rate ceiling | 100000 pps — `budget_ceiling.maximum_packets_per_second` in `lab/scope.json` — the ceiling the lab's own manifest authorizes, given to every tool that has a rate knob |

## The tools, and which of them ran (AC-7.13)

| Scanner | Status | Version | If absent, what makes it present |
|---|---|---|---|
| `bathy` | **ran** | bathy 0.1.0-alpha.1 (`/w/target/bench/release/bathy`) | — |
| `nmap` | **ran** | Nmap version 7.93 ( https://nmap.org ) (`/usr/bin/nmap`) | — |
| `masscan` | **NOT RUN — not installed** | — | `BENCH_APT_PACKAGES="nmap masscan" bench/compare.sh (Debian packages it; nothing here installs it for you)` |
| `rustscan` | **NOT RUN — not installed** | — | `no Debian package exists; put a Linux rustscan binary in bench/tools/, which bench/compare.sh prepends to PATH` |

## Command lines, verbatim (AC-7.13)

**bathy-ports-only** — TCP connect scan, service detection off (--no-service-detection)

```
bathy --json --state-dir /tmp/bathy-bench-404 scan start --scope lab/scope.json --idempotency-key bench --targets 10.30.0.10,10.30.0.11,10.30.0.12,10.30.0.13,10.30.0.14,10.30.0.15,10.30.0.16,10.30.0.17,10.30.0.18,10.30.0.200,10.30.0.201 --ports 22,25,53,80,443,587,853,2222,3306,5432,6379,8080,33060 --max-packets-per-second 100000 --no-service-detection
bathy --json --state-dir /tmp/bathy-bench-404 result query --scan $SCAN_ID
```
**bathy-connect** — TCP connect scan with service detection (bathy's default)

```
bathy --json --state-dir /tmp/bathy-bench-404 scan start --scope lab/scope.json --idempotency-key bench --targets 10.30.0.10,10.30.0.11,10.30.0.12,10.30.0.13,10.30.0.14,10.30.0.15,10.30.0.16,10.30.0.17,10.30.0.18,10.30.0.200,10.30.0.201 --ports 22,25,53,80,443,587,853,2222,3306,5432,6379,8080,33060 --max-packets-per-second 100000
bathy --json --state-dir /tmp/bathy-bench-404 result query --scan $SCAN_ID
```
**nmap-connect** — TCP connect scan (-sT), no version detection

```
nmap -n -Pn -sT -p 22,25,53,80,443,587,853,2222,3306,5432,6379,8080,33060 --max-rtt-timeout 2000ms --max-rate 100000 -oX - 10.30.0.10 10.30.0.11 10.30.0.12 10.30.0.13 10.30.0.14 10.30.0.15 10.30.0.16 10.30.0.17 10.30.0.18 10.30.0.200 10.30.0.201
```
**nmap-syn** — SYN scan (-sS) — Nmap's own default when privileged

```
nmap -n -Pn -sS -p 22,25,53,80,443,587,853,2222,3306,5432,6379,8080,33060 --max-rtt-timeout 2000ms --max-rate 100000 -oX - 10.30.0.10 10.30.0.11 10.30.0.12 10.30.0.13 10.30.0.14 10.30.0.15 10.30.0.16 10.30.0.17 10.30.0.18 10.30.0.200 10.30.0.201
```
*Privilege: this operation needs raw sockets and had them (running as uid 0 with CAP_NET_RAW). bathy's own scan is an unprivileged connect scan, so this row is a different operation, not a faster version of the same one.*

**nmap-version** — TCP connect scan with version detection (-sT -sV)

```
nmap -n -Pn -sT -sV -p 22,25,53,80,443,587,853,2222,3306,5432,6379,8080,33060 --max-rtt-timeout 2000ms --max-rate 100000 -oX - 10.30.0.10 10.30.0.11 10.30.0.12 10.30.0.13 10.30.0.14 10.30.0.15 10.30.0.16 10.30.0.17 10.30.0.18 10.30.0.200 10.30.0.201
```
**masscan-syn** — SYN scan; masscan has no connect mode and no version detection

```
masscan -p22,25,53,80,443,587,853,2222,3306,5432,6379,8080,33060 --rate 100000 --wait 2 -oL - 10.30.0.10 10.30.0.11 10.30.0.12 10.30.0.13 10.30.0.14 10.30.0.15 10.30.0.16 10.30.0.17 10.30.0.18 10.30.0.200 10.30.0.201
```
*Not run: `masscan` is not installed on this machine, so this row is empty rather than absent from the table*

*Privilege: this operation needs raw sockets and had them (running as uid 0 with CAP_NET_RAW). bathy's own scan is an unprivileged connect scan, so this row is a different operation, not a faster version of the same one.*

**rustscan-connect** — TCP connect scan, no version detection of its own

```
rustscan --greppable --no-config -a 10.30.0.10,10.30.0.11,10.30.0.12,10.30.0.13,10.30.0.14,10.30.0.15,10.30.0.16,10.30.0.17,10.30.0.18,10.30.0.200,10.30.0.201 -p 22,25,53,80,443,587,853,2222,3306,5432,6379,8080,33060 -t 2000
```
*Not run: `rustscan` is not installed on this machine, so this row is empty rather than absent from the table*

## Speed and accuracy, side by side (AC-7.11, AC-7.12)

Accuracy is scored against `lab/ground-truth.json`, which was derived from a 65535-port sweep run inside the lab network by a program sharing no code with any scanner here. No tool is scored against another tool's output.

Timings are the median and the observed range over every repetition. Accuracy is scored from the **final** repetition of each run — a scanner whose answer changes between runs is a finding, and folding several answers into one would hide it. `TCP opens` is the `Tcp: ActiveOpens` delta the kernel counted during that final repetition, so a SYN scan reads zero: it emits no connection at all.

| Run | Median | Min–max | Open found | False neg | False pos | Products named | Versions named | TCP opens |
|---|---|---|---|---|---|---|---|---|
| `bathy-ports-only` | 2063 ms | 2047–2072 ms | 12/12 | 0 | 0 | n/a (no identification) | n/a | 143 |
| `bathy-connect` | 26285 ms | 26265–26978 ms | 12/12 | 0 | 0 | 5/6 | 3/4 | 159 |
| `nmap-connect` | 1475 ms | 1466–1485 ms | 12/12 | 0 | 0 | n/a (no identification) | n/a | 170 |
| `nmap-syn` | 1375 ms | 1359–1390 ms | 12/12 | 0 | 0 | n/a (no identification) | n/a | 0 |
| `nmap-version` | 17819 ms | 17754–139145 ms | 12/12 | 0 | 0 | 5/6 | 3/4 | 294 |
| `masscan-syn` | **not run** | — | — | — | — | — | — | — |
| `rustscan-connect` | **not run** | — | — | — | — | — | — | — |

## Where bathy loses (AC-7.14)

- **wall clock** — bathy-ports-only (TCP connect scan, service detection off (--no-service-detection)) took 2063 ms; nmap-connect (TCP connect scan (-sT), no version detection) took 1475 ms — 1.4x.
- **wall clock** — bathy-ports-only (TCP connect scan, service detection off (--no-service-detection)) took 2063 ms; nmap-syn (SYN scan (-sS) — Nmap's own default when privileged) took 1375 ms — 1.5x.
- **wall clock** — bathy-connect (TCP connect scan with service detection (bathy's default)) took 26285 ms; nmap-connect (TCP connect scan (-sT), no version detection) took 1475 ms — 17.8x.
- **wall clock** — bathy-connect (TCP connect scan with service detection (bathy's default)) took 26285 ms; nmap-syn (SYN scan (-sS) — Nmap's own default when privileged) took 1375 ms — 19.1x.
- **wall clock** — bathy-connect (TCP connect scan with service detection (bathy's default)) took 26285 ms; nmap-version (TCP connect scan with version detection (-sT -sV)) took 17819 ms — 1.5x.
- **service identification, per endpoint** — nmap-version named the lab's product at 10.30.0.17:443 and bathy-connect did not.
- **identification gap recorded by the lab** — 10.30.0.17:443 — bathy reports no product here, and this entry records what is on the wire rather than what bathy finds.

<!-- END GENERATED -->

## Reading the results

**On speed, bathy loses, and the size of the loss depends entirely on which
comparison you make.** Against the same operation — port discovery with no
identification — it is about 1.4x slower than Nmap's connect scan and 1.5x
slower than its SYN scan. Against the whole default operation, with
identification on, it is 1.5x slower than `nmap -sV`. The 17.8x figure in the
loss list is real but is not like for like: it compares bathy's default, which
identifies services, against a bare Nmap port sweep that does not. Both
framings are published, with both operations named in each row, because
publishing only the favourable one is the thing this document exists not to do.

The ratio worth keeping is the third one. Service detection costs bathy about
24 seconds on this lab and Nmap about 16, on twelve open ports. Neither tool is
fast at it; the difference between them is smaller than the difference between
doing it and not.

**On service identification, the aggregate is a tie and the aggregate is
misleading.** Both `bathy-connect` and `nmap-version` named five of the six
products the lab establishes — *and they were not the same five*. bathy named
MySQL on `10.30.0.13:3306`, which Nmap did not. Nmap named nginx on
`10.30.0.17:443`, which bathy did not. That is why the loss list reports
identification per endpoint as well as in total: a count of five against five
would have hidden the single most concrete identification loss this project
has.

That loss is the one the lab already recorded before any competitor ran, and it
is structural rather than a missing rule. `Scheduler::detect_service` stops at
the first probe whose capture interprets to anything; on 443 that is `tls-v1`,
which is protocol-only by construction because RFC 8446 encrypts the
certificate, so `http-get-v1` never runs — even though `http.server.nginx.v1`
matches those exact bytes and would name the product outright. Changing that
policy changes per-endpoint packet accounting (AC-4.24), pacing (AC-4.26) and
the reported service for every TLS port, so it is a scanner change and not a
fix-round edit. `lab/ground-truth.json` holds that endpoint to being
unidentified today, so the day bathy names it the conformance suite fails and
demands the gap be deleted.

**Do not read the tie as parity.** Service-identification breadth is the
largest gap between this project and a mature scanner and it is not close. Nmap
has 28 years of community fingerprint contributions; bathy v0.1 has eight
protocols and thirteen interpretation rules. The lab is a nine-service network
built to exercise exactly those thirteen rules, which flatters us enormously —
on an arbitrary network the ratio would be far worse, and no number in this
document should be read as evidence otherwise. The one number here that does
generalise is the count of protocols, and it is eight.

**On accuracy, every tool that ran was exactly right**: twelve of twelve
known-open ports found, no false positives, including on the two addresses with
no host and the one host that answers on nothing. That is the expected result
on a nine-service lab with no packet loss, and it is reported because it is what
happened, not because it distinguishes anything.

The `TCP opens` column is the kernel's own `Tcp: ActiveOpens` counter, and it
says something the wall clock does not: bathy's port-discovery scan opens
exactly 143 connections, one per plan unit, with none left over. `nmap-syn`
opens zero, because a SYN scan never completes a connection — which is the
clearest available statement that it is not the same operation.

## Threats to validity

- **A nine-service lab is not a network.** Every service here is one bathy has
  a probe for. The comparison measures correctness on a fixture, not coverage
  in the wild.
- **Wall clock on a laptop is noisy.** Each tool is run five times and the
  table reports the median with the observed range; the range is the honest
  part. A single run would not have been a measurement at all.
- **`nmap-version`'s range spans an order of magnitude and is not explained
  here.** Two of its five repetitions took about 139 seconds against a median
  of about 17.8. The effect reproduced across three separate whole-benchmark
  executions and always on a repetition after the first. Two candidate causes
  were noted and neither was confirmed: Nmap's own retry behaviour, or a lab
  service rate-limiting a repeated version scan — Postfix and MySQL both do
  that, and `nmap-version` opens 294 connections per run, more than any other
  tool here. If it is the second, this benchmark's own repetition penalises the
  tool that connects most, which is a reason to read the median rather than the
  range for that row. It is recorded rather than smoothed away.
- **The ARP cache is part of the measurement.** The two absent addresses are
  resolved by ARP, and a run whose negative entry is still cached finishes far
  faster than one that has to time out. An earlier execution of this same
  harness, with cold ARP state, saw `bathy-ports-only` range from 241 ms to
  2887 ms across three repetitions; the published range is much tighter because
  by then the state was warm. Both are real; neither is "the" number.
- **A container on a bridge network has no loss and no latency.** Every timeout
  in the comparison is therefore reached only by the two addresses with no
  host. On a real network, retry policy would matter and the tools differ in
  it; that difference is invisible here.
- **The two SYN variants are not the same operation as ours.** They are in the
  table because leaving Nmap's own default mode out would be its own kind of
  dishonesty, not because bathy is being compared to them like for like.
- **This is the project's own benchmark of its own competitors.** The defence
  against that is not a promise; it is that the oracle is independent of every
  tool measured, the harness is unit-tested, the command lines are published
  verbatim, and the losses are computed from the results rather than chosen.

## The criterion micro-benchmarks (AC-7.15)

Four subjects, in the crate that owns each:

| Subject | File | What it measures |
|---|---|---|
| `interpret` | `crates/bathy-interpret/benches/interpret.rs` | The whole committed replay corpus, and the single largest response on its own. |
| `canonical_json` | `crates/bathy-types/benches/canonical_json.rs` | RFC 8785 canonicalization of a plan document, including one with its keys in reverse order, plus the BLAKE3 digest built on it. |
| plan construction | `crates/bathy-plan/benches/plan_construction.rs` | The lab's own shape, a `/24`, a `/16`, and `plan_hash` on its own. |
| log append | `crates/bathy-evidence/benches/log_append.rs` | `EventLog::append` with and without the durability barrier — the ratio is the number that matters. |

```
cargo bench -p bathy-interpret
cargo bench --workspace
```

They are deliberately *not* performance gates. A wall-clock threshold on a
shared runner is a flaky test, and a flaky test is a test people learn to
ignore. What CI does enforce is that they still build and still run:
`cargo clippy --workspace --all-targets` compiles them and
`cargo test --workspace --benches` executes each one once in criterion's
`--test` mode, so a benchmark that stops compiling — or that builds and then
panics, which the `interpret` one would if the corpus it reads off disk moved —
turns the build red. `check-bench` fails if that step disappears from the
workflow, if one of the four files disappears, or if a `[[bench]]` stanza loses
`harness = false`.

Plain `cargo test --workspace` does **not** reach them, and this document said
it did until the claim was checked: Cargo's default target selection for `test`
is lib, bins, tests and examples, and bench targets are not in it. That is why
there is a separate step and why a check now asserts it exists.

The plan filed these under `benches/lab_scan.rs` at the repository root. That
path cannot work: the workspace manifest is virtual, so a root `benches/`
directory belongs to no package and is never compiled by anything. It is
recorded as a plan defect in the task report along with the reason the
benchmarks live one per owning crate instead.
