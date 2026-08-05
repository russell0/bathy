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
BENCH_APT_PACKAGES="nmap masscan libpcap0.8" bench/compare.sh
```

Plain `bench/compare.sh` runs whatever is installed and gives every absent tool
a named **NOT RUN** row. The two environment hooks above are what make the run
a four-scanner one, and neither is a code change:

- **`BENCH_APT_PACKAGES`** replaces — does not extend — the packages installed
  in the runner container. `libpcap0.8` is named explicitly because Debian's
  `masscan` package declares `Depends: libc6` and nothing else while masscan
  `dlopen`s libpcap at run time: install `masscan` alone and it starts and then
  dies with `can't open adapter: libpcap not loaded`. Co-installing `nmap`
  happens to satisfy it, and an instruction that works only by accident of
  another package on the same line is one worth spelling out.
- **`bench/tools/`** is prepended to `PATH` inside the runner. RustScan has no
  Debian package, so the row is filled by dropping a Linux `rustscan` there.
  The one measured below was built with
  `cargo install rustscan --version 2.3.0 --locked` inside the same
  `rust:1-bookworm` image the runner uses.

A scanner installed on the **macOS host** takes no part in any of this, and
that is not a subtlety worth burying: the comparison executes inside a Linux
container, so a Homebrew `masscan` or `rustscan` on the Mac's `PATH` is both
the wrong operating system and on the wrong side of a network boundary the Mac
cannot cross. The binaries have to be Linux binaries of the runner's
architecture, reachable from inside the container.

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
| Nmap, Masscan | `--max-rate` / `--rate` | Set to the rate ceiling `lab/scope.json` authorizes: 100,000 pps. See below — the choice was measured, not asserted. |
| Masscan | `--wait` | Whole seconds, rounded **up** from the shared timeout. Rounding down would stop it listening while the other tools were still waiting. |
| RustScan | `-t` | Its per-connection timeout, in milliseconds, set to the shared value. |
| RustScan | `--greppable` | RustScan's *default* behaviour is to hand the ports it finds to Nmap for version detection. `--greppable` suppresses that, which is both what makes it a port-discovery row comparable to `nmap -sT` and what keeps the clean-room boundary intact: no Nmap data file is consulted through it. |
| RustScan | `--no-config` | Otherwise it would read `~/.rustscan.toml` and the published command line would stop being the whole input. |

#### The rate ceiling, and why 100,000 pps is fair to Masscan

Masscan's defaults are built to saturate a link, so an arbitrary rate would
make its number meaningless in one direction or the other. The rate here is not
chosen by this document at all: it is read out of `lab/scope.json`'s
`budget_ceiling.maximum_packets_per_second`, the ceiling the lab's own
authorization manifest grants, and it is handed identically to `nmap
--max-rate`, `masscan --rate` and `bathy --max-packets-per-second`.

That it is *fair* is a separate claim, and it was measured rather than assumed.
Sweeping Masscan's rate over four orders of magnitude against this lab, holding
everything else at the published values:

| `--rate` | Wall clock | Open ports found |
|---|---|---|
| 100 | 6502 ms | 12 |
| 1,000 | 5522 ms | 12 |
| 10,000 | 3998 ms | 12 |
| 100,000 | 4019 ms | 12 |

The curve is flat by 10,000 pps and the published ceiling sits well past the
knee, so the rate is not throttling Masscan below its natural speed on this
workload and no higher number could help it: the whole scan is 11 addresses ×
13 ports = 143 packets, which at the ceiling is under two milliseconds of
transmission. The same run with `--wait 0` finishes in 1680 ms against 4019 ms
with the mandated `--wait 2`, which locates the rest of Masscan's wall clock
where it actually is — a fixed listening window, not throughput. These figures
are a side experiment run in the same image on the same lab, not part of the
published run, and they were taken sequentially rather than repeated five
times.

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

RustScan needs one extra sentence, because it reaches Nmap by default: given no
flags it performs port discovery itself and then hands the open ports to
`nmap -sV`. The measured command passes `--greppable`, which stops it before
that hand-off. So the `rustscan-connect` row is RustScan's own port discovery
and nothing else, no Nmap data file is consulted through it, and its
identification columns read `n/a` rather than borrowing Nmap's answers.

<!-- BEGIN GENERATED: cargo run -p xtask -- bench-compare -->

*Everything between these markers is rendered from `bench/results.json` by `cargo run -p xtask -- bench-compare`. `check-bench` re-renders it in CI and fails on drift, so these numbers cannot quietly stop being the ones the run produced.*

## The run

| | |
|---|---|
| Observed at | 2026-08-05T16:28:23Z |
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
| `masscan` | **ran** | Masscan version 1.3.2 ( https://github.com/robertdavidgraham/masscan ) (`/usr/bin/masscan`) | — |
| `rustscan` | **ran** | rustscan 2.3.0 (`/w/bench/tools/rustscan`) | — |

## Command lines, verbatim (AC-7.13)

**bathy-ports-only** — TCP connect scan, service detection off (--no-service-detection)

```
bathy --json --state-dir /tmp/bathy-bench-415 scan start --scope lab/scope.json --idempotency-key bench --targets 10.30.0.10,10.30.0.11,10.30.0.12,10.30.0.13,10.30.0.14,10.30.0.15,10.30.0.16,10.30.0.17,10.30.0.18,10.30.0.200,10.30.0.201 --ports 22,25,53,80,443,587,853,2222,3306,5432,6379,8080,33060 --max-packets-per-second 100000 --no-service-detection
bathy --json --state-dir /tmp/bathy-bench-415 result query --scan $SCAN_ID
```
**bathy-connect** — TCP connect scan with service detection (bathy's default)

```
bathy --json --state-dir /tmp/bathy-bench-415 scan start --scope lab/scope.json --idempotency-key bench --targets 10.30.0.10,10.30.0.11,10.30.0.12,10.30.0.13,10.30.0.14,10.30.0.15,10.30.0.16,10.30.0.17,10.30.0.18,10.30.0.200,10.30.0.201 --ports 22,25,53,80,443,587,853,2222,3306,5432,6379,8080,33060 --max-packets-per-second 100000
bathy --json --state-dir /tmp/bathy-bench-415 result query --scan $SCAN_ID
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
*Privilege: this operation needs raw sockets and had them (running as uid 0 with CAP_NET_RAW). bathy's own scan is an unprivileged connect scan, so this row is a different operation, not a faster version of the same one.*

**rustscan-connect** — TCP connect scan, no version detection of its own

```
rustscan --greppable --no-config -a 10.30.0.10,10.30.0.11,10.30.0.12,10.30.0.13,10.30.0.14,10.30.0.15,10.30.0.16,10.30.0.17,10.30.0.18,10.30.0.200,10.30.0.201 -p 22,25,53,80,443,587,853,2222,3306,5432,6379,8080,33060 -t 2000
```
## Speed and accuracy, side by side (AC-7.11, AC-7.12)

Accuracy is scored against `lab/ground-truth.json`, which was derived from a 65535-port sweep run inside the lab network by a program sharing no code with any scanner here. No tool is scored against another tool's output.

Timings are the median and the observed range over every repetition. Accuracy is scored from the **final** repetition of each run — a scanner whose answer changes between runs is a finding, and folding several answers into one would hide it. `TCP opens` is the `Tcp: ActiveOpens` delta the kernel counted during that final repetition, so a SYN scan reads zero: it emits no connection at all.

| Run | Median | Min–max | Open found | False neg | False pos | Products named | Versions named | TCP opens |
|---|---|---|---|---|---|---|---|---|
| `bathy-ports-only` | 2105 ms | 993–2353 ms | 12/12 | 0 | 0 | n/a (no identification) | n/a | 143 |
| `bathy-connect` | 26315 ms | 26303–38025 ms | 12/12 | 0 | 0 | 5/6 | 3/4 | 159 |
| `nmap-connect` | 1473 ms | 1467–2376 ms | 12/12 | 0 | 0 | n/a (no identification) | n/a | 170 |
| `nmap-syn` | 1355 ms | 1320–1389 ms | 12/12 | 0 | 0 | n/a (no identification) | n/a | 0 |
| `nmap-version` | 17790 ms | 17784–17952 ms | 12/12 | 0 | 0 | 5/6 | 3/4 | 294 |
| `masscan-syn` | 3690 ms | 3430–3723 ms | 12/12 | 0 | 0 | n/a (no identification) | n/a | 0 |
| `rustscan-connect` | 2053 ms | 1013–2076 ms | 12/12 | 0 | 0 | n/a (no identification) | n/a | 143 |

## Where bathy loses (AC-7.14)

- **wall clock** — bathy-ports-only (TCP connect scan, service detection off (--no-service-detection)) took 2105 ms; nmap-connect (TCP connect scan (-sT), no version detection) took 1473 ms — 1.4x.
- **wall clock** — bathy-ports-only (TCP connect scan, service detection off (--no-service-detection)) took 2105 ms; nmap-syn (SYN scan (-sS) — Nmap's own default when privileged) took 1355 ms — 1.6x.
- **wall clock** — bathy-ports-only (TCP connect scan, service detection off (--no-service-detection)) took 2105 ms; rustscan-connect (TCP connect scan, no version detection of its own) took 2053 ms — 1.0x.
- **wall clock** — bathy-connect (TCP connect scan with service detection (bathy's default)) took 26315 ms; nmap-connect (TCP connect scan (-sT), no version detection) took 1473 ms — 17.9x.
- **wall clock** — bathy-connect (TCP connect scan with service detection (bathy's default)) took 26315 ms; nmap-syn (SYN scan (-sS) — Nmap's own default when privileged) took 1355 ms — 19.4x.
- **wall clock** — bathy-connect (TCP connect scan with service detection (bathy's default)) took 26315 ms; nmap-version (TCP connect scan with version detection (-sT -sV)) took 17790 ms — 1.5x.
- **service identification, per endpoint** — nmap-version named the lab's product at 10.30.0.17:443 and bathy-connect did not.
- **wall clock** — bathy-connect (TCP connect scan with service detection (bathy's default)) took 26315 ms; masscan-syn (SYN scan; masscan has no connect mode and no version detection) took 3690 ms — 7.1x.
- **wall clock** — bathy-connect (TCP connect scan with service detection (bathy's default)) took 26315 ms; rustscan-connect (TCP connect scan, no version detection of its own) took 2053 ms — 12.8x.
- **identification gap recorded by the lab** — 10.30.0.17:443 — bathy reports no product here, and this entry records what is on the wire rather than what bathy finds.

<!-- END GENERATED -->

## Reading the results

**On speed, bathy loses to every other scanner here, and the size of the loss
depends entirely on which comparison you make.** Against the same operation —
port discovery with no identification — it is about 1.4x slower than Nmap's
connect scan, 1.6x slower than its SYN scan, and 1.0x against RustScan, which
is a tie the loss list still prints as a loss because the median came out on
the wrong side of it. Against the whole default operation, with identification
on, it is 1.5x slower than `nmap -sV`. The 17.9x, 19.4x, 12.8x and 7.1x figures
in the loss list are real but are not like for like: they compare bathy's
default, which identifies services on every open port, against bare port sweeps
that do not. Every framing is published, with both operations named in each
row, because publishing only the favourable one is the thing this document
exists not to do.

The ratio worth keeping is the `bathy-connect` against `nmap-version` one.
Service detection costs bathy about 24 seconds on this lab and Nmap about 16,
on twelve open ports. Neither tool is fast at it; the difference between them is
smaller than the difference between doing it and not.

**Masscan's row is the one most likely to be misread, so read it carefully: it
is not a win.** `masscan-syn` took 3690 ms against `bathy-ports-only`'s
2105 ms, and that ordering says nothing whatever about Masscan being slower
than bathy. Masscan is designed to sweep the routable Internet, and its wall
clock on a nine-container lab is almost entirely fixed cost: the scan is 143
packets, under two milliseconds of transmission at the ceiling, and the run
drops to 1680 ms the moment its mandated `--wait 2` listening window is removed
(see the rate table above). What is left is startup, adapter open, ARP and
teardown. **This benchmark has no way to measure the thing Masscan is good at.**
A fair statement of the result is that on a target set this small every tool
here is measuring its own overhead, and the only reason Masscan appears behind
is that its overhead is amortised over a workload six orders of magnitude
larger than the one it was given. Anybody quoting this row as evidence about
Masscan's throughput is quoting it wrongly, and that includes us.

**RustScan is bimodal and the median lands on the slow mode.** Its five
repetitions were 1013, 1031, 2053, 2059 and 2076 ms, and the same split
appeared in an earlier whole-benchmark execution on the same day. Roughly half
its runs finish in about a second and half in about two; the published median,
2053 ms, is therefore a real number that no single run is especially likely to
reproduce. The cause was not investigated — it is a competitor's scheduling
behaviour, not ours, and guessing at it here would be worth less than saying
plainly that the spread is there.

**On service identification, only two of the four scanners compete at all.**
Masscan has no version detection and RustScan's own has been suppressed with
`--greppable`, because RustScan implements it by shelling out to Nmap and a
row that is Nmap wearing a different name is not a fourth data point. Both are
marked `n/a (no identification)` rather than `0/6`: a tool that did not try is
not a tool that failed.

Between the two that do try, **the aggregate is a tie and the aggregate is
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
exactly 143 connections, one per plan unit, with none left over — and so does
RustScan, which is the strongest available evidence that those two rows really
are the same operation. `nmap-connect` opens 170 for the same 143 units and
`nmap-version` 294. Both SYN rows, `nmap-syn` and `masscan-syn`, open zero,
because a SYN scan never completes a connection — which is the clearest
available statement that they are not the same operation as ours, whatever
their wall clocks say.

## Threats to validity

- **A nine-service lab is not a network.** Every service here is one bathy has
  a probe for. The comparison measures correctness on a fixture, not coverage
  in the wild.
- **Wall clock on a laptop is noisy.** Each tool is run five times and the
  table reports the median with the observed range; the range is the honest
  part. A single run would not have been a measurement at all.
- **The published table is one execution, and a second one was run to see how
  much that matters.** Two complete four-scanner executions were taken about
  half an hour apart on the same machine against the same lab. The medians
  agreed to within 2% on five of the seven rows — `bathy-ports-only` 2069 →
  2105 ms, `bathy-connect` 26212 → 26315, `nmap-connect` 1458 → 1473,
  `nmap-syn` 1334 → 1355, `masscan-syn` 3712 → 3690, `rustscan-connect` 2043 →
  2053 — and the accuracy columns were byte-identical, down to which five of
  the six products each identifying tool named. The exception is
  `nmap-version`, below. Only the second execution is published; the first is
  not in the tree, so this bullet is a statement you are taking on trust, which
  is why the numbers are quoted rather than summarised.
- **`nmap-version` is the row that moves, and it moves enough to change a
  published ratio.** In the first execution three of its five repetitions took
  about 23.7 s and two about 17.8 s, putting the median at 23740 ms. In the
  published execution all five landed in the fast mode, 17784–17952 ms, putting
  it at 17790. That is the only row whose two medians disagree by more than 2%,
  and it moves the `bathy-connect` against `nmap-version` ratio from 1.1x to
  1.5x. The 1.5x in the loss list is the published run's number and is the less
  flattering of the two, which is the only reason it is safe to leave the
  choice to whichever run happened to be last.
- **An earlier, larger `nmap-version` outlier did not reproduce and is recorded
  as unexplained.** Before Masscan and RustScan were installed, two of five
  repetitions took about 139 seconds, and that was described here as having
  reproduced across three separate whole-benchmark executions. It appeared in
  neither execution taken today, whose slowest `nmap-version` repetition was
  23.7 s. Nothing in this harness changed that would explain the difference.
  The earlier candidate causes — Nmap's own retry behaviour, or a lab service
  rate-limiting a repeated version scan, `nmap-version` being the row that
  opens the most connections at 294 — were never confirmed and are not
  confirmed now. An effect that appears in three executions and then vanishes
  from two is a reason to distrust this row's tail, not a reason to delete the
  paragraph.
- **RustScan's spread is bimodal too and is not noise.** Its runs split cleanly
  into an approximately 1.0 s mode and an approximately 2.05 s mode, in both
  executions, with the median landing on the slow one. The published median is
  not the value a single run is most likely to produce; the `Min–max` column is
  where that row's truth is.
- **Masscan is being measured outside its design envelope.** Its wall clock
  here is dominated by fixed startup and its mandated listening window rather
  than by scanning, and the rate sweep above shows the workload never reaches
  the rate ceiling. Its row is honest about what it measured and says nothing
  about Masscan at the scale Masscan exists for.
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
- **The two SYN variants are not the same operation as ours.** `nmap-syn` and
  `masscan-syn` both need raw sockets, both had them here (the runner is uid 0
  with `CAP_NET_RAW`, which the generated block records per row), and neither
  completes a TCP connection. They are in the table because leaving out Nmap's
  own default mode, and the only mode Masscan has, would be its own kind of
  dishonesty — not because bathy is being compared to them like for like. Had
  the runner been unprivileged, the generated block would say so on those rows
  and their numbers would be a fallback rather than the operation named.
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
