# Network Discovery After the CLI

### Designing a Deterministic Planner for Autonomous Software Agents

*Working paper for bathy v0.1. Every measurement cited here was taken on this
branch and can be reproduced from it; every limitation named in §8 was found by
running the thing, not by imagining it.*

---

## 1. The integration gap

Network scanners were designed for a person at a terminal. The interface they
present is a command line in and a report out, and the report is for reading.
Where a machine-readable form exists it is usually an XML document produced as a
rendering of that report rather than as a contract: a document whose shape is
stable in practice but whose meaning is documented in prose, if at all.

This is not a criticism of those tools. It is a statement about who they were
built for. A person constructing a command line brings judgement to it — they
know that `-sV` is slower, that `-Pn` changes what the numbers mean, that a
particular flag combination is a different operation and not a faster one. They
carry that context between the command and the report.

An autonomous software agent has a different shape:

- **It builds its arguments by generation, not by judgement.** If the interface
  is a command line, the agent's job is string construction, and the failure
  mode is a string that parses and means something other than what was
  intended. `--ports` and `-p` and `-p-` are three different things a
  probabilistic text generator will happily interchange.
- **It cannot be trusted with authorization.** An agent that can write its own
  scope is an agent whose scope is whatever the last few thousand tokens
  suggested.
- **It needs to justify what it says.** An agent reporting "there is an SSH
  server on 10.0.0.5" is making a claim that a human will act on. The
  provenance of that claim — what bytes came back, which rule fired, why that
  rule means what it says — is not a nice-to-have; it is the difference between
  a finding and an assertion.
- **It does not block.** A ten-minute synchronous call is not an operation an
  agent loop can hold open.

bathy is an attempt to build the same class of tool for that consumer. The
argument is not that the existing interface is wrong. It is that it is an
interface for a different consumer, and that a tool designed for this one comes
out looking different in specific, measurable ways. §7 is the measurements,
including where they go against us.

Concretely, the design differences are:

| Design decision | The consumer it is for |
|---|---|
| Every operation has a JSON Schema input and output, generated from the Rust type | An agent that fills fields, never constructs an argv |
| No tool input has a `command`, `args`, `flags`, `argv` or `raw` field | An agent that cannot smuggle a command line through a typed interface |
| A scope is named by a path, never supplied inline or by id | An agent that cannot author its own authorization |
| Scans return a task handle immediately | An agent loop that does not block |
| Every finding cites content-addressed bytes and a rule id | An agent that has to justify a claim to a human |
| Planning is a pure function of request and manifest | A caller that needs the same question to be the same scan |

## 2. Layers, and what each one is forbidden to do

The workspace is eleven crates in a strict stack. What matters is less the
number than the direction: every arrow points down, and each layer's *inability*
to do certain things is what the layer is for.

```
bathy (CLI) ─┬─ bathy-mcp        interface adapters: translation only, no scanning logic
             │
             ├─ bathy-query      pure fold and diff over an event log
             ├─ bathy-engine     the scheduler: the only thing that opens a socket
             ├─ bathy-interpret  pure: bytes in, meaning out. No I/O, no clock, no randomness
             ├─ bathy-probe      bounded I/O; returns raw bytes and never decides what they mean
             ├─ bathy-plan       request + manifest -> deterministic plan
             ├─ bathy-store      SQLite scan state (a derived index)
             ├─ bathy-evidence   content-addressed blobs + append-only event log (the source of truth)
             ├─ bathy-scope      deny-by-default authorization
             └─ bathy-types      pure types, JSON Schema, canonical hashing
```

Three of those prohibitions are enforced mechanically rather than by review:

- **No model or inference client below `bathy-mcp`.** There is no LLM anywhere
  on the packet path — not choosing probes, not deciding a port state, not
  interpreting a banner. `cargo run -p xtask -- check-deps` fails the build if
  any lower crate acquires such a dependency. The engine is a conventional
  scanner; the agent is a caller of it.
- **`bathy-interpret` is pure.** Two dependencies, no I/O, no clock, no
  randomness, no async runtime, checked by `check-purity`. That purity is what
  makes §4's replay property real rather than aspirational.
- **One `unsafe` block in the whole workspace, and it is not a socket call.**
  `#![forbid(unsafe_code)]` is on every crate target except the
  `bathy-packetd` library root, which is `#![deny(unsafe_code)]` so the single
  permitted site can be a site-level `expect` with a reason. That site is
  `prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)`, which makes the privileged
  helper's capability drop survive an `execve`. The raw sockets and the
  capability clearing needed none: `socket2::Socket::new` is `socket(2)` and
  `caps::clear` is `capset(2)`, both safe APIs over crates already in that
  process's graph. `check-phrases` enforces that the keyword appears nowhere
  else; `check-packetd` enforces the `SAFETY:` comment and that no crate
  target has lost its attribute.

## 3. Evidence and provenance

A `Finding` in this system cannot be constructed without at least one
`EvidenceRef`. That is a type-system fact, not a convention: the field is
`NonEmpty<Digest>`, so a finding with nothing behind it does not typecheck.

The chain runs:

1. A probe writes zero or more fixed, published bytes and reads a bounded
   response. It returns a `ProbeCapture` — raw bytes, the probe id, elapsed
   time, and whether the read hit its cap. It does not interpret.
2. `bathy-interpret` maps the capture to zero or more interpretations. Each
   carries a rule id, the byte span that justified it, a service name, and a
   confidence drawn from a fixed specificity ladder (protocol only < product <
   product and version). Every rule cites its source: an RFC section, vendor
   documentation, or a capture from software run in this project's own lab,
   recorded with the image digest.
3. The scheduler stores the response bytes **first**, then appends the
   `service.observed` event citing the resulting digest. The ordering is
   mandatory and tested by interleaving rather than by deletion: a crash between
   the two leaves an orphaned blob, which is harmless because nothing cites it.
   The reverse would leave a finding whose citation no `evidence.get` call could
   ever resolve, which is the failure this design exists to prevent.
4. `evidence.get` returns exactly those bytes. `fingerprint.explain` takes the
   `rule_id` a finding carries and returns what that rule looks for and where it
   came from.

The event log is the source of truth. It is append-only, gap-free (each record
carries a sequence number, and a gap is an error rather than a shrug), and made
durable before the SQLite state that indexes it. SQLite here is a derived index,
rebuildable from the log; the log is never rebuildable from SQLite. What may and
may not change about a stored record, so that a log written today stays readable
by a later build, is written down in
[`event-log-compatibility.md`](event-log-compatibility.md).

The point of all of this is a single property: **every claim this system makes
can be taken apart by its consumer.** An agent that says "MySQL on
10.30.0.13:3306" can be asked, mechanically, which bytes and which rule — and
the answer is the bytes themselves, not a summary of them.

## 4. Why planning is deterministic and observation is not

This is the distinction the whole codebase is arranged around, and it is stated
narrowly on purpose.

**Planning is deterministic.** `ScanRequest` + `ScopeManifest` → `ScanPlan` is a
pure function. Target expansion, port selection and ordering involve no clock,
no randomness and no network. The plan is canonicalized with RFC 8785 (JSON
Canonicalization Scheme) and hashed with BLAKE3 into a `plan_hash`. The same
question asked twice produces the same hash on any machine, which is what makes
two downstream features safe: idempotency (a repeated key with an identical plan
returns the original scan; with a different plan it is a conflict, not a silent
second scan) and resumption (a resume must be resuming *this* plan).

**Interpretation is reproducible.** The same evidence bytes through the same
engine version produce the same findings. Because `bathy-interpret` is pure,
this is testable without a network: a committed corpus of recorded captures is
replayed against the rules on every change, and every fixture carries the
provenance of the software that produced it.

**Observation is neither, and no engineering here can make it so.** Networks
drop packets, rate-limit, reorder, and change between one connection and the
next. Two scans of the same host minutes apart may legitimately disagree, and a
scanner that presented them as agreeing would be lying. So the project does not
claim it. The claim is scoped in the Global Constraints, and a CI check
(`check-phrases`) fails the build on the unscoped phrasing appearing anywhere in
the repository — this document included. A line that must name the phrase in
order to define, test or enforce the rule carries a sentinel marker; every other
line, here and everywhere else, is held to the scoped form.

What the project does instead is make disagreement *visible and classified*.
`result.diff` compares two folds and separates confidence noise from substantive
change, and it refuses to call an endpoint appeared or disappeared unless both
scans ran the same plan to completion. A refused, cancelled or budget-exhausted
scan is not a scan that found less. The testable form of the reproducibility
claim is the lab conformance test: two consecutive scans of a static,
digest-pinned lab must diff to no substantive changes. That is a claim about the
*scanner's* stability, which is ours to keep, rather than about the network's,
which is not.

## 5. Three-layer scope enforcement

Authorization is deny-by-default and is checked in three places that are
deliberately not redundant. Two of them are in the unprivileged half; the
third is inside the one process that holds a capability, and it shares no
code with the other two.

**Layer 1 — the upfront refusal, in the CLI and the MCP adapter.** `scan
preview`, `scan start` and `scan resume` each call `bathy_scope::evaluate` over
the plan's fully expanded target list before a scan record is written and before
a scheduler exists. `--scope <path>` is a required argument with no default and
no skip flag, so a scan with no manifest fails inside argument parsing. A
refusal here means nothing was created and no packet was ever possible.

**Layer 2 — the emission path, in `bathy-engine`.** Every `Scheduler::run`
verifies that its manifest is the one this scan was authorized under (identity,
not merely presence), that it has not expired, and — per unit, immediately
before each probe — that the target is inside the allow set and outside the deny
set. Service identification re-checks the manifest before opening any
connection.

**Layer 3 — inside the privileged process, in `bathy-packetd`.** The two layers
above are both in the *unprivileged* half. `packetd` is the only component that can
put an arbitrary packet on a wire, so it does not delegate the question of
whether it may: its `Init` fixes an allowlist, a denylist and a packet ceiling
for the process lifetime, a second `Init` is fatal rather than widening, and
every probe — SYN and ICMP echo alike — is checked against them by
`check_session_scope`, which **shares no code with `bathy-scope`**. It does not
import it, does not use `IpNet::contains`, and does not use `std`'s
`is_loopback`/`is_multicast`/`is_broadcast`/`is_link_local`: containment is a
mask comparison written there and the reserved ranges are decided from the
octets. Reserved addresses are refused even when the allowlist is `0.0.0.0/0`,
because an operator writing that is saying "I am authorized for the internet",
not "send this at 255.255.255.255".

This duplication is the point, and it is the one place in this design where
duplication is deliberate. The argument for the two-process split is that a bug
or a compromise in the unprivileged half must be *unable* to become a packet at
an address nobody authorized; a `packetd` that asked `bathy-scope` would make
both checks one implementation and one bug away from failing together. Two
statements of one policy are worth nothing unless something checks they agree,
so a proptest generates a CIDR pair and an address and asserts that
`check_session_scope` and a real `bathy_scope::ScopeManifest` reach the same
verdict, and the fuzz target that drives the line protocol with attacker-shaped
bytes judges every emitted packet by a *third* implementation of the same rules
— `ipnet`'s matcher and `std`'s predicates, which `packetd` uses neither of.

Both probe kinds reach that check through one function. `Prober::admit` is the
only place in the crate that asks "may I touch this address" and "have I any
budget left", in that order — scope first, so a privileged process never answers
"budget spent" about a target it was never authorized to touch. A second probe
type carrying its own copy would be a second place for the authorization to be
wrong, and a test that exhausts the ceiling with a *mix* of SYN and ICMP probes
is what makes one shared counter a fact rather than a claim: two counters that
agree still pass a budget test spent with one kind.

Layer 1 exists because refusing early is kinder and leaves nothing behind.
Layer 2 exists because Layer 1 is in an adapter, and an adapter can be bypassed
by a library caller. Layer 3 exists because Layers 1 and 2 are in a process that
cannot emit a packet at all, and the process that can is the one whose refusal
has to be true. **The property that must hold is "no packet leaves this system
for an unauthorized address", and each layer is the only one that still holds it
when the layer above is wrong.** Deleting Layer 1 costs tidiness; deleting Layer
2 costs the guarantee for library callers; deleting Layer 3 costs the argument
for splitting the process in the first place.

Three decisions inside the policy are worth stating because they cost something:

- **Refusal is total.** A manifest that covers 250 of 256 targets refuses the
  scan; it does not scan the 250. A partially-executed authorization is a result
  a caller cannot reason about.
- **IPv6 is refused outright**, not merely unimplemented, and so is loopback.
  The IPv6 decision came out of review: three rounds of prefix-by-prefix
  hardening each closed an enumerated set of IPv4-in-IPv6 embedding schemes and
  each was followed by a review finding one more — eight in total, the last
  (ISATAP) signalling through the interface identifier rather than a prefix,
  which no prefix list can catch. A blanket refusal is immune to every scheme,
  enumerated or not. The eight guards remain in the source, parked and tested,
  as the starting point for v0.2.
- **A manifest that expires mid-scan does not halt the run in progress.** This
  is a deliberate choice and it is a real hole in an otherwise clean story:
  expiry is checked once per `Scheduler::run`, not per unit. Making it per-unit
  would mean a scan can stop halfway through, which is the partially-executed
  authorization the first bullet rejects. Both positions are defensible; this
  one is written down rather than left to be discovered.

## 6. The plugin sandboxing plan, and why it is not in v0.1

The eight protocol probes in v0.1 are compiled in. That is a deliberate v0.1
position, not an oversight, and the reason is the same one that governs
everything else here: a probe decides what bytes go on somebody else's network.

The intended v0.2 shape is a WASM/WASI plugin runtime behind the existing
`Probe` trait, which is already the seam: a probe receives a bounded I/O handle
and returns raw bytes, and has no access to the scheduler, the manifest, the
budget ledger or the event log. A sandboxed plugin would inherit exactly that —
no filesystem, no network beyond the handle it is given, no clock, and a fuel
limit — and its output would still go through `bathy-interpret`, which is pure
and does not know where a capture came from.

What is *not* settled, and what a v0.2 design will have to answer before this
ships: how a plugin's traffic is charged to the packet budget when the plugin
controls the write pattern, and how a third-party fingerprint's provenance claim
is verified when the rule is no longer in this repository. Shipping the runtime
before those have answers would move the trust boundary without saying so.

## 7. Measurements

Full numbers, command lines and reproduction steps are in
[`benchmarks.md`](benchmarks.md). The headline results, including the losses:

- **Speed, like for like.** Port discovery with no identification: bathy is
  about **1.4x slower** than `nmap -sT` (2063 ms median vs 1475 ms) and 1.5x
  slower than its SYN scan. With identification on: about **1.5x slower** than
  `nmap -sT -sV` (26285 ms vs 17819 ms).
- **Speed, not like for like.** bathy's default, which identifies services,
  against a bare Nmap port sweep that does not: **17.8x**. That comparison is
  published because omitting an unflattering number that a reader can compute
  themselves is worse than explaining it.
- **Accuracy.** Every tool that ran found 12 of 12 known-open ports with no
  false positives, including on two addresses with no host and one host that
  answers on nothing. On a nine-service lab with no packet loss, this
  distinguishes nothing, and it is reported because it is what happened.
- **Identification breadth: a tie in aggregate, and the aggregate misleads.**
  bathy and `nmap -sV` each named five of the six products the lab establishes,
  and they were not the same five. bathy named MySQL where Nmap did not; Nmap
  named the product behind TLS on `10.30.0.17:443` where bathy did not. §8 is
  about that second one.
- **Micro-benchmarks.** Criterion benchmarks over `interpret`, canonical JSON,
  plan construction and log append exist as regression detectors, one per
  owning crate. They are deliberately not performance gates: a wall-clock
  threshold on a shared runner is a flaky test, and a flaky test is one people
  learn to ignore.

The comparison is scored against `lab/ground-truth.json`, which was derived by
sweeping all 65535 TCP ports on every lab address from inside the lab network
with a Python standard-library script that shares no code, no port table and no
fingerprint data with any scanner measured. **No tool is ever scored against
another tool's output.**

## 8. Limitations, and threats to validity

### 8.1 What the system cannot do

- **Service identification is a fraction of Nmap's.** Nmap has 28 years of
  accumulated community fingerprint contributions. bathy v0.1 has eight
  protocols and thirteen interpretation rules. This gap is the largest between
  this project and a mature scanner and it is not close.
- **A TLS-fronted service is identified only as `tls`.** This is structural, it
  is measured, and it is the most concrete identification loss the project has.
  `Scheduler::detect_service` stops at the first probe whose capture interprets
  to anything. On 443 that is `tls-v1`, which is protocol-only *by
  construction*: RFC 8446 encrypts the certificate, so a TLS 1.3 handshake
  yields no product name. The HTTP probe, whose rule matches those exact bytes
  and would name the product outright, therefore never runs. Changing the
  first-match policy changes per-endpoint packet accounting, pacing, and the
  reported service for every TLS port, so it is a scanner change and not a
  documentation fix. The gap is recorded as `identification_gap` in
  `lab/ground-truth.json`, and the conformance suite holds that endpoint to
  being unidentified — the day bathy names it, that test fails and demands the
  entry be deleted.
- **No OS detection, no UDP, no traceroute, no IPv6, no Windows, and no
  privileged scanning from the CLI or over MCP** in v0.1. `bathy-packetd` sends
  SYN probes and ICMP echo requests, and `bathy-engine` can drive both, but no
  surface asks it to and v0.1 ships no way to ask. That is a decision, not an
  unfinished wire: SYN scanning is more intrusive than connect, the approval
  threshold that gates `scan.start` does not yet distinguish the two, and the
  daemon is not published, so there is no privileged binary in an installed
  `bathy` for a flag to point at. A gate fails if either shipped surface
  reaches for it. Host discovery **is** in the output, for one objective:
  a scan requesting `host-inventory` runs a discovery phase and emits
  `host.discovered` events recording the method that decided, and every other
  objective emits none, so `hosts_up` is empty for them and an address with no
  host produces `filtered` endpoints rather than a "host down" verdict. Since
  no surface can reach `bathy-packetd`, the ICMP half of that pair never runs
  outside the tests, and the method a real scan records is always one of the
  `tcp-connect-*` ones.
- **Port presets are IANA-derived heuristics, not prevalence measurements.**
  `top-100` and `common-1000` come from the IANA service-name registry with a
  documented ranking heuristic. Nothing here claims they are the hundred ports
  most likely to be open on an arbitrary network, because nothing here measured
  that.
- **The approval threshold is a policy, not a security boundary against the
  operator.** It stops an agent from widening a scan without a human; it does
  nothing about a human who wants a wide scan.

### 8.2 Threats to validity in the measurements

- **A nine-service lab is not a network.** Every service in it is one bathy has
  a probe for, and the lab was built to exercise the thirteen rules that exist.
  It measures correctness on a fixture and says nothing about coverage in the
  wild. The identification tie in §7 should be read with that firmly in mind.
- **This is the project's own benchmark of its own competitors.** The defence
  is not a promise. It is that the oracle is independent of every tool
  measured, the harness is unit-tested, every command line is published
  verbatim, and the loss list is computed from the results rather than chosen by
  an author.
- **Wall clock on a laptop is noisy**, and one row's range spans an order of
  magnitude for reasons that were investigated and not resolved. It is recorded
  in `benchmarks.md` rather than smoothed away.
- **A container on a bridge network has no loss and no latency.** Retry policy,
  where the tools differ, is invisible in these numbers.
- **Two scanners were not installed and did not run.** Their rows say so, with
  the command that would fill them in. A reader must not be able to mistake a
  two-scanner comparison for a four-scanner one.

### 8.3 Threats to validity in the verification

- **`FUZZ_SURFACES` is a hand-maintained list.** Completeness of the
  "every untrusted-input parser is fuzzed" claim is asserted by the list rather
  than proved by the code. What is enforced is that every registered surface has
  a target or a self-expiring deferral, and that every declared fuzz binary is a
  registered surface.
- **`check-readme` pins numbers, not guarantees.** The claims that are numbers
  with a source of truth in the tree are mechanically checked. The prose
  guarantees — what the scheduler checks and when, what is refused in full —
  are statements about control flow, and `xtask/src/readme.rs` ends with the
  written-out list of what stays human-verified. A green check means those
  numbers agree with the tree; it never means the document is correct.
- **The absence-claim register catches staleness, not omission.** A sentence
  saying "X does not exist yet" that nobody registered is invisible to the
  checker. This was found the honest way: the register's entry for the
  verification suite named a path that never came to exist, so the entry could
  not fire, and the README carried a stale claim through this milestone until a
  human read it.

## 9. Clean-room attestation

This project's interpretation rules, probe byte sequences, port tables and
fingerprint data are independently authored. Specifically, and precisely:

- **No Nmap source code has been read, copied, translated, or derived from** in
  the authoring of any part of this repository.
- **No `nmap-service-probes`, `nmap-services`, `nmap-os-db`, or any other Nmap
  probe or fingerprint data file has been read or consulted**, and no content
  from any of them appears here in any form, transformed or otherwise.
- **Every interpretation rule cites its own source**, and the source is an RFC
  section, published vendor documentation, or a capture taken from software run
  in this project's own digest-pinned lab. The citations are in
  `crates/bathy-interpret/src/rules.rs` and are checked against a committed
  provenance corpus.
- **Port presets are derived from the IANA service-name and port-number
  registry**, by a generator in this repository (`cargo run -p xtask --
  gen-ports`), not from any scanner's port list.

**Nmap is installed on the machine this project was developed on, and it was run
here.** Stating that plainly is the point of an attestation. It was run in
exactly one capacity: **as a benchmark subject**, timed and scored against the
lab's independently derived ground truth, in `bench/compare.sh`. Timing a
program is not deriving from it. The specific boundaries:

- Its data files were **not read**. Installing Nmap necessarily places
  `nmap-service-probes` and its siblings on the disk. Their presence on a disk
  is not the boundary; opening them is, and they were not opened.
- **No rule, probe, port list or interpretation in this repository was
  authored, corrected, or tuned from Nmap's output.** Where Nmap identified
  something bathy did not — §8.1's TLS gap — the miss is recorded as a miss and
  we did not go and look at why. The cause given there was derived by reading
  our own code and RFC 8446.
- The XML parser that reads Nmap's benchmark results was written from the
  documented shape of `-oX` output. Its test fixture is synthetic: **not one
  captured Nmap run is checked into this repository.**

Contributors are held to the same rule, and are required to cite an RFC, vendor
documentation, or a lab capture as the source for every new interpretation rule.

## 10. What would falsify the thesis

The claim of this paper is narrow: *an interface designed for a software agent
produces a materially different tool, and the difference is measurable.* Things
that would count as evidence against it, listed here so that the paper cannot
quietly stop being checkable:

- If an agent driving a conventional scanner through a shell achieves the same
  task success rate as one driving typed tools, the integration-gap premise is
  weak. This has not been measured here, and until it is, §1 is an argument
  rather than a result.
- If provenance turns out to be something consumers never use — if no caller
  ever fetches the evidence behind a finding — the cost of the evidence model is
  not being repaid.
- If service-identification coverage stays at eight protocols, the interface
  argument stops mattering, because a tool that cannot see what is there is not
  a tool anyone should be integrating.

---

*This document is versioned with the code. Every number in it is either
reproducible from this branch or explicitly marked as unmeasured.*
