# bathy

An agent-native network discovery engine: turns authorized network questions into
bounded scan plans, executes them, and returns structured, evidence-backed findings
over MCP.

> **Status: Milestones 1-4 of 7 landed (contracts; evidence and state; planner
> and engine; probes and interpretation); Milestone 5 in progress — the `bathy`
> CLI runs.**
>
> bathy scans, and identifies what it finds. `bathy-engine`'s scheduler drives
> real, unprivileged TCP connect scanning against IPv4 targets: budget- and
> rate-governed, cancellable, and resumable. Every `Scheduler::run` call
> verifies, before it will ever emit a probe, that its manifest is the one this
> scan was actually authorized under (not merely *a* manifest), that the
> manifest is still active (unexpired), and that each individual target is
> inside its allow set — see `crates/bathy-engine/src/scheduler.rs`'s module
> doc. Since Milestone 5's CLI landed there is a second, earlier enforcement
> point: `bathy_scope::evaluate` is called by `bathy scan preview`, `bathy scan
> start` and `bathy scan resume` over the plan's fully expanded target list,
> before any scan record is written and before the scheduler exists. The two are
> not redundant — the CLI's is the *upfront* refusal (nothing is created, no
> packet is possible), the scheduler's is the check on the actual emission path
> that holds for any caller, including one that does not go through the CLI.
> Every observation lands in a durable,
> gap-free, append-only event log (`bathy-evidence`) before the SQLite state
> that indexes it is made durable — never the other way around.
>
> A port that answers gets one or more *additional* connections, each carrying a
> single real protocol probe — tried in order of port affinity and stopping at
> the first response that is recognized, up to an `intensity` bound (4 by
> default). What comes back is interpreted into a `service.observed` event
> citing the content-addressed response bytes, stored before the event that
> references them and capped at the configured evidence level (8 KiB for
> headers, 64 KiB for full; `EvidenceLevel::None` stores nothing and therefore
> emits no `service.observed` at all). Eight protocols: HTTP, TLS, SSH, SMTP,
> DNS, PostgreSQL, MySQL, Redis. Probe traffic is paced by the same rate limiter
> and charged to the same packet budget as the connect scan, and the manifest is
> re-checked before identification opens any connection at all. Identification
> can be turned off
> (`service_detection.enabled = false`), in which case no probe bytes are sent
> at all.
>
> What does not exist yet: an MCP server (the rest of Milestone 5), privileged
> SYN/ICMP scanning and a packet daemon (Milestone 6), and the verification
> suite (Milestone 7).
>
> Plans for all seven milestones — 210 numbered acceptance criteria — are in
> [`docs/superpowers/plans/`](docs/superpowers/plans/).

## What works today

| Crate | Delivers |
|---|---|
| `bathy-types` | Every type crossing a public boundary: `ScanRequest`, the immutable `Event` model, `Digest`, prefixed ULID identifiers, `NonEmpty`, `Confidence`, `TaskHandle`, canonical JSON and `plan_digest`. Zero internal dependencies, no async runtime. |
| `bathy-scope` | Deny-by-default authorization: scope manifests with expiry, policy evaluation with stable machine-readable deny codes, and a hard budget ledger. |
| `bathy-evidence` | The content-addressed blob store and the append-only, gap-free event log that is this project's actual source of truth — SQLite state elsewhere is a derived index rebuildable from it, never the reverse. |
| `bathy-store` | SQLite-backed scan state: idempotency (a repeated key with an identical plan reuses the scan; a different plan is refused as a conflict), a resumption cursor, and per-scan lifecycle status. A scan starts `pending` and `bathy-engine`'s scheduler transitions it to `completed`, `cancelled`, `failed`, or `denied` on each of its own terminal outcomes. `bathy scan start` and `bathy scan resume` set `running` before the first probe, so a handle that says `running` and a `scan status` read from another process agree; `paused` is still written by nothing. |
| `bathy-plan` | Turns a `ScanRequest` into a deterministic, indexable `ScanPlan`: target expansion, port selection, and the content hash idempotency and resumption are built on. |
| `bathy-probe` | Eight clean-room protocol probes (HTTP, TLS, SSH, SMTP, DNS, PostgreSQL, MySQL, Redis) and the bounded I/O layer they run on: every read is capped in bytes and bounded by a deadline that covers the whole read rather than each individual `recv`, so a peer that floods or dribbles forever cannot exhaust memory or hang a scan. The deadline is per call, not per probe: a probe that writes and then reads can take up to twice it, deliberately, since the hostile case being defended against is on the read path. Probes return raw, uninterpreted bytes — they never decide what a response *means*. |
| `bathy-interpret` | The rule engine that decides what those bytes mean. Pure: no I/O, no clock, no randomness, no async runtime — exactly two dependencies, enforced in CI. Every finding carries the rule that fired, the byte range that justified it, and a confidence from a fixed specificity ladder. Every rule cites its source (an RFC section, vendor documentation, or a capture with an image digest), and a committed corpus of recorded captures is replayed against it offline on every change. |
| `bathy-engine` | The scheduler: budget-governed, rate-limited, cancellable, resumable execution of a `ScanPlan` over real unprivileged TCP connect probes, with scope identity, manifest expiry, and per-target authorization all checked directly on the actual emission path. Drives service identification on top of that — up to `intensity` further paced, budgeted, scope-checked connections per open port, stopping at the first response a rule recognizes — and stores the evidence bytes *before* emitting the event that cites them. Also ships unprivileged TCP host discovery as a library building block (not yet wired into the scheduler — see the `discovery` module doc for why, and Milestone 6's plan for where it lands). |
| `bathy-query` | Milestone 5, in progress. Folds a scan's event log into the state it describes: one record per endpoint carrying its last observed reachability, its last service observation, every evidence digest cited for it, and the scan's terminal outcome — completed, failed, or refused by policy. Pure, and ordered by `sequence` rather than by arrival, so the answer does not depend on how the log was read. Diffs two of those folds into a classified list of what changed, and refuses to call an endpoint appeared or disappeared unless both scans ran the same plan to completion — a refused, cancelled or budget-exhausted scan is not a scan that found less. Both types are published schemas, and `bathy result query` / `bathy result diff` are this crate, called through the CLI with no second fold anywhere. The MCP server is the rest of Milestone 5. |
| `bathy` | The `bathy` command: `scope validate`, `scan preview/start/status/events/cancel/resume`, `result query/diff`, `evidence get`, `explain`. A translator over the engine API and nothing else — it contains no scanning logic. Every subcommand that can emit a packet takes `--scope` as a required argument with no default and no skip flag, so omitting it fails inside argument parsing, before a state directory is opened or a request exists. `--json` puts line-delimited JSON on stdout and every diagnostic on stderr, including on the failure paths; exit codes 0-4 have distinct documented meanings and are listed in `--help`. |
| `xtask` | Enforces the dependency layering, the "no inference client on the packet path" rule, and schema drift against the committed `schemas/`. |

Six schemas are committed under [`schemas/`](schemas/) and CI fails if a type
changes without regenerating them — they are the published contract, not a
by-product.

### Verified properties, not just tested ones

Reviews on this branch mutation-test their findings: a check is deleted, and the
suite must fail. Several defects were caught that way and would not have been
caught by reading, including a test that passed with the code it named removed,
eight distinct IPv4-in-IPv6 embedding schemes that bypassed the authorization
boundary, and an expiry comparison that reported an expired manifest as valid.

Milestone 4 added more of the same shape: renaming any of seven probe ids
silently disabled that protocol's identification with all 253 tests in the three
crates involved still green; the only public-API integration test passed with all
of service identification deleted; blanking a capture fixture's entire provenance
record passed the whole suite; and two RFC quotations turned out to be
fabricated — plausible sentences, in quotation marks, asserting something
stronger than the document said. Each of those now has a test that dies.

## Authorized use

bathy is built for scanning networks you are authorized to scan. Every scan requires
an unexpired scope manifest naming the permitted address ranges, bound to the exact
scope the scan was started under; there is no flag to bypass it, and a scan is
refused in full — never silently trimmed — the moment any of that fails: the
manifest belongs to a different scope, the manifest has expired, or a single target
falls outside its allow set. `bathy-engine`'s scheduler enforces all three directly,
on the actual emission path. Scope identity and expiry are checked once per
`Scheduler::run`, before any probe is dispatched; the allow/deny set is checked
per unit, immediately before each probe. A manifest that expires mid-scan does
not halt the run in progress. The CLI adds an earlier refusal in front of that:
`bathy scan preview`, `scan start` and `scan resume` each call
`bathy_scope::evaluate` over the fully expanded target list before anything is
written and before a scheduler exists, and each takes `--scope` as a required
argument, so a scan with no manifest fails during argument parsing rather than
reaching any code that could open a socket. `scan resume` is re-evaluated
against the manifest handed to it, not against the decision the original `scan
start` got. Scans carry hard packet, rate, and runtime budgets.

**What a scanned third party sees on their wire.** Every port is first touched by
a plain, unprivileged TCP connect that sends no payload. A port that answers then
receives **up to `intensity` further connections — four by default** — each a
separate TCP connection carrying one protocol probe, tried in order of port
affinity and stopping at the first response a rule recognizes. So a port whose
first probe is recognized receives one additional connection; a port that
answers but is never identified receives four. Most carry a real request — a
`GET /`, a TLS `ClientHello`, an `EHLO`, a Redis `PING`, a DNS `version.bind`
query, a PostgreSQL `SSLRequest`. **Two send nothing at all**: the SSH and MySQL
probes are listen-first, because those protocols have the server speak first and
sending anything would corrupt the banner being read. Those bytes are fixed and
public: they are listed, byte for byte, in each probe's own module in
`crates/bathy-probe/src/probes/`.

bathy is **deliberately identifiable**, and that is a design commitment, not an
oversight. The HTTP probe sends
`User-Agent: bathy/<version> (+https://github.com/russell0/bathy)`, and the SMTP
probe identifies itself as `bathy.invalid`. An operator who receives this traffic
can tell what it is and who to contact. There is no anonymous mode, no evasive
mode, and no flag to remove the identification. Detection evasion and
anonymization are permanent non-goals — see the design notes before opening a
feature request for either.

Service identification can be disabled entirely
(`service_detection.enabled = false`), in which case only the bare connect probe
is ever sent. It cannot be made anonymous.

Scanning networks without authorization may be unlawful in your jurisdiction and may
violate your provider's terms of service. That is your responsibility, not the tool's.

## What it is meant to be

The design premise is that existing scanners were built for humans at a terminal, and
expose their results to software as XML plus command-line string construction. That is
a poor fit for typed tool calling. bathy targets the gap:

- **Typed operations.** Every action has JSON Schema inputs and outputs. No agent
  constructs a command line.
- **Task handles.** Scans start, poll, stream, cancel, pause, and resume. Nothing
  blocks. *`bathy scan start` prints a `TaskHandle` before the scan runs and
  keeps running until it finishes; `scan status`, `scan events --follow`, `scan
  cancel` and `scan resume` all work from a separate process against a live
  scan. `pause` is not implemented.*
- **Evidence.** Every finding cites content-addressed response bytes. `evidence.get`
  returns exactly what justified a claim; `fingerprint.explain` says which rule fired
  and why. *Callable today as `bathy evidence get` and `bathy explain`; the MCP
  tool names arrive with the server.*
- **Scope enforcement.** Deny-by-default manifests with expiry, checked against
  scope identity, expiry, and per-target authorization on the actual emission
  path, and again as an upfront, pre-plan check in the CLI before anything is
  written — see "Authorized use" above for exactly what each of the two does.
- **Differential scanning.** "What changed since Monday" is a first-class query, with
  confidence noise separated from substantive change.

### What is deliberately *not* claimed

Planning is deterministic and interpretation is reproducible. **Observations are not** —
networks drop packets, rate-limit, and change under you. The distinction is enforced in
the codebase.

Service-identification coverage will start far below mature scanners: this project
begins with eight protocols against decades of accumulated community fingerprint data
elsewhere. Port presets are IANA-derived heuristics, not prevalence measurements.
See each plan's limitations sections.

## Planned scope for v0.1

IPv4 TCP connect scanning, optional privileged SYN and ICMP, host discovery, top-port
and explicit port selection, HTTP/TLS/SSH/DNS/SMTP/PostgreSQL/MySQL/Redis
identification, structured event output, cancellation and resumption, scope manifests
and rate budgets, a CLI, a Rust library, and an MCP server.

Out of scope for v0.1: OS fingerprinting, UDP breadth, traceroute, evasion modes,
IPv6 scanning, and Windows support.

**IPv6 is refused outright**, not merely unimplemented. `ScopeManifest::allows()`
returns false for every IPv6 address in v0.1. That decision came out of review:
three rounds of prefix-by-prefix hardening each closed an enumerated set of
IPv4-in-IPv6 embedding schemes and each was followed by a review finding one
more — eight in total, the last (ISATAP) signalling through the interface
identifier rather than a prefix, which no prefix list can catch. A blanket
refusal is immune to every scheme, enumerated or not. The eight guards remain in
the source, parked and tested, as the starting point for v0.2.

## Clean room

No Nmap source, probe file, or fingerprint database is consulted, copied, or derived
from in this project. Interpretation rules are authored from protocol RFCs, vendor
documentation, or captures from software run in this project's own test lab, and each
rule records its source. Contributions must follow the same rule.

## License

Apache-2.0 OR MIT, at your option.
