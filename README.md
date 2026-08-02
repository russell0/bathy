# bathy

An agent-native network discovery engine: turns authorized network questions into
bounded scan plans, executes them, and returns structured, evidence-backed findings
over MCP.

> **Status: Milestones 1-3 of 7 landed (contracts; evidence and state; planner
> and engine).**
>
> bathy scans. `bathy-engine`'s scheduler drives real, unprivileged TCP connect
> scanning against IPv4 targets: budget- and rate-governed, cancellable, and
> resumable, with authorization checked once over a scan's full expanded target
> list before any packet exists (`bathy_scope::evaluate`) and re-checked again,
> unconditionally, immediately before every single probe is actually emitted
> (`Scheduler::run` — see `crates/bathy-engine/src/scheduler.rs`'s module doc
> for why both checks exist and why the second one cannot be skipped by
> forgetting to call the first). Every observation lands in a durable,
> gap-free, append-only event log (`bathy-evidence`) before the SQLite state
> that indexes it is made durable — never the other way around.
>
> What does not exist yet: interpretation (service and version identification,
> Milestone 4), a CLI or an MCP server (Milestone 5), privileged SYN/ICMP
> scanning and a packet daemon (Milestone 6), and the verification suite
> (Milestone 7). There is still no way to invoke a scan except as a Rust
> library call — see `crates/bathy-engine/tests/end_to_end_scan.rs` for exactly
> that, exercised end to end against real sockets.
>
> Plans for all seven milestones — 185 numbered acceptance criteria — are in
> [`docs/superpowers/plans/`](docs/superpowers/plans/).

## What works today

| Crate | Delivers |
|---|---|
| `bathy-types` | Every type crossing a public boundary: `ScanRequest`, the immutable `Event` model, `Digest`, prefixed ULID identifiers, `NonEmpty`, `Confidence`, `TaskHandle`, canonical JSON and `plan_digest`. Zero internal dependencies, no async runtime. |
| `bathy-scope` | Deny-by-default authorization: scope manifests with expiry, policy evaluation with stable machine-readable deny codes, and a hard budget ledger. |
| `bathy-evidence` | The content-addressed blob store and the append-only, gap-free event log that is this project's actual source of truth — SQLite state elsewhere is a derived index rebuildable from it, never the reverse. |
| `bathy-store` | SQLite-backed scan state: idempotency (a repeated key with an identical plan reuses the scan; a different plan is refused as a conflict), a resumption cursor, and per-scan lifecycle status. A scan starts `pending` and `bathy-engine`'s scheduler transitions it to `completed`, `cancelled`, `failed`, or `denied` on each of its own terminal outcomes; `running`/`paused` are reserved for Milestone 5's pause/resume CLI surface. |
| `bathy-plan` | Turns a `ScanRequest` into a deterministic, indexable `ScanPlan`: target expansion, port selection, and the content hash idempotency and resumption are built on. |
| `bathy-engine` | The scheduler: budget-governed, rate-limited, cancellable, resumable execution of a `ScanPlan` over real unprivileged TCP connect probes, authorization re-checked on the actual emission path. Also ships unprivileged TCP host discovery as a library building block (not yet wired into the scheduler — see the `discovery` module doc for why, and Milestone 6's plan for where it lands). |
| `xtask` | Enforces the dependency layering, the "no inference client on the packet path" rule, and schema drift against the committed `schemas/`. |

Four schemas are committed under [`schemas/`](schemas/) and CI fails if a type
changes without regenerating them — they are the published contract, not a
by-product.

### Verified properties, not just tested ones

Reviews on this branch mutation-test their findings: a check is deleted, and the
suite must fail. Several defects were caught that way and would not have been
caught by reading, including a test that passed with the code it named removed,
eight distinct IPv4-in-IPv6 embedding schemes that bypassed the authorization
boundary, and an expiry comparison that reported an expired manifest as valid.

## Authorized use

bathy is built for scanning networks you are authorized to scan. Every scan requires
an unexpired scope manifest naming the permitted address ranges; there is no flag to
bypass it. Authorization is checked on two independent code paths — once over a
scan's full expanded target list before any packet exists, and again immediately
before every single probe is emitted — and either check refuses the whole scan
rather than silently trimming the offending targets. Scans carry hard packet, rate,
and runtime budgets. v0.1 probe traffic is a plain, unprivileged TCP connect: it
carries no identifying payload — that is a v0.1 limitation, not a claim otherwise.
Detection evasion and anonymization are permanent non-goals regardless — see the
design notes before opening a feature request for either.

Scanning networks without authorization may be unlawful in your jurisdiction and may
violate your provider's terms of service. That is your responsibility, not the tool's.

## What it is meant to be

The design premise is that existing scanners were built for humans at a terminal, and
expose their results to software as XML plus command-line string construction. That is
a poor fit for typed tool calling. bathy targets the gap:

- **Typed operations.** Every action has JSON Schema inputs and outputs. No agent
  constructs a command line.
- **Task handles.** Scans start, poll, stream, cancel, pause, and resume. Nothing blocks.
- **Evidence.** Every finding cites content-addressed response bytes. `evidence.get`
  returns exactly what justified a claim; `fingerprint.explain` says which rule fired
  and why.
- **Scope enforcement.** Deny-by-default manifests with expiry, enforced twice on
  independent code paths.
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
