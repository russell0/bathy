# bathy

An agent-native network discovery engine: turns authorized network questions into
bounded scan plans, executes them, and returns structured, evidence-backed findings
over MCP.

> **Status: Milestone 1 of 7 complete. Nothing here scans anything yet.**
>
> What exists: the contract layer (`bathy-types`) and the authorization engine
> (`bathy-scope`), with 194 tests, four published JSON Schemas, and CI enforcing
> the project's layering and clean-room rules. **No code in this repository sends
> a packet.** The scanning engine lands in Milestone 3.
>
> Plans for all seven milestones — 185 numbered acceptance criteria — are in
> [`docs/superpowers/plans/`](docs/superpowers/plans/).

## What works today

| Crate | Delivers |
|---|---|
| `bathy-types` | Every type crossing a public boundary: `ScanRequest`, the immutable `Event` model, `Digest`, prefixed ULID identifiers, `NonEmpty`, `Confidence`, `TaskHandle`, canonical JSON and `plan_digest`. Zero internal dependencies, no async runtime. |
| `bathy-scope` | Deny-by-default authorization: scope manifests with expiry, policy evaluation with stable machine-readable deny codes, and a hard budget ledger. |
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
bypass it, and a scan whose targets fall outside the manifest is refused in full
rather than trimmed. Scans carry hard packet, rate, and runtime budgets, and probe
traffic identifies itself. Detection evasion and anonymization are permanent
non-goals — see the design notes before opening a feature request for either.

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
