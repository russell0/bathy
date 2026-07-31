# sonde

An agent-native network discovery engine: turns authorized network questions into
bounded scan plans, executes them, and returns structured, evidence-backed findings
over MCP.

> **Status: pre-implementation.** This repository currently contains implementation
> plans only — no working code. Nothing here scans anything yet. See
> [`docs/superpowers/plans/`](docs/superpowers/plans/).

## Authorized use

sonde is built for scanning networks you are authorized to scan. Every scan requires
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
a poor fit for typed tool calling. sonde targets the gap:

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

## Clean room

No Nmap source, probe file, or fingerprint database is consulted, copied, or derived
from in this project. Interpretation rules are authored from protocol RFCs, vendor
documentation, or captures from software run in this project's own test lab, and each
rule records its source. Contributions must follow the same rule.

## License

Apache-2.0 OR MIT, at your option.
