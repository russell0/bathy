# bathy

Agent-native network discovery. Turns authorized network questions into bounded
scan plans, executes them, and returns structured, evidence-backed findings.

> **This crate is a name reservation.** The scanning engine is real, tested and
> working — it lives in the sibling crates and in the repository below. The
> `bathy` **command** lands in Milestone 5, at which point this crate gains its
> binary. Until then `cargo install bathy` will correctly tell you there is
> nothing to install.

## What exists today (v0.1.0-alpha.1)

A working TCP connect scanner with:

- **Deny-by-default authorization.** A `Scheduler` cannot be constructed without
  a scope manifest, and it verifies scope identity, manifest expiry, and the
  allow/deny set before emitting a packet.
- **Hard budgets** on packets, rate and runtime that survive cancel/resume.
- **Deterministic planning.** The same request produces the same `plan_hash` and
  the same unit at every index, across processes.
- **Gap-free, resumable event logs** with group-commit durability, and
  content-addressed evidence that is verified on read.

464 tests. Not yet: service identification, the MCP server, privileged SYN
scanning, or the benchmark suite.

## Authorized use

bathy is for scanning networks you are authorized to scan. Detection evasion and
anonymization are permanent non-goals.

## Source, plans and progress

**https://github.com/russell0/bathy**

## License

Apache-2.0 OR MIT
