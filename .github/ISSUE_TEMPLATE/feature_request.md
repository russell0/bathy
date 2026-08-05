---
name: Feature request
about: Something bathy should be able to do and cannot
title: ''
labels: enhancement
assignees: ''
---

<!--
BEFORE YOU WRITE THIS: two categories are declined on sight, and it is not
personal.

1. Detection evasion and anonymization. Decoys, spoofed sources, idle scanning,
   fragmentation and other IDS-evasion crafting, proxy/Tor integration offered
   as origin obfuscation, randomized or removable tool identification, timing
   profiles whose purpose is staying under a detection threshold. These are
   PERMANENT non-goals. SECURITY.md gives the reasoning and -- importantly --
   lists the adjacent things that are NOT covered: rate limiting, connect
   timeouts, concurrency ceilings, smaller port sets, and disabling service
   identification entirely are all supported.

2. Anything requiring code, probe strings, fingerprint data or port lists
   derived from Nmap or another incompatibly licensed project. CONTRIBUTING.md
   §1 explains why this is a legal boundary rather than a preference.

Deferred rather than declined, and already tracked: OS fingerprinting, UDP
breadth, traceroute, IPv6 scanning, WASM plugins, signed manifests, an A2A
agent card. The Gap Register in
docs/superpowers/plans/2026-07-31-bathy-v0.1-overview.md says which and why.
-->

## What can you not do today

## What would you do with it

<!-- The use case, not the implementation. "I need to know which of these 400
hosts changed since Tuesday" tells us more than "add a --diff flag". -->

## Which surface

- [ ] Rust library
- [ ] `bathy` CLI
- [ ] MCP server
- [ ] All three

<!-- One engine exposed three ways: a behaviour that lands in one usually has
to land in all three, and a divergence between the CLI and MCP is itself a bug
here. -->

## Is there evidence it would produce, and where would it come from

<!-- Every finding in bathy carries evidence, enforced in the type system. A
feature that reports something must be able to say which bytes justified it. If
yours cannot, say so -- that is a real answer and it shapes the design. -->

## Anything that makes this harder than it looks

<!-- Scope enforcement, budgets, determinism of planning, the schema being
committed and drift-checked. If you already know which of these your idea
touches, say so. -->
