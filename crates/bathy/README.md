# bathy

Agent-native network discovery. Turns authorized network questions into bounded
scan plans, executes them, and returns structured, evidence-backed findings.

This crate is the `bathy` **command**. The engine it drives lives in the sibling
crates in the repository below; this crate contains no scanning logic of its own.

> **Note:** the published `0.1.0-alpha.1` is the lib-only name reservation that
> preceded the binary. This README describes the working tree, which has the
> binary; nothing on crates.io installs a `bathy` command until the next release.

```
bathy scope validate  --scope <PATH>
bathy scan preview    --scope <PATH> --targets <T,...> --ports <P,...>
bathy scan start      --scope <PATH> --idempotency-key <KEY> --targets ... --ports ...
bathy scan status     --scan <SCAN_ID>
bathy scan events     --scan <SCAN_ID> [--follow [--idle-timeout-seconds <N>]]
bathy scan cancel     --scan <SCAN_ID>
bathy scan resume     --scope <PATH> --scan <SCAN_ID>
bathy result query    --scan <SCAN_ID>
bathy result diff     --before <SCAN_ID> --after <SCAN_ID>
bathy evidence get    --digest <blake3:...>
bathy explain         <RULE_ID> | --list
```

`--json` puts line-delimited JSON on stdout and every diagnostic on stderr,
including when a command fails, and including `--help` and `--version`, which
become documents rather than prose so that stdout is JSON without exception.
Exit codes: `0` success, `1` operational error, `2` policy denial, `3` budget or
time exhaustion, `4` idempotency conflict — `bathy --help` carries the same
table, and `bathy --json --help` carries it as data. An argument mistake is
always `1`: it is never reported as success, whatever shape it takes.

`scan events --follow` stops at the scan's terminal event, or after
`--idle-timeout-seconds` (default 300) with nothing new — a scan whose process
was killed never writes a terminal event, and a follower with no deadline waits
for it forever. `0` waits forever, for a caller who wants that.

## Authorization

Every subcommand that can emit a packet requires `--scope`, pointing at an
unexpired scope manifest that names the permitted address ranges. There is no
default and no flag to skip it, so a scan with no manifest fails during argument
parsing — before a state directory is opened, before a request exists, and
before anything that could open a socket runs. `scan preview` and `scan start`
evaluate the manifest over the fully expanded target list before anything is
written, and `scan resume` re-evaluates it rather than trusting the decision the
original start received. A scan is refused in full, never silently trimmed.

`scan preview` answers "what would this do" — plan hash, target and probe
estimates, policy decision — and emits no packet at all.

## What exists today

- **Deny-by-default authorization**, checked upfront by the CLI and again on the
  engine's own emission path.
- **Hard budgets** on packets, rate and runtime that survive cancel/resume.
- **Deterministic planning.** The same request produces the same `plan_hash` and
  the same unit at every index, across processes.
- **Gap-free, resumable event logs** with group-commit durability, and
  content-addressed evidence that is verified on read — `evidence get` returns
  the exact bytes a finding cited.
- **Service identification** over eight protocols (HTTP, TLS, SSH, SMTP, DNS,
  PostgreSQL, MySQL, Redis), every claim citing a rule and the bytes that fired
  it; `bathy explain` prints the rule's rationale and its source.
- **Differential scanning.** `result diff` classifies what changed between two
  scans, and refuses to read absence as evidence when the two scans did not run
  the same plan to completion.

Not yet: the MCP server, privileged SYN/ICMP scanning, IPv6, and the benchmark
suite.

## Authorized use

bathy is for scanning networks you are authorized to scan. Detection evasion and
anonymization are permanent non-goals.

## Source, plans and progress

**https://github.com/russell0/bathy**

## License

Apache-2.0 OR MIT
