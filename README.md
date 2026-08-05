# bathy

An agent-native network discovery engine: it turns authorized network questions
into bounded scan plans, executes them, and returns structured, evidence-backed
findings. One engine is exposed three ways — a Rust library, the `bathy`
command, and an MCP server — and none of the three contains any scanning logic
of its own.

## Authorized use

**bathy is for scanning networks you are authorized to scan.** Read this before
the quickstart; the quickstart cannot be completed without it.

- **Every scan requires a scope manifest.** `--scope <path>` is a required
  argument on every subcommand that can emit a packet. There is no default, no
  environment variable and no flag to skip it, so omitting it fails inside
  argument parsing — before a state directory is opened or a request exists.
- **Deny by default.** A manifest names the address ranges it authorizes and
  the instant it stops being valid. Anything it does not name is refused.
- **Refused in full, never trimmed.** If the manifest belongs to a different
  scope, has expired, or fails to cover a single one of the targets, the whole
  scan is refused. bathy does not scan the part it is allowed to scan and stay
  quiet about the rest.
- **Deliberately identifiable.** The probes name the tool and link to this
  repository. There is no anonymous mode, no evasive mode, and no flag to
  remove the identification.
- **Scanning networks without authorization may be unlawful in your
  jurisdiction and may violate your provider's terms of service. That is your
  responsibility, not the tool's.**

Exactly what a scanned third party receives on their wire, and where the
enforcement happens in the code, is in [Scope enforcement, in
detail](#scope-enforcement-in-detail) below.

> **Status: Milestones 1-5 of 7 landed (contracts; evidence and state; planner
> and engine; probes and interpretation; query, diff, CLI and MCP server);
> Milestone 7 — the verification suite — in progress.**
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
> What does not exist yet: nothing you run from the command line or over MCP
> sends a SYN or an ICMP echo. `bathy-engine` now *can* drive the packet
> daemon — it spawns it, initializes it from the manifest it validated
> against, falls back to connect scanning when the capability is absent, and
> records which method ran on `scan.started` — but no surface asks it to yet.
> `bathy-packetd` itself opens raw sockets, drops every capability before
> reading a byte, sends SYN probes, answers every SYN-ACK with an RST, and
> sends ICMP echo requests through the same scope check and the same session
> ceiling. Combined host discovery — ICMP first, TCP when ICMP is
> inconclusive — exists in `bathy-engine` as a library function, and nothing
> in production emits a `host.discovered` event yet, so `hosts_up` is still
> empty after every scan.
>
> Plans for all seven milestones — 213 numbered acceptance criteria — are in
> [`docs/superpowers/plans/`](docs/superpowers/plans/).

## 60-second quickstart

Every command below is real, and every line of output is a transcript of one
run on macOS on 2026-08-05 against `10.211.55.2` — an address of the machine it
ran on. Nothing in it is illustrative.

**Step 2 is not optional and cannot be worked around.** There is no way to
reach a socket in this tool without a manifest on disk that authorizes the
address you are about to touch.

### 1. Build

```
git clone https://github.com/russell0/bathy && cd bathy
cargo build --release -p bathy
```

`rust-toolchain.toml` pins stable; the `bathy` binary's own floor is Rust 1.95.

### 2. Write a scope manifest

Pick the address first, and pick one you are authorized to scan. A non-loopback
address of the machine you are sitting at is the easy answer — **`127.0.0.1`
will not work**: loopback is not an ordinary unicast address and no manifest
can authorize it (see [Limitations](#limitations)).

```
TARGET=          # ← put your address here. There is no default, deliberately.

cat > quickstart-scope.json <<EOF
{
  "id": "scope_01K2HZ8V5N3QR7BXMC4TDWF9GJ",
  "description": "Quickstart: this machine only, for one hour.",
  "not_after": "$(date -u -v+1H +%Y-%m-%dT%H:%M:%S.000Z 2>/dev/null || date -u -d '+1 hour' +%Y-%m-%dT%H:%M:%S.000Z)",
  "allowed_cidrs": ["$TARGET/32"],
  "denied_cidrs": [],
  "budget_ceiling": {
    "maximum_packets": 5000,
    "maximum_runtime_seconds": 60,
    "maximum_packets_per_second": 50
  }
}
EOF
```

The expiry is one hour out on purpose. A manifest is a grant of permission with
an end, not a setting.

### 3. Ask the manifest what it authorizes

```
$ ./target/release/bathy scope validate --scope quickstart-scope.json --targets $TARGET
scope_01K2HZ8V5N3QR7BXMC4TDWF9GJ "Quickstart: this machine only, for one hour."
  valid at 2026-08-05T00:17:29.502Z
  ceiling 5000pkt / 60s / 50pps
  1 target(s) in scope
  signature: none
```

### 4. Give it something to find (optional)

```
mkdir -p /tmp/quickstart-served
python3 -m http.server 8080 --bind $TARGET --directory /tmp/quickstart-served &
```

`--directory` is not decoration: `python3 -m http.server` serves the working
directory to everything that can reach that interface, and the working
directory here is a source tree.

### 5. Scan

```
$ ./target/release/bathy --state-dir ./quickstart-state scan start \
    --scope quickstart-scope.json --idempotency-key quickstart-1 \
    --targets $TARGET --ports 22,80,443,8080
scan_01KZ7MGMW7ZM647KA4AV7TCR4K  running  plan blake3:bc5b48d762941fa3f89dc775c37871e21dd3fc88ca18095fc1adbdf9e6f25735
4 unit(s) probed, 1 open, 5 packet(s) spent
```

### 6. Read the result, then read the bytes behind it

```
$ ./target/release/bathy --state-dir ./quickstart-state result query --scan scan_01KZ7MGMW7ZM647KA4AV7TCR4K
10.211.55.2:22 closed
10.211.55.2:80 closed
10.211.55.2:443 closed
10.211.55.2:8080 open http
4 of 4 endpoint(s)
```

Add `--json` for the same document as line-delimited JSON, which is what the
`result.query` tool returns. Each open endpoint carries the digest of the bytes
that justified it and the id of the rule that fired:

```
$ ./target/release/bathy --json --state-dir ./quickstart-state result query --scan scan_01KZ7MGMW7ZM647KA4AV7TCR4K
{"endpoints":[{"endpoint":{"port":22,"transport":"tcp"},"evidence_refs":[],"observation":null,"probe_id":null,"rule_id":null,"state":"closed","target":"10.211.55.2"},{"endpoint":{"port":80,"transport":"tcp"},"evidence_refs":[],"observation":null,"probe_id":null,"rule_id":null,"state":"closed","target":"10.211.55.2"},{"endpoint":{"port":443,"transport":"tcp"},"evidence_refs":[],"observation":null,"probe_id":null,"rule_id":null,"state":"closed","target":"10.211.55.2"},{"endpoint":{"port":8080,"transport":"tcp"},"evidence_refs":["blake3:7c79458c5f4c327b70c1746439bacdfd21c17694382155781659ee4f078713e7"],"observation":{"confidence":0.7,"service":"http"},"probe_id":"http-get-v1","rule_id":"http.protocol.bare.v1","state":"open","target":"10.211.55.2"}],"hosts_up":[],"plan_hash":"blake3:bc5b48d762941fa3f89dc775c37871e21dd3fc88ca18095fc1adbdf9e6f25735","terminal":{"findings":1,"outcome":"completed","packets_spent":5,"probes_sent":4},"total":4,"total_before_filter":4}

$ ./target/release/bathy --state-dir ./quickstart-state evidence get \
    --digest blake3:7c79458c5f4c327b70c1746439bacdfd21c17694382155781659ee4f078713e7 | head -5
HTTP/1.0 200 OK
Server: SimpleHTTP/0.6 Python/3.9.12
Date: Wed, 05 Aug 2026 00:17:31 GMT
Content-type: text/html; charset=utf-8
Content-Length: 297

$ ./target/release/bathy explain http.protocol.bare.v1
http.protocol.bare.v1
  service: http
  rationale: The response's first line is a well-formed HTTP status line, but no `Server` header matched any known product.
  source: RFC 9112 §4 ("Status Line": `status-line = HTTP-version SP status-code SP [ reason-phrase ]`)
```

Note two things that transcript does *not* say. It reports `http`, not
`SimpleHTTP/0.6 Python/3.9.12` — bathy has no rule for that server, so it names
the protocol it can prove and stops, at confidence 0.7. And `"hosts_up":[]` is
empty even though the host is plainly up: there is no host discovery in v0.1.
Both are in [Limitations](#limitations).

### What happens if you skip step 2

```
$ ./target/release/bathy scan start --idempotency-key x --targets 10.211.55.2 --ports 80
error: the following required arguments were not provided:
  --scope <PATH>

$ ./target/release/bathy scan start --scope quickstart-scope.json --idempotency-key y \
    --targets 10.211.55.3 --ports 80
bathy: denied (target_out_of_scope): 10.211.55.3 is not authorized by manifest scope_01K2HZ8V5N3QR7BXMC4TDWF9GJ
```

Exit code 1 for the first (argument parsing, before any bathy code runs) and 2
for the second (policy denial, before any packet). Codes 0-4 have distinct
documented meanings and are listed in `bathy --help`.

## Limitations

This section is the one a reader should weigh hardest, and it is written to
survive someone who runs [the benchmark](docs/benchmarks.md) themselves.

**Service identification is a fraction of Nmap's, and will stay that way for a
long time.** Nmap has 28 years of accumulated community fingerprint
contributions. bathy v0.1 has eight protocols and thirteen interpretation
rules, each authored from an RFC, vendor documentation or a lab capture. On
this project's own nine-service integration lab — a lab built to exercise
exactly those thirteen rules, which flatters bathy enormously — both tools
named five of the six products the lab establishes, and *they were not the same
five*. On an arbitrary network the ratio would be far worse. The one number
that generalises is the count of protocols, and it is eight.

**A TLS-fronted service is identified only as `tls`.** This is the most
concrete identification loss the project has, it is structural rather than a
missing rule, and it was measured: on the lab's `10.30.0.17:443`, `nmap -sV`
names the product and bathy does not. `Scheduler::detect_service` stops at the
first probe whose capture interprets to anything; on 443 that is `tls-v1`,
which is protocol-only *by construction* because RFC 8446 encrypts the
certificate, so the HTTP probe never runs — even though the rule that would
name the product matches those exact bytes. Changing that policy changes
per-endpoint packet accounting, pacing, and the reported service for every TLS
port, so it is a scanner change and not a documentation fix. The gap is
recorded as `identification_gap` in
[`lab/ground-truth.json`](lab/ground-truth.json), and the conformance suite
holds that endpoint to being unidentified — so the day bathy names it, the test
fails and demands the entry be deleted.

**bathy is slower than Nmap, by between 1.4x and 17.8x depending on which
comparison you make.** Like for like — port discovery with no identification —
it is about 1.4x slower than `nmap -sT`. With identification on, it is about
1.5x slower than `nmap -sT -sV`. The 17.8x figure compares bathy's default,
which identifies services, against a bare Nmap port sweep that does not; it is
real and it is not like for like. All of it, including the command lines and
the observed ranges, is in [`docs/benchmarks.md`](docs/benchmarks.md).

**Observations are not reproducible. Planning and interpretation are.** This is
a distinction, not a hedge, and it is the reason the codebase is shaped the way
it is:

- *Planning is deterministic.* The same request against the same scope manifest
  produces the same `plan_hash`, every time, on any machine. That is what makes
  idempotency and resumption safe.
- *Interpretation is reproducible.* The same evidence bytes through the same
  engine version produce the same findings, with no I/O, no clock and no
  randomness involved. A committed corpus of recorded captures is replayed
  against the rules offline on every change.
- *Observation is neither, and cannot be.* Networks drop packets, rate-limit,
  reorder, and change under you between one connection and the next. Two scans
  of the same host minutes apart may legitimately disagree, and no amount of
  engineering here changes that. What the project does instead is make the
  disagreement visible: every finding cites the bytes it came from, and
  `result.diff` separates confidence noise from substantive change.

**Not in v0.1, at all:**

- **No OS detection.** Nothing in this tree fingerprints an operating system.
- **No UDP.** `Transport::Udp` exists in the type system so that logs written
  today stay readable later; no planner emits it and no probe speaks it. Every
  scan is TCP.
- **No traceroute**, and no path or topology discovery of any kind.
- **No IPv6.** It is *refused*, not merely unimplemented — see below.
- **No Windows.** A licensing constraint, stated in full in
  [`docs/platform-support.md`](docs/platform-support.md).
- **No privileged scanning from the command line or over MCP, deliberately.**
  `bathy-packetd` can SYN scan — it builds the segment, classifies the reply,
  and tears an open port's half-open connection down with an RST — and
  `bathy-engine` can now drive it. Neither the CLI nor the MCP surface asks
  it to, and **v0.1 ships no way to make it**: there is no flag, no tool
  argument and no configuration file that puts a daemon path in front of the
  engine, `SchedulerConfig`'s daemon path defaults to none, and every scan you
  can start today is a TCP connect scan.

  Two things make that a decision rather than an omission. SYN scanning is
  more intrusive than connect — it leaves half-open connections on someone
  else's machine — and this project already treats `scan.start` as a
  destructive operation behind an approval threshold; an approval policy that
  distinguishes the two does not exist yet, and shipping the more intrusive
  method under the less intrusive method's threshold would be the wrong way
  round. And `bathy-packetd` is **not published**: it carries
  `publish = false` and is excluded from the crates this workspace releases,
  so `cargo install bathy` installs no privileged binary for a flag to point
  at. `cargo run -p xtask -- check-packetd` fails if either shipped surface
  ever reaches for the daemon, so this paragraph is checked rather than
  merely written. When one does ask, an absent
  `CAP_NET_RAW` falls back to connect scanning and says so on `scan.started`,
  and a daemon that dies mid-scan fails the scan with `packetd_unavailable`
  rather than quietly finishing by the other method. `bathy-packetd` also
  sends ICMP echo requests now, and `bathy-engine`'s `discover_host_combined`
  tries ICMP first and falls back to the TCP method when ICMP is inconclusive.
  A scan requesting `--objective host-inventory` runs a discovery phase and
  emits `host.discovered` events naming the method that decided, so `hosts_up`
  is populated for those scans. Every other objective runs no discovery phase,
  so `hosts_up` is empty and an address with no host on it produces `filtered`
  endpoints rather than a "host down" verdict. The **ICMP** half of discovery
  additionally needs a `bathy-packetd` the CLI cannot reach (see the bullet
  below), so from the CLI the deciding method is always one of the
  `tcp-connect-*` ones.
- **No loopback.** `127.0.0.0/8` is refused by `ScopeManifest::allows` on the
  same footing as IPv6, so no manifest can authorize a scan of the machine's
  own loopback interface. This is a deliberate blast-radius decision and it is
  why the quickstart needs a real interface address.
- **No evasion and no anonymization.** Permanent non-goals, not omissions.

**Port presets are IANA-derived heuristics, not prevalence measurements.**
`top-100` and `common-1000` are built from the IANA service-name registry with
a documented ranking heuristic. They are not derived from a measurement of what
is actually listening on the internet, and nothing here claims they are the
same hundred ports another tool would choose.

**IPv6 is refused outright**, not merely unimplemented. `ScopeManifest::allows()`
returns false for every IPv6 address in v0.1. That decision came out of review:
three rounds of prefix-by-prefix hardening each closed an enumerated set of
IPv4-in-IPv6 embedding schemes and each was followed by a review finding one
more — eight in total, the last (ISATAP) signalling through the interface
identifier rather than a prefix, which no prefix list can catch. A blanket
refusal is immune to every scheme, enumerated or not. The eight guards remain in
the source, parked and tested, as the starting point for v0.2.

**macOS is best-effort and Linux is the target.** Both are described, with the
specific things that differ, in
[`docs/platform-support.md`](docs/platform-support.md).

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
  returns exactly what justified a claim; `fingerprint.explain` takes the `rule_id` a finding
  carries and says why that rule fired. *Callable both ways: as `bathy evidence get` and `bathy explain`, and as
  the `evidence.get` and `fingerprint.explain` tools, which return the same
  documents.*
- **Scope enforcement.** Deny-by-default manifests with expiry, checked against
  scope identity, expiry, and per-target authorization on the actual emission
  path, and again as an upfront, pre-plan check in the CLI before anything is
  written.
- **Differential scanning.** "What changed since Monday" is a first-class query, with
  confidence noise separated from substantive change.

That argument is about interfaces and about measurements, and it is the whole
argument. Nothing in this repository claims another project is bad, badly run,
or obsolete, and nothing here is a comparison to a person.

## The eleven MCP tools

`bathy serve mcp` speaks MCP over stdio and advertises eleven typed tools:
`scope.validate`, `scan.preview`, `scan.start`, `scan.status`, `scan.events`,
`scan.cancel`, `scan.resume`, `result.query`, `result.diff`, `evidence.get`,
`fingerprint.explain`.

Every one of them declares an output schema and returns a conforming structured
result with a JSON text mirror. What the tool surface deliberately does not
have is as important as what it has:

- No tool's input schema has a `command`, `args`, `flags`, `argv` or `raw`
  field. An agent cannot build a command line through this interface.
- No tool accepts a scope manifest inline or by id. A scope is named by a path,
  exactly as `--scope` takes one, so a caller cannot author its own
  authorization.
- A scan wider than the server's configured approval threshold starts nothing.
  It returns an `input_required` result carrying an `elicitation/create`, and
  will only proceed when a retry brings back an approval token that is
  HMAC-sealed, bound to the caller and to the arguments it was issued for,
  time-limited and single-use. See [`docs/threat-model.md`](docs/threat-model.md).

Every tool has a CLI equivalent, and the two go through the same code — there
is no second implementation of the fold, the diff, or the policy check.

## What works today

| Crate | Delivers |
|---|---|
| `bathy-types` | Every type crossing a public boundary: `ScanRequest`, the immutable `Event` model, `Digest`, prefixed ULID identifiers, `NonEmpty`, `Confidence`, `TaskHandle`, canonical JSON and `plan_digest`. Zero internal dependencies, no async runtime. |
| `bathy-scope` | Deny-by-default authorization: scope manifests with expiry, policy evaluation with stable machine-readable deny codes, and a hard budget ledger. |
| `bathy-evidence` | The content-addressed blob store and the append-only, gap-free event log that is this project's actual source of truth — SQLite state elsewhere is a derived index rebuildable from it, never the reverse. What may and may not change about a record, so that a log stays readable by later builds, is written down in [`docs/event-log-compatibility.md`](docs/event-log-compatibility.md). |
| `bathy-store` | SQLite-backed scan state: idempotency (a repeated key with an identical plan reuses the scan; a different plan is refused as a conflict), a resumption cursor, and per-scan lifecycle status. A scan starts `pending` and `bathy-engine`'s scheduler transitions it to `completed`, `cancelled`, `failed`, or `denied` on each of its own terminal outcomes. `bathy scan start` and `bathy scan resume` set `running` before the first probe, so a handle that says `running` and a `scan status` read from another process agree; `paused` is still written by nothing. |
| `bathy-plan` | Turns a `ScanRequest` into a deterministic, indexable `ScanPlan`: target expansion, port selection, and the content hash idempotency and resumption are built on. |
| `bathy-probe` | Eight clean-room protocol probes (HTTP, TLS, SSH, SMTP, DNS, PostgreSQL, MySQL, Redis) and the bounded I/O layer they run on: every read is capped in bytes and bounded by a deadline that covers the whole read rather than each individual `recv`, so a peer that floods or dribbles forever cannot exhaust memory or hang a scan. The deadline is per call, not per probe: a probe that writes and then reads can take up to twice it, deliberately, since the hostile case being defended against is on the read path. Probes return raw, uninterpreted bytes — they never decide what a response *means*. |
| `bathy-interpret` | The rule engine that decides what those bytes mean. Pure: no I/O, no clock, no randomness, no async runtime — exactly two dependencies, enforced in CI. Every interpretation carries the rule that fired, the byte range that justified it, and a confidence from a fixed specificity ladder. The rule id travels with the observation all the way to the wire — `service.observed`, the fold, and `result.query`'s `rule_id` — so `fingerprint.explain` is reachable *from a finding* and not only from a listing. The byte range is not carried past this crate: it indexes the full response, and stored evidence is capped at the evidence level, so a span that could point past the bytes `evidence.get` returns would be a citation that does not resolve. Every rule cites its source (an RFC section, vendor documentation, or a capture with an image digest), and a committed corpus of recorded captures is replayed against it offline on every change. |
| `bathy-engine` | The scheduler: budget-governed, rate-limited, cancellable, resumable execution of a `ScanPlan` over real unprivileged TCP connect probes, with scope identity, manifest expiry, and per-target authorization all checked directly on the actual emission path. Drives service identification on top of that — up to `intensity` further paced, budgeted, scope-checked connections per open port, stopping at the first response a rule recognizes — and stores the evidence bytes *before* emitting the event that cites them. Also ships host discovery as library building blocks that nothing calls: the unprivileged TCP method, and a combined one that asks `bathy-packetd` for an ICMP echo first and falls back to TCP when the answer is inconclusive, reporting whichever method decided. Neither is wired into the scheduler and nothing constructs a `host.discovered` event — see the `discovery` module doc for why. |
| `bathy-packetd` | The privileged helper. It opens three raw sockets, drops every capability, sets `PR_SET_NO_NEW_PRIVS`, verifies both against `/proc/self/status`, and only then reads a byte — and reads it through a guard that re-measures the capability set on every fill and refuses while one is held. `--self-check` reports what it measured, including that opening a raw socket now fails; without `CAP_NET_RAW` it exits 69 naming the capability, the `setcap` command and the connect-scan fallback. It sends SYN probes when a caller drives its pipe, and it decides for itself whether it may: the session allowlist, denylist and packet ceiling are enforced again inside it, by a matcher that shares no code with `bathy-scope`, and reserved ranges are refused even under an allowlist of `0.0.0.0/0`. Every SYN-ACK is answered with an RST, so no half-open connection is left on a target. It sends ICMP echo requests too, through the *same* scope check and the *same* session ceiling — one admission path, not two — and classifies an echo reply as up, a destination unreachable as down and silence as unknown. `bathy-engine` drives it over that pipe now — the `init` allowlist is the validated manifest's networks and cannot be reached by the raw request — but no CLI or MCP surface asks for either probe kind. It is the one crate permitted `unsafe`, and contains one block, in `src/privilege.rs`, for the `prctl` above. What it does today is otherwise refuse: nothing but an `init` may arrive first, an `init` with an empty allowlist is refused rather than read as "allow everything", a second `init` cannot widen the session's scope, and malformed or oversized input ends the session instead of being resynchronized past. Every one of those refusals is final — the session answers `fatal` to everything afterwards, including a valid `init`. |
| `bathy-query` | Folds a scan's event log into the state it describes: one record per endpoint carrying its last observed reachability, its last service observation, every evidence digest cited for it, and the scan's terminal outcome — completed, failed, or refused by policy. Pure, and ordered by `sequence` rather than by arrival, so the answer does not depend on how the log was read. Diffs two of those folds into a classified list of what changed, and refuses to call an endpoint appeared or disappeared unless both scans ran the same plan to completion — a refused, cancelled or budget-exhausted scan is not a scan that found less. Both types are published schemas, and `bathy result query` / `bathy result diff` are this crate, called through the CLI and by the `result.query` / `result.diff` tools with no second fold anywhere. |
| `bathy-mcp` | The MCP server: eleven typed tools over protocol revision `2026-07-28` on stdio. That revision has no `initialize` handshake and no protocol-level sessions, so the server implements `server/discover` and takes the protocol version from each request's `_meta`. It contains no scanning logic. |
| `bathy` | The `bathy` command: `scope validate`, `scan preview/start/status/events/cancel/resume`, `result query/diff`, `evidence get`, `explain`, `serve mcp`. A translator over the engine API and nothing else — it contains no scanning logic. Every subcommand that can emit a packet takes `--scope` as a required argument with no default and no skip flag, so omitting it fails inside argument parsing, before a state directory is opened or a request exists. `--json` puts line-delimited JSON on stdout and every diagnostic on stderr, including on the failure paths; exit codes 0-4 have distinct documented meanings and are listed in `--help`. |
| `xtask` | Every gate this project has, as commands: the dependency layering, the "no inference client on the packet path" rule, schema drift against the committed `schemas/`, the README's checkable numbers, the documentation's structural claims, the forbidden-pattern rules, `bathy-interpret`'s dependency purity, the MSRV floors and their job membership, `cargo deny`'s check set, and — so a future gate cannot go back to being unrunnable — that every CI step is one of these. |

27 schemas are committed under [`schemas/`](schemas/) and CI fails if a type
changes without regenerating them — they are the published contract, not a
by-product. 21 of them are the MCP tool surface: 11 tool input schemas and 10
tool output schemas. The eleventh output is `result.diff`'s, which *is*
[`schemas/scan-diff.json`](schemas/scan-diff.json) rather than a copy of it —
the tool advertises the committed document itself, so the diff an agent is
handed and the diff the CLI prints cannot be two shapes. Either way the schema
an agent is shown is the one the Rust type generates rather than a second copy
someone wrote out.

## Scope enforcement, in detail

Every scan requires an unexpired scope manifest naming the permitted address
ranges, bound to the exact scope the scan was started under; there is no flag to
bypass it, and a scan is refused in full — never silently trimmed — the moment
any of that fails: the manifest belongs to a different scope, the manifest has
expired, or a single target falls outside its allow set. `bathy-engine`'s
scheduler enforces all three directly, on the actual emission path. Scope
identity and expiry are checked once per `Scheduler::run`, before any probe is
dispatched; the allow/deny set is checked per unit, immediately before each
probe. A manifest that expires mid-scan does not halt the run in progress. The
CLI adds an earlier refusal in front of that: `bathy scan preview`, `scan start`
and `scan resume` each call `bathy_scope::evaluate` over the fully expanded
target list before a scan record is written and before a scheduler exists, and
each takes `--scope` as a required argument, so a scan with no manifest fails
during argument parsing rather than reaching any code that could open a socket.
(`preview` and `start` refuse before the state directory is opened at all.
`resume` has to open it first — the plan it is re-authorizing is the one already
in the store — so a refused resume leaves behind a created state directory and
its empty stores, and no scan record, no plan and no packet.) `scan resume` is
re-evaluated against the manifest handed to it, not against the decision the
original `scan start` got. Scans carry hard packet, rate, and runtime budgets.
`maximum_packets` counts **probes**, not segments: one plan unit is charged
once, and one connect attempt is a SYN plus — for a port that answers — the
rest of a handshake and a teardown. It is an upper bound on probes issued, and
the packets they put on a wire are a small constant multiple of it.

**What a scanned third party sees on their wire.** Every port is first touched by
a plain, unprivileged TCP connect that sends no payload. A port that answers then
receives **up to `intensity` further connections — four by default, and never
fewer than one** — each a separate TCP connection carrying one protocol probe,
tried in order of port affinity and stopping at the first response a rule
recognizes. So a port whose first probe is recognized receives one additional
connection; a port that answers but is never identified receives four.
`--intensity 0` is accepted and means one, not none: the floor is one probe,
because "identify this service" with no probe at all is a request the flag
cannot express and `bathy scan preview` is what sends nothing. Most carry a
real request — a
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
anonymization are permanent non-goals — [`SECURITY.md`](SECURITY.md) states
that, says what it covers and what it deliberately does not, and is what a
feature request for either will be closed against.

Service identification can be disabled entirely
(`service_detection.enabled = false`), in which case only the bare connect probe
is ever sent. It cannot be made anonymous.

## Verified properties, not just tested ones

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

### Running the gates, including the ones that are not local

Every gate above is `cargo run -p xtask -- check-<something>` over the working
tree. Two things that are not in the working tree need their own commands, and
both exist because CI's `test` job was red on 17 consecutive pushes over five
days while every local command was green:

- `cargo run -p xtask -- check-ci-status` asks GitHub what CI actually
  concluded, **for the commit you are on**. It fails on a red run, and equally
  on a green run for an older commit — the branch this was written on had
  thirteen unpushed commits, so a green badge would have described code nobody
  was working on.
- `cargo run -p xtask -- linux-gate` runs `ci.yml`'s own `test` job steps —
  read out of `ci.yml`, not restated — inside a Linux container over this
  working tree, as your own uid rather than as root. Linux is this project's
  primary target and macOS is best-effort, but development happens on macOS,
  and the two failures that went unnoticed were invisible there: one assertion
  was `#[cfg(target_os = "linux")]` and so never compiled locally, and two test
  fixtures depended on the kernel handing out ephemeral ports in ascending
  order, which macOS does and Linux does not.

  **It is not hermetic, and it says so on every run.** The container's
  `CARGO_TARGET_DIR`, `CARGO_HOME` and `HOME` all live under `target/` and are
  reused between runs, because a cold Linux rebuild of the whole dependency
  graph takes minutes and a gate that costs minutes is a gate people stop
  running. The cost is that a result can be about what the last run left
  behind: a `target/linux-gate` from a *mutation* build made one run fail and
  the rerun pass, over an identical tree. Every run now prints whether it is
  reusing that state, and `linux-gate --fresh` clears it first.

## Planned scope for v0.1

IPv4 TCP connect scanning, optional privileged SYN and ICMP, host discovery, top-port
and explicit port selection, HTTP/TLS/SSH/DNS/SMTP/PostgreSQL/MySQL/Redis
identification, structured event output, cancellation and resumption, scope manifests
and rate budgets, a CLI, a Rust library, and an MCP server.

Out of scope for v0.1: OS fingerprinting, UDP breadth, traceroute, evasion modes,
IPv6 scanning, and Windows support.

### What is deliberately *not* claimed

Planning is deterministic and interpretation is reproducible. **Observations are not** —
networks drop packets, rate-limit, and change under you. The distinction is enforced in
the codebase and is explained under [Limitations](#limitations).

Service-identification coverage will start far below mature scanners: this project
begins with eight protocols against decades of accumulated community fingerprint data
elsewhere. Port presets are IANA-derived heuristics, not prevalence measurements.

## Documents

- [`SECURITY.md`](SECURITY.md) — how to report a vulnerability and what to
  expect back, the safety mechanisms and where they live in the code, and the
  permanent non-goals.
- [`CONTRIBUTING.md`](CONTRIBUTING.md) — the clean-room rule, what a citation
  for a new interpretation rule has to be checkable against, and every gate in
  its local form.
- [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) — including the rule specific to a
  scanner: do not post a third party's hosts in a public issue.
- [`docs/design-paper.md`](docs/design-paper.md) — why this exists, how it is
  built, what it measured, and where it falls short.
- [`docs/threat-model.md`](docs/threat-model.md) — what bathy defends against,
  what it does not, and who it trusts.
- [`docs/platform-support.md`](docs/platform-support.md) — Linux, macOS, and
  the Windows licensing position.
- [`docs/benchmarks.md`](docs/benchmarks.md) — the cross-scanner comparison,
  including every category bathy loses.
- [`docs/protocol-notes.md`](docs/protocol-notes.md) — the MCP revision this
  server implements and the reasoning behind each choice.
- [`docs/event-log-compatibility.md`](docs/event-log-compatibility.md) — what
  may and may not change about a stored record.
- [`lab/README.md`](lab/README.md) — the digest-pinned integration lab and its
  ground truth.
- [`fuzz/README.md`](fuzz/README.md) — the fuzz targets and their corpora.

## Clean room

No Nmap source, probe file, or fingerprint database is consulted, copied, or derived
from in this project. Interpretation rules are authored from protocol RFCs, vendor
documentation, or captures from software run in this project's own test lab, and each
rule records its source. Contributions must follow the same rule, and
[`CONTRIBUTING.md`](CONTRIBUTING.md) states what a citation has to be checkable
against — this project found two fabricated RFC quotations in its own history,
so "cite something" was not a strong enough rule. The full attestation,
including the one place Nmap is legitimately run, is in
[`docs/design-paper.md`](docs/design-paper.md).

## License

Apache-2.0 OR MIT, at your option.
