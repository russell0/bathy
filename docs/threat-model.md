# Threat model

What bathy defends against, what it does not, and who it trusts. Written so
that someone deciding whether to run this can find the boundary quickly, and so
that a feature request that would move the boundary can be recognised as one.

The system's single most important structural property, and the thing to read
the rest of this document against:

> **There is no language model anywhere on the packet path.** No model chooses a
> probe, decides a port state, or interprets a banner. The engine is a
> conventional scanner; the agent is a caller of it. This is enforced by
> `cargo run -p xtask -- check-deps`, which fails the build if any crate below
> `bathy-mcp` acquires a model or inference dependency.

## 1. Who is trusted, and how much

| Party | Trust |
|---|---|
| The operator running the process | **Fully trusted.** They chose the manifest and can edit it. |
| The scope manifest on disk | **Trusted as authorization.** Whoever can write that file can authorize a scan. |
| The calling agent (over MCP or the CLI) | **Untrusted to authorize. Trusted to ask.** It can name a manifest by path; it cannot supply, edit or widen one. |
| A scanned endpoint's response bytes | **Wholly untrusted.** Hostile input by definition. |
| The host filesystem and its state directory | Trusted for integrity; the event log defends against truncation and gaps, not against an attacker with write access. |
| `bathy-packetd`, when it exists (Milestone 6) | Will run privileged. Its IPC boundary will be the highest-value parsing surface in the project. |

## 2. What bathy defends against

### 2.1 A hostile response from a scanned endpoint

This is the primary adversary and the one the architecture is shaped around. An
endpoint that answers a probe controls every byte that comes back and may be
trying to hang, exhaust, or exploit the scanner.

- **Every read is bounded twice**: by a byte cap and by a deadline that covers
  the whole read rather than each individual `recv`. A peer that dribbles one
  byte per second forever, or floods without end, does neither harm — the
  deadline covers the aggregate, and the cap covers the volume.
- **No panics in parsing paths.** Every function that consumes network bytes
  returns `Result`. `unwrap()`, `expect()` and panicking slice indexing are
  denied by lint in `bathy-probe` and `bathy-interpret`.
- **Every parser of untrusted bytes is fuzzed.** Interpretation, event-log
  parsing, canonical JSON and manifest loading each have a libFuzzer target,
  seeded from real recorded data rather than from random bytes, with counters
  that report which rules were actually reached. `interpret`'s target asserts
  that every returned byte span is a valid index range into the input, in three
  forms — not inverted, not past the end, and usable to slice the response —
  because a bad span would panic the consumer that slices with it.
- **Probes never decide meaning.** A probe returns raw bytes; interpretation
  happens in a pure crate with no I/O, no clock and no randomness. A hostile
  response cannot reach a socket, a file, or a clock through the interpreter,
  because the interpreter has none.
- **`#![forbid(unsafe_code)]`** in every crate, so a parsing bug is a wrong
  answer or a panic, not memory corruption.

### 2.2 A confused or adversarial calling agent

An agent driving this tool may be jailbroken, prompt-injected by content it read
elsewhere, or simply wrong. The defence is that **the agent has no path to
authorization.**

- **No tool input schema has a `command`, `args`, `flags`, `argv` or `raw`
  field.** There is no string that becomes a command line.
- **A scope is named by a path.** No tool accepts a manifest inline or by id, so
  an agent cannot author, widen, or extend its own authorization. The most it
  can do is name a file the operator already wrote.
- **Scope enforcement is in two layers, and the second is not bypassable by an
  adapter.** The CLI and MCP adapters refuse upfront, before a scan record
  exists. `bathy-engine`'s scheduler checks scope identity, expiry and
  per-target authorization *on the actual emission path*, so a caller who skips
  the adapter entirely — a library user, a future adapter — gets the same
  refusal. See the design paper, §5.
- **A scan wider than a configured threshold does not start.** It returns an
  `input_required` result carrying an `elicitation/create`, and the client is
  expected to put the question to a human.

**The approval token is an authorization boundary, and it is treated as one.**
The `requestState` blob round-trips through the client, so on the retry it is
untrusted input that merely happens to have originated here. A forgeable one is
a scope bypass: a caller hands back a blob claiming a human approved a scan no
human ever saw. Four properties, each closing a separate way in:

1. **Integrity** — sealed with HMAC-SHA256 under a key that never leaves the
   process. A flipped byte fails to open.
2. **Binding** — the seal's associated data carries the principal it was issued
   to *and* a digest of the arguments it was issued for, under a domain
   separator. An approval for a `/24` cannot be replayed against a `/8`, and one
   issued to caller A cannot be redeemed by caller B. Opening without the
   binding fails closed.
3. **Expiry** — a TTL is sealed in. A human's approval of a scan is an approval
   of *that* scan, now, not a standing grant.
4. **Single use** — the seal cannot provide this, since a copy of a valid blob
   is a valid blob, so redemption records the nonce and refuses a second
   presentation.

Every rejection returns before a task record is created and before the scheduler
is constructed, so no rejected path emits a packet.

On stdio there is no authenticated principal — the client is the process that
launched this one, and `clientInfo` is self-asserted — so the binding to a
principal is defence in depth rather than authentication. The isolation that
actually holds today is that one server process serves one client. The binding
still does real work: it stops a blob from being carried between two clients of
a shared deployment, which is the arrangement a future transport would create.

### 2.3 An over-broad scope manifest

A manifest is a grant of permission, and the defences here are about limiting
what a mistake in one costs.

- **Expiry is mandatory.** `not_after` is a required field and a manifest
  without one does not load. There is no never-expires manifest — though
  nothing stops someone naming a distant date, which is a choice they make
  visibly rather than a default they inherit.
- **Deny sets are subtracted from allow sets**, so a broad allow can be carved
  down without rewriting it.
- **Hard budgets travel with the manifest**: a packet ceiling, a runtime
  ceiling and a packets-per-second ceiling, accounted in a ledger and enforced
  on the emission path — not advisory, and not reset by a resume.
- **Refusal is total, never partial.** A manifest covering 250 of 256 targets
  refuses the scan rather than scanning the 250 and staying quiet about the
  rest.
- **Loopback and IPv6 are refused regardless of what the manifest says.** No
  manifest can authorize either in v0.1. For IPv6 this is a blanket refusal
  adopted precisely because three rounds of prefix-by-prefix hardening each
  closed an enumerated set of IPv4-in-IPv6 embedding schemes and each was
  followed by a review finding one more.
- **Scans are deliberately identifiable.** The HTTP probe sends a `User-Agent`
  naming the tool and linking to the repository; the SMTP probe identifies
  itself as `bathy.invalid`. A third party who receives this traffic can tell
  what it is and who to contact. There is no flag to remove that.

### 2.4 A caller who wants to know what actually happened

Not an adversary, but a defended-against failure mode: a claim nobody can check.
Every finding cites content-addressed bytes and the id of the rule that fired;
`evidence.get` returns exactly those bytes and `fingerprint.explain` returns
what the rule looks for and where it came from. The event log is append-only and
gap-free, and is made durable before the SQLite index derived from it.

## 3. What bathy does not defend against

Stated plainly, because a threat model that lists only wins is marketing.

- **A malicious operator with legitimate scope.** Someone who can write the
  manifest can authorize a scan of anything the manifest names. bathy is a
  scanner; it enforces a scope, it does not adjudicate whether the scope is
  honest. Authorization to scan a network is a question about the world, and
  nothing in this process can answer it.
- **A compromised host running `packetd`** (Milestone 6, not yet present). A
  privileged daemon on a compromised host is a privileged process under the
  attacker's control. The mitigations planned are a narrow IPC surface, a
  fuzzed line protocol, and no policy decisions inside the daemon — but if the
  host is owned, the daemon is owned.
- **An attacker with write access to the state directory.** The event log
  detects truncation and sequence gaps, which catches corruption and partial
  writes. It is not a tamper-evidence scheme against someone who can rewrite
  the files and recompute what they need to.
- **An attacker who can edit the scope manifest.** That file *is* the
  authorization. Manifests may carry a `signature` field, and its presence is
  recorded, but v0.1 **does not verify signatures** and nothing downstream may
  act on an unverified one. Protect the file with filesystem permissions.
- **Traffic analysis, or being noticed.** bathy is deliberately identifiable and
  paced. It is not trying to be quiet.
- **Denial of service against the scanned network.** Budgets and rate ceilings
  bound what a single scan emits, and the defaults are conservative, but a
  scanner is a traffic generator and an operator who raises the ceilings can
  generate traffic. The ceilings are a safety rail for mistakes, not a
  guarantee to third parties.
- **Malicious dependencies.** `cargo deny check` runs in CI over advisories,
  licenses, bans and sources, and `Cargo.lock` is committed. That is supply-chain
  hygiene, not a defence against a targeted attack on a crate this project
  depends on.
- **The correctness of what a scanned service claims about itself.** A banner
  saying `OpenSSH 8.9` is evidence that something sent those bytes, and nothing
  more. Confidence values describe how specific the *rule* was, never how honest
  the endpoint was.

## 4. Permanent non-goals

These will not be added, and a feature request for them will be declined:

- **Detection evasion** of any kind — fragmentation, timing games, decoys,
  spoofed sources, randomized identification strings.
- **Anonymization** — proxying, source-address spoofing, or any mode that makes
  the traffic harder to attribute to its operator.
- **Removing the identifying `User-Agent` and SMTP identity.**

The reasoning is that the population of people helped by an evasive scanner and
the population helped by an auditable one barely overlap, and this tool is for
the second. A tool that an agent can drive at machine speed should be one whose
traffic a third party can recognise, attribute and complain about.

## 5. Reporting a vulnerability

`SECURITY.md`, carrying the disclosure contact and the response-time
expectation, is Task 5 of this milestone and **is not in this commit**. Until it
lands, report privately to the repository owner rather than in a public issue.
