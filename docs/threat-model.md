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
| `bathy-packetd` (Milestone 6) | **Runs privileged**, and is the only process in this project that ever holds a capability. Its IPC boundary is the highest-value parsing surface here: every line it reads comes from a caller it does not trust, and a parsing bug there is a privilege-escalation bug rather than a denial of service. That surface is fuzzed (`fuzz/fuzz_targets/ipc.rs`), the crate carries the panic lints from its first commit, and the code that runs while the capability is held is measured on every CI run rather than asserted. **No shipped surface can start it** — see §3. |

## 2. What bathy defends against

### 2.1 A hostile response from a scanned endpoint

This is the primary adversary and the one the architecture is shaped around. An
endpoint that answers a probe controls every byte that comes back and may be
trying to hang, exhaust, or exploit the scanner.

- **Every read is bounded twice**: by a byte cap and by a deadline that covers
  the whole read rather than each individual `recv`. A peer that dribbles one
  byte per second forever, or floods without end, does neither harm — the
  deadline covers the aggregate, and the cap covers the volume.
- **No panics in parsing paths, held by the compiler.** Every function that
  consumes network bytes returns `Result`, and `clippy::unwrap_used`,
  `expect_used`, `indexing_slicing`, `panic` and `arithmetic_side_effects` are
  at **deny** level in `bathy-probe`, `bathy-interpret`, `bathy-scope`,
  `bathy-types`, `bathy-evidence` and `bathy-query` — every crate
  `gates::FUZZ_SURFACES` registers as an untrusted-input surface, and
  `check-panics` fails if a registered surface names a crate outside that set.
  In each crate's `lib.rs`, scoped `cfg_attr(not(test), ...)` so unit tests
  keep `unwrap()`. `cargo run -p xtask -- check-panics` holds the tree, the
  exceptions and the Global Constraint's own wording to each other, and is a
  CI step.

  **The history, kept because it is the point.** This paragraph previously
  admitted the opposite: the Global Constraints had claimed *since M1* that
  those lints were on, and no such lint existed anywhere in the tree — not in
  either named crate's `lib.rs`, not in `ci.yml`, not in any `Cargo.toml` lint
  table. The property was held by review and by the fuzz targets below, not by
  the compiler, and that was found by re-verifying documentation claims against
  code in M7 Task 4. Turning the lints on found **43 real hits** in the two
  originally named crates, every one of them a candidate panic on hostile
  input: the offset arithmetic behind six `matched_span` computations, two
  slices built from unchecked `+` in the MySQL and DNS parsers, an indexed TLS
  record header, and — worst — `Instant::now() + deadline` at the top of both
  bounded read paths, which panics on overflow and is the *only* thing bounding
  a probe against a peer that never stops sending.

  **The two `expect()` calls that remain** in `bathy-interpret` are on
  `LazyLock` regex compilation and on the confidence ladder's four constants.
  Neither touches a network byte, each is a site-level `#[allow]` with a stated
  reason, and each is backed by a test that fails if its reasoning stops being
  true. A crate-level `#![allow]` is refused by `check-panics` outright,
  because it would reproduce exactly the defect described above.

  **The three crates that were outside it, and now are not.** `bathy-types`
  (37 measured hits — `canonical_json`/`plan_digest` and `clock.rs`'s RFC 3339
  handling), `bathy-evidence` (15 — the event-log reader, over JSONL that may
  have been written by an older build, a crashed one, or a hand editor) and
  `bathy-query` (7 — `fold_events` over the same logs) were registered with
  their counts in `gates::PANIC_LINT_UNCOVERED` and as the
  `panic-lint-widening` deferral rather than claimed. All 59 are fixed and all
  three carry the lint; the deferral reported itself stale and was deleted, and
  the rule it was an instance of is now checked over `FUZZ_SURFACES` directly.

  The one this round was looking for was in `bathy-evidence`'s tail read:
  `read_records_from` bounds-checked a caller-supplied cursor against
  `last_sequence` and then indexed `offsets` with it — two different values,
  related by an invariant no function established. The cursor arrives from
  outside the process (`bathy scan events --after-sequence <n>`, and the
  `scan.events` MCP tool). **It was not reachable**: `scan_records` pushes an
  offset and advances the expected sequence in the same branch, so the two
  counts could not diverge for any byte sequence a log file can hold — checked
  by execution over every log buildable from nine adversarial line shapes,
  against the pre-fix code, in
  `no_log_file_and_no_cursor_can_put_a_tail_read_out_of_bounds`. The same sweep
  with the invariant broken by one panics with `index out of bounds: the len is
  3 but the index is 3` on a cursor of `3`, which is what a remotely-triggerable
  denial of service in the MCP server would have looked like. The two values are
  now one `RecordIndex`, so the check and the lookup are the same operation.

  **What the lint does not cover.** `clippy::indexing_slicing` does not see
  `str` indexing or a third-party `Index` impl, and `clippy::panic` does not see
  `assert!` or `unreachable!`. A hand sweep of the newly-covered crates found
  five such panics — `clock.rs`'s two `s[i..i + n]` sites behind `expect`s,
  `ids.rs`'s `&hex[i * 2..i * 2 + 2]`, `store.rs`'s `hex[0..2]`/`hex[2..4]`
  behind a `.expect("digest renders with prefix")`, and `canonical.rs`'s
  `map[*k]` on a `serde_json::Map`. All are fixed; none would have gone red.
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
- **`#![forbid(unsafe_code)]`** on every crate target but one, so a parsing
  bug is a wrong answer or a panic, not memory corruption. The exception is
  the `bathy-packetd` library root, `#![deny(unsafe_code)]`, with exactly one
  block: `prctl(PR_SET_NO_NEW_PRIVS, ...)` in `src/privilege.rs`. It passes no
  pointer and is on the startup path, not the parsing path — by the time that
  process reads a byte from anyone, it has dropped every capability and
  cannot open another socket.

### 2.2 A confused or adversarial calling agent

An agent driving this tool may be jailbroken, prompt-injected by content it read
elsewhere, or simply wrong. The defence is that **the agent has no path to
authorization.**

- **No tool input schema has a `command`, `args`, `flags`, `argv` or `raw`
  field.** There is no string that becomes a command line.
- **A scope is named by a path.** No tool accepts a manifest inline or by id, so
  an agent cannot author, widen, or extend its own authorization. The most it
  can do is name a file the operator already wrote.
- **Scope enforcement is in three layers, and no layer below the first is
  bypassable by the one above it.** The CLI and MCP adapters refuse upfront,
  before a scan record exists. `bathy-engine`'s scheduler checks scope
  identity, expiry and per-target authorization *on the actual emission path*,
  so a caller who skips the adapter entirely — a library user, a future
  adapter — gets the same refusal. And `bathy-packetd`, the only process that
  can put an arbitrary packet on a wire, decides the question again from its
  own `Init`, in code that shares nothing with `bathy-scope`. See the design
  paper, §5. **This said "two layers" until M6's whole-branch review**, which
  was the count before the privileged process existed; the same stale count
  was also in `SECURITY.md` and in the design paper's own §5 heading, and the
  `check-docs` claim that pins this sentence was pinning the outdated
  version.
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
- **A compromised host running `packetd`.** A privileged daemon on a
  compromised host is a privileged process under the attacker's control. The
  mitigations are a narrow IPC surface (one JSON line in, one out, with a hard
  line cap enforced at the reader), a fuzzed line protocol, a privileged window
  measured on every CI run at 130 lines across 15 functions, and every
  capability dropped and *verified dropped against `/proc/self/status`* before
  the first byte of input is read — but if the host is owned, the daemon is
  owned.

  **The daemon makes policy decisions, and this document said it did not.**
  Until M6's whole-branch review the mitigation list here read "no policy
  decisions inside the daemon", which is the opposite of what shipped and was
  the opposite of the design by the time it was written: `packetd` fixes an
  allowlist, a denylist and a packet ceiling from its `Init` and refuses every
  probe outside them itself (AC-6.9, AC-6.10, AC-6.11), in code that shares
  none with `bathy-scope`. That duplication is the milestone's central security
  claim, and delegating the decision instead would mean the one process that
  can emit an arbitrary packet takes an unprivileged caller's word for whether
  it may.

  **Nothing a user can run starts it.** `bathy-packetd` carries
  `publish = false` and is excluded from the published crate set, so
  `cargo install bathy` installs no privileged binary, and neither the CLI nor
  the MCP server has any way to point a scan at one. See §3's last bullet.
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

[`SECURITY.md`](../SECURITY.md) carries the disclosure contact, the
response-time expectations, and what is and is not in scope as a vulnerability.
Report privately through GitHub Security Advisories rather than in a public
issue.

This paragraph previously said `SECURITY.md` was "not in this commit" and told
the reader to contact the repository owner instead. That was true for exactly
one task and would have read as current forever after; a forward reference to a
document that has since landed is the same defect class as a claim that has gone
stale, and this project has three recorded instances of that in `README.md`
alone.
