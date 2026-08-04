# MCP protocol notes

What `bathy-mcp` implements, why, and what it deliberately does not. Written
during M5 Task 4; the research it rests on is
`.superpowers/sdd/mcp-spec-research.md`, discharged against primary sources on
2026-08-03.

---

## The revision implemented: `2026-07-28`

**And the single most important fact about it: it is not an increment on the
MCP most documentation describes.** Revision `2026-07-28` dropped the
`initialize` handshake and protocol-level sessions entirely. Everything from
`2025-11-25` back is what the specification now calls *Legacy*, and that is
what nearly all tutorials, blog posts and model training data describe. A
server written from recall is a Legacy server, and a Legacy server hangs
against a Modern client: it waits to be initialized, and nothing ever
initializes it.

Consequences, each of which is a property of the shipped code:

| The revision says | What this server does |
|---|---|
| No handshake. The protocol version and the client's capabilities ride in each request's `_meta`. | Any request may come first. The version is read from `_meta` per request. |
| Servers **MUST** implement `server/discover`. | Implemented, advertising exactly the one version implemented, the tools capability, and the server identity. |
| An unsupported version is answered `UnsupportedProtocolVersionError` (`-32022`) with `data.supported`. | `supported_protocol_versions` is narrowed to `["2026-07-28"]`, which is what produces that error for anything else. |
| `outputSchema` is optional, but binding once declared: "Servers MUST provide structured results that conform to this schema." | All eleven tools declare one, and every success populates `structuredContent`. |
| A tool returning structured content SHOULD also return the serialized JSON in a text block. | Every success carries the identical document as JSON text in `content`. |
| Roots, Sampling and Logging are deprecated. | None are used. Diagnostics go to standard error. |

### Two SDK defaults that point at Legacy, overridden on purpose

Both are recorded here because they are the exact shape of the trap above, and
both would have produced a plausible-looking server that was quietly Legacy.

1. **`ProtocolVersion::default()` is `2025-11-25`.** `ServerInfo::new` uses it,
   so a server that does not set the field advertises a Legacy version. It is
   set explicitly in `get_info`. It is load-bearing on exactly one path — the
   `initialize` a Legacy client still opens with, where it is the fallback the
   SDK negotiates down to — and
   `an_initialize_from_a_legacy_client_is_answered_with_the_version_we_implement`
   is the test that covers it. That test exists because the first mutation run
   found the assignment was not covered by anything.
2. **`supported_protocol_versions()` defaults to every version the SDK knows** —
   five, four of which this server does not implement. Narrowing it is what
   turns "an old client is accepted and then fails on the first feature it
   relies on" into "an old client is told `-32022` and the one version it can
   use instead".

### Five more SDK defaults, found by sweeping rather than by report

M5 Task 4's review found a third — `server/discover` advertising `ttlMs: 0,
cacheScope: "private"` — and asked whether there was a fourth rather than for
that one to be fixed. There were four more, and the sweep is recorded here
because the class is "a value the SDK chose and nobody read", which is not a
class a reader can see the boundary of from any one instance.

3. **`DiscoverResult::from_server_info` hard-codes `ttlMs: 0` and
   `cacheScope: private`.** Spec-legal; `0` means immediately stale. A
   discovery answer here is one protocol version, one capability and eleven
   compiled-in tools, so it is published on the same terms as `tools/list`,
   from the same constant.
4-7. **`complete`, `list_prompts`, `list_resources` and
   `list_resource_templates` default to a *successful empty result*.** A server
   declaring only `tools` answered `prompts/list` with `{"prompts": []}` —
   "I have prompts and there are none", where the truth is "I do not implement
   prompts". The SDK is already inconsistent about this: `prompts/get`,
   `resources/read` and `logging/setLevel` default to `-32601`, so five of the
   nine undeclared methods told the truth and four did not. All nine now do,
   and `a_capability_this_server_does_not_declare_is_answered_as_absent_not_as_empty`
   asserts it over the list.

### `_meta` server identity

The specification says a server **SHOULD** include
`io.modelcontextprotocol/serverInfo` in every result's `_meta`. `rmcp` puts it
on `server/discover` and on nothing else; `tools/list` and `tools/call`
returned `_meta: null`. Both carry it now, including on a refusal — which is
the result a client is most likely to be holding when it wants to know whose
server said no — and a client that caches a tool list for an hour benefits
most from knowing whose list it cached.

---

## The SDK: `rmcp` 3.1.0, and its beta caveat

Official, from the `modelcontextprotocol` organization. MSRV 1.88, edition
2024, released 2026-07-31.

**The official MCP blog rates the Rust SDK's `2026-07-28` support "beta"**,
against Tier 1 for TypeScript, Python, Go and C#, while the SDK's own README
says "stable". The blog is the more authoritative signal and this project
treats it as such: expect rough edges around the newest features (Multi
Round-Trip requests, `server/discover`, the Tasks extension) rather than
parity with the TypeScript reference.

In practice, on the surface this task needed: **`rmcp` expressed everything the
specification required, with no workaround.** Specifically it provided
`DiscoverResult` and the `-32022` error with `data.supported`; `resultType`
including `input_required`; `InputRequiredResult` with `inputRequests` and
`requestState`; `ttlMs`/`cacheScope` on `tools/list`; all four tool
annotations; `structuredContent`; and — behind the `request-state` feature —
`RequestStateCodec`, an HMAC-SHA256 seal with associated-data binding and a
TTL. Two caveats worth writing down rather than discovering later:

- **The codec does not, and says it does not, provide single-use.** A copy of a
  valid token is a valid token. Replay prevention is server-side work, and it
  is done in `approval.rs`.
- **The SDK does not validate a result against the tool's declared
  `outputSchema`** when `call_tool` is implemented directly on `ServerHandler`
  rather than through the macro-generated router. Conformance is therefore
  asserted by this project's own tests, against the advertised schema, over
  real results from every tool — and that checker is the *only* thing behind
  the declaration on this side of the wire. See "Structured results" below for
  what it checks and what it cannot.

### Why this crate does not use `rmcp`'s tool macros

The default feature set enables `macros`. They are switched off. A macro that
derives a tool's schema from a function signature would put a second spelling
of the contract in the tree, next to the one in `bathy-types`/`bathy-query`
that `xtask check-schemas` drift-checks. One contract, one spelling.

---

## Transport: stdio, and nothing else

`bathy serve mcp` speaks newline-delimited JSON-RPC on its own standard input
and output. Standard output is the transport, so nothing else is written
there; diagnostics go to standard error.

The old two-endpoint HTTP+SSE transport is formally **Deprecated** in this
revision, the `Mcp-Session-Id` header and the persistent GET stream are
**removed**, and **SSE stream resumability is removed** — a broken stream means
the client re-issues the whole request with a new id, and there is no
protocol-level redelivery.

Nothing here assumes otherwise, and the guarantee is structural rather than
behavioural: the crate enables `transport-io` and no HTTP transport feature at
all, so none of that machinery is compiled in.
`nothing_shipped_speaks_the_deprecated_transport_or_assumes_a_stream_can_resume`
asserts it against the manifest.

If a remote deployment is ever wanted, the target is **Streamable HTTP**, and
the authorization changes that come with it (RFC 9207 `iss` validation, Client
ID Metadata Documents in place of the now-deprecated Dynamic Client
Registration) become relevant at that point and not before.

---

## Structured results

Every tool declares an `outputSchema` generated from a Rust type in
`bathy-types` or `bathy-query`, committed under `schemas/` and drift-checked.
Every successful `tools/call` returns:

- `structuredContent`: the typed result.
- `content`: one text block holding the identical document as JSON, for
  clients that predate structured results.

`result.diff` is the case worth naming: its `outputSchema` **is**
`schemas/scan-diff.json`, the document M5 Task 2 published, rather than a
shape re-derived in the server crate. A test compares the advertised schema
against the committed file, so the two cannot drift apart.

**`rmcp` does not validate a result against `outputSchema`** when `call_tool`
is implemented directly, as it is here. Nothing in the SDK stands behind the
declaration, and the specification asks *clients* to validate — so the only
thing behind AC-5.28 on this side of the wire is `conforms` in
`crates/bathy/tests/mcp.rs`, and it is only as strong as its own coverage. It
was weaker than the schemas it enforced until M5 Task 4's fix round: `pattern`
was unimplemented and these documents declare it 29 times, on every scan id,
scope id and digest, so `digest: "blake3:zzzz"` passed as a conforming result.
That function now carries a written-out list of the keywords it implements and
the ones it does not, and a test module that violates each keyword it claims.
A validator whose gaps are known is worth more than one assumed complete.

### Refusals

A refusal an agent can act on — an unknown scan, a digest that names nothing, a
manifest that will not load, a cursor outside the declared range — is a tool
result with `isError: true` carrying a stable code in a JSON text block, not a
JSON-RPC error. Clients render protocol errors opaquely, so a protocol error
tells the caller "it failed" and not why. The codes are the ones the
command-line surface already publishes for the same conditions.

There are two exceptions, and both are conditions the specification names a
protocol error for:

- an unknown tool name, which genuinely cannot be routed, gets `-32602` with
  the list of tools that do exist;
- a `scan.start` above the approval threshold from a client that declared no
  `elicitation` capability gets **`-32021`** with
  `data.requiredCapabilities`. MRTR's Server Requirements say a server
  **MUST NOT** send an `inputRequests` the client has not declared support
  for, and the base protocol says a request that cannot be processed without
  an undeclared capability **MUST** be answered `-32021` naming it. The scan
  does not start: the threshold has been crossed and no human has approved,
  so refusing is the answer rather than a fallback. The check sits where the
  challenge would be minted, not at the top of the call, because a scan at or
  below the threshold asks nobody and requires no capability.

A **policy denial is not a refusal of this kind**. It is a correct answer from
an authorization system, so it keeps its structured slot — the output shapes
were designed with a place for it — and is flagged `isError: true` so an agent
does not read it as success and retry forever.

---

## The approval flow: MRTR, not a bespoke status field

**This is where the source design document and the M5 plan were both wrong, and
the correction is an implementation change rather than a wording one.**

The plan framed approval as a choice between "elicitation (MCP)" and
"`input_required` (A2A)", as if they were competing vocabularies. They are
not. In this revision `input_required` **is** MCP's own vocabulary, and it
*wraps* elicitation rather than competing with it: the standalone
server-to-client `elicitation/create` request is gone, and elicitation now
exists only embedded inside a **Multi Round-Trip Request**.

So `scan.start` above the configured threshold returns a `tools/call` result
with `resultType: "input_required"`, whose `inputRequests` map carries an
`elicitation/create` describing the scan awaiting approval, plus an opaque
`requestState`. The client puts the question to a human and **retries
`scan.start`** with a new JSON-RPC id, `inputResponses`, and that
`requestState` echoed back byte-for-byte. The retry is what mints the real
handle.

A `resultType: "complete"` result carrying a bespoke
`{ status: "awaiting_approval", approval_id }` object — which is what the plan
originally specified — matches nothing in the specification, and no generic
client would act on it.

### `requestState` is attacker-controlled

It round-trips through the client, so on the retry it is untrusted input that
happens to have originated here. A forgeable one is a **scope bypass**: a
caller hands back a blob claiming a human approved a scan no human ever saw.
That is the same class of defect as an unconsulted scope check.

Four properties, each closing a different way in:

| Property | Mechanism |
|---|---|
| Integrity | HMAC-SHA256 under a 32-byte key from the operating system, generated per process and never written down. A server restart invalidating outstanding approvals is correct behaviour, not a limitation: a persisted key would let an approval issued by one run be redeemed against another. |
| Binding | The seal's associated data is `principal` + a digest of the call's arguments, canonicalized so re-serialization between rounds does not change it. Fail-closed: opening without it fails. An approval of a `/26` cannot be redeemed for a `/8`, and one issued to caller A cannot be redeemed by caller B. |
| Expiry | A TTL sealed into the token. Default ten minutes. An approval of a scan is an approval of that scan, then. |
| Single use | A server-side nonce set, spent **before** the answer is read — so a caller cannot probe for a live token by replaying it with a decline. The SDK's codec explicitly does not provide this. |

Anything that is not an explicit acceptance carrying `approved: true` is a
refusal: a missing entry, a decline, a cancel, an acceptance whose content says
`false`, an answer filed under some other key.

Every rejected path returns before a scan record is created and before a
scheduler is built, and the tests measure that with a real listener rather than
asserting it about the code.

**On the strength of the principal binding.** On stdio there is no
authenticated principal: `clientInfo` is what the client says it is, and the
isolation that actually holds is that one server process serves one client.
The binding is therefore defence in depth here. It does real work the moment
this server sits behind a transport where that is not true, which is precisely
when it would otherwise be forgotten.

**The threshold is server configuration** — `bathy serve mcp
--approval-threshold-targets N`, default 64 — and there is no tool argument for
it. Not a check that a caller did not set it: there is no field to set, and
`deny_unknown_fields` on every input type refuses one.

---

## "Anything the server can do, the CLI can do"

The premise that makes this surface auditable from a shell, and the one M5
Task 4's review found false: six documents differed between the two surfaces,
and four things the tools could do had no command-line spelling at all.
`result.query` took a filter (`state`, `service`, `min_confidence`,
`port_range`) that `bathy result query` could not express, so an agent could
ask a question an operator could not reproduce.

What holds now is stronger than the sentence was:

- **Each subcommand renders the corresponding tool's own typed output.** The
  documents are one Rust type, so their field sets cannot drift. `scan status`,
  `scan cancel`, `scan events`, `scan preview`, `result query`, `result diff`,
  `evidence get`, `explain` and both halves of `scan start`/`scan resume` that
  decide anything are one function each, in `bathy_mcp::tools`.
- **The comparison is generated from the advertised tool list.**
  `every_advertised_tool_and_its_subcommand_answer_the_same_question_the_same_way`
  iterates `tools/list` and matches on the name with no wildcard that passes,
  so a twelfth tool fails the suite until somebody writes down how its
  subcommand answers the same question.
- **Two differences are intended, declared and asserted.** `scan events`
  streams line-delimited events where the tool returns
  `{events, next_cursor, has_more}` — a JSON-RPC result is one value and needs
  a cursor; the command's contract is line-delimited JSON on stdout and
  `--follow` has no last page to attach one to. The test asserts the events are
  equal *and* that the envelope is exactly those two extra keys, so a new field
  fails rather than passes. `scan start` and `scan resume` print the tool's
  document and then a run summary, because this surface runs to completion the
  work the tool detaches.
- **A `scan events` read that is not following is unbounded, and `--limit` has
  no default.** This is the one behaviour the M5 Task 4 fix review sent back.
  `--limit` briefly defaulted to 200, which made a 402-event log answer with
  200 lines on stdout, exit 0, and the notice that there was more on stderr
  alone — so `bathy --json scan events --scan X > events.jsonl` silently became
  a *prefix* of the answer, and a consumer reading that file had no in-band way
  to tell. Silent truncation with a success code is the same defect shape as a
  usage error that exits 0 with an empty stdout, which this project has already
  fixed once.

  Of the three remedies on the table — leave a non-following read unbounded,
  signal truncation in band, or exit non-zero on truncation — the first is the
  one taken. A continuation record on stdout would put a non-event into a
  stream whose entire contract is one event per line, so every consumer would
  have to learn a second record shape to stay correct; and a non-zero exit
  would report a *success* (the caller got exactly the bound it asked for) as a
  failure, and would need a code the exit table does not have. Leaving the read
  unbounded costs nothing, because the bound stays fully expressible: `--limit`
  is still the same bound the `scan.events` tool takes, the parity comparison
  still passes it explicitly and still binds, and a truncation now only ever
  happens because a caller wrote one down — in which case the notice on stderr
  still says what is left and how to ask for it.

  Guarded by `a_read_that_is_not_following_returns_the_whole_log_rather_than_a_silent_prefix`,
  over a 1,402-event log: more than one page of the tool's own 1,000-event
  ceiling, so it proves the command pages to the end rather than that one large
  page happened to be enough.

Refusals differ in *envelope* on purpose and not in *code*: the tool marks a
policy denial `isError` with a structured result, the command exits 2 with a
failure document, and both carry the engine's own reason code.

---

## The cancel/resume handoff

**A scan whose stored status is terminal has already released its event log's
writer lock.** That is the contract, and it is what makes "poll `scan.status`
until it reports `cancelled`, then `scan.resume`" — the documented way to stop
and continue a scan — actually work.

It did not, briefly. `Scheduler::run` wrote `Cancelled` to the task store and
then released the log by *dropping* the scheduler, which for a detached scan
happens after the cancellation watcher is aborted and after a line is written
to standard error. Under load the drop lagged the status, so an agent that
polled for `cancelled` and immediately resumed opened the log while the
previous writer still held it and was told `log_unavailable`. M5 Task 4's fix
review caught this as a test failing about 2 runs in 20, but it was a race in
the product: the request was legitimate and the answer was confusing.

Three contracts were available and only one of them is right.

- *`scan.cancel` returns only once the writer has released.* Rejected.
  Cancellation drains probes already in flight, so this would make a cancel
  block for as long as the scan's longest outstanding probe — and `scan.cancel`
  is deliberately answerable for a scan running in **another process**, which
  this process cannot wait on at all.
- *`scan.resume` waits for the lock.* Rejected. It converts a genuine conflict
  — someone else really is scanning this — into a timeout, and makes the
  common, correct case (nobody is) pay a scheduling round-trip for the rare
  one.
- *Release before publishing the status.* Taken. The release is the first
  statement of `Scheduler::publish_terminal_status`, which is the only place a
  terminal `TaskStatus` is written, so the ordering cannot be broken by editing
  either write alone. `EventLog::release_writer_lock` exists precisely because
  a drop is not a schedulable event and an explicit release is.

Two consequences worth writing down:

- `log_unavailable` now means exactly one thing — **another writer is live** —
  rather than that plus "a finished run has not closed its file yet". A
  `Scheduler` is single-run: appending through a released handle is refused
  with `LogError::Released` rather than allowed to interleave.
- A refused resume is a **no-op**. Both surfaces now take the writer lock
  *before* clearing the cancel marker and stamping the scan `running`, so a
  refusal leaves the scan exactly as it was and can simply be retried.
  Previously the refusal happened after those two writes, leaving a scan marked
  `running` that no process was running and no poll would ever see finish.

Guarded by `a_terminal_status_is_not_published_until_the_event_log_is_released`
(both terminal shapes, deterministic — it reopens the log while the scheduler
that wrote the status is still alive) and by
`cancel_and_resume_round_trip_through_the_tool_surface`, which is the flake
this closed.

---

## Deliberately not implemented

### The `io.modelcontextprotocol/tasks` extension

The official Tasks extension is the specification's own generalized
`start`/`poll`/`cancel`, and it would be a plausible home for
`scan.start`/`scan.status`/`scan.cancel`. **This server does not use it, and
that omission is a decision, not an oversight.**

Why: the specification's own "Stateful Tools" guidance explicitly sanctions the
alternative — a server-minted opaque handle passed as an ordinary argument,
"because MCP has no protocol-level session" — and that is what `TaskHandle`
already is. Routing through the extension would mean the eleven-tool surface
either grows a twelfth shape or becomes two ways to do one thing, and the
eleven-tool surface is a published claim this project makes in its README.

What shipping without it costs, stated plainly rather than waved away: an agent
host that understands *only* the standard Tasks extension and cannot call
ordinary tools does not exist — `tools/call` is the base protocol and Tasks is
an opt-in extension on top of it. So no client is excluded. What such a host
loses is the *generic* affordance: its built-in task UI will not show a bathy
scan as a task, and it must instead be told to poll `scan.status`. That is a
convenience gap for one class of host, not a compatibility gap, which is why
the recommendation stands to revisit it in M7 rather than now. It is additive
when it lands.

### Progress notifications

`notifications/progress` exists and would work, but request-scoped
notifications flow on the response stream of the request they relate to, which
means holding that stream open. The Tasks documentation says plainly that
clients and intermediaries time this out past a few seconds. A scan runs for
minutes. `scan.events` — a cursor-paged read of the durable log — is the
mechanism, and it survives the client going away and coming back, which a held
stream does not.

### Resources

Evidence blobs are read-only, byte-exact, content-addressed content, so an
`evidence://<digest>` resource scheme is a plausible future addition. It is not
in the eleven, and the tool works; nothing precludes adding the scheme later.

---

## Deviations from the source design document and the M5 plan

Recorded so a future reader does not mistake any of them for drift.

1. **The approval mechanism.** As above: MRTR, not a bespoke
   `awaiting_approval` object. The plan's own instruction was "the spec wins".
2. **`evidence.get` returns hex, not base64.** The plan's contract table said
   base64; the command-line surface shipped `bytes_hex` in M5 Task 3, with a
   stated reason (no encoder dependency for one field, a human can compare it
   against a packet capture, and the digest naming the bytes is written the
   same way). Two encodings of one contract is worse than either, so the
   shipped one won, and the field name says which it is.
3. **`scan.preview`/`scan.start` take a `ScanRequestSpec`, not a
   `ScanRequest`.** `ScanRequest::authorization_scope_id` is the identity of
   the manifest that authorized the scan, and the server fills it from the
   document it loaded. Accepting a whole `ScanRequest` would have put a scope
   id in an input schema — which AC-5.38 forbids — and left a validation step
   ("refuse rather than reconcile a conflicting one") where an absence does the
   job.
4. **Three tools are not read-only, not one.** AC-5.29 listed `scan.resume`
   among the read-only ten. It emits packets exactly as `scan.start` does.
   `scan.cancel` changes local state. Annotating either as a read would
   understate what this program puts on someone else's wire.
5. **`bathy-mcp` is a 1.95-tier crate, not 1.88.** The plan put it in CI's
   `msrv` job because `rmcp` declares 1.88. That is a lower bound on this
   crate's floor, not its value: an adapter over the engine reaches
   `bathy-store`. Verified against real toolchains in both directions.
6. **`scope.validate`'s implementation is shared with `bathy scope validate`,
   which gained a `--targets` argument.** The tool takes targets and the
   command did not, so the tool surface could answer a question the command
   surface could not — the premise that makes this surface auditable from a
   shell. Two implementations of one authorization question is how two
   surfaces come to disagree about authorization.
