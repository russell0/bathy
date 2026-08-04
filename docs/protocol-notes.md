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
  real results from every tool.

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

### Refusals

A refusal an agent can act on — an unknown scan, a digest that names nothing, a
manifest that will not load, a cursor outside the declared range — is a tool
result with `isError: true` carrying a stable code in a JSON text block, not a
JSON-RPC error. Clients render protocol errors opaquely, so a protocol error
tells the caller "it failed" and not why. The codes are the ones the
command-line surface already publishes for the same conditions.

The one exception is an unknown tool name, which genuinely cannot be routed and
gets `-32602` with the list of tools that do exist.

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
