# Security policy

This document covers two different things that both belong here: how to report a
vulnerability **in** bathy, and what bathy will and will not do **to** the
networks it is pointed at. The second half is a security policy in the older
sense — the boundary the tool holds, and the features it refuses to grow.

`docs/threat-model.md` is the long form: what is defended, what is not, and who
is trusted. This document is the short form plus the disclosure path.

## Reporting a vulnerability

**Report privately through GitHub Security Advisories** on this repository:
<https://github.com/russell0/bathy/security/advisories/new>. That is the channel
monitored for this purpose, and it keeps the report private until there is
something to disclose. If the link does not work for you — private reporting can
be turned off, and a fork will not have it — open an ordinary issue containing
**only** the words "security report, please open a private advisory", with no
details, and one will be opened for you.

Please do not open a public issue that contains the details. Please do not
demonstrate a finding by scanning a third party.

**Response times.** These are commitments, not aspirations, and they are
deliberately modest so that they can be met by a project this size:

| Stage | Target |
|---|---|
| Acknowledgement that the report was received and read | **3 business days** |
| An assessment: affected versions, severity as we see it, and whether we agree it is a vulnerability | **10 business days** |
| A fix or a written decision not to fix, and a coordinated disclosure date | **90 days** from acknowledgement |

If you have not heard anything within the acknowledgement window, assume the
notification was lost rather than ignored, and comment on the advisory thread to
bump it.

There is no bug bounty and no PGP key. If a report needs an encrypted channel
beyond what GitHub advisories provide, say so in the advisory and one will be
arranged.

**What we consider in scope.** Anything that lets a caller emit a packet outside
an active scope manifest's allow set; anything that lets a caller forge an
approval; a panic, hang, or unbounded allocation reachable from bytes a scanned
endpoint controls; a path that writes evidence a later read cannot detect as
tampered; and any leak of the operator's credentials or filesystem beyond what
the scan requires.

**What we do not consider a vulnerability.** That bathy identifies itself (see
below — that is deliberate and it is not going to change); that a scan is
visible to the network it runs on; that an operator with a valid manifest can
scan what the manifest says. A malicious operator with legitimate scope is
explicitly outside the threat model, and `docs/threat-model.md` §3 says why.

## Supported versions

v0.1 is the first release. Until v1.0 there is exactly one supported version:
the latest tag. Security fixes are not backported to earlier `0.x` tags, because
maintaining two lines with this team size would mean doing neither well.

## Authorized use

**bathy is for scanning networks you are authorized to scan.**

Scanning hosts you do not have permission to scan may be unlawful in your
jurisdiction and may breach your provider's terms of service. That is the
operator's responsibility. The tool's responsibility is to make unauthorized
scanning hard to do by accident, and that is what the mechanisms below are for.

## The safety mechanisms, and where they live in the code

Each of these is a real mechanism with a real enforcement point, not a
convention. They are listed with their locations so a reader can check rather
than trust.

- **A scope manifest is mandatory.** `--scope <path>` is a required argument on
  every subcommand that can emit a packet. There is no default, no environment
  variable, and no flag to skip it, so omitting it fails inside argument parsing
  — before a state directory is opened or a request exists.
- **Deny by default.** A manifest names the address ranges it authorizes;
  anything it does not name is refused. `bathy-scope`'s policy also refuses
  loopback, link-local, multicast and the other reserved ranges outright, so a
  manifest cannot authorize them by naming them.
- **Manifests expire.** A manifest carries the instant it stops being valid, and
  validity is re-checked on every scan and on every resume, not once at load.
- **Enforcement is in three layers, and no layer is bypassable by the one
  above it.** The CLI and MCP surfaces refuse an out-of-scope request up front,
  before any record is written. `Scheduler::run` then re-checks — that the
  manifest is the one this scan was authorized under, that it is still
  unexpired, and that each individual target is inside its allow set — on the
  path packets actually leave by. A library caller that skips the first layer
  does not skip the second. `bathy-packetd`, the only process that can put an
  arbitrary packet on a wire, then decides the question a third time from its
  own session state, in code that shares nothing with `bathy-scope`.
- **No privileged scanning is reachable in v0.1.** `bathy-packetd` is the only
  component that holds a capability, and nothing a user can run starts it:
  there is no CLI flag and no MCP tool argument that points the engine at a
  daemon, and the crate is not published, so `cargo install bathy` installs no
  privileged binary. This is deliberate — SYN scanning is more intrusive than
  connect and the approval policy does not yet distinguish them — and
  `cargo run -p xtask -- check-packetd` fails if a shipped surface ever
  reaches for it.
- **Refused in full, never trimmed.** If a manifest fails to cover a single one
  of the targets, the whole scan is refused. bathy does not scan the part it is
  allowed to scan and stay quiet about the rest.
- **Hard budgets.** Every request carries `maximum_packets`,
  `maximum_runtime_seconds` and `maximum_packets_per_second`. They are accounted
  in `bathy-scope`'s budget engine and enforced by the scheduler; they are
  ceilings, not hints, and a scan that reaches one stops.
- **Bounded reads.** Every read from a scanned endpoint is bounded twice, by a
  byte cap and by a deadline covering the whole read rather than each `recv`, so
  a peer that dribbles or floods cannot hold a scan open.
- **Deliberately identifiable traffic.** The HTTP probe sends
  `User-Agent: bathy/<version> (+https://github.com/russell0/bathy)`. The SMTP
  probe sends `EHLO bathy.invalid` (RFC 2606 §2 reserves `.invalid`, so it can
  never be a real domain). Someone who notices bathy's traffic on their network
  can find out what it is, and who to ask about it, in one search.

## Non-goals: evasion and anonymization

**Detection evasion and anonymization are permanent non-goals of this project.
Feature requests for them will be declined.**

This is a settled position rather than a backlog item, so it is worth stating
exactly what it covers. bathy will not grow:

- decoy or spoofed source addresses;
- idle/zombie scanning, or any technique whose purpose is to make the scan
  appear to originate somewhere else;
- fragmentation, bad checksums, overlapping segments, or other IDS/IPS-evasion
  packet crafting;
- proxy, Tor, or relay integration offered as a way to obscure the scan's
  origin;
- randomized or absent tool identification — no "stealth mode", no flag to strip
  the `User-Agent`, no configurable `EHLO` domain;
- timing profiles whose stated purpose is staying under a detection threshold.
  Rate limiting exists and is encouraged, but it exists to be a good neighbour
  and to respect budgets, and it will be documented as that.

The reasons, in the order they actually matter:

1. **It is what makes the authorized-use statement mean something.** A tool
   whose stated purpose is authorized scanning, and whose feature list is built
   around not being noticed by the network's owner, is contradicting itself. If
   an operator is authorized, hiding from the network's defenders costs them
   nothing to skip; if they are not authorized, this project should not be
   helping.
2. **It is what makes bathy safe to hand to an autonomous agent.** The whole
   premise here is that a calling agent can be trusted to *ask* and not to
   *authorize*. Every capability that makes a scan harder to attribute makes a
   confused or manipulated agent more dangerous, and attribution is the last
   line of defence when the earlier ones are misconfigured.
3. **Evasion is an arms race that pulls a project's design out of shape.** The
   features that win it are the ones that make traffic unusual, and this project
   would rather spend that effort on evidence, provenance, and being
   reproducible.

**What this is not.** It is not a claim that evasion techniques are illegitimate
research, and it is not a criticism of tools that implement them — some of them
are excellent tools with a different job. Red-team tooling that must model an
attacker's traffic is a real need and bathy is the wrong instrument for it. This
project's positioning is technical and comparative: a different interface for a
different consumer, and the measurements are in `docs/benchmarks.md`.

**Adjacent things that are *not* covered by this non-goal**, because a rule that
swallows the neighbouring cases is a rule people route around:

- Rate limiting, connect timeouts and concurrency ceilings. These are politeness
  and budget controls and they are supported.
- Choosing a smaller port set, or scanning fewer hosts. Scanning less is always
  allowed.
- Running from a host of the operator's choosing. bathy does not care which
  interface it runs on; what it will not do is misrepresent it.
- Sending no payload. The first touch of every port is a plain TCP connect that
  sends nothing, and two of the eight probes (`ssh-banner-v1`,
  `mysql-greeting-v1`) send nothing either, because those protocols have the
  server speak first and writing would corrupt the banner. Both are protocol
  facts rather than stealth features: the connection is still an ordinary,
  completed TCP connection from the operator's real address. Service
  identification can also be turned off entirely
  (`service_detection.enabled = false`), which leaves only the bare connect. It
  cannot be made anonymous.

## If you are on the receiving end of a bathy scan

The `User-Agent` or `EHLO` you are looking at came from an operator, not from
this project. bathy has no telemetry, no callback, and no central service; there
is nobody here who knows who scanned you. If the traffic is unwelcome, the
address it came from is the one to contact — it is a real address, and this
project has deliberately made sure it stays one.

If you believe bathy itself behaved incorrectly — ignored a rate limit, kept
connecting after a scan was cancelled, sent something it does not document —
that is a bug and the disclosure path at the top of this document is the right
one to use.
