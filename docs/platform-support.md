# Platform support

| Platform | v0.1 position |
|---|---|
| Linux (x86-64, aarch64) | **Supported.** The primary target. CI's `test` job runs here and `lab/run.sh test` runs here. |
| macOS (aarch64) | **Best-effort.** Everything builds and the test suite passes; three specific things differ, listed below. |
| Windows | **Out of scope for v0.1.** A licensing constraint, described in full below. |
| Anything else | Untried. Nothing in v0.1 is knowingly Linux-only outside `bathy-packetd`, which does not exist yet, but nothing else has been run. |

## Linux is the target, and that has a consequence for macOS developers

Development on this project happens largely on macOS. That is a hazard rather
than a preference, and two real failures went unnoticed because of it:

1. An assertion behind `#[cfg(target_os = "linux")]` never compiled locally, so
   a change that broke it was green on every developer machine.
2. Two test fixtures depended on the kernel handing out ephemeral ports in
   ascending order. macOS does; Linux does not.

The fix was not "be more careful". It is `cargo run -p xtask -- linux-gate`,
which runs `ci.yml`'s own `test` job steps — read out of `ci.yml` rather than
restated — inside a Linux container over the working tree, as your own uid
rather than as root. Run it before claiming a change works.

## What differs on macOS

**The integration lab is not reachable from the host.** Docker Desktop runs the
daemon inside a VM whose bridge networks never enter the Mac's routing table, so
a container on a user-defined bridge answers neither a ping nor a TCP connect
from the host. This is measured, not assumed. Loopback aliasing is not a
workaround, because binding `127.0.0.2` requires root. The consequence is
built into the deliverables rather than papered over:

- The five lab conformance tests are `#[ignore]`d by default, listed as
  **ignored** rather than omitted, and when run with `--ignored` against an
  unreachable lab they write the reason and the fix straight to the process's
  stderr and return.
- `lab/run.sh test` sets `BATHY_LAB_REQUIRED`, which turns that skip into a
  failure — so the one command whose purpose is to test the lab cannot pass
  without a lab.
- `bench/compare.sh` detects that the host cannot route to `labnet` and runs
  every scanner inside one Linux container attached to it instead. On macOS
  that path is always taken.

**Loopback is refused, on every platform.** `ScopeManifest::allows` returns
false for `127.0.0.0/8`, so no manifest can authorize a scan of the machine's
own loopback interface. This is a blast-radius decision rather than a platform
one, but it bites first on a developer machine, where loopback is the obvious
thing to try. Use a non-loopback address of an interface you own.

**Raw sockets, when they arrive, will differ.** v0.1 emits only unprivileged
TCP connects and needs no special privilege anywhere. Milestone 6's
`bathy-packetd` will need raw sockets, and the mechanism is not the same: Linux
has `CAP_NET_RAW`, and macOS gates `/dev/bpf*` by device-node permissions, with
no capability model to grant a subset. Expect the macOS privileged path to
require either running the daemon as root or hand-managing BPF device
permissions. Nothing in v0.1 depends on this.

## Windows

**Windows is out of scope for v0.1, and the reason is a license, not a
technical judgement.**

To be precise about what is and is not affected:

- The **unprivileged** parts of bathy — TCP connect scanning, the probes, the
  interpretation engine, the event log, the CLI, the MCP server — have no
  platform-specific code and no known reason not to work on Windows. They are
  simply not built or tested there: there is no Windows CI job, so any claim of
  support would be a claim nobody checks. This is the same standard applied to
  every other claim in this repository.
- The **privileged** parts — Milestone 6's SYN scanning and ICMP host discovery
  — need a packet-capture and packet-injection layer. On Linux that is raw
  sockets in the kernel. On Windows the dominant such layer is **Npcap**, and
  Npcap's license is where the problem is.

Npcap is distributed under the Npcap License. It is not an OSI-approved
open-source license: as published, the free edition limits the number of
systems on which it may be installed, redistributing it inside another product
requires a separately negotiated OEM license, and modification and
reverse-engineering are restricted. bathy is Apache-2.0 OR MIT and is intended
to be redistributable by anyone, packaged by distributions, and vendored into
other projects without anyone having to negotiate a second license. A dependency
whose terms do not permit that would make the project's own license terms
misleading, which is a worse outcome than not supporting a platform.

Two things this is explicitly **not**:

- It is not a statement that Npcap is a bad piece of software or that its terms
  are unreasonable. They are the terms its authors chose, they are clearly
  published, and they are a legitimate way to fund maintained software. They are
  simply incompatible with *this* project's redistribution model.
- It is not permanent. If a packet-capture layer for Windows exists under terms
  compatible with Apache-2.0 OR MIT — or if Npcap's terms change — the
  constraint disappears and Windows becomes an ordinary porting question.

This summary is a snapshot, and license terms change. Read the current terms
yourself before relying on it.

### If you need bathy on Windows today

Run it in WSL2 or a Linux VM. The unprivileged scan path is the whole of v0.1,
it has no Linux-specific code, and it does not need the capture layer that this
section is about.
