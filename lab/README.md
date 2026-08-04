# The deterministic integration lab

A Docker Compose network of nine services on a private bridge subnet, with a
checked-in statement of exactly what listens on every address and port. It is
the oracle the rest of the project is verified against: because the images are
pinned by content digest, "is the scanner right" stops being a judgement call
and becomes an assertion against `ground-truth.json`.

Everything downstream depends on that being true. M6 cross-validates SYN
results against connect results here. M7's benchmarks compare scanners against
this subnet, which is what makes the comparison a measurement rather than an
anecdote. So **a wrong ground-truth file is worse than no lab at all** — it
would make every future disagreement look like our bug, or make a real bug look
like agreement.

```
lab/run.sh up       bring it up and wait for every service
lab/run.sh down     tear it down, including the generated TLS key
lab/run.sh status   what is running
lab/run.sh verify   re-derive the ground truth from the running containers
lab/run.sh test     up, run the conformance suite, down
```

## What is in it

| Address | Service | Image | Open TCP |
|---|---|---|---|
| `10.30.0.10` | `web-nginx` | `nginx` | 80 |
| `10.30.0.11` | `ssh-openssh` | `linuxserver/openssh-server` | 2222 |
| `10.30.0.12` | `db-postgres` | `postgres` | 5432 |
| `10.30.0.13` | `db-mysql` | `mysql` | 3306, 33060 |
| `10.30.0.14` | `cache-redis` | `redis` | 6379 |
| `10.30.0.15` | `mail-postfix` | `boky/postfix` | 25, 587 |
| `10.30.0.16` | `dns-bind` | `internetsystemsconsortium/bind9` | 53, 443, 853 |
| `10.30.0.17` | `tls-web` | `nginx` (TLS only) | 443 |
| `10.30.0.18` | `silent` | `alpine`, sleeping | *nothing* |
| `10.30.0.200`, `10.30.0.201` | — | — | *no host at all* |

Four of those rows are **narrowing controls**, and they are the reason a
false-positive assertion means anything:

- `silent` is up and answers nothing, so "reported down" and "reported open"
  are both wrong answers for it.
- `tls-web` serves 443 and **not** 80, while `web-nginx` serves 80 and **not**
  443. A scanner that reported every port open fails on both.
- `ssh-openssh` listens on **2222**, not 22, so 22 is shut on every host in
  the lab and is in the scanned port set on purpose.
- The two absent addresses are in the scanned set too.

`xtask check-lab` fails if any of those controls is removed — see
`the_scanned_port_set_contains_ports_that_are_shut_on_hosts_that_are_up` and
the seeded-violation tests in `xtask/src/gates.rs`.

No port is published to the host. The lab is reachable only from inside
`labnet`, so bringing it up does not change the exposure of the machine it
runs on.

## How the ground truth was derived, and how to re-derive it

Not by reading `docker-compose.yml`. That would be the assumption under test,
written down twice.

`verify-ground-truth.py` sweeps **all 65535 TCP ports** on every address in the
table above — including the absent ones — from a container inside `labnet`,
using nothing but Python's standard-library sockets. It shares no code, no port
table and no fingerprint data with `bathy`, and it consults neither Nmap nor
any of its data files (the clean-room rule in the overview's Global Constraints
applies to verification too). It then reads a banner from every open port and
prints it, so that each `product` and `version` in `ground-truth.json` is
transcribed from something observed rather than inferred from an image name.

```
lab/run.sh up
lab/run.sh verify
```

Three of the recorded rows are things a compose-file reading would have got
wrong, which is the argument for doing it this way:

- `db-mysql` also opens **33060**, the X Protocol port.
- `dns-bind` also opens **443** and **853** — DNS-over-HTTPS and DNS-over-TLS.
- `mail-postfix` also opens **587**.

Every one of those is a port `bathy` will correctly report open, and every one
of them would have been scored a false positive by a ground truth written from
the compose file.

The banners, as read:

```
10.30.0.10:80     HTTP/1.1 200 OK ... Server: nginx/1.29.8
10.30.0.11:2222   SSH-2.0-OpenSSH_10.3
10.30.0.12:5432   (nothing; PostgreSQL speaks only when spoken to)
10.30.0.13:3306   \x49\x00\x00\x00\x0a 9.4.0 \x00 ... caching_sha2_password
10.30.0.13:33060  \x05\x00\x00\x00\x0b\x08\x05\x1a\x00
10.30.0.14:6379   (nothing; RESP is request-response)
10.30.0.15:25     220 mail.lab.invalid ESMTP Postfix (Debian/GNU)
10.30.0.15:587    220 mail.lab.invalid ESMTP Postfix (Debian/GNU)
10.30.0.16:53     (nothing)
10.30.0.16:443    (nothing; TLS)
10.30.0.16:853    (nothing; TLS)
10.30.0.17:443    HTTP/1.1 400 Bad Request ... The plain HTTP request was sent to HTTPS port
10.30.0.18        (no port open)
```

`product` is deliberately `null` wherever the service volunteers nothing that
names one. That is a statement that *the lab does not establish a product
here*, not a note that identification failed — and it is why AC-7.5 asserts
over the four protocols where a banner does name a product (nginx, OpenSSH,
MySQL, Postfix) rather than over everything that is open.

## How the digests were obtained

Each image was pulled by the tag in the table below, and the digest recorded is
the one `docker` then reports in `RepoDigests`:

```
docker pull <name>:<tag>
docker image inspect <name>:<tag> --format '{{index .RepoDigests 0}}'
```

That is the **multi-architecture index** digest, not a per-architecture
manifest. Pinning a per-architecture manifest would make the lab arm64-only
(this was developed on an M1) or amd64-only (CI), and the resulting failure
would look like a scanner defect on whichever machine did not match.

| Image | Tag pulled | Digest |
|---|---|---|
| `nginx` | `1.29-alpine` | `sha256:5616878291a2eed594aee8db4dade5878cf7edcb475e59193904b198d9b830de` |
| `linuxserver/openssh-server` | `10.3_p1-r0-ls233` | `sha256:96b9a4d3b5106746d08d43a6911650d4d21f7d5c7f2ac9660e792bdb5e63157c` |
| `postgres` | `17-alpine` | `sha256:742f40ea20b9ff2ff31db5458d127452988a2164df9e17441e191f3b72252193` |
| `mysql` | `9.4` | `sha256:135bc87cce147c3d28cecb9ad270b814cb52805af7ddeea83bfcaf157d05a6b2` |
| `redis` | `8-alpine` | `sha256:978f0e01593e65eed801f2402944efcd936d43b5027e4908a7897baf88ed6241` |
| `boky/postfix` | `v4.4.0` | `sha256:f3f247fd42528b969e2603ac120d5a5b5db7dfe61f4505c49d438b9ba1822999` |
| `internetsystemsconsortium/bind9` | `9.20` | `sha256:4592e51108a135cb88c223718cae9720195de74102220a51a25e227c8dd8a569` |
| `alpine` | `3.22` | `sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce` |

The tag column is documentation only. Changing an image means pulling the new
tag, recording the new digest here **and** re-running `lab/run.sh verify`,
because a new image is a new set of banners.

`python:3.13-alpine`, used by `lab/run.sh verify`, is deliberately *not*
pinned: it is a tool, not part of the fixture, and nothing in the ground truth
depends on which build of it ran.

## No key material in this repository

`tls-web` needs a certificate. Rather than commit one, the `tls-init` service
generates a throwaway self-signed key into a Docker volume at `up` time, and
`lab/run.sh down` removes the volume with `-v`. Nothing under `lab/` is ever a
private key, which is what keeps `xtask publish-check`'s `BEGIN … PRIVATE KEY`
patterns honest.

`tls-init` uses the `boky/postfix` image only because it is the one image
already pinned here that ships an `openssl` binary; a tenth image would be a
tenth digest to keep current. It is deliberately off `labnet` — it exits, and
an address that is occupied while a generator runs and empty afterwards is not
something a ground truth can describe.

## Running the conformance suite

```
lab/run.sh test
```

That brings the lab up, runs `cargo test --workspace -- --ignored` with
`BATHY_LAB_REQUIRED=1`, and tears it down. The tests are:

| Test | AC |
|---|---|
| `the_scanner_finds_every_open_port_in_the_ground_truth` | AC-7.2 |
| `the_scanner_reports_no_open_port_that_is_not_in_the_ground_truth` | AC-7.3 |
| `addresses_with_no_host_are_never_reported_open_or_closed` | AC-7.4 |
| `service_identification_matches_the_ground_truth_products` | AC-7.5 |
| `two_consecutive_scans_of_the_static_lab_produce_no_substantive_changes` | AC-7.6 |
| `tls_probe_against_a_real_nginx_tls_server` | — (M4 probe, re-homed here) |

They live in `crates/bathy/tests/lab_conformance.rs`, except the last, which is
in `crates/bathy-probe/src/probes/tls.rs`.

### Where there is no Docker, and where there is no route

Three behaviours, and all three are deliberate:

1. **`cargo test --workspace`** never runs them. They are `#[ignore]`d, so they
   are *listed as ignored* — visible in the count, not silently omitted. Four
   further tests in the same file are **not** ignored and do run there: they
   check that the ground truth parses, that every recorded open port carries
   the evidence it was derived from, that `lab/scope.json` authorizes the lab
   and refuses everything else, and that the narrowing controls above still
   exist. None of those needs a container.
2. **`cargo test --workspace -- --ignored` with no lab** prints, for each test,
   why it is skipping and how to bring the lab up, then returns. A connection
   error in the middle of a scan reads like a scanner defect; this does not.
3. **`lab/run.sh test`** sets `BATHY_LAB_REQUIRED`, which turns that skip into
   a hard failure. The command whose entire purpose is to test the lab cannot
   pass without one.

And `lab/run.sh` refuses in words if `docker` is not on `PATH` or the daemon is
not responding, rather than failing somewhere inside a compose invocation.

### macOS

**The conformance suite cannot run on macOS.** `labnet` is a Docker bridge
network; on Linux the host routes to it, and on macOS it does not exist in the
host's routing table at all, because Docker Desktop runs the daemon inside a VM
whose bridges are never exposed to the Mac. This was measured, not assumed: a
container given `10.31.0.10` on a user-defined bridge answers neither `ping`
nor a TCP connect from the Mac, and loopback aliasing is not an alternative
because binding `127.0.0.2` needs root.

Everything that does not need a route works there: `lab/run.sh up`, `status`,
`verify` (which runs *inside* the network) and `xtask check-lab`. The
conformance tests skip with the message in (2) above.

This is consistent with the project's stated platform position — Linux first,
macOS best effort — but the M7 plan did not say so, and its Step 5 ("Run the
suite — `lab/run.sh test`. Expected: 5 passed") is not achievable on a macOS
developer machine. See the plan defects below.

## Plan defects found while building this

Recorded here because the milestone plan is a requirements document and a
defect in it outlives the task that hit it.

1. **AC-7.4's drafted test could not fail.** The plan asserts
   `!fold.hosts_up.contains(&ip)`. `Scheduler` has no call to `discover_host`
   in v0.1 — unprivileged ICMP is impossible, so host discovery ships with
   `packetd` in M6, and the overview's Gap Register says so — which means
   `ScanFold::hosts_up` is empty after *every* scan. The assertion would have
   passed against a scanner that reported the entire subnet live: a decoration
   test, and the thing the overview's "manual verification does not close an
   acceptance criterion" constraint exists to prevent. The test now asserts the
   property that is real in v0.1 — every endpoint on an address with no host is
   `Filtered`, never `Open` (we invented a service) and never `Closed` (we
   claim an RST arrived, which is itself evidence a host is there) — and
   separately asserts that `hosts_up` *is* empty, so that wiring host discovery
   in makes this test fail and demand the stronger assertion.

2. **The plan's ground truth was written from the compose file.** Its four
   hosts omit 33060, 587, 443 and 853, every one of which is genuinely open;
   scored against it, a correct scanner reports four false positives. Derived
   ground truth, not asserted ground truth, is the only kind worth having.

3. **The plan assumed the host can route to the lab subnet.** True on Linux,
   false on macOS. Step 5's expected result is unreachable there.

4. **The plan's compose file had no TLS material and no way to get any.** Its
   `tls-web` mounts `./tls` as `conf.d` with no certificate anywhere, so the
   service would not have started. Committing a key was not an option — this
   repository's own publish gate greps for exactly that.

5. **`cargo test --workspace -- --ignored`, which the plan's `run.sh` runs, had
   an unrelated ignored test in it.** `tls_probe_against_a_real_nginx_tls_1_3_server`
   dialled `127.0.0.1:18543` and depended on a container described only in an
   M4 task report — un-runnable by anyone without that report, and it would
   have failed `lab/run.sh test` on every machine. It now targets this lab.
