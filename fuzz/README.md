# Fuzzing bathy's parsers

Every function in this repository that consumes bytes it did not write has a
libFuzzer target here. That is the whole of AC-7.7: interpretation, event-log
parsing, canonical JSON, manifest loading, and `bathy-packetd`'s IPC protocol.

## Running them

```sh
rustup toolchain install nightly
cargo install cargo-fuzz --locked

# Every registered target, 120 seconds each -- the AC-7.8 run.
cargo run -p xtask -- fuzz --time 120

# One target.
cargo run -p xtask -- fuzz --target interpret --time 300

# The static half: a target per surface, seeds per target, the span
# assertions still present, the corpus cached in CI. Milliseconds, no
# nightly needed, and it runs in the ordinary CI job.
cargo run -p xtask -- check-fuzz
```

`xtask fuzz` iterates `gates::FUZZ_SURFACES` and CI calls `xtask fuzz`, so a
target added to the registry is run in CI without anyone editing
`.github/workflows/ci.yml`. A list of `cargo fuzz run` lines in the workflow
would be a second registry, and the two would diverge the first time a target
was added — the same defect as the MSRV membership rule that had no executable
form and three recorded recurrences.

## Why this package is its own workspace

`fuzz/Cargo.toml` opens with a bare `[workspace]`, which makes it the root of
a separate workspace. `rust-toolchain.toml` pins **stable** and libFuzzer needs
**nightly**; without the split, every `cargo build` at the repository root
would try to compile `libfuzzer-sys` under the pinned toolchain, and both MSRV
jobs would range over a package that has no MSRV to promise. `check-fuzz`
fails if the `[workspace]` table is removed.

The cost is that `cargo fmt --all`, `cargo clippy --workspace` and `cargo test
--workspace` at the root do not reach these files, and root `cargo deny` does
not reach this dependency tree. Both halves have a command and a CI step:

```sh
# fmt, clippy and this package's unit tests, run inside fuzz/. Stable: only
# *building* the targets needs nightly. A step in the fast CI job.
cargo run -p xtask -- check-fuzz-crate

# advisories, bans, licenses and sources over BOTH graphs -- the root
# workspace and this one.
cargo run -p xtask -- check-deny
```

Until M7 Task 2's fix round the control was this paragraph asking you to
remember to `cd fuzz` — which is the shape of the MSRV membership rule that
had no executable form and three recorded recurrences, and strictly weaker
than the five inline gates M5 closed. The first `cargo deny` run that was
ever pointed at this workspace found `libfuzzer-sys` is `(MIT OR Apache-2.0)
AND NCSA`, a licence in nobody's allow list; `deny.toml` carries the scoped
exception and the ruling.

## Seeds, and why a fuzz target without them proves nothing

`seeds/<target>/` is committed. `corpus/<target>/` is libFuzzer's working
directory: git-ignored, cached in CI, and passed *first* so that libFuzzer
writes there and never into the committed set.

This matters more than it looks. This milestone measured a property-test
strategy over `interpret` at **6 non-empty results in 4096 cases, and 0 spans
past byte 6** — it had never once reached the offset arithmetic it claimed to
guard, and nothing about it said so. Structured parsers are not reachable from
random bytes in any useful time, so `check-fuzz` fails a target whose seed
directory is empty.

Where the seeds came from:

| Target | Seeds |
|---|---|
| `interpret` | The response bytes of all 17 recorded captures in `testdata/captures/`, decoded from their base64. Plus `postgres-ssl-accepted.bin`, the single byte `S` that PostgreSQL's protocol defines as "SSLRequest accepted" — the one rule of the thirteen for which the recorded corpus has only the *declined* case. |
| `event_log` | Three real logs — two produced by real scans of this machine's own listener (one completed with an open port, a closed port and a service identification; one stopped by a packet budget), and the checked-in `crates/bathy-query/tests/fixtures/pre-rule-id-scan.jsonl`. Plus three derived from the first: truncated mid-record, first record only, and empty, which are what a full disk and an interrupted append actually produce. |
| `canonical_json` | All 27 committed schemas from `schemas/`, plus `lab/ground-truth.json` and `lab/scope.json`. |
| `manifest` | `lab/scope.json`, every distinct manifest document the workspace's own tests load, and two derived edge documents (an empty allow set, an all-IPv6 allow set) for the two rejection paths no real document in the tree exercises. |

## Instrumentation: what each target reports reaching

libFuzzer's own numbers — executions, edges, corpus size — are about the whole
process, including `serde_json`'s lexer and the allocator. "2.4M execs, 4193
edges" is entirely consistent with every input bouncing off the first `if` in
the parser under test. So each target counts what it reached in its own terms:

```sh
BATHY_FUZZ_STATS=1 cargo run -p xtask -- fuzz --time 120
```

prints a line to stderr every 100000 executions (override with
`BATHY_FUZZ_STATS_EVERY`; set it to `1` when replaying a finite corpus with
`-runs=0`, where the last line is the total). The measured numbers from the
AC-7.8 runs are in this task's report.

For `interpret` the load-bearing figure is `reached=13/13` — which of the
thirteen registered rules fired at all — followed by `matched_inputs` and
`deep_spans`. A run where every input lands in `interpret`'s empty-vector path
has fuzzed a `for` loop.

## When a target finds something

libFuzzer writes the input to `fuzz/artifacts/<target>/crash-<hash>`. Fix the
bug, then commit that input into `fuzz/seeds/<target>/` under a name that says
what it is. It is a regression case from that point on, run by every CI fuzz
job and by every `-runs=0` replay.

## `ipc` — the target that is not here yet

`bathy-packetd` does not exist: M7 runs before M6 in this project's execution
order. The surface is registered in `gates::FUZZ_SURFACES` marked `deferred`,
and `packetd-ipc-fuzz-target` is an entry in `xtask`'s `DEFERRALS`, so
`check-deps` fails the day `crates/bathy-packetd/Cargo.toml` appears without
`fuzz/fuzz_targets/ipc.rs` — and reports *itself* stale the day the target
lands. A stub target was the alternative and is worse: it would fuzz nothing
while registering as coverage, which is the exact failure this milestone
already measured once.
