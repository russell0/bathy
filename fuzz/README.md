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
has fuzzed a `for` loop, and it says so: `reached=0/13` is printed on every
report, including when nothing matched. (It was not, until M7 Task 2's fix
round: the flag names were supplied from inside the match loop, so the one
case the counter exists for was the one case it went silent in.)

Two of these numbers say less than their names suggest, and both are labelled
in the source rather than left to be discovered:

- `event_log`'s **`opened`** counts "the reader did not reject it". An empty
  file opens successfully with zero events — a measured run had
  `opened=93,728` against `events_parsed=6,610`. The figures that carry weight
  are `events_parsed`, `opened_multi_record` and `folded_endpoints`.
- `canonical_json`'s **`duplicate_keys`** was a punctuation heuristic that
  `{"a":"x:y"}` alone satisfied, so `reached=9/9` was eight shapes and one
  guess. It is now a scanner over the raw document (`bathy_fuzz::
  has_duplicate_keys`) with unit tests, that input among them.

## What a 60-second pull-request run does and does not cover

CI runs every target for **60 seconds on a push or pull request** and **600
seconds on the nightly schedule**, from the cached corpus. Be precise about
what the short run buys, because "the fuzz targets run on every PR" is easy to
read as more than it is:

**It does cover.** Every committed seed and every cached corpus input, replayed
before mutation begins — so any input that has *ever* found something is
re-run on every PR. Shallow new inputs around the corpus. Panics, hangs and
OOMs on any of that.

**It does not cover** a bug that needs a deep or narrowly-shaped input to
reach. Measured, in M7 Task 2's review, against a one-byte span corruption in
`dns.version_bind.txt_chaos.v1`:

| Run | Outcome |
|---|---|
| seed replay | not caught |
| 120 s, 2,964,533 executions | **not caught** |
| 600 s, 6,560,722 executions | caught, at roughly 276 s |
| one hand-built 33-byte input | **caught instantly** |

The DNS rule needs a two-byte length prefix, an RDLENGTH and a
character-string length to agree with the input's total length before the
faulty arithmetic is even reachable. HTTP's `Server:` header, by contrast,
falls out of a seeded response in 22 seconds. **The assertion covers every
rule; the 60-second run demonstrably does not.**

So the gap is closed where it is cheap, not by making every PR wait ten
minutes per target:

- **`fuzz/seeds/interpret/span-edge-*.bin`** — one input per rule whose match
  ends at the last byte the rule's grammar allows. `crates/bathy-interpret/
  tests/span_edge_corpus.rs` asserts every one of them on every
  `cargo test --workspace`, in about a millisecond, and it dies on a one-byte
  span change in *any* rule (verified by mutation against five of them,
  including the reviewer's own DNS corruption, which a 120-second fuzz run
  missed). A rule added without an edge input fails that test by name.
- **The 600-second nightly** stays, for the depth a short run cannot buy.
- **The 60-second PR run** stays at 60 seconds. Raising it to 600 would add
  ~40 minutes to every pull request and still would not be a guarantee — the
  DNS mutant needed 276 of those seconds on one machine, which is a
  measurement, not a bound.

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
