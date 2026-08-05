# Contributing to bathy

Thank you for considering it. This document is longer than most because two of
its rules — the clean-room rule and the citation rule — are the ones that decide
whether this project can be redistributed at all, and because this project has
already caught itself breaking the second one twice.

Read [`SECURITY.md`](SECURITY.md) before opening a feature request. Some things
are permanent non-goals, and knowing that first saves you writing the request.

## The three rules that are not negotiable

### 1. Clean room: nothing derived from Nmap, or from anything incompatibly licensed

**Do not submit code, probe strings, fingerprint data, port lists, or
interpretation rules derived from Nmap, `nmap-service-probes`, `nmap-os-db`, or
any other project whose licence is incompatible with Apache-2.0 OR MIT
redistribution.** Not copied, not translated, not "adapted", not
reverse-engineered from its output.

This is a legal requirement, not a style preference. bathy ships under
Apache-2.0 OR MIT and intends to stay redistributable by anyone, including
commercially. One incompatibly licensed probe string in the tree makes that
untrue for the whole project, and it cannot be fixed by deleting the line later
— the history is what is distributed.

Concretely, when you write a probe or an interpretation rule:

- **Do not open Nmap's data files** to see what it matches on. Their presence on
  your disk is not the boundary; opening them is.
- **Do not tune a rule from another scanner's output.** "Nmap says this is
  nginx, so I will make our regex match what it matched" is derivation, even
  though no file was copied. If another tool identified something bathy did not,
  record the miss and go read the protocol.
- The same applies to any other source you are not licensed to redistribute
  from: a vendor's proprietary signature set, a commercial scanner's database, a
  Stack Overflow answer's code block without checking its licence, model output
  you cannot account for.

The project's own attestation, including the one capacity in which Nmap is
legitimately used here — as a timed benchmark subject, with its data files
unopened — is `docs/design-paper.md` §9. Contributors are held to the same
boundary.

If you have previously worked on an incompatibly licensed scanner, you are still
welcome to contribute. Say so in the pull request, and keep to material you can
derive from public protocol documentation in front of you.

### 2. Every interpretation rule cites a source, and the citation must be checkable

Every entry in `bathy-interpret`'s rule registry carries a `source` field, and
`every_rule_documents_its_non_nmap_source` fails the build if one is empty or
names Nmap. That test checks that a citation *exists*. It cannot check that the
citation is *true*, and that is where this project has actually been bitten.

**This repository has shipped two fabricated RFC quotations.** One was found in
`bathy-interpret`, corrected, and left standing in `bathy-probe`, so for a while
the two crates contradicted each other about what RFC 5321 §3.1 says. The
branch-wide sweep that followed found a second fabrication in `probes/mysql.rs`
and a citation to a PostgreSQL section number that does not exist. In every case
the sentence was plausible, the section number looked right, and nobody had
opened the document.

So a citation here is not a gesture at an authority. It must be something a
reviewer can check in under a minute, and the requirement is stated in terms of
what it is checkable *against*:

**One of exactly three kinds of source, and nothing else:**

1. **An RFC, cited to the section.** `RFC 9112 §4`, not `RFC 9112`. If you quote
   it, the quotation must be **verbatim** from that section — copy and paste it,
   do not retype it from memory and do not paraphrase inside quotation marks. A
   reviewer will open <https://www.rfc-editor.org/rfc/rfc9112> and search for
   your string; if it is not there, the pull request is rejected on that ground
   alone. Cite the RFC that is *current* for the protocol (RFC 9112, not RFC
   2616) and say so if you are deliberately citing an obsoleted one.
2. **The vendor's own protocol documentation, cited to the section or page
   title**, with a URL. `PostgreSQL "Message Flow" §54.2.10 ("SSL Session
   Encryption")`. The same verbatim rule applies to quotations, and the same
   check applies: the section must exist, under that number, saying that.
3. **A capture this project ran itself**, in the lab or in a container you can
   name. Give the image and its **sha256 digest**, the service version, and the
   observed bytes. Add the capture as a fixture under `testdata/captures/` in
   the same pull request, so the bytes the rule was written against are in the
   tree and the rule can be replayed against them without a network. A capture
   you cannot show is not a source.

**A structural claim needs a structural citation.** If the rule matches on a
byte layout — a length prefix, a record header, a fixed first byte — cite the
part of the specification that *defines the layout*, not a part that merely
mentions the field. `tls-v1` cites RFC 8446 §5.1 ("Record Layer") for exactly
this reason: an earlier draft of that rule cited §4, which is the registry, and
the citation read as authoritative while pointing at the wrong thing.

**Say what the source does not say.** If the protocol makes no MUST-level
promise about the thing your rule relies on, write that down next to the
citation. The RFC 5321 rule in this tree does: the greeting shape it matches is
in §4.2 and *not* in §3.1, and the rule's comment says so, because the earlier
version claimed §3.1 said something it does not.

If your rule's source turns out not to say what the pull request claims, the
outcome is not "fix the comment". The rule is re-derived from what the source
actually says, or it is withdrawn — a rule justified by a citation that was
wrong was never justified.

### 3. Compare tools, never people

The README, the design paper, the benchmarks and every issue and pull request
compare bathy to **tools**, with measurements. No document in this repository
names an individual person in a comparative or critical context, and no
contribution may claim that another project is bad, badly run, or obsolete.

The argument this project makes is "here is an interface designed for a
different consumer, and here are the numbers". That argument is strictly
stronger than any adjective, and an adjective aimed at a human being is what a
reader uses to dismiss the whole document.

This is enforced, not merely requested: `cargo run -p xtask -- check-phrases`
carries a `compare-tools-not-people` rule over `README.md`, `docs/`, and these
policy files, and it is a CI step.

## Getting set up

```bash
git clone https://github.com/russell0/bathy && cd bathy
cargo test --workspace
```

The toolchain is pinned by `rust-toolchain.toml`. MSRV is tiered and every tier
has a stated cause — see the Global Constraints in
`docs/superpowers/plans/2026-07-31-bathy-v0.1-overview.md`. Develop on stable;
`cargo run -p xtask -- check-msrv` is what holds the floors honest.

## The gates, and how to run them locally

**Every gate has a local form.** That is a standing rule here: this project
spent half a milestone with a check that lived only inside `ci.yml`, went red,
and stayed red while six reports called it green. If you add a gate, it is an
`xtask` subcommand and `ci.yml` calls that subcommand; `check-ci` fails the
build if a gate is added inline instead.

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo test --workspace --benches
cargo run -p xtask -- check-deps        # layering, and no LLM below bathy-mcp
cargo run -p xtask -- check-schemas     # committed JSON Schema is not stale
cargo run -p xtask -- check-readme      # every number in the README, against the tree
cargo run -p xtask -- check-docs        # the structural claims of the documents
cargo run -p xtask -- check-phrases     # forbidden phrasings, including rule 3 above
cargo run -p xtask -- check-fixtures    # test-fixture hygiene
cargo run -p xtask -- check-purity      # bathy-interpret does no I/O
cargo run -p xtask -- check-panics      # the panic lints, and their exceptions
cargo run -p xtask -- check-msrv        # the two MSRV floors
cargo run -p xtask -- check-deny        # cargo-deny, same four checks CI runs
cargo run -p xtask -- check-lab         # the lab, digest-pinned
cargo run -p xtask -- check-bench       # the benchmark document, re-rendered
cargo run -p xtask -- check-fuzz        # a fuzz target per untrusted-input surface
cargo run -p xtask -- check-fuzz-crate  # fuzz/ is its own workspace; this reaches it
cargo run -p xtask -- check-ci          # no gate without a local form
```

`cargo run -p xtask -- publish-check` is the pre-publication gate. It is
local-only — it reads a git-ignored deny list — and it is not a CI step. You do
not need it for an ordinary contribution.

## Rules about tests, because they are the ones reviews turn on

These are not style preferences. Each of them is here because its absence
shipped a defect in this repository.

- **A criterion is closed by a named test that dies when the code it names is
  removed, and by nothing else.** Manual verification closes nothing. A
  cancellability property confirmed by hand, correctly, left no test behind, and
  a non-cancellable acquire then survived the entire suite.
- **A fixture that satisfies every branch tests none of them.** If a test
  exercises a filter, a limit, a branch or a flag, the fixture must **exclude**
  something the code is supposed to exclude, and the test must fail if the input
  is ignored. A parity suite whose single fixture satisfied all four filters
  passed while three of the four were unimplemented.
- **Assert the interleaving, not the presence.** If the invariant is "A happens
  before B", a test that fails when A is deleted leaves "A moved after B"
  completely unguarded — and that is the actual bug, twice now.
- **No decoration tests.** A test that cannot fail is worse than no test,
  because it reads as coverage. If you cannot state the mutation your test
  kills, it is decoration.
- **`cargo test -p <crate>` being green says nothing about the workspace.** Two
  mutants have survived a crate-local run and died only under
  `cargo test --workspace`, because the tests pinning those behaviours lived in
  another crate. Use `-p` for the loop; verify with the workspace.
- **A mutation test that does not rebuild is a test of nothing.** If you restore
  a mutated file in a way that preserves mtime, cargo skips the rebuild and your
  result belongs to code that was never compiled. Confirm the rebuild happened.
  Never revert a mutation with `git checkout --`; it will silently revert
  uncommitted work too.
- **A defect found in one file is a defect class until proven otherwise.** Fix
  the class and say what you swept. Both fabricated RFC quotations above were
  found this way, and the second was found only because the first prompted a
  sweep.

## Adding a probe

A probe puts bytes on somebody else's wire, so it carries obligations the rest
of the code does not:

- **The bytes are fixed, public, and documented in the probe's own module**, byte
  for byte. No probe composes its payload from anything the caller supplies.
- **It identifies bathy where the protocol has a place for that**, and it never
  offers a way to turn that off. See `SECURITY.md`.
- **It is bounded twice**: a byte cap and a deadline covering the whole read.
- **It returns `Result`.** `clippy::unwrap_used`, `expect_used`,
  `indexing_slicing`, `panic` and `arithmetic_side_effects` are at `deny` level
  in every crate that touches untrusted bytes. Note that `clippy::indexing_slicing`
  does **not** see `&s[i..j]` on a `str` and does not see a third-party `Index`
  impl; five real panics in this tree were found by reading, not by the lint, so
  do not index a `str`.
- **It gets a fuzz target** if it parses what comes back, registered in
  `gates::FUZZ_SURFACES` — `check-fuzz` fails if a registered surface has no
  target.

## Pull requests

- One concern per pull request. A refactor and a behaviour change in one diff is
  two reviews pretending to be one.
- Say what you swept. If you fixed an instance of something, say whether you
  looked for the class.
- Say what you did not do. A known hole named in the pull request is worth more
  than a clean-looking diff that hides it.
- The full gate list above should pass locally before you open it. CI runs the
  same commands; there is nothing in CI you cannot run yourself except the
  toolchain installs.

## Licensing of contributions

By contributing you agree that your contribution is licensed under **Apache-2.0
OR MIT**, at the user's option, matching the project. There is no CLA and no
copyright assignment.

## Conduct

[`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) applies to every space this project
occupies.
