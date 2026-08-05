#![forbid(unsafe_code)]

mod bench;
mod docs;
mod fixtures;
mod gates;
mod phrases;
mod prose;
mod readme;
mod visibility;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// Crates are listed lowest-level first. A crate may only depend on crates
/// that appear strictly earlier in this list.
const LAYERS: &[&str] = &[
    "bathy-types",
    "bathy-scope",
    "bathy-evidence",
    "bathy-store",
    "bathy-plan",
    "bathy-interpret",
    "bathy-probe",
    "bathy-engine",
    "bathy-packetd",
    "bathy-query",
    "bathy-mcp",
    "bathy",
];

/// No workspace crate — ranked or not — may depend on anything resembling a
/// model/inference client. Enforces "no LLM on the packet path".
const FORBIDDEN_SUBSTRINGS: &[&str] = &[
    "openai",
    "anthropic",
    "llm",
    "langchain",
    "ollama",
    "tokenizers",
];

/// Every subcommand this binary dispatches, in one place.
///
/// It is a list rather than only a `match` because `check-ci` needs to know
/// what exists: a `ci.yml` step that calls `cargo run -p xtask -- <name>` for
/// a name that is not here fails `check-ci` with the file and line, instead of
/// failing on a runner with `unknown xtask`. `.publish-deny` documented a
/// command in exactly that state ("Consumed by `xtask publish-check`") for a
/// milestone and a half.
///
/// Asserted against the `match` below by `the_dispatch_and_the_list_agree`.
const SUBCOMMANDS: &[&str] = &[
    "check-deps",
    "check-schemas",
    "check-readme",
    // AC-7.16 and AC-7.18 through AC-7.21: the structural claims of the four
    // documents a stranger reads before deciding whether to trust this. Every
    // one of those criteria would otherwise have been closed by a person
    // reading the file and saying so, and the Global Constraint is explicit
    // that manual verification closes nothing. `check-readme` asks whether a
    // number is true; this asks whether the section that has to exist still
    // does, and still says the thing its criterion names.
    "check-docs",
    "check-phrases",
    // The class the M7 flaky sweep found four times, in the four shapes a
    // checker can see: two tests sharing a scratch path, a port bound and
    // released and then relied on, a fixed scan range inside the kernel's
    // ephemeral window, and `/proc/self/*` read in a binary with more than
    // one test. What it deliberately cannot see is listed in
    // `fixtures::UNCHECKABLE` and printed by every successful run.
    "check-fixtures",
    "check-purity",
    "check-msrv",
    "check-deny",
    "check-lab",
    // AC-7.11 to AC-7.15. `check-bench` reads text -- the committed
    // `bench/results.json`, the document it renders to, and the four
    // criterion benchmark files -- so it runs in CI, where there is no lab
    // and no Nmap. `bench-compare` is the one that needs both and is NOT a
    // CI step: it is `bench/compare.sh`'s payload.
    "check-bench",
    "bench-compare",
    "check-fuzz",
    // `fuzz/` is its own workspace, so root `fmt --all`, `clippy --workspace`
    // and `test --workspace` do not reach it. This is the command that does.
    "check-fuzz-crate",
    "check-ci",
    // The two commands that answer questions the working tree cannot. Neither
    // is a `ci.yml` step: `check-ci-status` asks GitHub what CI said (asking
    // that from inside CI is circular), and `linux-gate` runs CI's own `test`
    // job in a container (running that on the runner would be CI in CI). They
    // are listed here because `check-ci` validates `ci.yml` against this list
    // and because `usage:` should name every command that exists.
    "check-ci-status",
    "linux-gate",
    "publish-check",
    "emit-schemas",
    "gen-ports",
    // Not a `check-*`: it runs the fuzz targets rather than reading the tree,
    // takes minutes rather than milliseconds, and needs a nightly toolchain
    // and `cargo-fuzz` installed. `check-fuzz` is the part that belongs in the
    // fast gate; this is the part CI's own fuzz job calls, and it exists as a
    // subcommand so the list of targets lives in exactly one place
    // (`gates::FUZZ_SURFACES`) instead of being restated in `ci.yml`.
    "fuzz",
];

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("check-deps") => check_deps(),
        Some("emit-schemas") => emit_schemas(true),
        Some("check-schemas") => emit_schemas(false),
        Some("gen-ports") => gen_ports(),
        Some("check-readme") => readme::check_readme(),
        Some("check-docs") => docs::check_docs(),
        Some("check-phrases") => phrases::check_phrases(),
        Some("check-fixtures") => fixtures::check_fixtures(),
        Some("check-purity") => gates::check_purity(),
        Some("check-msrv") => gates::check_msrv(args.iter().any(|a| a == "--run")),
        Some("check-deny") => gates::check_deny(),
        Some("check-lab") => gates::check_lab(),
        Some("check-bench") => bench::check_bench(),
        Some("bench-compare") => bench::bench_compare(args.iter().any(|a| a == "--render-only")),
        Some("check-fuzz") => gates::check_fuzz(),
        Some("check-fuzz-crate") => gates::check_fuzz_crate(),
        Some("fuzz") => {
            let seconds = flag_value(&args, "--time")
                .map(|v| {
                    v.parse::<u64>()
                        .map_err(|_| format!("--time wants a number of seconds, got `{v}`"))
                })
                .transpose()?
                .unwrap_or(120);
            gates::run_fuzz(seconds, flag_value(&args, "--target"))
        }
        Some("check-ci") => gates::check_ci(SUBCOMMANDS),
        Some("check-ci-status") => visibility::check_ci_status(),
        Some("linux-gate") => visibility::linux_gate(),
        Some("publish-check") => gates::publish_check(),
        Some(other) => Err(format!("unknown xtask: {other}").into()),
        None => Err(format!("usage: xtask <{}>", SUBCOMMANDS.join("|")).into()),
    }
}

/// `--flag value` from an argument list, or `None`.
fn flag_value<'a>(args: &'a [String], flag: &str) -> Option<&'a str> {
    let at = args.iter().position(|a| a == flag)?;
    args.get(at + 1).map(String::as_str)
}

/// A workspace package and the names of its direct dependencies, as parsed
/// out of `cargo metadata` JSON. This is the pure-data boundary between the
/// process-shelling `main` path and the testable rule logic below:
/// `find_violations` never touches the filesystem or a subprocess, so tests
/// can hand it synthetic fixtures directly instead of standing up a real
/// `cargo metadata` invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PackageInfo {
    name: String,
    dependencies: Vec<String>,
    /// The subset of `dependencies` that a downstream consumer of this
    /// package actually builds -- `[dependencies]`, not `[dev-dependencies]`
    /// or `[build-dependencies]`. [`find_pinned_dependency_drift`] needs the
    /// distinction; the layer and forbidden-substring rules deliberately do
    /// not, because a dev-dependency on a higher layer is still a cycle and a
    /// dev-dependency on an inference client still puts one in the repo.
    normal_dependencies: Vec<String>,
}

/// Crates whose documented central claim *is* their direct dependency set,
/// pinned to the set the documentation states.
///
/// `bathy-query`'s purity claim -- "no crate in this layer touches the store,
/// the network, the clock or the filesystem", and it stays true because the
/// graph makes it impossible rather than because anyone remembers -- is a
/// claim about exactly this list. It was stated in four places in prose, and
/// when M5 Task 2 added a fourth dependency all four went on saying three.
/// Prose that counts is prose that rots; this is the source of truth the
/// prose now names instead of counting.
const PINNED_DEPENDENCIES: &[(&str, &[&str])] = &[(
    "bathy-query",
    &[
        "bathy-types",
        "schemars",
        "serde",
        "serde_json",
        "thiserror",
    ],
)];

/// Whether `text` names `dependency` **as a crate**, rather than merely
/// containing its letters.
///
/// `text.contains("serde")` is true of a file that only ever says
/// `serde_json`, so the pinned set `{serde, serde_json}` was checked by a
/// rule that could not tell its two members apart: prose that dropped
/// `serde` and kept `serde_json` passed. A crate name ends where a character
/// that cannot occur in one begins, so both neighbours must be neither
/// alphanumeric nor `_` nor `-` -- which also stops `bathy-types` matching
/// inside a longer `bathy-types-something`.
fn names_dependency(text: &str, dependency: &str) -> bool {
    let boundary =
        |c: Option<char>| !c.is_some_and(|c| c.is_alphanumeric() || c == '_' || c == '-');
    text.match_indices(dependency).any(|(at, _)| {
        boundary(text[..at].chars().next_back())
            && boundary(text[at + dependency.len()..].chars().next())
    })
}

/// Phrases that make a file's mention of a crate a claim about a *dependency
/// set*, rather than an ordinary English use of the word.
///
/// Deliberately narrower than "dependenc": `Order-independence`,
/// `dependency's rendering` and `depends on no rendering` all contain that
/// substring and none of them enumerates anything. Each phrase below appears
/// in at least one real site in this repository.
const DEPENDENCY_CLAIM_PHRASES: &[&str] = &[
    "[dependencies]",
    "[dev-dependencies]",
    "PINNED_DEPENDENCIES",
    "dependency set",
    "dependencies are",
    "dependencies is",
    "direct dependencies",
    "cargo tree",
];

/// Path prefixes discovery does not walk.
///
/// Each is a **category with a reason**, not a file someone forgot about.
const PROSE_DISCOVERY_EXCLUSIONS: &[(&str, &str)] = &[
    ("target", "build output, not source"),
    (".git", "git internals, not source"),
    (
        "Cargo.lock",
        "generated by cargo: resolved rather than written, and correct by construction",
    ),
    (
        "xtask/src/main.rs",
        "holds PINNED_DEPENDENCIES itself, so it names every crate in every pinned set \
         by construction; checking the pin against its own source is circular",
    ),
    (
        ".superpowers",
        "session records and review diffs: an account of what was true when each was \
         written, deliberately not amended afterwards",
    ),
    (
        "docs/superpowers/plans",
        "the plans are requirements, amended through their own plan-edit convention, \
         not descriptions of the tree's current dependency graph",
    ),
];

fn is_excluded_from_prose_discovery(relative: &str) -> bool {
    PROSE_DISCOVERY_EXCLUSIONS
        .iter()
        .any(|(prefix, _)| relative == *prefix || relative.starts_with(&format!("{prefix}/")))
}

/// Every file in `root` that states `crate_name`'s dependency set in words,
/// **derived from the tree** rather than listed.
///
/// This used to be a hand-maintained array of four paths. That array was the
/// same defect one level up as the one it was written to catch: a fifth site
/// would go unchecked until somebody happened to add it, which is exactly how
/// the seventh site (`ci.yml`, the premise of the MSRV job split) came to sit
/// wrong in the tree with nothing able to say so.
///
/// A file qualifies when it contains one of
/// [`DEPENDENCY_CLAIM_PHRASES`] **and** either
///
/// - lives inside `crates/<crate_name>/` -- where a claim phrase is
///   necessarily about this crate, and where most such prose lives; or
/// - names the crate possessively (`bathy-query's`, with or without the
///   backticks markdown and rustdoc put around it) or as a cargo argument
///   (`-p bathy-query`) -- the shapes an *external* file uses when it is
///   talking about this crate's own dependencies rather than merely
///   depending on it. `crates/bathy/Cargo.toml` lists `bathy-query` under
///   `[dependencies]` and is not a claim about `bathy-query`'s dependencies;
///   it does not match, and that distinction is why the possessive is the
///   discriminator rather than mere co-occurrence.
///
/// Neither condition consults the pinned set, deliberately: a discovery rule
/// that required a file to name every pinned crate would find only the files
/// that already pass, which is no check at all. This was tried first and is
/// recorded here because it looks reasonable.
///
/// It can still be defeated -- prose that describes the set without any of
/// these phrases is invisible, in the same way `xtask/src/prose.rs`'s own
/// marker list can be paraphrased around. What it removes is the failure that
/// actually happened: a site written by someone who did not know a list
/// existed.
fn find_prose_sites(root: &Path, crate_name: &str) -> Vec<String> {
    let inside = format!("crates/{crate_name}/");
    let mut files = Vec::new();
    collect_files(root, root, &mut files);
    files.sort();
    files.retain(|relative| {
        let Ok(text) = std::fs::read_to_string(root.join(relative)) else {
            return false;
        };
        if !DEPENDENCY_CLAIM_PHRASES.iter().any(|p| text.contains(p)) {
            return false;
        }
        relative.starts_with(&inside)
            || text.contains(&format!("{crate_name}'s"))
            || text.contains(&format!("{crate_name}`'s"))
            || text.contains(&format!("-p {crate_name}"))
    });
    files
}

/// Every file under `dir`, as paths relative to `root`, `/`-separated.
fn collect_files(root: &Path, dir: &Path, out: &mut Vec<String>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(relative) = path.strip_prefix(root) else {
            continue;
        };
        let relative = relative.to_string_lossy().replace('\\', "/");
        if is_excluded_from_prose_discovery(&relative) {
            continue;
        }
        if path.is_dir() {
            collect_files(root, &path, out);
        } else {
            out.push(relative);
        }
    }
}

/// Report every file that states a pinned crate's dependency set without
/// naming one of the crates in it.
///
/// [`PINNED_DEPENDENCIES`] pins the set; this checks the *prose about* the
/// set, which is a different thing and is what actually rotted. MINOR-1 was
/// "a count that is wrong in N places". The sweep that fixed it found six
/// places and missed a seventh: `.github/workflows/ci.yml` still said
/// `bathy-query`'s `[dependencies]` is "`bathy-types` and nothing else" --
/// and that sentence is not an incidental mention, it is the *premise* of the
/// argument that splits `bathy-query` across the two MSRV jobs. The
/// conclusion survived (every added crate was already in `bathy-types`'
/// 1.88-clean graph, and both jobs pass), but nothing in the tree could have
/// told anyone the premise had stopped being true.
///
/// The check is one-directional on purpose: every crate in the pinned set
/// must be *named* in each site. A crate the set no longer contains is not
/// reported, because a file may legitimately name `serde` for a reason that
/// has nothing to do with this claim, and a check with false positives gets
/// deleted. Addition is the direction that rots -- it is the direction that
/// rotted here.
///
/// A pinned crate that no site describes at all is reported too. Discovery
/// makes vacuity the new way this check could die quietly: a claim phrase
/// reworded out of every site would leave nothing to check and nothing to say
/// so.
fn find_pinned_dependency_prose_drift(root: &Path) -> Vec<String> {
    let mut drift = Vec::new();
    for (crate_name, pinned) in PINNED_DEPENDENCIES {
        let sites = find_prose_sites(root, crate_name);
        if sites.is_empty() {
            drift.push(format!(
                "nothing in the tree states {crate_name}'s dependency set any more; \
                 either the claim was deleted, or it was reworded past every phrase in \
                 DEPENDENCY_CLAIM_PHRASES and is no longer checked"
            ));
            continue;
        }
        for file in sites {
            let Ok(text) = std::fs::read_to_string(root.join(&file)) else {
                continue;
            };
            for dependency in *pinned {
                if !names_dependency(&text, dependency) {
                    drift.push(format!(
                        "{file} describes {crate_name}'s dependencies but never names \
                         `{dependency}`, which is in its pinned set; the description is \
                         out of date"
                    ));
                }
            }
        }
    }
    drift
}

// ---------------------------------------------------------------------------
// The one deferred architecture move, registered mechanically (AC-5.39).
// ---------------------------------------------------------------------------

/// A decision this project deliberately postponed, together with the condition
/// under which it stops being postponable.
///
/// **This was a hard-coded function pair and a literal `1` in `check-deps`'s
/// success line**, which the M5 close-out review pointed out is not a
/// registry: registering a second deferral meant restructuring the function
/// rather than appending a row, so "it is a one-line entry" understated the
/// cost by a lot. It is a collection now, the count is `DEFERRALS.len()`
/// rather than a literal, and the second entry is the one the review was
/// asking about.
///
/// Every entry checks **two directions**, and the second is why these are not
/// `assert!`s: the condition firing means the deferral is now due, and the
/// condition becoming *unreachable* means the registration is checking nothing
/// and should be deleted. A check that has quietly stopped applying is worse
/// than no check, because it reads as coverage.
struct Deferral {
    /// Short, stable, and what a failure message leads with.
    id: &'static str,
    check: fn(&Path) -> Vec<String>,
}

const DEFERRALS: &[Deferral] = &[
    // AC-5.39. The ops layer (`bathy_mcp::{engine,tools}`) serves both the
    // command line and the MCP server; the honest home for it is a crate below
    // both, and the move is deferred for v0.1 with one trigger.
    Deferral {
        id: "ops-layer-move",
        check: |root| find_deferred_move_violations(&scrape_ops_layer(root)),
    },
    // The `rmcp` stdio workaround. `crates/bathy-mcp/src/lifecycle.rs` sits
    // between the transport and the SDK because `rmcp`'s own pre-lifecycle
    // loop makes a malformed opening `_meta` fatal to the *process* rather
    // than to the request. The workaround is self-describing and its wrapper
    // has a divergence test -- but that test catches the wrapper drifting from
    // the SDK, and says nothing about the workaround having become
    // unnecessary, which is the thing that actually needs re-measuring.
    Deferral {
        id: "rmcp-stdio-workaround",
        check: find_rmcp_workaround_staleness,
    },
    // AC-7.7's fifth untrusted-input surface: `bathy-packetd`'s IPC protocol.
    // M7 runs before M6 in this project's execution order, so the crate the
    // criterion names does not exist while the fuzz targets are being written.
    // The alternative to registering it was a stub target, which would fuzz
    // nothing while reading as coverage -- the same shape as the property-test
    // strategy this milestone measured at 6 non-empty results in 4096 cases.
    // `gates::packetd_ipc_deferral_violations` fires the day the crate lands
    // and reports itself stale the day the target does.
    Deferral {
        id: "packetd-ipc-fuzz-target",
        check: gates::packetd_ipc_deferral_violations,
    },
    // AC-7.7's MCP stdio surface: the opening JSON-RPC frame from a calling
    // agent, which the threat model treats as possibly adversarial and which
    // `crates/bathy-mcp/src/lifecycle.rs` exists to handle because a
    // malformed `_meta` there was fatal to the *process*. It has no fuzz
    // target because `classify` is `pub(crate)` and its input is already
    // deserialized, so there is nothing a target can call; the deferral's
    // condition is that blocker rather than a date, and it fires the day
    // `classify` becomes reachable.
    Deferral {
        id: "mcp-stdio-fuzz-target",
        check: gates::mcp_stdio_deferral_violations,
    },
];

/// The `rmcp` release the stdio workaround was measured against.
///
/// The workaround, its hand-copied `INLINE_LIFECYCLE_VERSION` and every
/// deviation `docs/protocol-notes.md` records were established against exactly
/// this version. A newer SDK may have fixed the behaviour, in which case the
/// wrapper is dead weight that a reader will assume is load-bearing; or it may
/// have changed the inline-lifecycle rules, in which case the hand-copied
/// constant rots silently. Either way the answer is a measurement, and the
/// only thing a checker can honestly do is fire when the pin moves and say so.
const RMCP_VERSION_THE_WORKAROUND_WAS_MEASURED_AGAINST: &str = "3.1.0";

/// The rmcp deferral's condition: the pin moved, or the workaround is gone.
fn find_rmcp_workaround_staleness(root: &Path) -> Vec<String> {
    let manifest =
        std::fs::read_to_string(root.join("crates/bathy-mcp/Cargo.toml")).unwrap_or_default();
    let lifecycle =
        std::fs::read_to_string(root.join("crates/bathy-mcp/src/lifecycle.rs")).unwrap_or_default();

    if lifecycle.is_empty() || !lifecycle.contains("INLINE_LIFECYCLE_VERSION") {
        return vec![
            "crates/bathy-mcp/src/lifecycle.rs no longer carries the inline-lifecycle \
             workaround, so this deferral is checking nothing: remove its entry from \
             DEFERRALS and the paragraph it points at in docs/protocol-notes.md"
                .to_string(),
        ];
    }

    let pinned = manifest.lines().find_map(|line| {
        let rest = line.trim().strip_prefix("rmcp = { version = \"")?;
        rest.split('"').next().map(str::to_owned)
    });
    match pinned.as_deref() {
        None => vec![
            "crates/bathy-mcp/Cargo.toml no longer pins an rmcp version in the form \
             this check reads, so the staleness condition cannot be evaluated and \
             would pass over any SDK at all"
                .to_string(),
        ],
        Some(v) if v != RMCP_VERSION_THE_WORKAROUND_WAS_MEASURED_AGAINST => vec![format!(
            "rmcp moved from {RMCP_VERSION_THE_WORKAROUND_WAS_MEASURED_AGAINST} to {v} \
             and the stdio workaround in crates/bathy-mcp/src/lifecycle.rs has not been \
             re-measured against it. The workaround exists because rmcp made a malformed \
             opening `_meta` fatal to the process; if that is fixed the wrapper is dead \
             weight a reader will assume is load-bearing, and if the inline-lifecycle \
             rules changed the hand-copied INLINE_LIFECYCLE_VERSION has rotted. Drive the \
             opening shapes in docs/protocol-notes.md against the new SDK, then move \
             RMCP_VERSION_THE_WORKAROUND_WAS_MEASURED_AGAINST in the same commit."
        )],
        Some(_) => Vec::new(),
    }
}

/// What the tree says about the ops layer and about feature-gating.
///
/// Plain data, like [`PackageInfo`], so [`find_deferred_move_violations`] can
/// be handed synthetic facts. The rule is the part worth testing; the scrape
/// is the part that has to read files.
#[derive(Debug, Clone, PartialEq, Eq)]
struct OpsLayer {
    /// `bathy` reaches into `bathy_mcp::{engine,tools}`, and those modules
    /// are still in `bathy-mcp`. That is the arrangement the deferral is
    /// about: a layer named for one of its two consumers.
    shared_from_bathy_mcp: bool,
    /// Every site that makes `serve mcp` -- or the dependency it fronts --
    /// conditional on a cargo feature. Each is a human-readable location.
    feature_gates: Vec<String>,
}

/// The condition the M5 exit review wrote down, as a check.
///
/// The overview records that `bathy_mcp::{engine,tools}` now serves both the
/// command line and the MCP server, that the honest home for it is a crate
/// below both, and that the move is deferred for v0.1 **with one trigger**:
/// *if `serve mcp` is ever feature-gated, the ops layer must move rather than
/// be duplicated back into `bathy`* -- because feature-gating it where it
/// stands takes `scan status`, `result query` and `explain` out with it.
///
/// That trigger was prose, and this milestone built `ABSENCE_CLAIMS` on the
/// finding that prose does not enforce itself: the README asserted three
/// times that the MCP server did not exist yet, in the commit range that
/// shipped it, and every check passed. A deferral nobody can be reminded of
/// is a deferral that becomes permanent by default.
///
/// Two directions, and the second is why this is not just an `assert!`:
///
/// 1. The layer is still shared **and** something feature-gates it: the move
///    is now due, and the message says what it is.
/// 2. The layer is no longer shared: either the move happened or the sharing
///    ended, and this registration is now checking nothing. A check that has
///    quietly stopped applying is worse than no check, because it reads as
///    coverage. It reports itself, naming what to delete.
fn find_deferred_move_violations(ops: &OpsLayer) -> Vec<String> {
    if !ops.shared_from_bathy_mcp {
        return vec![
            "`bathy` no longer reaches into `bathy_mcp::{engine,tools}`, or those \
             modules have left `bathy-mcp`. The deferred move this check registers \
             has either happened or become moot, so the check now guards nothing: \
             delete `find_deferred_move_violations` and the deferral paragraph in \
             docs/superpowers/plans/2026-07-31-bathy-v0.1-overview.md, and drop \
             AC-5.39 with them"
                .to_string(),
        ];
    }
    ops.feature_gates
        .iter()
        .map(|site| {
            format!(
                "{site} makes `serve mcp` (or the crate it fronts) conditional on a \
                 cargo feature, while the ops layer both surfaces use still lives in \
                 `bathy-mcp`. That is the written trigger for the deferred move: the \
                 ops layer (`bathy-mcp`'s `engine.rs` and `tools/`) must move to a \
                 crate below both surfaces first, because gating it where it stands \
                 takes `scan status`, `result query` and `explain` out with it. See \
                 the deferral in docs/superpowers/plans/2026-07-31-bathy-v0.1-overview.md \
                 and AC-5.39"
            )
        })
        .collect()
}

/// Read [`OpsLayer`] out of the tree.
fn scrape_ops_layer(root: &Path) -> OpsLayer {
    let read = |relative: &str| std::fs::read_to_string(root.join(relative)).unwrap_or_default();

    let mut uses_ops_layer = false;
    let mut sources = Vec::new();
    collect_files(root, &root.join("crates/bathy/src"), &mut sources);
    for relative in &sources {
        let text = read(relative);
        if text.contains("bathy_mcp::tools") || text.contains("bathy_mcp::engine") {
            uses_ops_layer = true;
        }
    }
    let ops_layer_lives_in_bathy_mcp = root.join("crates/bathy-mcp/src/engine.rs").exists()
        && root.join("crates/bathy-mcp/src/tools/mod.rs").exists();

    let manifest = read("crates/bathy/Cargo.toml");
    let mut feature_gates = Vec::new();
    if manifest.contains("[features]") {
        feature_gates.push("crates/bathy/Cargo.toml declares [features]".to_string());
    }
    for line in manifest.lines() {
        if line.contains("bathy-mcp") && line.contains("optional") {
            feature_gates
                .push("crates/bathy/Cargo.toml makes bathy-mcp an optional dependency".to_string());
        }
    }
    // `bathy` has no cargo features at all today, so any `cfg(feature = ...)`
    // in its sources is new. Narrower rules -- looking only at `serve.rs`, or
    // only for a feature named `mcp` -- would miss the gate being spelled
    // some other way, and this one has no false positives to spend.
    for relative in &sources {
        if read(relative).contains("cfg(feature") {
            feature_gates.push(format!("{relative} is compiled behind a cargo feature"));
        }
    }

    OpsLayer {
        shared_from_bathy_mcp: uses_ops_layer && ops_layer_lives_in_bathy_mcp,
        feature_gates,
    }
}

/// Report every difference between a pinned crate's real direct dependencies
/// and its pinned set, in both directions -- an addition is a purity claim
/// that quietly stopped being true, and a removal is documentation naming a
/// crate that is no longer there. A pinned crate that is not in the workspace
/// at all is reported too: a renamed package must not silently disable its
/// own check.
fn find_pinned_dependency_drift(packages: &[PackageInfo]) -> Vec<String> {
    let mut drift = Vec::new();
    for (name, pinned) in PINNED_DEPENDENCIES {
        let Some(pkg) = packages.iter().find(|p| p.name == *name) else {
            drift.push(format!(
                "{name} has a pinned dependency set but is not in the workspace -- renamed, \
                 or removed without its pin"
            ));
            continue;
        };
        let actual: BTreeSet<&str> = pkg.normal_dependencies.iter().map(String::as_str).collect();
        let expected: BTreeSet<&str> = pinned.iter().copied().collect();
        for added in actual.difference(&expected) {
            drift.push(format!(
                "{name} directly depends on {added}, which is not in its pinned set; \
                 this crate's documented claim is its dependency list, so update both \
                 or drop the dependency"
            ));
        }
        for removed in expected.difference(&actual) {
            drift.push(format!(
                "{name}'s pinned set names {removed}, which it no longer depends on; \
                 the documentation that names it is now wrong"
            ));
        }
    }
    drift
}

/// Pure rule check: given a workspace's packages, return every
/// dependency-boundary or forbidden-substring violation as a human-readable
/// message. No I/O — this is what AC-1.1 and AC-1.2 test directly.
///
/// The two checks are gated independently: the layer-order check only
/// applies when the *depending* package itself has a rank (an unranked
/// package, like `xtask`, isn't part of the layer order and so can't violate
/// it). The forbidden-substring check has no such gate — AC-1.2 requires it
/// for "any workspace crate", ranked or not, so it runs over every
/// dependency of every package regardless of whether the depender is ranked.
fn find_violations(packages: &[PackageInfo]) -> Vec<String> {
    let rank: BTreeMap<&str, usize> = LAYERS.iter().enumerate().map(|(i, n)| (*n, i)).collect();
    let mut violations = Vec::new();

    for pkg in packages {
        let own_rank = rank.get(pkg.name.as_str()).copied();
        for dep_name in &pkg.dependencies {
            if let Some(own_rank) = own_rank
                && let Some(&dep_rank) = rank.get(dep_name.as_str())
                && dep_rank >= own_rank
            {
                violations.push(format!(
                    "{} depends on {dep_name}, which is not strictly lower in the layer order",
                    pkg.name
                ));
            }
            let lowered = dep_name.to_ascii_lowercase();
            if FORBIDDEN_SUBSTRINGS.iter().any(|f| lowered.contains(f)) {
                violations.push(format!(
                    "{} depends on {dep_name}, which looks like an inference client; \
                     no crate may put a model on the packet path",
                    pkg.name
                ));
            }
        }
    }

    violations
}

/// Number of packages in `packages` that are actually part of the layer
/// order (as opposed to the fixed size of `LAYERS` itself, which would stay
/// constant regardless of how many crates exist yet).
fn count_ranked(packages: &[PackageInfo]) -> usize {
    packages
        .iter()
        .filter(|p| LAYERS.contains(&p.name.as_str()))
        .count()
}

/// Parse the subset of `cargo metadata --no-deps` JSON that `find_violations`
/// needs, into the pure `PackageInfo` shape.
fn parse_packages(
    meta: &serde_json::Value,
) -> Result<Vec<PackageInfo>, Box<dyn std::error::Error>> {
    let mut packages = Vec::new();
    for pkg in meta["packages"].as_array().ok_or("no packages")? {
        let name = pkg["name"].as_str().ok_or("unnamed package")?.to_string();
        let mut dependencies = Vec::new();
        let mut normal_dependencies = Vec::new();
        for dep in pkg["dependencies"].as_array().ok_or("no dependencies")? {
            let dep_name = dep["name"].as_str().ok_or("unnamed dep")?.to_string();
            // `cargo metadata` spells a normal dependency's `kind` as `null`;
            // `"dev"` and `"build"` are the other two.
            if dep["kind"].is_null() {
                normal_dependencies.push(dep_name.clone());
            }
            dependencies.push(dep_name);
        }
        packages.push(PackageInfo {
            name,
            dependencies,
            normal_dependencies,
        });
    }
    Ok(packages)
}

fn check_deps() -> Result<(), Box<dyn std::error::Error>> {
    let meta = std::process::Command::new("cargo")
        .args(["metadata", "--format-version", "1", "--no-deps"])
        .output()?;
    let meta: serde_json::Value = serde_json::from_slice(&meta.stdout)?;
    let packages = parse_packages(&meta)?;
    let mut violations = find_violations(&packages);
    violations.extend(find_pinned_dependency_drift(&packages));
    violations.extend(find_pinned_dependency_prose_drift(Path::new(".")));
    for deferral in DEFERRALS {
        violations.extend(
            (deferral.check)(Path::new("."))
                .into_iter()
                .map(|v| format!("[{}] {v}", deferral.id)),
        );
    }

    if violations.is_empty() {
        let sites: usize = PINNED_DEPENDENCIES
            .iter()
            .map(|(name, _)| find_prose_sites(Path::new("."), name).len())
            .sum();
        println!(
            "check-deps: ok ({} crates ranked, {} pinned dependency set(s), {sites} prose \
             site(s) discovered and checked against them, {} deferral(s) registered)",
            count_ranked(&packages),
            PINNED_DEPENDENCIES.len(),
            DEFERRALS.len(),
        );
        Ok(())
    } else {
        for v in &violations {
            eprintln!("check-deps: {v}");
        }
        Err(format!("{} dependency-boundary violation(s)", violations.len()).into())
    }
}

/// The published contract: `schemas/*.json` are committed, and this is the
/// gate that stops a type change from silently altering what agents were
/// promised (AC-1.22).
///
/// `write == true` ("emit-schemas") regenerates every file under `dir` from
/// the union of every crate's `schema::all()`, unconditionally. `write == false`
/// ("check-schemas") instead compares what's on disk against what
/// regeneration would produce and fails — naming every drifted file — if
/// they differ. A missing file is treated as drift too (surfaced as an `Err`
/// naming the path, same as any other read failure), not silently skipped,
/// so a schema that was never committed at all is still caught.
fn emit_schemas(write: bool) -> Result<(), Box<dyn std::error::Error>> {
    // Every crate that publishes a wire type owns its own `schema::all()`,
    // and this is the one place they are merged -- so a new published type is
    // drift-checked by the same gate as the first four, rather than growing a
    // second mechanism. `schemars::schema_for!` needs a concrete type, so a
    // type defined in `bathy-query` (M5: `ScanFold`, `ScanDiff`) cannot be
    // named from `bathy-types` without moving the fold below the layer that
    // owns it.
    let schemas = union_schemas(vec![bathy_types::schema::all(), bathy_query::schema::all()])?;
    emit_schemas_into(&schemas, Path::new("schemas"), write)
}

/// The body of [`emit_schemas`], against a given schema set and directory so
/// the ordering below is testable without writing to this repository's own
/// `schemas/`.
///
/// **The prose check runs over the in-memory set first, and nothing is
/// written if it fires.** The first version ran `diff_or_write` and only then
/// `prose::check_dir`, which had two consequences the M5 Task 2 fix re-review
/// found. `emit-schemas` exited non-zero *and* left the leak on disk, so the
/// stated property ("regenerating cannot launder a leaked doc comment into
/// the tree") was not what the code delivered. Worse, `check-schemas` against
/// a leak that lived in a `///` rather than in the committed file saw only
/// drift -- the prose check read the still-clean committed document and found
/// nothing -- and told the maintainer to run `emit-schemas` and commit, which
/// is precisely the action that publishes the leak. Checking the source of
/// the write before the write closes both: a leak in a doc comment is now
/// reported as a leak in every mode, and drift can no longer be reported on
/// its own while one exists.
fn emit_schemas_into(
    schemas: &BTreeMap<&'static str, serde_json::Value>,
    dir: &Path,
    write: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut source_leaks = Vec::new();
    for (name, schema) in schemas {
        source_leaks.extend(prose::find_maintainer_prose(
            &format!("{name}.json"),
            schema,
        ));
    }
    if !source_leaks.is_empty() {
        return Err(format!(
            "{}\nNothing was written: the doc comments these came from are the fix, \
             and regenerating would only copy them into the committed contract.",
            leak_report(&source_leaks)
        )
        .into());
    }

    let drift = diff_or_write(schemas, dir, write)?;

    // Over every file in the directory as well, in both modes: `check_dir`
    // reads `dir` rather than the set above, so a committed document no crate
    // generates any more -- which regeneration never touches and the source
    // check above never sees -- is still checked. See `prose`'s module
    // documentation for why this is not a unit test in the crate that
    // generates the document.
    let leaks = prose::check_dir(dir)?;

    let mut problems = Vec::new();
    if !drift.is_empty() {
        problems.push(format!(
            "schema drift in: {}. The published types no longer match the committed \
             documents; run `cargo run -p xtask -- emit-schemas` and commit. (The \
             regenerated text has already been checked for maintainer prose above, so \
             following this instruction cannot publish a leaked doc comment.)",
            drift.join(", ")
        ));
    }
    if !leaks.is_empty() {
        problems.push(leak_report(&leaks));
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems.join("\n").into())
    }
}

fn leak_report(leaks: &[String]) -> String {
    format!(
        "maintainer prose reached a published contract -- make the doc comment a `//` \
         comment, or rewrite it as contract text:\n{}",
        leaks.join("\n")
    )
}

/// Merge every publishing crate's `schema::all()` into one filename-keyed
/// set, refusing a filename two crates both claim.
///
/// Pure, and separated from [`emit_schemas`] for the same reason
/// `find_violations` and `diff_or_write` are: the collision path is the one
/// that matters and it cannot be reached from the real workspace, where no
/// two crates claim a name. A rule with no way to fail in a test is a rule
/// nobody knows still works.
///
/// Silent overwrite is the failure being prevented. `BTreeMap::insert`
/// returns the displaced value rather than erroring, so a second crate
/// publishing `scan-fold` would replace the first crate's contract, the
/// committed file would follow on the next `emit-schemas`, and every check
/// would stay green.
fn union_schemas(
    sets: Vec<BTreeMap<&'static str, serde_json::Value>>,
) -> Result<BTreeMap<&'static str, serde_json::Value>, Box<dyn std::error::Error>> {
    let mut merged: BTreeMap<&'static str, serde_json::Value> = BTreeMap::new();
    for set in sets {
        for (name, schema) in set {
            if let Some(previous) = merged.insert(name, schema) {
                return Err(
                    format!("two crates both publish `schemas/{name}.json`: {previous}").into(),
                );
            }
        }
    }
    Ok(merged)
}

/// The pure-ish core of [`emit_schemas`]: given the schema set and a target
/// directory, either writes every schema (returning no drift) or reports
/// which files, if any, differ from what writing would produce. Separated
/// from `emit_schemas` (which always points at `bathy_types::schema::all()`
/// and the real `schemas/` directory) so the drift-detection logic itself is
/// testable against a synthetic schema set and a scratch directory, without
/// mutating this repository's committed schemas — mirroring `find_violations`
/// above, which is `check_deps`'s own I/O-free rule-checking core.
fn diff_or_write(
    schemas: &BTreeMap<&'static str, serde_json::Value>,
    dir: &Path,
    write: bool,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut drift = Vec::new();
    for (name, schema) in schemas {
        let path = dir.join(format!("{name}.json"));
        let rendered = format!("{}\n", serde_json::to_string_pretty(schema)?);
        if write {
            std::fs::create_dir_all(dir)?;
            std::fs::write(&path, rendered)?;
        } else {
            let on_disk = std::fs::read_to_string(&path).map_err(|e| {
                format!(
                    "{}: {e} (run `cargo run -p xtask -- emit-schemas`)",
                    path.display()
                )
            })?;
            if on_disk != rendered {
                drift.push(path.display().to_string());
            }
        }
    }
    Ok(drift)
}

/// `gen-ports`: regenerate `data/ports/top-100.txt` and
/// `data/ports/common-1000.txt` from a local copy of the IANA *Service Name
/// and Transport Protocol Port Number Registry* CSV.
///
/// # Clean-room note
///
/// This reads only the file named by `--registry`, which the caller must
/// have fetched from IANA (see `data/ports/README.md`). It never reads,
/// searches for, or consults any Nmap data file, installed or otherwise.
///
/// # The ranking heuristic
///
/// Exactly the two-step ranking documented in `data/ports/README.md`:
///
/// 1. System ports (1-1023, port 0 excluded) with a TCP assignment, ascending.
/// 2. User ports (1024-49151) with a TCP assignment, ascending.
///
/// "Has a TCP assignment" means the registry contains a row for that port
/// with `Transport Protocol == "tcp"` and a non-empty `Service Name` --
/// rows marked `Reserved` or `Unassigned` carry no service name and are
/// excluded, which is what keeps port 0 (always `Reserved` in the registry)
/// out of both datasets even before its own numeric value is checked. See
/// [`rank_ports`] for where each of these rules is enforced.
fn gen_ports() -> Result<(), Box<dyn std::error::Error>> {
    let mut registry: Option<String> = None;
    let mut out_dir = PathBuf::from("data/ports");
    let mut args = std::env::args().skip(2);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--registry" => {
                registry = Some(args.next().ok_or("--registry requires a path argument")?);
            }
            "--out-dir" => {
                out_dir = PathBuf::from(args.next().ok_or("--out-dir requires a path argument")?);
            }
            other => return Err(format!("gen-ports: unknown argument `{other}`").into()),
        }
    }
    let registry_path = registry.ok_or("gen-ports requires --registry <path-to-csv>")?;
    let csv_text = std::fs::read_to_string(&registry_path)
        .map_err(|e| format!("reading registry CSV at {registry_path}: {e}"))?;

    let ranked = rank_ports(&csv_text)?;
    write_datasets(&ranked, &out_dir)?;
    println!(
        "gen-ports: wrote {} ({} ports) and {} ({} ports) from {}",
        out_dir.join("top-100.txt").display(),
        ranked.top_100.len(),
        out_dir.join("common-1000.txt").display(),
        ranked.common_1000.len(),
        registry_path,
    );
    Ok(())
}

/// The two generated datasets. `top_100` and `common_1000` are both prefixes
/// of the same ascending, deduplicated ranking (see [`rank_ports`]), which is
/// what guarantees `top_100` is a strict subset of `common_1000` by
/// construction rather than by a separate check bolted on afterward.
#[derive(Debug)]
struct RankedPorts {
    top_100: Vec<u16>,
    common_1000: Vec<u16>,
}

/// Pure rule logic behind `gen-ports`, exercised directly by tests below
/// against small synthetic CSV fixtures -- mirroring `find_violations` and
/// `diff_or_write` above, this is the I/O-free core the process-shelling
/// parts of `gen_ports` delegate to, so the ranking algorithm itself is
/// testable without a 1MB IANA download on every `cargo test`.
fn rank_ports(csv_text: &str) -> Result<RankedPorts, String> {
    // `flexible(true)`: defensive only. The real IANA file has a consistent
    // 12 columns on every one of its ~14,500 rows (confirmed by parsing it
    // in full before writing this), so this never triggers today -- but a
    // future registry edit that introduces one short row shouldn't make the
    // whole regeneration fail when that row wouldn't have contributed a
    // port anyway.
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .from_reader(csv_text.as_bytes());
    let headers = reader
        .headers()
        .map_err(|e| format!("reading registry CSV header: {e}"))?
        .clone();
    let col = |name: &str| -> Result<usize, String> {
        headers
            .iter()
            .position(|h| h == name)
            .ok_or_else(|| format!("registry CSV is missing a \"{name}\" column"))
    };
    let service_name_idx = col("Service Name")?;
    let port_number_idx = col("Port Number")?;
    let transport_idx = col("Transport Protocol")?;

    let mut system: BTreeSet<u16> = BTreeSet::new();
    let mut user: BTreeSet<u16> = BTreeSet::new();

    for (row_num, result) in reader.records().enumerate() {
        let record =
            result.map_err(|e| format!("reading registry CSV row {}: {e}", row_num + 2))?;
        if record.get(transport_idx).unwrap_or("").trim() != "tcp" {
            continue;
        }
        if record.get(service_name_idx).unwrap_or("").trim().is_empty() {
            // No service name: "Reserved" or "Unassigned" in the registry's
            // own terms, i.e. not an assignment at all. This is also what
            // excludes port 0, which the registry lists as Reserved.
            continue;
        }
        let port_field = record.get(port_number_idx).unwrap_or("").trim();
        for port in expand_port_field(port_field) {
            match port {
                1..=1023 => {
                    system.insert(port);
                }
                1024..=49151 => {
                    user.insert(port);
                }
                // Port 0, and anything at or above the Dynamic/Private range
                // (49152-65535): out of scope for this heuristic. Port 0 is
                // never a scannable port at all (see `ports::PortError`);
                // dynamic/private ports have no meaningful "assignment" to
                // rank by in the first place.
                _ => {}
            }
        }
    }

    let ranked: Vec<u16> = system.into_iter().chain(user).collect();
    if ranked.len() < 1000 {
        return Err(format!(
            "registry yielded only {} TCP-assigned ports in 1-49151; need at least 1000 to \
             build common-1000 (top-100 needs at least 100)",
            ranked.len()
        ));
    }
    Ok(RankedPorts {
        top_100: ranked[..100].to_vec(),
        common_1000: ranked[..1000].to_vec(),
    })
}

/// Expand a registry "Port Number" field into the concrete ports it names:
/// a single integer (`"22"`), an inclusive range (`"6000-6063"`, e.g. the
/// registry's own `x11` entry), or nothing (a blank field, for a service
/// registered without a specific port yet -- about 360 rows in the current
/// registry). A malformed range (reversed, or a side that doesn't parse) is
/// treated the same as a blank field: `rank_ports` only needs the ports a
/// row legitimately identifies, not to validate every row in the registry,
/// and every value this function has actually been observed to receive
/// besides these three shapes fits one of them (checked against the full
/// downloaded file before writing this).
fn expand_port_field(field: &str) -> Vec<u16> {
    if field.is_empty() {
        return Vec::new();
    }
    if let Ok(p) = field.parse::<u16>() {
        return vec![p];
    }
    if let Some((a, b)) = field.split_once('-')
        && let (Ok(a), Ok(b)) = (a.trim().parse::<u16>(), b.trim().parse::<u16>())
        && a <= b
    {
        return (a..=b).collect();
    }
    Vec::new()
}

/// Write both dataset files under `dir`, creating it if necessary.
fn write_datasets(ranked: &RankedPorts, dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
    write_dataset(&dir.join("top-100.txt"), &ranked.top_100)?;
    write_dataset(&dir.join("common-1000.txt"), &ranked.common_1000)?;
    Ok(())
}

fn write_dataset(path: &Path, ports: &[u16]) -> Result<(), String> {
    let mut body = String::from(
        "# Generated by `cargo run -p xtask -- gen-ports`. Do not hand-edit --\n\
         # see data/ports/README.md for provenance and regeneration.\n",
    );
    for p in ports {
        body.push_str(&p.to_string());
        body.push('\n');
    }
    std::fs::write(path, body).map_err(|e| format!("writing {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `SUBCOMMANDS` is what `check-ci` validates `ci.yml` against, so a name
    /// in the list that the `match` does not dispatch would bless a CI step
    /// that fails on the runner with `unknown xtask` — which is the exact
    /// state `.publish-deny` documented for a milestone and a half.
    ///
    /// Read out of this file's own text, so the two cannot drift.
    #[test]
    fn the_dispatch_and_the_list_agree() {
        let source = include_str!("main.rs");
        let dispatched: Vec<&str> = source
            .lines()
            .filter_map(|line| line.trim().strip_prefix("Some(\""))
            .filter_map(|rest| rest.split('"').next())
            .collect();
        assert!(
            dispatched.len() >= 11,
            "only {} `Some(\"…\")` arms were found; the parse broke and this \
             comparison is vacuous",
            dispatched.len()
        );
        let mut dispatched_sorted = dispatched.clone();
        dispatched_sorted.sort_unstable();
        let mut listed = SUBCOMMANDS.to_vec();
        listed.sort_unstable();
        assert_eq!(
            dispatched_sorted, listed,
            "the `match` in `main` and `SUBCOMMANDS` disagree"
        );
    }

    // --- The deferral registry. ---

    #[test]
    fn every_registered_deferral_is_reachable_and_the_registry_is_not_empty() {
        // The count in `check-deps`'s success line used to be the literal `1`,
        // so a deferral could be deleted and the line would still claim one
        // was registered. It is `DEFERRALS.len()` now, which makes the count
        // honest and this assertion the thing that keeps it non-trivial.
        assert_eq!(
            DEFERRALS.len(),
            4,
            "the deferral registry changed size; the four entries are the ops-layer \
             move (AC-5.39), the rmcp stdio workaround, the `packetd` IPC fuzz target \
             that AC-7.7 names and M6 has not yet made writable, and the MCP stdio fuzz \
             target whose blocker is `classify`'s visibility"
        );
        let ids: Vec<&str> = DEFERRALS.iter().map(|d| d.id).collect();
        assert_eq!(
            ids,
            vec![
                "ops-layer-move",
                "rmcp-stdio-workaround",
                "packetd-ipc-fuzz-target",
                "mcp-stdio-fuzz-target"
            ]
        );
    }

    #[test]
    fn the_rmcp_deferral_is_silent_on_the_version_it_was_measured_against() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        assert!(
            find_rmcp_workaround_staleness(&root).is_empty(),
            "{:#?}",
            find_rmcp_workaround_staleness(&root)
        );
        // The premise, asserted rather than assumed: the constant and the pin
        // agree today. Without this the test above passes just as happily
        // against a parser that finds no pin at all.
        let manifest = std::fs::read_to_string(root.join("crates/bathy-mcp/Cargo.toml")).unwrap();
        assert!(
            manifest.contains(&format!(
                "rmcp = {{ version = \"{RMCP_VERSION_THE_WORKAROUND_WAS_MEASURED_AGAINST}\""
            )),
            "the pin and the measured-against constant have already diverged"
        );
    }

    #[test]
    fn the_rmcp_deferral_fires_when_the_pin_moves_and_when_the_workaround_goes() {
        let dir = std::env::temp_dir().join(format!("bathy-xtask-deferral-{}", std::process::id()));
        let mcp = dir.join("crates/bathy-mcp/src");
        std::fs::create_dir_all(&mcp).unwrap();
        let write = |manifest: &str, lifecycle: &str| {
            std::fs::write(dir.join("crates/bathy-mcp/Cargo.toml"), manifest).unwrap();
            std::fs::write(mcp.join("lifecycle.rs"), lifecycle).unwrap();
        };
        let workaround = "const INLINE_LIFECYCLE_VERSION: ProtocolVersion = X;";

        // Direction 1: the SDK moved, and nobody re-measured.
        write(
            "rmcp = { version = \"4.0.0\", default-features = false }",
            workaround,
        );
        let v = find_rmcp_workaround_staleness(&dir);
        assert_eq!(v.len(), 1, "{v:#?}");
        assert!(v[0].contains("3.1.0") && v[0].contains("4.0.0"), "{v:#?}");
        assert!(
            v[0].contains("re-measured"),
            "the message must say what to do, not merely that something changed: {v:#?}"
        );

        // Direction 2: the workaround is gone, so this registration now guards
        // nothing and says so rather than passing.
        write(
            &format!(
                "rmcp = {{ version = \"{RMCP_VERSION_THE_WORKAROUND_WAS_MEASURED_AGAINST}\" }}"
            ),
            "// the wrapper was deleted\n",
        );
        let v = find_rmcp_workaround_staleness(&dir);
        assert_eq!(v.len(), 1, "{v:#?}");
        assert!(v[0].contains("checking nothing"), "{v:#?}");

        // And the unreadable-pin direction, which would otherwise be a silent
        // pass over any SDK at all.
        write("rmcp.workspace = true", workaround);
        let v = find_rmcp_workaround_staleness(&dir);
        assert_eq!(v.len(), 1, "{v:#?}");
        assert!(v[0].contains("cannot be evaluated"), "{v:#?}");

        std::fs::remove_dir_all(&dir).ok();
    }

    fn pkg(name: &str, deps: &[&str]) -> PackageInfo {
        PackageInfo {
            name: name.to_string(),
            dependencies: deps.iter().map(|d| d.to_string()).collect(),
            normal_dependencies: deps.iter().map(|d| d.to_string()).collect(),
        }
    }

    /// A package whose `[dev-dependencies]` differ from its `[dependencies]`.
    fn pkg_with_dev(name: &str, normal: &[&str], dev: &[&str]) -> PackageInfo {
        PackageInfo {
            name: name.to_string(),
            dependencies: normal.iter().chain(dev).map(|d| d.to_string()).collect(),
            normal_dependencies: normal.iter().map(|d| d.to_string()).collect(),
        }
    }

    /// The real pinned set for `bathy-query`, as a fixture.
    fn pinned_query_deps() -> Vec<&'static str> {
        PINNED_DEPENDENCIES
            .iter()
            .find(|(n, _)| *n == "bathy-query")
            .expect("bathy-query is pinned")
            .1
            .to_vec()
    }

    #[test]
    fn a_crate_matching_its_pinned_dependency_set_is_clean() {
        let packages = vec![pkg("bathy-query", &pinned_query_deps())];
        let drift = find_pinned_dependency_drift(&packages);
        assert!(drift.is_empty(), "unexpected drift: {drift:?}");
    }

    #[test]
    fn a_new_direct_dependency_on_a_pinned_crate_is_reported() {
        // The claim `bathy-query`'s documentation makes is that nothing in
        // its graph can reach a socket, a clock or the filesystem. `tokio`
        // arriving is that claim ceasing to be true.
        let mut deps = pinned_query_deps();
        deps.push("tokio");
        let drift = find_pinned_dependency_drift(&[pkg("bathy-query", &deps)]);
        assert_eq!(drift.len(), 1, "{drift:?}");
        assert!(drift[0].contains("tokio"), "{drift:?}");
        assert!(drift[0].contains("pinned set"), "{drift:?}");
    }

    #[test]
    fn a_dependency_that_disappears_from_a_pinned_crate_is_reported_too() {
        // The other direction: documentation naming a crate that is no
        // longer there is wrong in the same way, and only a two-sided check
        // catches it.
        let deps: Vec<&str> = pinned_query_deps()
            .into_iter()
            .filter(|d| *d != "thiserror")
            .collect();
        let drift = find_pinned_dependency_drift(&[pkg("bathy-query", &deps)]);
        assert_eq!(drift.len(), 1, "{drift:?}");
        assert!(drift[0].contains("thiserror"), "{drift:?}");
    }

    #[test]
    fn a_dev_dependency_does_not_count_against_a_pinned_set() {
        // `bathy-query` really does dev-depend on `bathy-engine` and friends
        // to fold the log of a real scan. The pin is about what a *consumer*
        // builds, which is `[dependencies]` only -- a pin that counted dev
        // dependencies would have to be updated by every new test fixture and
        // would be turned off within a milestone.
        let packages = vec![pkg_with_dev(
            "bathy-query",
            &pinned_query_deps(),
            &["bathy-engine", "tempfile", "tokio", "proptest"],
        )];
        let drift = find_pinned_dependency_drift(&packages);
        assert!(drift.is_empty(), "unexpected drift: {drift:?}");
    }

    #[test]
    fn a_pinned_crate_missing_from_the_workspace_is_reported_not_skipped() {
        // A renamed package must not silently disable its own check.
        let drift = find_pinned_dependency_drift(&[pkg("bathy-types", &[])]);
        assert_eq!(drift.len(), 1, "{drift:?}");
        assert!(drift[0].contains("bathy-query"), "{drift:?}");
        assert!(drift[0].contains("not in the workspace"), "{drift:?}");
    }

    #[test]
    fn parse_packages_separates_dev_dependencies_from_normal_ones() {
        // The `kind` field is the whole basis of the distinction above, so
        // the parse of it is asserted directly rather than assumed.
        let meta = serde_json::json!({"packages": [{
            "name": "bathy-query",
            "dependencies": [
                {"name": "bathy-types", "kind": null},
                {"name": "serde", "kind": null},
                {"name": "bathy-engine", "kind": "dev"},
                {"name": "cc", "kind": "build"},
            ],
        }]});
        let packages = parse_packages(&meta).unwrap();
        assert_eq!(
            packages[0].normal_dependencies,
            vec!["bathy-types", "serde"]
        );
        assert_eq!(
            packages[0].dependencies,
            vec!["bathy-types", "serde", "bathy-engine", "cc"],
            "the layer and forbidden-substring rules still see every kind"
        );
    }

    #[test]
    fn layer_violation_is_detected() {
        // AC-1.1: bathy-types (layer 0) depending on bathy-scope (layer 1)
        // depends on something at or above its own layer.
        let packages = vec![pkg("bathy-types", &["bathy-scope"])];
        let violations = find_violations(&packages);
        assert_eq!(
            violations.len(),
            1,
            "expected exactly one violation: {violations:?}"
        );
        assert!(violations[0].contains("bathy-types depends on bathy-scope"));
    }

    #[test]
    fn same_layer_dependency_is_a_violation() {
        // A crate depending on a peer at its own rank is >= its own layer.
        let packages = vec![pkg("bathy-probe", &["bathy-probe"])];
        let violations = find_violations(&packages);
        assert_eq!(
            violations.len(),
            1,
            "expected exactly one violation: {violations:?}"
        );
    }

    #[test]
    fn strictly_lower_layer_dependency_is_fine() {
        let packages = vec![pkg("bathy-scope", &["bathy-types"])];
        let violations = find_violations(&packages);
        assert!(
            violations.is_empty(),
            "unexpected violations: {violations:?}"
        );
    }

    #[test]
    fn forbidden_substring_dependency_is_detected() {
        // AC-1.2
        let packages = vec![pkg("bathy-probe", &["async-openai"])];
        let violations = find_violations(&packages);
        assert_eq!(
            violations.len(),
            1,
            "expected exactly one violation: {violations:?}"
        );
        assert!(violations[0].contains("looks like an inference client"));
    }

    #[test]
    fn forbidden_substring_dependency_is_detected_for_unranked_depender() {
        // AC-1.2 says "any workspace crate", not "any ranked crate". xtask
        // itself is a real workspace member but has no entry in LAYERS, so
        // it must not get a free pass on the forbidden-substring rule.
        let packages = vec![pkg("xtask", &["async-openai"])];
        let violations = find_violations(&packages);
        assert_eq!(
            violations.len(),
            1,
            "expected exactly one violation: {violations:?}"
        );
        assert!(violations[0].contains("looks like an inference client"));
    }

    #[test]
    fn ordinary_dependency_is_not_flagged() {
        let packages = vec![pkg("bathy-probe", &["serde"])];
        let violations = find_violations(&packages);
        assert!(
            violations.is_empty(),
            "unexpected violations: {violations:?}"
        );
    }

    #[test]
    fn empty_workspace_has_no_violations() {
        let violations = find_violations(&[]);
        assert!(violations.is_empty());
    }

    // --- diff_or_write: the drift-detection core behind AC-1.22, exercised
    // against a synthetic schema set and a scratch directory rather than the
    // real `schemas/` this repository commits. Each test cleans up its own
    // directory at the end so scratch state never leaks between tests. ---

    fn scratch_dir(label: &str) -> std::path::PathBuf {
        // Unique per test *and* per call within a test, so parallel test
        // threads (cargo test's default) never collide on the same path.
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "xtask-diff-or-write-test-{label}-{}-{n}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        dir
    }

    fn one_schema() -> BTreeMap<&'static str, serde_json::Value> {
        let mut m = BTreeMap::new();
        m.insert("thing", serde_json::json!({"type": "object"}));
        m
    }

    #[test]
    fn union_schemas_merges_disjoint_sets() {
        let a = BTreeMap::from([("scan-fold", serde_json::json!({"type": "object"}))]);
        let b = BTreeMap::from([("event", serde_json::json!({"type": "object"}))]);
        let merged = union_schemas(vec![a, b]).unwrap();
        assert_eq!(
            merged.keys().copied().collect::<Vec<_>>(),
            vec!["event", "scan-fold"]
        );
    }

    #[test]
    fn union_schemas_refuses_a_filename_two_crates_both_claim() {
        // Unreachable from the real workspace, which is exactly why it needs
        // a test: `insert` would silently replace one published contract with
        // another and every check downstream would stay green.
        let a = BTreeMap::from([("scan-fold", serde_json::json!({"title": "first"}))]);
        let b = BTreeMap::from([("scan-fold", serde_json::json!({"title": "second"}))]);
        let err = union_schemas(vec![a, b]).unwrap_err().to_string();
        assert!(err.contains("scan-fold.json"), "{err}");
        assert!(err.contains("two crates"), "{err}");
        assert!(
            err.contains("first"),
            "the error must show the contract that would have been overwritten: {err}"
        );
    }

    #[test]
    fn write_true_creates_the_directory_and_file() {
        let dir = scratch_dir("write-creates");
        let drift = diff_or_write(&one_schema(), &dir, true).unwrap();
        assert!(drift.is_empty(), "write mode should report no drift");
        let on_disk = std::fs::read_to_string(dir.join("thing.json")).unwrap();
        assert_eq!(on_disk, "{\n  \"type\": \"object\"\n}\n");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn check_false_reports_no_drift_immediately_after_write() {
        let dir = scratch_dir("check-matches");
        diff_or_write(&one_schema(), &dir, true).unwrap();
        let drift = diff_or_write(&one_schema(), &dir, false).unwrap();
        assert!(drift.is_empty(), "expected no drift, got {drift:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn check_false_names_the_file_when_on_disk_content_differs() {
        // Proves the "one byte edited" case: write the real schema, hand-edit
        // the file on disk, then confirm check mode names it.
        let dir = scratch_dir("check-byte-edit");
        diff_or_write(&one_schema(), &dir, true).unwrap();
        let path = dir.join("thing.json");
        let mut edited = std::fs::read_to_string(&path).unwrap();
        edited.push_str("   "); // trailing bytes: still "one byte changed" in spirit
        std::fs::write(&path, edited).unwrap();

        let drift = diff_or_write(&one_schema(), &dir, false).unwrap();
        assert_eq!(
            drift.len(),
            1,
            "expected exactly one drifted file: {drift:?}"
        );
        assert!(
            drift[0].ends_with("thing.json"),
            "drift entry should name the file, got {drift:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn check_false_fails_when_a_type_gains_a_field_and_regeneration_never_ran() {
        // The case the check exists for: the schema *source* (what
        // `bathy_types::schema::all()` would now produce) has changed --
        // simulated here by handing `diff_or_write` a schema set with an
        // extra property -- but nobody re-ran `emit-schemas`, so the
        // committed file is still the old shape. This must be reported as
        // drift even though no one touched the file on disk at all.
        let dir = scratch_dir("check-added-field");
        diff_or_write(&one_schema(), &dir, true).unwrap();

        let mut changed = BTreeMap::new();
        changed.insert(
            "thing",
            serde_json::json!({"type": "object", "properties": {"new_field": {"type": "string"}}}),
        );
        let drift = diff_or_write(&changed, &dir, false).unwrap();
        assert_eq!(
            drift.len(),
            1,
            "a type gaining a field without regeneration must be reported as drift: {drift:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- The prose about the pinned set: discovered, not listed. ---

    fn write(root: &Path, relative: &str, text: &str) {
        let path = root.join(relative);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, text).unwrap();
    }

    const WHOLE_SET: &str = "`bathy-query`'s [dependencies] are `bathy-types`, `schemars`, `serde`, \
         `serde_json` and `thiserror`.";

    #[test]
    fn a_dependency_is_named_only_when_it_is_named_as_a_crate() {
        // The bug: `contains` made `serde_json` satisfy the pin on `serde`,
        // so a site that dropped one of the two passed on the strength of
        // the other.
        assert!(!names_dependency("serde_json = \"1\"", "serde"));
        assert!(names_dependency("serde_json = \"1\"", "serde_json"));

        // Every punctuation this repository actually wraps a crate name in.
        for text in [
            "serde = { version = \"1\" }",
            "`serde`, and nothing else",
            "serde.workspace = true",
            "(serde)",
            "serde",
        ] {
            assert!(names_dependency(text, "serde"), "{text}");
        }

        // A hyphen is a name character too, so a longer name must not
        // satisfy a shorter prefix of it.
        assert!(!names_dependency("bathy-types-extra", "bathy-types"));
        assert!(names_dependency("`bathy-types`,", "bathy-types"));
    }

    // -----------------------------------------------------------------
    // The deferred ops-layer move (AC-5.39).
    // -----------------------------------------------------------------

    fn ops(shared: bool, gates: &[&str]) -> OpsLayer {
        OpsLayer {
            shared_from_bathy_mcp: shared,
            feature_gates: gates.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn feature_gating_serve_mcp_while_the_ops_layer_is_still_shared_is_refused() {
        let found = find_deferred_move_violations(&ops(true, &["crates/bathy/Cargo.toml"]));
        assert_eq!(found.len(), 1);
        assert!(found[0].contains("must move to a crate below both surfaces"));
    }

    #[test]
    fn a_shared_ops_layer_that_nothing_gates_is_the_arrangement_v0_1_ships() {
        assert!(find_deferred_move_violations(&ops(true, &[])).is_empty());
    }

    #[test]
    fn the_registration_reports_itself_once_it_has_stopped_applying() {
        // The vacuity direction. If `bathy` stops reaching into
        // `bathy_mcp::{engine,tools}` -- because the move happened, or
        // because the sharing ended some other way -- this check guards
        // nothing, and a check that reads as coverage while guarding nothing
        // is the failure mode the whole file is written against.
        let found = find_deferred_move_violations(&ops(false, &[]));
        assert_eq!(found.len(), 1);
        assert!(found[0].contains("guards nothing"), "{}", found[0]);
    }

    #[test]
    fn the_scrape_sees_the_sharing_this_repository_actually_has_and_no_gate() {
        // Without this, every rule test above could be exercising a fact the
        // scraper never produces: the premise of the whole registration is
        // that `bathy` really does call into `bathy_mcp::tools` today.
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let scraped = scrape_ops_layer(&root);
        assert!(
            scraped.shared_from_bathy_mcp,
            "the ops layer is not shared any more; see \
             `the_registration_reports_itself_once_it_has_stopped_applying`"
        );
        assert!(scraped.feature_gates.is_empty(), "{scraped:?}");
    }

    #[test]
    fn the_scrape_finds_a_gate_however_it_is_spelled() {
        for (relative, text) in [
            (
                "crates/bathy/Cargo.toml",
                "[features]\nmcp = [\"dep:bathy-mcp\"]\n",
            ),
            (
                "crates/bathy/Cargo.toml",
                "[dependencies]\nbathy-mcp = { path = \"../bathy-mcp\", optional = true }\n",
            ),
            (
                "crates/bathy/src/commands/serve.rs",
                "#[cfg(feature = \"mcp\")]\nfn serve() {}\n",
            ),
        ] {
            let root = scratch_dir("deferred-move");
            // The arrangement the deferral is about, so the gate is the only
            // thing that varies between these three cases.
            write(&root, "crates/bathy-mcp/src/engine.rs", "// ops layer");
            write(&root, "crates/bathy-mcp/src/tools/mod.rs", "// ops layer");
            write(
                &root,
                "crates/bathy/src/commands/scope.rs",
                "bathy_mcp::tools::scope::validate",
            );
            write(&root, relative, text);

            let scraped = scrape_ops_layer(&root);
            assert!(scraped.shared_from_bathy_mcp, "{relative}: {scraped:?}");
            assert!(
                !scraped.feature_gates.is_empty(),
                "{relative} spells a feature gate that the scrape does not see: {text}"
            );
            assert_eq!(
                find_deferred_move_violations(&scraped).len(),
                scraped.feature_gates.len()
            );
            let _ = std::fs::remove_dir_all(&root);
        }
    }

    #[test]
    fn every_real_prose_site_names_every_crate_in_the_pinned_set() {
        // The check over this repository, which is what the seventh site --
        // `.github/workflows/ci.yml`, the premise of the MSRV job split --
        // was missing.
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let drift = find_pinned_dependency_prose_drift(&root);
        assert!(drift.is_empty(), "{}", drift.join("\n"));
    }

    #[test]
    fn discovery_finds_the_sites_that_used_to_be_listed_by_hand() {
        // The four paths the hand-maintained array held. This is not a
        // ceiling -- a fifth site is welcome and is the point -- it is a
        // floor: it fails if the discovery rule is ever narrowed until one
        // of the known claims stops being checked.
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let sites = find_prose_sites(&root, "bathy-query");
        for known in [
            "crates/bathy-query/Cargo.toml",
            "crates/bathy-query/src/lib.rs",
            "crates/bathy-query/tests/real_log_fold.rs",
            ".github/workflows/ci.yml",
        ] {
            assert!(
                sites.iter().any(|s| s == known),
                "{known} is no longer discovered as a prose site; sites were {sites:?}"
            );
        }
    }

    #[test]
    fn a_site_nobody_listed_is_discovered_and_reported_when_it_omits_a_crate() {
        // The defect this replaced a hand-maintained array to fix: a fifth
        // file, written by someone who did not know the array existed.
        let root = scratch_dir("prose-fifth-site");
        write(&root, "crates/bathy-query/src/lib.rs", WHOLE_SET);
        write(
            &root,
            "docs/architecture.md",
            "`bathy-query`'s direct dependencies are `bathy-types`, `serde` and \
             `serde_json`.",
        );
        let drift = find_pinned_dependency_prose_drift(&root);
        assert!(
            drift
                .iter()
                .any(|d| d.contains("docs/architecture.md") && d.contains("schemars")),
            "{drift:?}"
        );
        assert!(
            drift
                .iter()
                .any(|d| d.contains("docs/architecture.md") && d.contains("thiserror")),
            "{drift:?}"
        );
        assert!(
            !drift.iter().any(|d| d.contains("lib.rs")),
            "the complete site must be clean: {drift:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_file_that_merely_depends_on_the_crate_is_not_a_site() {
        // `crates/bathy/Cargo.toml` names `bathy-query` under
        // `[dependencies]` alongside `serde` and `serde_json`, and says
        // nothing about `bathy-query`'s own dependencies. Mere co-occurrence
        // must not make it a site -- a check with false positives gets
        // deleted, and this is the commonest false positive available.
        let root = scratch_dir("prose-mere-dependent");
        write(&root, "crates/bathy-query/src/lib.rs", WHOLE_SET);
        write(
            &root,
            "crates/bathy/Cargo.toml",
            "[dependencies]\nbathy-query = { path = \"../bathy-query\" }\n\
             serde.workspace = true\nserde_json.workspace = true\n",
        );
        let sites = find_prose_sites(&root, "bathy-query");
        assert!(
            !sites.iter().any(|s| s == "crates/bathy/Cargo.toml"),
            "{sites:?}"
        );
        assert!(find_pinned_dependency_prose_drift(&root).is_empty());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn a_pinned_set_that_no_site_describes_at_all_is_reported_not_passed() {
        // Discovery's own failure mode. With a hand-maintained list, an
        // entry that stopped existing was reported as unreadable; with
        // discovery there is no entry to miss, so the way this check dies
        // quietly is that every site gets reworded past every claim phrase
        // and nothing is left to check.
        let root = scratch_dir("prose-vacuous");
        write(
            &root,
            "crates/bathy-query/src/lib.rs",
            "A fold over an event log.",
        );
        let drift = find_pinned_dependency_prose_drift(&root);
        assert!(
            drift
                .iter()
                .any(|d| d.contains("nothing in the tree states")),
            "{drift:?}"
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn discovery_does_not_walk_the_excluded_categories() {
        // Each exclusion is a category with a reason (see
        // `PROSE_DISCOVERY_EXCLUSIONS`); this pins that they are actually
        // skipped rather than merely documented, and that a directory whose
        // name merely *starts* with an excluded one is not.
        for excluded in [
            "target/debug/x.rs",
            "Cargo.lock",
            "xtask/src/main.rs",
            ".superpowers/notes.md",
            "docs/superpowers/plans/m5.md",
        ] {
            assert!(is_excluded_from_prose_discovery(excluded), "{excluded}");
        }
        assert!(
            !is_excluded_from_prose_discovery(".github/workflows/ci.yml"),
            "`.github` is not `.git`, and it holds a real site"
        );
        assert!(!is_excluded_from_prose_discovery("docs/superpowers/sdd.md"));
    }

    // --- emit_schemas_into: the prose check runs before the write. ---

    fn leaky_schema() -> BTreeMap<&'static str, serde_json::Value> {
        BTreeMap::from([(
            "thing",
            serde_json::json!({
                "title": "Thing",
                "description": "Kept in sync with the loader in manifest.rs by hand.",
                "type": "object",
            }),
        )])
    }

    #[test]
    fn a_leak_in_a_doc_comment_is_refused_before_anything_is_written() {
        // The write-before-check ordering the fix re-review found: the
        // command exited non-zero and the leak was on disk anyway.
        let dir = scratch_dir("emit-leak-write");
        let err = emit_schemas_into(&leaky_schema(), &dir, true)
            .unwrap_err()
            .to_string();
        assert!(err.contains("maintainer prose"), "{err}");
        assert!(err.contains("thing.json"), "{err}");
        assert!(err.contains("Nothing was written"), "{err}");
        assert!(
            !dir.exists(),
            "emit-schemas must not create the directory, let alone the file, \
             when the schema it would write carries maintainer prose"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_leak_in_a_doc_comment_is_never_reported_as_mere_drift() {
        // The trap: with a clean file committed and a leak added to the
        // `///` it came from, `check-schemas` used to report only drift and
        // tell the maintainer to run `emit-schemas` and commit -- which is
        // exactly the action that publishes the leak. The prose check reads
        // the committed file, which is still clean, so it said nothing.
        let dir = scratch_dir("emit-leak-drift");
        emit_schemas_into(&one_schema(), &dir, true).expect("a clean schema writes");
        let clean = std::fs::read_to_string(dir.join("thing.json")).unwrap();

        let err = emit_schemas_into(&leaky_schema(), &dir, false)
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("maintainer prose"),
            "the leak must be named, not hidden behind a drift report: {err}"
        );
        assert!(
            !err.contains("schema drift"),
            "a source leak must not be reported as drift with an `emit-schemas` \
             instruction attached: {err}"
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("thing.json")).unwrap(),
            clean,
            "check mode must leave the committed document alone"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn ordinary_drift_still_names_the_files_and_the_remedy() {
        // The other side of the previous test: with no leak anywhere, drift
        // must still be reported and must still point at `emit-schemas`.
        let dir = scratch_dir("emit-plain-drift");
        emit_schemas_into(&one_schema(), &dir, true).unwrap();
        let changed = BTreeMap::from([(
            "thing",
            serde_json::json!({"type": "object", "properties": {"new_field": {"type": "string"}}}),
        )]);
        let err = emit_schemas_into(&changed, &dir, false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("schema drift"), "{err}");
        assert!(err.contains("thing.json"), "{err}");
        assert!(err.contains("emit-schemas"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_leak_in_a_committed_document_no_crate_generates_is_still_caught() {
        // `find_maintainer_prose` over the in-memory set cannot see this
        // one; only the directory read can. Both must run.
        let dir = scratch_dir("emit-orphan");
        emit_schemas_into(&one_schema(), &dir, true).unwrap();
        std::fs::write(
            dir.join("orphan-legacy.json"),
            r#"{"title":"OrphanLegacy","description":"Superseded by revision one; see fold.rs."}"#,
        )
        .unwrap();
        let err = emit_schemas_into(&one_schema(), &dir, false)
            .unwrap_err()
            .to_string();
        assert!(err.contains("orphan-legacy.json"), "{err}");
        assert!(err.contains("maintainer prose"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn check_false_errors_naming_the_path_when_the_file_is_missing_entirely() {
        let dir = scratch_dir("check-missing");
        let err = diff_or_write(&one_schema(), &dir, false).unwrap_err();
        assert!(
            err.to_string().contains("thing.json"),
            "error should name the missing file: {err}"
        );
        assert!(
            err.to_string().contains("emit-schemas"),
            "error should point at the remediation command: {err}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // --- gen-ports: expand_port_field ---------------------------------

    #[test]
    fn expand_port_field_parses_a_single_port() {
        assert_eq!(expand_port_field("22"), vec![22]);
    }

    #[test]
    fn expand_port_field_expands_an_inclusive_range() {
        // The registry's own shape for this: `x11` is listed as `6000-6063`.
        assert_eq!(
            expand_port_field("6000-6063"),
            (6000..=6063).collect::<Vec<u16>>()
        );
    }

    #[test]
    fn expand_port_field_treats_a_blank_field_as_no_ports() {
        assert_eq!(expand_port_field(""), Vec::<u16>::new());
    }

    #[test]
    fn expand_port_field_treats_a_reversed_range_as_no_ports_not_a_panic() {
        assert_eq!(expand_port_field("100-50"), Vec::<u16>::new());
    }

    #[test]
    fn expand_port_field_treats_non_numeric_garbage_as_no_ports_not_a_panic() {
        for garbage in ["http", "n/a", "-", "1-", "-1", "1-2-3"] {
            assert_eq!(expand_port_field(garbage), Vec::<u16>::new(), "{garbage}");
        }
    }

    // --- gen-ports: rank_ports -----------------------------------------

    /// The full 12-column header the real IANA registry uses, in its real
    /// order. `rank_ports` looks columns up by name, not position, but this
    /// keeps the fixture honest about the shape it will actually see.
    const REGISTRY_HEADER: &[&str] = &[
        "Service Name",
        "Port Number",
        "Transport Protocol",
        "Description",
        "Assignee",
        "Contact",
        "Registration Date",
        "Modification Date",
        "Reference",
        "Service Code",
        "Unauthorized Use Reported",
        "Assignment Notes",
    ];

    /// Build a row with every column the real registry has, so the fixture
    /// building code below reads as "the fields that matter" rather than a
    /// wall of empty-string positional arguments.
    fn registry_row(
        service_name: &str,
        port: &str,
        transport: &str,
        description: &str,
    ) -> Vec<String> {
        vec![
            service_name.to_string(),
            port.to_string(),
            transport.to_string(),
            description.to_string(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
        ]
    }

    /// Render rows to CSV text through the real `csv` crate's writer, not by
    /// hand-joining with commas -- this is the same quoting/escaping engine
    /// `rank_ports` reads back with, so a fixture built this way proves
    /// round-tripping through embedded commas, quotes, and newlines the same
    /// way the real IANA file needs (see the module doc on why a naive
    /// `split(',')` was rejected for this task).
    fn render_csv(header: &[&str], rows: &[Vec<String>]) -> String {
        let mut writer = csv::Writer::from_writer(Vec::new());
        writer.write_record(header).unwrap();
        for row in rows {
            writer.write_record(row).unwrap();
        }
        String::from_utf8(writer.into_inner().unwrap()).unwrap()
    }

    /// A registry fixture large enough to produce both real datasets:
    /// `system_count` ascending TCP-named system ports (starting at 1) and
    /// `user_count` ascending TCP-named user ports (starting at 1024), plus
    /// a handful of rows that must each be excluded for a different reason
    /// (see the assertions in the tests that use this).
    fn synthetic_registry(system_count: u16, user_count: u16) -> String {
        let mut rows = Vec::new();
        for p in 1..=system_count {
            rows.push(registry_row(
                &format!("svc-sys-{p}"),
                &p.to_string(),
                "tcp",
                "system",
            ));
        }
        for i in 0..user_count {
            let p = 1024 + i;
            rows.push(registry_row(
                &format!("svc-usr-{p}"),
                &p.to_string(),
                "tcp",
                "user",
            ));
        }
        // Port 0: always Reserved in the real registry (empty service name).
        rows.push(registry_row("", "0", "tcp", "Reserved"));
        // UDP-only port: must not leak into the TCP ranking.
        rows.push(registry_row("udp-only", "9999", "udp", "udp only"));
        // Unassigned in the system range: empty service name, must be excluded.
        rows.push(registry_row("", "777", "tcp", "Unassigned"));
        // A blank Port Number: a real registry pattern for a service that
        // hasn't been assigned a specific port yet.
        rows.push(registry_row("no-port-yet", "", "tcp", "pending"));
        // A ranged assignment, the registry's own `x11`-shaped row, with a
        // quoted, comma- and newline-bearing description -- the exact shape
        // that broke a naive comma-split parse during exploration.
        rows.push(registry_row(
            "x11-like",
            "6000-6063",
            "tcp",
            "X Window System, ports 6000-6063\nsee RFC-ish notes, allegedly",
        ));
        render_csv(REGISTRY_HEADER, &rows)
    }

    #[test]
    fn rank_ports_produces_sorted_unique_prefixed_datasets() {
        let csv_text = synthetic_registry(200, 850); // 1050 total, > 1000
        let ranked = rank_ports(&csv_text).unwrap();

        assert_eq!(ranked.top_100.len(), 100);
        assert_eq!(ranked.common_1000.len(), 1000);

        for name in ["top_100", "common_1000"] {
            let v = if name == "top_100" {
                &ranked.top_100
            } else {
                &ranked.common_1000
            };
            let mut sorted = v.clone();
            sorted.sort_unstable();
            sorted.dedup();
            assert_eq!(*v, sorted, "{name} must be sorted and unique");
        }

        assert!(
            ranked
                .top_100
                .iter()
                .all(|p| ranked.common_1000.contains(p)),
            "top_100 must be a subset of common_1000"
        );

        // System ports precede user ports, exactly as the documented
        // heuristic promises, and the synthetic fixture's system range
        // (1..=200) is entirely inside top_100.
        assert_eq!(ranked.top_100, (1..=100).collect::<Vec<u16>>());

        // Exclusions: port 0, the UDP-only port, the unnamed/Unassigned
        // port, and the blank-port row must never appear.
        assert!(!ranked.common_1000.contains(&0));
        assert!(!ranked.common_1000.contains(&9999));
        assert!(!ranked.common_1000.contains(&777));
    }

    #[test]
    fn rank_ports_expands_a_ranged_row_but_it_does_not_affect_the_top_of_the_ranking() {
        // The synthetic fixture's x11-like row (6000-6063) sits far above
        // both cutoffs (200 system + 850 user tops out at 1873), so it must
        // not appear in either dataset even though it's a legitimate TCP
        // assignment -- this is `rank_ports` correctly using *rank*, not
        // just "is it assigned at all".
        let csv_text = synthetic_registry(200, 850);
        let ranked = rank_ports(&csv_text).unwrap();
        assert!(!ranked.common_1000.contains(&6000));
        assert!(!ranked.common_1000.contains(&6063));
    }

    #[test]
    fn rank_ports_fails_clearly_rather_than_panicking_on_too_little_data() {
        let csv_text = synthetic_registry(5, 5); // 10 total, far under 1000
        let err = rank_ports(&csv_text).unwrap_err();
        assert!(
            err.contains("10") || err.to_lowercase().contains("only"),
            "error should explain the shortfall: {err}"
        );
    }

    #[test]
    fn rank_ports_reports_a_missing_required_column_by_name() {
        let csv_text = render_csv(&["Service Name", "Transport Protocol"], &[]);
        let err = rank_ports(&csv_text).unwrap_err();
        assert!(
            err.contains("Port Number"),
            "error should name the missing column: {err}"
        );
    }

    // --- gen-ports: write_datasets --------------------------------------

    #[test]
    fn write_datasets_writes_both_files_sorted_one_port_per_line() {
        let dir = scratch_dir("gen-ports-write");
        let ranked = RankedPorts {
            top_100: (1..=100).collect(),
            common_1000: (1..=1000).collect(),
        };
        write_datasets(&ranked, &dir).unwrap();

        for (file, expected_len) in [("top-100.txt", 100usize), ("common-1000.txt", 1000)] {
            let text = std::fs::read_to_string(dir.join(file)).unwrap();
            let ports: Vec<u16> = text
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(|l| l.parse().unwrap())
                .collect();
            assert_eq!(ports.len(), expected_len, "{file}");
            let mut sorted = ports.clone();
            sorted.sort_unstable();
            sorted.dedup();
            assert_eq!(
                ports, sorted,
                "{file} must already be sorted and unique on disk"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
