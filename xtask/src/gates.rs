//! The gates that lived only inside `.github/workflows/ci.yml`, made into
//! programs a person can run.
//!
//! # Why this file exists
//!
//! Every gate in this project is `cargo run -p xtask -- check-<something>`
//! except the ones that are not, and the ones that are not are the ones that
//! go red and stay red. The AC-2.1 phrase rules were three inline `grep`
//! pipelines in `ci.yml` and nowhere else; they were red from `89142bf` to the
//! end of M5 while six task reports and a milestone review called them green,
//! because running "the documented gate commands" never ran them. That is now
//! `check-phrases`.
//!
//! The M5 close-out review then enumerated the rest of the class. Five gates
//! had no local form:
//!
//! 1. **AC-4.10**, `bathy-interpret`'s dependency purity — inline shell, and
//!    the forbidden-crate list existed only inside one `grep -iE`.
//! 2. **The MSRV `1.88` floor** — the gate is a *combination* of a toolchain
//!    action, `rm -f rust-toolchain.toml` and a crate list, and the
//!    `cargo +1.88 …` incantation appeared nowhere in the repository.
//! 3. **The MSRV `1.95` floor** — the same shape one tier up.
//! 4. **The "exactly one job" membership rule** — prose in a YAML comment with
//!    *no* executable form at all, and three recorded recurrences
//!    (`bathy-plan` in M3, `crates/bathy` in M4, `bathy-mcp` in M5). Highest
//!    recidivism in the repository; sole enforcement was a comment.
//! 5. **The `deny` job** — an action invoked with no `command:`, so what ran
//!    was the action's built-in default, written down nowhere here.
//!
//! [`check_purity`], [`check_msrv`] and [`check_deny`] are those, in that
//! order. [`publish_check`] closes a sixth thing the review found: `.publish-deny`
//! said *"Consumed by `xtask publish-check`"* and no such subcommand existed.
//!
//! # The meta-gate
//!
//! Closing five instances of a class is not closing the class. [`check_ci`] is
//! the part that is: it reads `ci.yml` and fails on any `run:` step that is
//! neither a `cargo run -p xtask -- …` call to a subcommand that exists, nor
//! one of the small, named set of cargo built-ins (`fmt`, `clippy`, `test`)
//! that need no wrapper. A sixth inline gate cannot be added without either
//! giving it a local form or writing its exemption down next to the others.
//!
//! # What genuinely cannot be an xtask subcommand
//!
//! **Installing a toolchain.** `dtolnay/rust-toolchain@1.88` provisions a
//! compiler on a fresh runner; a Rust program that needs that compiler to have
//! been built cannot be what installs it. So the split is: the *provisioning*
//! stays in `ci.yml`, and everything checkable about it moves here —
//! [`check_msrv`] verifies that each MSRV job pins a toolchain some crate
//! actually declares, that it removes `rust-toolchain.toml` (without which the
//! `stable` pin silently overrides the floor and the job checks nothing), and
//! that the crate lists satisfy the membership rule. `check-msrv --run` then
//! executes the floors locally with `cargo +<toolchain>`, which needs no file
//! moved because an explicit `+toolchain` overrides `rust-toolchain.toml`.
//!
//! **Installing `cargo-deny`.** Same reasoning. [`check_deny`] runs it and
//! says how to install it if it is absent, rather than passing quietly.

use std::path::Path;

type Fallible<T> = Result<T, Box<dyn std::error::Error>>;

// ---------------------------------------------------------------------------
// AC-4.10 — `bathy-interpret`'s dependency tree is pure.
// ---------------------------------------------------------------------------

/// The exact direct dependency set `bathy-interpret` is allowed.
///
/// Equality, not containment: something silently *dropped* is as much a
/// change to the claim as something added, and the claim ("this crate can be
/// replayed with the network interface down") is about the whole set.
pub const INTERPRET_DIRECT_DEPENDENCIES: &[&str] = &["bathy-types", "regex"];

/// Crates that must not appear anywhere in `bathy-interpret`'s tree, direct or
/// transitive, each with the reason it is named.
///
/// This list existed only inside one `grep -iE` alternation in `ci.yml` and
/// was referenced by nothing else in the repository — the same shape as the
/// three phrase greps. The rationales are here because a bare list of crate
/// names is a list nobody can maintain: the next person needs to know whether
/// a new crate belongs on it.
pub const FORBIDDEN_IN_INTERPRET: &[(&str, &str)] = &[
    (
        "tokio",
        "an async runtime; this crate decides in memory and awaits nothing",
    ),
    ("tokio-util", "an async runtime's companion, same reason"),
    ("mio", "the event loop under tokio; reaches the OS poller"),
    (
        "async-trait",
        "async in the trait surface means an async caller",
    ),
    ("fs4", "file locking, which means a filesystem"),
    (
        "rusqlite",
        "a database, and with it a filesystem and a C build",
    ),
    (
        "libsqlite3-sys",
        "the same, one level down, and it raises the MSRV floor",
    ),
    ("walkdir", "directory traversal"),
    (
        "tempfile",
        "creates files, and consults the clock and the RNG to name them",
    ),
    ("filetime", "reads and writes file timestamps, so: a clock"),
];

/// A dependency-purity finding, reported the way `phrases.rs` reports one:
/// with the thing that is wrong and enough context to act on it.
#[derive(Debug, PartialEq, Eq)]
pub struct PurityViolation(pub String);

impl std::fmt::Display for PurityViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// The rule, pure. `direct` is the crate's direct normal dependencies;
/// `tree` is every crate in its normal dependency closure, itself included.
///
/// No filesystem and no subprocess, so the tests below feed it the graphs it
/// is supposed to reject instead of standing up a workspace that has them.
pub fn purity_violations(direct: &[String], tree: &[String]) -> Vec<PurityViolation> {
    let mut found = Vec::new();

    let mut got: Vec<&str> = direct.iter().map(String::as_str).collect();
    got.sort_unstable();
    got.dedup();
    let mut want: Vec<&str> = INTERPRET_DIRECT_DEPENDENCIES.to_vec();
    want.sort_unstable();
    if got != want {
        found.push(PurityViolation(format!(
            "bathy-interpret's direct dependencies changed:\n  got:  {}\n  want: {}\n\
             AC-4.10 is an equality: M4 Task 4's replay corpus runs with the network \
             interface down and M7's fuzz target runs without sockets because this set \
             is exactly these two crates.",
            got.join(" "),
            want.join(" "),
        )));
    }

    for crate_name in tree {
        if let Some((_, why)) = FORBIDDEN_IN_INTERPRET
            .iter()
            .find(|(name, _)| name == crate_name)
        {
            found.push(PurityViolation(format!(
                "{crate_name} is in bathy-interpret's dependency tree: {why}. \
                 It may have arrived transitively through bathy-types or regex — \
                 run `cargo tree -p bathy-interpret --edges normal` to see the path."
            )));
        }
    }

    found
}

/// `cargo tree -p bathy-interpret --edges normal --prefix none`, parsed.
///
/// The first line is the crate itself; every line's first whitespace-delimited
/// field is a crate name. Deliberately the same invocation `ci.yml` used, so
/// this is a move rather than a reimplementation with its own opinions about
/// what a dependency is.
fn cargo_tree(depth: Option<u32>) -> Fallible<Vec<String>> {
    let mut args = vec![
        "tree",
        "-p",
        "bathy-interpret",
        "--edges",
        "normal",
        "--prefix",
        "none",
    ];
    let depth = depth.map(|d| d.to_string());
    if let Some(d) = depth.as_deref() {
        args.push("--depth");
        args.push(d);
    }
    let out = std::process::Command::new("cargo").args(&args).output()?;
    if !out.status.success() {
        return Err(format!(
            "cargo tree failed: {}",
            String::from_utf8_lossy(&out.stderr)
        )
        .into());
    }
    Ok(String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .collect())
}

pub fn check_purity() -> Fallible<()> {
    let direct: Vec<String> = cargo_tree(Some(1)).map(|mut v| {
        if !v.is_empty() {
            v.remove(0); // the crate itself
        }
        v
    })?;
    let mut tree = cargo_tree(None)?;
    tree.sort();
    tree.dedup();

    let violations = purity_violations(&direct, &tree);
    if violations.is_empty() {
        println!(
            "check-purity: ok (direct deps {}; {} crate(s) in the normal tree, none of \
             the {} forbidden)",
            direct.join(" "),
            tree.len(),
            FORBIDDEN_IN_INTERPRET.len(),
        );
        Ok(())
    } else {
        for v in &violations {
            eprintln!("check-purity: {v}");
        }
        Err(format!(
            "{} dependency-purity violation(s) (AC-4.10)",
            violations.len()
        )
        .into())
    }
}

// ---------------------------------------------------------------------------
// The MSRV membership rule.
// ---------------------------------------------------------------------------

/// A crate that is deliberately named in **two** MSRV jobs, and why.
///
/// The standing rule is "a crate declaring a floor appears in exactly one of
/// these two jobs". `bathy-query` is the one crate that cannot: its library
/// floor is `1.88` — its `[dependencies]` are `bathy-types`, `schemars`,
/// `serde`, `serde_json` and `thiserror`, every one already in the 1.88-clean
/// graph — while its *test* targets reach a `1.95` build script. Naming it in
/// one job would make a claim nobody checks — the precise defect M3 found in
/// `bathy-plan`.
///
/// That five-crate list is not maintained by memory: it is pinned in `main.rs`
/// and `check-deps` fails on this very file if a direct dependency is added or
/// removed without this sentence moving with it. (It found this comment on its
/// first run, which is the point.)
///
/// So the exception is written down rather than being an unexplained second
/// occurrence, and it carries the `--all-targets` disposition per tier,
/// because that split is the entire point: at `1.88` **without**
/// `--all-targets` (the floor a downstream consumer experiences, and the only
/// one `rust-version` governs) and at `1.95` **with** it (the floor the test
/// harness needs). A naive local re-run that passed `--all-targets` to both
/// would lose the distinction and report a green that means nothing.
const DUAL_TIER: &[(&str, &[(&str, bool)])] =
    &[("bathy-query", &[("1.88", false), ("1.95", true)])];

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct MsrvCheck {
    /// The crates named with `-p` on this `cargo check` line.
    pub crates: Vec<String>,
    pub all_targets: bool,
    /// 1-based line number in `ci.yml`.
    pub line: usize,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct MsrvJob {
    pub name: String,
    pub toolchain: String,
    pub toolchain_line: usize,
    /// Whether the job removes `rust-toolchain.toml`. Without it the repo's
    /// `stable` pin wins over the installed toolchain and the job silently
    /// checks `stable` twice instead of checking a floor.
    pub removes_toolchain_pin: bool,
    pub checks: Vec<MsrvCheck>,
}

impl MsrvJob {
    pub fn crates(&self) -> Vec<&str> {
        self.checks
            .iter()
            .flat_map(|c| c.crates.iter().map(String::as_str))
            .collect()
    }
}

/// A workspace crate and the compiler floor it declares.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct CrateFloor {
    pub name: String,
    pub floor: String,
    /// Repository-relative, for the error message.
    pub manifest: String,
}

/// Parse the MSRV jobs out of a workflow document.
///
/// Line-oriented rather than a YAML parse: `xtask` has no YAML dependency, the
/// structure being read is three keys deep, and a parser that accepted more
/// shapes than `ci.yml` actually uses would be a second definition of the
/// workflow. A job is an MSRV job iff it pins a `dtolnay/rust-toolchain@` to
/// something other than `stable`.
pub fn parse_msrv_jobs(ci: &str) -> Vec<MsrvJob> {
    let mut jobs: Vec<MsrvJob> = Vec::new();
    let mut current: Option<MsrvJob> = None;

    for (index, line) in ci.lines().enumerate() {
        let number = index + 1;
        // A job key: exactly two spaces of indent, then `name:`.
        if let Some(rest) = line.strip_prefix("  ")
            && !rest.starts_with(' ')
            && !rest.starts_with('#')
            && !rest.starts_with('-')
            && let Some(name) = rest.strip_suffix(':')
        {
            if let Some(job) = current.take()
                && job.toolchain != "stable"
            {
                jobs.push(job);
            }
            current = Some(MsrvJob {
                name: name.to_string(),
                toolchain: String::new(),
                toolchain_line: 0,
                removes_toolchain_pin: false,
                checks: Vec::new(),
            });
            continue;
        }
        let Some(job) = current.as_mut() else {
            continue;
        };
        if let Some(at) = line.find("dtolnay/rust-toolchain@") {
            job.toolchain = line[at + "dtolnay/rust-toolchain@".len()..]
                .split_whitespace()
                .next()
                .unwrap_or_default()
                .to_string();
            job.toolchain_line = number;
        }
        if line.contains("rm -f rust-toolchain.toml") {
            job.removes_toolchain_pin = true;
        }
        if let Some(at) = line.find("cargo check ") {
            let command = &line[at..];
            let mut fields = command.split_whitespace().peekable();
            let mut crates = Vec::new();
            while let Some(field) = fields.next() {
                if field == "-p"
                    && let Some(name) = fields.next()
                {
                    crates.push(name.to_string());
                }
            }
            job.checks.push(MsrvCheck {
                crates,
                all_targets: command.contains("--all-targets"),
                line: number,
            });
        }
    }
    if let Some(job) = current.take()
        && job.toolchain != "stable"
        && !job.checks.is_empty()
    {
        jobs.push(job);
    }
    jobs.retain(|job| !job.checks.is_empty() && job.toolchain != "stable");
    jobs
}

/// The membership rule, executable at last. `ci_path` is used only to name the
/// file in messages.
///
/// Six things are checked, and each one has a recorded instance behind it:
///
/// 1. Every crate declaring a floor is named in at least one MSRV job. This is
///    the rule with three recurrences — `bathy-plan` (M3), `crates/bathy` (M4)
///    and `bathy-mcp` (M5) were each given a floor and named in neither job.
/// 2. Every crate named in a job exists in the workspace and declares a floor,
///    so a rename leaves a dangling `-p` rather than a silent no-op.
/// 3. The floor a crate declares is checked by exactly one job — the one whose
///    toolchain equals it. A crate named only in jobs above its own floor has
///    its declared floor unchecked, which is the defect stated at full size.
/// 4. A crate named in more than one job is in [`DUAL_TIER`], with the
///    `--all-targets` disposition it is there for. This is where "exactly one
///    job" lives; the exception is declared rather than tolerated.
/// 5. [`DUAL_TIER`] names no crate that appears in only one job — a dead
///    exception is a licence nobody revoked.
/// 6. Every MSRV job removes `rust-toolchain.toml`. The repository pins
///    `stable`; a job that installs `1.88` and leaves the pin in place builds
///    with `stable` and reports a floor it never checked.
pub fn msrv_violations(ci_path: &str, jobs: &[MsrvJob], floors: &[CrateFloor]) -> Vec<String> {
    let mut found = Vec::new();

    if jobs.is_empty() {
        found.push(format!(
            "{ci_path}: no MSRV job was found at all. Either the jobs were removed or \
             this parser stopped recognising them; both make every check below vacuous."
        ));
        return found;
    }
    if floors.is_empty() {
        found.push(
            "no workspace crate declares a `rust-version`, so the membership rule has \
             nothing to range over and would pass over any workflow at all"
                .to_string(),
        );
        return found;
    }

    for job in jobs {
        if !job.removes_toolchain_pin {
            found.push(format!(
                "{ci_path}:{}: job `{}` installs {} but never removes \
                 `rust-toolchain.toml`. The repository pins `stable`, which wins, so \
                 this job checks `stable` and reports a floor it did not build.",
                job.toolchain_line, job.name, job.toolchain,
            ));
        }
        if !floors.iter().any(|c| c.floor == job.toolchain) {
            found.push(format!(
                "{ci_path}:{}: job `{}` pins toolchain {} and no crate in the workspace \
                 declares that floor. Either the job is checking a version nobody \
                 promises, or a crate's `rust-version` moved without its job moving.",
                job.toolchain_line, job.name, job.toolchain,
            ));
        }
        for check in &job.checks {
            for named in &check.crates {
                if !floors.iter().any(|c| &c.name == named) {
                    found.push(format!(
                        "{ci_path}:{}: job `{}` names `-p {named}`, which is not a \
                         workspace crate declaring a `rust-version`.",
                        check.line, job.name,
                    ));
                }
            }
        }
    }

    for floor in floors {
        let appearances: Vec<&MsrvJob> = jobs
            .iter()
            .filter(|job| job.crates().contains(&floor.name.as_str()))
            .collect();
        if appearances.is_empty() {
            found.push(format!(
                "{} declares `rust-version = \"{}\"` ({}) and is named in NO msrv job, \
                 so the floor it promises downstream consumers is never built. This is \
                 the fourth instance of this defect: bathy-plan (M3), crates/bathy (M4) \
                 and bathy-mcp (M5) were the first three. Add it to the job whose \
                 toolchain is {}.",
                floor.name, floor.floor, floor.manifest, floor.floor,
            ));
            continue;
        }
        let at_its_floor: Vec<&&MsrvJob> = appearances
            .iter()
            .filter(|job| job.toolchain == floor.floor)
            .collect();
        if at_its_floor.len() != 1 {
            found.push(format!(
                "{} declares `rust-version = \"{}\"` ({}) and appears in {} job(s) \
                 pinned to that toolchain (expected exactly 1); it appears in [{}]. A \
                 crate checked only above its own floor has a declared floor nothing \
                 builds.",
                floor.name,
                floor.floor,
                floor.manifest,
                at_its_floor.len(),
                appearances
                    .iter()
                    .map(|j| format!("{}@{}", j.name, j.toolchain))
                    .collect::<Vec<_>>()
                    .join(", "),
            ));
        }
        let declared = DUAL_TIER.iter().find(|(name, _)| *name == floor.name);
        if appearances.len() > 1 {
            match declared {
                None => found.push(format!(
                    "{} is named in {} msrv jobs ([{}]). The standing rule is exactly \
                     one; a crate whose tests reach further down the stack than its \
                     library does has two floors and belongs in `DUAL_TIER` with the \
                     reason and the `--all-targets` disposition written out.",
                    floor.name,
                    appearances.len(),
                    appearances
                        .iter()
                        .map(|j| j.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", "),
                )),
                Some((_, tiers)) => {
                    for (toolchain, all_targets) in *tiers {
                        let matching: Vec<&&MsrvJob> = appearances
                            .iter()
                            .filter(|job| job.toolchain == *toolchain)
                            .collect();
                        let Some(job) = matching.first() else {
                            found.push(format!(
                                "{} is declared in DUAL_TIER at toolchain {toolchain}, \
                                 and no msrv job pinned to {toolchain} names it.",
                                floor.name,
                            ));
                            continue;
                        };
                        for check in &job.checks {
                            if check.crates.iter().any(|c| c == &floor.name)
                                && check.all_targets != *all_targets
                            {
                                found.push(format!(
                                    "{ci_path}:{}: {} is checked at {toolchain} with \
                                     `--all-targets` = {}, and DUAL_TIER declares {}. \
                                     The split is the whole reason this crate is named \
                                     twice: at its library floor WITHOUT --all-targets \
                                     (which would build the dev-dependencies and turn \
                                     it into a check of the test harness) and at the \
                                     test floor WITH it.",
                                    check.line, floor.name, check.all_targets, all_targets,
                                ));
                            }
                        }
                    }
                }
            }
        } else if declared.is_some() {
            found.push(format!(
                "{} is declared in DUAL_TIER but appears in only one msrv job. A dead \
                 exception is a licence nobody revoked; remove the entry.",
                floor.name,
            ));
        }
    }

    found
}

/// Every workspace member that declares a compiler floor, with the floor
/// resolved through `rust-version.workspace = true`.
///
/// Read from the manifests rather than from `cargo metadata` so the message
/// can name the file the number is written in, which is the file that has to
/// change.
pub fn crate_floors(root: &Path) -> Fallible<Vec<CrateFloor>> {
    let workspace_floor = literal_rust_version(&std::fs::read_to_string(root.join("Cargo.toml"))?);
    let mut floors = Vec::new();
    let mut dirs = vec![root.join("crates"), root.to_path_buf()];
    dirs.push(root.join("xtask"));
    let mut manifests: Vec<std::path::PathBuf> = Vec::new();
    for entry in std::fs::read_dir(root.join("crates"))? {
        let path = entry?.path();
        if path.is_dir() {
            manifests.push(path.join("Cargo.toml"));
        }
    }
    manifests.push(root.join("xtask/Cargo.toml"));
    dirs.clear();

    for manifest in manifests {
        if !manifest.is_file() {
            continue;
        }
        let text = std::fs::read_to_string(&manifest)?;
        let name = package_name(&text).ok_or_else(|| format!("{manifest:?} has no name"))?;
        let floor = if text
            .lines()
            .any(|l| l.trim_start().starts_with("rust-version.workspace = true"))
        {
            workspace_floor.clone()
        } else {
            literal_rust_version(&text)
        };
        let Some(floor) = floor else { continue };
        floors.push(CrateFloor {
            name,
            floor,
            manifest: manifest
                .strip_prefix(root)
                .unwrap_or(&manifest)
                .to_string_lossy()
                .replace('\\', "/"),
        });
    }
    floors.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(floors)
}

/// `rust-version = "X"` from a manifest, ignoring the many comment lines in
/// this repository that discuss one.
fn literal_rust_version(text: &str) -> Option<String> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.starts_with('#'))
        .find_map(|line| {
            let rest = line.strip_prefix("rust-version")?.trim_start();
            let rest = rest.strip_prefix('=')?.trim();
            Some(rest.trim_matches('"').to_string())
        })
}

fn package_name(text: &str) -> Option<String> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.starts_with('#'))
        .find_map(|line| {
            let rest = line.strip_prefix("name")?.trim_start();
            let rest = rest.strip_prefix('=')?.trim();
            Some(rest.trim_matches('"').to_string())
        })
}

/// The exact local commands the MSRV jobs run, derived from `ci.yml` rather
/// than remembered.
///
/// No file needs moving to run these: an explicit `+toolchain` on the command
/// line overrides `rust-toolchain.toml`, which is what `rm -f` exists to work
/// around on a runner where the toolchain is the *default* instead.
pub fn msrv_commands(jobs: &[MsrvJob]) -> Vec<Vec<String>> {
    let mut commands = Vec::new();
    for job in jobs {
        for check in &job.checks {
            let mut argv = vec![format!("+{}", job.toolchain), "check".to_string()];
            for name in &check.crates {
                argv.push("-p".to_string());
                argv.push(name.clone());
            }
            if check.all_targets {
                argv.push("--all-targets".to_string());
            }
            commands.push(argv);
        }
    }
    commands
}

pub fn check_msrv(run: bool) -> Fallible<()> {
    let root = Path::new(".");
    let ci_path = ".github/workflows/ci.yml";
    let ci = std::fs::read_to_string(root.join(ci_path))
        .map_err(|e| format!("reading {ci_path}: {e}"))?;
    let jobs = parse_msrv_jobs(&ci);
    let floors = crate_floors(root)?;
    let violations = msrv_violations(ci_path, &jobs, &floors);

    if !violations.is_empty() {
        for v in &violations {
            eprintln!("check-msrv: {v}");
        }
        return Err(format!("{} msrv membership violation(s)", violations.len()).into());
    }

    let commands = msrv_commands(&jobs);
    println!(
        "check-msrv: ok ({} crate(s) declaring a floor, {} job(s): {})",
        floors.len(),
        jobs.len(),
        jobs.iter()
            .map(|j| format!("{}@{}", j.name, j.toolchain))
            .collect::<Vec<_>>()
            .join(", "),
    );
    for argv in &commands {
        println!("  cargo {}", argv.join(" "));
    }
    if !run {
        println!(
            "  (membership only. `check-msrv --run` builds each floor above; \
             installing the toolchains is `rustup toolchain install <version>` and is \
             the one part of this gate that cannot be an xtask subcommand.)"
        );
        return Ok(());
    }
    for argv in &commands {
        eprintln!("check-msrv: cargo {}", argv.join(" "));
        let status = std::process::Command::new("cargo").args(argv).status()?;
        if !status.success() {
            return Err(format!(
                "`cargo {}` failed. If the toolchain is missing, install it with \
                 `rustup toolchain install <version>`; if it compiled and failed, the \
                 floor moved and the crate's `rust-version` and its job must move too.",
                argv.join(" ")
            )
            .into());
        }
    }
    println!("check-msrv: {} floor build(s) ok", commands.len());
    Ok(())
}

// ---------------------------------------------------------------------------
// The `deny` job.
// ---------------------------------------------------------------------------

/// The four checks `cargo deny` performs, named explicitly.
///
/// `ci.yml` used `EmbarkStudios/cargo-deny-action@v2` with no `command:` and
/// no `arguments:`, so what actually ran was the action's built-in default —
/// written down nowhere in this repository, and free to change under a
/// floating `@v2`. Naming the four here and in `ci.yml`, and asserting that
/// the two agree, is what makes the local run the same run.
pub const DENY_CHECKS: &[&str] = &["advisories", "bans", "licenses", "sources"];

/// The check set `ci.yml`'s deny job declares, if it declares one.
pub fn deny_checks_in_ci(ci: &str) -> Option<Vec<String>> {
    let mut in_deny = false;
    for line in ci.lines() {
        // A comment discussing `arguments:` is not a declaration of one. This
        // file's deny job carries a paragraph about the input having been
        // absent, and reading that paragraph as the check set produced a
        // failure message quoting its own prose.
        if line.trim_start().starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("  ")
            && !rest.starts_with(' ')
            && let Some(name) = rest.strip_suffix(':')
        {
            in_deny = name == "deny";
        }
        if in_deny && let Some(at) = line.find("arguments:") {
            return Some(
                line[at + "arguments:".len()..]
                    .split_whitespace()
                    .map(str::to_owned)
                    .collect(),
            );
        }
    }
    None
}

pub fn check_deny() -> Fallible<()> {
    let ci_path = ".github/workflows/ci.yml";
    let ci = std::fs::read_to_string(Path::new(".").join(ci_path))
        .map_err(|e| format!("reading {ci_path}: {e}"))?;
    match deny_checks_in_ci(&ci) {
        None => {
            return Err(format!(
                "{ci_path}: the deny job declares no `arguments:`, so what runs there is \
                 the action's built-in default and this command cannot reproduce it. \
                 Declare the check set explicitly — see DENY_CHECKS."
            )
            .into());
        }
        Some(declared) if declared != DENY_CHECKS => {
            return Err(format!(
                "{ci_path}: the deny job runs `{}` and this command runs `{}`. A local \
                 gate that checks a different set from CI is worse than none.",
                declared.join(" "),
                DENY_CHECKS.join(" "),
            )
            .into());
        }
        Some(_) => {}
    }

    let out = std::process::Command::new("cargo")
        .arg("deny")
        .arg("check")
        .args(DENY_CHECKS)
        .status();
    match out {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(
            "cargo-deny is not installed. `cargo install cargo-deny --locked`. \
             Installing it is the one part of this gate that cannot be an xtask \
             subcommand — a program that needs the tool cannot be what provides it."
                .into(),
        ),
        Err(e) => Err(e.into()),
        Ok(status) if !status.success() => {
            Err(format!("cargo deny check {} failed", DENY_CHECKS.join(" ")).into())
        }
        Ok(_) => {
            println!("check-deny: ok ({})", DENY_CHECKS.join(" "));
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// `publish-check` — the subcommand `.publish-deny` already named.
// ---------------------------------------------------------------------------

/// Directories never scanned for publish-denied strings.
const NEVER_SCANNED: &[&str] = &[".git", "target", "node_modules", "mutants.out"];

/// Where the denied strings live. Git-ignored on purpose: the list itself is
/// the thing that must not be published.
pub const PUBLISH_DENY_FILE: &str = ".publish-deny";

/// Non-comment, non-blank entries of a `.publish-deny` document.
pub fn publish_denied_strings(text: &str) -> Vec<&str> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect()
}

pub fn publish_check() -> Fallible<()> {
    let root = Path::new(".");
    let deny_path = root.join(PUBLISH_DENY_FILE);
    let text = std::fs::read_to_string(&deny_path).map_err(|e| {
        format!(
            "{PUBLISH_DENY_FILE}: {e}. This file is git-ignored, so a fresh clone does \
             not have one and this gate is local-only by construction — which is why it \
             is not a step in ci.yml."
        )
    })?;
    let denied = publish_denied_strings(&text);
    if denied.is_empty() {
        return Err(format!(
            "{PUBLISH_DENY_FILE} lists no strings, so this check would pass over any \
             tree at all. An empty deny list is not an empty risk."
        )
        .into());
    }

    let mut files = Vec::new();
    walk(root, &mut files)?;
    let mut violations = Vec::new();
    let mut scanned = 0usize;
    for file in &files {
        let relative = file
            .strip_prefix(root)
            .unwrap_or(file)
            .to_string_lossy()
            .replace('\\', "/");
        if relative == PUBLISH_DENY_FILE {
            continue;
        }
        let Ok(bytes) = std::fs::read(file) else {
            continue;
        };
        let Ok(content) = String::from_utf8(bytes) else {
            continue; // binary, as `grep -I` treats it
        };
        scanned += 1;
        for (index, line) in content.lines().enumerate() {
            for needle in &denied {
                if line.contains(needle) {
                    violations.push(format!("{relative}:{}: {needle}", index + 1));
                }
            }
        }
    }

    if scanned == 0 {
        return Err("publish-check read no files, so it proves nothing".into());
    }
    if violations.is_empty() {
        println!(
            "publish-check: ok ({} denied string(s), {scanned} file reads, 0 violations)",
            denied.len()
        );
        Ok(())
    } else {
        for v in &violations {
            eprintln!("publish-check: {v}");
        }
        Err(format!(
            "{} publish-denied string(s) in tracked content",
            violations.len()
        )
        .into())
    }
}

fn walk(dir: &Path, into: &mut Vec<std::path::PathBuf>) -> Fallible<()> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .map_err(|e| format!("reading {}: {e}", dir.display()))?
        .collect::<Result<Vec<_>, _>>()?;
    entries.sort_by_key(std::fs::DirEntry::path);
    for entry in entries {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if path.is_dir() {
            if NEVER_SCANNED.contains(&name.as_str()) {
                continue;
            }
            walk(&path, into)?;
        } else if path.is_file() {
            into.push(path);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The meta-gate: every CI step is runnable locally.
// ---------------------------------------------------------------------------

/// `run:` steps that are cargo built-ins and need no wrapper to be runnable.
///
/// Each is already a command anyone can type; wrapping `cargo fmt` in an
/// xtask subcommand would add a spelling, not a capability. Everything NOT on
/// this list must be `cargo run -p xtask -- <subcommand>`.
const RUNNABLE_WITHOUT_XTASK: &[&str] = &[
    "cargo fmt",
    "cargo clippy",
    "cargo test",
    // Provisioning, not checking: see this module's header for why the
    // toolchain half of the MSRV gate cannot be an xtask subcommand. The
    // checkable half is `check-msrv`, which reads these very lines.
    "rm -f rust-toolchain.toml",
    "cargo check -p",
];

/// The rule: no gate without a local form. `subcommands` is `xtask`'s actual
/// dispatch list, so a step naming a subcommand that does not exist fails
/// here — which is what `.publish-deny` needed and did not have.
pub fn ci_steps_without_a_local_form(ci_path: &str, ci: &str, subcommands: &[&str]) -> Vec<String> {
    let mut found = Vec::new();
    let mut steps = 0usize;
    for (index, line) in ci.lines().enumerate() {
        let number = index + 1;
        let trimmed = line.trim_start();
        let Some(rest) = trimmed
            .strip_prefix("- run:")
            .or_else(|| trimmed.strip_prefix("run:"))
        else {
            continue;
        };
        let command = rest.trim();
        if command == "|" {
            found.push(format!(
                "{ci_path}:{number}: an inline `run: |` block. Every gate this project \
                 has lost was an inline shell block: the three phrase greps (AC-2.1, red \
                 for half a milestone while six reports called it green) and \
                 bathy-interpret's purity check (AC-4.10). Move it into `xtask` and call \
                 it here."
            ));
            steps += 1;
            continue;
        }
        steps += 1;
        if let Some(rest) = command.strip_prefix("cargo run -p xtask -- ") {
            let name = rest.split_whitespace().next().unwrap_or("");
            if !subcommands.contains(&name) {
                found.push(format!(
                    "{ci_path}:{number}: calls `xtask {name}`, which is not a \
                     subcommand. `.publish-deny` documented exactly this — a gate \
                     command that exits `unknown xtask`."
                ));
            }
            continue;
        }
        if RUNNABLE_WITHOUT_XTASK
            .iter()
            .any(|allowed| command.starts_with(allowed))
        {
            continue;
        }
        found.push(format!(
            "{ci_path}:{number}: `{command}` is neither an xtask subcommand nor one of \
             the declared cargo built-ins, so it is a gate with no local form. Add it to \
             `xtask` (the `check-phrases` pattern) or, if it genuinely cannot be one, \
             add it to RUNNABLE_WITHOUT_XTASK with the reason."
        ));
    }
    if steps == 0 {
        found.push(format!(
            "{ci_path}: no `run:` step was found, so this check ranged over nothing"
        ));
    }
    found
}

pub fn check_ci(subcommands: &[&str]) -> Fallible<()> {
    let ci_path = ".github/workflows/ci.yml";
    let ci = std::fs::read_to_string(Path::new(".").join(ci_path))
        .map_err(|e| format!("reading {ci_path}: {e}"))?;
    let violations = ci_steps_without_a_local_form(ci_path, &ci, subcommands);
    if violations.is_empty() {
        let steps = ci
            .lines()
            .filter(|l| l.trim_start().starts_with("- run:"))
            .count();
        println!(
            "check-ci: ok ({steps} run step(s), {} xtask subcommand(s), \
             {} declared built-in(s))",
            subcommands.len(),
            RUNNABLE_WITHOUT_XTASK.len(),
        );
        Ok(())
    } else {
        for v in &violations {
            eprintln!("check-ci: {v}");
        }
        Err(format!("{} CI step(s) with no local form", violations.len()).into())
    }
}

// ---------------------------------------------------------------------------
// AC-7.1 — the integration lab is pinned, and its ground truth describes it.
// ---------------------------------------------------------------------------

pub const LAB_COMPOSE: &str = "lab/docker-compose.yml";
pub const LAB_GROUND_TRUTH: &str = "lab/ground-truth.json";

/// Every `image:` reference in a compose file, with its 1-based line number.
///
/// Text, not YAML: this check has to run on a machine with no Docker and no
/// YAML crate in `xtask`'s tree, and the shape it cares about ("the token
/// after `image:`") survives any formatting the file could take.
pub fn image_references(compose: &str) -> Vec<(usize, String)> {
    compose
        .lines()
        .enumerate()
        .filter_map(|(index, line)| {
            let trimmed = line.trim_start().trim_start_matches("- ");
            let rest = trimmed.strip_prefix("image:")?;
            let reference = rest.trim();
            (!reference.is_empty()).then(|| (index + 1, reference.to_string()))
        })
        .collect()
}

/// Whether `reference` names an image by content digest rather than by tag.
///
/// A digest is `sha256:` followed by exactly 64 lowercase hex characters.
/// Uppercase is rejected rather than normalised: `docker` renders digests
/// lowercase, so an uppercase one is a hand-edit, and a hand-edited digest is
/// the thing this check exists to notice.
pub fn is_digest_pinned(reference: &str) -> bool {
    let Some((name, digest)) = reference.split_once('@') else {
        return false;
    };
    if name.is_empty() {
        return false;
    }
    let Some(hex) = digest.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64
        && hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Every static address `labnet` assigns, with its 1-based line number.
fn assigned_addresses(compose: &str) -> Vec<(usize, String)> {
    compose
        .lines()
        .enumerate()
        .filter_map(|(index, line)| {
            let rest = line.trim_start().strip_prefix("ipv4_address:")?;
            let address = rest.trim();
            (!address.is_empty()).then(|| (index + 1, address.to_string()))
        })
        .collect()
}

/// What is wrong with the lab, as text a person can act on.
///
/// Two families of finding, and they are here together because they fail the
/// same way. AC-7.1 is the pinning rule: a moving tag silently changes the
/// banners `bathy-interpret`'s rules are tested against. The rest is the rule
/// the milestone plan states in prose and nothing enforced — **a wrong
/// ground-truth file is worse than no lab at all**, because it makes every
/// future disagreement look like our bug, or makes a real bug look like
/// agreement. A service added to the compose file and not to the ground truth
/// produces exactly that, and produces it silently.
///
/// Both texts are parameters so the tests can feed seeded violations rather
/// than mutating the repository.
pub fn lab_violations(
    compose_path: &str,
    compose: &str,
    truth_path: &str,
    truth: &serde_json::Value,
) -> Vec<String> {
    let mut found = Vec::new();

    // --- AC-7.1: every image pinned by digest. ---
    let images = image_references(compose);
    for (number, reference) in &images {
        if !is_digest_pinned(reference) {
            found.push(format!(
                "{compose_path}:{number}: `{reference}` is not pinned by digest. Use \
                 `<name>@sha256:<64 lowercase hex>`: a tag moves, and when it moves it \
                 changes the banners the interpretation rules are tested against, so \
                 the lab stops being an oracle without anything going red. \
                 `docker image inspect <name>:<tag> --format '{{{{index .RepoDigests 0}}}}'` \
                 prints the multi-architecture digest to paste here."
            ));
        }
    }
    if images.is_empty() {
        found.push(format!(
            "{compose_path}: no `image:` line was found, so the pinning check ranged \
             over nothing"
        ));
    }

    // --- The ground truth describes this lab and not some other one. ---
    let assigned: std::collections::BTreeSet<String> = assigned_addresses(compose)
        .into_iter()
        .map(|(_, a)| a)
        .collect();
    if assigned.is_empty() {
        found.push(format!(
            "{compose_path}: no `ipv4_address:` line was found, so the ground-truth \
             cross-check ranged over nothing"
        ));
    }

    let hosts = truth.get("hosts").and_then(|h| h.as_array());
    let Some(hosts) = hosts else {
        found.push(format!("{truth_path}: no `hosts` array"));
        return found;
    };
    let described: std::collections::BTreeSet<String> = hosts
        .iter()
        .filter_map(|h| h.get("ip").and_then(|i| i.as_str()).map(str::to_string))
        .collect();

    for address in assigned.difference(&described) {
        found.push(format!(
            "{compose_path}: `labnet` assigns {address} but {truth_path} does not \
             describe it. A host the oracle does not account for is a false positive \
             waiting to be blamed on the scanner."
        ));
    }
    for address in described.difference(&assigned) {
        found.push(format!(
            "{truth_path}: describes {address}, which `labnet` assigns to nothing in \
             {compose_path}. The oracle is describing a lab that is not this one."
        ));
    }

    let absent: Vec<&str> = truth
        .get("absent")
        .and_then(|a| a.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();
    if absent.is_empty() {
        found.push(format!(
            "{truth_path}: no `absent` address. AC-7.4 has nothing to assert over, so \
             a scanner that reported every address in the subnet as live would pass."
        ));
    }
    for address in &absent {
        if assigned.contains(*address) {
            found.push(format!(
                "{truth_path}: {address} is listed as absent but {compose_path} assigns \
                 it to a container."
            ));
        }
    }

    // --- The narrowing controls, per the overview's fixture constraint. ---
    //
    // "A fixture that satisfies every branch tests none of them." A ground
    // truth in which every host has an open port gives AC-7.3 nothing to
    // catch; one whose scanned port set contains no port that is closed on a
    // live host gives it nothing either -- a scanner that reported every port
    // it touched as open would satisfy both.
    let scanned: Vec<u64> = truth
        .get("scanned_ports")
        .and_then(|p| p.as_array())
        .map(|a| a.iter().filter_map(serde_json::Value::as_u64).collect())
        .unwrap_or_default();
    if scanned.is_empty() {
        found.push(format!(
            "{truth_path}: no `scanned_ports`. Zero false positives is a claim about a \
             stated port set; without one it claims nothing."
        ));
    }

    let open_of = |host: &serde_json::Value| -> Vec<u64> {
        host.get("open")
            .and_then(|o| o.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|e| e.get("port").and_then(serde_json::Value::as_u64))
                    .collect()
            })
            .unwrap_or_default()
    };

    if !hosts.iter().any(|h| open_of(h).is_empty()) {
        found.push(format!(
            "{truth_path}: every described host has an open port, so a scanner that \
             never reported a host as closed would still pass. The lab needs a live \
             host that answers nothing."
        ));
    }
    if !hosts.iter().any(|h| !open_of(h).is_empty()) {
        found.push(format!(
            "{truth_path}: no described host has an open port, so AC-7.2 ranges over \
             nothing."
        ));
    }
    if !hosts
        .iter()
        .any(|h| scanned.iter().any(|p| !open_of(h).contains(p)))
    {
        found.push(format!(
            "{truth_path}: every scanned port is open on every host, so a scanner that \
             reported everything it touched as open would pass AC-7.3. The scanned set \
             needs a port that is closed on a host that is up."
        ));
    }
    for host in hosts {
        let ip = host.get("ip").and_then(|i| i.as_str()).unwrap_or("?");
        for port in open_of(host) {
            if !scanned.contains(&port) {
                found.push(format!(
                    "{truth_path}: {ip}:{port} is recorded open but is not in \
                     `scanned_ports`, so AC-7.2 never looks for it."
                ));
            }
        }
    }

    found
}

pub fn check_lab() -> Fallible<()> {
    let compose = std::fs::read_to_string(Path::new(".").join(LAB_COMPOSE))
        .map_err(|e| format!("reading {LAB_COMPOSE}: {e}"))?;
    let truth_text = std::fs::read_to_string(Path::new(".").join(LAB_GROUND_TRUTH))
        .map_err(|e| format!("reading {LAB_GROUND_TRUTH}: {e}"))?;
    let truth: serde_json::Value = serde_json::from_str(&truth_text)
        .map_err(|e| format!("parsing {LAB_GROUND_TRUTH}: {e}"))?;
    let violations = lab_violations(LAB_COMPOSE, &compose, LAB_GROUND_TRUTH, &truth);
    if violations.is_empty() {
        let images = image_references(&compose).len();
        let addresses = assigned_addresses(&compose).len();
        println!(
            "check-lab: ok ({images} image(s), all digest-pinned; {addresses} lab \
             address(es) accounted for by {LAB_GROUND_TRUTH})"
        );
        Ok(())
    } else {
        for v in &violations {
            eprintln!("check-lab: {v}");
        }
        Err(format!("{} lab violation(s) (AC-7.1)", violations.len()).into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- The registries themselves. See the M5 residual wave: a loop over an
    // emptied register reports success, and `phrases.rs` has asserted its own
    // non-emptiness twice since the blocker wave. ---

    #[test]
    fn the_registries_these_checks_range_over_are_not_empty() {
        assert_eq!(
            INTERPRET_DIRECT_DEPENDENCIES.len(),
            2,
            "AC-4.10 is `bathy-types` and `regex`; a shorter list is not a weaker \
             claim, it is no claim"
        );
        assert!(
            FORBIDDEN_IN_INTERPRET.len() >= 10,
            "the forbidden-crate list was shortened; `purity_violations` iterates it \
             and a short one narrows the check silently"
        );
        assert_eq!(DENY_CHECKS.len(), 4, "advisories, bans, licenses, sources");
        assert!(
            !DUAL_TIER.is_empty(),
            "bathy-query is the one declared exception"
        );
        assert!(!RUNNABLE_WITHOUT_XTASK.is_empty());
    }

    // --- AC-4.10. ---

    fn owned(names: &[&str]) -> Vec<String> {
        names.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn the_real_direct_dependency_set_passes() {
        let v = purity_violations(
            &owned(&["bathy-types", "regex"]),
            &owned(&["bathy-interpret", "bathy-types", "regex", "serde", "memchr"]),
        );
        assert!(v.is_empty(), "{v:?}");
    }

    #[test]
    fn a_direct_dependency_added_is_caught_and_so_is_one_removed() {
        let added = purity_violations(&owned(&["bathy-types", "regex", "tokio"]), &[]);
        assert_eq!(added.len(), 1, "{added:?}");
        assert!(
            added[0].0.contains("direct dependencies changed"),
            "{added:?}"
        );

        let removed = purity_violations(&owned(&["bathy-types"]), &[]);
        assert_eq!(removed.len(), 1, "{removed:?}");
        assert!(
            removed[0].0.contains("want: bathy-types regex"),
            "a dependency silently dropped must fail too: {removed:?}"
        );
    }

    #[test]
    fn every_forbidden_crate_is_caught_transitively_and_says_why() {
        for (name, why) in FORBIDDEN_IN_INTERPRET {
            let tree = owned(&["bathy-interpret", "bathy-types", "regex", name]);
            let v = purity_violations(&owned(&["bathy-types", "regex"]), &tree);
            assert_eq!(v.len(), 1, "{name} was not caught: {v:?}");
            assert!(v[0].0.contains(name), "{v:?}");
            assert!(
                v[0].0.contains(why),
                "the rationale must travel with the failure: {v:?}"
            );
        }
    }

    #[test]
    fn a_crate_merely_containing_a_forbidden_name_is_not_flagged() {
        // `tokio-console`, `mio-extras`: substring matching would flag both,
        // and neither is what AC-4.10 forbids. The rule is crate identity.
        let v = purity_violations(
            &owned(&["bathy-types", "regex"]),
            &owned(&[
                "bathy-interpret",
                "tokio-console",
                "mio-extras",
                "not-tokio",
            ]),
        );
        assert!(v.is_empty(), "{v:?}");
    }

    // --- The MSRV membership rule. ---

    const CI: &str = "\
name: ci
on: [push]
jobs:
  test:
    steps:
      - uses: dtolnay/rust-toolchain@stable
      - run: cargo test --workspace
  msrv:
    steps:
      - uses: dtolnay/rust-toolchain@1.88
      - run: rm -f rust-toolchain.toml
      - run: cargo check -p bathy-types -p xtask --all-targets
      - run: cargo check -p bathy-query
  msrv-bathy-store:
    steps:
      - uses: dtolnay/rust-toolchain@1.95
      - run: rm -f rust-toolchain.toml
      - run: cargo check -p bathy-store -p bathy-query --all-targets
";

    fn floors() -> Vec<CrateFloor> {
        [
            ("bathy-types", "1.88"),
            ("xtask", "1.88"),
            ("bathy-query", "1.88"),
            ("bathy-store", "1.95"),
        ]
        .iter()
        .map(|(name, floor)| CrateFloor {
            name: (*name).to_string(),
            floor: (*floor).to_string(),
            manifest: format!("crates/{name}/Cargo.toml"),
        })
        .collect()
    }

    #[test]
    fn the_two_msrv_jobs_are_found_and_the_stable_job_is_not() {
        let jobs = parse_msrv_jobs(CI);
        assert_eq!(jobs.len(), 2, "{jobs:#?}");
        assert_eq!(jobs[0].name, "msrv");
        assert_eq!(jobs[0].toolchain, "1.88");
        assert!(jobs[0].removes_toolchain_pin);
        assert_eq!(jobs[0].checks.len(), 2);
        assert!(jobs[0].checks[0].all_targets);
        assert!(!jobs[0].checks[1].all_targets, "the bathy-query split");
        assert_eq!(jobs[1].toolchain, "1.95");
    }

    #[test]
    fn a_well_formed_workflow_has_no_violations() {
        let v = msrv_violations("ci.yml", &parse_msrv_jobs(CI), &floors());
        assert!(v.is_empty(), "{v:#?}");
    }

    #[test]
    fn a_crate_declaring_a_floor_and_named_in_no_job_is_the_defect_with_three_recurrences() {
        let mut floors = floors();
        floors.push(CrateFloor {
            name: "bathy-mcp".to_string(),
            floor: "1.95".to_string(),
            manifest: "crates/bathy-mcp/Cargo.toml".to_string(),
        });
        let v = msrv_violations("ci.yml", &parse_msrv_jobs(CI), &floors);
        assert_eq!(v.len(), 1, "{v:#?}");
        assert!(v[0].contains("bathy-mcp"), "{v:#?}");
        assert!(v[0].contains("named in NO msrv job"), "{v:#?}");
        assert!(
            v[0].contains("crates/bathy-mcp/Cargo.toml"),
            "the message must name the file that has to change: {v:#?}"
        );
    }

    #[test]
    fn a_crate_checked_only_above_its_own_floor_is_caught() {
        // `bathy-store` moved to a 1.88 declaration but is still named only in
        // the 1.95 job: it now claims a floor nothing builds.
        let mut floors = floors();
        floors
            .iter_mut()
            .find(|c| c.name == "bathy-store")
            .unwrap()
            .floor = "1.88".to_string();
        let v = msrv_violations("ci.yml", &parse_msrv_jobs(CI), &floors);
        assert!(
            v.iter()
                .any(|m| m.contains("bathy-store") && m.contains("expected exactly 1")),
            "{v:#?}"
        );
    }

    #[test]
    fn a_second_appearance_that_is_not_declared_in_dual_tier_is_caught() {
        let ci = CI.replace(
            "cargo check -p bathy-store -p bathy-query --all-targets",
            "cargo check -p bathy-store -p bathy-query -p bathy-types --all-targets",
        );
        let v = msrv_violations("ci.yml", &parse_msrv_jobs(&ci), &floors());
        assert!(
            v.iter()
                .any(|m| m.contains("bathy-types") && m.contains("belongs in `DUAL_TIER`")),
            "{v:#?}"
        );
    }

    #[test]
    fn the_all_targets_split_that_makes_bathy_query_two_floors_is_asserted() {
        // The naive local re-run the review warned about: `--all-targets` at
        // the library tier turns the floor check into a check of the test
        // harness, and the two floors collapse into one.
        let ci = CI.replace(
            "cargo check -p bathy-query\n",
            "cargo check -p bathy-query --all-targets\n",
        );
        let v = msrv_violations("ci.yml", &parse_msrv_jobs(&ci), &floors());
        assert!(
            v.iter()
                .any(|m| m.contains("bathy-query") && m.contains("--all-targets")),
            "{v:#?}"
        );
    }

    #[test]
    fn a_dead_dual_tier_exception_is_caught() {
        let ci = CI.replace(" -p bathy-query --all-targets", " --all-targets");
        let v = msrv_violations("ci.yml", &parse_msrv_jobs(&ci), &floors());
        assert!(v.iter().any(|m| m.contains("dead exception")), "{v:#?}");
    }

    #[test]
    fn a_job_that_leaves_the_toolchain_pin_in_place_checks_stable_and_says_so() {
        let ci = CI.replacen("      - run: rm -f rust-toolchain.toml\n", "", 1);
        let v = msrv_violations("ci.yml", &parse_msrv_jobs(&ci), &floors());
        assert!(
            v.iter()
                .any(|m| m.contains("never removes") && m.contains("`stable`")),
            "{v:#?}"
        );
    }

    #[test]
    fn a_job_pinned_to_a_toolchain_no_crate_declares_is_caught() {
        let ci = CI.replace("rust-toolchain@1.95", "rust-toolchain@1.99");
        let v = msrv_violations("ci.yml", &parse_msrv_jobs(&ci), &floors());
        assert!(
            v.iter().any(|m| m.contains("no crate in the workspace")),
            "{v:#?}"
        );
    }

    #[test]
    fn a_p_naming_a_crate_that_is_not_in_the_workspace_is_caught() {
        let ci = CI.replace("-p bathy-types", "-p bathy-typos");
        let v = msrv_violations("ci.yml", &parse_msrv_jobs(&ci), &floors());
        assert!(v.iter().any(|m| m.contains("bathy-typos")), "{v:#?}");
    }

    #[test]
    fn no_msrv_job_at_all_fails_rather_than_passing_vacuously() {
        let v = msrv_violations("ci.yml", &[], &floors());
        assert_eq!(v.len(), 1, "{v:#?}");
        assert!(v[0].contains("no MSRV job"), "{v:#?}");

        let v = msrv_violations("ci.yml", &parse_msrv_jobs(CI), &[]);
        assert_eq!(v.len(), 1, "{v:#?}");
        assert!(v[0].contains("nothing to range over"), "{v:#?}");
    }

    #[test]
    fn the_commands_it_prints_are_the_commands_the_jobs_run() {
        let commands = msrv_commands(&parse_msrv_jobs(CI));
        assert_eq!(
            commands.iter().map(|c| c.join(" ")).collect::<Vec<_>>(),
            vec![
                "+1.88 check -p bathy-types -p xtask --all-targets",
                "+1.88 check -p bathy-query",
                "+1.95 check -p bathy-store -p bathy-query --all-targets",
            ]
        );
    }

    // --- This repository's own workflow. The tests above are about the rule;
    // this one is about the tree, and it is the one that would have caught
    // `bathy-plan`, `crates/bathy` and `bathy-mcp`. ---

    #[test]
    fn this_repositorys_own_workflow_satisfies_the_membership_rule() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let ci = std::fs::read_to_string(root.join(".github/workflows/ci.yml"))
            .expect("ci.yml is readable");
        let jobs = parse_msrv_jobs(&ci);
        assert_eq!(jobs.len(), 2, "expected two MSRV jobs: {jobs:#?}");
        let floors = crate_floors(&root).expect("manifests are readable");
        assert!(
            floors.len() >= 11,
            "only {} crates declare a floor; the rule below would range over too few",
            floors.len()
        );
        let v = msrv_violations(".github/workflows/ci.yml", &jobs, &floors);
        assert!(v.is_empty(), "{v:#?}");
    }

    #[test]
    fn the_floors_are_read_through_workspace_inheritance() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let floors = crate_floors(&root).unwrap();
        let by_name = |n: &str| {
            floors
                .iter()
                .find(|c| c.name == n)
                .unwrap_or_else(|| panic!("{n} declares no floor"))
                .floor
                .clone()
        };
        // `rust-version.workspace = true`, resolved.
        assert_eq!(by_name("bathy-types"), "1.88");
        // A literal that overrides it.
        assert_eq!(by_name("bathy-store"), "1.95");
        assert_eq!(by_name("bathy-mcp"), "1.95");
    }

    #[test]
    fn a_comment_discussing_rust_version_is_not_read_as_declaring_one() {
        let manifest = "\
[package]
name = \"example\"
# rust-version = \"1.70\" -- this is prose about the floor, not the floor
rust-version = \"1.88\"
";
        assert_eq!(literal_rust_version(manifest).as_deref(), Some("1.88"));
        assert_eq!(package_name(manifest).as_deref(), Some("example"));
    }

    // --- The deny job. ---

    #[test]
    fn the_declared_check_set_is_read_out_of_the_deny_job_only() {
        let ci = "\
jobs:
  test:
    steps:
      - uses: x
        with:
          arguments: not-this-one
  deny:
    steps:
      - uses: EmbarkStudios/cargo-deny-action@v2
        with:
          command: check
          arguments: advisories bans licenses sources
";
        assert_eq!(
            deny_checks_in_ci(ci).unwrap(),
            vec!["advisories", "bans", "licenses", "sources"]
        );
        assert_eq!(deny_checks_in_ci("jobs:\n  deny:\n    steps: []\n"), None);
        assert_eq!(
            deny_checks_in_ci(
                "jobs:\n  deny:\n    steps:\n      # `arguments:` were both absent\n"
            ),
            None,
            "a comment discussing the input is not a declaration of it"
        );
    }

    #[test]
    fn this_repositorys_deny_job_declares_the_set_this_command_runs() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let ci = std::fs::read_to_string(root.join(".github/workflows/ci.yml")).unwrap();
        assert_eq!(
            deny_checks_in_ci(&ci).expect("the deny job declares `arguments:`"),
            DENY_CHECKS,
            "the local command and the CI job must run the same four checks"
        );
    }

    // --- publish-check. ---

    #[test]
    fn comments_and_blank_lines_are_not_denied_strings() {
        let text = "# Strings that must never appear.\n# Consumed by `xtask publish-check`.\n\nfoo@\n\nSECRET\n";
        assert_eq!(publish_denied_strings(text), vec!["foo@", "SECRET"]);
    }

    // --- The meta-gate. ---

    const SUBS: &[&str] = &["check-deps", "check-phrases", "check-msrv"];

    #[test]
    fn a_workflow_whose_every_step_has_a_local_form_passes() {
        let ci = "\
jobs:
  test:
    steps:
      - run: cargo fmt --all -- --check
      - run: cargo test --workspace
      - run: cargo run -p xtask -- check-phrases
";
        assert!(
            ci_steps_without_a_local_form("ci.yml", ci, SUBS).is_empty(),
            "{:#?}",
            ci_steps_without_a_local_form("ci.yml", ci, SUBS)
        );
    }

    #[test]
    fn an_inline_shell_block_is_the_thing_this_check_exists_to_refuse() {
        let ci = "\
jobs:
  test:
    steps:
      - name: a gate nobody can run
        run: |
          grep -r 'SystemTime::now' crates/ && exit 1
";
        let v = ci_steps_without_a_local_form("ci.yml", ci, SUBS);
        assert_eq!(v.len(), 1, "{v:#?}");
        assert!(v[0].contains("ci.yml:5"), "it must name the line: {v:#?}");
        assert!(v[0].contains("inline `run: |` block"), "{v:#?}");
    }

    #[test]
    fn a_step_calling_an_xtask_subcommand_that_does_not_exist_is_caught() {
        let ci = "jobs:\n  a:\n    steps:\n      - run: cargo run -p xtask -- publish-check\n";
        let v = ci_steps_without_a_local_form("ci.yml", ci, SUBS);
        assert_eq!(v.len(), 1, "{v:#?}");
        assert!(v[0].contains("publish-check"), "{v:#?}");
        assert!(v[0].contains("ci.yml:4"), "{v:#?}");
    }

    #[test]
    fn an_arbitrary_shell_one_liner_is_caught_too() {
        let ci = "jobs:\n  a:\n    steps:\n      - run: ./scripts/secret-gate.sh\n";
        let v = ci_steps_without_a_local_form("ci.yml", ci, SUBS);
        assert_eq!(v.len(), 1, "{v:#?}");
        assert!(v[0].contains("no local form"), "{v:#?}");
    }

    #[test]
    fn a_workflow_with_no_run_steps_fails_rather_than_passing_over_nothing() {
        let v = ci_steps_without_a_local_form("ci.yml", "jobs:\n  a:\n    steps: []\n", SUBS);
        assert_eq!(v.len(), 1, "{v:#?}");
        assert!(v[0].contains("ranged over nothing"), "{v:#?}");
    }

    // --- check-lab (AC-7.1). ---

    const PIN_A: &str = "sha256:5616878291a2eed594aee8db4dade5878cf7edcb475e59193904b198d9b830de";
    const PIN_B: &str = "sha256:14358309a308569c32bdc37e2e0e9694be33a9d99e68afb0f5ff33cc1f695dce";

    /// A compose file and a ground truth that agree, so each test below can
    /// break exactly one thing and see exactly one violation.
    fn lab_fixture() -> (String, serde_json::Value) {
        let compose = format!(
            "services:\n  \
             web:\n    image: nginx@{PIN_A}\n    networks:\n      labnet:\n        \
             ipv4_address: 10.30.0.10\n  \
             quiet:\n    image: alpine@{PIN_B}\n    networks:\n      labnet:\n        \
             ipv4_address: 10.30.0.18\n"
        );
        let truth = serde_json::json!({
            "scanned_ports": [22, 80],
            "hosts": [
                { "ip": "10.30.0.10", "open": [{ "port": 80 }] },
                { "ip": "10.30.0.18", "open": [] },
            ],
            "absent": ["10.30.0.200"],
        });
        (compose, truth)
    }

    fn lab(compose: &str, truth: &serde_json::Value) -> Vec<String> {
        lab_violations(
            "lab/docker-compose.yml",
            compose,
            "lab/ground-truth.json",
            truth,
        )
    }

    #[test]
    fn the_fixture_this_checks_seeded_violations_against_is_itself_clean() {
        // Without this, every test below could be passing for the wrong
        // reason: a fixture that already violates something reports a
        // violation no matter what is done to it.
        let (compose, truth) = lab_fixture();
        assert!(
            lab(&compose, &truth).is_empty(),
            "{:#?}",
            lab(&compose, &truth)
        );
    }

    #[test]
    fn an_image_pinned_only_by_tag_is_caught_and_its_line_named() {
        let (compose, truth) = lab_fixture();
        let tagged = compose.replace(&format!("nginx@{PIN_A}"), "nginx:1.29-alpine");
        let v = lab(&tagged, &truth);
        assert_eq!(v.len(), 1, "{v:#?}");
        assert!(v[0].contains("lab/docker-compose.yml:3"), "{v:#?}");
        assert!(v[0].contains("nginx:1.29-alpine"), "{v:#?}");
        assert!(v[0].contains("not pinned by digest"), "{v:#?}");
    }

    #[test]
    fn a_digest_that_is_the_wrong_length_or_the_wrong_alphabet_is_not_a_pin() {
        assert!(is_digest_pinned(&format!("nginx@{PIN_A}")));
        assert!(
            !is_digest_pinned("nginx@sha256:5616878291a2eed5"),
            "too short"
        );
        assert!(
            !is_digest_pinned(&format!("nginx@{}", PIN_A.to_uppercase())),
            "uppercase hex is a hand-edit, and a hand-edited digest is what this catches"
        );
        assert!(
            !is_digest_pinned(&format!("nginx@md5:{}", &PIN_A[7..])),
            "wrong algorithm"
        );
        assert!(!is_digest_pinned(&format!("@{PIN_A}")), "no image name");
        assert!(!is_digest_pinned("nginx:latest"), "a tag is not a pin");
        assert!(
            !is_digest_pinned(&format!("nginx@sha256:{}g", &PIN_A[7..70])),
            "`g` is not hex"
        );
    }

    #[test]
    fn a_compose_file_with_no_images_fails_rather_than_passing_over_nothing() {
        let (_, truth) = lab_fixture();
        let v = lab("services: {}\n", &truth);
        assert!(
            v.iter().any(|m| m.contains("no `image:` line")),
            "an empty compose file must not read as `every image is pinned`: {v:#?}"
        );
    }

    #[test]
    fn a_service_added_to_the_lab_and_not_to_the_ground_truth_is_caught() {
        let (compose, truth) = lab_fixture();
        let extended = format!(
            "{compose}  new:\n    image: redis@{PIN_B}\n    networks:\n      labnet:\n        \
             ipv4_address: 10.30.0.14\n"
        );
        let v = lab(&extended, &truth);
        assert_eq!(v.len(), 1, "{v:#?}");
        assert!(v[0].contains("10.30.0.14"), "{v:#?}");
        assert!(v[0].contains("does not describe it"), "{v:#?}");
    }

    #[test]
    fn a_ground_truth_describing_a_host_the_lab_does_not_run_is_caught() {
        let (compose, mut truth) = lab_fixture();
        truth["hosts"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({ "ip": "10.30.0.99", "open": [{ "port": 80 }] }));
        let v = lab(&compose, &truth);
        assert_eq!(v.len(), 1, "{v:#?}");
        assert!(v[0].contains("10.30.0.99"), "{v:#?}");
        assert!(v[0].contains("not this one"), "{v:#?}");
    }

    #[test]
    fn an_absent_address_that_a_container_actually_occupies_is_caught() {
        let (compose, mut truth) = lab_fixture();
        truth["absent"] = serde_json::json!(["10.30.0.10"]);
        let v = lab(&compose, &truth);
        assert!(v.iter().any(|m| m.contains("listed as absent")), "{v:#?}");
    }

    #[test]
    fn a_ground_truth_with_no_absent_address_leaves_ac_7_4_with_nothing_to_assert() {
        let (compose, mut truth) = lab_fixture();
        truth["absent"] = serde_json::json!([]);
        let v = lab(&compose, &truth);
        assert_eq!(v.len(), 1, "{v:#?}");
        assert!(v[0].contains("AC-7.4"), "{v:#?}");
    }

    #[test]
    fn a_lab_where_every_host_has_an_open_port_gives_ac_7_3_nothing_to_catch() {
        // The overview's fixture constraint, over the oracle itself: remove
        // the one live host that answers nothing and a scanner that never
        // reported a closed host would still pass.
        let (compose, mut truth) = lab_fixture();
        truth["hosts"][1]["open"] = serde_json::json!([{ "port": 80 }]);
        let v = lab(&compose, &truth);
        assert_eq!(v.len(), 1, "{v:#?}");
        assert!(v[0].contains("answers nothing"), "{v:#?}");
    }

    #[test]
    fn a_scanned_port_set_with_no_shut_port_gives_ac_7_3_nothing_to_catch_either() {
        let (compose, mut truth) = lab_fixture();
        // Every scanned port open on every host: port 80 only, open on both.
        truth["scanned_ports"] = serde_json::json!([80]);
        truth["hosts"][1]["open"] = serde_json::json!([{ "port": 80 }]);
        let v = lab(&compose, &truth);
        assert!(
            v.iter()
                .any(|m| m.contains("needs a port that is closed on a host that is up")),
            "{v:#?}"
        );
    }

    #[test]
    fn an_open_port_that_the_conformance_scan_never_touches_is_caught() {
        let (compose, mut truth) = lab_fixture();
        truth["hosts"][0]["open"] = serde_json::json!([{ "port": 8443 }]);
        let v = lab(&compose, &truth);
        assert!(
            v.iter().any(|m| m.contains("8443") && m.contains("AC-7.2")),
            "{v:#?}"
        );
    }

    #[test]
    fn this_repositorys_own_lab_is_pinned_and_matches_its_ground_truth() {
        // The repository itself, not a fixture: `check-lab` passing over a
        // synthetic compose file says nothing about `lab/docker-compose.yml`.
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let compose = std::fs::read_to_string(root.join(LAB_COMPOSE)).unwrap();
        let truth: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(root.join(LAB_GROUND_TRUTH)).unwrap())
                .unwrap();
        let v = lab_violations(LAB_COMPOSE, &compose, LAB_GROUND_TRUTH, &truth);
        assert!(v.is_empty(), "{v:#?}");
        assert!(
            image_references(&compose).len() >= 8,
            "the lab is supposed to cover eight protocols; only {} image(s) found",
            image_references(&compose).len()
        );
    }
}
