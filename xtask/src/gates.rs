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

/// The manifests `cargo deny` is pointed at, root-relative.
///
/// `fuzz/Cargo.toml` is the second one because `fuzz/` is its own workspace:
/// `cargo metadata` at the root lists twelve packages and none of them is
/// `bathy-fuzz`, so root `cargo deny` never saw `libfuzzer-sys`, `arbitrary`
/// or `ipnet`. It found something the first time it was pointed there —
/// `libfuzzer-sys` is `(MIT OR Apache-2.0) AND NCSA`, and NCSA was in
/// nobody's allow list. See `deny.toml`'s exception for the ruling.
pub const DENY_MANIFESTS: &[&str] = &["./Cargo.toml", "fuzz/Cargo.toml"];

/// The cargo-deny global flags, which must be identical locally and in CI:
/// they decide which crates are in the graph at all, so a run without them
/// checks a different set of crates and reports the same "ok".
///
/// `--config deny.toml` is here rather than left to default because
/// cargo-deny resolves its config against the *current directory*, not
/// against `--manifest-path`: `fuzz/` has no `deny.toml`, and one policy
/// file for both graphs is the point.
pub const DENY_GLOBAL_ARGS: &[&str] = &["--all-features", "--config", "deny.toml"];

/// One `cargo-deny-action` step's declared inputs, as `ci.yml` spells them.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct DenyStep {
    pub manifest_path: Option<String>,
    pub arguments: Option<Vec<String>>,
    pub command: Option<String>,
    pub command_arguments: Option<Vec<String>>,
}

/// Every `cargo-deny-action` step in the `deny` job, with its inputs.
///
/// Reads STEPS rather than lines. The input names matter and are easy to
/// confuse — this is how the check set came to be declared in `arguments:`,
/// which the action splices in *before* the subcommand, producing
/// `cargo-deny … advisories bans licenses sources check` and the exit-2
/// `unrecognized subcommand 'advisories'`. The old checker compared that
/// list to `DENY_CHECKS`, found it equal, and reported ok: it checked the
/// spelling of a set and never the position it was spelled in.
pub fn deny_steps_in_ci(ci: &str) -> Vec<DenyStep> {
    let Some(block) = job_block(ci, "deny") else {
        return Vec::new();
    };
    let mut steps = Vec::new();
    for lines in steps_of(block) {
        // A comment discussing `arguments:` is not a declaration of one. This
        // file's deny job carries a paragraph about the input having been
        // absent, and reading that paragraph as the check set produced a
        // failure message quoting its own prose.
        let uncommented = || {
            lines
                .iter()
                .map(|line| line.trim_start())
                .filter(|line| !line.starts_with('#'))
        };
        if !uncommented().any(|line| line.contains("cargo-deny-action@")) {
            continue;
        }
        let input = |name: &str| {
            uncommented().find_map(|line| {
                let rest = line
                    .strip_prefix("- ")
                    .unwrap_or(line)
                    .strip_prefix(name)?
                    .strip_prefix(':')?;
                Some(rest.trim().to_string())
            })
        };
        let words = |name: &str| {
            input(name).map(|v| v.split_whitespace().map(str::to_owned).collect::<Vec<_>>())
        };
        steps.push(DenyStep {
            manifest_path: input("manifest-path"),
            arguments: words("arguments"),
            command: input("command"),
            command_arguments: words("command-arguments"),
        });
    }
    steps
}

/// What the local command runs for one manifest, derived rather than
/// remembered — and the same argv the action produces from the inputs above.
pub fn deny_command(manifest: &str) -> Vec<String> {
    let mut argv = vec!["--manifest-path".to_string(), manifest.to_string()];
    argv.extend(DENY_GLOBAL_ARGS.iter().map(|a| (*a).to_string()));
    argv.push("check".to_string());
    argv.extend(DENY_CHECKS.iter().map(|c| (*c).to_string()));
    argv
}

/// What is wrong with the `deny` job, as text a person can act on.
pub fn deny_job_violations(ci_path: &str, ci: &str) -> Vec<String> {
    let steps = deny_steps_in_ci(ci);
    let mut found = Vec::new();
    for manifest in DENY_MANIFESTS {
        let Some(step) = steps
            .iter()
            .find(|s| s.manifest_path.as_deref() == Some(*manifest))
        else {
            found.push(format!(
                "{ci_path}: the `deny` job has no `cargo-deny-action` step with \
                 `manifest-path: {manifest}`, so that crate graph is audited by nobody. \
                 `fuzz/` is its own workspace: root `cargo deny` does not reach it, and \
                 the first run that did found an unallowed licence."
            ));
            continue;
        };
        if step.command.as_deref() != Some("check") {
            found.push(format!(
                "{ci_path}: the `cargo-deny-action` step for {manifest} declares \
                 `command: {}` rather than `check`.",
                step.command.as_deref().unwrap_or("<absent>")
            ));
        }
        match step.command_arguments.as_deref() {
            None => found.push(format!(
                "{ci_path}: the `cargo-deny-action` step for {manifest} declares no \
                 `command-arguments:`, so which checks run is the action's default — \
                 written down nowhere here and free to change under a floating `@v2`. \
                 Note the input name: `arguments:` is spliced in BEFORE the subcommand \
                 (`cargo-deny … advisories … check`) and exits 2 with `unrecognized \
                 subcommand`, which is how this job spent a milestone unable to run."
            )),
            Some(declared) if declared != DENY_CHECKS => found.push(format!(
                "{ci_path}: the step for {manifest} runs `{}` and this command runs \
                 `{}`. A local gate that checks a different set from CI is worse than \
                 none.",
                declared.join(" "),
                DENY_CHECKS.join(" "),
            )),
            Some(_) => {}
        }
        match step.arguments.as_deref() {
            Some(declared) if declared == DENY_GLOBAL_ARGS => {}
            other => found.push(format!(
                "{ci_path}: the step for {manifest} declares `arguments: {}` and this \
                 command runs `{}`. These are cargo-deny's GLOBAL flags — they decide \
                 which crates are in the graph — so a difference here is a different \
                 audit reporting the same word.",
                other.map_or("<absent>".to_string(), |a| a.join(" ")),
                DENY_GLOBAL_ARGS.join(" "),
            )),
        }
    }
    found
}

pub fn check_deny() -> Fallible<()> {
    let ci_path = ".github/workflows/ci.yml";
    let ci = std::fs::read_to_string(Path::new(".").join(ci_path))
        .map_err(|e| format!("reading {ci_path}: {e}"))?;
    let violations = deny_job_violations(ci_path, &ci);
    if !violations.is_empty() {
        for v in &violations {
            eprintln!("check-deny: {v}");
        }
        return Err(format!("{} deny job violation(s)", violations.len()).into());
    }

    for manifest in DENY_MANIFESTS {
        let argv = deny_command(manifest);
        eprintln!("check-deny: cargo deny {}", argv.join(" "));
        let out = std::process::Command::new("cargo")
            .arg("deny")
            .args(&argv)
            .status();
        match out {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(
                    "cargo-deny is not installed. `cargo install cargo-deny --locked`. \
                     Installing it is the one part of this gate that cannot be an xtask \
                     subcommand — a program that needs the tool cannot be what provides it."
                        .into(),
                );
            }
            Err(e) => return Err(e.into()),
            Ok(status) if !status.success() => {
                return Err(format!("cargo deny {} failed", argv.join(" ")).into());
            }
            Ok(_) => {}
        }
    }
    println!(
        "check-deny: ok ({} over {})",
        DENY_CHECKS.join(" "),
        DENY_MANIFESTS.join(", "),
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// `publish-check` — the subcommand `.publish-deny` already named.
// ---------------------------------------------------------------------------

/// Directories never scanned for publish-denied strings.
const NEVER_SCANNED: &[&str] = &[".git", "target", "node_modules", "mutants.out"];

/// Directories that are never scanned, by PATH rather than by name.
///
/// `fuzz/corpus` and `fuzz/artifacts` are libFuzzer's working state:
/// git-ignored, thousands of generated files, present or absent depending on
/// whether someone has run the fuzzer locally. Scanning them made this gate's
/// own reported evidence unreproducible -- the same commit reported 5,375
/// file reads on one machine and 14,920 on another, and the whole difference
/// was local fuzz state. A count printed as evidence must not depend on that.
/// By path and not by name, because `corpus` and `artifacts` are ordinary
/// words that a real source directory may well be called.
const NEVER_SCANNED_PATHS: &[&str] = &["fuzz/corpus", "fuzz/artifacts"];

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
            if NEVER_SCANNED.contains(&name.as_str())
                || NEVER_SCANNED_PATHS.iter().any(|skip| path.ends_with(skip))
            {
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
    // Provisioning again, and the same reason as the toolchain above: a
    // program that needs `cargo-fuzz` cannot be what provides it, and
    // `cargo run -p xtask -- install-cargo-fuzz` would be a spelling of
    // `cargo install`, not a capability. The *checkable* half -- that a fuzz
    // target exists for every untrusted-input surface, that each has seeds,
    // that the corpus is cached, that the span assertion is still in the
    // interpret target -- is `check-fuzz`, and the running of them is
    // `cargo run -p xtask -- fuzz`, which reads the same registry `check-fuzz`
    // does. Narrow on purpose: `cargo install` in general is not exempt.
    "cargo install cargo-fuzz",
    // The local form IS this script, it is in the repository, and it is what
    // `lab/README.md` documents. Re-spelling it as `cargo run -p xtask --
    // check-conformance` would put a Docker Compose driver behind an xtask
    // subcommand that could only shell out to the same script -- a spelling,
    // not a capability, which is the criterion this list is for. What must not
    // be true is that the gate exists only here: `check-lab` asserts that this
    // step is present and that the script sets `BATHY_LAB_REQUIRED`, so an
    // absent lab fails the job rather than skipping the suite.
    "lab/run.sh",
];

/// The `- ` steps of a job block, each with the lines nested under it.
///
/// A step is what a workflow actually acts on: `uses:`, `with:` and
/// `working-directory:` mean nothing except relative to the step they sit
/// in, so a check phrased over the job's lines rather than its steps can be
/// satisfied by two halves of two different steps.
fn steps_of(block: &str) -> Vec<Vec<&str>> {
    let mut steps: Vec<Vec<&str>> = Vec::new();
    let mut marker_indent = usize::MAX;
    for line in block.lines() {
        let trimmed = line.trim_start();
        let indent = line.len() - trimmed.len();
        if trimmed.starts_with("- ") && indent <= marker_indent {
            marker_indent = indent;
            steps.push(vec![line]);
        } else if let Some(current) = steps.last_mut()
            && (trimmed.is_empty() || indent > marker_indent)
        {
            current.push(line);
        }
    }
    steps
}

/// The `working-directory:` of the step containing line `at`, if it has one.
///
/// A step is the block from a `- ` marker to the next marker at the same
/// indentation, so a `working-directory:` written above or below the `run:`
/// key is found either way — YAML mapping keys are unordered and a check
/// that only looked below would be satisfied by moving one line.
fn step_working_directory(lines: &[&str], at: usize) -> Option<String> {
    let indent_of = |line: &str| line.len() - line.trim_start().len();
    let is_marker = |line: &str| line.trim_start().starts_with("- ");
    let start = (0..=at).rev().find(|i| is_marker(lines[*i]))?;
    let marker_indent = indent_of(lines[start]);
    let end = ((start + 1)..lines.len())
        .find(|i| {
            let line = lines[*i];
            if line.trim().is_empty() {
                return false;
            }
            indent_of(line) < marker_indent || (is_marker(line) && indent_of(line) == marker_indent)
        })
        .unwrap_or(lines.len());
    lines[start..end].iter().find_map(|line| {
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') {
            return None;
        }
        let rest = trimmed
            .strip_prefix("- ")
            .unwrap_or(trimmed)
            .strip_prefix("working-directory:")?;
        Some(rest.trim().trim_matches('"').trim_matches('\'').to_string())
    })
}

/// The rule: no gate without a local form. `subcommands` is `xtask`'s actual
/// dispatch list, so a step naming a subcommand that does not exist fails
/// here — which is what `.publish-deny` needed and did not have.
pub fn ci_steps_without_a_local_form(ci_path: &str, ci: &str, subcommands: &[&str]) -> Vec<String> {
    let mut found = Vec::new();
    let mut steps = 0usize;
    let lines: Vec<&str> = ci.lines().collect();
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
        // A `run:` step is not only its command: `working-directory:` changes
        // which tree the command runs over, and this check read the `run:`
        // line alone. `cargo fmt --all -- --check` under `working-directory:
        // fuzz` is a DIFFERENT gate from the root one -- a different
        // workspace, a different dependency graph -- and it passed here as
        // the root gate, which is how ~900 lines of Rust came to sit outside
        // `cargo fmt --all`, `cargo clippy --workspace` and `cargo deny` with
        // a README sentence as the only control. The allowlist below is a
        // list of commands that are already runnable *from the repository
        // root*; a directory-scoped one is not one of them, and the local
        // form it needs is an xtask subcommand that names the directory
        // (`check-fuzz-crate` is exactly that).
        if let Some(directory) = step_working_directory(&lines, index) {
            steps += 1;
            found.push(format!(
                "{ci_path}:{number}: `{command}` runs with `working-directory: \
                 {directory}`, so it is not the root gate it reads as and there is no \
                 local form of it -- someone reproducing this run from the repository \
                 root gets a different answer. Move it into `xtask` (which can `cd` \
                 where it needs to and be one command anyone can type) and call that \
                 here."
            ));
            continue;
        }
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
pub const LAB_RUN_SH: &str = "lab/run.sh";
/// The one file outside `lab/` that hardcodes a lab address. See
/// [`probe_lab_address_violations`].
pub const LAB_TLS_PROBE: &str = "crates/bathy-probe/src/probes/tls.rs";

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

    // --- The narrowing controls `lab/README.md` names, one by one. ---
    //
    // The generic checks above are necessary and were not sufficient: the M7
    // Task 1 review removed port 22 from `scanned_ports` -- the control
    // documented as "`ssh-openssh` listens on 2222, not 22, so 22 is shut on
    // every host and is in the scanned port set on purpose" -- and `check-lab`,
    // the conformance suite and the fixture guards all stayed green, because
    // 8080 independently satisfied every generic property. `lab/README.md`
    // said "`xtask check-lab` fails if any of those controls is removed", and
    // that sentence was false for at least one of the four. A README claim
    // that nothing enforces is the exact recurrence pattern the overview's
    // README constraint was written for, so the sentence is made true here
    // rather than weakened there.
    for control in NARROWING_CONTROLS {
        if let Some(complaint) = (control.check)(&scanned, hosts, &open_of) {
            found.push(format!(
                "{truth_path}: the `{}` narrowing control is gone -- {complaint} {}",
                control.name, control.why
            ));
        }
    }

    found.extend(product_claims_not_backed_by_their_own_evidence(
        truth_path, hosts,
    ));

    found
}

/// The lab address `crates/bathy-probe/src/probes/tls.rs` dials, cross-checked
/// against the lab it claims to be dialing.
///
/// That crate's dependency set is `bathy-types` and nothing else, which is what
/// keeps it in CI's 1.88 MSRV tier, so the address is a literal rather than a
/// read of `lab/ground-truth.json`. The literal is the right trade and the
/// missing half was that nothing tied it to the lab: a re-address would have
/// left `tls_probe_against_a_real_nginx_tls_server` dialing a dead address, and
/// -- until this round -- skipping silently when it did.
pub fn probe_lab_address_violations(
    probe_path: &str,
    probe_source: &str,
    truth_path: &str,
    truth: &serde_json::Value,
) -> Vec<String> {
    let Some(literal) = probe_source.lines().find_map(|line| {
        line.split_once("LAB_TLS_WEB: &str = \"")?
            .1
            .split('"')
            .next()
    }) else {
        return vec![format!(
            "{probe_path}: no `LAB_TLS_WEB` address literal found. If the constant was \
             renamed, rename it here too -- this cross-check silently ranging over \
             nothing is worse than not having it."
        )];
    };
    let Some((ip, port)) = literal.rsplit_once(':') else {
        return vec![format!("{probe_path}: `{literal}` is not `<ip>:<port>`")];
    };
    let open_here = truth
        .get("hosts")
        .and_then(|h| h.as_array())
        .map(|hosts| {
            hosts.iter().any(|h| {
                h.get("ip").and_then(|i| i.as_str()) == Some(ip)
                    && h.get("open")
                        .and_then(|o| o.as_array())
                        .is_some_and(|open| {
                            open.iter().any(|e| {
                                e.get("port")
                                    .and_then(serde_json::Value::as_u64)
                                    .map(|p| p.to_string())
                                    == Some(port.to_string())
                            })
                        })
            })
        })
        .unwrap_or(false);
    if open_here {
        Vec::new()
    } else {
        vec![format!(
            "{probe_path}: dials {literal}, which {truth_path} does not record as an open \
             port. The test would connect to nothing and -- being a test that skips when \
             the lab is unreachable -- report `ok` for the wrong reason."
        )]
    }
}

/// The conformance suite has a CI job, and the command that job runs is the one
/// that makes an absent lab a failure.
///
/// Five acceptance criteria (AC-7.2 .. AC-7.6) were closed by named tests that
/// die under mutation, and defended by nobody: nothing ran them on a push, so a
/// regression would land green and stay green until someone remembered. The
/// stated reason for deferring the job was not a technical one -- `ubuntu-latest`
/// ships Docker and, being Linux, routes to `labnet` natively, which is the
/// single thing that makes this impossible on the macOS machine the lab was
/// built on.
/// The job in `ci.yml` that runs the conformance suite. Named here so the
/// check and the failure message cannot drift apart.
pub const LAB_CI_JOB: &str = "lab-conformance";

pub fn lab_ci_job_violations(
    ci_path: &str,
    ci: &str,
    run_sh_path: &str,
    run_sh: &str,
) -> Vec<String> {
    let mut found = Vec::new();
    // A `run:` STEP, not an occurrence of the string. The first version of
    // this check asked `ci.contains("lab/run.sh test")` and survived deleting
    // the step outright, because the comment block explaining the job names
    // the command four times -- a guard satisfied by the prose that documents
    // it. Found by mutating the file, which is the only way that kind of
    // vacuity ever shows up.
    //
    // And a step in THE JOB, not anywhere in the file -- the same sweep that
    // job-scoped `fuzz_ci_job_violations`. The reason is narrower here than
    // there but it is the same reason: this job is deliberately scheduled
    // rather than per-push (its comment block gives the pull-rate arithmetic),
    // so "the suite runs daily and on demand" is a claim about which job the
    // step is in. A `lab/run.sh test` step sitting in the fast `test` job
    // satisfies a file-scoped check while pulling 2.8 GiB of images on every
    // pull request; a step in a job that never runs satisfies it while running
    // nothing at all.
    let runs_the_suite = job_block(ci, LAB_CI_JOB).is_some_and(|block| {
        block.lines().any(|line| {
            let trimmed = line.trim_start();
            trimmed
                .strip_prefix("- run:")
                .or_else(|| trimmed.strip_prefix("run:"))
                .is_some_and(|command| command.trim().starts_with("lab/run.sh test"))
        })
    });
    if !runs_the_suite {
        found.push(format!(
            "{ci_path}: no `run:` step in the `{LAB_CI_JOB}` job invokes `lab/run.sh \
             test`, so AC-7.2 through AC-7.6 are closed by tests nothing executes. The \
             job needs Docker and a Linux runner and nothing else -- `ubuntu-latest` has \
             both, and routes to `labnet` natively."
        ));
    }
    if !run_sh.contains("BATHY_LAB_REQUIRED=1") {
        found.push(format!(
            "{run_sh_path}: does not set BATHY_LAB_REQUIRED, so the conformance tests \
             would SKIP rather than FAIL when the lab is not reachable -- and a CI job \
             that silently skips the suite is the same defect as a test that silently \
             skips itself, one level up."
        ));
    }
    found
}

/// One control that keeps the lab from being a fixture that satisfies every
/// branch. Each is named in `lab/README.md`'s bulleted list, and each is here
/// so that list is a description of enforced behaviour rather than a promise.
pub struct NarrowingControl {
    /// The `lab/README.md` bullet this is, by the service or port it turns on.
    pub name: &'static str,
    /// What breaks if it goes, printed with the failure.
    pub why: &'static str,
    /// `Some(complaint)` when the control is no longer present.
    #[allow(clippy::type_complexity)]
    pub check: fn(
        scanned: &[u64],
        hosts: &[serde_json::Value],
        open_of: &dyn Fn(&serde_json::Value) -> Vec<u64>,
    ) -> Option<String>,
}

pub const NARROWING_CONTROLS: &[NarrowingControl] = &[
    NarrowingControl {
        name: "ssh-on-2222-so-22-is-shut-everywhere",
        why: "22 is the port a scanner that assumes `ssh => 22` gets wrong, and it is in \
              `scanned_ports` on purpose so that assuming it costs a false positive.",
        check: |scanned, hosts, open_of| {
            if !scanned.contains(&22) {
                return Some(
                    "22 is not in `scanned_ports`, so nothing ever asks about it.".to_string(),
                );
            }
            let listening: Vec<String> = hosts
                .iter()
                .filter(|h| open_of(h).contains(&22))
                .map(|h| {
                    h.get("ip")
                        .and_then(|i| i.as_str())
                        .unwrap_or("?")
                        .to_string()
                })
                .collect();
            (!listening.is_empty()).then(|| {
                format!(
                    "22 is recorded open on {}, so it is no longer shut on every host.",
                    listening.join(", ")
                )
            })
        },
    },
    NarrowingControl {
        name: "tls-web-and-web-nginx-serve-opposite-ports",
        why: "A scanner that reported every port it touched as open fails on both hosts \
              only while each is open on exactly one of the pair.",
        check: |scanned, hosts, open_of| {
            for port in [80u64, 443] {
                if !scanned.contains(&port) {
                    return Some(format!("{port} is not in `scanned_ports`."));
                }
            }
            let complementary = hosts.iter().any(|a| {
                let a_open = open_of(a);
                a_open.contains(&80)
                    && !a_open.contains(&443)
                    && hosts.iter().any(|b| {
                        let b_open = open_of(b);
                        b_open.contains(&443) && !b_open.contains(&80)
                    })
            });
            (!complementary).then(|| {
                "no host serves 80 without 443 while another serves 443 without 80.".to_string()
            })
        },
    },
    NarrowingControl {
        name: "a-live-host-that-answers-nothing",
        why: "`silent` is up and answers nothing, so \"reported down\" and \"reported open\" \
              are both wrong answers for it. Without it a scanner that never reported a \
              host as closed would still pass AC-7.3.",
        check: |_scanned, hosts, open_of| {
            hosts
                .iter()
                .all(|h| !open_of(h).is_empty())
                .then(|| "every described host has an open port.".to_string())
        },
    },
];

/// Every `product` in the ground truth is either a literal in the `evidence`
/// string it was transcribed from, or declares the non-literal basis it rests
/// on in `product_inference`. Same for `version`, with no inference escape:
/// a version that is not in the observed bytes is a guess.
///
/// This is the mechanical half of the fix for the M7 Task 1 review's central
/// finding. The oracle recorded `product: null` at `10.30.0.17:443` while the
/// bytes it was transcribed from carried `Server: nginx/1.29.8` -- the
/// transcription step dropped the line, and a null is what AC-7.5 filters on,
/// so the loss hid inside the criterion it corrupted. Nothing binds the file
/// to a sweep run (that is Task 6's `publish-check` and is still open), but
/// binding each *claim* to the evidence text stored beside it is checkable
/// today, and it is the step where the error entered.
/// The product an evidence string names outright, if any.
///
/// Three banner shapes, and only three, because these are the ones that carry
/// a vendor name by protocol definition rather than by luck:
///
/// * HTTP's `Server:` response header (RFC 9110 §10.2.4) -- the one that was
///   elided at `10.30.0.17:443`;
/// * SSH's identification string, `SSH-2.0-<softwareversion>` (RFC 4253 §4.2);
/// * SMTP's greeting, where `ESMTP <word>` is the near-universal convention.
///
/// Deliberately conservative: a shape not on this list returns `None`, so this
/// never invents a product. What it must not do is stay quiet about a banner
/// that plainly names one, which is the failure it exists for.
pub fn product_named_by(evidence: &str) -> Option<String> {
    let word = |rest: &str| {
        let name: String = rest
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '+')
            .collect();
        (name.len() >= 3).then_some(name)
    };
    for (marker, skip) in [("Server: ", 0usize), ("SSH-2.0-", 0), ("ESMTP ", 0)] {
        if let Some(index) = evidence.find(marker)
            && let Some(name) = word(&evidence[index + marker.len() + skip..])
        {
            return Some(name);
        }
    }
    None
}

pub fn product_claims_not_backed_by_their_own_evidence(
    truth_path: &str,
    hosts: &[serde_json::Value],
) -> Vec<String> {
    let mut found = Vec::new();
    for host in hosts {
        let ip = host.get("ip").and_then(|i| i.as_str()).unwrap_or("?");
        let Some(open) = host.get("open").and_then(|o| o.as_array()) else {
            continue;
        };
        for entry in open {
            let port = entry
                .get("port")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0);
            let text = |key: &str| entry.get(key).and_then(|v| v.as_str());
            let evidence = text("evidence").unwrap_or("").to_lowercase();
            let inference = text("product_inference");

            if let Some(product) = text("product") {
                let literal = evidence.contains(&product.to_lowercase());
                match (literal, inference) {
                    (false, None) => found.push(format!(
                        "{truth_path}: {ip}:{port} claims product `{product}`, which does \
                         not appear in its own `evidence`. Either it is not what the \
                         sweep saw, or the transcription dropped the line that says so -- \
                         which is exactly how `10.30.0.17:443` came to record `null` \
                         against a response carrying `Server: nginx/1.29.8`. Quote the \
                         bytes, or state the non-literal basis in `product_inference`."
                    )),
                    (true, Some(_)) => found.push(format!(
                        "{truth_path}: {ip}:{port} declares `product_inference` but \
                         `{product}` is already a literal in its `evidence`. An unused \
                         escape hatch reads as coverage; delete it."
                    )),
                    _ => {}
                }
            } else {
                if inference.is_some() {
                    found.push(format!(
                        "{truth_path}: {ip}:{port} declares `product_inference` with no \
                         `product` to infer."
                    ));
                }
                // The direction that actually went wrong, and the one a
                // "product must be backed by evidence" rule does not cover at
                // all: evidence that names a product, recorded as `null`.
                // A null is self-exempting -- AC-7.5's test filters on
                // `product.is_some()` -- so this is the only shape of oracle
                // error that removes its own endpoint from the criterion it
                // corrupts. It is what `10.30.0.17:443` did.
                if let Some(named) = product_named_by(text("evidence").unwrap_or("")) {
                    found.push(format!(
                        "{truth_path}: {ip}:{port} records `product: null`, but its own \
                         `evidence` names `{named}`. A null means \"the lab does not \
                         establish a product here\" and this evidence establishes one. \
                         AC-7.5 skips null-product endpoints, so a null here does not \
                         weaken the criterion -- it silently removes this endpoint from \
                         it, which is how the oracle came to agree with the scanner \
                         about nothing at the one address where the bytes say \
                         otherwise. Record the product; if bathy cannot see it, say so \
                         in `identification_gap`."
                    ));
                }
            }

            if let Some(version) = text("version")
                && !evidence.contains(&version.to_lowercase())
            {
                found.push(format!(
                    "{truth_path}: {ip}:{port} claims version `{version}`, which does not \
                     appear in its own `evidence`. A version is read off the wire or it \
                     is a guess; there is no inference escape for this one."
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
    let probe = std::fs::read_to_string(Path::new(".").join(LAB_TLS_PROBE))
        .map_err(|e| format!("reading {LAB_TLS_PROBE}: {e}"))?;
    let ci_path = ".github/workflows/ci.yml";
    let ci = std::fs::read_to_string(Path::new(".").join(ci_path))
        .map_err(|e| format!("reading {ci_path}: {e}"))?;
    let run_sh = std::fs::read_to_string(Path::new(".").join(LAB_RUN_SH))
        .map_err(|e| format!("reading {LAB_RUN_SH}: {e}"))?;

    let mut violations = lab_violations(LAB_COMPOSE, &compose, LAB_GROUND_TRUTH, &truth);
    violations.extend(probe_lab_address_violations(
        LAB_TLS_PROBE,
        &probe,
        LAB_GROUND_TRUTH,
        &truth,
    ));
    violations.extend(lab_ci_job_violations(ci_path, &ci, LAB_RUN_SH, &run_sh));
    if violations.is_empty() {
        let images = image_references(&compose).len();
        let addresses = assigned_addresses(&compose).len();
        println!(
            "check-lab: ok ({images} image(s), all digest-pinned; {addresses} lab \
             address(es) accounted for by {LAB_GROUND_TRUTH}; {} narrowing control(s) \
             present; the conformance suite has a CI job)",
            NARROWING_CONTROLS.len(),
        );
        Ok(())
    } else {
        for v in &violations {
            eprintln!("check-lab: {v}");
        }
        Err(format!("{} lab violation(s) (AC-7.1)", violations.len()).into())
    }
}

// ---------------------------------------------------------------------------
// AC-7.7 to AC-7.10 — a fuzz target for every parser that eats untrusted bytes.
// ---------------------------------------------------------------------------

pub const FUZZ_MANIFEST: &str = "fuzz/Cargo.toml";

/// The statement in `interpret.rs` that names the flag bits, which must run
/// once per execution rather than once per match. See the check that uses it.
pub const INTERPRET_NAMES_THE_RULES: &str = "let rules = rule_ids();";

/// One function that consumes bytes this project did not write, and the fuzz
/// target that drives it (AC-7.7).
///
/// This is a registry for the same reason `DEFERRALS` and `NARROWING_CONTROLS`
/// are: a list of parsers written in a plan is a list nobody re-reads, and the
/// failure mode is not a red build, it is a surface that quietly has no
/// target. `run_fuzz` runs exactly this list and CI calls `run_fuzz`, so a
/// target added here is fuzzed in CI without anyone editing `ci.yml` — the
/// drift that a hand-maintained second list in a workflow file guarantees.
///
/// # What this list is and is not
///
/// It is **hand-maintained**, and no checker derives it from the code. So
/// "every function that consumes untrusted bytes is registered" is asserted
/// by this list, not proved by it — the completeness claim is exactly the
/// kind of second registry the rest of this file objects to, and saying so is
/// the only honest option available. What IS enforced: every entry has a
/// target or an expiring deferral, every target has seeds, and every declared
/// `[[bin]]` is an entry.
///
/// The M7 Task 2 review named the one candidate it could find that was
/// missing — the MCP stdio boundary — and it is registered below rather than
/// left in a report.
pub struct FuzzSurface {
    /// The target's name: `fuzz/fuzz_targets/<name>.rs`, and the `[[bin]]`
    /// that declares it.
    pub name: &'static str,
    /// What it drives, named the way a reader would grep for it.
    pub parser: &'static str,
    /// `None` when the target exists. `Some(reason)` when the surface is real
    /// and the code it would fuzz is not in the tree yet — see the
    /// `packetd-ipc-fuzz-target` entry in `xtask`'s `DEFERRALS`, which is what
    /// makes the deferral expire on its own rather than by memory.
    pub deferred: Option<&'static str>,
}

pub const FUZZ_SURFACES: &[FuzzSurface] = &[
    FuzzSurface {
        name: "interpret",
        parser: "bathy_interpret::interpret — the response side of every probe",
        deferred: None,
    },
    FuzzSurface {
        name: "event_log",
        parser: "bathy_evidence::EventLogReader + bathy_query::fold_events — JSONL \
                 written by an older build, a crashed one, or a hand editor",
        deferred: None,
    },
    FuzzSurface {
        name: "canonical_json",
        parser: "bathy_types::canonical::{canonical_json, plan_digest} — every hash \
                 this project computes",
        deferred: None,
    },
    FuzzSurface {
        name: "manifest",
        parser: "bathy_scope::ScopeManifest::load + allows — the authorization boundary",
        deferred: None,
    },
    FuzzSurface {
        name: "ipc",
        parser: "bathy-packetd's line protocol between the unprivileged engine and the \
                 privileged helper",
        // M7 was resequenced ahead of M6 (see the overview's "Recommended
        // execution order": M1-M5, M7, M6), so AC-7.7 names a crate that does
        // not exist while this task runs. A stub target would be worse than
        // the honest gap: it would fuzz nothing, register as coverage, and be
        // the exact "reaches nothing" shape this milestone measured and
        // rejected in a property-test strategy. So the surface stays
        // registered here and the obligation is mechanical rather than
        // remembered.
        deferred: Some(
            "crates/bathy-packetd does not exist yet — M6 ships after M7 in this \
             project's execution order. `xtask check-deps` fails the moment the crate \
             lands without `fuzz/fuzz_targets/ipc.rs`, via the `packetd-ipc-fuzz-target` \
             deferral.",
        ),
    },
    FuzzSurface {
        name: "mcp_stdio",
        parser: "bathy_mcp::lifecycle::classify + the JSON-RPC frame it is handed — the \
                 opening message from a calling agent, which the threat model treats as \
                 possibly adversarial",
        // Named by the M7 Task 2 review as the one unregistered surface it
        // could find, and it is right: this boundary EXISTS because a
        // malformed opening `_meta` was fatal to the process rather than to
        // the request (see `crates/bathy-mcp/src/lifecycle.rs` and
        // `docs/protocol-notes.md`). "It is only a confused agent" is not the
        // discriminator AC-7.7 uses.
        deferred: Some(
            "`bathy_mcp::lifecycle::classify` is `pub(crate)` and takes an already \
             deserialized `ClientJsonRpcMessage`, so there is no entry point a fuzz \
             target can reach from outside the crate, and the byte-level parse belongs \
             to `rmcp`'s transport. Widening the visibility to fuzz it would also drag \
             the whole engine — `bathy-store` and `libsqlite3-sys`'s build script — into \
             a nightly sanitizer build. The `mcp-stdio-fuzz-target` deferral fires the \
             day `classify` becomes reachable, and reports itself stale the day the \
             target lands.",
        ),
    },
];

/// The MCP surface's blocker, as a fact about the source: while `classify` is
/// `pub(crate)` there is no entry point to fuzz.
pub const MCP_LIFECYCLE: &str = "crates/bathy-mcp/src/lifecycle.rs";
/// The target that would discharge it.
pub const MCP_STDIO_FUZZ_TARGET: &str = "fuzz/fuzz_targets/mcp_stdio.rs";

/// The `mcp-stdio-fuzz-target` deferral's condition, in both directions.
///
/// The trigger is the blocker itself rather than a date: a deferral whose
/// condition is "when someone remembers" is a note. When `classify` becomes
/// reachable from outside its crate, the stated reason for the gap is gone
/// and the target is due; when the target lands, this reports itself stale.
pub fn mcp_stdio_deferral_violations(root: &Path) -> Vec<String> {
    let lifecycle = std::fs::read_to_string(root.join(MCP_LIFECYCLE)).unwrap_or_default();
    let reachable = lifecycle.contains("pub fn classify");
    let target_exists = root.join(MCP_STDIO_FUZZ_TARGET).is_file();
    let registered_deferred = FUZZ_SURFACES
        .iter()
        .any(|s| s.name == "mcp_stdio" && s.deferred.is_some());

    let mut found = Vec::new();
    if reachable && !target_exists {
        found.push(format!(
            "{MCP_LIFECYCLE} now exports `classify`, so the reason AC-7.7's MCP stdio \
             surface has no fuzz target is gone: write {MCP_STDIO_FUZZ_TARGET}, seed \
             `fuzz/seeds/mcp_stdio/` from real opening frames, and clear `deferred` on \
             the `mcp_stdio` entry in `FUZZ_SURFACES`. This boundary exists because a \
             malformed opening `_meta` was fatal to the process rather than to the \
             request."
        ));
    }
    if target_exists && registered_deferred {
        found.push(format!(
            "{MCP_STDIO_FUZZ_TARGET} exists but the `mcp_stdio` entry in `FUZZ_SURFACES` \
             is still marked `deferred`, so `run_fuzz` skips the target it has. Clear \
             `deferred` and delete this deferral's entry from `DEFERRALS`."
        ));
    }
    if !reachable && !registered_deferred && !target_exists {
        found.push(format!(
            "the `mcp_stdio` entry in `FUZZ_SURFACES` is no longer marked `deferred` and \
             no {MCP_STDIO_FUZZ_TARGET} exists, so AC-7.7's MCP stdio surface is neither \
             covered nor recorded as outstanding"
        ));
    }
    found
}

/// The crate whose arrival makes the `ipc` target due.
pub const PACKETD_CRATE: &str = "crates/bathy-packetd";
/// The target that discharges it.
pub const IPC_FUZZ_TARGET: &str = "fuzz/fuzz_targets/ipc.rs";

/// The `packetd-ipc-fuzz-target` deferral's condition, in both directions.
///
/// Registered in `xtask`'s `DEFERRALS` rather than only in `check-fuzz`
/// because a deferral that only the thing being deferred knows about is a
/// note. The second direction is the one that matters most here: when the
/// target does land, this check reports *itself* as stale, so the registry
/// does not keep a discharged obligation on the books forever.
pub fn packetd_ipc_deferral_violations(root: &Path) -> Vec<String> {
    let crate_exists = root.join(PACKETD_CRATE).join("Cargo.toml").is_file();
    let target_exists = root.join(IPC_FUZZ_TARGET).is_file();
    let registered_deferred = FUZZ_SURFACES
        .iter()
        .any(|s| s.name == "ipc" && s.deferred.is_some());

    let mut found = Vec::new();
    if crate_exists && !target_exists {
        found.push(format!(
            "{PACKETD_CRATE} now exists, so AC-7.7's `packetd` IPC fuzz target is due: \
             write {IPC_FUZZ_TARGET}, seed `fuzz/seeds/ipc/`, and clear `deferred` on the \
             `ipc` entry in `FUZZ_SURFACES`. The IPC protocol is the boundary a \
             *privileged* process parses across, which is the one surface in this \
             repository where a parsing bug is a privilege-escalation bug rather than \
             only a denial of service."
        ));
    }
    if target_exists && registered_deferred {
        found.push(format!(
            "{IPC_FUZZ_TARGET} exists but the `ipc` entry in `FUZZ_SURFACES` is still \
             marked `deferred`, so `run_fuzz` skips the target it has. Clear `deferred` \
             and delete this deferral's entry from `DEFERRALS` — a check that has \
             quietly stopped applying reads as coverage while guarding nothing."
        ));
    }
    if !crate_exists && !registered_deferred && !target_exists {
        found.push(format!(
            "the `ipc` entry in `FUZZ_SURFACES` is no longer marked `deferred` and no \
             {IPC_FUZZ_TARGET} exists, so AC-7.7's fifth surface is neither covered nor \
             recorded as outstanding"
        ));
    }
    found
}

/// Every `[[bin]]` name declared by the fuzz manifest.
///
/// Text, not TOML: `xtask` has no TOML parser in its dependency tree (see
/// `crate_floors` for the same decision and the same reason), and the shape
/// this cares about — `name = "x"` under a `[[bin]]` header — survives any
/// formatting the file could take.
pub fn fuzz_bin_targets(manifest: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut in_bin = false;
    for line in manifest.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_bin = trimmed == "[[bin]]";
            continue;
        }
        if !in_bin {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("name")
            && let Some(value) = rest.trim_start().strip_prefix('=')
        {
            let value = value.trim().trim_matches('"');
            if !value.is_empty() {
                names.push(value.to_string());
            }
        }
    }
    names
}

/// The fuzz job in `ci.yml`, checked for the two things AC-7.10 actually
/// asks for: that it runs, and that the corpus survives between runs.
///
/// Split out and pure so the tests can feed it a workflow with each half
/// removed. `lab_ci_job_violations`' first version asked `ci.contains(...)`
/// and was satisfied by the comment that documents the step; this one looks
/// for a `run:` step, for the same reason.
pub fn fuzz_ci_job_violations(ci_path: &str, ci: &str) -> Vec<String> {
    let mut found = Vec::new();

    // Everything below is asked of the `fuzz` JOB, not of the file. The
    // review round that found this had both of the first two assertions
    // file-scoped: moving `cargo run -p xtask -- fuzz` into the
    // schedule-gated `lab-conformance` job left `check-fuzz` and `check-ci`
    // green while the targets ran daily instead of per pull request, which is
    // the literal text of AC-7.10. A criterion about *when* something runs
    // cannot be checked by asking whether the file mentions it anywhere: in a
    // workflow, which job a step sits in IS its schedule.
    let Some(block) = job_block(ci, "fuzz") else {
        found.push(format!(
            "{ci_path}: there is no `fuzz:` job. The targets are then run by whatever \
             other job happens to mention them, which is not a thing a reviewer can check."
        ));
        return found;
    };

    let runs_the_targets = block.lines().any(|line| {
        let trimmed = line.trim_start();
        trimmed
            .strip_prefix("- run:")
            .or_else(|| trimmed.strip_prefix("run:"))
            .is_some_and(|command| command.trim().starts_with("cargo run -p xtask -- fuzz"))
    });
    if !runs_the_targets {
        let elsewhere = ci.contains("run: cargo run -p xtask -- fuzz");
        found.push(format!(
            "{ci_path}: no `run:` step *in the `fuzz` job* invokes `cargo run -p xtask \
             -- fuzz`{}, so AC-7.10 is unmet: the targets exist and nothing executes \
             them on a pull request. A fuzz target that runs only when someone \
             remembers is a fuzz target that runs once.",
            if elsewhere {
                " (there is one in another job, which is worse than none: the other \
                 job's `if:` decides when the targets run, and AC-7.10 is exactly a \
                 statement about when)"
            } else {
                ""
            }
        ));
    }

    // AC-7.10 says *with a cached corpus*, and the caching is not a
    // performance nicety: a 60-second run from an empty corpus re-derives the
    // same shallow inputs every time and never gets past them. Without the
    // cache the job is a 60-second smoke test wearing a fuzzer's name.
    //
    // One STEP in this job that is both a cache action and about the corpus,
    // rather than two independent line scans over the job. Two scans are
    // satisfied by a cache of the cargo registry plus the word `fuzz/corpus`
    // in any other line -- and a conjunct that no fixture can fail on its own
    // is a conjunct nothing tests, which is the three-fragment lesson AC-7.9
    // already taught this file.
    let caches_the_corpus = steps_of(block).iter().any(|step| {
        let uncommented = || {
            step.iter()
                .filter(|line| !line.trim_start().starts_with('#'))
        };
        uncommented().any(|line| line.contains("actions/cache@"))
            && uncommented().any(|line| line.contains("fuzz/corpus"))
    });
    if !caches_the_corpus {
        found.push(format!(
            "{ci_path}: the `fuzz` job does not cache `fuzz/corpus` with \
             `actions/cache@` — a cache step in another job restores nothing here — so \
             every run starts from the committed seeds and re-derives the same shallow \
             inputs. AC-7.10 requires a cached corpus."
        ));
    }

    // The workflow must actually fire on pull requests. `on: pull_request` is
    // already there for the whole file; what would silently remove the fuzz
    // job from PRs is a job-level `if:` like the `lab-conformance` job's.
    if let Some(condition) = block
        .lines()
        .find(|l| l.trim_start().starts_with("if:") && l.len() - l.trim_start().len() <= 4)
    {
        found.push(format!(
            "{ci_path}: the `fuzz` job carries a job-level condition ({}), so it does \
             not run on every pull request. AC-7.10 is specifically about pull \
             requests; if the long nightly run needs a condition, put it on the \
             duration rather than on the job.",
            condition.trim()
        ));
    }
    found
}

/// The lines of the named job, from its `  <name>:` header to the next
/// header at the same indentation.
///
/// Every job-scoped assertion in this file rests on this, so the end of a
/// block has to be a *job header* and nothing that merely looks like one.
/// `ci.yml`'s inter-job prose is two-space indented and several lines of it
/// end in a colon; treating one of those as the next job would silently
/// shrink the block, and a shrunk block makes a job-scoped check pass by
/// seeing less. [`is_job_header`] is the single definition of what a header
/// is, and `a_two_space_comment_ending_in_a_colon_does_not_end_a_job`
/// pins it.
fn job_block<'a>(ci: &'a str, job: &str) -> Option<&'a str> {
    let header = format!("\n  {job}:\n");
    let start = ci.find(&header)? + 1;
    let rest = &ci[start..];
    let end = rest
        .match_indices("\n  ")
        .find(|(at, _)| {
            let line = rest[at + 1..].lines().next().unwrap_or("");
            is_job_header(line) && line.trim_start() != format!("{job}:")
        })
        .map_or(rest.len(), |(at, _)| at);
    Some(&rest[..end])
}

/// Whether `line` is a job header: exactly two spaces of indentation, a
/// name, a colon, and nothing else. Not a comment, not a deeper key, not a
/// sentence that happens to end in a colon.
fn is_job_header(line: &str) -> bool {
    let Some(rest) = line.strip_prefix("  ") else {
        return false;
    };
    if rest.starts_with(' ') {
        return false;
    }
    let Some(name) = rest.trim_end().strip_suffix(':') else {
        return false;
    };
    // The name test is what excludes a comment, and it is written as one
    // test rather than two so that neither can be the dead half of a pair:
    // `# WHY THE CORPUS IS CACHED:` fails it on the `#` and on the spaces,
    // and a bare `#cache:` fails it on the `#` alone.
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

/// What is wrong with the fuzzing surface, as text a person can act on.
pub fn fuzz_violations(root: &Path, manifest: &str, ci_path: &str, ci: &str) -> Vec<String> {
    let mut found = Vec::new();

    // The fuzz package must stay out of the root workspace. If it joins it,
    // `cargo test --workspace` and both MSRV jobs start building a
    // nightly-only crate against the pinned stable toolchain, and the failure
    // reads as a toolchain problem rather than as this.
    if !manifest.lines().any(|l| l.trim() == "[workspace]") {
        found.push(format!(
            "{FUZZ_MANIFEST}: no `[workspace]` table, so this package joins the root \
             workspace. `rust-toolchain.toml` pins stable and libFuzzer needs nightly; \
             every `cargo build` at the root would try to compile it."
        ));
    }

    let declared = fuzz_bin_targets(manifest);
    for surface in FUZZ_SURFACES {
        let source = format!("fuzz/fuzz_targets/{}.rs", surface.name);
        let seeds = root.join("fuzz/seeds").join(surface.name);
        if surface.deferred.is_some() {
            if root.join(&source).is_file() {
                found.push(format!(
                    "{source} exists but `{}` is registered as deferred in \
                     FUZZ_SURFACES, so `run_fuzz` skips it",
                    surface.name
                ));
            }
            continue;
        }
        if !root.join(&source).is_file() {
            found.push(format!(
                "{source} is missing, so nothing fuzzes {} (AC-7.7)",
                surface.parser
            ));
            continue;
        }
        if !declared.iter().any(|n| n == surface.name) {
            found.push(format!(
                "{FUZZ_MANIFEST} declares no `[[bin]] name = \"{}\"`, so {source} is a \
                 file nothing builds",
                surface.name
            ));
        }
        // A target with no seeds is the failure this milestone already
        // measured once: a strategy that produced 6 non-empty results in 4096
        // cases and never reached the code it claimed to cover. Structured
        // parsers are not reachable from random bytes in any useful time.
        let seed_count = std::fs::read_dir(&seeds)
            .map(|d| {
                d.filter_map(Result::ok)
                    .filter(|e| e.path().is_file())
                    .count()
            })
            .unwrap_or(0);
        if seed_count == 0 {
            found.push(format!(
                "fuzz/seeds/{}/ has no seed inputs, so this target starts from random \
                 bytes and will spend its whole budget failing to guess a valid record. \
                 Seed it from real recorded data — `testdata/captures/`, a real event \
                 log, a real manifest.",
                surface.name
            ));
        }
    }

    // A target present in the manifest but absent from the registry would be
    // built, never run by `run_fuzz`, and read as covered.
    for name in &declared {
        if !FUZZ_SURFACES.iter().any(|s| s.name == *name) {
            found.push(format!(
                "{FUZZ_MANIFEST} declares a `[[bin]]` named `{name}` that is not in \
                 FUZZ_SURFACES, so `cargo run -p xtask -- fuzz` never runs it"
            ));
        }
    }

    // AC-7.9, asserted about the assertion. This is the one criterion in the
    // task whose subject is a line of test code, and a fuzz assertion nobody
    // has seen fail is the same shape as a decoration test — so the check is
    // that the assertion is still there, and the evidence that it *works* is
    // the recorded mutation run in the task report.
    let interpret_target = root.join("fuzz/fuzz_targets/interpret.rs");
    let interpret = std::fs::read_to_string(&interpret_target).unwrap_or_default();
    for (fragment, why) in [
        (
            "i.matched_span.end <= capture.response.len()",
            "the upper bound: a span running past the response panics any consumer that \
             slices with it",
        ),
        (
            "i.matched_span.start <= i.matched_span.end",
            "the range is not inverted",
        ),
        (
            "&capture.response[i.matched_span.clone()]",
            "the span is actually used to slice the response, which is what a consumer \
             does and what the seven historical span mutants broke",
        ),
    ] {
        if !interpret.contains(fragment) {
            found.push(format!(
                "fuzz/fuzz_targets/interpret.rs no longer asserts `{fragment}` — {why} \
                 (AC-7.9)"
            ));
        }
    }

    // AC-7.8's other half: the target must report what it reached, including
    // when that is nothing. `rule_ids()` is what names the flag bits, and
    // while it was called only from inside `for i in &out`, an execution that
    // matched nothing left the labels empty and `Stats::report` dropped the
    // entire `reached=` clause — the instrument went silent in precisely the
    // case it exists for. The fix is one line and the position IS the fix, so
    // the check is about the position: the call has to be outside the loop.
    //
    // Over the CODE, not the file: the comment above the call quotes `for i
    // in &out` to explain itself, and a check that read the comment would
    // find the loop before the call and report a defect in the fix. This is
    // the third time in this file that prose about a gate has satisfied or
    // broken the gate.
    let code: String = interpret
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    let names_the_rules_at = code.find(INTERPRET_NAMES_THE_RULES);
    let matches_at = code.find("for i in &out");
    match (names_the_rules_at, matches_at) {
        (Some(names), Some(loops)) if names < loops => {}
        (None, _) => found.push(format!(
            "fuzz/fuzz_targets/interpret.rs no longer calls `{INTERPRET_NAMES_THE_RULES}`, \
             which is what supplies the `reached=` denominator. Without it a run that \
             matched nothing prints no `reached=` clause at all, and `reached=0/13` is \
             the most important thing this target can say (AC-7.8)."
        )),
        _ => found.push(format!(
            "fuzz/fuzz_targets/interpret.rs calls `{INTERPRET_NAMES_THE_RULES}` only \
             inside the match loop, so an execution that matched nothing never names the \
             flag bits and the `reached=` clause disappears — in exactly the case it \
             exists to report (AC-7.8). Hoist it above `for i in &out`."
        )),
    }

    found.extend(fuzz_ci_job_violations(ci_path, ci));
    found.extend(fuzz_crate_gate_violations(ci_path, ci));
    found.extend(packetd_ipc_deferral_violations(root));
    found.extend(mcp_stdio_deferral_violations(root));
    found
}

/// The job that runs on every push and pull request with no condition on it
/// — where a gate that reads files belongs.
pub const FAST_CI_JOB: &str = "test";

/// `fuzz/`'s own fmt, clippy and unit tests have a CI step, in the fast job.
///
/// Job-scoped for the same reason as everything else in this file: a step in
/// the nightly job is a gate that does not run on the pull request that
/// breaks it. And in the *fast* job specifically, because it needs neither
/// nightly nor `cargo-fuzz` — putting it in the `fuzz` job would tie a
/// stable-toolchain lint to a job that installs a nightly one.
pub fn fuzz_crate_gate_violations(ci_path: &str, ci: &str) -> Vec<String> {
    let command = "cargo run -p xtask -- check-fuzz-crate";
    let in_fast_job = job_block(ci, FAST_CI_JOB).is_some_and(|block| {
        block.lines().any(|line| {
            let trimmed = line.trim_start();
            trimmed
                .strip_prefix("- run:")
                .or_else(|| trimmed.strip_prefix("run:"))
                .is_some_and(|c| c.trim().starts_with(command))
        })
    });
    if in_fast_job {
        return Vec::new();
    }
    vec![format!(
        "{ci_path}: no `run:` step in the `{FAST_CI_JOB}` job invokes `{command}`, so \
         `fuzz/`'s ~900 lines are outside `cargo fmt --all`, `cargo clippy --workspace` \
         and `cargo test --workspace` with nothing but a README sentence in their \
         place. That is the shape of the MSRV membership rule that had no executable \
         form and three recorded recurrences."
    )]
}

/// The gates the root workspace cannot reach, made into one command.
///
/// `fuzz/` is deliberately its own workspace (three reasons, in
/// `fuzz/Cargo.toml`), and the cost is that `cargo fmt --all`, `cargo clippy
/// --workspace` and `cargo test --workspace` at the root do not see ~900
/// lines of Rust. Until this existed, the compensating control was a
/// sentence in `fuzz/README.md` asking a human to remember to `cd fuzz` —
/// which is the shape of the MSRV membership rule that had no executable
/// form and three recorded recurrences, and strictly weaker than the five
/// inline gates M5 closed. **The gates people run are the gates that have a
/// command.**
///
/// Not a `working-directory:` step in `ci.yml`: `check-ci` refuses those, on
/// purpose and for this reason — from the repository root, `cargo fmt --all
/// -- --check` means the *root* workspace, and a workflow step that quietly
/// means a different one is a gate nobody can reproduce.
///
/// Everything here runs on **stable**. Only *building* the fuzz targets
/// needs nightly; `fmt`, `clippy` and the library's own unit tests do not.
pub fn check_fuzz_crate() -> Fallible<()> {
    let runs: &[&[&str]] = &[
        &["fmt", "--all", "--", "--check"],
        &["clippy", "--all-targets", "--", "-D", "warnings"],
        // The library carries the instrumentation every target shares —
        // `Stats`, and the duplicate-key scan `canonical_json` reports a flag
        // from. A counter with a unit test is a counter someone can trust;
        // one without is a number in a report.
        &["test", "--lib"],
    ];
    for args in runs {
        eprintln!("check-fuzz-crate: (cd fuzz && cargo {})", args.join(" "));
        let status = std::process::Command::new("cargo")
            .args(*args)
            .current_dir("fuzz")
            .status()
            .map_err(|e| format!("running `cargo {}` in fuzz/: {e}", args.join(" ")))?;
        if !status.success() {
            return Err(format!(
                "`cargo {}` failed in fuzz/. This is the same gate the root workspace \
                 runs, pointed at the one package it cannot see.",
                args.join(" ")
            )
            .into());
        }
    }
    println!(
        "check-fuzz-crate: ok ({} gate(s) over fuzz/, the package outside the root \
         workspace)",
        runs.len()
    );
    Ok(())
}

pub fn check_fuzz() -> Fallible<()> {
    let root = Path::new(".");
    let manifest = std::fs::read_to_string(root.join(FUZZ_MANIFEST))
        .map_err(|e| format!("reading {FUZZ_MANIFEST}: {e}"))?;
    let ci_path = ".github/workflows/ci.yml";
    let ci = std::fs::read_to_string(root.join(ci_path))
        .map_err(|e| format!("reading {ci_path}: {e}"))?;

    let violations = fuzz_violations(root, &manifest, ci_path, &ci);
    if violations.is_empty() {
        let live = FUZZ_SURFACES
            .iter()
            .filter(|s| s.deferred.is_none())
            .count();
        let deferred = FUZZ_SURFACES.len() - live;
        let seeds: usize = FUZZ_SURFACES
            .iter()
            .filter(|s| s.deferred.is_none())
            .map(|s| {
                std::fs::read_dir(root.join("fuzz/seeds").join(s.name))
                    .map(|d| d.filter_map(Result::ok).count())
                    .unwrap_or(0)
            })
            .sum();
        println!(
            "check-fuzz: ok ({live} target(s) over {} untrusted-input surface(s), \
             {deferred} deferred, {seeds} committed seed input(s), corpus cached in CI)",
            FUZZ_SURFACES.len(),
        );
        Ok(())
    } else {
        for v in &violations {
            eprintln!("check-fuzz: {v}");
        }
        Err(format!(
            "{} fuzzing violation(s) (AC-7.7 to AC-7.10)",
            violations.len()
        )
        .into())
    }
}

/// The exact `cargo fuzz` invocation for one target, derived rather than
/// remembered.
///
/// Two corpus directories, in this order and on purpose. libFuzzer writes new
/// inputs into the **first** one only, so `fuzz/corpus/<name>` is the working,
/// git-ignored, CI-cached corpus and `fuzz/seeds/<name>` is the committed set
/// it may read but never grow. Committing the working corpus instead would
/// make every local run dirty the tree.
pub fn fuzz_command(name: &str, seconds: u64) -> Vec<String> {
    [
        "+nightly".to_string(),
        "fuzz".to_string(),
        "run".to_string(),
        name.to_string(),
        format!("fuzz/corpus/{name}"),
        format!("fuzz/seeds/{name}"),
        "--".to_string(),
        format!("-max_total_time={seconds}"),
        "-print_final_stats=1".to_string(),
    ]
    .to_vec()
}

/// When a working corpus is large enough to be minimised before the next
/// run, and the reason each bound is where it is.
///
/// Nothing bounded the corpus before this. The CI cache rolls forward
/// through `restore-keys: fuzz-corpus-`, so every run inherits the last
/// one's inputs and adds to them, and libFuzzer holds the whole corpus in
/// memory alongside its coverage tables — the observed 475–556 MB against
/// libFuzzer's default 2048 MB `-rss_limit_mb` is mostly that, not the
/// targets, which allocate a few kilobytes per execution. Left alone, the
/// eventual failure of the fuzz job is a red build that is not a bug, which
/// is the kind of failure people learn to ignore.
///
/// `cargo fuzz cmin` re-runs the corpus and keeps one input per coverage
/// feature, so it is bounded work proportional to what is already there.
/// The thresholds are set above this repository's measured corpora
/// (2,289–9,642 files, 8.9–38 MB per target after several full runs) so an
/// ordinary run does not pay for a minimisation it does not need.
pub fn corpus_needs_minimisation(files: usize, bytes: u64) -> bool {
    const MAX_FILES: usize = 20_000;
    const MAX_BYTES: u64 = 256 * 1024 * 1024;
    files > MAX_FILES || bytes > MAX_BYTES
}

/// The file count and total size of one working corpus directory.
fn corpus_size(name: &str) -> (usize, u64) {
    let Ok(entries) = std::fs::read_dir(format!("fuzz/corpus/{name}")) else {
        return (0, 0);
    };
    entries
        .filter_map(Result::ok)
        .filter_map(|e| e.metadata().ok())
        .filter(std::fs::Metadata::is_file)
        .fold((0, 0), |(files, bytes), m| (files + 1, bytes + m.len()))
}

/// Run every registered, non-deferred fuzz target for `seconds` each.
///
/// This exists rather than a list of `cargo fuzz run` lines in `ci.yml` for
/// one reason: the list in the workflow would be a second registry, and the
/// two would diverge the first time a target was added. `FUZZ_SURFACES` is
/// the only list, `check-fuzz` holds the tree to it, and this runs it.
pub fn run_fuzz(seconds: u64, only: Option<&str>) -> Fallible<()> {
    let targets: Vec<&FuzzSurface> = FUZZ_SURFACES
        .iter()
        .filter(|s| s.deferred.is_none())
        .filter(|s| only.is_none_or(|name| name == s.name))
        .collect();
    if targets.is_empty() {
        return Err(match only {
            Some(name) => format!(
                "no runnable fuzz target named `{name}`; registered: {}",
                FUZZ_SURFACES
                    .iter()
                    .map(|s| s.name)
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
            None => "every registered fuzz surface is deferred, so this ran nothing".into(),
        }
        .into());
    }
    for surface in &targets {
        std::fs::create_dir_all(format!("fuzz/corpus/{}", surface.name))
            .map_err(|e| format!("creating fuzz/corpus/{}: {e}", surface.name))?;
        let args = fuzz_command(surface.name, seconds);
        println!("fuzz: cargo {}", args.join(" "));
        let status = std::process::Command::new("cargo")
            .args(&args)
            .status()
            .map_err(|e| {
                format!(
                    "running `cargo {}`: {e}. `cargo fuzz` needs a nightly toolchain and \
                     the `cargo-fuzz` binary: `rustup toolchain install nightly` and \
                     `cargo install cargo-fuzz --locked`.",
                    args.join(" ")
                )
            })?;
        if !status.success() {
            return Err(format!(
                "fuzz target `{}` failed. libFuzzer writes the input that did it to \
                 `fuzz/artifacts/{}/`; copy it into `fuzz/seeds/{}/` as a regression case \
                 once the bug is fixed.",
                surface.name, surface.name, surface.name
            )
            .into());
        }

        let (files, bytes) = corpus_size(surface.name);
        if corpus_needs_minimisation(files, bytes) {
            println!(
                "fuzz: fuzz/corpus/{} is {files} file(s), {} MiB — minimising, because \
                 libFuzzer holds the corpus in memory and the CI cache rolls it forward \
                 for ever otherwise",
                surface.name,
                bytes / (1024 * 1024),
            );
            let status = std::process::Command::new("cargo")
                .args(["+nightly", "fuzz", "cmin", surface.name])
                .status()
                .map_err(|e| format!("running `cargo fuzz cmin {}`: {e}", surface.name))?;
            if !status.success() {
                return Err(format!(
                    "`cargo fuzz cmin {}` failed. The corpus is over the bound in \
                     `corpus_needs_minimisation`, so the next runs get slower and \
                     hungrier until the job goes red for a reason that is not a bug.",
                    surface.name
                )
                .into());
            }
        }
    }
    println!(
        "fuzz: ok ({} target(s), {seconds}s each, no crash, hang or OOM)",
        targets.len()
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// The "No panics in parsing paths" Global Constraint, made executable.
// ---------------------------------------------------------------------------

/// The lints the constraint's own sentence names, plus the two the M7
/// panic-lint round judged inseparable from it.
///
/// `unwrap_used`, `expect_used` and `indexing_slicing` are the three the
/// overview writes out. `panic` is the same failure spelled differently.
/// `arithmetic_side_effects` is here because an overflowing offset is a panic
/// in a debug build and a *silently wrong span* in a release one, and a wrong
/// span is a claim about which bytes justified a finding — this project has
/// already shipped that bug once, via `from_utf8_lossy` offsets used as
/// indices into the original slice, and killed seven span-corrupting mutants
/// across three review rounds.
pub const PANIC_LINTS: &[&str] = &[
    "clippy::unwrap_used",
    "clippy::expect_used",
    "clippy::indexing_slicing",
    "clippy::panic",
    "clippy::arithmetic_side_effects",
];

/// The crates the constraint covers: every one must carry the deny attribute,
/// and the constraint's text in the overview must name exactly this set.
///
/// The overview said this was true of `bathy-probe` and `bathy-interpret`
/// **from M1**, and no such lint existed anywhere in the tree — not in either
/// `lib.rs`, not in `ci.yml`, not in any `Cargo.toml` lint table — until the
/// M7 verification round found the gap. This constant exists so that
/// sentence can never again be true of the document and false of the code:
/// [`panic_lint_violations`] fails both ways round.
pub const PANIC_LINT_CRATES: &[&str] = &["bathy-probe", "bathy-interpret", "bathy-scope"];

/// Where the attribute has to be, per crate.
fn panic_lint_lib_rs(crate_name: &str) -> String {
    format!("crates/{crate_name}/src/lib.rs")
}

/// An untrusted-input crate the constraint does **not** yet cover, the
/// measured number of hits enabling [`PANIC_LINTS`] produces there, and what
/// that code parses.
///
/// This is the honest half of widening the constraint. `FUZZ_SURFACES`
/// registers five untrusted-input surfaces and the constraint named two
/// crates; the M7 panic-lint round measured every one of the others rather
/// than reasoning about them. `bathy-scope` came back at zero and joined
/// [`PANIC_LINT_CRATES`] the same day. These three did not, and widening the
/// *sentence* over them without doing the work would be the M1 defect
/// committed a second time by the person fixing it.
pub const PANIC_LINT_UNCOVERED: &[(&str, usize, &str)] = &[
    (
        "bathy-types",
        37,
        "canonical_json/plan_digest (every hash this project computes) and clock.rs's \
         RFC 3339 handling; 31 of the 37 are in clock.rs alone",
    ),
    (
        "bathy-evidence",
        14,
        "EventLogReader over JSONL written by an older build, a crashed one, or a hand \
         editor — including an `offsets[after_sequence]` index and an `expected - 1`",
    ),
    (
        "bathy-query",
        8,
        "fold_events over the same logs, plus diff.rs's counters",
    ),
];

/// A site-level allow of a [`PANIC_LINTS`] lint must carry a `reason`.
const PANIC_LINT_REASON_MARKER: &str = "reason =";

/// The exact `ci.yml` step that gives the deny attributes their teeth over
/// every target, including the ones `cargo clippy` alone would skip.
pub const CLIPPY_ALL_TARGETS_STEP: &str = "cargo clippy --workspace --all-targets -- -D warnings";

/// Every `.rs` file under `crates/<name>/src`, sorted.
fn crate_sources(root: &Path, crate_name: &str) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![root.join(format!("crates/{crate_name}/src"))];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|e| e == "rs") {
                out.push(path);
            }
        }
    }
    out.sort();
    out
}

/// The crates the overview's constraint sentence names, in the order it names
/// them.
///
/// Deliberately parses the document rather than trusting it: the whole point
/// of this gate is that the sentence and the tree disagreed for six
/// milestones and nothing noticed.
pub fn crates_named_by_the_constraint(overview: &str) -> Vec<String> {
    let Some(line) = overview
        .lines()
        .find(|l| l.contains("**No panics in parsing paths.**"))
    else {
        return Vec::new();
    };
    let mut named = Vec::new();
    for candidate in PANIC_LINT_CRATES
        .iter()
        .chain(PANIC_LINT_UNCOVERED.iter().map(|(name, _, _)| name))
    {
        if line.contains(&format!("`{candidate}`")) {
            named.push((*candidate).to_string());
        }
    }
    named
}

/// The whole rule, as pure text analysis so it is testable against fixtures.
pub fn panic_lint_violations(root: &Path) -> Vec<String> {
    let mut found = Vec::new();

    for crate_name in PANIC_LINT_CRATES {
        let rel = panic_lint_lib_rs(crate_name);
        let Ok(lib) = std::fs::read_to_string(root.join(&rel)) else {
            found.push(format!(
                "{rel} does not exist, but `{crate_name}` is named by the \"No panics in \
                 parsing paths\" constraint — either the crate moved or the constraint's \
                 crate list is stale"
            ));
            continue;
        };
        let attribute: String = lib
            .split("#![cfg_attr(")
            .find(|chunk| chunk.contains("not(test)") && chunk.contains("deny("))
            .unwrap_or("")
            .to_string();
        if attribute.is_empty() {
            found.push(format!(
                "{rel} carries no `#![cfg_attr(not(test), deny(...))]`. The constraint says \
                 panics are denied by lint in `{crate_name}`; nothing in this file denies \
                 anything. This is the exact state the whole tree was in from M1 to M7."
            ));
            continue;
        }
        for lint in PANIC_LINTS {
            if !attribute.contains(lint) {
                found.push(format!(
                    "{rel}'s deny attribute does not name `{lint}`, so that class of panic \
                     is unguarded in a crate that consumes bytes it did not write"
                ));
            }
        }

        for path in crate_sources(root, crate_name) {
            let Ok(text) = std::fs::read_to_string(&path) else {
                continue;
            };
            let shown = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .display()
                .to_string();
            for (i, line) in text.lines().enumerate() {
                let number = i + 1;
                let names_a_panic_lint = PANIC_LINTS.iter().any(|lint| line.contains(lint));
                if !names_a_panic_lint {
                    continue;
                }
                // A crate-level allow re-opens the hole entirely, which is
                // worse than never having had the lint: the attribute reads
                // as coverage.
                if line.trim_start().starts_with("#![allow(")
                    || (line.contains("#![allow(") && line.contains("clippy::"))
                {
                    found.push(format!(
                        "{shown}:{number}: crate-level `#![allow]` of a panic lint. An \
                         exception must be site-level; a crate-level one reproduces the \
                         defect this constraint exists to close."
                    ));
                }
                // A site-level allow is fine, and must say why.
                if line.trim_start().starts_with("#[allow(") && !line.contains("#![allow(") {
                    let block = allow_attribute_block(&text, i);
                    if !block.contains(PANIC_LINT_REASON_MARKER) {
                        found.push(format!(
                            "{shown}:{number}: `#[allow]` of a panic lint with no `reason = \
                             \"...\"`. An exception that does not say why its panic is \
                             unreachable is indistinguishable from one that is wrong."
                        ));
                    }
                }
            }
        }
    }

    // The document, held to the code — in both directions.
    let overview_path = "docs/superpowers/plans/2026-07-31-bathy-v0.1-overview.md";
    match std::fs::read_to_string(root.join(overview_path)) {
        Err(_) => found.push(format!(
            "{overview_path} is unreadable, so the constraint's own \
             text cannot be checked against the tree"
        )),
        Ok(overview) => {
            let named = crates_named_by_the_constraint(&overview);
            if named.is_empty() {
                found.push(format!(
                    "{overview_path} no longer states the \"No panics in parsing paths\" \
                     constraint in the form this gate reads (a bullet beginning `**No panics \
                     in parsing paths.**` naming its crates in backticks), so the sentence \
                     and the tree are no longer tied together at all"
                ));
            } else {
                let mut expected: Vec<String> =
                    PANIC_LINT_CRATES.iter().map(|c| (*c).to_string()).collect();
                expected.sort();
                let mut actual = named.clone();
                actual.sort();
                if actual != expected {
                    found.push(format!(
                        "{overview_path}'s \"No panics in parsing paths\" constraint names \
                         [{}] but the lint is carried by [{}]. A constraint that names a \
                         crate the tree does not lint is exactly what was claimed from M1 \
                         and never true; a crate that carries the lint and is not named \
                         under-reports what this project actually guarantees.",
                        actual.join(", "),
                        expected.join(", ")
                    ));
                }
            }
        }
    }

    // The deferral's other direction: a crate listed as outstanding that has
    // quietly been covered is a registration checking nothing.
    for (crate_name, _hits, _what) in PANIC_LINT_UNCOVERED {
        let rel = panic_lint_lib_rs(crate_name);
        let Ok(lib) = std::fs::read_to_string(root.join(&rel)) else {
            found.push(format!(
                "{rel} does not exist, but `{crate_name}` is registered in \
                 `PANIC_LINT_UNCOVERED` as an untrusted-input crate still to be covered — \
                 delete the entry"
            ));
            continue;
        };
        if lib.contains("#![cfg_attr(")
            && lib.contains("not(test)")
            && lib.contains("deny(")
            && PANIC_LINTS.iter().any(|lint| lib.contains(lint))
        {
            found.push(format!(
                "{rel} now carries the panic-lint deny attribute, so `{crate_name}`'s entry \
                 in `PANIC_LINT_UNCOVERED` is stale: move it into `PANIC_LINT_CRATES` and \
                 add it to the constraint's own sentence in the overview"
            ));
        }
    }

    // The deny attributes only bite if clippy actually compiles every target.
    let ci_path = ".github/workflows/ci.yml";
    match std::fs::read_to_string(root.join(ci_path)) {
        Err(_) => found.push(format!("{ci_path} is unreadable")),
        Ok(ci) => {
            if !ci.contains(CLIPPY_ALL_TARGETS_STEP) {
                found.push(format!(
                    "{ci_path} no longer runs `{CLIPPY_ALL_TARGETS_STEP}`. Without \
                     `--all-targets` the deny attributes still fire, but only over the \
                     targets clippy happens to build — and this gate's whole claim is that \
                     the lint runs where the other gates run."
                ));
            }
        }
    }

    found
}

/// The text of an `#[allow(...)]` attribute starting at line `start`,
/// including its continuation lines.
///
/// `rustfmt` wraps a multi-line `#[allow(lint, reason = "...")]`, so a check
/// that read only the line the lint name appears on would demand a `reason`
/// that is right there on the next line — a gate that fails correct code is a
/// gate people switch off.
fn allow_attribute_block(text: &str, start: usize) -> String {
    let mut depth = 0i32;
    let mut block = String::new();
    for line in text.lines().skip(start) {
        block.push_str(line);
        block.push('\n');
        depth += line.chars().filter(|c| *c == '(').count() as i32;
        depth -= line.chars().filter(|c| *c == ')').count() as i32;
        if depth <= 0 {
            break;
        }
    }
    block
}

/// The condition for the `panic-lint-widening` entry in `xtask`'s
/// `DEFERRALS`: the three measured-but-uncovered crates, checked in both
/// directions by [`panic_lint_violations`].
pub fn panic_lint_widening_deferral_violations(root: &Path) -> Vec<String> {
    if PANIC_LINT_UNCOVERED.is_empty() {
        return vec![
            "`PANIC_LINT_UNCOVERED` is empty, so every untrusted-input crate is covered and \
             this deferral is checking nothing: delete its entry from DEFERRALS"
                .to_string(),
        ];
    }
    panic_lint_violations(root)
        .into_iter()
        .filter(|v| v.contains("PANIC_LINT_UNCOVERED"))
        .collect()
}

pub fn check_panics() -> Fallible<()> {
    let root = Path::new(".");
    let violations = panic_lint_violations(root);
    if violations.is_empty() {
        let outstanding: usize = PANIC_LINT_UNCOVERED.iter().map(|(_, hits, _)| hits).sum();
        println!(
            "check-panics: ok ({} lint(s) denied in {} crate(s): {}; every exception is \
             site-level and carries a reason; the overview's constraint names exactly \
             those crates)",
            PANIC_LINTS.len(),
            PANIC_LINT_CRATES.len(),
            PANIC_LINT_CRATES.join(" "),
        );
        println!(
            "check-panics: WHAT THIS DOES NOT SEE — {} measured hit(s) across {} \
             untrusted-input crate(s) still outside the constraint ({}), registered as the \
             `panic-lint-widening` deferral. It also cannot see whether a `reason` string is \
             *true*: that a panic is unreachable is an argument, and this gate only checks \
             that someone made one.",
            outstanding,
            PANIC_LINT_UNCOVERED.len(),
            PANIC_LINT_UNCOVERED
                .iter()
                .map(|(name, hits, _)| format!("{name}: {hits}"))
                .collect::<Vec<_>>()
                .join(", "),
        );
        Ok(())
    } else {
        for v in &violations {
            eprintln!("check-panics: {v}");
        }
        Err(format!(
            "{} panic-lint violation(s) against the \"No panics in parsing paths\" Global \
             Constraint",
            violations.len()
        )
        .into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------
    // check-panics: the checker, checked.
    //
    // The failure this gate exists to prevent is a claim nobody runs, so a
    // gate closing it that is itself never exercised would be the same
    // defect one level up. Each test below builds a fake tree in exactly one
    // broken state and asserts the violation is reported with the file that
    // is wrong.
    // -----------------------------------------------------------------

    /// The attribute a covered crate's `lib.rs` must carry, as source text.
    fn panic_lint_attribute() -> String {
        format!(
            "#![cfg_attr(not(test), deny({}))]\n",
            PANIC_LINTS.join(", ")
        )
    }

    /// A tree in which `panic_lint_violations` finds nothing, so each test
    /// below can break exactly one thing.
    fn healthy_panic_lint_tree() -> tempfile::TempDir {
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let root = scratch.path();
        for name in PANIC_LINT_CRATES {
            let dir = root.join(format!("crates/{name}/src"));
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("lib.rs"), panic_lint_attribute()).unwrap();
        }
        for (name, _, _) in PANIC_LINT_UNCOVERED {
            let dir = root.join(format!("crates/{name}/src"));
            std::fs::create_dir_all(&dir).unwrap();
            std::fs::write(dir.join("lib.rs"), "#![forbid(unsafe_code)]\n").unwrap();
        }
        std::fs::create_dir_all(root.join("docs/superpowers/plans")).unwrap();
        std::fs::write(
            root.join("docs/superpowers/plans/2026-07-31-bathy-v0.1-overview.md"),
            format!(
                "- **No panics in parsing paths.** ... denied by lint in {}.\n",
                PANIC_LINT_CRATES
                    .iter()
                    .map(|c| format!("`{c}`"))
                    .collect::<Vec<_>>()
                    .join(" and ")
            ),
        )
        .unwrap();
        std::fs::create_dir_all(root.join(".github/workflows")).unwrap();
        std::fs::write(
            root.join(".github/workflows/ci.yml"),
            format!("      - run: {CLIPPY_ALL_TARGETS_STEP}\n"),
        )
        .unwrap();
        scratch
    }

    #[test]
    fn a_healthy_tree_has_no_panic_lint_violations() {
        let scratch = healthy_panic_lint_tree();
        assert_eq!(
            panic_lint_violations(scratch.path()),
            Vec::<String>::new(),
            "the fixture every other test in this group mutates must start clean"
        );
    }

    #[test]
    fn the_real_tree_passes_check_panics() {
        // The fixtures above prove the rule fires. This proves it is pointed
        // at the repository people actually commit -- the half a
        // fixture-only test suite silently drops.
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        assert_eq!(panic_lint_violations(&root), Vec::<String>::new());
    }

    #[test]
    fn a_crate_with_no_deny_attribute_at_all_is_caught() {
        // The exact state `bathy-probe` and `bathy-interpret` were in from M1
        // to M7 while this constraint said otherwise.
        let scratch = healthy_panic_lint_tree();
        let lib = scratch.path().join("crates/bathy-probe/src/lib.rs");
        std::fs::write(&lib, "#![forbid(unsafe_code)]\n").unwrap();
        let found = panic_lint_violations(scratch.path());
        assert!(
            found
                .iter()
                .any(|v| v.contains("crates/bathy-probe/src/lib.rs")
                    && v.contains("carries no `#![cfg_attr(not(test), deny(...))]`")),
            "{found:?}"
        );
    }

    #[test]
    fn a_deny_attribute_missing_one_lint_is_caught_and_names_the_lint() {
        let scratch = healthy_panic_lint_tree();
        let lib = scratch.path().join("crates/bathy-interpret/src/lib.rs");
        let partial: Vec<&str> = PANIC_LINTS.iter().skip(1).copied().collect();
        std::fs::write(
            &lib,
            format!("#![cfg_attr(not(test), deny({}))]\n", partial.join(", ")),
        )
        .unwrap();
        let found = panic_lint_violations(scratch.path());
        assert!(
            found
                .iter()
                .any(|v| v.contains("clippy::unwrap_used") && v.contains("bathy-interpret")),
            "{found:?}"
        );
    }

    #[test]
    fn a_deny_that_is_not_scoped_to_non_test_builds_is_not_accepted_as_one() {
        // A bare `#![deny(...)]` would fire on `#[cfg(test)] mod tests` too,
        // and the way that gets "fixed" under time pressure is a crate-level
        // allow. The gate only recognises the `cfg_attr(not(test), ...)`
        // form, so the shortcut reads as no attribute at all.
        let scratch = healthy_panic_lint_tree();
        let lib = scratch.path().join("crates/bathy-scope/src/lib.rs");
        std::fs::write(&lib, format!("#![deny({})]\n", PANIC_LINTS.join(", "))).unwrap();
        let found = panic_lint_violations(scratch.path());
        assert!(
            found
                .iter()
                .any(|v| v.contains("bathy-scope") && v.contains("carries no")),
            "{found:?}"
        );
    }

    #[test]
    fn a_crate_level_allow_reopening_the_hole_is_caught() {
        let scratch = healthy_panic_lint_tree();
        let lib = scratch.path().join("crates/bathy-probe/src/lib.rs");
        std::fs::write(
            &lib,
            format!(
                "{}#![allow(clippy::indexing_slicing)]\n",
                panic_lint_attribute()
            ),
        )
        .unwrap();
        let found = panic_lint_violations(scratch.path());
        assert!(
            found
                .iter()
                .any(|v| v.contains("crate-level `#![allow]` of a panic lint")),
            "{found:?}"
        );
    }

    #[test]
    fn a_site_level_allow_without_a_reason_is_caught() {
        let scratch = healthy_panic_lint_tree();
        let src = scratch.path().join("crates/bathy-probe/src/parse.rs");
        std::fs::write(
            &src,
            "#[allow(clippy::unwrap_used)]\nfn f() { None::<u8>.unwrap(); }\n",
        )
        .unwrap();
        let found = panic_lint_violations(scratch.path());
        assert!(
            found
                .iter()
                .any(|v| v.contains("parse.rs:1") && v.contains("no `reason")),
            "{found:?}"
        );
    }

    #[test]
    fn a_site_level_allow_with_a_wrapped_reason_is_accepted() {
        // rustfmt splits a long `#[allow(lint, reason = "...")]` across
        // lines. A gate that demanded the reason on the same line as the
        // lint would fail correct code, and a gate that fails correct code
        // is a gate someone switches off.
        let scratch = healthy_panic_lint_tree();
        let src = scratch.path().join("crates/bathy-probe/src/parse.rs");
        std::fs::write(
            &src,
            "#[allow(\n    clippy::unwrap_used,\n    reason = \"the const is in range\"\n)]\nfn f() {}\n",
        )
        .unwrap();
        assert_eq!(panic_lint_violations(scratch.path()), Vec::<String>::new());
    }

    #[test]
    fn a_constraint_naming_a_crate_the_tree_does_not_lint_is_caught() {
        // The M1 defect itself, in its purest form: the sentence claims a
        // crate the code does not cover.
        let scratch = healthy_panic_lint_tree();
        let doc = scratch
            .path()
            .join("docs/superpowers/plans/2026-07-31-bathy-v0.1-overview.md");
        std::fs::write(
            &doc,
            "- **No panics in parsing paths.** ... denied by lint in `bathy-probe`, \
             `bathy-interpret`, `bathy-scope` and `bathy-evidence`.\n",
        )
        .unwrap();
        let found = panic_lint_violations(scratch.path());
        assert!(
            found.iter().any(|v| v.contains("bathy-evidence")),
            "{found:?}"
        );
    }

    #[test]
    fn a_crate_that_carries_the_lint_and_is_not_named_by_the_constraint_is_caught() {
        // The other direction. Under-reporting is a smaller sin than
        // over-reporting, but it still means the document is not the answer
        // to "what does this project guarantee".
        let scratch = healthy_panic_lint_tree();
        let doc = scratch
            .path()
            .join("docs/superpowers/plans/2026-07-31-bathy-v0.1-overview.md");
        std::fs::write(
            &doc,
            "- **No panics in parsing paths.** ... denied by lint in `bathy-probe` and \
             `bathy-interpret`.\n",
        )
        .unwrap();
        let found = panic_lint_violations(scratch.path());
        assert!(found.iter().any(|v| v.contains("bathy-scope")), "{found:?}");
    }

    #[test]
    fn a_deferred_crate_that_has_quietly_been_covered_is_reported_stale() {
        // The registration's second direction, which is why these are not
        // `assert!`s: a deferral that has stopped applying reads as coverage.
        let scratch = healthy_panic_lint_tree();
        let (name, _, _) = PANIC_LINT_UNCOVERED[0];
        std::fs::write(
            scratch.path().join(format!("crates/{name}/src/lib.rs")),
            panic_lint_attribute(),
        )
        .unwrap();
        let found = panic_lint_widening_deferral_violations(scratch.path());
        assert!(
            found
                .iter()
                .any(|v| v.contains(name) && v.contains("stale")),
            "{found:?}"
        );
    }

    #[test]
    fn dropping_the_all_targets_clippy_step_is_caught() {
        // The deny attributes are compiled by that step and by nothing else
        // in the workflow. Losing it would leave `check-panics` green over a
        // lint that never ran -- a gate reporting on a gate that is gone.
        let scratch = healthy_panic_lint_tree();
        std::fs::write(
            scratch.path().join(".github/workflows/ci.yml"),
            "      - run: cargo clippy --workspace -- -D warnings\n",
        )
        .unwrap();
        let found = panic_lint_violations(scratch.path());
        assert!(
            found.iter().any(|v| v.contains("--all-targets")),
            "{found:?}"
        );
    }

    #[test]
    fn every_uncovered_crate_is_registered_with_a_measurement_and_a_reason() {
        // A deferral whose entry is a crate name and nothing else is a
        // to-do. Each has to carry the count that was actually measured and
        // what the code parses, because the next person's first question is
        // "how big is this".
        for (name, hits, what) in PANIC_LINT_UNCOVERED {
            assert!(!name.is_empty());
            assert!(*hits > 0, "{name} is registered as outstanding at 0 hits");
            assert!(
                what.len() > 30,
                "{name}'s entry does not say what it parses"
            );
        }
    }

    /// A gate's own evidence must not depend on whether someone has run the
    /// fuzzer. `fuzz/corpus` is git-ignored working state of thousands of
    /// generated files, and walking it made the reported file count differ
    /// by three times between two checkouts of the same commit.
    #[test]
    fn the_fuzzers_working_state_is_not_walked_and_a_real_corpus_directory_still_is() {
        // `tempfile::tempdir()`, not a name built out of the process id.
        // This test and its namesake in `phrases.rs` (`walk` exists in both
        // modules, and both need the same fixture) used to compute the
        // byte-identical path `<tmp>/bathy-walk-<pid>-2` --
        // `NEVER_SCANNED_PATHS.len()` is 2 in both -- and both began and
        // ended by `remove_dir_all`-ing it. They live in the same `xtask`
        // test binary and libtest runs them concurrently, so either could
        // delete the other's tree mid-walk. A process id is unique per
        // *process*; what a scratch path has to be unique per is *test*, and
        // nothing but a comment was making it so.
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let root = scratch.path().to_path_buf();
        for dir in [
            "fuzz/corpus/interpret",
            "fuzz/artifacts/interpret",
            "fuzz/seeds",
            "crates/corpus",
        ] {
            std::fs::create_dir_all(root.join(dir)).unwrap();
            std::fs::write(root.join(dir).join("a.txt"), "x").unwrap();
        }
        let mut found = Vec::new();
        walk(&root, &mut found).unwrap();
        let names: Vec<String> = found
            .iter()
            .map(|p| {
                p.strip_prefix(&root)
                    .unwrap()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        assert!(
            !names.iter().any(|n| n.starts_with("fuzz/corpus")),
            "{names:?}"
        );
        assert!(
            !names.iter().any(|n| n.starts_with("fuzz/artifacts")),
            "{names:?}"
        );
        assert!(names.contains(&"fuzz/seeds/a.txt".to_string()), "{names:?}");
        // `corpus` is an ordinary word: only the fuzz one is skipped, which
        // is why the skip list is paths and not names.
        assert!(
            names.contains(&"crates/corpus/a.txt".to_string()),
            "{names:?}"
        );
        // No explicit removal: `scratch` deletes the tree when it drops,
        // which also happens on the panic paths above. The hand-rolled
        // version leaked its tree on every failure.
    }

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
            !FUZZ_SURFACES.is_empty(),
            "`fuzz_violations` and `run_fuzz` both iterate FUZZ_SURFACES; an empty \
             registry makes check-fuzz pass and `xtask fuzz` run nothing"
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

    fn clean_deny_ci() -> String {
        let step = |manifest: &str| {
            format!(
                "      - uses: EmbarkStudios/cargo-deny-action@v2\n        with:\n          \
                 manifest-path: {manifest}\n          arguments: {}\n          command: \
                 check\n          command-arguments: {}\n",
                DENY_GLOBAL_ARGS.join(" "),
                DENY_CHECKS.join(" "),
            )
        };
        format!(
            "jobs:\n  test:\n    steps:\n      - uses: x\n        with:\n          arguments: \
             not-this-one\n  deny:\n    steps:\n{}{}",
            step(DENY_MANIFESTS[0]),
            step(DENY_MANIFESTS[1]),
        )
    }

    #[test]
    fn a_clean_deny_job_passes_and_its_inputs_are_read_out_of_that_job_only() {
        let ci = clean_deny_ci();
        let v = deny_job_violations("ci.yml", &ci);
        assert!(v.is_empty(), "{v:#?}");
        let steps = deny_steps_in_ci(&ci);
        assert_eq!(steps.len(), 2, "{steps:#?}");
        assert_eq!(
            steps[0].command_arguments.clone().unwrap_or_default(),
            DENY_CHECKS,
            "the `arguments: not-this-one` in the neighbouring job is not this job's"
        );
    }

    /// The defect this rewrite exists for. The four check names were declared
    /// in `arguments:`, which the action splices in BEFORE the subcommand --
    /// `cargo-deny … advisories bans licenses sources check`, which exits 2
    /// with `unrecognized subcommand 'advisories'` (measured against
    /// cargo-deny 0.20.2). The old checker read `arguments:`, compared it to
    /// `DENY_CHECKS`, found it equal and reported ok: it checked the spelling
    /// of a set and never the position it was spelled in.
    #[test]
    fn the_check_set_in_the_global_flag_slot_is_reported() {
        let ci = clean_deny_ci().replace(
            &format!(
                "arguments: {}\n          command: check\n          command-arguments: {}",
                DENY_GLOBAL_ARGS.join(" "),
                DENY_CHECKS.join(" ")
            ),
            &format!(
                "arguments: {}\n          command: check",
                DENY_CHECKS.join(" ")
            ),
        );
        let v = deny_job_violations("ci.yml", &ci);
        assert_eq!(v.len(), 4, "one per manifest per input: {v:#?}");
        assert!(
            v.iter()
                .any(|m| m.contains("unrecognized \\\n") || m.contains("unrecognized")),
            "it must say what actually happens: {v:#?}"
        );
    }

    /// `fuzz/` is its own workspace, so root `cargo deny` never sees
    /// `libfuzzer-sys`, `arbitrary` or `ipnet`. Deleting the second step
    /// silently returns ~900 lines of Rust and a whole dependency tree to
    /// being audited by nobody.
    #[test]
    fn a_deny_job_that_does_not_audit_the_fuzz_workspace_is_reported() {
        let ci = clean_deny_ci();
        let cut = ci.find("manifest-path: fuzz/Cargo.toml").unwrap();
        let start = ci[..cut].rfind("      - uses:").unwrap();
        let v = deny_job_violations("ci.yml", &format!("{}{}", &ci[..start], ""));
        assert_eq!(v.len(), 1, "{v:#?}");
        assert!(v[0].contains("fuzz/Cargo.toml"), "{}", v[0]);
    }

    #[test]
    fn a_deny_step_whose_global_flags_differ_from_the_local_command_is_reported() {
        // `--all-features` decides which crates are in the graph at all, so
        // dropping it in one place is a different audit reporting the same
        // word.
        let ci = clean_deny_ci().replacen(
            &format!("arguments: {}", DENY_GLOBAL_ARGS.join(" ")),
            "arguments: --config deny.toml",
            1,
        );
        let v = deny_job_violations("ci.yml", &ci);
        assert_eq!(v.len(), 1, "{v:#?}");
        assert!(v[0].contains("GLOBAL flags"), "{}", v[0]);
    }

    #[test]
    fn a_comment_discussing_the_inputs_is_not_a_declaration_of_them() {
        let ci = "jobs:\n  deny:\n    steps:\n      - uses: \
                  EmbarkStudios/cargo-deny-action@v2\n        with:\n          # \
                  `command-arguments:` and `arguments:` were both absent\n";
        let steps = deny_steps_in_ci(ci);
        assert_eq!(steps.len(), 1);
        assert_eq!(steps[0], DenyStep::default(), "{steps:#?}");
    }

    #[test]
    fn this_repositorys_deny_job_runs_what_this_command_runs() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let ci = std::fs::read_to_string(root.join(".github/workflows/ci.yml")).unwrap();
        let v = deny_job_violations(".github/workflows/ci.yml", &ci);
        assert!(v.is_empty(), "{v:#?}");
        // And the local argv is the action's argv, in the action's order:
        // `cargo-deny <arguments> <command> <command-arguments>`.
        assert_eq!(
            deny_command("fuzz/Cargo.toml"),
            vec![
                "--manifest-path",
                "fuzz/Cargo.toml",
                "--all-features",
                "--config",
                "deny.toml",
                "check",
                "advisories",
                "bans",
                "licenses",
                "sources"
            ]
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

    /// The blindness that let `fuzz/` sit outside every root gate: the check
    /// read the `run:` line and never the sibling key that says which tree it
    /// runs over. Both orderings, because YAML keys are unordered and a check
    /// that only looked below the `run:` would be satisfied by swapping two
    /// lines.
    #[test]
    fn a_step_scoped_to_a_subdirectory_is_not_the_root_gate_it_reads_as() {
        for ci in [
            "jobs:\n  a:\n    steps:\n      - run: cargo fmt --all -- --check\n        \
             working-directory: fuzz\n",
            "jobs:\n  a:\n    steps:\n      - working-directory: fuzz\n        run: cargo fmt \
             --all -- --check\n",
        ] {
            let v = ci_steps_without_a_local_form("ci.yml", ci, SUBS);
            assert_eq!(v.len(), 1, "{ci}\n{v:#?}");
            assert!(v[0].contains("working-directory: fuzz"), "{}", v[0]);
            assert!(v[0].contains("no local form"), "{}", v[0]);
        }
    }

    /// ...and the neighbouring step is not dragged into it. A step block ends
    /// at the next `- ` marker; if it did not, one `working-directory:`
    /// anywhere would condemn every step after it and the check would be
    /// noise rather than a gate.
    #[test]
    fn a_working_directory_does_not_leak_into_the_next_step() {
        // The root gate FIRST and the scoped one after it, so a step block
        // that ran past its own `- ` marker would condemn the root `cargo
        // test --workspace` for a key belonging to the step below it.
        let ci = "jobs:\n  a:\n    steps:\n      - run: cargo test --workspace\n      \
                  - run: cargo fmt --all -- --check\n        working-directory: fuzz\n";
        let v = ci_steps_without_a_local_form("ci.yml", ci, SUBS);
        assert_eq!(v.len(), 1, "{v:#?}");
        assert!(v[0].contains("ci.yml:5"), "{}", v[0]);
        assert!(v[0].contains("cargo fmt"), "{}", v[0]);
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
             tls:\n    image: alpine@{PIN_B}\n    networks:\n      labnet:\n        \
             ipv4_address: 10.30.0.17\n  \
             quiet:\n    image: alpine@{PIN_B}\n    networks:\n      labnet:\n        \
             ipv4_address: 10.30.0.18\n"
        );
        // Every narrowing control the real lab has, in miniature: 22 scanned
        // and shut everywhere, 80 and 443 served by different hosts, and a
        // live host that answers nothing. A fixture missing one of them would
        // make the seeded-violation test for that control pass vacuously.
        let truth = serde_json::json!({
            "scanned_ports": [22, 80, 443],
            "hosts": [
                { "ip": "10.30.0.10", "open": [
                    { "port": 80, "product": "nginx", "version": "1.29.8",
                      "evidence": "Server: nginx/1.29.8" }] },
                { "ip": "10.30.0.17", "open": [{ "port": 443 }] },
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
        truth["hosts"][2]["open"] = serde_json::json!([{ "port": 80 }]);
        let v = lab(&compose, &truth);
        assert_eq!(v.len(), 1, "{v:#?}");
        assert!(v[0].contains("answers nothing"), "{v:#?}");
    }

    #[test]
    fn a_scanned_port_set_with_no_shut_port_gives_ac_7_3_nothing_to_catch_either() {
        let (compose, mut truth) = lab_fixture();
        // Every scanned port open on every host: port 80 only, open on all
        // three. This necessarily removes the named controls too (they are
        // defined over ports this leaves unscanned), which is why the
        // assertion below names the generic property rather than counting.
        truth["scanned_ports"] = serde_json::json!([80]);
        truth["hosts"][1]["open"] = serde_json::json!([{ "port": 80 }]);
        truth["hosts"][2]["open"] = serde_json::json!([{ "port": 80 }]);
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

    // --- The narrowing controls, one seeded removal each. ---
    //
    // `lab/README.md` names four and states that `check-lab` fails if any is
    // removed. That sentence was false: the M7 Task 1 review removed port 22
    // from `scanned_ports` and everything stayed green, because the generic
    // "some scanned port is shut somewhere" property was independently
    // satisfied by 8080. Generic properties do not defend named controls.

    #[test]
    fn removing_port_22_from_the_scanned_set_is_caught_the_way_the_readme_promises() {
        let (compose, mut truth) = lab_fixture();
        truth["scanned_ports"] = serde_json::json!([80, 443]);
        let v = lab(&compose, &truth);
        assert_eq!(v.len(), 1, "{v:#?}");
        assert!(
            v[0].contains("ssh-on-2222-so-22-is-shut-everywhere"),
            "{}",
            v[0]
        );
    }

    #[test]
    fn a_lab_where_something_starts_listening_on_22_loses_the_same_control() {
        let (compose, mut truth) = lab_fixture();
        truth["hosts"][1]["open"] = serde_json::json!([{ "port": 443 }, { "port": 22 }]);
        let v = lab(&compose, &truth);
        assert_eq!(v.len(), 1, "{v:#?}");
        assert!(
            v[0].contains("22 is recorded open on 10.30.0.17"),
            "{}",
            v[0]
        );
    }

    #[test]
    fn a_lab_whose_web_hosts_stop_serving_opposite_ports_is_caught() {
        let (compose, mut truth) = lab_fixture();
        // The TLS host starts serving 80 as well, so no host serves 443
        // without 80 and a scanner that reported everything open is no longer
        // distinguishable from a correct one on this pair.
        truth["hosts"][1]["open"] = serde_json::json!([{ "port": 443 }, { "port": 80 }]);
        let v = lab(&compose, &truth);
        assert_eq!(v.len(), 1, "{v:#?}");
        assert!(
            v[0].contains("tls-web-and-web-nginx-serve-opposite-ports"),
            "{}",
            v[0]
        );
    }

    #[test]
    fn every_narrowing_control_the_readme_names_has_a_checker_here() {
        assert_eq!(
            NARROWING_CONTROLS.len(),
            3,
            "the fourth README bullet -- the absent addresses -- is enforced by the \
             `absent` checks above rather than by a NarrowingControl. If a bullet is \
             added to lab/README.md, it needs an entry here or the sentence that says \
             check-lab enforces them all goes back to being false."
        );
    }

    // --- Product claims and the evidence they were transcribed from. ---

    #[test]
    fn a_product_that_is_not_in_its_own_evidence_is_caught() {
        let (compose, mut truth) = lab_fixture();
        truth["hosts"][0]["open"][0]["product"] = serde_json::json!("Apache");
        let v = lab(&compose, &truth);
        assert_eq!(v.len(), 1, "{v:#?}");
        assert!(v[0].contains("claims product `Apache`"), "{}", v[0]);
    }

    #[test]
    fn a_version_that_is_not_in_its_own_evidence_is_caught_with_no_escape_hatch() {
        let (compose, mut truth) = lab_fixture();
        truth["hosts"][0]["open"][0]["version"] = serde_json::json!("1.28.0");
        truth["hosts"][0]["open"][0]["product_inference"] = serde_json::json!("a guess");
        let v = lab(&compose, &truth);
        // Two: the version has no basis, and the inference note is unused
        // because the product IS a literal. Both are the point.
        assert_eq!(v.len(), 2, "{v:#?}");
        assert!(
            v.iter().any(|s| s.contains("claims version `1.28.0`")),
            "{v:#?}"
        );
    }

    #[test]
    fn the_one_product_read_off_a_wire_format_rather_than_a_literal_must_say_so() {
        let (compose, mut truth) = lab_fixture();
        // MySQL's shape: the handshake gives a version and an auth plugin and
        // never the vendor name.
        truth["hosts"][0]["open"][0] = serde_json::json!({
            "port": 80, "product": "MySQL", "version": "9.4.0",
            "evidence": "\\x0a 9.4.0 \\x00 caching_sha2_password",
        });
        let v = lab(&compose, &truth);
        assert_eq!(v.len(), 1, "{v:#?}");
        assert!(v[0].contains("claims product `MySQL`"), "{}", v[0]);

        truth["hosts"][0]["open"][0]["product_inference"] =
            serde_json::json!("protocol-10 handshake; the bytes name no vendor");
        assert!(lab(&compose, &truth).is_empty());
    }

    /// The mutation that reproduces the review's central finding exactly:
    /// put `product: null` back at `10.30.0.17:443` and leave the evidence
    /// alone. Nothing caught this before -- a null claims nothing, so a rule
    /// that only checks claims against evidence has nothing to check, and
    /// AC-7.5 skips the endpoint entirely. It is the one oracle error that
    /// deletes its own witness.
    #[test]
    fn evidence_that_names_a_product_may_not_be_recorded_as_null() {
        let (compose, mut truth) = lab_fixture();
        truth["hosts"][0]["open"][0]["product"] = serde_json::Value::Null;
        truth["hosts"][0]["open"][0]["version"] = serde_json::Value::Null;
        let v = lab(&compose, &truth);
        assert_eq!(v.len(), 1, "{v:#?}");
        assert!(
            v[0].contains("its own `evidence` names `nginx`"),
            "{}",
            v[0]
        );
    }

    #[test]
    fn the_banner_shapes_that_name_a_product_are_recognised_and_others_are_not() {
        for (evidence, expected) in [
            (
                "HTTP/1.1 400 Bad Request\\r\\nServer: nginx/1.29.8",
                Some("nginx"),
            ),
            ("SSH-2.0-OpenSSH_10.3", Some("OpenSSH")),
            (
                "220 mail.lab.invalid ESMTP Postfix (Debian/GNU)",
                Some("Postfix"),
            ),
            // Nothing names a product in any of these, and inventing one
            // would be worse than the silence this check exists to break.
            ("accepts a connection and volunteers no bytes", None),
            ("\\x05\\x00\\x00\\x00\\x0b\\x08\\x05\\x1a\\x00", None),
            ("open; the bind9 image enables DoT by default.", None),
        ] {
            assert_eq!(
                product_named_by(evidence).as_deref(),
                expected,
                "{evidence:?}"
            );
        }
    }

    #[test]
    fn the_real_ground_truth_backs_every_product_it_claims() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let truth: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(root.join(LAB_GROUND_TRUTH)).unwrap())
                .unwrap();
        let hosts = truth["hosts"].as_array().unwrap();
        let claims = hosts
            .iter()
            .flat_map(|h| h["open"].as_array().unwrap())
            .filter(|o| !o["product"].is_null())
            .count();
        assert!(
            claims >= 5,
            "only {claims} product claim(s) in the real ground truth; this check would \
             range over almost nothing"
        );
        assert!(
            product_claims_not_backed_by_their_own_evidence(LAB_GROUND_TRUTH, hosts).is_empty()
        );
    }

    // --- The lab address `bathy-probe` hardcodes (MINOR-5). ---

    fn probe_check(source: &str, truth: &serde_json::Value) -> Vec<String> {
        probe_lab_address_violations(LAB_TLS_PROBE, source, LAB_GROUND_TRUTH, truth)
    }

    #[test]
    fn the_address_the_tls_probe_test_dials_must_be_open_in_the_ground_truth() {
        let (_, truth) = lab_fixture();
        assert!(
            probe_check(
                "    const LAB_TLS_WEB: &str = \"10.30.0.17:443\";\n",
                &truth
            )
            .is_empty()
        );
        for moved in ["10.30.0.99:443", "10.30.0.17:8443", "10.30.0.18:443"] {
            let v = probe_check(
                &format!("    const LAB_TLS_WEB: &str = \"{moved}\";\n"),
                &truth,
            );
            assert_eq!(v.len(), 1, "{moved} must be caught: {v:#?}");
        }
    }

    #[test]
    fn a_renamed_constant_fails_rather_than_letting_the_cross_check_range_over_nothing() {
        let (_, truth) = lab_fixture();
        let v = probe_check("    const LAB_TLS: &str = \"10.30.0.17:443\";\n", &truth);
        assert_eq!(v.len(), 1, "{v:#?}");
        assert!(
            v[0].contains("no `LAB_TLS_WEB` address literal"),
            "{}",
            v[0]
        );
    }

    #[test]
    fn this_repositorys_probe_test_dials_this_repositorys_lab() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let source = std::fs::read_to_string(root.join(LAB_TLS_PROBE)).unwrap();
        let truth: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(root.join(LAB_GROUND_TRUTH)).unwrap())
                .unwrap();
        assert!(
            probe_lab_address_violations(LAB_TLS_PROBE, &source, LAB_GROUND_TRUTH, &truth)
                .is_empty()
        );
    }

    // --- The conformance suite's CI job. ---

    const CLEAN_LAB_CI: &str = "\
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: cargo test --workspace
  lab-conformance:
    if: github.event_name == 'schedule'
    runs-on: ubuntu-latest
    steps:
      - run: lab/run.sh test
";
    const REQUIRES_THE_LAB: &str = "BATHY_LAB_REQUIRED=1 cargo test --workspace -- --ignored\n";

    #[test]
    fn a_clean_lab_workflow_and_runner_pass() {
        let v = lab_ci_job_violations("ci.yml", CLEAN_LAB_CI, "lab/run.sh", REQUIRES_THE_LAB);
        assert!(v.is_empty(), "{v:#?}");
    }

    #[test]
    fn a_workflow_that_never_runs_the_conformance_suite_is_caught() {
        let v = lab_ci_job_violations(
            "ci.yml",
            &CLEAN_LAB_CI.replace("      - run: lab/run.sh test\n", ""),
            "lab/run.sh",
            REQUIRES_THE_LAB,
        );
        assert_eq!(v.len(), 1, "{v:#?}");
        assert!(v[0].contains("lab/run.sh test"), "{}", v[0]);
    }

    /// The same defect class as the fuzz job's, in the job next door: a step
    /// that exists in the *wrong* job satisfies a file-scoped check while
    /// running on a schedule nobody asked for. Here the move is into the fast
    /// `test` job, which would pull 2.8 GiB of images on every pull request --
    /// the exact cost the `lab-conformance` job's comment block exists to
    /// avoid -- and the file still contains the step, so a `ci.contains` or a
    /// whole-file line scan sees nothing wrong.
    #[test]
    fn a_conformance_step_in_a_neighbouring_job_is_reported() {
        let moved = CLEAN_LAB_CI
            .replace("      - run: lab/run.sh test\n", "")
            .replace(
                "      - run: cargo test --workspace\n",
                "      - run: cargo test --workspace\n      - run: lab/run.sh test\n",
            );
        assert!(
            moved.contains("- run: lab/run.sh test"),
            "the step is still in the file, which is the point"
        );
        let v = lab_ci_job_violations("ci.yml", &moved, "lab/run.sh", REQUIRES_THE_LAB);
        assert_eq!(v.len(), 1, "{v:#?}");
        assert!(v[0].contains(LAB_CI_JOB), "{}", v[0]);
    }

    /// The first version of this check was `ci.contains("lab/run.sh test")`,
    /// and deleting the step did not fail it: the comment block above the job
    /// names the command four times. A guard satisfied by the prose that
    /// documents it guards nothing.
    #[test]
    fn a_comment_naming_the_command_does_not_count_as_running_it() {
        let commented = CLEAN_LAB_CI.replace(
            "      - run: lab/run.sh test\n",
            "      # `lab/run.sh test` sets BATHY_LAB_REQUIRED, so an absent lab fails\n\
             \x20     # rather than skipping. See lab/run.sh test.\n      - uses: actions/checkout@v4\n",
        );
        let v = lab_ci_job_violations("ci.yml", &commented, "lab/run.sh", REQUIRES_THE_LAB);
        assert_eq!(v.len(), 1, "{v:#?}");
        assert!(v[0].contains("no `run:` step"), "{}", v[0]);
    }

    #[test]
    fn a_runner_script_that_stopped_requiring_the_lab_is_caught_too() {
        // The job would then run, find no lab, skip five criteria and exit 0 --
        // the AC-7.32 defect one level up.
        let v = lab_ci_job_violations(
            "ci.yml",
            CLEAN_LAB_CI,
            "lab/run.sh",
            "cargo test --workspace -- --ignored\n",
        );
        assert_eq!(v.len(), 1, "{v:#?}");
        assert!(v[0].contains("BATHY_LAB_REQUIRED"), "{}", v[0]);
    }

    #[test]
    fn this_repositorys_workflow_runs_the_conformance_suite_and_requires_the_lab() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let ci = std::fs::read_to_string(root.join(".github/workflows/ci.yml")).unwrap();
        let run_sh = std::fs::read_to_string(root.join(LAB_RUN_SH)).unwrap();
        assert!(
            lab_ci_job_violations(".github/workflows/ci.yml", &ci, LAB_RUN_SH, &run_sh).is_empty()
        );
    }

    // --- AC-7.7 to AC-7.10. ---
    //
    // Every test below removes something from a fixture that is otherwise
    // clean and asserts the removal is what is reported. A checker whose
    // tests only feed it the real repository passes just as happily when its
    // predicate is `true`.

    /// The bound exists to keep the fuzz job's eventual failure a bug rather
    /// than a corpus. Both halves are asserted, at the boundary: a check
    /// with only one live conjunct is a check with a dead one.
    #[test]
    fn a_corpus_is_minimised_by_count_or_by_size_and_not_before() {
        assert!(!corpus_needs_minimisation(20_000, 256 * 1024 * 1024));
        assert!(corpus_needs_minimisation(20_001, 0));
        assert!(corpus_needs_minimisation(0, 256 * 1024 * 1024 + 1));
        // This repository's largest measured corpus after several full runs
        // (`manifest`: 9,642 files, 38 MB) is well inside both, so an
        // ordinary run pays nothing.
        assert!(!corpus_needs_minimisation(9_642, 38 * 1024 * 1024));
    }

    /// A workspace-scoped scratch directory, removed and recreated so a
    /// previous run cannot leave a file that makes a check pass.
    fn scratch(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("bathy-xtask-fuzz-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// A tree that satisfies every non-CI half of `fuzz_violations`.
    fn clean_fuzz_tree(root: &Path) {
        std::fs::create_dir_all(root.join("fuzz/fuzz_targets")).unwrap();
        for surface in FUZZ_SURFACES.iter().filter(|s| s.deferred.is_none()) {
            std::fs::write(
                root.join(format!("fuzz/fuzz_targets/{}.rs", surface.name)),
                // The three fragments AC-7.9 is about, present verbatim, and
                // the flag naming AC-7.8 needs, above the loop where it
                // belongs.
                "let rules = rule_ids();\n\
                 for i in &out {\n\
                 assert!(i.matched_span.start <= i.matched_span.end);\n\
                 assert!(i.matched_span.end <= capture.response.len());\n\
                 let m = &capture.response[i.matched_span.clone()];\n\
                 }\n",
            )
            .unwrap();
            let seeds = root.join("fuzz/seeds").join(surface.name);
            std::fs::create_dir_all(&seeds).unwrap();
            std::fs::write(seeds.join("seed.bin"), b"seed").unwrap();
        }
    }

    fn clean_fuzz_manifest() -> String {
        let mut manifest = String::from("[workspace]\n[package]\nname = \"bathy-fuzz\"\n");
        for surface in FUZZ_SURFACES.iter().filter(|s| s.deferred.is_none()) {
            manifest.push_str(&format!(
                "\n[[bin]]\nname = \"{}\"\npath = \"fuzz_targets/{}.rs\"\n",
                surface.name, surface.name
            ));
        }
        manifest
    }

    const CLEAN_FUZZ_CI: &str = "\
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: cargo run -p xtask -- check-fuzz-crate
  fuzz:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/cache@v4
        with:
          path: fuzz/corpus
      - run: cargo run -p xtask -- fuzz --time 60
  other:
    runs-on: ubuntu-latest
";

    #[test]
    fn the_fuzz_registry_is_not_empty_and_names_every_surface_the_plan_does() {
        assert_eq!(
            FUZZ_SURFACES.len(),
            6,
            "AC-7.7 names five surfaces -- interpretation, event-log parsing, canonical \
             JSON, manifest loading and the packetd IPC protocol -- and the M7 Task 2 \
             review named a sixth the criterion's own wording covers and the list had \
             missed: the MCP stdio boundary"
        );
        let names: Vec<&str> = FUZZ_SURFACES.iter().map(|s| s.name).collect();
        assert_eq!(
            names,
            vec![
                "interpret",
                "event_log",
                "canonical_json",
                "manifest",
                "ipc",
                "mcp_stdio"
            ]
        );
        assert!(
            FUZZ_SURFACES.iter().all(|s| !s.parser.is_empty()),
            "a surface with no named parser is a row nobody can act on"
        );
    }

    #[test]
    fn the_fixture_this_sections_tests_mutate_is_clean_to_begin_with() {
        // Without this, every assertion below could be reporting the
        // fixture's own defects and would pass for the wrong reason.
        let root = scratch("clean");
        clean_fuzz_tree(&root);
        let v = fuzz_violations(&root, &clean_fuzz_manifest(), "ci.yml", CLEAN_FUZZ_CI);
        assert!(v.is_empty(), "{v:#?}");
    }

    #[test]
    fn a_missing_target_source_is_reported_against_the_surface_it_leaves_unfuzzed() {
        let root = scratch("missing-target");
        clean_fuzz_tree(&root);
        std::fs::remove_file(root.join("fuzz/fuzz_targets/event_log.rs")).unwrap();
        let v = fuzz_violations(&root, &clean_fuzz_manifest(), "ci.yml", CLEAN_FUZZ_CI);
        assert_eq!(v.len(), 1, "{v:#?}");
        assert!(v[0].contains("event_log.rs is missing"), "{}", v[0]);
        assert!(v[0].contains("AC-7.7"), "{}", v[0]);
    }

    #[test]
    fn a_target_with_no_seed_inputs_is_reported() {
        // The whole point of AC-7.8 being 120 seconds is that the target
        // reaches the parser in 120 seconds. From random bytes it does not.
        let root = scratch("no-seeds");
        clean_fuzz_tree(&root);
        std::fs::remove_file(root.join("fuzz/seeds/interpret/seed.bin")).unwrap();
        let v = fuzz_violations(&root, &clean_fuzz_manifest(), "ci.yml", CLEAN_FUZZ_CI);
        assert_eq!(v.len(), 1, "{v:#?}");
        assert!(v[0].contains("fuzz/seeds/interpret/"), "{}", v[0]);
    }

    #[test]
    fn a_target_source_that_no_bin_declares_is_reported() {
        let root = scratch("undeclared");
        clean_fuzz_tree(&root);
        let manifest = clean_fuzz_manifest().replace("name = \"manifest\"", "name = \"other\"");
        let v = fuzz_violations(&root, &manifest, "ci.yml", CLEAN_FUZZ_CI);
        // Two complaints, and both are real: `manifest` has no `[[bin]]`, and
        // `other` is a `[[bin]]` no registry entry names.
        assert_eq!(v.len(), 2, "{v:#?}");
        assert!(
            v.iter().any(|m| m.contains("declares no `[[bin]]")),
            "{v:#?}"
        );
        assert!(v.iter().any(|m| m.contains("`other`")), "{v:#?}");
    }

    #[test]
    fn a_fuzz_package_that_joins_the_root_workspace_is_reported() {
        let root = scratch("no-workspace");
        clean_fuzz_tree(&root);
        let manifest = clean_fuzz_manifest().replace("[workspace]\n", "");
        let v = fuzz_violations(&root, &manifest, "ci.yml", CLEAN_FUZZ_CI);
        assert_eq!(v.len(), 1, "{v:#?}");
        assert!(v[0].contains("nightly"), "{}", v[0]);
    }

    #[test]
    fn removing_any_of_the_three_span_assertions_is_reported_separately() {
        // AC-7.9 is the criterion whose subject is a line of test code, so
        // this is the check that the line is still there. Each fragment is
        // removed on its own: a check that only fires when all three go is a
        // check that misses the realistic edit.
        for fragment in [
            "i.matched_span.end <= capture.response.len()",
            "i.matched_span.start <= i.matched_span.end",
            "&capture.response[i.matched_span.clone()]",
        ] {
            let root = scratch("span");
            clean_fuzz_tree(&root);
            let path = root.join("fuzz/fuzz_targets/interpret.rs");
            let weakened = std::fs::read_to_string(&path)
                .unwrap()
                .replace(fragment, "true");
            std::fs::write(&path, weakened).unwrap();
            let v = fuzz_violations(&root, &clean_fuzz_manifest(), "ci.yml", CLEAN_FUZZ_CI);
            assert_eq!(v.len(), 1, "removing `{fragment}` produced {v:#?}");
            assert!(v[0].contains("AC-7.9"), "{}", v[0]);
        }
    }

    /// The counter that goes quiet in the one case it exists for. Both
    /// failures are checked, and they are different failures: deleting the
    /// call, and putting it back where it was -- inside the match loop, where
    /// an execution that matched nothing never reaches it, `flag_labels`
    /// stays empty and `Stats::report` drops the whole `reached=` clause.
    #[test]
    fn naming_the_rules_only_inside_the_match_loop_is_reported() {
        let root = scratch("reached");
        clean_fuzz_tree(&root);
        let path = root.join("fuzz/fuzz_targets/interpret.rs");
        let clean = std::fs::read_to_string(&path).unwrap();

        std::fs::write(&path, clean.replace(INTERPRET_NAMES_THE_RULES, "")).unwrap();
        let v = fuzz_violations(&root, &clean_fuzz_manifest(), "ci.yml", CLEAN_FUZZ_CI);
        assert_eq!(v.len(), 1, "{v:#?}");
        assert!(v[0].contains("reached=0/13"), "{}", v[0]);

        let inside = clean.replace(INTERPRET_NAMES_THE_RULES, "").replace(
            "for i in &out {",
            &format!("for i in &out {{\n{INTERPRET_NAMES_THE_RULES}"),
        );
        std::fs::write(&path, &inside).unwrap();
        assert!(
            inside.contains(INTERPRET_NAMES_THE_RULES),
            "the call is still in the file, which is the point"
        );
        let v = fuzz_violations(&root, &clean_fuzz_manifest(), "ci.yml", CLEAN_FUZZ_CI);
        assert_eq!(v.len(), 1, "{v:#?}");
        assert!(
            v[0].contains("only \\\n") || v[0].contains("only"),
            "{}",
            v[0]
        );
        assert!(v[0].contains("Hoist it"), "{}", v[0]);
    }

    /// ...and the comment that explains the hoist quotes the loop it must sit
    /// above, so the check reads code and not prose. This is the third time
    /// in this file that a gate's own documentation could satisfy or break
    /// the gate.
    #[test]
    fn a_comment_quoting_the_loop_does_not_decide_where_the_call_is() {
        let root = scratch("reached-comment");
        clean_fuzz_tree(&root);
        let path = root.join("fuzz/fuzz_targets/interpret.rs");
        let clean = std::fs::read_to_string(&path).unwrap();
        std::fs::write(
            &path,
            format!("// hoisted above `for i in &out` on purpose\n{clean}"),
        )
        .unwrap();
        let v = fuzz_violations(&root, &clean_fuzz_manifest(), "ci.yml", CLEAN_FUZZ_CI);
        assert!(v.is_empty(), "{v:#?}");
    }

    #[test]
    fn a_workflow_that_never_runs_the_targets_is_reported() {
        let ci = CLEAN_FUZZ_CI.replace("- run: cargo run -p xtask -- fuzz --time 60", "");
        let v = fuzz_ci_job_violations("ci.yml", &ci);
        assert_eq!(v.len(), 1, "{v:#?}");
        assert!(v[0].contains("AC-7.10"), "{}", v[0]);
    }

    #[test]
    fn a_workflow_that_does_not_cache_the_corpus_is_reported() {
        let ci = CLEAN_FUZZ_CI.replace("          path: fuzz/corpus\n", "");
        let v = fuzz_ci_job_violations("ci.yml", &ci);
        assert_eq!(v.len(), 1, "{v:#?}");
        assert!(v[0].contains("cached corpus"), "{}", v[0]);
    }

    /// The review's reproduction, made permanent. Both of these assertions
    /// were file-scoped: moving the run step into the schedule-gated
    /// `lab-conformance` job left `check-fuzz` and `check-ci` green while the
    /// targets never ran on a pull request -- which is the literal text of
    /// AC-7.10 and the exact thing the job-level `if:` check was written to
    /// prevent. The `if:` check guarded the job it could see; nothing guarded
    /// the step being somewhere else.
    #[test]
    fn a_fuzz_run_step_in_a_neighbouring_job_is_reported() {
        let ci = CLEAN_FUZZ_CI
            .replace("      - run: cargo run -p xtask -- fuzz --time 60\n", "")
            .replace(
                "  other:\n    runs-on: ubuntu-latest\n",
                "  other:\n    if: github.event_name == 'schedule'\n    runs-on: ubuntu-latest\n\
                 \x20   steps:\n      - run: cargo run -p xtask -- fuzz --time 600\n",
            );
        assert!(
            ci.contains("run: cargo run -p xtask -- fuzz"),
            "the step is still in the file, which is the whole point of this test"
        );
        let v = fuzz_ci_job_violations("ci.yml", &ci);
        assert_eq!(v.len(), 1, "{v:#?}");
        assert!(v[0].contains("in the `fuzz` job"), "{}", v[0]);
        assert!(
            v[0].contains("another job"),
            "it must say where the step went: {}",
            v[0]
        );
    }

    /// The same hole for the cache: a cache step in the fast job restores
    /// nothing into the job that fuzzes, and the reported line still said
    /// "corpus cached in CI".
    #[test]
    fn a_corpus_cache_in_a_neighbouring_job_is_reported() {
        let ci = CLEAN_FUZZ_CI
            .replace(
                "      - uses: actions/cache@v4\n        with:\n          path: fuzz/corpus\n",
                "",
            )
            .replace(
                "  other:\n    runs-on: ubuntu-latest\n",
                "  other:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/cache@v4\n\
                 \x20       with:\n          path: fuzz/corpus\n",
            );
        assert!(ci.contains("path: fuzz/corpus"), "still in the file");
        assert!(ci.contains("actions/cache@v4"), "still in the file");
        let v = fuzz_ci_job_violations("ci.yml", &ci);
        assert_eq!(v.len(), 1, "{v:#?}");
        assert!(v[0].contains("the `fuzz` job does not cache"), "{}", v[0]);
    }

    /// The half of that check which "the whole step moved" cannot pin. The
    /// fuzz job keeps *a* cache — of the cargo registry, which is the
    /// realistic edit — and only the corpus path ends up next door, so
    /// `actions/cache@` is present in the block either way and the corpus
    /// path is the only thing job-scoping decides. A check whose two
    /// conjuncts are only ever tested together passes with one of them
    /// weakened, which is the three-fragment lesson from AC-7.9.
    #[test]
    fn a_cache_of_something_other_than_the_corpus_does_not_satisfy_the_corpus_check() {
        let ci = CLEAN_FUZZ_CI
            .replace(
                "          path: fuzz/corpus\n",
                "          path: ~/.cargo/registry\n",
            )
            .replace(
                "  other:\n    runs-on: ubuntu-latest\n",
                "  other:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/cache@v4\n\
                 \x20       with:\n          path: fuzz/corpus\n",
            );
        let v = fuzz_ci_job_violations("ci.yml", &ci);
        assert_eq!(v.len(), 1, "{v:#?}");
        assert!(v[0].contains("does not cache `fuzz/corpus`"), "{}", v[0]);
    }

    /// And the other half of the same conjunction: the corpus is named in
    /// this job, an `actions/cache@` is in this job, and they are not the
    /// same step -- so nothing is cached and a line-scan check says
    /// otherwise.
    #[test]
    fn a_corpus_named_in_a_different_step_from_the_cache_action_is_not_a_cache() {
        let ci = CLEAN_FUZZ_CI.replace(
            "          path: fuzz/corpus\n",
            "          path: ~/.cargo/registry\n      - run: ls fuzz/corpus\n",
        );
        assert!(ci.contains("actions/cache@v4"), "still in the job");
        assert!(ci.contains("fuzz/corpus"), "still in the job");
        let v = fuzz_ci_job_violations("ci.yml", &ci);
        assert_eq!(v.len(), 1, "{v:#?}");
        assert!(v[0].contains("does not cache `fuzz/corpus`"), "{}", v[0]);
    }

    /// `job_block` decides the scope of every job-scoped assertion above, so
    /// what ends a block has to be a job header and not merely a line that
    /// looks like one. `ci.yml`'s own inter-job prose is two-space indented
    /// and runs to paragraphs; a comment ending in a colon that truncated the
    /// block would make every check inside it pass by seeing less.
    #[test]
    fn a_two_space_comment_ending_in_a_colon_does_not_end_a_job() {
        let ci = "\
jobs:
  fuzz:
    runs-on: ubuntu-latest
  # WHY THE CORPUS IS CACHED:
  # because a cold 60-second run is a smoke test wearing a fuzzer's name.
  #cache:
    steps:
      - uses: actions/cache@v4
        with:
          path: fuzz/corpus
      - run: cargo run -p xtask -- fuzz --time 60
  other:
    runs-on: ubuntu-latest
";
        let block = job_block(ci, "fuzz").expect("the fuzz job is there");
        assert!(
            block.contains("cargo run -p xtask -- fuzz"),
            "the comment truncated the block: {block}"
        );
        assert!(!block.contains("other:"), "the block ran into the next job");
        assert!(fuzz_ci_job_violations("ci.yml", ci).is_empty());
    }

    #[test]
    fn a_fuzz_job_gated_by_a_condition_is_reported() {
        // The realistic mistake: copying `lab-conformance`'s `if:`, which is
        // correct there and would silently take fuzzing off every pull
        // request here.
        let ci = CLEAN_FUZZ_CI.replace(
            "  fuzz:\n    runs-on",
            "  fuzz:\n    if: github.event_name == 'schedule'\n    runs-on",
        );
        let v = fuzz_ci_job_violations("ci.yml", &ci);
        assert_eq!(v.len(), 1, "{v:#?}");
        assert!(v[0].contains("pull request"), "{}", v[0]);
    }

    /// `fuzz/`'s own fmt, clippy and unit tests are ~900 lines outside every
    /// root gate. Their only defence before this was a sentence in
    /// `fuzz/README.md`; the defence now is a step, and the step has a check.
    #[test]
    fn a_workflow_that_does_not_gate_the_fuzz_crate_itself_is_reported() {
        let ci = CLEAN_FUZZ_CI.replace("      - run: cargo run -p xtask -- check-fuzz-crate\n", "");
        let v = fuzz_crate_gate_violations("ci.yml", &ci);
        assert_eq!(v.len(), 1, "{v:#?}");
        assert!(v[0].contains("cargo fmt --all"), "{}", v[0]);
    }

    /// And in the fast job, not wherever. In the schedule-gated job it is a
    /// lint that does not run on the pull request that breaks it -- the same
    /// hole as the fuzz run step's, one gate over.
    #[test]
    fn a_fuzz_crate_gate_in_a_neighbouring_job_is_reported() {
        let ci = CLEAN_FUZZ_CI
            .replace("      - run: cargo run -p xtask -- check-fuzz-crate\n", "")
            .replace(
                "  other:\n    runs-on: ubuntu-latest\n",
                "  other:\n    if: github.event_name == 'schedule'\n    runs-on: ubuntu-latest\n\
                 \x20   steps:\n      - run: cargo run -p xtask -- check-fuzz-crate\n",
            );
        assert!(ci.contains("check-fuzz-crate"), "still in the file");
        let v = fuzz_crate_gate_violations("ci.yml", &ci);
        assert_eq!(v.len(), 1, "{v:#?}");
        assert!(v[0].contains(FAST_CI_JOB), "{}", v[0]);
    }

    #[test]
    fn a_workflow_with_no_fuzz_job_at_all_is_reported() {
        let v = fuzz_ci_job_violations("ci.yml", "jobs:\n  test:\n    runs-on: ubuntu-latest\n");
        assert!(v.iter().any(|m| m.contains("no `fuzz:` job")), "{v:#?}");
    }

    /// The sixth surface's deferral, in both directions. The trigger is the
    /// blocker itself -- `classify`'s visibility -- because a deferral whose
    /// condition is "when someone remembers" is a note, and this repository
    /// has three recorded recurrences of exactly that.
    #[test]
    fn the_mcp_deferral_fires_when_classify_becomes_reachable_and_when_the_target_lands() {
        let root = scratch("mcp-stdio");
        std::fs::create_dir_all(root.join("crates/bathy-mcp/src")).unwrap();
        let lifecycle = root.join(MCP_LIFECYCLE);

        // As shipped: `pub(crate)`, no target. Registered and silent.
        std::fs::write(
            &lifecycle,
            "pub(crate) fn classify(message: &ClientJsonRpcMessage) -> Opener {}\n",
        )
        .unwrap();
        assert!(mcp_stdio_deferral_violations(&root).is_empty());

        // The blocker goes: the target is due, and it says why without
        // anyone having to remember AC-7.7.
        std::fs::write(
            &lifecycle,
            "pub fn classify(message: &ClientJsonRpcMessage) -> Opener {}\n",
        )
        .unwrap();
        let due = mcp_stdio_deferral_violations(&root);
        assert_eq!(due.len(), 1, "{due:#?}");
        assert!(due[0].contains(MCP_STDIO_FUZZ_TARGET), "{}", due[0]);

        // The target lands: the deferral reports ITSELF stale, so a
        // discharged obligation does not stay on the books reading as
        // coverage.
        std::fs::create_dir_all(root.join("fuzz/fuzz_targets")).unwrap();
        std::fs::write(
            root.join(MCP_STDIO_FUZZ_TARGET),
            "fuzz_target!(|_: &[u8]| {});",
        )
        .unwrap();
        let stale = mcp_stdio_deferral_violations(&root);
        assert!(
            stale.iter().any(|m| m.contains("still marked `deferred`")),
            "{stale:#?}"
        );
    }

    #[test]
    fn the_packetd_deferral_fires_when_the_crate_lands_and_reports_itself_stale_when_the_target_does()
     {
        let root = scratch("packetd");
        // Neither present: the deferral is registered and silent.
        assert!(packetd_ipc_deferral_violations(&root).is_empty());

        // The crate lands. The obligation is now due, and it says so without
        // anyone having to remember AC-7.7.
        std::fs::create_dir_all(root.join(PACKETD_CRATE)).unwrap();
        std::fs::write(root.join(PACKETD_CRATE).join("Cargo.toml"), "[package]\n").unwrap();
        let due = packetd_ipc_deferral_violations(&root);
        assert_eq!(due.len(), 1, "{due:#?}");
        assert!(due[0].contains(IPC_FUZZ_TARGET), "{}", due[0]);

        // The target lands too. Now the deferral is the thing that is stale,
        // and it reports itself rather than sitting on the books as coverage.
        std::fs::create_dir_all(root.join("fuzz/fuzz_targets")).unwrap();
        std::fs::write(root.join(IPC_FUZZ_TARGET), "#![no_main]\n").unwrap();
        let stale = packetd_ipc_deferral_violations(&root);
        assert_eq!(stale.len(), 1, "{stale:#?}");
        assert!(stale[0].contains("still marked `deferred`"), "{}", stale[0]);
    }

    #[test]
    fn fuzz_bin_targets_reads_names_only_from_bin_tables() {
        let names = fuzz_bin_targets(
            "[package]\nname = \"bathy-fuzz\"\n\n[[bin]]\nname = \"a\"\n\n\
             [dependencies]\nname = \"not-a-bin\"\n\n[[bin]]\nname = \"b\"\n",
        );
        assert_eq!(names, vec!["a", "b"]);
    }

    #[test]
    fn the_fuzz_invocation_puts_the_writable_corpus_before_the_committed_seeds() {
        // libFuzzer writes new inputs into the FIRST corpus directory only.
        // Reversing these two would have every local run write into
        // `fuzz/seeds/`, which is committed -- so the tree would go dirty on
        // every run and the seed set would stop being a curated one.
        let args = fuzz_command("interpret", 60);
        let corpus = args
            .iter()
            .position(|a| a == "fuzz/corpus/interpret")
            .unwrap();
        let seeds = args
            .iter()
            .position(|a| a == "fuzz/seeds/interpret")
            .unwrap();
        assert!(corpus < seeds, "{args:?}");
        assert!(args.contains(&"-max_total_time=60".to_string()), "{args:?}");
        assert_eq!(args.first().map(String::as_str), Some("+nightly"));
    }

    #[test]
    fn this_repositorys_fuzzing_surface_is_complete() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let manifest = std::fs::read_to_string(root.join(FUZZ_MANIFEST)).unwrap();
        let ci = std::fs::read_to_string(root.join(".github/workflows/ci.yml")).unwrap();
        let v = fuzz_violations(&root, &manifest, ".github/workflows/ci.yml", &ci);
        assert!(v.is_empty(), "{v:#?}");
    }
}
