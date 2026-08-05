//! Two commands, because CI was red for five days and no local command could
//! have said so.
//!
//! # What actually went wrong
//!
//! Every gate in this repository is a `cargo run -p xtask -- check-<x>` that
//! reads the working tree. Not one of them reads *GitHub*, and not one of them
//! runs on *Linux*. So from 2026-08-01 the `test` job failed on 17 consecutive
//! pushes while every documented local command was green, for two reasons that
//! compound:
//!
//! 1. **The failures were Linux-only.** `many_open_probes_in_sequence_do_not_leak_the_socket`'s
//!    numeric assertion is `#[cfg(target_os = "linux")]` — on the macOS
//!    machines this is developed on it is not merely skipped at runtime, it is
//!    not compiled. The two cancellation fixtures depended on the kernel
//!    handing out ephemeral ports in ascending order, which macOS does and
//!    Linux does not. Nothing a developer could type reproduced either.
//! 2. **Nothing asserted CI's state.** Worse than "nobody looked": at the time
//!    this was found, the branch had *thirteen unpushed commits*, so even a
//!    green badge would have been green for code thirteen commits old.
//!    [`check_ci_status`] fails on that case as loudly as on an outright
//!    failure, because a stale green is the more dangerous of the two.
//!
//! [`check_ci_status`] answers "what does CI actually say about the code I am
//! sitting on". [`linux_gate`] answers "what would CI say", without pushing —
//! it runs `ci.yml`'s own `test` job steps, read out of `ci.yml` rather than
//! restated here, inside a Linux container over this working tree.

use std::path::Path;
use std::process::Command;

type Fallible<T> = Result<T, Box<dyn std::error::Error>>;

pub const CI_PATH: &str = ".github/workflows/ci.yml";

/// The Linux image `linux-gate` reproduces CI in.
///
/// `ubuntu-latest` plus `dtolnay/rust-toolchain@stable` is what the runner
/// is; `rust:1-bookworm` is the closest thing that is one `docker run` away
/// and tracks the same `stable`. It is deliberately NOT pinned to a digest:
/// this is a reproduction aid, and a stale pin here would reproduce a
/// toolchain CI stopped using.
pub const LINUX_IMAGE: &str = "rust:1-bookworm";

/// The job whose steps `linux-gate` runs. The other three jobs (`msrv`,
/// `msrv-bathy-store`, `deny`) need a specific toolchain or a specific
/// action and already have their own local forms (`check-msrv --run`,
/// `check-deny`).
pub const LINUX_GATE_JOB: &str = "test";

// ---------------------------------------------------------------------------
// `check-ci-status` — what GitHub says about the commit in front of you.
// ---------------------------------------------------------------------------

/// The one CI run this check reasons about: the newest one on this branch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LatestRun {
    pub head_sha: String,
    /// `completed`, `in_progress`, `queued`, …
    pub status: String,
    /// `success`, `failure`, `cancelled`, … Empty while still running.
    pub conclusion: String,
    pub url: String,
    pub created_at: String,
}

/// Parses `gh run list --json headSha,status,conclusion,url,createdAt`.
///
/// An empty array is not an error here — it is [`None`], which
/// [`status_violations`] reports as "this branch has never been built",
/// which is itself a finding.
pub fn parse_latest_run(json: &str) -> Result<Option<LatestRun>, String> {
    let value: serde_json::Value =
        serde_json::from_str(json).map_err(|e| format!("gh returned unparseable JSON: {e}"))?;
    let array = value
        .as_array()
        .ok_or_else(|| "gh did not return a JSON array".to_string())?;
    let Some(first) = array.first() else {
        return Ok(None);
    };
    let field = |name: &str| -> String {
        first
            .get(name)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    };
    Ok(Some(LatestRun {
        head_sha: field("headSha"),
        status: field("status"),
        conclusion: field("conclusion"),
        url: field("url"),
        created_at: field("createdAt"),
    }))
}

/// The whole verdict, as pure data: no `git`, no `gh`, no network.
///
/// `ahead_by` is how many commits local `HEAD` is ahead of the run's own
/// `head_sha` (`None` when the run's commit is not in the local history at
/// all — someone else pushed, or it was rebased away).
pub fn status_violations(
    branch: &str,
    head: &str,
    ahead_by: Option<usize>,
    run: Option<&LatestRun>,
) -> Vec<String> {
    let mut found = Vec::new();
    let Some(run) = run else {
        found.push(format!(
            "branch `{branch}` has no CI run at all. Nothing has ever built this code."
        ));
        return found;
    };
    if run.head_sha != head {
        found.push(match ahead_by {
            Some(0) => format!(
                "the newest run is for {}, HEAD is {head} — same commit count, different \
                 commit. Something was amended or force-pushed.",
                short(&run.head_sha)
            ),
            Some(n) => format!(
                "HEAD ({}) is {n} commit(s) AHEAD of the newest CI run ({}, {}). Whatever \
                 that run says, it does not say it about the code you are sitting on. This \
                 is the stale-green case: it is why 17 failing runs went unnoticed for five \
                 days while local gates passed.",
                short(head),
                short(&run.head_sha),
                run.created_at
            ),
            None => format!(
                "the newest CI run is for {}, which is not in this branch's local history. \
                 Fetch, or check you are on the branch you think you are.",
                short(&run.head_sha)
            ),
        });
    }
    if run.status != "completed" {
        found.push(format!(
            "the newest run ({}) is `{}`, not completed — no verdict yet. {}",
            short(&run.head_sha),
            run.status,
            run.url
        ));
    } else if run.conclusion != "success" {
        found.push(format!(
            "the newest run ({}, {}) concluded `{}`. {}",
            short(&run.head_sha),
            run.created_at,
            run.conclusion,
            run.url
        ));
    }
    found
}

fn short(sha: &str) -> String {
    sha.chars().take(9).collect()
}

fn capture(program: &str, args: &[&str]) -> Fallible<String> {
    let out = Command::new(program).args(args).output().map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            format!(
                "`{program}` is not installed. `check-ci-status` asks GitHub what it \
                 actually ran; that needs `gh` (`brew install gh`, then `gh auth login`) \
                 and `git`. This is the one gate in this repository that cannot be \
                 answered from the working tree alone."
            )
        } else {
            format!("running `{program}`: {e}")
        }
    })?;
    if !out.status.success() {
        return Err(format!(
            "`{program} {}` failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        )
        .into());
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

pub fn check_ci_status() -> Fallible<()> {
    let branch = capture("git", &["rev-parse", "--abbrev-ref", "HEAD"])?;
    let head = capture("git", &["rev-parse", "HEAD"])?;
    let json = capture(
        "gh",
        &[
            "run",
            "list",
            "--branch",
            &branch,
            "--limit",
            "1",
            "--json",
            "headSha,status,conclusion,url,createdAt",
        ],
    )?;
    let run = parse_latest_run(&json)?;
    // How far ahead of the run's commit we are. `git rev-list --count A..B`
    // errors when A is unknown locally, which is itself the answer (`None`).
    let ahead_by = run.as_ref().and_then(|r| {
        capture(
            "git",
            &["rev-list", "--count", &format!("{}..HEAD", r.head_sha)],
        )
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
    });
    let violations = status_violations(&branch, &head, ahead_by, run.as_ref());
    if violations.is_empty() {
        let run = run.expect("no run is itself a violation");
        println!(
            "check-ci-status: ok (branch {branch}, {} succeeded at {})",
            short(&run.head_sha),
            run.created_at
        );
        return Ok(());
    }
    for v in &violations {
        eprintln!("check-ci-status: {v}");
    }
    Err(format!("{} CI status finding(s)", violations.len()).into())
}

// ---------------------------------------------------------------------------
// `linux-gate` — CI's own test job, on Linux, over this working tree.
// ---------------------------------------------------------------------------

/// Every `run:` command in `job`, in order, read out of `ci.yml`.
///
/// Derived rather than restated: a step added to the `test` job is a step
/// `linux-gate` runs, with no second list to keep in sync. Jobs sit at
/// indent 2 (`  test:`) and steps below them, which is enough shape to find
/// without a YAML crate — the same text-not-YAML choice `check-lab` makes,
/// and for the same reason (`xtask` has no YAML dependency and this must run
/// anywhere).
pub fn job_run_steps(ci: &str, job: &str) -> Vec<String> {
    let mut steps = Vec::new();
    let mut inside = false;
    for line in ci.lines() {
        let indent = line.len() - line.trim_start().len();
        let trimmed = line.trim_start();
        if indent == 2 && trimmed.ends_with(':') && !trimmed.starts_with('#') {
            inside = trimmed.trim_end_matches(':') == job;
            continue;
        }
        if !inside {
            continue;
        }
        if let Some(rest) = trimmed
            .strip_prefix("- run:")
            .or_else(|| trimmed.strip_prefix("run:"))
        {
            steps.push(rest.trim().to_string());
        }
    }
    steps
}

/// The `docker run` argument vector, as pure data so a test can read it.
///
/// `--user` is not optional and not cosmetic. `ubuntu-latest` runs jobs as a
/// normal user; a container defaults to **root**, and root on Linux bypasses
/// the DAC write check. `scheduler::tests::a_failed_evidence_write_leaves_no_service_observed_event_that_would_have_cited_it`
/// makes `blobs/` mode `0o555` and requires the write to fail with a real
/// `EACCES` — as root it succeeds, and the test reports a defect that CI has
/// never seen. A reproduction harness that manufactures its own failures is
/// worse than none, so this pins the uid/gid to the invoking user's.
pub fn docker_argv(image: &str, repo_root: &str, uid: u32, gid: u32, script: &str) -> Vec<String> {
    vec![
        "run".into(),
        "--rm".into(),
        "--user".into(),
        format!("{uid}:{gid}"),
        "--volume".into(),
        format!("{repo_root}:/w"),
        "--workdir".into(),
        "/w".into(),
        // The host tree is macOS-built; sharing `target/` directly would
        // make cargo rebuild the world in both directions on every switch,
        // so the Linux build gets its own directory *under* `target/` --
        // already gitignored, and (unlike a named docker volume, which is
        // created root-owned) already owned by the user this runs as, which
        // is what `--user` above requires.
        "--env".into(),
        "CARGO_TARGET_DIR=/w/target/linux-gate".into(),
        "--env".into(),
        "CARGO_HOME=/w/target/linux-gate-cargo".into(),
        "--env".into(),
        "HOME=/w/target/linux-gate-home".into(),
        image.into(),
        "bash".into(),
        "-euxo".into(),
        "pipefail".into(),
        "-c".into(),
        script.into(),
    ]
}

/// The three directories the container writes into, all under `target/` and
/// all reused between runs.
///
/// They are why `linux-gate` is **not hermetic**, and naming them here is what
/// lets [`linux_gate`] say so on every run and clear them on request. The M7
/// panic-lint round hit the consequence directly: a `target/linux-gate` left
/// behind by a *mutation* build made a run fail, and the same tree passed on
/// the rerun that reused the now-repopulated directory. A gate whose result
/// depends on what the last run left behind reports on two things at once,
/// and only one of them is the working tree.
///
/// Reuse is still the default, and deliberately: a cold run is a full Linux
/// rebuild of the workspace and its dependency graph, which is minutes, and a
/// gate that costs minutes is a gate people stop running — the failure this
/// repository has measured more than once. So the cost stays low and the state
/// stops being invisible.
pub const LINUX_GATE_DIRS: &[&str] = &["linux-gate", "linux-gate-cargo", "linux-gate-home"];

pub fn linux_gate(fresh: bool) -> Fallible<()> {
    let ci = std::fs::read_to_string(Path::new(".").join(CI_PATH))
        .map_err(|e| format!("reading {CI_PATH}: {e}"))?;
    let steps = job_run_steps(&ci, LINUX_GATE_JOB);
    if steps.is_empty() {
        return Err(format!(
            "{CI_PATH} has no `run:` steps in the `{LINUX_GATE_JOB}` job, so this gate \
             would run nothing at all and report ok — the exact vacuous-pass shape this \
             repository has already been bitten by twice."
        )
        .into());
    }
    let repo_root = capture("git", &["rev-parse", "--show-toplevel"])?;
    // Not `std::os::unix::fs::MetadataExt` on a path: the invoking user is
    // what matters, and `id -u` is the answer on every platform Docker runs
    // on here.
    let uid: u32 = capture("id", &["-u"])?.parse()?;
    let gid: u32 = capture("id", &["-g"])?.parse()?;
    // Created here, on the host, so they exist owned by `uid:gid` before a
    // container that cannot create them (no root) tries to write into them.
    let mut reused = Vec::new();
    for dir in LINUX_GATE_DIRS {
        let path = Path::new(&repo_root).join("target").join(dir);
        if fresh && path.exists() {
            std::fs::remove_dir_all(&path).map_err(|e| format!("clearing target/{dir}: {e}"))?;
        } else if path.exists() {
            reused.push(*dir);
        }
        std::fs::create_dir_all(&path).map_err(|e| format!("creating target/{dir}: {e}"))?;
    }
    // Said on every run, pass or fail. See [`LINUX_GATE_DIRS`]: this gate is
    // not hermetic, and a green result over reused state is a weaker statement
    // than a green result over a cold one.
    if reused.is_empty() {
        eprintln!(
            "linux-gate: cold — nothing under target/ to reuse, so this result is over \
             this working tree and nothing else"
        );
    } else {
        eprintln!(
            "linux-gate: NOT HERMETIC — reusing {} from a previous run. A result that \
             disagrees with the last one may be about that state rather than about the \
             tree; `cargo run -p xtask -- linux-gate --fresh` clears it (minutes, not \
             seconds).",
            reused
                .iter()
                .map(|d| format!("target/{d}"))
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    let script = steps.join("\n");
    let argv = docker_argv(LINUX_IMAGE, &repo_root, uid, gid, &script);
    eprintln!(
        "linux-gate: {} step(s) from {CI_PATH}'s `{LINUX_GATE_JOB}` job, in {LINUX_IMAGE} as \
         {uid}:{gid}",
        steps.len()
    );
    for step in &steps {
        eprintln!("linux-gate:   {step}");
    }
    let status = Command::new("docker").args(&argv).status().map_err(|e| {
        if e.kind() == std::io::ErrorKind::NotFound {
            "docker is not installed or not on PATH. `linux-gate` is the only way to run \
             this repository's Linux-only assertions (the `/proc/self/fd` leak check, and \
             every test whose behaviour depends on the kernel's ephemeral-port allocation) \
             without pushing."
                .to_string()
        } else {
            format!("running docker: {e}")
        }
    })?;
    if !status.success() {
        return Err(format!(
            "linux-gate failed. This is what CI's `{LINUX_GATE_JOB}` job would say."
        )
        .into());
    }
    println!("linux-gate: ok ({} step(s) on {LINUX_IMAGE})", steps.len());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(head_sha: &str, status: &str, conclusion: &str) -> LatestRun {
        LatestRun {
            head_sha: head_sha.into(),
            status: status.into(),
            conclusion: conclusion.into(),
            url: "https://example.invalid/run/1".into(),
            created_at: "2026-08-04T14:44:18Z".into(),
        }
    }

    #[test]
    fn a_green_run_on_exactly_this_commit_is_the_only_clean_verdict() {
        let r = run("abc123", "completed", "success");
        assert!(status_violations("b", "abc123", Some(0), Some(&r)).is_empty());
    }

    #[test]
    fn a_green_run_that_is_behind_head_is_reported_because_a_stale_green_is_the_dangerous_case() {
        // The actual state this branch was found in: 13 unpushed commits, so
        // the newest run — whatever it said — said it about older code.
        let r = run("abc123", "completed", "success");
        let v = status_violations("b", "def456", Some(13), Some(&r));
        assert_eq!(v.len(), 1, "{v:?}");
        assert!(v[0].contains("13 commit(s) AHEAD"), "{v:?}");
    }

    #[test]
    fn a_failed_run_is_reported_with_its_url() {
        let r = run("abc123", "completed", "failure");
        let v = status_violations("b", "abc123", Some(0), Some(&r));
        assert_eq!(v.len(), 1, "{v:?}");
        assert!(
            v[0].contains("failure") && v[0].contains("example.invalid"),
            "{v:?}"
        );
    }

    #[test]
    fn a_run_still_in_progress_is_not_a_pass() {
        let r = run("abc123", "in_progress", "");
        let v = status_violations("b", "abc123", Some(0), Some(&r));
        assert_eq!(v.len(), 1, "{v:?}");
        assert!(v[0].contains("in_progress"), "{v:?}");
    }

    #[test]
    fn a_branch_with_no_runs_at_all_is_a_finding_not_a_pass() {
        let v = status_violations("b", "abc123", None, None);
        assert_eq!(v.len(), 1, "{v:?}");
        assert!(v[0].contains("no CI run at all"), "{v:?}");
    }

    #[test]
    fn a_run_on_a_commit_this_clone_has_never_seen_is_reported_as_such() {
        let r = run("abc123", "completed", "success");
        let v = status_violations("b", "def456", None, Some(&r));
        assert_eq!(v.len(), 1, "{v:?}");
        assert!(v[0].contains("not in this branch's local history"), "{v:?}");
    }

    #[test]
    fn ghs_json_is_parsed_and_an_empty_array_is_none_rather_than_an_error() {
        let json = r#"[{"headSha":"abc","status":"completed","conclusion":"failure",
                        "url":"u","createdAt":"t"}]"#;
        let got = parse_latest_run(json).unwrap().unwrap();
        assert_eq!(got.head_sha, "abc");
        assert_eq!(got.conclusion, "failure");
        assert_eq!(parse_latest_run("[]").unwrap(), None);
    }

    #[test]
    fn the_steps_come_from_the_named_job_only() {
        let ci = "\
name: ci
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: cargo fmt --all -- --check
      # a comment
      - run: cargo test --workspace
  deny:
    runs-on: ubuntu-latest
    steps:
      - run: something-else
";
        assert_eq!(
            job_run_steps(ci, "test"),
            vec![
                "cargo fmt --all -- --check".to_string(),
                "cargo test --workspace".to_string()
            ]
        );
        assert_eq!(
            job_run_steps(ci, "deny"),
            vec!["something-else".to_string()]
        );
        assert!(job_run_steps(ci, "nope").is_empty());
    }

    #[test]
    fn the_real_ci_files_test_job_is_what_this_gate_would_run() {
        // Reads the committed file, so a step added to the `test` job is
        // covered here without anyone remembering to update a fixture — and
        // an empty result (which `linux_gate` refuses) fails loudly.
        let ci = std::fs::read_to_string(std::path::Path::new("..").join(CI_PATH))
            .or_else(|_| std::fs::read_to_string(CI_PATH))
            .expect("the workflow file this gate derives itself from must be readable");
        let steps = job_run_steps(&ci, LINUX_GATE_JOB);
        assert!(
            steps.len() >= 3,
            "the `{LINUX_GATE_JOB}` job should have several run steps, got {steps:?}"
        );
        assert!(
            steps
                .iter()
                .any(|s| s.starts_with("cargo test --workspace")),
            "the whole point is that `cargo test --workspace` runs on Linux; got {steps:?}"
        );
    }

    #[test]
    fn the_container_never_runs_as_root_because_root_defeats_the_permission_test() {
        let argv = docker_argv("img", "/repo", 501, 20, "cargo test");
        let user = argv
            .iter()
            .position(|a| a == "--user")
            .map(|i| argv[i + 1].clone());
        assert_eq!(user, Some("501:20".to_string()));
        assert!(!argv.contains(&"--privileged".to_string()));
        assert!(argv.contains(&"/repo:/w".to_string()));
    }
}
