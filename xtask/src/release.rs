//! `check-release` and `release` — the executable form of publishing this
//! workspace to crates.io.
//!
//! # Why this is a module and not a shell step in a workflow
//!
//! crates.io publication is **irreversible**. A version cannot be unpublished,
//! only yanked, and a yanked version still occupies its number forever. That
//! makes a release the one operation in this repository where "it failed
//! halfway through" is a permanent state, so every part of it that can be
//! checked before the first upload is checked here, and every part of it that
//! can be rehearsed is rehearsed with `--dry-run`.
//!
//! It is also why the release workflow calls this rather than spelling
//! `cargo publish` eleven times in YAML. `gates::check_ci`'s rule — every CI
//! step has a local form — exists because every gate this project has lost was
//! an inline shell block. A release is a worse thing to lose that way than a
//! lint.
//!
//! # The split between [`check_release`] and [`release`]
//!
//! [`check_release`] is **offline and pure-ish**: it reads `cargo metadata` and
//! the workflow file, and it decides whether this workspace *could* be
//! published. It is a `check-*` subcommand, so `publish-check` runs it
//! automatically (see `publish::gates_to_run`) and so does CI, which means the
//! manifest defects that make a release impossible are found on an ordinary
//! push rather than on the day of the release.
//!
//! [`release`] is the part that talks to the network and to `cargo publish`.
//! It is deliberately **not** a `check-*` name: it is not a gate, it takes
//! minutes, and it must never run as a side effect of `publish-check`.
//!
//! # What was actually wrong before this existed
//!
//! Every intra-workspace dependency in this repository was a bare `path`
//! dependency with no `version`. `cargo publish` refuses that outright — "all
//! dependencies must have a version requirement specified when publishing" —
//! so every crate above `bathy-types` was unpublishable, and nothing in the
//! tree could say so. `bathy` itself is on crates.io at `0.1.0-alpha.1` only
//! because a lib-only name reservation has no dependencies to resolve.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;

type Fallible<T> = Result<T, Box<dyn std::error::Error>>;

/// The release workflow this module is the local form of.
pub const RELEASE_WORKFLOW: &str = ".github/workflows/release.yml";

/// The tag prefix a release is cut from.
pub const TAG_PREFIX: &str = "v";

/// Workspace members that are deliberately **not** published, and why.
///
/// A crate published once is a permanent name and a permanent maintenance
/// surface: the version cannot be withdrawn, and the name cannot be reused by
/// anyone, ever. A crate *not* published can be published later. The asymmetry
/// is the whole argument for keeping this list non-empty, and it is why each
/// entry has to say more than "not needed".
///
/// Checked in both directions by [`release_violations`]: an entry naming a
/// crate that is not in the workspace is reported, because an exclusion that
/// has stopped applying reads as a decision while guarding nothing — the same
/// failure `DEFERRALS` in `main.rs` is arranged to avoid.
pub const EXCLUDED_FROM_PUBLICATION: &[(&str, &str)] = &[
    (
        "xtask",
        "it is this workspace's own build tool, not a library anyone can consume. Its \
         entire surface is `check-*` gates over THIS repository's file layout, so a \
         published copy would be inert in any other tree. It already carries \
         `publish = false` in its manifest, which is what makes this entry a statement \
         of the same fact rather than the only thing enforcing it.",
    ),
    (
        "bathy-packetd",
        "the privileged helper that will hold CAP_NET_RAW. Three reasons, and the first \
         alone is sufficient: nothing depends on it (its only `bathy` edge is a \
         DEV-dependency on `bathy-types`), so no consumer of the published crates needs \
         it on the registry. It is also the one crate in the workspace that is not \
         `#![forbid(unsafe_code)]`, and its IPC line protocol is still moving -- \
         publishing it now would put a permanent, stable-looking version number on the \
         wire format of the component that runs with elevated privileges. Publishing it \
         later costs nothing; publishing it now cannot be undone.",
    ),
];

/// What this cannot decide, printed on every successful run.
///
/// Same practice as `publish::NOT_MECHANIZABLE` and `fixtures::UNCHECKABLE`:
/// the failure mode of a green check is that it gets read as a complete one,
/// and a release is the worst place in this repository for that to happen.
pub const NOT_CHECKED_HERE: &[(&str, &str)] = &[
    (
        "Whether the crates are ready to be depended on",
        "This proves the workspace CAN be published. Whether these eleven APIs should \
         carry a permanent version number is a judgement about the code, and the \
         pre-release suffix is this project's answer to it rather than a substitute for \
         asking.",
    ),
    (
        "Whether the descriptions are accurate",
        "A crates.io description is the entire first impression for a reader who arrives \
         from a search. This checks that one exists and is not empty. Nothing here reads \
         it against the crate.",
    ),
    (
        "Whether the owner intends to release",
        "A tag is one command and publication is irreversible. This module refuses a \
         great many bad releases; it cannot tell a deliberate one from a mistaken one.",
    ),
];

// ---------------------------------------------------------------------------
// The pure data model and the rules over it.
// ---------------------------------------------------------------------------

/// One workspace member, reduced to what a release decision needs.
///
/// Plain data, like `PackageInfo` in `main.rs` and `OpsLayer` beside it, so
/// every rule below can be handed a synthetic workspace. The rules are the part
/// worth testing; reading `cargo metadata` is not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Crate {
    pub name: String,
    pub version: String,
    /// `None` when the manifest has no `description`. crates.io **rejects** an
    /// upload without one, and it rejects it after the earlier crates in the
    /// order have already been published irreversibly.
    pub description: Option<String>,
    /// False when the manifest says `publish = false`.
    pub publishable: bool,
    /// Normal (`[dependencies]`) edges onto other workspace members, with the
    /// version requirement each declares, if any.
    pub workspace_deps: Vec<(String, Option<String>)>,
}

/// The order the crates must be published in, derived from the real dependency
/// graph rather than listed.
///
/// A hardcoded order is a list that rots: it is correct on the day it is
/// written and silently wrong the first time somebody adds an edge. This is a
/// topological sort of the actual `[dependencies]` edges, with `LAYERS` used
/// only to break ties so that the output is deterministic — the graph decides
/// what *must* come first, and the declared layering decides the order of
/// crates the graph leaves genuinely unordered.
///
/// Returns `Err` on a cycle. `check-deps` already makes a cycle impossible (it
/// rejects any edge that is not strictly downward in `LAYERS`), so this arm is
/// unreachable from a healthy tree — which is exactly why it returns an error
/// naming the crates rather than looping or panicking. A publication tool that
/// hangs has no result, and no result is the state most likely to be read as
/// "it did not complain".
pub fn publish_order(
    crates: &[Crate],
    layers: &[&str],
    excluded: &[&str],
) -> Result<Vec<String>, String> {
    let included: BTreeSet<&str> = crates
        .iter()
        .map(|c| c.name.as_str())
        .filter(|name| !excluded.contains(name))
        .collect();
    let rank: BTreeMap<&str, usize> = layers.iter().enumerate().map(|(i, n)| (*n, i)).collect();
    // Unranked crates sort after every ranked one, deterministically by name.
    let key = |name: &str| {
        (
            rank.get(name).copied().unwrap_or(usize::MAX),
            name.to_owned(),
        )
    };

    let mut pending: Vec<&str> = included.iter().copied().collect();
    pending.sort_by_key(|name| key(name));

    let mut done: Vec<String> = Vec::new();
    let mut placed: BTreeSet<&str> = BTreeSet::new();
    while !pending.is_empty() {
        // The first crate, in tie-break order, whose in-workspace dependencies
        // are all already placed.
        let ready = pending.iter().position(|name| {
            crates
                .iter()
                .find(|c| c.name == *name)
                .map(|c| {
                    c.workspace_deps
                        .iter()
                        .filter(|(dep, _)| included.contains(dep.as_str()))
                        .all(|(dep, _)| placed.contains(dep.as_str()))
                })
                .unwrap_or(true)
        });
        match ready {
            Some(at) => {
                let name = pending.remove(at);
                placed.insert(name);
                done.push(name.to_owned());
            }
            None => {
                return Err(format!(
                    "the workspace dependency graph has a cycle among {:?}, so no publish \
                     order exists. `check-deps` should have caught this first -- if it did \
                     not, its layer rule and this sort disagree, and that is the defect.",
                    pending
                ));
            }
        }
    }
    Ok(done)
}

/// Everything that would make a release of this workspace fail, or succeed
/// while publishing something it should not have.
///
/// Every rule here fires *before* the first irreversible upload. That is the
/// only property that matters: `cargo publish` reports a missing description on
/// crate nine of eleven, by which time eight crates are on crates.io forever.
pub fn release_violations(
    crates: &[Crate],
    order: &[String],
    layers: &[&str],
    excluded: &[(&str, &str)],
) -> Vec<String> {
    let mut found = Vec::new();
    let excluded_names: Vec<&str> = excluded.iter().map(|(name, _)| *name).collect();
    let rank: BTreeMap<&str, usize> = layers.iter().enumerate().map(|(i, n)| (*n, i)).collect();

    // An exclusion that names nothing is an exclusion that has stopped
    // applying, and it reads as a decision while guarding nothing.
    for (name, why) in excluded {
        if !crates.iter().any(|c| c.name == *name) {
            found.push(format!(
                "`{name}` is listed in EXCLUDED_FROM_PUBLICATION but is not a workspace \
                 member any more -- renamed, or removed without its exclusion. Delete the \
                 entry: an exclusion for a crate that does not exist reads as a decision \
                 and guards nothing."
            ));
        }
        if why.len() < 60 {
            found.push(format!(
                "`{name}`'s exclusion reason is {} characters. A crate not published is a \
                 crate nobody can depend on; that trade needs an argument, not a label.",
                why.len()
            ));
        }
    }

    let published: Vec<&Crate> = crates
        .iter()
        .filter(|c| !excluded_names.contains(&c.name.as_str()))
        .collect();

    if published.is_empty() {
        found.push("no crate would be published at all, so this check ranged over nothing".into());
        return found;
    }

    // Lockstep. Taken from the order's first crate rather than from a constant,
    // so there is no second place for the version to live.
    let mut versions: BTreeSet<&str> = BTreeSet::new();
    for c in &published {
        versions.insert(c.version.as_str());
    }
    if versions.len() > 1 {
        found.push(format!(
            "the crates to be published do not agree on a version: {:?}. They are released \
             in lockstep from one tag, so a tag can only mean one version -- and a library \
             released at a bare `0.1.0` beside an alpha binary promises a stability its \
             only consumer does not have. Set `[workspace.package].version` and let every \
             member say `version.workspace = true`.",
            versions
        ));
    }

    for c in &published {
        if !c.publishable {
            found.push(format!(
                "`{}` is in the publish set but its manifest says `publish = false`. \
                 `cargo publish` will refuse it. Either give it an entry in \
                 EXCLUDED_FROM_PUBLICATION with a reason, or drop the `publish = false`.",
                c.name
            ));
        }
        match &c.description {
            None => found.push(format!(
                "`{}` has no `description`. crates.io REJECTS an upload without one, and it \
                 rejects it at the upload step -- which in an ordered release is after the \
                 crates before it are already published and cannot be taken back.",
                c.name
            )),
            Some(d) if d.trim().is_empty() => found.push(format!(
                "`{}` has an empty `description`, which crates.io treats as none at all.",
                c.name
            )),
            Some(_) => {}
        }
        if !rank.contains_key(c.name.as_str()) {
            found.push(format!(
                "`{}` is published but has no rank in LAYERS, so nothing constrains where it \
                 sits in the dependency order. Add it to LAYERS or exclude it.",
                c.name
            ));
        }
        for (dep, requirement) in &c.workspace_deps {
            if requirement.is_none() {
                found.push(format!(
                    "`{}` depends on `{dep}` with a `path` and no `version`. `cargo publish` \
                     refuses this outright (\"all dependencies must have a version \
                     requirement specified when publishing\"): the published manifest has \
                     the path stripped out, so the dependency would have no way to resolve. \
                     Declare it in `[workspace.dependencies]` with both.",
                    c.name
                ));
            }
            if excluded_names.contains(&dep.as_str()) {
                found.push(format!(
                    "`{}` depends on `{dep}`, which EXCLUDED_FROM_PUBLICATION says is not \
                     published. The published crate would name a dependency that does not \
                     exist on the registry and would not build for anyone. Publish `{dep}` \
                     or drop the edge.",
                    c.name
                ));
            }
        }
    }

    // The derived order must agree with the declared layering. They are derived
    // from the same graph by different rules, so a disagreement means one of
    // them is wrong and it is worth knowing which.
    let mut previous: Option<(usize, &str)> = None;
    for name in order {
        let Some(&this) = rank.get(name.as_str()) else {
            continue;
        };
        if let Some((before, before_name)) = previous
            && this < before
        {
            found.push(format!(
                "the derived publish order puts `{name}` after `{before_name}`, but LAYERS \
                 ranks it before. The dependency graph and the declared layering disagree; \
                 `check-deps` enforces the layering, so this is the graph telling you the \
                 layering is stale."
            ));
        }
        previous = Some((this, name));
    }

    // Every member is accounted for, one way or the other. This is the rule
    // that makes a NEW crate a release decision rather than a silent default:
    // without it, a crate added tomorrow is published by accident or omitted by
    // accident, and either way nobody chose.
    for c in crates {
        if !order.contains(&c.name) && !excluded_names.contains(&c.name.as_str()) {
            found.push(format!(
                "`{}` is a workspace member that is neither in the publish order nor in \
                 EXCLUDED_FROM_PUBLICATION. Publishing a crate is permanent and not \
                 publishing one makes it undependable; that is a decision, so make it \
                 explicitly.",
                c.name
            ));
        }
    }

    found
}

/// Whether `tag` names exactly the version the workspace is at.
///
/// The check that stops the single worst mechanical release failure: a tag that
/// says one version while the manifests say another. Whichever one is wrong,
/// the number that reaches crates.io is the manifest's, and it is the tag that
/// everybody reads afterwards.
pub fn tag_violations(tag: &str, version: &str) -> Vec<String> {
    let expected = format!("{TAG_PREFIX}{version}");
    if tag == expected {
        return Vec::new();
    }
    let mut found = vec![format!(
        "the tag is `{tag}` but the workspace version is `{version}`, so the release would \
         be tagged `{tag}` and published as `{version}`. crates.io cannot be corrected \
         afterwards -- a version is unpublishable, only yankable. Expected tag: `{expected}`."
    )];
    if let Some(rest) = tag.strip_prefix(TAG_PREFIX)
        && rest == version.trim()
    {
        found.push(
            "(the two differ only in surrounding whitespace, which is almost certainly a \
             quoting problem in whatever produced the tag)"
                .into(),
        );
    }
    found
}

/// The sparse-index path crates.io serves a crate's version list at.
///
/// The rules are the registry's own: one-, two- and three-character names live
/// under `1/`, `2/` and `3/<first>/`, and everything else under
/// `<first two>/<second two>/`. Written with `chars` rather than byte ranges
/// because `str` indexing is invisible to `clippy::indexing_slicing`, and this
/// project found five production panics that way.
pub fn sparse_index_path(name: &str) -> String {
    let lower = name.to_lowercase();
    let chars: Vec<char> = lower.chars().collect();
    let take =
        |from: usize, count: usize| -> String { chars.iter().skip(from).take(count).collect() };
    match chars.len() {
        0 => String::new(),
        1 => format!("1/{lower}"),
        2 => format!("2/{lower}"),
        3 => format!("3/{}/{lower}", take(0, 1)),
        _ => format!("{}/{}/{lower}", take(0, 2), take(2, 2)),
    }
}

/// Every version of a crate the sparse index reports, from its newline-
/// delimited JSON body.
///
/// Yanked versions are included deliberately: a yanked version still occupies
/// its number and republishing it is impossible, so for the only question this
/// is asked — "can we publish this version?" — a yank changes nothing.
pub fn versions_in_index(body: &str) -> Vec<String> {
    body.lines()
        .filter(|line| !line.trim().is_empty())
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter_map(|v| {
            v.get("vers")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// The workflow file, held to the claims it makes.
// ---------------------------------------------------------------------------

/// The job blocks of a workflow file, as `(name, text)`.
///
/// Text, not YAML: `xtask` has no YAML crate and `gates.rs` reads `ci.yml` the
/// same way for the same reason. A job starts at a two-space-indented `name:`
/// key and runs to the next one.
fn job_blocks(workflow: &str) -> Vec<(String, String)> {
    let mut jobs: Vec<(String, String)> = Vec::new();
    let mut in_jobs = false;
    for line in workflow.lines() {
        if line.starts_with("jobs:") {
            in_jobs = true;
            continue;
        }
        if !in_jobs {
            continue;
        }
        let trimmed = line.trim_start();
        let indent = line.len() - trimmed.len();
        let is_job_key = indent == 2
            && !trimmed.starts_with('#')
            && trimmed.ends_with(':')
            && !trimmed.contains(' ');
        if is_job_key {
            jobs.push((trimmed.trim_end_matches(':').to_owned(), String::new()));
        } else if let Some((_, body)) = jobs.last_mut() {
            body.push_str(line);
            body.push('\n');
        }
    }
    jobs
}

/// The guard this whole module exists to keep: **nothing publishes for real
/// except on a release tag.**
///
/// `release --execute` is the only invocation that uploads. This asserts that
/// every job containing one is gated on the ref being a tag, and that the same
/// job runs `publish-check` first. Both are one line in YAML and both are one
/// line to delete, which is precisely why neither is left to review.
pub fn workflow_violations(path: &str, workflow: &str) -> Vec<String> {
    let mut found = Vec::new();
    let jobs = job_blocks(workflow);
    if jobs.is_empty() {
        found.push(format!(
            "{path}: no job block was parsed, so every check below ranged over nothing"
        ));
        return found;
    }

    let executing: Vec<&(String, String)> = jobs
        .iter()
        .filter(|(_, body)| body.contains("release --execute"))
        .collect();
    if executing.is_empty() {
        found.push(format!(
            "{path}: no job runs `release --execute`, so this workflow can never actually \
             publish. If that is deliberate the workflow is decoration; if it is not, the \
             release path has been removed."
        ));
    }
    for (name, body) in &executing {
        if !body.contains("refs/tags/") {
            found.push(format!(
                "{path}: job `{name}` runs `release --execute` -- the invocation that \
                 uploads to crates.io irreversibly -- but nothing in it restricts the run \
                 to a tag ref. Guard it with `if: startsWith(github.ref, 'refs/tags/{TAG_PREFIX}')`."
            ));
        }
        if !body.contains("publish-check") {
            found.push(format!(
                "{path}: job `{name}` publishes without running `publish-check` first. That \
                 gate is what reads the history for leaked identifiers and runs every other \
                 `check-*`; after an upload it has nothing left to protect."
            ));
        }
    }

    if !workflow.contains("release --dry-run") {
        found.push(format!(
            "{path}: nothing runs `release --dry-run`. A release workflow whose first real \
             execution is the release is the same defect class as a CI gate nobody ran."
        ));
    }

    // The dry run has to be reachable without a tag, or it is not a rehearsal.
    let rehearsing = jobs
        .iter()
        .filter(|(_, body)| body.contains("release --dry-run"))
        .any(|(_, body)| !body.contains("refs/tags/"));
    if !rehearsing {
        found.push(format!(
            "{path}: every job that runs `release --dry-run` is itself gated on a tag, so \
             the workflow is still first exercised on the day it matters."
        ));
    }

    found
}

// ---------------------------------------------------------------------------
// The world-reading half.
// ---------------------------------------------------------------------------

/// Read the workspace into [`Crate`]s.
fn read_workspace() -> Fallible<Vec<Crate>> {
    let output = Command::new("cargo")
        .args(["metadata", "--format-version", "1", "--no-deps"])
        .output()
        .map_err(|e| format!("running `cargo metadata`: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "`cargo metadata` failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )
        .into());
    }
    let meta: serde_json::Value = serde_json::from_slice(&output.stdout)?;
    let members: Vec<&str> = meta["packages"]
        .as_array()
        .ok_or("no packages in cargo metadata")?
        .iter()
        .filter_map(|p| p["name"].as_str())
        .collect();

    let mut crates = Vec::new();
    for pkg in meta["packages"].as_array().ok_or("no packages")? {
        let name = pkg["name"].as_str().ok_or("unnamed package")?.to_owned();
        let version = pkg["version"].as_str().unwrap_or_default().to_owned();
        let description = pkg["description"].as_str().map(str::to_owned);
        // `publish` is `null` when unrestricted and an array (empty for
        // `publish = false`) when restricted.
        let publishable = match pkg.get("publish") {
            None | Some(serde_json::Value::Null) => true,
            Some(serde_json::Value::Array(registries)) => !registries.is_empty(),
            Some(_) => true,
        };
        let mut workspace_deps = Vec::new();
        for dep in pkg["dependencies"].as_array().ok_or("no dependencies")? {
            let dep_name = dep["name"].as_str().unwrap_or_default();
            if !dep["kind"].is_null() || !members.contains(&dep_name) {
                continue; // dev/build edges, and edges out of the workspace
            }
            // `cargo metadata` renders a versionless path dependency's `req`
            // as `*`. That is the shape `cargo publish` refuses.
            let requirement = match dep["req"].as_str() {
                None | Some("*") => None,
                Some(req) => Some(req.to_owned()),
            };
            workspace_deps.push((dep_name.to_owned(), requirement));
        }
        crates.push(Crate {
            name,
            version,
            description,
            publishable,
            workspace_deps,
        });
    }
    crates.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(crates)
}

/// The version every publishable crate agrees on.
fn workspace_version(crates: &[Crate], excluded: &[&str]) -> Fallible<String> {
    let versions: BTreeSet<&str> = crates
        .iter()
        .filter(|c| !excluded.contains(&c.name.as_str()))
        .map(|c| c.version.as_str())
        .collect();
    match versions.len() {
        1 => Ok(versions.into_iter().next().unwrap_or_default().to_owned()),
        _ => Err(format!(
            "the publishable crates do not agree on a version: {versions:?}. \
             `check-release` reports this with the fix; nothing should publish until it does."
        )
        .into()),
    }
}

/// `check-release`: everything about a release that can be decided offline.
pub fn check_release(layers: &[&str], subcommands: &[&str]) -> Fallible<()> {
    let crates = read_workspace()?;
    let excluded: Vec<&str> = EXCLUDED_FROM_PUBLICATION
        .iter()
        .map(|(name, _)| *name)
        .collect();

    let order = publish_order(&crates, layers, &excluded)
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
    let mut violations = release_violations(&crates, &order, layers, EXCLUDED_FROM_PUBLICATION);

    let workflow_path = Path::new(".").join(RELEASE_WORKFLOW);
    match std::fs::read_to_string(&workflow_path) {
        Ok(workflow) => {
            violations.extend(workflow_violations(RELEASE_WORKFLOW, &workflow));
            // The same rule `check-ci` applies to `ci.yml`: every step has a
            // local form. Reusing the function rather than restating the rule
            // is what stops the two files drifting apart in what they demand.
            violations.extend(crate::gates::ci_steps_without_a_local_form(
                RELEASE_WORKFLOW,
                &workflow,
                subcommands,
            ));
        }
        Err(e) => violations.push(format!(
            "{RELEASE_WORKFLOW}: {e}. The release path is this file; without it the \
             publish order derived above is a plan nobody executes."
        )),
    }

    if !violations.is_empty() {
        for v in &violations {
            eprintln!("check-release: {v}");
        }
        return Err(format!("{} release-readiness violation(s)", violations.len()).into());
    }

    let version = workspace_version(&crates, &excluded)?;
    println!(
        "check-release: ok ({} crate(s) to publish at {version}, {} excluded with reasons)",
        order.len(),
        EXCLUDED_FROM_PUBLICATION.len(),
    );
    println!("  publish order: {}", order.join(" -> "));
    for (name, why) in EXCLUDED_FROM_PUBLICATION {
        println!("  excluded: {name} -- {}", first_sentence(why));
    }
    println!();
    println!(
        "check-release: {} THING(S) THIS DOES NOT DECIDE.",
        NOT_CHECKED_HERE.len()
    );
    for (what, why) in NOT_CHECKED_HERE {
        println!("  - {what}");
        println!("      {why}");
    }
    Ok(())
}

fn first_sentence(text: &str) -> String {
    text.split_once(". ")
        .map(|(head, _)| format!("{head}."))
        .unwrap_or_else(|| text.to_owned())
}

/// Ask crates.io which of `names` already have `version`.
///
/// Shells out to `curl` for the same reason the rest of `xtask` shells out to
/// `git` and `cargo`: adding an HTTP client to this workspace's dependency
/// graph to ask one question would be a worse trade than the subprocess.
fn already_published(names: &[String], version: &str) -> Fallible<Vec<String>> {
    let mut taken = Vec::new();
    for name in names {
        let url = format!("https://index.crates.io/{}", sparse_index_path(name));
        let output = Command::new("curl")
            .args([
                "--silent",
                "--show-error",
                "--fail-with-body",
                "--max-time",
                "30",
                &url,
            ])
            .output()
            .map_err(|e| format!("running `curl` for {name}: {e}"))?;
        let body = String::from_utf8_lossy(&output.stdout);
        if !output.status.success() {
            // A 404 is the ordinary answer for a crate nobody has published
            // yet, and `--fail-with-body` makes it a non-zero exit. Anything
            // else -- no network, DNS, a 5xx -- must NOT be read as "the name
            // is free", so it is only tolerated when the body is empty.
            if body.trim().is_empty() {
                continue;
            }
            return Err(format!(
                "querying the crates.io index for `{name}` failed: {}. Refusing to \
                 continue: an unanswered question about whether a version already exists \
                 is not the same as the answer `no`.",
                String::from_utf8_lossy(&output.stderr).trim()
            )
            .into());
        }
        if versions_in_index(&body).iter().any(|v| v == version) {
            taken.push(name.clone());
        }
    }
    Ok(taken)
}

/// How a `release` run was asked to behave.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReleaseMode {
    /// Upload for real. Off by default, and the workflow only turns it on
    /// inside a job gated on a tag ref.
    pub execute: bool,
    /// Skip crates whose version is already on crates.io, for resuming a
    /// release that failed partway. Never a default: without it, a rerun of a
    /// half-finished release stops with an explanation instead of guessing.
    pub resume: bool,
}

/// `release`: rehearse or perform the publication, in dependency order.
pub fn release(mode: ReleaseMode, tag: Option<&str>, layers: &[&str]) -> Fallible<()> {
    let crates = read_workspace()?;
    let excluded: Vec<&str> = EXCLUDED_FROM_PUBLICATION
        .iter()
        .map(|(name, _)| *name)
        .collect();
    let order = publish_order(&crates, layers, &excluded)
        .map_err(|e| -> Box<dyn std::error::Error> { e.into() })?;
    let version = workspace_version(&crates, &excluded)?;

    // A tag means a release is being attempted, whether or not this run
    // uploads. That is what makes the checks below conditional on the tag
    // rather than on `--execute`: the dry run's whole job is to predict the
    // real one, and a dry run that skipped them would predict a run that
    // passes when the real one would not.
    let releasing = mode.execute || tag.is_some();

    let mut refusals: Vec<String> = Vec::new();
    if let Some(tag) = tag {
        refusals.extend(tag_violations(tag, &version));
    } else if mode.execute {
        refusals.push(
            "`release --execute` was called with no `--tag`, so nothing verified that the \
             version about to be published is the version somebody tagged. Pass \
             `--tag v<version>`."
                .into(),
        );
    }

    if releasing {
        let dirty = Command::new("git")
            .args(["status", "--porcelain"])
            .output()
            .map_err(|e| format!("running `git status`: {e}"))?;
        let dirty = String::from_utf8_lossy(&dirty.stdout);
        if !dirty.trim().is_empty() {
            refusals.push(format!(
                "the working tree has uncommitted changes, so what would be uploaded is not \
                 what is committed at this tag:\n{}\n  `--allow-dirty` is deliberately \
                 never passed by this command: it is the one flag that makes an \
                 irreversible upload differ from the reviewed source.",
                dirty.trim()
            ));
        }
    }

    let mut to_publish = order.clone();
    match already_published(&order, &version) {
        Ok(taken) if !taken.is_empty() => {
            if mode.resume {
                println!(
                    "release: --resume, so {} crate(s) already at {version} are left \
                     untouched: {}",
                    taken.len(),
                    taken.join(", ")
                );
                to_publish.retain(|name| !taken.contains(name));
            } else if releasing {
                refusals.push(format!(
                    "these crate(s) are ALREADY on crates.io at {version}: {}. A version \
                     cannot be replaced, only yanked, so this release cannot proceed as it \
                     stands. Either bump `[workspace.package].version` (and retag), or -- \
                     if you are resuming a release that failed partway -- rerun with \
                     `--resume`, which skips exactly these and publishes the rest.",
                    taken.join(", ")
                ));
            } else {
                println!(
                    "release: note -- {} crate(s) are already on crates.io at {version}: {}. \
                     Not an error without a `--tag` (this is the version that was last \
                     released), but a release AT this version would be refused.",
                    taken.len(),
                    taken.join(", ")
                );
            }
        }
        Ok(_) => {}
        Err(e) if releasing => return Err(e),
        Err(e) => println!("release: note -- could not reach the crates.io index ({e})"),
    }

    if !refusals.is_empty() {
        eprintln!();
        for r in &refusals {
            eprintln!("release: {r}");
        }
        return Err(format!(
            "{} refusal(s). Nothing was published: every one of these is checked before the \
             first upload precisely because the first upload cannot be undone.",
            refusals.len()
        )
        .into());
    }

    if to_publish.is_empty() {
        println!("release: nothing left to publish at {version}");
        return Ok(());
    }

    // ONE `cargo publish` invocation naming every crate, rather than one per
    // crate. This is not a convenience: a single invocation is the only form
    // that works. Cargo builds a temporary local registry for the packages in
    // the same command, so a crate whose dependency is not yet on crates.io
    // still resolves -- which is exactly the situation a first release is in,
    // and a per-crate loop fails on crate two with "no matching package named
    // `bathy-types` found". For a real publish cargo also waits for each crate
    // to appear in the index before publishing its dependents. The order is
    // still passed explicitly, and still derived from the graph, because it is
    // what a human reads when something goes wrong.
    let mut args: Vec<String> = vec!["publish".into()];
    if !mode.execute {
        args.push("--dry-run".into());
    }
    for name in &to_publish {
        args.push("-p".into());
        args.push(name.clone());
    }

    println!();
    println!(
        "release: {} {} crate(s) at {version}",
        if mode.execute {
            "PUBLISHING"
        } else {
            "rehearsing"
        },
        to_publish.len()
    );
    println!("release: order  {}", to_publish.join(" -> "));
    println!("release: cargo {}", args.join(" "));
    println!();

    let status = Command::new("cargo")
        .args(&args)
        .status()
        .map_err(|e| format!("running `cargo publish`: {e}"))?;
    if !status.success() {
        return Err(format!(
            "`cargo {}` failed. In `--execute` mode some crates may already be published; \
             rerun with `--resume` after fixing the cause, which skips the ones that landed.",
            args.join(" ")
        )
        .into());
    }

    if mode.execute {
        println!(
            "release: published {} crate(s) at {version}",
            to_publish.len()
        );
    } else {
        println!(
            "release: dry run ok -- {} crate(s) would publish at {version}, in the order above",
            to_publish.len()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a_crate(name: &str, deps: &[(&str, Option<&str>)]) -> Crate {
        Crate {
            name: name.to_owned(),
            version: "0.1.0-alpha.2".to_owned(),
            description: Some("a description".to_owned()),
            publishable: true,
            workspace_deps: deps
                .iter()
                .map(|(d, r)| ((*d).to_owned(), r.map(str::to_owned)))
                .collect(),
        }
    }

    /// A healthy three-crate workspace, so each test below breaks exactly one
    /// thing. Without this the "catches X" tests may be catching the fixture.
    fn a_publishable_workspace() -> Vec<Crate> {
        vec![
            a_crate("bathy-types", &[]),
            a_crate("bathy-scope", &[("bathy-types", Some("0.1.0-alpha.2"))]),
            a_crate(
                "bathy",
                &[
                    ("bathy-types", Some("0.1.0-alpha.2")),
                    ("bathy-scope", Some("0.1.0-alpha.2")),
                ],
            ),
        ]
    }

    const TEST_LAYERS: &[&str] = &["bathy-types", "bathy-scope", "bathy"];

    fn violations_of(crates: &[Crate]) -> Vec<String> {
        let order = publish_order(crates, TEST_LAYERS, &[]).expect("an order");
        release_violations(crates, &order, TEST_LAYERS, &[])
    }

    #[test]
    fn the_healthy_fixture_has_no_violations() {
        let found = violations_of(&a_publishable_workspace());
        assert!(found.is_empty(), "{found:#?}");
    }

    // --- the order itself --------------------------------------------------

    #[test]
    fn a_dependency_is_always_published_before_its_dependent() {
        let order = publish_order(&a_publishable_workspace(), TEST_LAYERS, &[]).expect("an order");
        assert_eq!(order, vec!["bathy-types", "bathy-scope", "bathy"]);
    }

    /// The order comes from the GRAPH, not from `LAYERS`. Handed a layering
    /// that disagrees with the edges, the sort must still put dependencies
    /// first -- otherwise "derived from the dependency graph" is decoration and
    /// the real guarantee is a hand-kept list.
    #[test]
    fn the_order_follows_the_graph_even_when_the_layering_disagrees() {
        let crates = a_publishable_workspace();
        let backwards = &["bathy", "bathy-scope", "bathy-types"];
        let order = publish_order(&crates, backwards, &[]).expect("an order");
        let at = |name: &str| order.iter().position(|n| n == name).expect("present");
        assert!(at("bathy-types") < at("bathy-scope"), "{order:?}");
        assert!(at("bathy-scope") < at("bathy"), "{order:?}");
    }

    #[test]
    fn a_cycle_is_reported_rather_than_looping_forever() {
        let crates = vec![
            a_crate("a", &[("b", Some("1"))]),
            a_crate("b", &[("a", Some("1"))]),
        ];
        let err = publish_order(&crates, &["a", "b"], &[]).expect_err("a cycle");
        assert!(err.contains("cycle"), "{err}");
    }

    #[test]
    fn an_excluded_crate_is_left_out_of_the_order() {
        let order = publish_order(&a_publishable_workspace(), TEST_LAYERS, &["bathy-scope"])
            .expect("an order");
        assert_eq!(order, vec!["bathy-types", "bathy"]);
    }

    // --- the metadata that makes a publish possible at all -----------------

    /// The defect that made this whole workspace unpublishable: a `path`
    /// dependency with no `version`. `cargo publish` refuses outright.
    #[test]
    fn a_path_dependency_without_a_version_is_reported_by_name() {
        let mut crates = a_publishable_workspace();
        crates[1].workspace_deps = vec![("bathy-types".to_owned(), None)];
        let found = violations_of(&crates);
        assert!(
            found.iter().any(|v| v.contains("bathy-scope")
                && v.contains("bathy-types")
                && v.contains("version")),
            "{found:#?}"
        );
    }

    #[test]
    fn a_missing_description_is_reported_because_crates_io_rejects_the_upload() {
        for (index, name) in [(0, "bathy-types"), (2, "bathy")] {
            let mut crates = a_publishable_workspace();
            crates[index].description = None;
            let found = violations_of(&crates);
            assert!(
                found
                    .iter()
                    .any(|v| v.contains(name) && v.contains("description")),
                "removing `{name}`'s description produced no failure naming it: {found:#?}"
            );
        }
    }

    #[test]
    fn an_empty_description_is_not_a_description() {
        let mut crates = a_publishable_workspace();
        crates[0].description = Some("   ".to_owned());
        let found = violations_of(&crates);
        assert!(found.iter().any(|v| v.contains("empty")), "{found:#?}");
    }

    #[test]
    fn crates_that_disagree_on_a_version_are_refused() {
        let mut crates = a_publishable_workspace();
        crates[1].version = "0.2.0".to_owned();
        let found = violations_of(&crates);
        assert!(
            found
                .iter()
                .any(|v| v.contains("do not agree on a version")),
            "{found:#?}"
        );
    }

    #[test]
    fn a_publish_false_crate_in_the_publish_set_is_reported() {
        let mut crates = a_publishable_workspace();
        crates[0].publishable = false;
        let found = violations_of(&crates);
        assert!(
            found.iter().any(|v| v.contains("publish = false")),
            "{found:#?}"
        );
    }

    /// The rule that makes a NEW crate a decision. Without it a crate added
    /// tomorrow is published, or omitted, by nobody's choice.
    #[test]
    fn a_member_that_is_neither_published_nor_excluded_is_reported() {
        let crates = a_publishable_workspace();
        // An order that simply forgets one, as a stale hardcoded list would.
        let order = vec!["bathy-types".to_owned(), "bathy".to_owned()];
        let found = release_violations(&crates, &order, TEST_LAYERS, &[]);
        assert!(
            found
                .iter()
                .any(|v| v.contains("bathy-scope") && v.contains("neither")),
            "{found:#?}"
        );
    }

    #[test]
    fn depending_on_an_excluded_crate_is_reported_as_unbuildable() {
        let crates = a_publishable_workspace();
        let excluded: &[(&str, &str)] = &[(
            "bathy-scope",
            "a reason long enough to satisfy the rule that an exclusion must be argued \
             rather than merely labelled, which is what this padding is for",
        )];
        let order = publish_order(&crates, TEST_LAYERS, &["bathy-scope"]).expect("an order");
        let found = release_violations(&crates, &order, TEST_LAYERS, excluded);
        assert!(
            found
                .iter()
                .any(|v| v.contains("bathy") && v.contains("would not build")),
            "{found:#?}"
        );
    }

    #[test]
    fn an_exclusion_naming_a_crate_that_does_not_exist_is_reported() {
        let crates = a_publishable_workspace();
        let excluded: &[(&str, &str)] = &[(
            "bathy-renamed",
            "a reason long enough to satisfy the rule that an exclusion must be argued \
             rather than merely labelled, which is what this padding is for",
        )];
        let order = publish_order(&crates, TEST_LAYERS, &["bathy-renamed"]).expect("an order");
        let found = release_violations(&crates, &order, TEST_LAYERS, excluded);
        assert!(
            found.iter().any(|v| v.contains("not a workspace member")),
            "{found:#?}"
        );
    }

    /// This repository's real exclusions, held to their own rule: each must
    /// name a crate that exists and argue the case.
    #[test]
    fn the_real_exclusions_are_argued_and_not_merely_labelled() {
        assert!(!EXCLUDED_FROM_PUBLICATION.is_empty());
        for (name, why) in EXCLUDED_FROM_PUBLICATION {
            assert!(
                why.len() > 60,
                "`{name}`'s exclusion is {} characters: a crate nobody can depend on needs \
                 an argument",
                why.len()
            );
        }
    }

    // --- the tag ------------------------------------------------------------

    #[test]
    fn a_tag_that_matches_the_workspace_version_is_accepted() {
        assert!(tag_violations("v0.1.0-alpha.2", "0.1.0-alpha.2").is_empty());
    }

    #[test]
    fn a_tag_that_does_not_match_is_refused_and_names_both() {
        for (tag, version) in [
            ("v0.1.0-alpha.1", "0.1.0-alpha.2"),
            ("v0.2.0", "0.1.0-alpha.2"),
            ("0.1.0-alpha.2", "0.1.0-alpha.2"), // the `v` is not optional
            ("v0.1.0-alpha.2", "0.1.0"),
        ] {
            let found = tag_violations(tag, version);
            assert!(!found.is_empty(), "`{tag}` vs `{version}` must be refused");
            assert!(
                found[0].contains(tag) && found[0].contains(version),
                "the message must name both: {}",
                found[0]
            );
        }
    }

    // --- the crates.io index ------------------------------------------------

    #[test]
    fn the_sparse_index_path_follows_the_registrys_own_rules() {
        assert_eq!(sparse_index_path("a"), "1/a");
        assert_eq!(sparse_index_path("ab"), "2/ab");
        assert_eq!(sparse_index_path("abc"), "3/a/abc");
        assert_eq!(sparse_index_path("bathy"), "ba/th/bathy");
        assert_eq!(sparse_index_path("bathy-types"), "ba/th/bathy-types");
        // The registry lowercases; a mixed-case name must not miss.
        assert_eq!(sparse_index_path("Bathy-Types"), "ba/th/bathy-types");
    }

    #[test]
    fn versions_are_read_out_of_the_index_including_yanked_ones() {
        let body = "{\"name\":\"bathy\",\"vers\":\"0.1.0-alpha.1\",\"yanked\":false}\n\
                    {\"name\":\"bathy\",\"vers\":\"0.1.0-alpha.2\",\"yanked\":true}\n";
        let versions = versions_in_index(body);
        assert_eq!(versions, vec!["0.1.0-alpha.1", "0.1.0-alpha.2"]);
    }

    #[test]
    fn a_malformed_index_line_is_skipped_rather_than_panicking() {
        let body = "not json\n{\"vers\":\"1.0.0\"}\n\n{}\n";
        assert_eq!(versions_in_index(body), vec!["1.0.0"]);
    }

    // --- the workflow's own guards -----------------------------------------

    fn a_healthy_workflow() -> String {
        "name: release\n\
         on:\n  push:\n\
         jobs:\n\
         \x20 rehearse:\n\
         \x20   steps:\n\
         \x20     - run: cargo run -p xtask -- release --dry-run\n\
         \x20 publish:\n\
         \x20   if: startsWith(github.ref, 'refs/tags/v')\n\
         \x20   steps:\n\
         \x20     - run: cargo run -p xtask -- publish-check\n\
         \x20     - run: cargo run -p xtask -- release --execute\n"
            .to_owned()
    }

    #[test]
    fn the_healthy_workflow_fixture_passes() {
        let found = workflow_violations("release.yml", &a_healthy_workflow());
        assert!(found.is_empty(), "{found:#?}");
    }

    /// The single most dangerous one-line edit anyone could make to the
    /// workflow: deleting the tag guard, so every push publishes for real.
    #[test]
    fn an_execute_job_with_no_tag_guard_is_reported() {
        let workflow =
            a_healthy_workflow().replace("    if: startsWith(github.ref, 'refs/tags/v')\n", "");
        let found = workflow_violations("release.yml", &workflow);
        assert!(
            found.iter().any(|v| v.contains("restricts the run")),
            "{found:#?}"
        );
    }

    #[test]
    fn publishing_without_publish_check_is_reported() {
        let workflow =
            a_healthy_workflow().replace("      - run: cargo run -p xtask -- publish-check\n", "");
        let found = workflow_violations("release.yml", &workflow);
        assert!(
            found
                .iter()
                .any(|v| v.contains("without running `publish-check`")),
            "{found:#?}"
        );
    }

    #[test]
    fn a_workflow_that_never_rehearses_is_reported() {
        let workflow = a_healthy_workflow()
            .replace("      - run: cargo run -p xtask -- release --dry-run\n", "");
        let found = workflow_violations("release.yml", &workflow);
        assert!(found.iter().any(|v| v.contains("dry-run")), "{found:#?}");
    }

    /// A dry run that only ever happens on a tag is not a rehearsal: it first
    /// executes on the day it matters, which is the defect the whole
    /// `--dry-run` arrangement exists to prevent.
    #[test]
    fn a_dry_run_reachable_only_from_a_tag_is_reported() {
        let workflow = "jobs:\n\
             \x20 only-on-tags:\n\
             \x20   if: startsWith(github.ref, 'refs/tags/v')\n\
             \x20   steps:\n\
             \x20     - run: cargo run -p xtask -- release --dry-run\n\
             \x20     - run: cargo run -p xtask -- publish-check\n\
             \x20     - run: cargo run -p xtask -- release --execute\n";
        let found = workflow_violations("release.yml", workflow);
        assert!(
            found
                .iter()
                .any(|v| v.contains("first exercised on the day it matters")),
            "{found:#?}"
        );
    }

    #[test]
    fn a_workflow_with_no_parseable_jobs_says_so_rather_than_passing() {
        let found = workflow_violations("release.yml", "name: release\non:\n  push:\n");
        assert!(
            found.iter().any(|v| v.contains("ranged over nothing")),
            "{found:#?}"
        );
    }

    // --- the real workspace -------------------------------------------------

    /// The premise every claim in the report rests on: this repository's own
    /// crates really are publishable, in an order really derived from its
    /// graph. Reads the tree rather than a fixture, so it fails if somebody
    /// adds a versionless path dependency tomorrow.
    #[test]
    fn this_workspace_has_a_publish_order_and_no_release_violations() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let output = Command::new("cargo")
            .args(["metadata", "--format-version", "1", "--no-deps"])
            .current_dir(&root)
            .output()
            .expect("cargo metadata");
        assert!(output.status.success(), "cargo metadata failed");
        let meta: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("metadata json");
        let members: Vec<&str> = meta["packages"]
            .as_array()
            .expect("packages")
            .iter()
            .filter_map(|p| p["name"].as_str())
            .collect();
        let mut crates = Vec::new();
        for pkg in meta["packages"].as_array().expect("packages") {
            let publishable = !matches!(
                pkg.get("publish"),
                Some(serde_json::Value::Array(r)) if r.is_empty()
            );
            let mut workspace_deps = Vec::new();
            for dep in pkg["dependencies"].as_array().expect("dependencies") {
                let name = dep["name"].as_str().unwrap_or_default();
                if !dep["kind"].is_null() || !members.contains(&name) {
                    continue;
                }
                let requirement = match dep["req"].as_str() {
                    None | Some("*") => None,
                    Some(req) => Some(req.to_owned()),
                };
                workspace_deps.push((name.to_owned(), requirement));
            }
            crates.push(Crate {
                name: pkg["name"].as_str().expect("name").to_owned(),
                version: pkg["version"].as_str().unwrap_or_default().to_owned(),
                description: pkg["description"].as_str().map(str::to_owned),
                publishable,
                workspace_deps,
            });
        }

        let excluded: Vec<&str> = EXCLUDED_FROM_PUBLICATION
            .iter()
            .map(|(name, _)| *name)
            .collect();
        let order = publish_order(&crates, crate::LAYERS, &excluded).expect("a publish order");
        assert!(
            order.len() >= 10,
            "only {} crate(s) would publish; the parse or the exclusions are wrong: {order:?}",
            order.len()
        );
        assert_eq!(
            order.first().map(String::as_str),
            Some("bathy-types"),
            "the bottom of the layer order must publish first: {order:?}"
        );
        assert_eq!(
            order.last().map(String::as_str),
            Some("bathy"),
            "the binary crate depends on everything and must publish last: {order:?}"
        );
        let found = release_violations(&crates, &order, crate::LAYERS, EXCLUDED_FROM_PUBLICATION);
        assert!(found.is_empty(), "{found:#?}");
    }

    /// And the workflow that ships in this repository, held to the same rules
    /// as the fixtures above.
    #[test]
    fn this_repositorys_release_workflow_passes_its_own_guards() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let workflow = std::fs::read_to_string(root.join(RELEASE_WORKFLOW))
            .expect("the release workflow must exist");
        let found = workflow_violations(RELEASE_WORKFLOW, &workflow);
        assert!(found.is_empty(), "{found:#?}");
    }
}
