//! `check-readme`: the guard that should have existed three milestones ago.
//!
//! # Why this file exists
//!
//! `README.md` has been factually wrong at three consecutive milestone
//! reviews, **and twice inside the fixes for those reviews**. M3 found it
//! promising guarantees that did not exist. M4 found it telling operators
//! that probe traffic "carries no identifying payload" while eight probes
//! sent real payloads. M4's *fix* for that introduced three fresh errors in
//! the same paragraph, including an undercount of connections per port. The
//! sweep for *that* found the same connection-count error still standing in a
//! third location, in the paragraph headed "What a scanned third party sees
//! on their wire" -- the single most safety-relevant number in the document,
//! because it describes traffic other people receive.
//!
//! The structural cause is not carelessness. **Every other invariant in this
//! project is enforced by a test that dies, and this one was enforced by
//! whoever last remembered to look.** The README-asserting tests that already
//! existed cover `data/ports/README.md` and the interpret provenance corpus.
//! Nothing covered the root README.
//!
//! # The design, and the one decision that matters
//!
//! **The README states the number and this checker proves it.** The inverse
//! -- generating the prose from the tree -- was rejected: prose a generator
//! writes is prose nobody reads, and an operator skims a paragraph precisely
//! because a human wrote it to be read.
//!
//! The second decision follows from how the defect actually recurred. The
//! same number appeared in *three* places; two were corrected and one was
//! missed. So a checker anchored to marked locations would have passed the
//! commit that left the third one wrong. Every claim here is therefore
//! matched against the **whole document**, by every phrasing the document
//! uses, and *each* pattern must match at least once. A pattern that stops
//! matching is a loud failure, not silent under-coverage -- because "the
//! checker quietly covers less than it used to" is the same failure mode as
//! having no checker.
//!
//! What this cannot do is notice a claim nobody wrote a pattern for. See the
//! `NOT MECHANICALLY CHECKED` list at the bottom of this file, which is
//! deliberately written out rather than left implied: listing what stays
//! human-verified is more useful than covering the easy half and letting a
//! green check imply the rest.

use std::collections::BTreeSet;
use std::path::Path;

use regex::Regex;

/// The path is part of every failure message, and it is the only README this
/// check covers.
const README: &str = "README.md";

/// Probe id -> the protocol name `README.md` uses for it -> the module the
/// probe is implemented in.
///
/// The id column is checked for exact set equality against
/// `ProbeRegistry::standard()`, so this table cannot rot silently: adding a
/// ninth probe fails `check-readme` with the new id named, and the fix is to
/// add a row here and a protocol to the README. That is deliberate. The
/// alternative -- deriving a display name from the id by string surgery --
/// would silently produce "Postgres Startup" for `postgres-startup-v1` and
/// call the README wrong.
const PROBES: &[ProbeRow] = &[
    ProbeRow::new("http-get-v1", "HTTP", "http.rs"),
    ProbeRow::new("tls-v1", "TLS", "tls.rs"),
    ProbeRow::new("ssh-banner-v1", "SSH", "ssh.rs"),
    ProbeRow::new("smtp-banner-v1", "SMTP", "smtp.rs"),
    ProbeRow::new("dns-version-bind-v1", "DNS", "dns.rs"),
    ProbeRow::new("postgres-startup-v1", "PostgreSQL", "postgres.rs"),
    ProbeRow::new("mysql-greeting-v1", "MySQL", "mysql.rs"),
    ProbeRow::new("redis-ping-v1", "Redis", "redis.rs"),
];

struct ProbeRow {
    id: &'static str,
    protocol: &'static str,
    module: &'static str,
}

impl ProbeRow {
    const fn new(id: &'static str, protocol: &'static str, module: &'static str) -> Self {
        Self {
            id,
            protocol,
            module,
        }
    }
}

/// `xtask` may not depend on `bathy-engine` (it is a 1.95-MSRV crate and
/// `xtask` is pinned to the 1.88 tier), so the evidence caps are read out of
/// the scheduler's source rather than by calling it. Anchored on the exact
/// match arms, so a reformat that keeps the arms intact still matches and a
/// change to the numbers does not.
const SCHEDULER: &str = "crates/bathy-engine/src/scheduler.rs";

/// Everything `README.md` claims that this tree can be asked about, read out
/// of the tree.
///
/// A plain-data struct with no I/O of its own, so [`violations`] -- the rule
/// logic every test below exercises -- can be handed synthetic values.
/// Mirrors `find_violations` and `diff_or_write` in `main.rs`, which are
/// factored the same way for the same reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Truth {
    /// `ServiceDetection::default().intensity`.
    pub intensity: usize,
    /// Unique `AC-N.M` ids across `docs/superpowers/plans/*.md`.
    pub acceptance_criteria: usize,
    /// Milestone plans (every plan that is not the overview).
    pub milestones: usize,
    /// Workspace members that must each have a "What works today" row.
    pub crates: BTreeSet<String>,
    /// Protocol names, from `ProbeRegistry::standard()` via [`PROBES`].
    pub protocols: BTreeSet<String>,
    /// The subset of [`Truth::protocols`] whose probe writes no bytes.
    pub silent_protocols: BTreeSet<String>,
    /// Files under `schemas/`.
    pub committed_schemas: usize,
    /// `EvidenceLevel::Headers` / `Full` caps, in KiB.
    pub evidence_cap_headers_kib: usize,
    pub evidence_cap_full_kib: usize,
}

/// A claim stated as a number.
///
/// `patterns` is every phrasing `README.md` uses. Each must match at least
/// once and every capture must equal the expected value -- the two halves
/// that between them make "corrected in two places out of three" impossible.
struct NumberClaim {
    /// Named in the failure message.
    claim: &'static str,
    /// Where the truth comes from, so a failure can be adjudicated without
    /// reading this file.
    source: &'static str,
    expected: usize,
    patterns: &'static [&'static str],
}

/// A claim stated as a list of names (the protocol set, twice over).
struct NameSetClaim {
    claim: &'static str,
    source: &'static str,
    expected: BTreeSet<String>,
    patterns: &'static [&'static str],
}

fn number_claims(truth: &Truth) -> Vec<NumberClaim> {
    vec![
        NumberClaim {
            claim: "connections a scanned third party receives per open port",
            source: "ServiceDetection::default().intensity (crates/bathy-types/src/request.rs)",
            expected: truth.intensity,
            // Three phrasings, in three separate paragraphs. This is the
            // claim that has been wrong three times, and the third site is
            // the one two rounds of fixes both missed.
            patterns: &[
                r"`intensity` bound \((\w+) by default\)",
                r"up to `intensity` further connections — (\w+) by default",
                r"is never identified receives (\w+)\.",
            ],
        },
        NumberClaim {
            claim: "number of acceptance criteria in the plans",
            source: "unique AC-N.M ids across docs/superpowers/plans/*.md",
            expected: truth.acceptance_criteria,
            patterns: &[r"(\w+) numbered acceptance criteria"],
        },
        NumberClaim {
            claim: "number of milestones",
            source: "milestone plans under docs/superpowers/plans/ (the overview is not one)",
            expected: truth.milestones,
            patterns: &[
                r"Plans for all (\w+) milestones",
                r"Milestones 1-\d+ of (\w+) landed",
            ],
        },
        NumberClaim {
            claim: "number of protocols identified",
            source: "ProbeRegistry::standard() (crates/bathy-probe/src/framework.rs)",
            expected: truth.protocols.len(),
            patterns: &[
                r"(\w+) protocols: [A-Z]",
                r"(\w+) clean-room protocol probes",
                r"begins with (\w+) protocols",
            ],
        },
        NumberClaim {
            claim: "number of probes that put no bytes on the wire",
            source: "probe modules under crates/bathy-probe/src/probes/ that never call \
                     io.write_all",
            expected: truth.silent_protocols.len(),
            patterns: &[r"\*\*(\w+) send nothing at all\*\*"],
        },
        NumberClaim {
            claim: "number of committed schemas",
            source: "schemas/*.json",
            expected: truth.committed_schemas,
            patterns: &[r"(\w+) schemas are committed under"],
        },
        NumberClaim {
            claim: "evidence cap at EvidenceLevel::Headers, in KiB",
            source: "Scheduler's EvidenceLevel::Headers arm (crates/bathy-engine/src/scheduler.rs)",
            expected: truth.evidence_cap_headers_kib,
            patterns: &[r"\((\w+) KiB for headers"],
        },
        NumberClaim {
            claim: "evidence cap at EvidenceLevel::Full, in KiB",
            source: "Scheduler's EvidenceLevel::Full arm (crates/bathy-engine/src/scheduler.rs)",
            expected: truth.evidence_cap_full_kib,
            patterns: &[r"(\w+) KiB for full"],
        },
    ]
}

fn name_set_claims(truth: &Truth) -> Vec<NameSetClaim> {
    vec![
        NameSetClaim {
            claim: "the set of protocols identified",
            source: "ProbeRegistry::standard() (crates/bathy-probe/src/framework.rs)",
            expected: truth.protocols.clone(),
            // Compared as a set, not a sequence: the README lists these in
            // two different orders in three places, and the order is not a
            // factual claim. The membership is.
            patterns: &[
                r"\w+ protocols: ([^.]+)\.",
                r"clean-room protocol probes \(([^)]+)\)",
                r"([A-Za-z0-9]+(?:/[A-Za-z0-9]+){2,}) identification",
            ],
        },
        NameSetClaim {
            claim: "which probes put no bytes on the wire",
            source: "probe modules under crates/bathy-probe/src/probes/ that never call \
                     io.write_all",
            expected: truth.silent_protocols.clone(),
            patterns: &[r"send nothing at all\*\*: the ([A-Za-z0-9 ]+?) probes are"],
        },
    ]
}

/// Every violation, as a message that names the file, the claim, what the
/// README says, and what the tree says.
///
/// Pure: no filesystem, no subprocess. `readme` is the raw file text.
pub fn violations(readme: &str, truth: &Truth) -> Vec<String> {
    let prose = flatten(readme);
    let mut out = Vec::new();

    for claim in number_claims(truth) {
        for pattern in claim.patterns {
            let re = Regex::new(pattern).expect("checker pattern must compile");
            let mut matched = false;
            for caps in re.captures_iter(&prose) {
                matched = true;
                let text = &caps[1];
                match parse_quantity(text) {
                    Some(found) if found == claim.expected => {}
                    Some(found) => out.push(format!(
                        "{README}: the claim \"{}\" is wrong.\n  \
                         README says {found} (in: \"{}\")\n  \
                         the tree says {}\n  \
                         source of truth: {}",
                        claim.claim,
                        caps.get(0).unwrap().as_str().trim(),
                        claim.expected,
                        claim.source,
                    )),
                    None => out.push(format!(
                        "{README}: the claim \"{}\" reads \"{text}\", which is not a number.\n  \
                         in: \"{}\"\n  \
                         the tree says {}\n  source of truth: {}",
                        claim.claim,
                        caps.get(0).unwrap().as_str().trim(),
                        claim.expected,
                        claim.source,
                    )),
                }
            }
            if !matched {
                out.push(unmatched(claim.claim, pattern));
            }
        }
    }

    for claim in name_set_claims(truth) {
        for pattern in claim.patterns {
            let re = Regex::new(pattern).expect("checker pattern must compile");
            let mut matched = false;
            for caps in re.captures_iter(&prose) {
                matched = true;
                let found = parse_name_list(&caps[1]);
                if found != claim.expected {
                    let missing: Vec<&str> = claim
                        .expected
                        .difference(&found)
                        .map(String::as_str)
                        .collect();
                    let extra: Vec<&str> = found
                        .difference(&claim.expected)
                        .map(String::as_str)
                        .collect();
                    out.push(format!(
                        "{README}: the claim \"{}\" is wrong.\n  \
                         README says: {}\n  the tree says: {}\n  \
                         missing from the README: {}\n  \
                         in the README but not in the tree: {}\n  \
                         in: \"{}\"\n  source of truth: {}",
                        claim.claim,
                        join(&found),
                        join(&claim.expected),
                        if missing.is_empty() {
                            "(none)".into()
                        } else {
                            missing.join(", ")
                        },
                        if extra.is_empty() {
                            "(none)".into()
                        } else {
                            extra.join(", ")
                        },
                        caps.get(0).unwrap().as_str().trim(),
                        claim.source,
                    ));
                }
            }
            if !matched {
                out.push(unmatched(claim.claim, pattern));
            }
        }
    }

    out.extend(table_violations(readme, &truth.crates));
    out
}

/// The "What works today" table against the workspace's actual membership,
/// both directions.
///
/// A *missing* row is how `crates/bathy` went undescribed for a whole
/// milestone; an *extra* row is how a table outlives the crate it describes.
/// Neither is a formatting nit: the table is the first thing a reader uses to
/// decide what this project does.
fn table_violations(readme: &str, expected: &BTreeSet<String>) -> Vec<String> {
    // Raw lines, not the flattened prose: a table row is a line.
    let row = Regex::new(r"^\|\s*`([a-z0-9-]+)`\s*\|").expect("row pattern must compile");
    let listed: BTreeSet<String> = readme
        .lines()
        .filter_map(|line| row.captures(line))
        .map(|c| c[1].to_string())
        .collect();

    let mut out = Vec::new();
    for name in expected.difference(&listed) {
        out.push(format!(
            "{README}: the \"What works today\" table has no row for `{name}`, which is a \
             workspace member.\n  A crate with no row is how `crates/bathy` went undescribed \
             for a whole milestone.\n  source of truth: the directories under crates/, plus xtask/"
        ));
    }
    for name in listed.difference(expected) {
        out.push(format!(
            "{README}: the \"What works today\" table has a row for `{name}`, which is not a \
             workspace member.\n  source of truth: the directories under crates/, plus xtask/"
        ));
    }
    out
}

fn unmatched(claim: &str, pattern: &str) -> String {
    format!(
        "{README}: the claim \"{claim}\" is not stated anywhere the checker can see.\n  \
         pattern `{pattern}` matched nothing.\n  \
         Either the sentence was deleted -- then delete the pattern from \
         xtask/src/readme.rs too -- or it was reworded, and the pattern must follow it.\n  \
         This is a hard failure on purpose: a checker that quietly matches less than it used \
         to is how the same number stayed wrong in a third location after two were fixed."
    )
}

/// Collapse `README.md` into one line of prose so patterns are independent of
/// hard wrapping, which is how the file is written and how it will be
/// rewrapped.
///
/// Blockquote markers are stripped per line before joining. Without that, the
/// status note's `> ` prefixes land *inside* wrapped sentences -- the protocol
/// list "HTTP, TLS, SSH, SMTP,\n> DNS, ..." would flatten with a stray `>` in
/// the middle of it and every list pattern would silently stop matching.
fn flatten(readme: &str) -> String {
    let mut joined = String::new();
    for line in readme.lines() {
        let mut rest = line.trim_start();
        while let Some(stripped) = rest.strip_prefix('>') {
            rest = stripped.trim_start();
        }
        if !joined.is_empty() {
            joined.push(' ');
        }
        joined.push_str(rest.trim_end());
    }
    joined.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// A count the README states either as digits or as an English word. Both
/// forms are in use ("(4 by default)" and "four by default", one paragraph
/// apart), and pinning only the digit form would leave the word form free to
/// drift -- which is exactly the shape of the defect that recurred.
fn parse_quantity(text: &str) -> Option<usize> {
    if let Ok(n) = text.parse::<usize>() {
        return Some(n);
    }
    const WORDS: &[&str] = &[
        "zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten",
        "eleven", "twelve",
    ];
    let lowered = text.to_ascii_lowercase();
    WORDS.iter().position(|w| *w == lowered)
}

/// Split a README list of names on every separator the file actually uses:
/// commas (`HTTP, TLS, SSH`), slashes (`HTTP/TLS/SSH`), and the conjunction
/// (`the SSH and MySQL probes`).
fn parse_name_list(text: &str) -> BTreeSet<String> {
    text.split(['/', ',', ';'])
        .flat_map(|part| part.split(" and "))
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(str::to_string)
        .collect()
}

fn join(set: &BTreeSet<String>) -> String {
    set.iter().cloned().collect::<Vec<_>>().join(", ")
}

// ---------------------------------------------------------------------------
// Reading the truth out of the tree. Everything below does I/O; everything
// above is pure.
// ---------------------------------------------------------------------------

type Fallible<T> = Result<T, Box<dyn std::error::Error>>;

pub fn gather_truth(root: &Path) -> Fallible<Truth> {
    let (protocols, silent_protocols) = probe_truth(root)?;
    Ok(Truth {
        // The compiled default, not a literal re-typed here: this is the
        // number a scanned third party's connection count is governed by.
        intensity: usize::from(bathy_types::request::ServiceDetection::default().intensity),
        acceptance_criteria: count_acceptance_criteria(root)?,
        milestones: count_milestones(root)?,
        crates: workspace_members(root)?,
        protocols,
        silent_protocols,
        committed_schemas: count_files(&root.join("schemas"))?,
        evidence_cap_headers_kib: evidence_cap(root, "Headers")?,
        evidence_cap_full_kib: evidence_cap(root, "Full")?,
    })
}

/// `ProbeRegistry::standard()` is the source of truth for *which* probes
/// exist -- called, not parsed, so it is compile-checked -- and [`PROBES`]
/// supplies only the README-facing display name and the module to read for
/// wire behaviour. Set equality between the two is enforced here, so a ninth
/// probe fails loudly instead of being quietly omitted from the README's
/// count.
fn probe_truth(root: &Path) -> Fallible<(BTreeSet<String>, BTreeSet<String>)> {
    let registry = bathy_probe::ProbeRegistry::standard();
    let registered: BTreeSet<&str> = registry.all().iter().map(|p| p.id()).collect();
    let tabulated: BTreeSet<&str> = PROBES.iter().map(|p| p.id).collect();
    if registered != tabulated {
        return Err(format!(
            "check-readme's probe table is out of date with ProbeRegistry::standard().\n  \
             in the registry but not in xtask/src/readme.rs: {:?}\n  \
             in xtask/src/readme.rs but not in the registry: {:?}\n  \
             Add the probe's id, its README-facing protocol name and its module file to \
             PROBES, then state the protocol in README.md.",
            registered.difference(&tabulated).collect::<Vec<_>>(),
            tabulated.difference(&registered).collect::<Vec<_>>(),
        )
        .into());
    }

    let mut protocols = BTreeSet::new();
    let mut silent = BTreeSet::new();
    for probe in PROBES {
        protocols.insert(probe.protocol.to_string());
        let path = root
            .join("crates/bathy-probe/src/probes")
            .join(probe.module);
        let source = std::fs::read_to_string(&path)
            .map_err(|e| format!("reading {}: {e}", path.display()))?;
        // `io.write_all` is the only way a probe puts bytes on a scanned
        // host's wire (`ProbeIo` owns the socket and `execute` gets nothing
        // else). Test fixtures in the same file drive their own listener
        // through `sock.write_all`, which is why the receiver is part of the
        // needle rather than just `write_all`.
        if !source.contains("io.write_all") {
            silent.insert(probe.protocol.to_string());
        }
    }
    Ok((protocols, silent))
}

fn count_acceptance_criteria(root: &Path) -> Fallible<usize> {
    let id = Regex::new(r"\bAC-[0-9]+\.[0-9]+\b")?;
    let mut ids: BTreeSet<String> = BTreeSet::new();
    for path in plan_files(root)? {
        let text = std::fs::read_to_string(&path)?;
        for m in id.find_iter(&text) {
            ids.insert(m.as_str().to_string());
        }
    }
    if ids.is_empty() {
        return Err("no AC-N.M ids found under docs/superpowers/plans/".into());
    }
    Ok(ids.len())
}

/// Milestone plans, which is every plan that is not the overview. Counted
/// from the files rather than from the ids so that "seven milestones" and
/// "204 acceptance criteria" cannot be satisfied by the same evidence.
fn count_milestones(root: &Path) -> Fallible<usize> {
    let mut milestones: BTreeSet<String> = BTreeSet::new();
    let id = Regex::new(r"\bAC-([0-9]+)\.[0-9]+\b")?;
    for path in plan_files(root)? {
        let text = std::fs::read_to_string(&path)?;
        for caps in id.captures_iter(&text) {
            milestones.insert(caps[1].to_string());
        }
    }
    if milestones.is_empty() {
        return Err("no milestone-numbered AC ids found under docs/superpowers/plans/".into());
    }
    Ok(milestones.len())
}

fn plan_files(root: &Path) -> Fallible<Vec<std::path::PathBuf>> {
    let dir = root.join("docs/superpowers/plans");
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&dir).map_err(|e| format!("reading {}: {e}", dir.display()))? {
        let path = entry?.path();
        if path.extension().and_then(|e| e.to_str()) == Some("md") {
            out.push(path);
        }
    }
    out.sort();
    Ok(out)
}

/// Every workspace member that must have a "What works today" row: the
/// directories under `crates/` that contain a `Cargo.toml`, plus `xtask`,
/// which is a real member and is described in the table but does not live
/// under `crates/`.
fn workspace_members(root: &Path) -> Fallible<BTreeSet<String>> {
    let dir = root.join("crates");
    let mut out = BTreeSet::new();
    for entry in std::fs::read_dir(&dir).map_err(|e| format!("reading {}: {e}", dir.display()))? {
        let path = entry?.path();
        if path.join("Cargo.toml").is_file()
            && let Some(name) = path.file_name().and_then(|n| n.to_str())
        {
            out.insert(name.to_string());
        }
    }
    if root.join("xtask/Cargo.toml").is_file() {
        out.insert("xtask".to_string());
    }
    if out.is_empty() {
        return Err("no workspace members found under crates/".into());
    }
    Ok(out)
}

fn count_files(dir: &Path) -> Fallible<usize> {
    let mut n = 0;
    for entry in std::fs::read_dir(dir).map_err(|e| format!("reading {}: {e}", dir.display()))? {
        if entry?.path().is_file() {
            n += 1;
        }
    }
    Ok(n)
}

/// The `EvidenceLevel` cap the scheduler actually applies, in KiB, read from
/// its source. `xtask` sits in the 1.88 MSRV tier and `bathy-engine` is 1.95
/// (`libsqlite3-sys`'s build script), so this one number cannot be obtained by
/// calling the code that owns it without dragging `xtask` up a tier and out of
/// the `msrv` CI job. Anchored on the match arm so a reformat is tolerated and
/// a changed number is not.
fn evidence_cap(root: &Path, level: &str) -> Fallible<usize> {
    let path = root.join(SCHEDULER);
    let source =
        std::fs::read_to_string(&path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    let arm = Regex::new(&format!(r"EvidenceLevel::{level}\s*=>\s*(\d+)\s*\*\s*1024"))?;
    let caps = arm.captures(&source).ok_or_else(|| {
        format!(
            "{}: no `EvidenceLevel::{level} => N * 1024` arm found. The README states this cap \
             in KiB; either the arm moved (update the pattern in xtask/src/readme.rs) or the \
             cap is no longer expressed in KiB (update the README).",
            path.display()
        )
    })?;
    Ok(caps[1].parse::<usize>()?)
}

pub fn check_readme() -> Fallible<()> {
    let root = Path::new(".");
    let truth = gather_truth(root)?;
    let text =
        std::fs::read_to_string(root.join(README)).map_err(|e| format!("reading {README}: {e}"))?;
    let found = violations(&text, &truth);
    if found.is_empty() {
        println!(
            "check-readme: ok ({} numeric claims, {} name-set claims, {} table rows)",
            number_claims(&truth)
                .iter()
                .map(|c| c.patterns.len())
                .sum::<usize>(),
            name_set_claims(&truth)
                .iter()
                .map(|c| c.patterns.len())
                .sum::<usize>(),
            truth.crates.len(),
        );
        return Ok(());
    }
    for v in &found {
        eprintln!("check-readme: {v}\n");
    }
    Err(format!("{} README claim(s) contradict the tree", found.len()).into())
}

// ---------------------------------------------------------------------------
// NOT MECHANICALLY CHECKED -- written out deliberately.
//
// These claims in README.md have no source of truth this checker can read,
// and remain human-verified at each milestone exit per the Global Constraint.
// Listing them is the point: a green `check-readme` must not be read as "the
// README is correct", only as "these numbers agree with the tree".
//
//   - "Milestones 1-4 of 7 landed". Which milestones are *done* is a
//     judgement about acceptance, not a fact in the tree. The 7 is checked.
//   - Every guarantee sentence in the status note and "Authorized use":
//     what the scheduler checks and when, that a scan is refused in full and
//     never silently trimmed, that a mid-scan expiry does not halt a run in
//     progress, that `bathy_scope::evaluate` has no caller. Each is a
//     statement about control flow. These are the claims M3's review found
//     wrong, and they are the ones a checker helps with least.
//   - "Most carry a real request" and the named example bytes (`GET /`, a TLS
//     `ClientHello`, an `EHLO`, a Redis `PING`, a DNS `version.bind` query, a
//     PostgreSQL `SSLRequest`). The *count* of payload-free probes and *which*
//     they are is checked; that each remaining probe sends the specific thing
//     named is not.
//   - The `User-Agent` and `bathy.invalid` identification strings. Checkable
//     in principle against the probe sources; not done here, so still human.
//   - Everything in "Verified properties, not just tested ones" -- a
//     historical account of past reviews, not a property of today's tree.
//   - The eight IPv4-in-IPv6 embedding schemes and the ISATAP reasoning.
//   - "Planned scope" and "Out of scope" beyond the protocol list.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// A README that is correct with respect to [`truth`], written the way
    /// the real file is written: hard-wrapped, blockquoted in places, with
    /// each claim stated in every phrasing the real file uses. Tests mutate
    /// *this* rather than the repository's own README, so nothing here can
    /// leave the real file edited.
    fn readme() -> String {
        "\
# bathy

> A port that answers gets one or more *additional* connections, stopping at
> the first response that is recognized, up to an `intensity` bound (4 by
> default). Eight protocols: HTTP, TLS, SSH, SMTP,
> DNS, PostgreSQL, MySQL, Redis. Capped at the configured evidence level
> (8 KiB for headers, 64 KiB for full).
>
> Milestones 1-4 of 7 landed.
>
> Plans for all seven milestones — 204 numbered acceptance criteria — are in
> [`docs/superpowers/plans/`](docs/superpowers/plans/).

## What works today

| Crate | Delivers |
|---|---|
| `bathy-types` | Types. |
| `bathy-probe` | Eight clean-room protocol probes (HTTP, TLS, SSH, SMTP, DNS, PostgreSQL, MySQL, Redis) and the bounded I/O layer. |
| `xtask` | Checks. |

Four schemas are committed under [`schemas/`](schemas/) and CI fails if a type
changes without regenerating them.

**What a scanned third party sees on their wire.** A port that answers then
receives **up to `intensity` further connections — four by default** — each a
separate TCP connection carrying one protocol probe. So a port whose first
probe is recognized receives one additional connection; a port that
answers but is never identified receives four. **Two send nothing at all**:
the SSH and MySQL probes are listen-first, because those protocols have the
server speak first.

Service-identification coverage will start far below mature scanners: this
project begins with eight protocols against decades of accumulated community
fingerprint data elsewhere.

## Planned scope for v0.1

IPv4 TCP connect scanning, HTTP/TLS/SSH/DNS/SMTP/PostgreSQL/MySQL/Redis
identification, structured event output.
"
        .to_string()
    }

    fn names(list: &[&str]) -> BTreeSet<String> {
        list.iter().map(|s| s.to_string()).collect()
    }

    fn truth() -> Truth {
        Truth {
            intensity: 4,
            acceptance_criteria: 204,
            milestones: 7,
            crates: names(&["bathy-types", "bathy-probe", "xtask"]),
            protocols: names(&[
                "HTTP",
                "TLS",
                "SSH",
                "SMTP",
                "DNS",
                "PostgreSQL",
                "MySQL",
                "Redis",
            ]),
            silent_protocols: names(&["SSH", "MySQL"]),
            committed_schemas: 4,
            evidence_cap_headers_kib: 8,
            evidence_cap_full_kib: 64,
        }
    }

    /// Assert that mutating the README produces a failure that names the
    /// claim, what the README now says, and what the tree says. "Fails" is
    /// not enough: a failure a maintainer has to investigate gets the check
    /// disabled, which is how this project ends up back where it started.
    #[track_caller]
    fn fails_naming(readme: &str, claim: &str, says: &str, expected: &str) {
        let found = violations(readme, &truth());
        assert!(
            !found.is_empty(),
            "expected a violation for {claim:?}, got none"
        );
        let joined = found.join("\n");
        for needle in [claim, says, expected, README] {
            assert!(
                joined.contains(needle),
                "failure message must contain {needle:?}; got:\n{joined}"
            );
        }
    }

    #[test]
    fn a_correct_readme_produces_no_violations() {
        let found = violations(&readme(), &truth());
        assert!(
            found.is_empty(),
            "unexpected violations:\n{}",
            found.join("\n")
        );
    }

    // --- One test per pinned claim, mutating the README the way a real
    // behaviour change would leave it: the number changes and nobody updates
    // the prose. Each of these is the mutation that proves the pin is real. ---

    #[test]
    fn a_wrong_digit_connection_count_is_caught_and_named() {
        // The exact defect, three times over: the count of connections a
        // scanned third party receives per open port.
        let readme = readme().replace("(4 by\n> default)", "(5 by\n> default)");
        fails_naming(
            &readme,
            "connections a scanned third party receives per open port",
            "README says 5",
            "the tree says 4",
        );
    }

    #[test]
    fn a_wrong_word_connection_count_is_caught_in_the_wire_paragraph() {
        // The *second* site, stated as an English word rather than a digit --
        // the form a digit-only checker would have let through, in the
        // paragraph describing what other people receive.
        let readme = readme().replace("— four by default", "— three by default");
        fails_naming(
            &readme,
            "connections a scanned third party receives per open port",
            "README says 3",
            "the tree says 4",
        );
    }

    #[test]
    fn the_third_statement_of_the_connection_count_is_pinned_too() {
        // This is the site two consecutive fix rounds both missed. If the
        // checker anchored on one location, this mutation would survive.
        let readme = readme().replace(
            "never identified receives four.",
            "never identified receives two.",
        );
        fails_naming(
            &readme,
            "connections a scanned third party receives per open port",
            "README says 2",
            "the tree says 4",
        );
    }

    #[test]
    fn a_wrong_acceptance_criterion_count_is_caught_and_named() {
        let readme = readme().replace("204 numbered", "199 numbered");
        fails_naming(
            &readme,
            "number of acceptance criteria",
            "README says 199",
            "the tree says 204",
        );
    }

    #[test]
    fn a_wrong_milestone_count_is_caught_in_both_of_its_statements() {
        for (from, to, says) in [
            (
                "all seven milestones",
                "all six milestones",
                "README says 6",
            ),
            ("1-4 of 7 landed", "1-4 of 8 landed", "README says 8"),
        ] {
            fails_naming(
                &readme().replace(from, to),
                "number of milestones",
                says,
                "the tree says 7",
            );
        }
    }

    #[test]
    fn a_wrong_protocol_count_is_caught_in_each_of_its_three_statements() {
        for (from, to, says) in [
            ("Eight protocols:", "Seven protocols:", "README says 7"),
            (
                "Eight clean-room protocol probes",
                "Nine clean-room protocol probes",
                "README says 9",
            ),
            (
                "begins with eight protocols",
                "begins with six protocols",
                "README says 6",
            ),
        ] {
            fails_naming(
                &readme().replace(from, to),
                "number of protocols identified",
                says,
                "the tree says 8",
            );
        }
    }

    #[test]
    fn a_protocol_dropped_from_a_list_is_caught_and_the_missing_one_named() {
        // The list-membership half: the count can stay right while the set
        // goes wrong, and vice versa, so both are pinned.
        let readme = readme().replace(
            "MySQL, Redis) and the bounded",
            "MariaDB, Redis) and the bounded",
        );
        let found = violations(&readme, &truth());
        let joined = found.join("\n");
        assert!(
            joined.contains("the set of protocols identified"),
            "got:\n{joined}"
        );
        assert!(
            joined.contains("missing from the README: MySQL"),
            "the failure must name the protocol that went missing; got:\n{joined}"
        );
        assert!(
            joined.contains("in the README but not in the tree: MariaDB"),
            "and the one that was invented; got:\n{joined}"
        );
    }

    #[test]
    fn a_wrong_payload_free_probe_count_is_caught() {
        // "What a scanned third party sees on their wire": M4 told operators
        // probe traffic "carries no identifying payload" while eight probes
        // sent real payloads. This is the count that says how many do not.
        let readme = readme().replace(
            "**Two send nothing at all**",
            "**Three send nothing at all**",
        );
        fails_naming(
            &readme,
            "number of probes that put no bytes on the wire",
            "README says 3",
            "the tree says 2",
        );
    }

    #[test]
    fn naming_the_wrong_probes_as_payload_free_is_caught() {
        let readme = readme().replace(
            "the SSH and MySQL probes are",
            "the SSH and SMTP probes are",
        );
        let joined = violations(&readme, &truth()).join("\n");
        assert!(
            joined.contains("which probes put no bytes on the wire"),
            "got:\n{joined}"
        );
        assert!(
            joined.contains("missing from the README: MySQL"),
            "got:\n{joined}"
        );
        assert!(
            joined.contains("in the README but not in the tree: SMTP"),
            "got:\n{joined}"
        );
    }

    #[test]
    fn a_wrong_schema_count_is_caught() {
        let readme = readme().replace("Four schemas are committed", "Five schemas are committed");
        fails_naming(
            &readme,
            "number of committed schemas",
            "README says 5",
            "the tree says 4",
        );
    }

    #[test]
    fn wrong_evidence_caps_are_caught_separately() {
        fails_naming(
            &readme().replace("(8 KiB for headers", "(16 KiB for headers"),
            "evidence cap at EvidenceLevel::Headers",
            "README says 16",
            "the tree says 8",
        );
        fails_naming(
            &readme().replace("64 KiB for full", "32 KiB for full"),
            "evidence cap at EvidenceLevel::Full",
            "README says 32",
            "the tree says 64",
        );
    }

    // --- The table, both directions. ---

    #[test]
    fn a_crate_with_no_table_row_is_caught_and_named() {
        // Exactly how `crates/bathy` went undescribed for a whole milestone.
        let mut truth = truth();
        truth.crates.insert("bathy-query".into());
        let found = violations(&readme(), &truth);
        let joined = found.join("\n");
        assert!(
            joined.contains("no row for `bathy-query`"),
            "the failure must name the crate; got:\n{joined}"
        );
    }

    #[test]
    fn a_table_row_for_a_crate_that_does_not_exist_is_caught() {
        let readme = readme().replace(
            "| `xtask` | Checks. |",
            "| `xtask` | Checks. |\n| `bathy-ghost` | Nothing. |",
        );
        let joined = violations(&readme, &truth()).join("\n");
        assert!(joined.contains("row for `bathy-ghost`"), "got:\n{joined}");
    }

    // --- The guard on the guard: a claim that stops being stated must fail
    // loudly, or the checker silently covers less than it advertises. This
    // is the failure mode that let the same number stay wrong in a third
    // location after two were corrected. ---

    #[test]
    fn deleting_a_pinned_sentence_fails_rather_than_passing_vacuously() {
        let readme = readme().replace(
            "a port that\nanswers but is never identified receives four.",
            "",
        );
        let joined = violations(&readme, &truth()).join("\n");
        assert!(
            joined.contains("is not stated anywhere the checker can see"),
            "a deleted claim must fail, not pass; got:\n{joined}"
        );
        assert!(
            joined.contains("connections a scanned third party receives per open port"),
            "and must name which claim went missing; got:\n{joined}"
        );
    }

    #[test]
    fn rewording_a_claim_out_of_the_checkers_reach_fails_loudly() {
        let readme = readme().replace(
            "Four schemas are committed under",
            "There are four schemas living beneath",
        );
        let joined = violations(&readme, &truth()).join("\n");
        assert!(
            joined.contains("number of committed schemas"),
            "got:\n{joined}"
        );
        assert!(
            joined.contains("was reworded"),
            "the message must tell the maintainer what to do; got:\n{joined}"
        );
    }

    #[test]
    fn an_empty_readme_fails_every_claim_rather_than_passing() {
        let found = violations("", &truth());
        assert!(
            found.len()
                >= number_claims(&truth())
                    .iter()
                    .map(|c| c.patterns.len())
                    .sum::<usize>(),
            "an empty README must fail every pattern, got {} violations",
            found.len()
        );
    }

    // --- The parsing helpers. ---

    #[test]
    fn flatten_strips_blockquote_markers_before_joining_wrapped_lines() {
        // Without this, "SMTP,\n> DNS" flattens to "SMTP, > DNS" and every
        // list pattern silently stops matching -- the checker would be
        // decoration for the whole status note.
        let flat = flatten("> Eight protocols: HTTP, TLS, SSH, SMTP,\n> DNS, PostgreSQL.");
        assert_eq!(
            flat,
            "Eight protocols: HTTP, TLS, SSH, SMTP, DNS, PostgreSQL."
        );
    }

    #[test]
    fn quantities_parse_from_digits_and_from_english_words() {
        assert_eq!(parse_quantity("4"), Some(4));
        assert_eq!(parse_quantity("four"), Some(4));
        assert_eq!(parse_quantity("Four"), Some(4));
        assert_eq!(parse_quantity("204"), Some(204));
        assert_eq!(parse_quantity("several"), None);
    }

    #[test]
    fn name_lists_split_on_commas_slashes_and_the_conjunction() {
        assert_eq!(
            parse_name_list("HTTP, TLS, SSH"),
            names(&["HTTP", "TLS", "SSH"])
        );
        assert_eq!(
            parse_name_list("HTTP/TLS/SSH"),
            names(&["HTTP", "TLS", "SSH"])
        );
        assert_eq!(parse_name_list("SSH and MySQL"), names(&["SSH", "MySQL"]));
    }

    #[test]
    fn a_non_numeric_quantity_in_a_pinned_slot_is_reported_not_ignored() {
        let readme = readme().replace("(4 by\n> default)", "(several by\n> default)");
        let joined = violations(&readme, &truth()).join("\n");
        assert!(
            joined.contains("which is not a number"),
            "vague prose in a pinned slot must fail; got:\n{joined}"
        );
    }
}
