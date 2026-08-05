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
    /// Entries in `bathy-interpret`'s `ALL_RULES`.
    ///
    /// M7 Task 4 put this number in the README's limitations section, which
    /// makes it exactly the kind of claim the Global Constraint says must be
    /// pinned: a number with a source of truth in the tree, sitting in the
    /// paragraph a sceptical reader weighs hardest.
    pub interpretation_rules: usize,
    /// `bathy_mcp::descriptors::TOOL_NAMES`.
    ///
    /// "Eleven tools" was stated in the README from M5 onward and read by
    /// nothing. The set is pinned too, not only the count: an eleven-element
    /// list with one wrong name is the failure a count cannot see.
    pub mcp_tools: BTreeSet<String>,
    /// Files under `schemas/`.
    pub committed_schemas: usize,
    /// Files under `schemas/` whose name begins `mcp-`: the tool surface.
    pub mcp_schemas: usize,
    /// The subset of [`Truth::mcp_schemas`] that are tool *input* schemas.
    pub mcp_input_schemas: usize,
    /// The subset of [`Truth::mcp_schemas`] that are tool *output* schemas.
    /// Not equal to [`Truth::mcp_input_schemas`], and that is the point:
    /// `result.diff`'s output schema is `schemas/scan-diff.json` itself.
    pub mcp_output_schemas: usize,
    /// `EvidenceLevel::Headers` / `Full` caps, in KiB.
    pub evidence_cap_headers_kib: usize,
    pub evidence_cap_full_kib: usize,
    /// The subset of [`ABSENCE_CLAIMS`] whose falsifying path exists.
    pub falsified_absences: BTreeSet<String>,
}

/// Claims that something does **not** exist, each registered with the path
/// whose presence makes the claim false.
///
/// M5's review found `README.md` saying three times, in the commit range that
/// shipped it, that the MCP server did not exist yet -- three lines from a
/// table row describing the shipped server in detail. `check-readme` passed,
/// because it checks numbers and table membership and this is prose.
///
/// A claim of absence is the one kind of prose claim that *is* mechanically
/// checkable, because something in the tree falsifies it. So the rule is:
/// **writing one means registering the path that would make it false.** That
/// is the same discipline the `[phrase-rule]` marker uses -- the checker
/// cannot find a claim nobody registered, which is why the limitation is
/// written into the `NOT MECHANICALLY CHECKED` list at the bottom of this
/// file rather than left implied.
const ABSENCE_CLAIMS: &[AbsenceClaim] = &[
    AbsenceClaim {
        phrase: "an MCP server (the rest of Milestone 5)",
        falsified_by: "crates/bathy-mcp/src/server.rs",
    },
    AbsenceClaim {
        phrase: "The MCP server is the rest of Milestone 5.",
        falsified_by: "crates/bathy-mcp/src/server.rs",
    },
    AbsenceClaim {
        phrase: "the MCP tool names arrive with the server",
        falsified_by: "crates/bathy-mcp/src/descriptors.rs",
    },
    AbsenceClaim {
        phrase: "a packet daemon (Milestone 6)",
        falsified_by: "crates/bathy-packetd/Cargo.toml",
    },
    // `lab/Cargo.toml` until M7 Task 4, which is a path that was never going
    // to exist: the lab is a digest-pinned compose file, a ground-truth
    // document and a shell script, and it is not a crate. So this entry was
    // structurally dead -- the README asserted through the whole of M7 Tasks 1
    // to 3 that the verification suite does not exist yet, while the lab, four
    // fuzz targets and a published benchmark were all committed, and
    // `check-readme` stayed green because the falsifier could not appear.
    // A register catches a claim that GOES stale; it cannot catch one whose
    // falsifier is unreachable, which makes the *choice of path* part of the
    // entry rather than a detail. `every_falsifier_names_a_path_the_tree_can_
    // actually_produce` is the guard.
    AbsenceClaim {
        phrase: "the verification suite (Milestone 7)",
        falsified_by: "lab/docker-compose.yml",
    },
];

pub struct AbsenceClaim {
    /// Exactly as `README.md` writes it, matched against the flattened prose.
    phrase: &'static str,
    /// Relative to the repository root. If this exists, the phrase is a lie.
    falsified_by: &'static str,
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
            claim: "number of interpretation rules",
            source: "ALL_RULES (crates/bathy-interpret/src/rules.rs)",
            expected: truth.interpretation_rules,
            patterns: &[r"(\w+) interpretation rules"],
        },
        NumberClaim {
            claim: "number of MCP tools",
            source: "TOOL_NAMES (crates/bathy-mcp/src/descriptors.rs)",
            expected: truth.mcp_tools.len(),
            patterns: &[r"(\w+) typed tools"],
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
        // The three below are one sentence that the total above did not
        // cover, and the M5 whole-branch review found it wrong: "twenty-one
        // of them are the MCP tool surface: every tool's input and its
        // output" implies 11 x 2 = 22, and there are 21, because
        // `result.diff` advertises `schemas/scan-diff.json` itself rather
        // than a copy. The total was pinned; the *breakdown* of the same
        // directory was a second claim nothing read. It is three numbers
        // with a source of truth in the tree, so it is three claims here.
        NumberClaim {
            claim: "number of committed schemas that are the MCP tool surface",
            source: "schemas/mcp-*.json",
            expected: truth.mcp_schemas,
            patterns: &[r"(\w+) of them are the MCP tool surface"],
        },
        NumberClaim {
            claim: "number of committed MCP tool input schemas",
            source: "schemas/mcp-*input*.json",
            expected: truth.mcp_input_schemas,
            patterns: &[r"(\w+) tool input schemas"],
        },
        NumberClaim {
            claim: "number of committed MCP tool output schemas",
            source: "schemas/mcp-*output*.json",
            expected: truth.mcp_output_schemas,
            patterns: &[r"(\w+) tool output schemas"],
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
        NameSetClaim {
            claim: "the set of MCP tools",
            source: "TOOL_NAMES (crates/bathy-mcp/src/descriptors.rs)",
            expected: truth.mcp_tools.clone(),
            // The whole backticked, comma-separated run after "typed tools:".
            // A tool name contains a `.`, so the `([^.]+)` shape the protocol
            // patterns use cannot be reused here -- it would stop at
            // `scope.validate`'s own dot and compare a one-element set.
            patterns: &[r"typed tools: ((?:`[a-z.]+`(?:, )?)+)"],
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

    // A claim of absence whose falsifier is in the tree. See `ABSENCE_CLAIMS`.
    for claim in ABSENCE_CLAIMS {
        if truth.falsified_absences.contains(claim.phrase) && prose.contains(claim.phrase) {
            out.push(format!(
                "{README}: the claim \"{}\" is false.\n  \
                 {} exists, which is what that sentence says does not.\n  \
                 source of truth: the tree",
                claim.phrase, claim.falsified_by,
            ));
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
    // Index is the value, so the list must stay contiguous. It stopped at
    // twelve until M7 Task 4 wrote "thirteen interpretation rules" into the
    // limitations section, at which point the parser reported a correct
    // sentence as "not a number" -- a failure in the safe direction, but a
    // failure. Extended to twenty rather than to exactly thirteen so the next
    // rule does not have to touch this.
    const WORDS: &[&str] = &[
        "zero",
        "one",
        "two",
        "three",
        "four",
        "five",
        "six",
        "seven",
        "eight",
        "nine",
        "ten",
        "eleven",
        "twelve",
        "thirteen",
        "fourteen",
        "fifteen",
        "sixteen",
        "seventeen",
        "eighteen",
        "nineteen",
        "twenty",
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
        // The MCP tool list is written in code spans, as every identifier in
        // this README is; the protocol lists are not. Trimming backticks is
        // what lets one parser read both, and it cannot change a protocol
        // name, which has none.
        .map(|part| part.trim_matches('`'))
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
        interpretation_rules: count_interpretation_rules(root)?,
        mcp_tools: mcp_tool_names(root)?,
        committed_schemas: count_files(&root.join("schemas"))?,
        mcp_schemas: count_matching(&root.join("schemas"), |n| n.starts_with("mcp-"))?,
        mcp_input_schemas: count_matching(&root.join("schemas"), |n| {
            n.starts_with("mcp-") && n.contains("input")
        })?,
        mcp_output_schemas: count_matching(&root.join("schemas"), |n| {
            n.starts_with("mcp-") && n.contains("output")
        })?,
        evidence_cap_headers_kib: evidence_cap(root, "Headers")?,
        evidence_cap_full_kib: evidence_cap(root, "Full")?,
        falsified_absences: ABSENCE_CLAIMS
            .iter()
            .filter(|c| root.join(c.falsified_by).exists())
            .map(|c| c.phrase.to_string())
            .collect(),
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
    count_matching(dir, |_| true)
}

/// Files in `dir` whose file name satisfies `keep`.
///
/// The README's schema sentence makes three claims about one directory -- a
/// total and two subtotals -- and only the total had a counter. A subtotal is
/// as checkable as a total; the reason it went unchecked was that nobody
/// wrote the predicate down.
fn count_matching(dir: &Path, keep: impl Fn(&str) -> bool) -> Fallible<usize> {
    let mut n = 0;
    for entry in std::fs::read_dir(dir).map_err(|e| format!("reading {}: {e}", dir.display()))? {
        let entry = entry?;
        if entry.path().is_file() && entry.file_name().to_str().is_some_and(&keep) {
            n += 1;
        }
    }
    Ok(n)
}

/// Every rule `bathy-interpret` can fire, counted by asking the crate.
///
/// Called rather than parsed, on the same reasoning as [`probe_truth`]: a
/// fourteenth rule then fails `check-readme` instead of quietly leaving the
/// README's limitations section understating what this project identifies.
fn count_interpretation_rules(_root: &Path) -> Fallible<usize> {
    Ok(bathy_interpret::all_rules().count())
}

/// The MCP tool names, read out of `descriptors.rs`.
///
/// `bathy-mcp` is a 1.95-MSRV crate (it depends on `bathy-engine`, which
/// depends on `bathy-store`), and `xtask` is pinned to the 1.88 tier, so this
/// list cannot be obtained by calling the code that owns it without dragging
/// `xtask` out of the `msrv` CI job. Anchored on the `TOOL_NAMES` literal, so
/// a reformat that keeps the array intact still matches and a changed name
/// does not.
///
/// The array is asserted non-empty: a parse that silently found nothing would
/// compare the README's eleven names against an empty set and report eleven
/// spurious extras, which reads as a README defect rather than as the parser
/// defect it is.
fn mcp_tool_names(root: &Path) -> Fallible<BTreeSet<String>> {
    const DESCRIPTORS: &str = "crates/bathy-mcp/src/descriptors.rs";
    let path = root.join(DESCRIPTORS);
    let source = std::fs::read_to_string(&path).map_err(|e| format!("{DESCRIPTORS}: {e}"))?;
    let re = Regex::new(r#"(?s)TOOL_NAMES:\s*&\[&str\]\s*=\s*&\[(.*?)\]"#)
        .expect("checker pattern must compile");
    let body = re
        .captures(&source)
        .ok_or_else(|| {
            format!(
                "{DESCRIPTORS}: no `TOOL_NAMES: &[&str] = &[...]` literal found. The README \
                 states the tool count and the tool set and this is where both are read from; \
                 either the constant moved (update this pattern) or it is no longer a literal \
                 array (then the README's list has no source of truth and must be re-derived)."
            )
        })?
        .get(1)
        .expect("the pattern has one group")
        .as_str();
    let name = Regex::new(r#""([a-z][a-z.]*)""#).expect("checker pattern must compile");
    let names: BTreeSet<String> = name.captures_iter(body).map(|c| c[1].to_string()).collect();
    if names.is_empty() {
        return Err(format!("{DESCRIPTORS}: `TOOL_NAMES` parsed to no names at all").into());
    }
    Ok(names)
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
//     judgement about acceptance, not a fact in the tree -- a milestone whose
//     crates all exist may still be open on a criterion, and one that is
//     closed leaves nothing behind that says so. The 7 is checked. What *can*
//     be checked is the other half of the same sentence, and now is: a claim
//     that something does not exist yet, registered in `ABSENCE_CLAIMS` with
//     the path that falsifies it. M5's review found three such claims about
//     the MCP server standing in the commit range that shipped it.
//   - **A claim of absence nobody registered.** `ABSENCE_CLAIMS` is a
//     register, not a scan: it catches a claim that has gone stale, never a
//     new claim written without an entry. Writing "X does not exist yet" and
//     not registering it is exactly as invisible to this checker as the three
//     MCP sentences were before the register existed. A *registered* entry
//     can also be dead rather than merely quiet, and one was: the
//     verification suite's falsifier named `lab/Cargo.toml`, a path the tree
//     was never going to produce, so the README carried the claim through all
//     of M7 Tasks 1 to 3 with the lab, the fuzz targets and the benchmarks
//     committed. `every_falsifier_names_a_path_the_tree_can_actually_produce`
//     now guards the paths; nothing guards the completeness of the register.
//   - **Everything outside `README.md`.** This module reads one file. The
//     structural claims of the design paper, the platform-support document
//     and the threat model -- that each required section exists and states
//     the thing its acceptance criterion names -- are `check-docs`
//     (`xtask/src/docs.rs`), which has its own list of what it cannot see.
//     Neither checker reads the *truth* of a sentence in any of them.
//   - Every guarantee sentence in the status note and "Authorized use":
//     what the scheduler checks and when, that a scan is refused in full and
//     never silently trimmed, that a mid-scan expiry does not halt a run in
//     progress, *which* of the three packet-emitting subcommands refuse
//     before the state directory is opened (`preview` and `start` do;
//     `resume` opens it first, because the plan it re-authorizes is the one
//     already in the store). Each is a statement about control flow. These
//     are the claims M3's review found wrong, and they are the ones a
//     checker helps with least. This entry used to name "that
//     `bathy_scope::evaluate` has no caller" as a human-verified README
//     claim; that sentence left the README two milestones ago and `evaluate`
//     has had three production callers since M5, so the entry was describing
//     neither the file nor the tree.
//   - **The floor under `--intensity`.** The *default* (4) is pinned in
//     three phrasings. That `--intensity 0` still sends one probe rather
//     than none -- `select_probes` sets `budget = 1` -- is a second claim
//     about the same knob and is a branch, not a number, so it is not
//     pinned. It is in the README because understating what goes on someone
//     else's wire is a defect in its own right.
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
//   - **The crate table's descriptions.** Row *membership* is pinned in both
//     directions -- a crate with no row, and a row with no crate, both fail --
//     but what a row *says* is prose and is not read. At least three
//     checkable claims currently live in those descriptions: the number of
//     protocol probes, `bathy-interpret`'s "exactly two dependencies", and
//     `bathy-types`' "zero internal dependencies". All three are true today
//     and none is enforced here. Omitted from the first version of this list;
//     added after the Task 1 fix re-review pointed out that a reader could
//     take "the table is checked" to mean more than it does.
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

Six schemas are committed under [`schemas/`](schemas/) and CI fails if a type
changes without regenerating them. 5 of them are the MCP tool surface: 3 tool
input schemas and 2 tool output schemas.

**What a scanned third party sees on their wire.** A port that answers then
receives **up to `intensity` further connections — four by default** — each a
separate TCP connection carrying one protocol probe. So a port whose first
probe is recognized receives one additional connection; a port that
answers but is never identified receives four. **Two send nothing at all**:
the SSH and MySQL probes are listen-first, because those protocols have the
server speak first.

Service-identification coverage will start far below mature scanners: this
project begins with eight protocols against decades of accumulated community
fingerprint data elsewhere. bathy v0.1 has eight protocols and three
interpretation rules.

`bathy serve mcp` advertises two typed tools: `scope.validate`, `scan.start`.

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
            interpretation_rules: 3,
            mcp_tools: names(&["scope.validate", "scan.start"]),
            committed_schemas: 6,
            mcp_schemas: 5,
            mcp_input_schemas: 3,
            mcp_output_schemas: 2,
            evidence_cap_headers_kib: 8,
            evidence_cap_full_kib: 64,
            falsified_absences: names(&["an MCP server (the rest of Milestone 5)"]),
        }
    }

    /// The defect this rule exists for. The README asserted "twenty-one of
    /// them are the MCP tool surface: every tool's input and its output",
    /// which is 11 x 2 and is not 21 -- and `check-readme` was green, because
    /// it pinned the directory's *total* and nothing read the breakdown of
    /// the same directory. Written as a symmetric claim, which is exactly the
    /// wrong shape it had.
    #[test]
    fn a_tool_surface_breakdown_that_assumes_one_output_per_input_fails() {
        let readme = readme().replace("2 tool output schemas", "3 tool output schemas");
        let joined = violations(&readme, &truth()).join("\n");
        assert!(
            joined.contains("number of committed MCP tool output schemas"),
            "got:\n{joined}"
        );
        assert!(
            joined.contains("schemas/mcp-*output*.json"),
            "got:\n{joined}"
        );
    }

    #[test]
    fn the_tool_surface_subtotal_is_pinned_independently_of_the_directory_total() {
        let readme = readme().replace("5 of them are the MCP", "6 of them are the MCP");
        let joined = violations(&readme, &truth()).join("\n");
        assert!(
            joined.contains("number of committed schemas that are the MCP tool surface"),
            "got:\n{joined}"
        );
        assert!(
            !joined.contains("number of committed schemas\n"),
            "the directory total is a different claim and must not also fail: {joined}"
        );
    }

    /// The defect this rule exists for: `README.md` said three times, in the
    /// commit range that shipped it, that the MCP server did not exist yet.
    #[test]
    fn a_claim_of_absence_whose_falsifier_is_in_the_tree_fails_and_names_both() {
        let readme = "What does not exist yet: an MCP server (the rest of Milestone 5), \
                      privileged SYN/ICMP scanning.";
        let found = violations(readme, &truth());
        let named = found
            .iter()
            .find(|v| v.contains("an MCP server (the rest of Milestone 5)"))
            .unwrap_or_else(|| panic!("no violation named the false claim: {found:#?}"));
        assert!(
            named.contains("crates/bathy-mcp/src/server.rs"),
            "the failure must name what falsifies the claim: {named}"
        );
    }

    /// The register catches a claim that *goes* stale. It cannot catch one
    /// whose falsifier can never appear, and it had one: the verification
    /// suite's entry named `lab/Cargo.toml`, and the lab is a compose file, a
    /// ground-truth document and a shell script -- never a crate. So the
    /// README asserted through the whole of M7 Tasks 1 to 3 that the
    /// verification suite does not exist yet, with a committed lab, four fuzz
    /// targets and a published benchmark in the tree, and this check stayed
    /// green. The *choice of path* is therefore part of the entry, and this
    /// is its guard: every falsifier must be a path this repository could
    /// actually produce, which for a path outside `crates/` means one that
    /// exists right now.
    #[test]
    fn every_falsifier_names_a_path_the_tree_can_actually_produce() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        for claim in ABSENCE_CLAIMS {
            let exists = root.join(claim.falsified_by).exists();
            // A falsifier under `crates/` names a crate this project has
            // planned and not yet written -- that is the whole point of the
            // entry, and it must NOT exist yet. Anywhere else, the file has
            // to be real, or nothing will ever make the claim false.
            let is_a_planned_crate = claim.falsified_by.starts_with("crates/");
            assert!(
                exists || is_a_planned_crate,
                "ABSENCE_CLAIMS entry for {:?} is falsified by `{}`, which does not exist and \
                 is not a planned crate under crates/. A falsifier that cannot appear makes the \
                 entry dead: the claim can never be reported false. Name a path the tree really \
                 produces.",
                claim.phrase,
                claim.falsified_by,
            );
        }
    }

    /// And it is the *tree* that decides, not the phrase: the same sentence
    /// about a crate that really is absent is not a violation.
    #[test]
    fn a_claim_of_absence_whose_falsifier_is_absent_is_not_a_violation() {
        let readme = "What does not exist yet: a packet daemon (Milestone 6).";
        let found = violations(readme, &truth());
        assert!(
            !found.iter().any(|v| v.contains("a packet daemon")),
            "{found:#?}"
        );
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

    /// The number lives in the limitations section, which is the paragraph a
    /// reader deciding whether to trust this weighs hardest, and it is the
    /// one place where *understating* is as much a defect as overstating.
    #[test]
    fn a_wrong_interpretation_rule_count_is_caught_and_named() {
        let readme = readme().replace("three\ninterpretation rules", "nine\ninterpretation rules");
        fails_naming(
            &readme,
            "number of interpretation rules",
            "README says 9",
            "the tree says 3",
        );
    }

    #[test]
    fn a_wrong_tool_count_is_caught_and_named() {
        let readme = readme().replace("two typed tools", "five typed tools");
        fails_naming(
            &readme,
            "number of MCP tools",
            "README says 5",
            "the tree says 2",
        );
    }

    /// A count cannot see this: eleven names with one of them wrong is still
    /// eleven. `scan.start` renamed to `scan.begin` is a README that sends an
    /// agent author to a tool that does not exist.
    #[test]
    fn a_tool_list_with_the_right_length_and_a_wrong_name_is_caught() {
        let readme = readme().replace("`scan.start`", "`scan.begin`");
        let joined = violations(&readme, &truth()).join("\n");
        assert!(
            joined.contains("the set of MCP tools"),
            "a renamed tool must fail the set claim; got:\n{joined}"
        );
        assert!(
            joined.contains("scan.start"),
            "the failure must name what is missing; got:\n{joined}"
        );
        assert!(
            !joined.contains("number of MCP tools"),
            "the count is still right, so the count claim must not also fail:\n{joined}"
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
        let readme = readme().replace("Six schemas are committed", "Five schemas are committed");
        fails_naming(
            &readme,
            "number of committed schemas",
            "README says 5",
            "the tree says 6",
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
            "Six schemas are committed under",
            "There are six schemas living beneath",
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
        // Both sides of the comparison below are computed from
        // `number_claims`, so an emptied registry gives `0 >= 0` and this
        // test goes on passing over a checker that checks nothing. The M5
        // close-out review found the same shape in `bathy-types`; here the
        // consequence is that `check-readme` -- the mechanism that replaced
        // three milestones of human attention -- could be silently disarmed
        // and still print `ok`. The floor is stated as a literal for that
        // reason. It is a floor, not a pin: adding a claim is the point of
        // the registry and must not fail here.
        let patterns: usize = number_claims(&truth())
            .iter()
            .map(|c| c.patterns.len())
            .sum();
        assert!(
            patterns >= 16,
            "the numeric-claim registry is down to {patterns} patterns; the \
             comparison below is derived from it on both sides and cannot see \
             that, and `check-readme` would still report ok"
        );
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
