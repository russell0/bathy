//! `publish-check` — the last thing standing between private work and a
//! public repository.
//!
//! # What this is for
//!
//! The overview's Pre-Publication Gates are a checklist, and a checklist is
//! read once. This is the executable form of it: run it immediately before the
//! repository is made public, and fix everything it reports.
//!
//! The specific risk it exists for is concrete rather than hypothetical. The
//! **parent** directory of this repository holds a saved search-results page
//! and its `_files/` sidecar, and between them they carry the owner's account
//! email, an inferred physical location, and a live session token. The
//! repository root is a *sibling* of those files, so they are structurally
//! outside it and no `git add` from inside the repository can reach them —
//! and this gate exists so that stays true rather than being true by luck.
//!
//! # The rule about the checker's own source
//!
//! **Personal identifiers live only in the git-ignored [`PUBLISH_DENY_FILE`],
//! never in this file.** A leak detector that hardcodes the strings it detects
//! publishes them, which is the defect it was written to prevent, committed.
//! Everything in this module's source is a *generic* pattern — a private-key
//! header, a token prefix, the shape of a home directory path — and everything
//! specific comes from a file that is never committed. `.publish-deny` is
//! itself checked for being ignored and untracked, because the one edit that
//! would undo all of this is somebody adding it.
//!
//! That is also why this gate is **not a step in `ci.yml`**: the list it reads
//! does not exist in a fresh clone, so an ordinary CI run of it would either
//! fail on every runner or, worse, pass while checking nothing.
//!
//! # The one place it does run off this machine
//!
//! `.github/workflows/release.yml` runs it, because a release is the moment
//! this gate exists for and a publication that skipped it would be the gate
//! being decoration. A runner has no `.publish-deny`, so the workflow supplies
//! the list through [`PUBLISH_DENY_ENV`] from a repository secret.
//!
//! This does **not** reintroduce the failure the paragraph above describes, and
//! the reason is worth stating because it is the whole argument: the fallback
//! only ever *adds* a source for the list, never a way to proceed without one.
//! An absent secret yields an empty string, an empty list is already a hard
//! error here ("an empty deny list is not an empty risk"), and that error fails
//! the workflow before anything is uploaded. The gate is fail-closed in CI for
//! exactly the same reason it is fail-closed locally.
//!
//! # What it covers
//!
//! Three layers, because publication exposes all three:
//!
//! 1. **What a publish would contain.** Every tracked file, plus every
//!    untracked file that is not ignored — which is exactly the set
//!    `git add -A` would sweep in. Research artifacts by filename, denied
//!    strings and generic secrets by content, a leftover `OWNER` placeholder,
//!    a home-directory path that names the operator.
//! 2. **What the history contains.** Publishing a repository publishes every
//!    blob reachable from every ref, not the working tree. A file that was
//!    committed and then deleted is still published. So the same denied
//!    strings and secret patterns are checked over every blob in the object
//!    database, and the commit identities are checked separately.
//! 3. **What the repository claims.** The required files exist and are
//!    tracked, `SECURITY.md` carries the authorized-use statement in as many
//!    words, the design paper carries the clean-room attestation, and every
//!    other gate this project has — every `check-*` subcommand — passes.
//!
//! # What it deliberately cannot do
//!
//! [`NOT_MECHANIZABLE`] is printed on **every** run, passing or failing. This
//! project's standing practice is to write down what its checkers cannot see
//! (`readme.rs`'s human-verified list, `fixtures.rs`'s `UNCHECKABLE`, `fuzz/`'s
//! hole list) rather than let a green check be read as a complete one, and a
//! publication gate is the worst possible place to break that habit.

use std::path::Path;
use std::process::Command;

type Fallible<T> = Result<T, Box<dyn std::error::Error>>;

// ---------------------------------------------------------------------------
// The deny list. Personal identifiers live here and nowhere else.
// ---------------------------------------------------------------------------

/// Where the denied strings live. Git-ignored on purpose: the list itself is
/// the thing that must not be published.
pub const PUBLISH_DENY_FILE: &str = ".publish-deny";

/// Where the deny list comes from when there is no file — that is, on a CI
/// runner, which has no git-ignored files at all.
///
/// Read **only** when [`PUBLISH_DENY_FILE`] is absent, never merged with it: a
/// machine that has the file is the machine whose file is authoritative, and a
/// gate whose input silently depends on an environment variable is a gate whose
/// result cannot be reproduced by running the same command.
pub const PUBLISH_DENY_ENV: &str = "BATHY_PUBLISH_DENY";

/// The marker that acknowledges commit authorship as intentionally published.
///
/// See [`identity_violations`]. It lives in the deny list rather than in this
/// source for the same reason everything else specific does: writing it here
/// would mean writing what it acknowledges.
pub const AUTHORSHIP_ACK: &str = "#authorship-ok";

/// Non-comment, non-blank entries of a `.publish-deny` document.
pub fn publish_denied_strings(text: &str) -> Vec<&str> {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect()
}

/// Whether the deny list acknowledges that commit authorship is published.
pub fn authorship_acknowledged(text: &str) -> bool {
    text.lines()
        .map(str::trim)
        .any(|line| line.starts_with(AUTHORSHIP_ACK))
}

// ---------------------------------------------------------------------------
// Generic patterns. Nothing here is specific to any person.
// ---------------------------------------------------------------------------

/// A credential shape: what starts it, what it is, and how much
/// credential-looking material has to follow before it is one.
pub struct SecretPattern {
    /// The literal that begins the credential.
    pub prefix: &'static str,
    /// What it is, printed with the failure.
    pub what: &'static str,
    /// The number of ASCII-alphanumeric characters that must immediately
    /// follow `prefix`. Zero means the prefix alone is conclusive, which is
    /// true only of the fully delimited PEM headers.
    pub min_suffix: usize,
}

/// The credential shapes this gate looks for.
///
/// # Why there is a length rule and not just a prefix
///
/// The first version of this list was prefixes alone, and the first real run
/// of the gate reported **90 secrets, every one of them false**. It flagged
/// its own source (this list), the plan document that specifies this list,
/// every historical revision of that plan document, and — the one that shows
/// the rule best — `xtask/src/visibility.rs`'s test
/// `ghs_json_is_parsed_and_an_empty_array_is_none_rather_than_an_error`, whose
/// name begins with a GitHub token prefix by pure coincidence.
///
/// The defect was not the list. It was that the check matched **the name of a
/// secret rather than a secret**. `AKIA` is four characters of prose; an AWS
/// key id is `AKIA` plus sixteen more. So each entry now says how much
/// credential-shaped material must follow, and the alphabet is strict ASCII
/// alphanumerics — no underscore — because that is what these credentials are
/// made of and it is what stops `ghs_json_is_…` at four characters.
///
/// This matters beyond tidiness. A gate that reports ninety false positives on
/// its first run is a gate whose next run nobody reads, and the one thing this
/// gate cannot afford is to be skimmed. It is also the only fix available for
/// the historical blobs: a marker or an exemption can be added to a file, and
/// nothing can be added to a commit that already happened.
/// # Why the PEM headers are spelled with `concat!`
///
/// A fully delimited PEM header is conclusive on its own — `min_suffix` is 0 —
/// so writing one as a literal here would make this file trip this check, and
/// `publish-check` reads `xtask/` like every other tracked file. The second run
/// of the gate reported exactly that, six times.
///
/// `concat!` splits the literal across two string tokens, so the *source text*
/// never contains the header contiguously while the compiled constant does.
/// It is the same device `phrases.rs` uses for the names its own rules forbid
/// and for the determinism phrase, and it is preferred to an exemption for the
/// same reason: an exemption is a hole, and this one would sit in the file
/// whose whole job is not to have holes. `the_checkers_own_source_carries_no_
/// credential` is what keeps it honest.
pub const SECRET_PATTERNS: &[SecretPattern] = &[
    // The PEM headers are conclusive in their fully delimited form and only
    // in that form: the plan document quotes `"BEGIN RSA PRIVATE KEY"` as a
    // string literal, and that is a specification, not a key.
    SecretPattern {
        prefix: concat!("-----BEGIN ", "RSA PRIVATE KEY-----"),
        what: "an RSA private key",
        min_suffix: 0,
    },
    SecretPattern {
        prefix: concat!("-----BEGIN ", "OPENSSH PRIVATE KEY-----"),
        what: "an OpenSSH private key",
        min_suffix: 0,
    },
    SecretPattern {
        prefix: concat!("-----BEGIN ", "EC PRIVATE KEY-----"),
        what: "an EC private key",
        min_suffix: 0,
    },
    SecretPattern {
        prefix: concat!("-----BEGIN ", "DSA PRIVATE KEY-----"),
        what: "a DSA private key",
        min_suffix: 0,
    },
    SecretPattern {
        prefix: concat!("-----BEGIN ", "PGP PRIVATE KEY BLOCK-----"),
        what: "a PGP private key",
        min_suffix: 0,
    },
    SecretPattern {
        prefix: concat!("-----BEGIN ", "PRIVATE KEY-----"),
        what: "a PKCS#8 private key",
        min_suffix: 0,
    },
    // AWS key ids are twenty characters: the four-character prefix and sixteen
    // more.
    SecretPattern {
        prefix: "AKIA",
        what: "an AWS access key id",
        min_suffix: 12,
    },
    SecretPattern {
        prefix: "ASIA",
        what: "an AWS temporary access key id",
        min_suffix: 12,
    },
    // GitHub's tokens are the prefix plus thirty-six alphanumerics.
    SecretPattern {
        prefix: "ghp_",
        what: "a GitHub personal access token",
        min_suffix: 30,
    },
    SecretPattern {
        prefix: "gho_",
        what: "a GitHub OAuth token",
        min_suffix: 30,
    },
    SecretPattern {
        prefix: "ghs_",
        what: "a GitHub server-to-server token",
        min_suffix: 30,
    },
    SecretPattern {
        prefix: "github_pat_",
        what: "a GitHub fine-grained token",
        min_suffix: 20,
    },
    // Slack tokens are hyphen-separated groups of digits; the first group
    // alone is longer than any word that would precede a hyphen by accident.
    SecretPattern {
        prefix: "xoxb-",
        what: "a Slack bot token",
        min_suffix: 8,
    },
    SecretPattern {
        prefix: "xoxp-",
        what: "a Slack user token",
        min_suffix: 8,
    },
    SecretPattern {
        prefix: "xoxa-",
        what: "a Slack app token",
        min_suffix: 8,
    },
    SecretPattern {
        prefix: "sk-ant-",
        what: "an Anthropic API key",
        min_suffix: 3,
    },
];

/// Whether `line` carries a credential of this shape.
///
/// `split` rather than byte offsets: `str` indexing is invisible to
/// `clippy::indexing_slicing`, this project found five production panics that
/// way by reading, and new code here does not index a `str` at all.
fn carries_secret(line: &str, pattern: &SecretPattern) -> bool {
    line.split(pattern.prefix).skip(1).any(|tail| {
        tail.chars().take_while(char::is_ascii_alphanumeric).count() >= pattern.min_suffix
    })
}

/// Filename markers of a saved-web-page research artifact.
///
/// Filenames, not content: a saved page's own text is arbitrary, and what is
/// invariant about one is how the browser named it. `_files` is the sidecar
/// directory every browser writes beside a saved page, and it is the half that
/// actually carries the tokens and the images.
///
/// Generic by construction — none of these is a person's name, and the
/// person-specific half comes from the deny list at run time.
pub const ARTIFACT_MARKERS: &[&str] = &[
    "google search",
    "search results",
    "_files/",
    ".html.orig",
    ".mhtml",
    ".webarchive",
    ".har",
    "cookies.txt",
    "cookies.sqlite",
];

/// Paths that exist to be ignored, and whose appearance in `git ls-files`
/// means the ignore rule stopped working.
///
/// `.publish-deny` is first for the obvious reason: committing it publishes
/// every string this gate exists to keep out, and the gate would go on
/// reporting success while doing it.
pub const MUST_STAY_UNTRACKED: &[(&str, &str)] = &[
    (
        PUBLISH_DENY_FILE,
        "it is the list of strings that must never be published; committing it publishes \
         all of them at once, and this checker would keep reporting success",
    ),
    (
        ".superpowers/",
        "plan-execution scratch: ledgers, briefs and review packages, written for this \
         machine and not for readers",
    ),
    (
        "lab/.state/",
        "the lab's runtime state, including whatever a scan wrote to disk",
    ),
    (
        "target/",
        "build output; it also contains absolute paths from this machine",
    ),
];

/// Files that must exist and be tracked before the repository is public, and
/// why each one is a publication gate rather than a nicety.
pub const REQUIRED_FILES: &[(&str, &str)] = &[
    (
        "LICENSE-APACHE",
        "the dual licence is Apache-2.0 OR MIT and a repository with no licence file is \
         not open source, whatever its manifests say",
    ),
    ("LICENSE-MIT", "the other half of the dual licence"),
    (
        "README.md",
        "the first thing a stranger reads, and the document `check-readme` holds to the \
         tree",
    ),
    (
        "SECURITY.md",
        "the overview's Pre-Publication Gates require a disclosure path and an explicit \
         authorized-use statement (AC-7.22, AC-7.24)",
    ),
    (
        "CONTRIBUTING.md",
        "the clean-room rule stated for contributors, and the citation requirement \
         (AC-7.23). Without it the clean-room boundary is a claim this project makes \
         about itself and asks of nobody",
    ),
    ("CODE_OF_CONDUCT.md", "Task 5 Step 3"),
    (
        "docs/design-paper.md",
        "it carries the clean-room attestation the Pre-Publication Gates name",
    ),
];

/// A sentence a document must carry at publication, and the reason.
///
/// These duplicate three of `check-docs`' claims **on purpose**. `check-docs`
/// is the gate that runs on every push; this is the gate that runs once, at
/// the moment it matters, and a publication check that outsources its most
/// important assertion to another command is a publication check that passes
/// when somebody forgets to run the other command. The duplication is one
/// line each and the failure mode it removes is the whole point of the file.
pub const REQUIRED_STATEMENTS: &[(&str, &str, &str)] = &[
    (
        "SECURITY.md",
        "**bathy is for scanning networks you are authorized to scan.**",
        "the explicit authorized-use statement the Pre-Publication Gates require",
    ),
    (
        "SECURITY.md",
        "Report privately through GitHub Security Advisories",
        "the vulnerability disclosure path (AC-7.24)",
    ),
    (
        "docs/design-paper.md",
        "Clean-room attestation",
        "the clean-room attestation the Pre-Publication Gates require by name",
    ),
    (
        "docs/design-paper.md",
        "they were not opened",
        "the precise half of the attestation: Nmap's data files are on this disk and were \
         not read. An attestation that omits the complication is the one a reader \
         discredits",
    ),
];

/// The `check-*` subcommands `publish-check` does **not** run, and why.
///
/// Everything else that starts with `check-` is run, derived from `main`'s own
/// subcommand list rather than restated here — so a gate added tomorrow is
/// part of the publication gate without anyone remembering to add it. That is
/// the same arrangement `check-ci` uses, and for the same reason: a
/// hand-maintained second list of gates drifts, silently, in the direction of
/// covering less.
pub const GATES_NOT_RUN: &[(&str, &str)] = &[(
    "check-ci-status",
    "it asks GitHub what CI said about a pushed branch. Before the first public push \
     there is no such branch and no answer, and it needs `gh` credentials this gate \
     must not require. It is the right command to run *after* publishing.",
)];

/// The gates a person has to discharge, because no program here can.
///
/// Printed on every run, passing or failing, for the reason `readme.rs` and
/// `fixtures.rs` print theirs: the failure mode of a checklist is that a green
/// check gets read as a complete one.
pub const NOT_MECHANIZABLE: &[(&str, &str)] = &[
    (
        "Name availability: crates.io, GitHub, DNS (AC-7.31)",
        "Three network lookups and a judgement call. A program here could fetch \
         crates.io, but a cached or offline answer that reported `available` would be \
         the worst possible failure -- the name is unrenameable after the first \
         publish. Confirm by hand, record the answer, and remember the fallback order \
         is fathom, assay, reckon.",
    ),
    (
        "The lab conformance suite: `lab/run.sh test`",
        "It needs Docker, nine containers and pinned images pulled from a registry. \
         `check-lab` proves the compose file is digest-pinned and that CI has a job for \
         it; nothing here proves the suite passed on this tree. Run it.",
    ),
    (
        "GitHub private vulnerability reporting is switched on",
        "`SECURITY.md` publishes an advisories URL and a fallback for when it does not \
         work. Whether the setting is enabled is a checkbox on a website, and whether \
         anyone is watching it is a promise about a human being.",
    ),
    (
        "The README's guarantee sentences",
        "`check-readme` proves the numbers. The claims about what the scheduler checks \
         and when, what is refused in full, and what has no caller are statements about \
         control flow, and they are the ones three consecutive milestone reviews found \
         wrong. `xtask/src/readme.rs` ends with the written-out list.",
    ),
    (
        "Whether the policy documents are true",
        "`check-docs` proves `SECURITY.md` says evasion is a non-goal. That the code \
         still has no evasion feature is a different question, and this repository's \
         worst defect class is a document that stayed still while the code moved.",
    ),
    (
        "The research artifacts in the PARENT directory",
        "They are outside the repository and no check inside it can see them. This gate \
         proves they were never added; it cannot prove they are gone from the disk, and \
         it is not this gate's job to delete somebody's files. Look in the directory \
         above this one before you publish.",
    ),
    (
        "Whether the deny list is complete",
        "It is a hand-maintained register, exactly like `FUZZ_SURFACES`. It catches the \
         identifiers somebody thought to write down. An identifier nobody listed is \
         invisible to every check in this file.",
    ),
];

// ---------------------------------------------------------------------------
// The pure checks. Each takes data and returns messages; none reads the world.
// ---------------------------------------------------------------------------

/// One file a publish would carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate {
    /// Repository-relative, forward slashes.
    pub path: String,
    /// Whether git already tracks it. An untracked, unignored file is not
    /// published today and is one `git add -A` away from being published, so
    /// it is checked and the message says which it is.
    pub tracked: bool,
}

impl Candidate {
    pub fn tracked(path: &str) -> Self {
        Self {
            path: path.to_string(),
            tracked: true,
        }
    }
    pub fn untracked(path: &str) -> Self {
        Self {
            path: path.to_string(),
            tracked: false,
        }
    }
    fn how(&self) -> &'static str {
        if self.tracked {
            "tracked"
        } else {
            "untracked but not ignored, so `git add -A` would sweep it in"
        }
    }
}

/// A path that is safe to print, given what must not be printed.
///
/// The obvious message for "a denied string appears in a filename" is one that
/// prints the filename, and that message publishes the denied string into a
/// terminal, a scrollback, and — this project's actual risk — a report file.
/// Caught by `a_denied_string_in_a_filename_is_rejected_without_being_printed`,
/// which failed the first time it was run.
///
/// A path with nothing denied in it is returned unchanged, because redacting
/// every path would make the ordinary output unreadable to buy nothing. A path
/// that does match is lowercased first — detection is case-insensitive, and
/// redacting the lowercase form against the lowercase needle is exact, where
/// redacting mixed case against three spellings is a guess. A lowercased path
/// still names the file.
fn safe_path(path: &str, denied: &[&str]) -> String {
    let lower = path.to_lowercase();
    if !denied.iter().any(|n| lower.contains(&n.to_lowercase())) {
        return path.to_string();
    }
    let mut out = lower;
    for (position, needle) in denied.iter().enumerate() {
        out = out.replace(
            &needle.to_lowercase(),
            &format!("<{PUBLISH_DENY_FILE} entry #{}>", position + 1),
        );
    }
    format!("{out} [lowercased and redacted: the path itself contains a denied string]")
}

/// Research artifacts, by filename, and any denied string appearing in a path.
///
/// A path is checked case-insensitively because the marker this exists for is
/// a browser-generated filename with capitals in it.
pub fn artifact_violations(files: &[Candidate], denied: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    for file in files {
        let lower = file.path.to_lowercase();
        let shown = safe_path(&file.path, denied);
        for marker in ARTIFACT_MARKERS {
            if lower.contains(marker) {
                out.push(format!(
                    "research artifact: `{shown}` ({}) matches the filename marker \
                     `{marker}`. Saved pages and their `_files/` sidecars carry session \
                     tokens and account identifiers; nothing of the kind is publishable.",
                    file.how(),
                ));
            }
        }
        for (position, needle) in denied.iter().enumerate() {
            if lower.contains(&needle.to_lowercase()) {
                out.push(format!(
                    "{PUBLISH_DENY_FILE} entry #{} appears in a PATH: `{shown}` ({}).",
                    position + 1,
                    file.how(),
                ));
            }
        }
    }
    out
}

/// Paths where the `OWNER` placeholder is a specification rather than a leak.
///
/// The only exemption in this module, and the argument for it, in the form
/// `phrases::Rule::exemption_rationale` uses.
///
/// **What the check is for.** `github.com/OWNER/` matters because it reaches
/// `Cargo.toml`'s `repository` field and, through it, the `User-Agent` this
/// project puts on other people's wires — which is the one string a scanned
/// third party has to work with. Shipping the literal word `OWNER` there
/// would make bathy's traffic unattributable, which is the thing `SECURITY.md`
/// promises it never is.
///
/// **Why these two paths are not that.** `xtask/src/publish.rs` is the checker
/// and has to contain what it looks for. The plan documents *specify* the
/// checker, in a fenced Rust sketch that contains the same line. Neither ships
/// anywhere.
///
/// **Why by path and not by the `[phrase-rule]` sentinel**, which is this
/// project's usual device for a line that legitimately names a forbidden
/// thing: this check also runs over *history*, and a marker can be added to a
/// file but not to a commit that has already happened. Every historical
/// revision of the plan carries the sketch, under one of these two prefixes,
/// and no line-level mechanism can reach them.
///
/// **What it costs.** A real placeholder left in a plan document is not
/// reported. That is the whole of the exposure, and a plan document is not a
/// manifest.
pub const PLACEHOLDER_EXEMPT_PREFIXES: &[&str] =
    &["docs/superpowers/plans/", "xtask/src/publish.rs"];

/// Whether `where_` — a path, or a history-blob label naming one — is exempt.
fn placeholder_exempt(where_: &str) -> bool {
    PLACEHOLDER_EXEMPT_PREFIXES.iter().any(|prefix| {
        where_.starts_with(prefix)
            // A history blob's label is `history blob <sha> (last seen as
            // `<path>`)`, and the path inside it is the thing to match.
            || where_.contains(&format!("`{prefix}"))
    })
}

/// Every denied string, secret pattern, placeholder and home path in `text`.
///
/// `where_` names the thing being scanned — a working-tree path, or a blob in
/// the history — so the same rules run over both and the message says which.
///
/// The denied string itself is **never** printed: only its length, its
/// position, and the fact that one matched. Printing it would move it from a
/// git-ignored file into a terminal, a scrollback, and quite possibly a
/// report — which is the failure this whole module is arranged around.
pub fn content_violations(where_: &str, text: &str, denied: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    // The label is a path or a blob description, and either can itself contain
    // a denied string. See [`safe_path`].
    let where_ = &safe_path(where_, denied);
    for (index, line) in text.lines().enumerate() {
        let number = index + 1;
        for (position, needle) in denied.iter().enumerate() {
            if line.contains(needle) {
                out.push(format!(
                    "{where_}:{number}: {PUBLISH_DENY_FILE} entry #{} ({} chars) appears \
                     here. The string is not reproduced in this message, in this \
                     checker's source, or anywhere else that is committed.",
                    position + 1,
                    needle.chars().count(),
                ));
            }
        }
        for pattern in SECRET_PATTERNS {
            if carries_secret(line, pattern) {
                out.push(format!(
                    "{where_}:{number}: `{}` followed by {}+ credential characters -- {}. \
                     Rotate it first and remove it second; a secret that has been in a \
                     repository is a secret that has been published, whatever the \
                     repository's visibility was.",
                    pattern.prefix, pattern.min_suffix, pattern.what,
                ));
            }
        }
        if !placeholder_exempt(where_)
            && (line.contains("github.com/OWNER/") || line.contains("<OWNER>"))
        {
            out.push(format!(
                "{where_}:{number}: the `OWNER` placeholder is still here. It ends up in \
                 the `User-Agent` this project puts on other people's wires, which is \
                 the one string a scanned third party has to work with."
            ));
        }
        out.extend(home_path_violation(where_, number, line));
    }
    out
}

/// A `/Users/<name>` or `/home/<name>` path, which names the operator.
///
/// Split out because the rule has one deliberate exemption and an exemption
/// needs somewhere to be argued: a *bare* `/Users/` or `/home/` with nothing
/// after it names nobody, and `/home/runner` is GitHub Actions' own working
/// directory and appears in workflow files and CI logs by construction.
///
/// Written with `split` rather than byte offsets. `str` indexing is invisible
/// to `clippy::indexing_slicing` -- this project found five production panics
/// that way by hand -- so new code here does not index a `str` at all.
fn home_path_violation(where_: &str, number: usize, line: &str) -> Vec<String> {
    let mut out = Vec::new();
    for prefix in ["/Users/", "/home/"] {
        for tail in line.split(prefix).skip(1) {
            let user: String = tail
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '-' || *c == '_' || *c == '.')
                .collect();
            if user.is_empty() || user == "runner" || user == "root" {
                continue;
            }
            out.push(format!(
                "{where_}:{number}: an absolute home-directory path (`{prefix}…`, {} \
                 characters of account name) names the machine's account. Use a relative \
                 path, or `$HOME`.",
                user.chars().count(),
            ));
        }
    }
    out
}

/// Paths that must not be tracked, and are.
pub fn tracked_but_must_not_be(files: &[Candidate]) -> Vec<String> {
    let mut out = Vec::new();
    for (path, why) in MUST_STAY_UNTRACKED {
        let hit = files
            .iter()
            .find(|f| f.tracked && (f.path == *path || f.path.starts_with(path)));
        if let Some(file) = hit {
            out.push(format!(
                "`{}` is tracked and must not be: {why}. Check `.gitignore` -- the rule \
                 that was keeping it out has stopped working, and that is a worse defect \
                 than the file itself.",
                file.path,
            ));
        }
    }
    out
}

/// Required files that are absent from disk, or present and untracked.
///
/// Both halves matter and only one of them is obvious. A `SECURITY.md` that
/// exists locally and was never `git add`ed satisfies every check that reads
/// the filesystem and is absent from the published repository, which is the
/// only place it was ever needed.
pub fn required_file_violations(root: &Path, files: &[Candidate]) -> Vec<String> {
    let mut out = Vec::new();
    for (path, why) in REQUIRED_FILES {
        if !root.join(path).is_file() {
            out.push(format!("required file `{path}` does not exist: {why}."));
            continue;
        }
        if !files.iter().any(|f| f.tracked && f.path == *path) {
            out.push(format!(
                "required file `{path}` exists on disk and is NOT tracked, so it would \
                 not be published: {why}."
            ));
        }
    }
    out
}

/// Required sentences that a document has stopped carrying.
pub fn required_statement_violations(documents: &[(&str, String)]) -> Vec<String> {
    let mut out = Vec::new();
    for (path, needle, why) in REQUIRED_STATEMENTS {
        let Some((_, text)) = documents.iter().find(|(p, _)| p == path) else {
            out.push(format!(
                "`{path}` could not be read, so {why} could not be confirmed."
            ));
            continue;
        };
        let flat = text.split_whitespace().collect::<Vec<_>>().join(" ");
        if !flat.contains(&needle.split_whitespace().collect::<Vec<_>>().join(" ")) {
            out.push(format!(
                "`{path}` no longer contains {why}.\n  looked for: {needle}\n  This is \
                 checked here as well as in `check-docs` deliberately: a publication \
                 gate that depends on someone having run another command first is a \
                 publication gate with a hole in it."
            ));
        }
    }
    out
}

/// Denied strings in the identity of the commits themselves.
///
/// Publishing a repository publishes every author and committer line in it.
/// On a personal repository that is usually the owner's own address, and it is
/// usually intended — which is exactly why it needs an explicit decision
/// rather than a silent pass. Acknowledge it by putting a line starting with
/// [`AUTHORSHIP_ACK`] in the deny list, which is git-ignored, so the
/// acknowledgement is local and per-machine.
///
/// The identity itself is never printed.
pub fn identity_violations(
    identities: &[String],
    denied: &[&str],
    acknowledged: bool,
) -> Vec<String> {
    if acknowledged {
        return Vec::new();
    }
    let mut out = Vec::new();
    for (position, needle) in denied.iter().enumerate() {
        let lower = needle.to_lowercase();
        let count = identities
            .iter()
            .filter(|identity| identity.to_lowercase().contains(&lower))
            .count();
        if count > 0 {
            out.push(format!(
                "{PUBLISH_DENY_FILE} entry #{} ({} chars) appears in the author or \
                 committer identity of {count} commit(s). Publishing the repository \
                 publishes every one of them, and no change to the working tree removes \
                 it -- only rewriting history does.\n  If that is intended (it usually \
                 is: they are your commits), add a line starting `{AUTHORSHIP_ACK}` to \
                 {PUBLISH_DENY_FILE}. That file is git-ignored, so the acknowledgement \
                 stays on this machine and the decision is made once, on purpose, \
                 instead of by nobody.",
                position + 1,
                needle.chars().count(),
            ));
        }
    }
    out
}

/// Everything wrong with the working tree, given the files a publish carries.
///
/// Pure apart from reading the files it was handed the names of, so a test can
/// build a fixture tree and get exactly the messages a real run would print.
pub fn working_tree_violations(root: &Path, files: &[Candidate], denied: &[&str]) -> Vec<String> {
    let mut out = artifact_violations(files, denied);
    out.extend(tracked_but_must_not_be(files));
    out.extend(required_file_violations(root, files));

    let mut documents: Vec<(&str, String)> = Vec::new();
    for (path, _, _) in REQUIRED_STATEMENTS {
        if documents.iter().any(|(p, _)| p == path) {
            continue;
        }
        if let Ok(text) = std::fs::read_to_string(root.join(path)) {
            documents.push((path, text));
        }
    }
    out.extend(required_statement_violations(&documents));

    for file in files {
        if file.path == PUBLISH_DENY_FILE {
            // The one file whose whole purpose is to contain these strings.
            continue;
        }
        let Ok(bytes) = std::fs::read(root.join(&file.path)) else {
            continue;
        };
        let Ok(text) = String::from_utf8(bytes) else {
            continue; // binary, as `grep -I` treats it
        };
        out.extend(content_violations(&file.path, &text, denied));
    }
    out
}

// ---------------------------------------------------------------------------
// The world-reading half: git, subprocesses, and the driver.
// ---------------------------------------------------------------------------

fn git(root: &Path, args: &[&str]) -> Fallible<String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(root)
        .output()
        .map_err(|e| format!("running `git {}`: {e}", args.join(" ")))?;
    if !output.status.success() {
        return Err(format!(
            "`git {}` failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim(),
        )
        .into());
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Every file a publish would carry: tracked, plus untracked and not ignored.
///
/// That is precisely the set `git add -A` operates on, which is the set this
/// project's own process rule ("never `git add -A` without checking what it
/// swept in") exists because of. Ignored files are excluded on purpose and it
/// is a deliberate narrowing of the previous whole-tree walk: an ignored file
/// cannot be published without first changing `.gitignore`, and the old walk's
/// file count depended on whether anyone had run the fuzzer locally, which
/// made the gate's own evidence unreproducible.
pub fn publish_candidates(root: &Path) -> Fallible<Vec<Candidate>> {
    let tracked: Vec<String> = git(root, &["ls-files", "-z"])?
        .split('\0')
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect();
    let untracked: Vec<String> = git(root, &["ls-files", "-z", "--others", "--exclude-standard"])?
        .split('\0')
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect();
    let mut out: Vec<Candidate> = tracked.iter().map(|p| Candidate::tracked(p)).collect();
    out.extend(untracked.iter().map(|p| Candidate::untracked(p)));
    Ok(out)
}

/// Author and committer identity of every commit reachable from any ref.
fn commit_identities(root: &Path) -> Fallible<Vec<String>> {
    Ok(
        git(root, &["log", "--all", "--format=%an <%ae>%n%cn <%ce>"])?
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(str::to_owned)
            .collect(),
    )
}

/// Every denied string or secret in any blob in the object database.
///
/// The reason this exists rather than being left to the working-tree scan: a
/// publish exposes the *history*, and a file that was committed and then
/// deleted is still in it. The working tree is the one place where removing
/// the file is enough, and it is the only place the old check looked.
///
/// Implemented with `git rev-list --objects --all` piped into
/// `git cat-file --batch`, which is one subprocess for the whole database
/// rather than one per object.
fn history_violations(root: &Path, denied: &[&str]) -> Fallible<(Vec<String>, usize)> {
    let listing = git(root, &["rev-list", "--objects", "--all"])?;
    let mut names = String::new();
    let mut paths: Vec<(String, String)> = Vec::new();
    for line in listing.lines() {
        let mut parts = line.splitn(2, ' ');
        let Some(sha) = parts.next() else { continue };
        if sha.is_empty() {
            continue;
        }
        names.push_str(sha);
        names.push('\n');
        paths.push((sha.to_owned(), parts.next().unwrap_or("").to_owned()));
    }
    if paths.is_empty() {
        return Err(
            "`git rev-list --objects --all` listed nothing, so the history scan \
                    would have proven nothing"
                .into(),
        );
    }

    let output = run_with_stdin(root, "git", &["cat-file", "--batch"], &names)?;
    let mut violations = Vec::new();
    let mut blobs = 0usize;
    for (sha, body) in batch_objects(&output) {
        blobs += 1;
        let Ok(text) = std::str::from_utf8(body) else {
            continue; // binary, as `grep -I` treats it
        };
        let path = paths
            .iter()
            .find(|(candidate, _)| *candidate == sha)
            .map(|(_, path)| path.as_str())
            .unwrap_or("");
        let short: String = sha.chars().take(12).collect();
        let where_ = if path.is_empty() {
            format!("history blob {short}")
        } else {
            format!("history blob {short} (last seen as `{path}`)")
        };
        violations.extend(content_violations(&where_, text, denied));
    }
    Ok((violations, blobs))
}

/// Split `git cat-file --batch` output into `(sha, contents)` for each blob.
///
/// The format is `<sha> <type> <size>\n<contents>\n`, repeated, with the size
/// in bytes. Parsed by walking a byte cursor with checked `get`, never by
/// indexing: a malformed or truncated stream must stop the scan, not panic in
/// the middle of a publication gate.
fn batch_objects(output: &[u8]) -> Vec<(String, &[u8])> {
    let mut out = Vec::new();
    let mut cursor = 0usize;
    while let Some(rest) = output.get(cursor..) {
        if rest.is_empty() {
            break;
        }
        let Some(newline) = rest.iter().position(|b| *b == b'\n') else {
            break;
        };
        let Some(header) = rest
            .get(..newline)
            .and_then(|h| std::str::from_utf8(h).ok())
        else {
            break;
        };
        let mut fields = header.split(' ');
        let (Some(sha), Some(kind), Some(size)) = (fields.next(), fields.next(), fields.next())
        else {
            break;
        };
        let Ok(size) = size.trim().parse::<usize>() else {
            break;
        };
        let body_start = match newline.checked_add(1) {
            Some(start) => start,
            None => break,
        };
        let Some(body_end) = body_start.checked_add(size) else {
            break;
        };
        let Some(body) = rest.get(body_start..body_end) else {
            break;
        };
        if kind == "blob" {
            out.push((sha.to_owned(), body));
        }
        // The trailing newline git writes after each object's contents.
        cursor = match cursor
            .checked_add(body_end)
            .and_then(|end| end.checked_add(1))
        {
            Some(next) => next,
            None => break,
        };
    }
    out
}

fn run_with_stdin(root: &Path, program: &str, args: &[&str], stdin: &str) -> Fallible<Vec<u8>> {
    use std::io::Write;
    let mut child = Command::new(program)
        .args(args)
        .current_dir(root)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawning `{program} {}`: {e}", args.join(" ")))?;
    child
        .stdin
        .take()
        .ok_or("the child has no stdin")?
        .write_all(stdin.as_bytes())
        .map_err(|e| format!("writing to `{program}`: {e}"))?;
    let output = child
        .wait_with_output()
        .map_err(|e| format!("waiting for `{program}`: {e}"))?;
    if !output.status.success() {
        return Err(format!("`{program} {}` failed", args.join(" ")).into());
    }
    Ok(output.stdout)
}

/// The gates `publish-check` runs, derived from `main`'s subcommand list.
pub fn gates_to_run<'a>(subcommands: &[&'a str]) -> Vec<&'a str> {
    subcommands
        .iter()
        .copied()
        .filter(|name| name.starts_with("check-"))
        .filter(|name| !GATES_NOT_RUN.iter().any(|(skip, _)| skip == name))
        .collect()
}

/// Every check that must pass before this repository becomes public.
///
/// `dispatch` runs one `xtask` subcommand by name; it is passed in rather than
/// imported so that this module does not have to know `main`'s `match`, and so
/// that a test can drive the gate list without shelling out.
pub fn publish_check(
    run_tests: bool,
    subcommands: &[&str],
    dispatch: &dyn Fn(&str) -> Fallible<()>,
) -> Fallible<()> {
    let root = Path::new(".");
    let deny_text = match std::fs::read_to_string(root.join(PUBLISH_DENY_FILE)) {
        Ok(text) => text,
        Err(e) => std::env::var(PUBLISH_DENY_ENV).map_err(|_| {
            format!(
                "{PUBLISH_DENY_FILE}: {e}, and {PUBLISH_DENY_ENV} is not set either. The \
                 file is git-ignored, so a fresh clone does not have one -- which is why \
                 this gate is not a step in ci.yml. The release workflow, which MUST run \
                 it, supplies the list through {PUBLISH_DENY_ENV} from a repository \
                 secret. If you are seeing this on a runner, that secret is missing, and \
                 this gate failing is the correct outcome: nothing publishes."
            )
        })?,
    };
    let denied = publish_denied_strings(&deny_text);
    if denied.is_empty() {
        return Err(format!(
            "{PUBLISH_DENY_FILE} lists no strings, so this check would pass over any \
             tree at all. An empty deny list is not an empty risk."
        )
        .into());
    }

    let files = publish_candidates(root)?;
    if files.is_empty() {
        return Err("git listed no files, so publish-check read nothing and proves nothing".into());
    }

    let mut violations = working_tree_violations(root, &files, &denied);

    let (history, blobs) = history_violations(root, &denied)?;
    violations.extend(history);

    let identities = commit_identities(root)?;
    if identities.is_empty() {
        return Err("no commit identities were read, so that check proves nothing".into());
    }
    violations.extend(identity_violations(
        &identities,
        &denied,
        authorship_acknowledged(&deny_text),
    ));

    // Every other gate this project has. Collected rather than short-circuited:
    // the point of a pre-publication run is to learn everything that is wrong
    // in one pass.
    let gates = gates_to_run(subcommands);
    let mut failed_gates = Vec::new();
    for gate in &gates {
        eprintln!("publish-check: running {gate}");
        if let Err(e) = dispatch(gate) {
            failed_gates.push(format!("`xtask {gate}` failed: {e}"));
        }
    }
    violations.extend(failed_gates);

    if run_tests {
        eprintln!("publish-check: running cargo test --workspace");
        let status = Command::new("cargo")
            .args(["test", "--workspace"])
            .status()
            .map_err(|e| format!("running `cargo test --workspace`: {e}"))?;
        if !status.success() {
            violations.push("`cargo test --workspace` failed".into());
        }
    }

    print_manual_gates();

    if !violations.is_empty() {
        eprintln!();
        for v in &violations {
            eprintln!("publish-check: {v}");
        }
        return Err(format!(
            "{} pre-publication violation(s). Nothing here is advisory.",
            violations.len()
        )
        .into());
    }

    if !run_tests {
        return Err(format!(
            "publish-check: NOT DISCHARGED. Everything else passed -- {} denied string(s) \
             over {} working-tree file(s) and {blobs} history blob(s), {} gate(s) -- but \
             `cargo test --workspace` was skipped by `--no-tests`. The pre-publication \
             gate is discharged by a run with no flags and by nothing else; this exits \
             non-zero so that a partial run can never be mistaken for a pass.",
            denied.len(),
            files.len(),
            gates.len(),
        )
        .into());
    }

    println!(
        "publish-check: ok ({} denied string(s) over {} working-tree file(s) and {blobs} \
         history blob(s); {} required file(s); {} required statement(s); {} gate(s); \
         cargo test --workspace green)",
        denied.len(),
        files.len(),
        REQUIRED_FILES.len(),
        REQUIRED_STATEMENTS.len(),
        gates.len(),
    );
    Ok(())
}

fn print_manual_gates() {
    println!();
    println!(
        "publish-check: {} GATE(S) THIS PROGRAM CANNOT DISCHARGE.",
        NOT_MECHANIZABLE.len()
    );
    println!("  A green run above means these were not checked, not that they passed.");
    for (gate, why) in NOT_MECHANIZABLE {
        println!("  - {gate}");
        println!("      {why}");
    }
    println!();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A denied-string fixture assembled at run time.
    ///
    /// It is built from parts for the same reason `phrases.rs`' name fixtures
    /// are: a test that spells out a realistic personal identifier commits one,
    /// which is the defect the module under test exists to prevent.
    fn a_denied_string() -> String {
        format!("{}{}{}", "not", "-a-real-", "identifier")
    }

    fn tree_with(files: &[(&str, &str)]) -> tempfile::TempDir {
        let scratch = tempfile::tempdir().expect("a scratch directory");
        for (path, contents) in files {
            let at = scratch.path().join(path);
            if let Some(parent) = at.parent() {
                std::fs::create_dir_all(parent).expect("a parent directory");
            }
            std::fs::write(&at, contents).expect("writing a fixture file");
        }
        scratch
    }

    /// A tree that satisfies every file- and statement-level check, so each
    /// test below can break exactly one thing.
    fn a_publishable_tree() -> tempfile::TempDir {
        let mut files: Vec<(&str, &str)> = Vec::new();
        for (path, _) in REQUIRED_FILES {
            files.push((path, "placeholder\n"));
        }
        let scratch = tree_with(&files);
        for (path, needle, _) in REQUIRED_STATEMENTS {
            let at = scratch.path().join(path);
            let existing = std::fs::read_to_string(&at).unwrap_or_default();
            std::fs::write(&at, format!("{existing}\n{needle}\n")).expect("a statement");
        }
        scratch
    }

    fn all_required_tracked() -> Vec<Candidate> {
        REQUIRED_FILES
            .iter()
            .map(|(path, _)| Candidate::tracked(path))
            .collect()
    }

    /// The premise every falsifier below rests on: the healthy fixture is
    /// actually healthy. Without this, a test that "catches" a seeded
    /// violation may be catching the fixture's own unrelated breakage.
    #[test]
    fn the_healthy_fixture_has_no_violations() {
        let tree = a_publishable_tree();
        let denied = [a_denied_string()];
        let denied: Vec<&str> = denied.iter().map(String::as_str).collect();
        let found = working_tree_violations(tree.path(), &all_required_tracked(), &denied);
        assert!(found.is_empty(), "{found:#?}");
    }

    // --- AC-7.25: research artifacts and denied strings -------------------

    #[test]
    fn a_tracked_research_artifact_is_rejected_by_name() {
        let denied = [a_denied_string()];
        let denied: Vec<&str> = denied.iter().map(String::as_str).collect();
        for name in [
            "nmap scanner - Google Search.html",
            "nmap scanner - Google Search_files/logo.png",
            "capture.har",
            "page.mhtml",
            "index.html.orig",
        ] {
            let found = artifact_violations(&[Candidate::tracked(name)], &denied);
            assert!(
                found.iter().any(|v| v.contains(name)),
                "`{name}` must be rejected and the message must name the file: {found:#?}"
            );
        }
    }

    #[test]
    fn an_untracked_but_unignored_artifact_is_rejected_and_says_which_it_is() {
        let found = artifact_violations(
            &[Candidate::untracked("Search results - Google Search.html")],
            &[],
        );
        assert!(
            found.iter().any(|v| v.contains("git add -A")),
            "an unignored file is one `git add -A` from being published: {found:#?}"
        );
    }

    #[test]
    fn a_denied_string_in_a_filename_is_rejected_without_being_printed() {
        let needle = a_denied_string();
        let found = artifact_violations(
            &[Candidate::tracked(&format!("docs/{needle}-notes.md"))],
            &[&needle],
        );
        assert_eq!(found.len(), 1, "{found:#?}");
        assert!(
            !found[0].contains(&needle),
            "the message must not reproduce the denied string"
        );
    }

    #[test]
    fn a_denied_string_in_content_is_rejected_with_its_line_and_without_its_text() {
        let needle = a_denied_string();
        let text = format!("fine\nalso fine\ncontact: {needle} here\n");
        let found = content_violations("docs/x.md", &text, &[&needle]);
        assert_eq!(found.len(), 1, "{found:#?}");
        assert!(found[0].contains("docs/x.md:3"), "{found:#?}");
        assert!(
            !found[0].contains(&needle),
            "the message must not reproduce the denied string: {}",
            found[0]
        );
        assert!(
            found[0].contains("entry #1"),
            "the message must say WHICH entry matched, since it cannot say what: {}",
            found[0]
        );
    }

    #[test]
    fn every_secret_pattern_is_caught_and_named() {
        for pattern in SECRET_PATTERNS {
            let suffix: String = "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
                .chars()
                .take(pattern.min_suffix.max(1))
                .collect();
            let text = format!("key = \"{}{suffix}\"\n", pattern.prefix);
            let found = content_violations("config.toml", &text, &[]);
            assert!(
                found
                    .iter()
                    .any(|v| v.contains(pattern.prefix) && v.contains(pattern.what)),
                "`{}` was not caught, or the message does not say what it is: {found:#?}",
                pattern.prefix,
            );
        }
    }

    /// The defect the first real run of this gate found: ninety reported
    /// secrets, every one of them false, because the check matched the *name*
    /// of a secret rather than a secret. Every line below is real text from
    /// this repository.
    #[test]
    fn the_name_of_a_secret_is_not_a_secret() {
        for line in [
            // The plan document's sketch of this very list -- and every
            // historical revision of it, which no marker or path exemption
            // could ever have reached.
            r#"    ("AKIA",                 // AWS access key id prefix"#,
            r#"    "ghp_", "gho_", "github_pat_","#,
            r#"    "xoxb-", "xoxp-",       // Slack"#,
            r#"        "BEGIN RSA PRIVATE KEY","#,
            r#"        "BEGIN OPENSSH PRIVATE KEY","#,
            // `xtask/src/visibility.rs`, where a test name begins with a
            // GitHub token prefix by pure coincidence.
            "    fn ghs_json_is_parsed_and_an_empty_array_is_none_rather_than_an_error() {",
            // Prose.
            "An AKIA prefix identifies a long-lived AWS key.",
        ] {
            let found = content_violations("some/file.rs", &format!("{line}\n"), &[]);
            assert!(
                found.is_empty(),
                "`{line}` is not a credential and must not be reported: {found:#?}"
            );
        }
    }

    /// And the other direction, which is what stops the fix above from being
    /// a way to turn the check off: a real credential on the line after a
    /// sentence about credentials is still caught.
    #[test]
    fn a_credential_is_still_caught_beside_the_prose_that_is_not_one() {
        // Assembled, so this file's own source does not carry a
        // credential-shaped string: `publish-check` runs over `xtask/` like
        // everything else, and a checker that trips itself is one people
        // learn to ignore. Same device as `phrases.rs`' name fixtures.
        let key = format!("{}{}", "AKIA", "IOSFODNN7EXAMPLE");
        let text = format!("An AKIA prefix identifies a key.\nAWS_ACCESS_KEY_ID={key}\n");
        let found = content_violations("notes.md", &text, &[]);
        assert_eq!(found.len(), 1, "{found:#?}");
        assert!(found[0].contains("notes.md:2"), "{}", found[0]);
    }

    /// The placeholder exemption covers the checker and its specification, and
    /// nothing else -- including a manifest, which is the file the check
    /// exists for.
    #[test]
    fn the_placeholder_exemption_covers_the_sketch_and_not_the_manifest() {
        let line = "repository = \"https://github.com/OWNER/bathy\"\n";
        assert!(
            content_violations("Cargo.toml", line, &[]).len() == 1,
            "a manifest is never exempt"
        );
        for exempt in PLACEHOLDER_EXEMPT_PREFIXES {
            assert!(
                content_violations(&format!("{exempt}whatever.md"), line, &[]).is_empty(),
                "`{exempt}` must be exempt"
            );
            assert!(
                content_violations(
                    &format!("history blob abc123 (last seen as `{exempt}whatever.md`)"),
                    line,
                    &[],
                )
                .is_empty(),
                "a historical revision of `{exempt}` must be exempt too -- a marker \
                 cannot be added to a commit that already happened"
            );
        }
    }

    // --- AC-7.28: the leftover placeholder --------------------------------

    #[test]
    fn a_leftover_owner_placeholder_is_rejected() {
        for line in [
            "repository = \"https://github.com/OWNER/bathy\"",
            "see <OWNER> for details",
        ] {
            let found = content_violations("Cargo.toml", &format!("{line}\n"), &[]);
            assert!(
                found.iter().any(|v| v.contains("OWNER")),
                "`{line}` must be rejected: {found:#?}"
            );
        }
    }

    #[test]
    fn the_real_repository_url_is_not_mistaken_for_a_placeholder() {
        let found = content_violations(
            "Cargo.toml",
            "repository = \"https://github.com/russell0/bathy\"\n",
            &[],
        );
        assert!(found.is_empty(), "{found:#?}");
    }

    // --- the home-directory path ------------------------------------------

    #[test]
    fn an_absolute_home_path_is_rejected_without_printing_the_account_name() {
        let line = format!("cd /{}/someaccount/work\n", "Users");
        let found = content_violations("script.sh", &line, &[]);
        assert_eq!(found.len(), 1, "{found:#?}");
        assert!(
            !found[0].contains("someaccount"),
            "the account name must not be echoed: {}",
            found[0]
        );
    }

    #[test]
    fn the_ci_runners_home_is_not_a_violation() {
        let found = content_violations("ci.yml", "working-directory: /home/runner/work\n", &[]);
        assert!(found.is_empty(), "{found:#?}");
    }

    // --- the deny list itself ---------------------------------------------

    #[test]
    fn tracking_the_deny_list_is_rejected_and_says_why() {
        let found = tracked_but_must_not_be(&[Candidate::tracked(PUBLISH_DENY_FILE)]);
        assert_eq!(found.len(), 1, "{found:#?}");
        assert!(
            found[0].contains("publishes all of them at once"),
            "{}",
            found[0]
        );
    }

    #[test]
    fn tracking_the_scratch_directory_is_rejected() {
        let found = tracked_but_must_not_be(&[Candidate::tracked(".superpowers/sdd/report.md")]);
        assert_eq!(found.len(), 1, "{found:#?}");
    }

    #[test]
    fn an_untracked_deny_list_is_fine() {
        assert!(tracked_but_must_not_be(&[Candidate::untracked(PUBLISH_DENY_FILE)]).is_empty());
    }

    // --- AC-7.29: required files and statements ---------------------------

    #[test]
    fn each_required_file_going_missing_is_reported_by_name() {
        for (path, _) in REQUIRED_FILES {
            let tree = a_publishable_tree();
            std::fs::remove_file(tree.path().join(path)).expect("removing one required file");
            let found = required_file_violations(tree.path(), &all_required_tracked());
            assert!(
                found
                    .iter()
                    .any(|v| v.contains(path) && v.contains("does not exist")),
                "removing `{path}` produced no failure naming it: {found:#?}"
            );
        }
    }

    #[test]
    fn a_required_file_that_exists_but_is_untracked_is_reported() {
        let tree = a_publishable_tree();
        let tracked: Vec<Candidate> = REQUIRED_FILES
            .iter()
            .skip(1)
            .map(|(path, _)| Candidate::tracked(path))
            .collect();
        let found = required_file_violations(tree.path(), &tracked);
        let (missing, _) = REQUIRED_FILES.first().expect("a required file");
        assert!(
            found
                .iter()
                .any(|v| v.contains(missing) && v.contains("NOT tracked")),
            "an untracked required file is absent from the published repository: {found:#?}"
        );
    }

    #[test]
    fn each_required_statement_going_missing_is_reported_with_what_was_looked_for() {
        for (path, needle, _) in REQUIRED_STATEMENTS {
            let documents: Vec<(&str, String)> = REQUIRED_STATEMENTS
                .iter()
                .map(|(p, n, _)| (*p, (*n).to_string()))
                .filter(|(p, n)| !(p == path && n == needle))
                .fold(Vec::new(), |mut acc: Vec<(&str, String)>, (p, n)| {
                    match acc.iter_mut().find(|(existing, _)| *existing == p) {
                        Some((_, text)) => text.push_str(&format!("\n{n}")),
                        None => acc.push((p, n)),
                    }
                    acc
                });
            let found = required_statement_violations(&documents);
            assert!(
                found.iter().any(|v| v.contains(needle)),
                "removing {needle:?} from `{path}` produced no failure naming it: {found:#?}"
            );
        }
    }

    // --- the history and the identities -----------------------------------

    #[test]
    fn a_denied_string_in_a_historical_blob_is_reported_as_history() {
        let needle = a_denied_string();
        let found = content_violations(
            "history blob abc123456789 (last seen as `deleted.txt`)",
            &format!("{needle}\n"),
            &[&needle],
        );
        assert_eq!(found.len(), 1, "{found:#?}");
        assert!(found[0].contains("history blob"), "{}", found[0]);
        assert!(found[0].contains("deleted.txt"), "{}", found[0]);
    }

    #[test]
    fn batch_output_is_split_into_blobs_and_a_truncated_stream_stops_rather_than_panics() {
        let mut stream = Vec::new();
        stream.extend_from_slice(b"aaa blob 5\nhello\n");
        stream.extend_from_slice(b"bbb tree 3\nxyz\n");
        stream.extend_from_slice(b"ccc blob 3\nend\n");
        let objects = batch_objects(&stream);
        assert_eq!(objects.len(), 2, "trees are not blobs: {objects:#?}");
        assert_eq!(objects[0].1, b"hello");
        assert_eq!(objects[1].1, b"end");

        // Truncated in the middle of a body, in the header, and empty. None of
        // these may panic: a publication gate that crashes on a malformed
        // object database has no result at all, which is the state most likely
        // to be read as "it did not complain".
        for truncated in [&stream[..12], &stream[..3], &stream[..0]] {
            let _ = batch_objects(truncated);
        }
    }

    #[test]
    fn a_denied_string_in_a_commit_identity_is_reported_and_the_ack_silences_it() {
        let needle = a_denied_string();
        let identities = vec![format!("A Person <{needle}@example.invalid>")];
        let found = identity_violations(&identities, &[&needle], false);
        assert_eq!(found.len(), 1, "{found:#?}");
        assert!(found[0].contains("1 commit(s)"), "{}", found[0]);
        assert!(
            !found[0].contains(&needle),
            "the identity must not be echoed: {}",
            found[0]
        );
        assert!(
            identity_violations(&identities, &[&needle], true).is_empty(),
            "the acknowledgement must silence it, or nobody can ever pass this gate"
        );
    }

    #[test]
    fn the_authorship_acknowledgement_is_recognised_only_as_a_whole_line() {
        assert!(authorship_acknowledged(&format!(
            "# a comment\n{AUTHORSHIP_ACK} these are my own commits\nfoo\n"
        )));
        assert!(!authorship_acknowledged("# nothing here\nfoo\n"));
        assert!(
            !authorship_acknowledged(&format!("a line mentioning {AUTHORSHIP_ACK} in passing\n")),
            "a mention inside a denied string must not acknowledge anything"
        );
    }

    // --- the deny list's own preconditions --------------------------------

    #[test]
    fn comments_and_blanks_are_not_denied_strings() {
        let text = "# a comment\n\n  spaced  \n#another\n";
        assert_eq!(publish_denied_strings(text), vec!["spaced"]);
    }

    // --- the gate list -----------------------------------------------------

    #[test]
    fn every_check_subcommand_is_run_unless_it_is_excluded_with_a_reason() {
        let subcommands = [
            "check-deps",
            "check-lab",
            "check-ci-status",
            "publish-check",
            "emit-schemas",
        ];
        let gates = gates_to_run(&subcommands);
        assert_eq!(gates, vec!["check-deps", "check-lab"]);
        assert!(
            GATES_NOT_RUN.iter().all(|(_, why)| why.len() > 40),
            "an exclusion without a stated reason is how a gate quietly stops running"
        );
    }

    #[test]
    fn the_manual_gate_list_is_not_empty_and_every_entry_says_why() {
        assert!(
            NOT_MECHANIZABLE.len() >= 5,
            "the list of what this cannot see is the part a reader needs most"
        );
        for (gate, why) in NOT_MECHANIZABLE {
            assert!(!gate.is_empty() && why.len() > 60, "{gate}: {why}");
        }
    }

    /// The rule this whole module is arranged around, asserted over its own
    /// source: no personal identifier is written down here.
    ///
    /// It cannot decide personhood -- nothing can -- so it checks the property
    /// that is decidable and that actually failed in this project's plan
    /// documents: every string constant in this file is a generic pattern, and
    /// the specific ones come from a file that is never committed. The
    /// falsifier is direct: paste a deny-list entry into `SECRET_PATTERNS` and
    /// this test goes red.
    /// The same rule for credentials: this file must not itself carry one.
    ///
    /// Not a stylistic point. `publish-check` scans `xtask/` like every other
    /// tracked path, so a literal here makes the gate fail on a clean tree —
    /// which is how a gate becomes something people pass `--no-tests` at and
    /// skim. The falsifier is direct: replace any `concat!` in
    /// [`SECRET_PATTERNS`] with the literal it builds, and this goes red.
    #[test]
    fn the_checkers_own_source_carries_no_credential() {
        let source = include_str!("publish.rs");
        for (number, line) in source.lines().enumerate() {
            for pattern in SECRET_PATTERNS {
                assert!(
                    !carries_secret(line, pattern),
                    "publish.rs:{}: this file carries `{}`, so the gate fails on a clean \
                     tree. Assemble it with `concat!` or `format!` as the others are.",
                    number + 1,
                    pattern.prefix,
                );
            }
        }
    }

    #[test]
    fn this_checkers_source_contains_no_denied_string() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let Ok(deny_text) = std::fs::read_to_string(root.join(PUBLISH_DENY_FILE)) else {
            // A fresh clone has no deny list. That is the documented state and
            // it is not a test failure -- but it must not read as a pass
            // either, so it says so.
            eprintln!(
                "this_checkers_source_contains_no_denied_string: no {PUBLISH_DENY_FILE} on \
                 this machine, so this assertion ranged over nothing"
            );
            return;
        };
        let source = include_str!("publish.rs");
        for (position, needle) in publish_denied_strings(&deny_text).iter().enumerate() {
            assert!(
                !source.to_lowercase().contains(&needle.to_lowercase()),
                "{PUBLISH_DENY_FILE} entry #{} appears in this checker's own source. A \
                 leak detector that hardcodes what it detects publishes it.",
                position + 1,
            );
        }
    }
}
