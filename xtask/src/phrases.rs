//! The forbidden-pattern rules, and why they live here rather than in CI.
//!
//! # A check nobody can run locally is a check that goes red and stays red
//!
//! These three rules used to exist only as inline `grep` pipelines inside
//! `.github/workflows/ci.yml`. Every *other* gate in this project is
//! `cargo run -p xtask -- check-<something>`, so an agent or a contributor
//! running "the documented gate commands" ran ten of the eleven and never
//! these. The result was not hypothetical: the AC-2.1 rule exited 1 from
//! `89142bf` -- the middle of M5 -- through the end of the milestone, and six
//! task reports plus one milestone review stated that "both phrase-rule greps"
//! were green. They were not lying about a check they had run; they were
//! reporting a check that had no local form to run.
//!
//! That is a structural defect, not carelessness, and the structural fix is
//! that the rules have exactly one implementation, it is a program, and CI
//! calls it. `ci.yml` now has one step where it had three.
//!
//! # The sentinel convention, applied to every rule
//!
//! A rule enforced by pattern-matching would otherwise fail on its own
//! statement -- the first CI run in this project's history failed on `ci.yml`
//! itself. The overview's Global Constraints therefore establish: *any line
//! that legitimately names a forbidden phrase (to define, test, or enforce the
//! rule) carries the marker `[phrase-rule]`, and every check excludes marked
//! lines.*
//!
//! "Every check" was not true before this module. Only the determinism rule
//! honoured the marker; the AC-2.1 and `unsafe` greps did not, and would fail
//! on any comment that quoted the thing they forbid. That is not academic
//! either -- [`RULES`] below cannot state the AC-2.1 pattern without one of
//! its own literals matching itself. The convention is now applied uniformly,
//! by construction, in [`violations_in_text`].
//!
//! The marker is deliberately weak: any line can opt out by carrying it. It is
//! a convention with an audit trail (`grep -rn '\[phrase-rule\]'` enumerates
//! every exemption in the repository), not a security boundary. What is *not*
//! available to a line is silence -- an exempted line says so in its own text.
//!
//! # Path exemptions are a separate, narrower thing
//!
//! A marker exempts a line of prose that *names* a pattern. A path exemption
//! ([`Rule::exempt_path_prefixes`]) exempts a file that legitimately *does* the
//! forbidden thing: `bathy_types::clock` is where system time is read, and
//! `bathy-packetd` is where `unsafe` is permitted for raw socket syscalls.
//! Both are listed here, in full, with the criterion that grants them.

use std::path::{Path, PathBuf};

use regex::Regex;

type Fallible<T> = Result<T, Box<dyn std::error::Error>>;

/// One forbidden-pattern rule.
pub struct Rule {
    /// Stable identifier, reported with every violation so a failure names
    /// the rule and not only the line.
    pub id: &'static str,
    /// What the rule is for, in one line -- the text a failing build shows.
    pub headline: &'static str,
    /// The pattern, as a `regex` crate expression.
    pub pattern: &'static str,
    /// What to scan, relative to the repository root. A directory is walked;
    /// a plain file is scanned on its own.
    ///
    /// Files matter: AC-7.17's rule covers `docs/` **and `README.md`**, and a
    /// root list that silently ignored the second would have made the rule
    /// cover the one document positioning errors are most likely to reach.
    /// [`a_file_named_as_a_root_is_scanned`] pins it.
    pub roots: &'static [&'static str],
    /// File extensions to consider. `None` means every text file.
    pub extensions: Option<&'static [&'static str]>,
    /// Files and directories that may legitimately contain the pattern *as
    /// code*, by path prefix. Each one is a decision recorded in
    /// [`Rule::exemption_rationale`].
    pub exempt_path_prefixes: &'static [&'static str],
    /// Why those paths are exempt. Printed by `--explain`-less failure too,
    /// so a contributor who trips the rule reads the reasoning rather than
    /// guessing at it.
    pub exemption_rationale: &'static str,
}

/// Directories that are never scanned.
///
/// `target` and `.git` are build and VCS state, and were `--exclude-dir` in
/// the greps this replaces. `.superpowers` is gitignored scratch space for
/// plan execution: it is not part of a CI checkout, so scanning it locally
/// would make the local run *stricter* than CI, which is its own kind of
/// divergence -- a rule that fails only on one developer's machine gets
/// disabled rather than obeyed.
const NEVER_SCANNED: &[&str] = &["target", ".git", ".superpowers"];

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

pub const RULES: &[Rule] = &[
    Rule {
        id: "clock-only-time-and-ids",
        headline: "no direct time/id generation outside Clock (AC-2.1)",
        // `Clock` (crates/bathy-types/src/clock.rs) is the only place
        // permitted to read the system clock or construct a random ULID.
        // Injecting both through `Clock` is what makes an event log
        // byte-comparable between a recorded run and a replayed one; any
        // other call site breaks that guarantee.
        //
        // One of the alternatives below is a plain literal that matches
        // itself in this very file, which is precisely the situation the
        // sentinel exists for -- hence the marker on the pattern line, and
        // on this one, which names it: `ulid::Generator`.  [phrase-rule]
        pattern: r"SystemTime::now\(\)|ulid::Generator|Ulid::new\(", // [phrase-rule]
        roots: &["crates", "xtask"],
        extensions: Some(&["rs"]),
        exempt_path_prefixes: &["crates/bathy-types/src/clock.rs"],
        exemption_rationale: "`bathy_types::clock` is the injection point itself: SystemClock \
                              reads the system clock and drives the ULID generator there so that \
                              nothing else has to. Exempting a second file would mean two answers \
                              to \"what time is it\" in one process, which is the defect the rule \
                              exists to prevent.",
    },
    Rule {
        id: "unsafe-only-in-packetd",
        headline: "no unsafe outside bathy-packetd", // [phrase-rule]
        // Matches `unsafe` followed by a space, `{`, `(`, or end-of-line, so
        // `unsafe fn`, `unsafe{`, `unsafe(no_mangle)`, and a bare trailing  // [phrase-rule]
        // `unsafe` are all caught, not just the space-delimited form. Scans
        // both crates/ and xtask/ -- the binding constraint is "no crate
        // outside bathy-packetd", not "no crate under crates/ outside
        // bathy-packetd".
        //
        // The leading `\b` matters: without it, `unsafe` matches as a plain
        // substring, so `let is_unsafe = true;` (word character `_`
        // immediately before `unsafe`, then a space) false-positives on
        // legitimate code. `\b` requires a transition from a non-word
        // character (or start of line) into `u`, which `is_unsafe` never has.
        // Pinned by `a_word_ending_in_unsafe_is_not_a_violation` below rather
        // than by a comment claiming GNU grep supports the escape.
        pattern: r"\bunsafe([ {(]|$)",
        roots: &["crates", "xtask"],
        extensions: Some(&["rs"]),
        exempt_path_prefixes: &["crates/bathy-packetd/"],
        exemption_rationale: "The Global Constraint is `#![forbid(unsafe_code)]` in every crate \
                              except bathy-packetd, which may use `unsafe` only for raw socket \
                              syscalls and must document every block.",
    },
    Rule {
        id: "no-unscoped-determinism-claim",
        headline: "forbidden unscoped determinism claim",
        // The bracket expression matches the phrase without this line
        // containing it -- the same device the grep this replaces used, kept
        // because it means the rule's own definition needs no exemption at
        // all. `(?i)` is the greps' `-i`.
        pattern: r"(?i)deterministic[ ]results",
        roots: &["."],
        extensions: None,
        exempt_path_prefixes: &[],
        exemption_rationale: "None. The claim is scoped -- deterministic *planning* and \
                              reproducible *interpretation* -- and no file in this repository \
                              may make the unscoped one. A line that must name the phrase to \
                              define, test or enforce the rule carries the [phrase-rule] marker.",
    },
    Rule {
        id: "captured-skip-message",
        headline: "a skip reason printed through libtest's captured stdio (AC-7.32)",
        // libtest captures `print!`/`eprintln!` and DISCARDS the capture for a
        // test that PASSES. A test that skips -- returns early because its
        // precondition (a lab, a daemon, a fixture) is absent -- passes. So a
        // skip announced with `eprintln!` announces nothing without
        // `--nocapture`: the run prints `ok` and the suite reports success
        // having done nothing. That is strictly worse than no test at all,
        // because the green is read as coverage.
        //
        // This has now happened twice in this repository, and the second time
        // it was left standing in the same commit that fixed the first:
        // `crates/bathy/tests/lab_conformance.rs` was converted to
        // `stderr().write_all` while `crates/bathy-probe/src/probes/tls.rs`
        // kept its `eprintln!`, so `lab/run.sh test`'s sixth test reported
        // `ok` on a machine with no lab (M7 Task 1 review, IMPORTANT-1). The
        // sweep that commit describes was looking for exactly this and missed
        // it, which is the argument for a pattern rather than another sweep.
        //
        // `std::io::stderr().write_all(...)` does not go through the capture
        // hook, so the reason is always visible. That is the fix; this rule is
        // what makes forgetting it red.
        //
        // Scope, stated honestly: the general class -- "a test that reports
        // success when its precondition is absent" -- is not decidable by
        // pattern. This catches the one shape that has actually occurred,
        // which is a skip message emitted by a print macro. `[^"]{0,200}`
        // spans newlines, which is what makes it survive `rustfmt` splitting
        // the macro call across lines.  [phrase-rule]
        pattern: r#"(?i)\b(?:e?println)!\s*\(\s*"[^"]{0,200}skip"#, // [phrase-rule]
        roots: &["crates", "xtask"],
        extensions: Some(&["rs"]),
        exempt_path_prefixes: &[],
        exemption_rationale: "None. A skip reason belongs on the process's own stderr via \
                              `std::io::stderr().write_all` followed by `flush`, which libtest \
                              does not capture. If a print macro genuinely must carry the word \
                              (a CLI that reports skipped work to a user, not a test that skips \
                              itself), mark the line -- an exempted line then says so in its own \
                              text.",
    },
    Rule {
        id: "compare-tools-not-people",
        headline: "a named individual in README.md, docs/, or a policy document (AC-7.17)",
        // M7 Task 4's binding positioning rule: this project compares itself
        // to *tools*, publishes measurements, and never argues against a
        // person. The argument "here is an interface designed for a different
        // consumer, here are the numbers" is strictly stronger than any
        // adjective, and an adjective aimed at a human being is what a reader
        // uses to dismiss a whole document.
        //
        // The pattern is written with bracket expressions so that this line
        // does not itself contain either name -- the same device the
        // determinism rule uses one rule up, and for the same reason: a rule
        // whose own definition trips it needs an exemption, and an exemption
        // is a hole. `grep -ri` for either name over this repository returns
        // nothing, which is the property the rule exists to keep.
        //
        // What this is and is not, stated honestly, because the difference
        // matters when someone later reads a green check as proof:
        //
        //   IS: a denylist of the specific names that this project's own
        //       positioning could plausibly reach for, checked over the two
        //       places positioning prose lives.
        //   IS NOT: a detector of personhood. "No document names an
        //       individual in a comparative context" is not decidable by
        //       pattern, and nothing here decides it. A new name written into
        //       a document tomorrow is invisible to this rule until someone
        //       adds it -- exactly the hand-maintained-register limitation
        //       AC-7.7 records about `FUZZ_SURFACES`.
        //
        // Deliberately NOT read out of `.publish-deny`: that file is
        // git-ignored, so a rule sourced from it would scan for nothing in
        // CI, which is the "check that silently covers nothing" defect. The
        // reason those two files hold personal identifiers is that publishing
        // a secret detector publishes the secret; a public figure's public
        // name is not a secret, and the concern here is positioning rather
        // than disclosure.
        pattern: r"(?i)\bf[y]odor\b|\bgordon[ ]lyon\b",
        // M7 Task 5 widened this from `docs/` + `README.md`. The policy
        // documents are where positioning prose is *most* likely to slip:
        // `SECURITY.md` has to explain why evasion is a non-goal without
        // implying that people who build evasive tools are doing something
        // wrong, `CONTRIBUTING.md` has to explain a licence boundary without
        // making it a complaint about whoever chose that licence, and the
        // issue templates decline requests, which is the single most tempting
        // place to editorialise. A rule that covered the documents a stranger
        // reads and not the documents a contributor is told to obey would have
        // covered the wrong half.
        //
        // `.github/ISSUE_TEMPLATE` is the directory rather than the two files
        // a criterion names, so a template added later is covered without
        // anyone remembering to add it here -- the drift a second hand-kept
        // list guarantees.
        roots: &[
            "docs",
            "README.md",
            "SECURITY.md",
            "CONTRIBUTING.md",
            "CODE_OF_CONDUCT.md",
            ".github/ISSUE_TEMPLATE",
        ],
        extensions: None,
        exempt_path_prefixes: &[],
        exemption_rationale: "None. Compare tools, never people, and never claim another project \
                              is bad, badly run or obsolete -- publish the measurement instead. A \
                              line that must name a forbidden name to define, test or enforce this \
                              rule carries the [phrase-rule] marker; there are none in `docs/` or \
                              `README.md` today, and a document that needs one is almost certainly \
                              a document making the argument this rule forbids.",
    },
];

/// The marker that exempts a line. See this module's header.
const SENTINEL: &str = "[phrase-rule]";

#[derive(Debug, PartialEq, Eq)]
pub struct Violation {
    pub rule_id: &'static str,
    pub path: String,
    /// 1-based, as every tool that reports a file position uses.
    pub line: usize,
    pub text: String,
}

impl std::fmt::Display for Violation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{}] {}:{}: {}",
            self.rule_id,
            self.path,
            self.line,
            self.text.trim()
        )
    }
}

/// Whether `path` is exempt from `rule` by path.
///
/// Compares against the repository-relative path with forward slashes, which
/// is the form the rules are written in and the form violations are reported
/// in, so the exemption list reads the same as the output it suppresses.
pub fn is_exempt_path(rule: &Rule, path: &str) -> bool {
    rule.exempt_path_prefixes
        .iter()
        .any(|prefix| path == *prefix || path.starts_with(prefix))
}

/// Compiles `rule`'s pattern in multi-line mode.
///
/// `(?m)` is prepended rather than written into each pattern so that `^` and
/// `$` keep meaning "start/end of line" now that matching runs over the whole
/// file instead of line by line -- `unsafe-only-in-packetd`'s trailing `$`
/// would otherwise silently become "end of file" and stop catching a bare
/// trailing `unsafe`. [phrase-rule]
///
/// Whole-file matching exists because the defect `captured-skip-message`
/// catches does not fit on one line: `rustfmt` puts `eprintln!(` and its
/// message on separate lines, which is exactly how the swallowed skip in
/// `crates/bathy-probe/src/probes/tls.rs` survived a sweep that was looking
/// for it (M7 Task 1 review, IMPORTANT-1).
pub fn compile(rule: &Rule) -> Result<Regex, regex::Error> {
    Regex::new(&format!("(?m){}", rule.pattern))
}

/// Every violation of `rule` in `text`, attributed to `path`.
///
/// Pure: no filesystem, no subprocess. The walk feeds it; the tests feed it
/// directly. Lines carrying the sentinel are skipped here, for every rule,
/// which is where "every check excludes marked lines" is actually true rather
/// than merely written down -- and for a match that spans several lines, the
/// marker on *any* line it covers exempts it, so a multi-line rule cannot be
/// made unexemptable by accident.
///
/// At most one violation is reported per starting line, per rule: a line
/// containing two spellings of the same forbidden thing is one place to fix,
/// not two.
pub fn violations_in_text(rule: &Rule, compiled: &Regex, path: &str, text: &str) -> Vec<Violation> {
    if is_exempt_path(rule, path) {
        return Vec::new();
    }
    // 0-based start offset of every line, so a match offset maps to a line.
    let mut line_starts = vec![0usize];
    line_starts.extend(text.match_indices('\n').map(|(i, _)| i + 1));
    let line_of = |offset: usize| match line_starts.binary_search(&offset) {
        Ok(index) => index,
        Err(index) => index - 1,
    };
    let line_text = |index: usize| {
        let start = line_starts[index];
        let end = text[start..]
            .find('\n')
            .map_or(text.len(), |rel| start + rel);
        &text[start..end]
    };

    let mut violations: Vec<Violation> = Vec::new();
    for m in compiled.find_iter(text) {
        let first = line_of(m.start());
        // `m.end()` is exclusive; a match ending exactly at a newline covers
        // the line before it, not the one after.
        let last = line_of(m.end().saturating_sub(1).max(m.start()));
        if (first..=last).any(|index| line_text(index).contains(SENTINEL)) {
            continue;
        }
        if violations.last().is_some_and(|v| v.line == first + 1) {
            continue;
        }
        violations.push(Violation {
            rule_id: rule.id,
            path: path.to_string(),
            line: first + 1,
            text: line_text(first).to_string(),
        });
    }
    violations
}

/// Repository-relative, forward-slashed.
fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/")
}

/// Every file under `dir`, depth-first, skipping [`NEVER_SCANNED`].
fn walk(dir: &Path, into: &mut Vec<PathBuf>) -> Fallible<()> {
    let mut entries: Vec<_> = std::fs::read_dir(dir)
        .map_err(|e| format!("reading {}: {e}", dir.display()))?
        .collect::<Result<Vec<_>, _>>()?;
    // Sorted so a failure lists violations in the same order on every machine
    // -- an unstable report is one nobody can diff between two runs.
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

/// `grep -I`: a file that is not valid UTF-8 is binary as far as these rules
/// are concerned, and is skipped rather than being an error. Returning `None`
/// rather than lossily decoding means a `.png` whose bytes happen to spell a
/// forbidden phrase is not a violation, which is the behaviour the greps had.
fn text_of(path: &Path) -> Fallible<Option<String>> {
    let bytes = std::fs::read(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
    Ok(String::from_utf8(bytes).ok())
}

fn has_extension(path: &Path, extensions: Option<&[&str]>) -> bool {
    match extensions {
        None => true,
        Some(allowed) => path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| allowed.contains(&e)),
    }
}

/// Run every rule over the tree rooted at `root`, returning what it found.
pub fn scan(root: &Path) -> Fallible<(Vec<Violation>, usize)> {
    let mut violations = Vec::new();
    let mut scanned = 0usize;
    for rule in RULES {
        let compiled =
            compile(rule).map_err(|e| format!("rule {} has an invalid pattern: {e}", rule.id))?;
        let mut files = Vec::new();
        for r in rule.roots {
            let at = root.join(r);
            if at.is_dir() {
                walk(&at, &mut files)?;
            } else if at.is_file() {
                // A root may name a single file. Without this arm a rule
                // declaring `README.md` scans nothing at all and reports
                // success -- the "covers less than it says" shape this
                // repository has now found five times.
                files.push(at);
            }
        }
        for file in files {
            if !has_extension(&file, rule.extensions) {
                continue;
            }
            let Some(text) = text_of(&file)? else {
                continue;
            };
            scanned += 1;
            violations.extend(violations_in_text(
                rule,
                &compiled,
                &relative(root, &file),
                &text,
            ));
        }
    }
    Ok((violations, scanned))
}

/// Every declared root that is neither a directory nor a file under `root`.
///
/// [`scan`] skips a root it cannot find, which is right for the scratch trees
/// the tests build (a fixture exercising one rule should not have to
/// materialise `crates/` to do it) and wrong for the repository, where a root
/// that has moved is coverage that has silently gone away.
///
/// Found by falsifying the widened `compare-tools-not-people` rule in M7 Task
/// 5: with `SECURITY.md` deleted, `check-phrases` printed
/// `ok (5 rules, 684 file reads, 0 violations)`. That is the sixth instance in
/// this repository of a check that covers less than it says it does, and with
/// six roots on one rule a typo in any of them is the same silent hole. So the
/// repository-facing entry point asserts the roots exist, and the pure walk
/// stays permissive.
pub fn missing_roots(root: &Path) -> Vec<String> {
    let mut out = Vec::new();
    for rule in RULES {
        for r in rule.roots {
            let at = root.join(r);
            if !at.is_dir() && !at.is_file() {
                out.push(format!(
                    "rule `{}` declares the root `{r}`, which is neither a directory nor a \
                     file under {}. A root that does not exist scans nothing and reports \
                     success. Either the path moved -- fix it -- or the document is gone, in \
                     which case the rule no longer covers what its headline claims: {}",
                    rule.id,
                    root.display(),
                    rule.headline,
                ));
            }
        }
    }
    out
}

pub fn check_phrases() -> Fallible<()> {
    let root = Path::new(".");
    let absent = missing_roots(root);
    if !absent.is_empty() {
        for a in &absent {
            eprintln!("check-phrases: {a}");
        }
        return Err(format!("{} declared root(s) do not exist", absent.len()).into());
    }
    let (violations, scanned) = scan(root)?;
    if violations.is_empty() {
        println!(
            "check-phrases: ok ({} rules, {scanned} file reads, 0 violations)",
            RULES.len()
        );
        return Ok(());
    }
    for v in &violations {
        eprintln!("check-phrases: {v}");
    }
    // The rationale is printed with the failure, not filed somewhere the
    // person reading a red build has to go and find.
    for rule in RULES {
        if violations.iter().any(|v| v.rule_id == rule.id) {
            eprintln!("\ncheck-phrases: rule `{}` -- {}", rule.id, rule.headline);
            eprintln!("  exemptions: {}", rule.exemption_rationale);
            eprintln!(
                "  a line that must name this pattern to define, test or enforce the rule \
                 carries the {SENTINEL} marker."
            );
        }
    }
    Err(format!("{} forbidden-pattern violation(s)", violations.len()).into())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A gate's own evidence must not depend on whether someone has run the
    /// fuzzer. `fuzz/corpus` is git-ignored working state of thousands of
    /// generated files, and walking it made the reported file count differ
    /// by three times between two checkouts of the same commit.
    #[test]
    fn the_fuzzers_working_state_is_not_walked_and_a_real_corpus_directory_still_is() {
        // `tempfile::tempdir()`, not a name built out of the process id --
        // see the same comment on the namesake in `gates.rs`. The two
        // computed the identical path, in one test binary, and each began
        // and ended by deleting it.
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
        // `scratch` removes the tree on drop, including on the panic paths.
    }

    fn rule(id: &str) -> &'static Rule {
        RULES
            .iter()
            .find(|r| r.id == id)
            .expect("no such rule in RULES")
    }

    fn run(id: &str, path: &str, text: &str) -> Vec<Violation> {
        let r = rule(id);
        violations_in_text(r, &compile(r).unwrap(), path, text)
    }

    /// A name `compare-tools-not-people` forbids, assembled at run time.
    ///
    /// Spelled out as a literal here, this file would be the one place in the
    /// repository where `grep -ri` finds the name -- and a test fixture is a
    /// silly place to lose a property the rule exists to keep. The rule's own
    /// pattern uses the same device for the same reason.
    fn forbidden_name(which: usize) -> String {
        match which {
            0 => format!("F{}odor", "y"),
            _ => format!("Gordon {}yon", "L"),
        }
    }

    /// The exact line that was in the tree, red, for the whole back half of
    /// M5. If this rule ever stops matching it, the defect returns silently.
    #[test]
    fn the_ac_2_1_rule_catches_the_call_that_was_red_for_half_a_milestone() {
        let found = run(
            "clock-only-time-and-ids",
            "crates/bathy-mcp/src/approval.rs",
            "fn now_ms() -> u64 {\n    SystemTime::now()\n        .duration_since(UNIX_EPOCH)\n", // [phrase-rule]
        );
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].line, 2, "the report must name the line");
        assert_eq!(found[0].path, "crates/bathy-mcp/src/approval.rs");
    }

    #[test]
    fn the_ac_2_1_rule_catches_both_id_spellings_too() {
        for (source, why) in [
            ("let mut g = ulid::Generator::new();", "the generator type"), // [phrase-rule]
            ("let id = Ulid::new();", "the constructor ulid 3.x removed"), // [phrase-rule]
        ] {
            assert_eq!(
                run(
                    "clock-only-time-and-ids",
                    "crates/bathy-engine/src/x.rs",
                    source
                )
                .len(),
                1,
                "{why} must be caught: a random id minted outside Clock is as unreplayable \
                 as a timestamp minted outside it"
            );
        }
    }

    #[test]
    fn the_clock_module_may_read_the_system_clock_and_nothing_else_may() {
        let source = "        let d = SystemTime::now().duration_since(UNIX_EPOCH)"; // [phrase-rule]
        assert!(
            run(
                "clock-only-time-and-ids",
                "crates/bathy-types/src/clock.rs",
                source
            )
            .is_empty(),
            "the injection point itself is exempt"
        );
        assert_eq!(
            run(
                "clock-only-time-and-ids",
                "crates/bathy-types/src/ids.rs",
                source
            )
            .len(),
            1,
            "a sibling file in the same crate is not exempt -- the exemption is a path, \
             not a crate"
        );
    }

    #[test]
    fn the_unsafe_rule_catches_every_spelling_the_grep_was_written_for() {
        for source in [
            "unsafe fn raw(&self) {}", // [phrase-rule]
            "    unsafe{ *p }",        // [phrase-rule]
            "#[unsafe(no_mangle)]",    // [phrase-rule]
            "        unsafe",
        ] {
            assert_eq!(
                run(
                    "unsafe-only-in-packetd",
                    "crates/bathy-engine/src/x.rs",
                    source
                )
                .len(),
                1,
                "{source:?} must be caught"
            );
        }
    }

    #[test]
    fn a_word_ending_in_unsafe_is_not_a_violation() {
        // Without the leading `\b` this is a false positive, and a rule that
        // cries wolf on `let is_unsafe = true;` is a rule someone deletes.
        assert!(
            run(
                "unsafe-only-in-packetd",
                "crates/bathy-scope/src/policy.rs",
                "let is_unsafe = true;",
            )
            .is_empty()
        );
    }

    #[test]
    fn packetd_may_use_unsafe_and_its_neighbours_may_not() {
        assert!(
            run(
                "unsafe-only-in-packetd",
                "crates/bathy-packetd/src/socket.rs",
                "unsafe { libc::socket(domain, ty, proto) }", // [phrase-rule]
            )
            .is_empty()
        );
        assert_eq!(
            run(
                "unsafe-only-in-packetd",
                "crates/bathy-engine/src/connect.rs",
                "unsafe { libc::socket(domain, ty, proto) }", // [phrase-rule]
            )
            .len(),
            1
        );
    }

    #[test]
    fn the_determinism_rule_catches_the_unscoped_claim_in_any_case_and_any_file_type() {
        for (path, source) in [
            ("README.md", "bathy produces deterministic results."), // [phrase-rule]
            ("docs/design-paper.md", "DETERMINISTIC RESULTS, always"), // [phrase-rule]
            ("src/lib.rs", "//! Deterministic Results"),            // [phrase-rule]
        ] {
            assert_eq!(
                run("no-unscoped-determinism-claim", path, source).len(),
                1,
                "{path} must be caught"
            );
        }
    }

    #[test]
    fn the_scoped_claim_this_project_actually_makes_is_not_a_violation() {
        for source in [
            "deterministic planning: same request + same manifest -> same plan_hash",
            "reproducible interpretation: same bytes + same engine version -> same findings",
        ] {
            assert!(run("no-unscoped-determinism-claim", "README.md", source).is_empty());
        }
    }

    /// The exact bytes that were in `crates/bathy-probe/src/probes/tls.rs`
    /// when `lab/run.sh test`'s sixth test reported `ok` on a machine with no
    /// lab, having done nothing (M7 Task 1 review, IMPORTANT-1 -- AC-7.32).
    /// `rustfmt` splits the call across lines, which is how a sweep looking
    /// for exactly this shape walked past it.
    #[test]
    fn the_captured_skip_rule_catches_the_swallowed_skip_that_reported_ok() {
        let source = "            Err(e) => {\n\
                      \x20               eprintln!(\n\
                      \x20                   \"skipping: the lab is not reachable at \
                      {LAB_TLS_WEB} ({e}). See lab/README.md.\"\n\
                      \x20               );\n\
                      \x20               return;\n\
                      \x20           }";
        let found = run(
            "captured-skip-message",
            "crates/bathy-probe/src/probes/tls.rs",
            source,
        );
        assert_eq!(
            found.len(),
            1,
            "the swallowed skip must be caught even though `eprintln!(` and its \
             message are on different lines"
        );
        assert_eq!(
            found[0].line, 2,
            "the report must name the macro's own line"
        );
    }

    #[test]
    fn the_captured_skip_rule_catches_the_single_line_spelling_too() {
        for source in [
            r#"    eprintln!("skipping: no docker");"#, // [phrase-rule]
            r#"    println!("Skipping: no docker");"#,  // [phrase-rule]
            r#"    eprintln!("SKIPPED (no lab): {reason}");"#, // [phrase-rule]
        ] {
            assert_eq!(
                run("captured-skip-message", "crates/bathy/tests/x.rs", source).len(),
                1,
                "{source:?} must be caught"
            );
        }
    }

    /// The fix, as it stands in `crates/bathy/tests/lab_conformance.rs`. A
    /// rule that also fired on the correct form would be a rule someone turns
    /// off rather than obeys.
    #[test]
    fn the_uncaptured_skip_the_rule_asks_for_is_not_a_violation() {
        for source in [
            r#"            let _ = err.write_all(format!("\nSKIPPED (no lab): {reason}\n\n").as_bytes());"#,
            r#"    /// `false` means "skip"; a panic means "you asked for the lab"."#,
            r#"    println!("check-lab: ok ({images} image(s))");"#,
        ] {
            assert!(
                run("captured-skip-message", "crates/bathy/tests/x.rs", source).is_empty(),
                "{source:?} must not be caught"
            );
        }
    }

    /// The Global Constraint says *every* check excludes marked lines. Before
    /// this module only one of the three did. This asserts the property over
    /// `RULES` itself, so a rule added later inherits it or fails here.
    #[test]
    fn every_rule_without_exception_honours_the_sentinel() {
        let a_name = forbidden_name(0);
        let offending = [
            ("clock-only-time-and-ids", "    SystemTime::now()"), // [phrase-rule]
            ("unsafe-only-in-packetd", "unsafe fn raw() {}"),     // [phrase-rule]
            ("no-unscoped-determinism-claim", "DETERMINISTIC RESULTS"), // [phrase-rule]
            ("captured-skip-message", r#"eprintln!("skipping: no lab");"#), // [phrase-rule]
            ("compare-tools-not-people", a_name.as_str()),
        ];
        assert_eq!(
            offending.len(),
            RULES.len(),
            "a rule was added without a sentinel case here"
        );
        for (id, source) in offending {
            let path = "docs/some-note.md";
            assert_eq!(
                run(id, path, source).len(),
                1,
                "fixture sanity: {id} must catch this line unmarked"
            );
            assert!(
                run(id, path, &format!("{source}  // {SENTINEL}")).is_empty(),
                "rule {id} does not honour the sentinel"
            );
        }
    }

    #[test]
    fn a_marked_line_is_exempt_only_on_the_line_that_carries_the_marker() {
        let text = format!(
            "let a = 1;  // SystemTime::now() is forbidden {SENTINEL}\nlet b = SystemTime::now();" // [phrase-rule]
        );
        let found = run("clock-only-time-and-ids", "crates/bathy/src/main.rs", &text);
        assert_eq!(found.len(), 1, "the marker must not exempt the whole file");
        assert_eq!(found[0].line, 2);
    }

    /// Whole-file matching would break `unsafe-only-in-packetd` silently if
    /// `(?m)` were dropped: its `$` would mean end-of-*file*, so a bare
    /// trailing `unsafe` anywhere but the last line would stop being caught.
    /// [phrase-rule]
    #[test]
    fn end_of_line_anchors_still_mean_end_of_line_and_not_end_of_file() {
        let text = "        unsafe\nfn later() {}\n";
        let found = run(
            "unsafe-only-in-packetd",
            "crates/bathy-engine/src/x.rs",
            text,
        );
        assert_eq!(found.len(), 1, "a bare trailing `unsafe` on line 1"); // [phrase-rule]
        assert_eq!(found[0].line, 1);
    }

    /// A marker on any line a multi-line match covers exempts that match --
    /// otherwise a rule that spans lines would be unexemptable by whichever
    /// line the author happened to mark.
    #[test]
    fn the_sentinel_exempts_a_multi_line_match_from_any_line_it_covers() {
        let with_marker_on_the_message = format!(
            "eprintln!(\n    \"skipping: illustrative only {SENTINEL}\"\n);\n" // [phrase-rule]
        );
        assert!(
            run(
                "captured-skip-message",
                "crates/bathy/tests/x.rs",
                &with_marker_on_the_message
            )
            .is_empty(),
            "the marker on the second line of the match must exempt it"
        );
        let unmarked = "eprintln!(\n    \"skipping: illustrative only\"\n);\n"; // [phrase-rule]
        assert_eq!(
            run("captured-skip-message", "crates/bathy/tests/x.rs", unmarked).len(),
            1,
            "fixture sanity: without the marker this is a violation"
        );
    }

    /// AC-7.17, in the direction that matters: the rule fires on a name in
    /// either of the two places positioning prose lives, in any case, and it
    /// names the file and the line.
    #[test]
    fn the_positioning_rule_catches_a_named_individual_in_a_document() {
        for which in 0..2 {
            let name = forbidden_name(which);
            for path in ["README.md", "docs/design-paper.md"] {
                for text in [
                    format!("bathy is faster to integrate than {name}'s scanner."),
                    format!("{} wrote it that way.", name.to_uppercase()),
                ] {
                    let found = run("compare-tools-not-people", path, &text);
                    assert_eq!(found.len(), 1, "{path}: {text:?} must be caught");
                    assert_eq!(found[0].path, path);
                    assert_eq!(found[0].line, 1);
                }
            }
        }
    }

    /// The argument this project is allowed to make. A rule that also fired on
    /// the sentences the documents actually contain would be a rule someone
    /// deletes, and the whole positioning position with it.
    #[test]
    fn comparing_tools_and_publishing_measurements_is_not_a_violation() {
        for source in [
            "Nmap has 28 years of community fingerprint contributions; bathy v0.1 has eight.",
            "bathy-connect took 26285 ms; nmap-version took 17819 ms -- 1.5x.",
            "Npcap's license terms are incompatible with this project's redistribution model.",
            "Nmap identified the product at 10.30.0.17:443 and bathy did not.",
        ] {
            assert!(
                run("compare-tools-not-people", "README.md", source).is_empty(),
                "{source:?} must not be caught"
            );
        }
    }

    /// A rule may name a plain file as a root, and it must actually be read.
    ///
    /// This is the arm's own guard: with the `is_file()` branch in [`scan`]
    /// removed, `docs/` is still walked and the README is silently skipped,
    /// so the check reports success over a document carrying the exact thing
    /// it forbids. That is the "covers less than it claims" shape, and it
    /// would land on the single most likely file for a positioning error.
    #[test]
    fn a_file_named_as_a_root_is_scanned() {
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let root = scratch.path();
        std::fs::create_dir_all(root.join("docs")).expect("docs/");
        let name = forbidden_name(1);
        std::fs::write(
            root.join("README.md"),
            format!("bathy compared with {name}'s tool.\n"),
        )
        .expect("README.md");
        std::fs::write(
            root.join("docs/positioning.md"),
            format!("as {name} put it\n"),
        )
        .expect("docs/positioning.md");

        let (violations, _) = scan(root).expect("scanning the scratch tree");
        let mut paths: Vec<&str> = violations
            .iter()
            .filter(|v| v.rule_id == "compare-tools-not-people")
            .map(|v| v.path.as_str())
            .collect();
        paths.sort_unstable();
        assert_eq!(
            paths,
            ["README.md", "docs/positioning.md"],
            "both roots must be read: the directory and the plain file"
        );
    }

    /// Every root every rule declares exists in this repository right now.
    ///
    /// The falsifier, and the reason this test is not decoration: deleting
    /// `SECURITY.md` and re-running `check-phrases` before this landed printed
    /// `ok (5 rules, 684 file reads, 0 violations)`.
    #[test]
    fn every_declared_root_exists_in_this_repository() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let absent = missing_roots(&root);
        assert!(absent.is_empty(), "{}", absent.join("\n"));
    }

    #[test]
    fn a_root_that_does_not_exist_is_reported_with_its_rule() {
        let scratch = tempfile::tempdir().expect("a scratch directory");
        let absent = missing_roots(scratch.path());
        // An empty tree is missing every root, so the check must find at
        // least one per rule and must name the rule that loses coverage.
        assert!(
            absent.len() >= RULES.len(),
            "an empty tree is missing every declared root; only {} were reported",
            absent.len()
        );
        assert!(
            absent
                .iter()
                .any(|a| a.contains("compare-tools-not-people") && a.contains("SECURITY.md")),
            "the report must name both the rule and the root that is gone: {absent:#?}"
        );
    }

    #[test]
    fn a_violation_renders_as_rule_file_and_line() {
        let v = Violation {
            rule_id: "clock-only-time-and-ids",
            path: "crates/bathy-mcp/src/approval.rs".into(),
            line: 286,
            text: "    SystemTime::now()".into(), // [phrase-rule]
        };
        assert_eq!(
            v.to_string(),
            "[clock-only-time-and-ids] crates/bathy-mcp/src/approval.rs:286: SystemTime::now()" // [phrase-rule]
        );
    }

    #[test]
    fn extension_filters_are_what_each_rule_declares() {
        // The two code rules are `--include='*.rs'`; the determinism rule is
        // every text file, which is why a claim in the README is caught.
        assert!(has_extension(Path::new("a/b.rs"), Some(&["rs"])));
        assert!(!has_extension(Path::new("a/b.md"), Some(&["rs"])));
        assert!(has_extension(Path::new("a/b.md"), None));
        assert!(has_extension(Path::new("a/LICENSE"), None));
    }

    /// The rules must hold over the repository, run the way CI runs them.
    /// This is the one test that would have been red for the whole back half
    /// of M5, and the reason it can exist at all is that the rules are a
    /// program now.
    #[test]
    fn the_repository_itself_passes_every_rule() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let (violations, scanned) = scan(&root).expect("scanning the repository");
        assert!(
            scanned > 0,
            "a scan that read no files is a check that proves nothing"
        );
        assert!(
            violations.is_empty(),
            "{} forbidden-pattern violation(s):\n{}",
            violations.len(),
            violations
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("\n")
        );
    }

    #[test]
    fn every_rule_has_a_pattern_that_compiles_and_a_stated_exemption_rationale() {
        for rule in RULES {
            compile(rule)
                .unwrap_or_else(|e| panic!("rule {} has an invalid pattern: {e}", rule.id));
            assert!(
                !rule.exemption_rationale.trim().is_empty(),
                "rule {} exempts paths with no stated reason",
                rule.id
            );
        }
    }
}
