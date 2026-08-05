//! `check-fixtures`: the shapes of "this test depends on state outside its
//! own process" that a checker can actually see.
//!
//! # Why this exists
//!
//! Four instances of one class have now been found here by three different
//! people, and every one of them was found by *reading*:
//!
//! | found in | shape |
//! |---|---|
//! | `8edb833` | `/proc/self/fd` counted in a binary with 104 other tests |
//! | `b7200a6` | four fixtures binding a port, dropping it, and calling it unbound |
//! | `361b843` | three `--ports` ranges inside the kernel's ephemeral window |
//! | `cd754f8` | two tests computing the same `/tmp` path and each deleting it |
//!
//! This project's standing answer to a class that recurs is to mechanize it
//! -- `check-readme`, `check-phrases`, `check-ci`, `ABSENCE_CLAIMS`,
//! `DEFERRALS` all exist because something was found twice. So: four rules,
//! one per shape above, each of which fails on the tree as it was before its
//! fix and passes on the tree as it is now. That property is asserted, not
//! claimed -- [`tests`] below feeds each rule the real pre-fix text.
//!
//! # What these rules are, and are not
//!
//! They are pattern rules over source text, like [`crate::phrases`]'s, and
//! they inherit its sentinel convention: a line that must legitimately
//! contain a flagged shape carries [`SENTINEL`], and
//! `grep -rn '\[fixture-rule\]'` enumerates every exemption in the
//! repository. The marker is weak on purpose. What is not available to a
//! line is silence.
//!
//! They are **not** a claim that this class is now caught. Three of the nine
//! categories the class sweep searched cannot be reduced to a pattern at
//! all, and pretending otherwise is worse than not checking: a green
//! `check-fixtures` would then be read as "no test in this workspace depends
//! on anything outside its process", which is false. What is deliberately
//! out of reach is written down in [`UNCHECKABLE`], next to the rules, so
//! the two are read together -- the same thing `xtask/src/readme.rs` does
//! for the claims its regexes cannot reach and `fuzz/`'s hole list does for
//! the surfaces it does not cover.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

type Fallible<T> = Result<T, Box<dyn std::error::Error>>;

/// A line that legitimately contains a flagged shape says so in its own
/// text. Same convention, and same deliberate weakness, as
/// [`crate::phrases`]'s `[phrase-rule]`.
pub const SENTINEL: &str = "[fixture-rule]";

/// Directories never walked. Build output, VCS state, gitignored scratch,
/// and libFuzzer's working corpus -- the last two by path, because a real
/// source directory may well be called `corpus`.
const NEVER_SCANNED: &[&str] = &["target", ".git", ".superpowers"];
const NEVER_SCANNED_PATHS: &[&str] = &["fuzz/corpus", "fuzz/artifacts"];

/// Roots walked, relative to the repository root.
pub const ROOTS: &[&str] = &["crates", "xtask", "fuzz", "lab", "bench"];

/// Files not walked, each with the criterion that grants it.
///
/// Exactly one, and it is the same argument `PROSE_DISCOVERY_EXCLUSIONS`
/// makes for `xtask/src/main.rs`: this file *is* the statement of every
/// pattern below, so every rule matches it by construction, and checking a
/// rule against its own definition is circular rather than strict. Its
/// fixtures are the pre-fix text of real defects -- that is the point of
/// them -- and a sentinel on each would put the marker on twenty lines and
/// teach the next reader that the marker is decoration.
pub const EXEMPT_FILES: &[(&str, &str)] = &[(
    "xtask/src/fixtures.rs",
    "holds the rules themselves, and every fixture that proves one is by \
     construction an instance of what it forbids",
)];

/// Linux's ephemeral range is `32768-60999` and macOS's is `49152-65535`.
/// A fixed port at or above the lower of the two floors can be handed to a
/// `bind(:0)` by the kernel on at least one platform this repository is
/// developed and tested on, so that is the floor this rule uses.
pub const EPHEMERAL_FLOOR: u32 = 32_768;

/// What this checker deliberately cannot see, so that a green run is not
/// read as a claim it does not make. Printed by a successful run.
pub const UNCHECKABLE: &[(&str, &str)] = &[
    (
        "wall-clock bounds",
        "`elapsed < N ms` is a claim about the machine, and whether it holds depends on \
         what the machine is doing -- which is decided by the test's NEIGHBOURS, in a \
         binary a checker would have to schedule to know. No pattern separates a bound \
         with 10x of headroom from one with 10%.",
    ),
    (
        "ambient environment",
        "`local_ipv4()` needs a default route; `an_unroutable_host_is_reported_down_...` \
         needs TEST-NET-1 to be unrouted; `$HOME` and `$BATHY_STATE_DIR` are read by the \
         binary under test. Each is a precondition of the machine, and a checker on the \
         same machine has no independent way to ask whether it holds.",
    ),
    (
        "fixed ports below the ephemeral floor",
        "`20000-29999` is out of the kernel allocator's reach and still exposed to a \
         foreign daemon. Which one a given box has is not in the source tree.",
    ),
];

// ---------------------------------------------------------------------------
// Text handling.
// ---------------------------------------------------------------------------

/// `src` with every comment replaced by spaces, preserving byte offsets and
/// line numbers.
///
/// Rules that match source *shapes* must not match prose describing them,
/// and this repository's prose describes them at length: `connect.rs` quotes
/// the `bind`/`drop` anti-pattern in a comment, `test_support.rs` reproduces
/// it in a doc-test block, and both would otherwise be reported as the very
/// defect they document. Tracking string literals as well as comments is
/// what keeps `"http://..."` from swallowing the rest of its line.
pub fn strip_comments(src: &str) -> String {
    let b: Vec<char> = src.chars().collect();
    let mut out: Vec<char> = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        // Raw string: r"..." or r#"..."# with any number of hashes.
        if b[i] == 'r' && i + 1 < b.len() && (b[i + 1] == '"' || b[i + 1] == '#') {
            let mut j = i + 1;
            let mut hashes = 0;
            while j < b.len() && b[j] == '#' {
                hashes += 1;
                j += 1;
            }
            if j < b.len() && b[j] == '"' {
                out.push(b[i]);
                for c in b.iter().take(j + 1).skip(i + 1) {
                    out.push(*c);
                }
                let mut k = j + 1;
                loop {
                    if k >= b.len() {
                        i = k;
                        break;
                    }
                    if b[k] == '"' && b[k + 1..].iter().take(hashes).all(|c| *c == '#') {
                        for c in b.iter().take(k + 1 + hashes).skip(k) {
                            out.push(*c);
                        }
                        i = k + 1 + hashes;
                        break;
                    }
                    out.push(b[k]);
                    k += 1;
                }
                continue;
            }
        }
        if b[i] == '"' {
            out.push(b[i]);
            i += 1;
            while i < b.len() {
                out.push(b[i]);
                if b[i] == '\\' && i + 1 < b.len() {
                    out.push(b[i + 1]);
                    i += 2;
                    continue;
                }
                if b[i] == '"' {
                    i += 1;
                    break;
                }
                i += 1;
            }
            continue;
        }
        if b[i] == '\'' && i + 2 < b.len() {
            // A char literal, or a lifetime. Only `'x'` and `'\x'` consume.
            if b[i + 1] == '\\' {
                let mut j = i + 2;
                while j < b.len() && b[j] != '\'' {
                    j += 1;
                }
                for c in b.iter().take((j + 1).min(b.len())).skip(i) {
                    out.push(*c);
                }
                i = j + 1;
                continue;
            }
            if b[i + 2] == '\'' {
                out.extend_from_slice(&b[i..i + 3]);
                i += 3;
                continue;
            }
        }
        if b[i] == '/' && i + 1 < b.len() && b[i + 1] == '/' {
            while i < b.len() && b[i] != '\n' {
                out.push(' ');
                i += 1;
            }
            continue;
        }
        if b[i] == '/' && i + 1 < b.len() && b[i + 1] == '*' {
            let mut depth = 1;
            out.push(' ');
            out.push(' ');
            i += 2;
            while i < b.len() && depth > 0 {
                if b[i] == '/' && i + 1 < b.len() && b[i + 1] == '*' {
                    depth += 1;
                    out.push(' ');
                    out.push(' ');
                    i += 2;
                    continue;
                }
                if b[i] == '*' && i + 1 < b.len() && b[i + 1] == '/' {
                    depth -= 1;
                    out.push(' ');
                    out.push(' ');
                    i += 2;
                    continue;
                }
                out.push(if b[i] == '\n' { '\n' } else { ' ' });
                i += 1;
            }
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    out.into_iter().collect()
}

fn line_of(src: &str, byte_offset: usize) -> usize {
    src[..byte_offset].matches('\n').count() + 1
}

/// Every string literal in `text`, with the line it starts on.
fn string_literals(text: &str) -> Vec<(usize, String)> {
    let b: Vec<char> = text.chars().collect();
    let mut out = Vec::new();
    let mut i = 0;
    let mut line = 1usize;
    while i < b.len() {
        if b[i] == '\n' {
            line += 1;
            i += 1;
            continue;
        }
        if b[i] == '"' {
            let start_line = line;
            let mut s = String::new();
            i += 1;
            while i < b.len() {
                if b[i] == '\\' && i + 1 < b.len() {
                    // A `\` line continuation ends the source line inside
                    // the literal. Not counting it here cost 26 lines of
                    // drift on `mcp.rs` the first time this ran, and a rule
                    // that reports the wrong line is a rule people learn to
                    // ignore.
                    if b[i + 1] == '\n' {
                        line += 1;
                    }
                    s.push(b[i]);
                    s.push(b[i + 1]);
                    i += 2;
                    continue;
                }
                if b[i] == '"' {
                    i += 1;
                    break;
                }
                if b[i] == '\n' {
                    line += 1;
                }
                s.push(b[i]);
                i += 1;
            }
            out.push((start_line, s));
            continue;
        }
        i += 1;
    }
    out
}

// ---------------------------------------------------------------------------
// The findings.
// ---------------------------------------------------------------------------

/// One violation: which rule, where, and what a reader should do about it.
#[derive(Debug, PartialEq, Eq)]
pub struct Finding {
    pub rule: &'static str,
    pub file: String,
    pub line: usize,
    pub detail: String,
}

impl std::fmt::Display for Finding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{}] {}:{}: {}",
            self.rule, self.file, self.line, self.detail
        )
    }
}

// ---------------------------------------------------------------------------
// Rule 1: two scratch paths that are the same path.
// ---------------------------------------------------------------------------

/// The literal text a `std::env::temp_dir()` expression builds, per site.
///
/// The name after `temp_dir()` is everything a checker can compare: the
/// runtime parts (`process::id()`, a counter) are what a reader mistakes for
/// uniqueness. A process id is unique per *process*, and two tests in one
/// binary share one.
pub fn scratch_path_keys(code: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    for (at, _) in code.match_indices("temp_dir()") {
        let rest = &code[at + "temp_dir()".len()..];
        let end = rest.find(';').unwrap_or(rest.len());
        let stmt = &rest[..end];
        if !stmt.contains("join") {
            continue;
        }
        let key: Vec<String> = string_literals(stmt).into_iter().map(|(_, s)| s).collect();
        if key.is_empty() {
            continue;
        }
        out.push((line_of(code, at), key.join("/")));
    }
    out
}

fn shared_scratch_paths(files: &[(String, String)]) -> Vec<Finding> {
    let mut seen: BTreeMap<String, Vec<(String, usize)>> = BTreeMap::new();
    for (path, code) in files {
        for (line, key) in scratch_path_keys(code) {
            seen.entry(key).or_default().push((path.clone(), line));
        }
    }
    let mut findings = Vec::new();
    for (key, sites) in seen {
        if sites.len() < 2 {
            continue;
        }
        let where_ = sites
            .iter()
            .map(|(p, l)| format!("{p}:{l}"))
            .collect::<Vec<_>>()
            .join(", ");
        for (path, line) in &sites {
            findings.push(Finding {
                rule: "shared-scratch-path",
                file: path.clone(),
                line: *line,
                detail: format!(
                    "the scratch name `{key}` is built in {} places ({where_}). Whatever \
                     varies at runtime -- a process id, a counter -- is shared by every \
                     test in one binary, so these are one directory and libtest runs them \
                     concurrently. Use `tempfile::tempdir()`, which is unique by \
                     construction and removes the tree on the panic paths too.",
                    sites.len()
                ),
            });
        }
    }
    findings
}

// ---------------------------------------------------------------------------
// Rule 2: a port bound, read, released, and then relied upon.
// ---------------------------------------------------------------------------

/// Identifiers bound from a `bind(` call, with the line.
fn bound_listeners(code: &str) -> Vec<(String, usize)> {
    let mut out = Vec::new();
    for (at, _) in code.match_indices("let ") {
        let rest = &code[at + 4..];
        let end = match rest.find(';') {
            Some(e) => e,
            None => continue,
        };
        let stmt = &rest[..end];
        let Some((lhs, rhs)) = stmt.split_once('=') else {
            continue;
        };
        if !rhs.contains("bind(") {
            continue;
        }
        let name = lhs.trim().trim_start_matches("mut ").trim();
        if name.is_empty() || !name.chars().all(|c| c.is_alphanumeric() || c == '_') {
            continue;
        }
        out.push((name.to_string(), line_of(code, at)));
    }
    out
}

/// `let <port> = <listener>.local_addr()...;` -- the port read out of a
/// listener, with the name it was read into.
fn port_readouts(code: &str, listener: &str) -> Vec<String> {
    let needle = format!("{listener}.local_addr()");
    let mut out = Vec::new();
    for (at, _) in code.match_indices(needle.as_str()) {
        let before = &code[..at];
        let Some(let_at) = before.rfind("let ") else {
            continue;
        };
        let stmt = &code[let_at + 4..at];
        if stmt.contains(';') {
            continue;
        }
        let Some((lhs, _)) = stmt.split_once('=') else {
            continue;
        };
        let name = lhs.trim().trim_start_matches("mut ").trim();
        if !name.is_empty() && name.chars().all(|c| c.is_alphanumeric() || c == '_') {
            out.push(name.to_string());
        }
    }
    out
}

/// Whether `name` is used as a whole word on a line after `after_line`.
fn used_after(code: &str, name: &str, after_line: usize) -> Option<usize> {
    for (index, line) in code.lines().enumerate() {
        let number = index + 1;
        if number <= after_line {
            continue;
        }
        if names_word(line, name) {
            return Some(number);
        }
    }
    None
}

/// Whether `text` uses `ident` as a whole identifier rather than as a
/// substring of a longer one. Same boundary rule as `check-deps`'s
/// `names_dependency`, for the same reason: `port` occurs inside
/// `port_state`.
pub fn names_word(text: &str, ident: &str) -> bool {
    let boundary = |c: Option<char>| !c.is_some_and(|c| c.is_alphanumeric() || c == '_');
    text.match_indices(ident).any(|(at, _)| {
        boundary(text[..at].chars().next_back())
            && boundary(text[at + ident.len()..].chars().next())
    })
}

/// A listener bound, its port read out, the listener dropped, and the port
/// still used afterwards.
///
/// The trailing use is what separates the defect from the correct pattern.
/// `scheduler.rs`'s full-backlog fixture also binds, reads and drops -- but
/// it drops *after* the last assertion, releasing a port it has finished
/// with, which is ordinary cleanup. The defect is releasing a port and then
/// continuing to speak about it, and the difference is visible in the source
/// as "is the port named below the `drop`".
pub fn vacated_ports(code: &str) -> Vec<(usize, String, String)> {
    let mut out = Vec::new();
    for (listener, _) in bound_listeners(code) {
        let drop_call = format!("drop({listener})");
        let Some(at) = code.find(drop_call.as_str()) else {
            continue;
        };
        let drop_line = line_of(code, at);
        for port in port_readouts(code, &listener) {
            if let Some(use_line) = used_after(code, &port, drop_line) {
                out.push((drop_line, listener.clone(), format!("{port}:{use_line}")));
            }
        }
    }
    out
}

fn vacated_port_findings(files: &[(String, String)]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (path, code) in files {
        for (line, listener, port) in vacated_ports(code) {
            let (port_name, use_line) = port.split_once(':').expect("formatted above");
            findings.push(Finding {
                rule: "vacated-port",
                file: path.clone(),
                line,
                detail: format!(
                    "`{listener}` is bound, its port is read into `{port_name}`, the \
                     listener is dropped here, and `{port_name}` is still used at line \
                     {use_line}. \"Nothing is listening on that port now\" is a claim \
                     about the whole machine: the moment the listener drops, the port is \
                     back in the kernel's ephemeral pool and any sibling test's \
                     `bind(:0)` can take it. Measured at 16 red runs in 30 under a \
                     narrowed range, and the test that went red was often not this one. \
                     Use `bathy_engine::test_support::closed_port` (or `reserving_listener` \
                     + `seal` if the port must serve first), which keeps the port."
                ),
            });
        }
    }
    findings
}

// ---------------------------------------------------------------------------
// Rule 3: a fixed scan range inside the kernel's ephemeral window.
// ---------------------------------------------------------------------------

/// Port ranges written as `"A-B"` with an endpoint at or above
/// [`EPHEMERAL_FLOOR`].
pub fn ephemeral_ranges(code: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    for (line, literal) in string_literals(code) {
        let Some((a, b)) = literal.split_once('-') else {
            continue;
        };
        if a.is_empty() || b.is_empty() || !a.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        if !b.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let (Ok(a), Ok(b)) = (a.parse::<u32>(), b.parse::<u32>()) else {
            continue;
        };
        if a > b || b > 65_535 {
            continue;
        }
        if a >= EPHEMERAL_FLOOR || b >= EPHEMERAL_FLOOR {
            out.push((line, literal));
        }
    }
    out
}

fn ephemeral_range_findings(
    files: &[(String, String)],
    raw: &BTreeMap<String, String>,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (path, code) in files {
        if !path.starts_with("crates/") {
            continue;
        }
        let source_lines: Vec<&str> = raw[path].lines().collect();
        for (line, literal) in ephemeral_ranges(code) {
            // On the flagged line, or the one above it -- a reason worth
            // writing rarely fits after a comma.
            let exempted = source_lines
                .get(line - 1)
                .is_some_and(|l| l.contains(SENTINEL))
                || (line >= 2
                    && source_lines
                        .get(line - 2)
                        .is_some_and(|l| l.contains(SENTINEL)));
            if exempted {
                continue;
            }
            findings.push(Finding {
                rule: "ephemeral-scan-range",
                file: path.clone(),
                line,
                detail: format!(
                    "the port range `{literal}` reaches into the kernel's ephemeral \
                     window (Linux {EPHEMERAL_FLOOR}-60999, macOS 49152-65535), which is \
                     where every `bind(127.0.0.1:0)` in this workspace lands. A scan over \
                     it connects to whatever a neighbouring test is holding, and the test \
                     that goes red is the neighbour -- observed once already, on a \
                     zero-accept assertion 500 lines from the range that broke it. Move \
                     the range below {EPHEMERAL_FLOOR}, keeping its width, or mark this \
                     line {SENTINEL} if it is not a scan target."
                ),
            });
        }
    }
    findings
}

// ---------------------------------------------------------------------------
// Rule 4: a process-wide counter in a binary with more than one test.
// ---------------------------------------------------------------------------

/// `#[test]` and `#[tokio::test]` attributes.
pub fn test_attribute_count(code: &str) -> usize {
    code.match_indices("#[test]").count() + code.match_indices("#[tokio::test").count()
}

/// Calls that actually READ a path. `/proc/self/` named in an error message
/// (`visibility.rs` names it in the message `linux-gate` prints when Docker
/// is missing) is not a process-wide measurement, and flagging it would put
/// the rule's first real user in the position of exempting a string.
const PATH_READERS: &[&str] = &[
    "read_dir(",
    "read_to_string(",
    "File::open(",
    "metadata(",
    "read(",
];

/// Whether this file reads `/proc/self/` rather than merely mentioning it.
pub fn reads_proc_self(code: &str) -> Option<usize> {
    for (at, _) in code.match_indices("\"/proc/self/") {
        let before = &code[..at];
        if PATH_READERS.iter().any(|r| before.trim_end().ends_with(r)) {
            return Some(at);
        }
    }
    None
}

fn process_wide_findings(files: &[(String, String)]) -> Vec<Finding> {
    let mut findings = Vec::new();
    for (path, code) in files {
        let Some(at) = reads_proc_self(code) else {
            continue;
        };
        let count = test_attribute_count(code);
        if count <= 1 {
            continue;
        }
        findings.push(Finding {
            rule: "process-wide-counter",
            file: path.clone(),
            line: line_of(code, at),
            detail: format!(
                "this file reads `/proc/self/`, which reports the WHOLE PROCESS, and it \
                 declares {count} tests. `cargo test` runs the tests in one binary \
                 concurrently, so the reading includes every other test's descriptors and \
                 the difference gets attributed to whatever this one was measuring. That \
                 exact mistake put `many_open_probes_in_sequence_do_not_leak_the_socket` \
                 red on every Linux CI run for five days, accusing `probe_connect` of a \
                 leak that did not exist -- the reported growth tracked `--test-threads`, \
                 not the probe count. A file that reads `/proc/self/` owns its binary."
            ),
        });
    }
    findings
}

// ---------------------------------------------------------------------------
// The gate.
// ---------------------------------------------------------------------------

fn walk(dir: &Path, into: &mut Vec<PathBuf>) -> std::io::Result<()> {
    if !dir.exists() {
        return Ok(());
    }
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if path.is_dir() {
            if NEVER_SCANNED.contains(&name.as_str())
                || NEVER_SCANNED_PATHS.iter().any(|skip| path.ends_with(skip))
            {
                continue;
            }
            walk(&path, into)?;
        } else if path.extension().is_some_and(|e| e == "rs") {
            into.push(path);
        }
    }
    Ok(())
}

/// Every rule, over the working tree.
pub fn findings_for_tree(root: &Path) -> Fallible<Vec<Finding>> {
    let mut paths = Vec::new();
    for r in ROOTS {
        walk(&root.join(r), &mut paths)?;
    }
    paths.sort();
    let mut raw: BTreeMap<String, String> = BTreeMap::new();
    let mut files: Vec<(String, String)> = Vec::new();
    for path in &paths {
        let relative = path
            .strip_prefix(root)
            .unwrap_or(path)
            .to_string_lossy()
            .into_owned();
        if EXEMPT_FILES.iter().any(|(f, _)| *f == relative) {
            continue;
        }
        let text = std::fs::read_to_string(path).map_err(|e| format!("reading {relative}: {e}"))?;
        files.push((relative.clone(), strip_comments(&text)));
        raw.insert(relative, text);
    }
    let mut findings = shared_scratch_paths(&files);
    findings.extend(vacated_port_findings(&files));
    findings.extend(ephemeral_range_findings(&files, &raw));
    findings.extend(process_wide_findings(&files));
    findings.sort_by(|a, b| (a.file.as_str(), a.line).cmp(&(b.file.as_str(), b.line)));
    Ok(findings)
}

pub fn check_fixtures() -> Fallible<()> {
    let findings = findings_for_tree(Path::new("."))?;
    if findings.is_empty() {
        println!(
            "check-fixtures: ok (4 rule(s) over {} root(s), {} file(s) exempt; {} \
             shape(s) this check cannot see, listed in UNCHECKABLE)",
            ROOTS.len(),
            EXEMPT_FILES.len(),
            UNCHECKABLE.len()
        );
        for (name, why) in UNCHECKABLE {
            println!("check-fixtures:   not checked -- {name}: {why}");
        }
        return Ok(());
    }
    for f in &findings {
        eprintln!("check-fixtures: {f}");
    }
    Err(format!(
        "{} out-of-process test dependency violation(s)",
        findings.len()
    )
    .into())
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- The rules must fire on the real pre-fix text. Each fixture below
    // is the defect as it was actually committed, not a paraphrase: a rule
    // that catches a paraphrase of the bug it was written for is the same
    // decoration this whole class keeps producing. ---

    #[test]
    fn the_two_xtask_tests_that_shared_one_tmp_path_are_reported() {
        // `xtask/src/gates.rs` and `xtask/src/phrases.rs`, verbatim, before
        // `cd754f8`. `NEVER_SCANNED_PATHS.len()` is 2 in both modules, so
        // both computed `<tmp>/bathy-walk-<pid>-2`.
        let site = r#"
            let root = std::env::temp_dir().join(format!(
                "bathy-walk-{}-{}",
                std::process::id(),
                NEVER_SCANNED_PATHS.len()
            ));
        "#;
        let files = vec![
            ("xtask/src/gates.rs".to_string(), site.to_string()),
            ("xtask/src/phrases.rs".to_string(), site.to_string()),
        ];
        let findings = shared_scratch_paths(&files);
        assert_eq!(findings.len(), 2, "{findings:?}");
        assert!(
            findings[0].detail.contains("bathy-walk-{}-{}"),
            "the report must name the colliding path: {}",
            findings[0].detail
        );
    }

    #[test]
    fn two_scratch_paths_that_differ_by_one_literal_are_not_reported() {
        // The near miss, and the reason the key is the literal text: these
        // two DO differ, and a rule that keyed on "uses temp_dir" would
        // fail the whole workspace.
        let files = vec![
            (
                "a.rs".to_string(),
                r#"let d = std::env::temp_dir().join(format!("xtask-prose-empty-{}", pid()));"#
                    .to_string(),
            ),
            (
                "b.rs".to_string(),
                r#"let d = std::env::temp_dir().join(format!("bathy-xtask-fuzz-{}", pid()));"#
                    .to_string(),
            ),
        ];
        assert_eq!(shared_scratch_paths(&files), vec![]);
    }

    #[test]
    fn the_bind_read_drop_fixture_is_reported() {
        // `crates/bathy-engine/src/connect.rs`, verbatim, before `b7200a6`.
        let code = "
            async fn a_refused_connection_reports_closed() {
                let listener = TcpListener::bind(\"127.0.0.1:0\").await.unwrap();
                let port = listener.local_addr().unwrap().port();
                drop(listener);
                let out = probe_connect(ip, port, timeout).await;
                assert_eq!(out, ConnectOutcome::Closed);
            }
        ";
        let hits = vacated_ports(code);
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert_eq!(hits[0].1, "listener");
    }

    #[test]
    fn a_listener_dropped_after_its_port_is_finished_with_is_not_reported() {
        // `scheduler.rs`'s full-backlog fixture: bound, read, and dropped
        // at the END, after every assertion. That is cleanup, not a
        // vacated port, and the difference is exactly "is the port named
        // below the drop". Without this test the rule fails the workspace
        // on a correct fixture, which is how a checker gets disabled.
        let code = "
            let filtered_listener = TcpListener::bind(\"127.0.0.1:0\").await.unwrap();
            let filtered_addr = filtered_listener.local_addr().unwrap();
            let ports = [filtered_addr.port()];
            assert_eq!(count_state(PortState::Filtered), 1);
            drop(filtered_listener);
        ";
        assert_eq!(vacated_ports(code), vec![]);
    }

    #[test]
    fn the_three_cli_scan_ranges_are_reported_and_their_replacements_are_not() {
        // `crates/bathy/tests/cli.rs`, before `361b843` and after it.
        let before = "const A: &str = \"40000-40999\"; const B: &str = \"40000-40099\"; \
                      const C: &str = \"41000-41999\";";
        let after = "const A: &str = \"20000-20999\"; const B: &str = \"20000-20099\"; \
                     const C: &str = \"21000-21999\";";
        assert_eq!(
            ephemeral_ranges(before).len(),
            3,
            "{:?}",
            ephemeral_ranges(before)
        );
        assert_eq!(ephemeral_ranges(after), vec![]);
    }

    #[test]
    fn a_range_that_is_not_a_port_range_is_not_reported() {
        // `80-70000` (a rejected-input fixture, out of the port space) and
        // `100-50` (a reversed range) are both `\\d+-\\d+` and neither is a
        // scan window.
        assert_eq!(
            ephemeral_ranges("\"80-70000\" \"100-50\" \"8000-8100\""),
            vec![]
        );
    }

    #[test]
    fn a_whole_port_space_literal_can_opt_out_by_saying_so() {
        let marked = format!("let all = \"1-65535\"; // {SENTINEL}");
        // The rule itself still sees it -- the exemption is applied against
        // the raw line, so an exemption is always visible in the source.
        assert_eq!(ephemeral_ranges(&marked).len(), 1);
        assert!(marked.contains(SENTINEL));
    }

    #[test]
    fn a_second_test_in_the_proc_self_fd_binary_is_reported() {
        let one = "fn open_fd_count() { std::fs::read_dir(\"/proc/self/fd\"); } #[tokio::test] \
                   async fn only_test() {}";
        let two = format!("{one} #[tokio::test] async fn a_second_one() {{}}");
        assert_eq!(
            process_wide_findings(&[("f.rs".into(), one.into())]),
            vec![]
        );
        let findings = process_wide_findings(&[("f.rs".into(), two)]);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert!(
            findings[0].detail.contains("2 tests"),
            "{}",
            findings[0].detail
        );
    }

    #[test]
    fn prose_that_describes_a_defect_is_not_reported_as_the_defect() {
        // This repository documents every one of these shapes at length,
        // including in a doc-comment code block that reproduces the
        // bind/drop pattern line for line. Without comment stripping the
        // rules fail on their own explanations -- the first CI run in this
        // project's history failed on `ci.yml` itself for the same reason.
        let code = "
            // Was: bind, read the port, drop(listener) -- \"so the port is free\".
            //! let l = TcpListener::bind(\"127.0.0.1:0\").await.unwrap();
            //! let port = l.local_addr().unwrap().port();
            //! drop(l);
            //! probe(port);
            let reserved = closed_port();
        ";
        assert_eq!(vacated_ports(&strip_comments(code)), vec![]);
    }

    #[test]
    fn stripping_comments_leaves_string_literals_alone() {
        let code = "let url = \"http://example.invalid/a\"; // gone\nlet r = r#\"a // b\"#;";
        let stripped = strip_comments(code);
        assert!(stripped.contains("http://example.invalid/a"), "{stripped}");
        assert!(stripped.contains("a // b"), "{stripped}");
        assert!(!stripped.contains("gone"), "{stripped}");
        assert_eq!(stripped.lines().count(), code.lines().count());
    }

    // --- The registries, which a loop over an emptied list would pass
    // silently. Same guard `gates.rs` and `phrases.rs` carry. ---

    #[test]
    fn the_registries_this_check_ranges_over_are_not_empty() {
        assert_eq!(ROOTS.len(), 5, "crates, xtask, fuzz, lab, bench");
        assert_eq!(EXEMPT_FILES.len(), 1, "one exemption, and it is this file");
        assert!(EXEMPT_FILES.iter().all(|(_, why)| why.len() > 40));
        assert_eq!(PATH_READERS.len(), 5);
        assert_eq!(
            UNCHECKABLE.len(),
            3,
            "a shorter list of what this check cannot see is not a stronger check, it is \
             a quieter one"
        );
        assert!(
            UNCHECKABLE
                .iter()
                .all(|(n, w)| !n.is_empty() && w.len() > 80)
        );
    }

    #[test]
    fn this_repositorys_own_tree_is_clean() {
        // The gate, run against the real tree, from the test that ships
        // with it. A rule whose only evidence is a synthetic fixture has
        // never met the codebase it governs.
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("xtask/ has a parent")
            .to_path_buf();
        let findings = findings_for_tree(&root).expect("walking the tree");
        assert!(
            findings.is_empty(),
            "{}",
            findings
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
}
