use std::collections::BTreeMap;
use std::path::Path;

/// Crates are listed lowest-level first. A crate may only depend on crates
/// that appear strictly earlier in this list.
const LAYERS: &[&str] = &[
    "sonde-types",
    "sonde-scope",
    "sonde-evidence",
    "sonde-store",
    "sonde-plan",
    "sonde-interpret",
    "sonde-probe",
    "sonde-engine",
    "sonde-packetd",
    "sonde-query",
    "sonde-mcp",
    "sonde-cli",
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    match std::env::args().nth(1).as_deref() {
        Some("check-deps") => check_deps(),
        Some("emit-schemas") => emit_schemas(true),
        Some("check-schemas") => emit_schemas(false),
        Some(other) => Err(format!("unknown xtask: {other}").into()),
        None => Err("usage: xtask <check-deps|emit-schemas|check-schemas>".into()),
    }
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
            if let Some(own_rank) = own_rank {
                if let Some(&dep_rank) = rank.get(dep_name.as_str()) {
                    if dep_rank >= own_rank {
                        violations.push(format!(
                            "{} depends on {dep_name}, which is not strictly lower in the layer order",
                            pkg.name
                        ));
                    }
                }
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
        for dep in pkg["dependencies"].as_array().ok_or("no dependencies")? {
            let dep_name = dep["name"].as_str().ok_or("unnamed dep")?.to_string();
            dependencies.push(dep_name);
        }
        packages.push(PackageInfo { name, dependencies });
    }
    Ok(packages)
}

fn check_deps() -> Result<(), Box<dyn std::error::Error>> {
    let meta = std::process::Command::new("cargo")
        .args(["metadata", "--format-version", "1", "--no-deps"])
        .output()?;
    let meta: serde_json::Value = serde_json::from_slice(&meta.stdout)?;
    let packages = parse_packages(&meta)?;
    let violations = find_violations(&packages);

    if violations.is_empty() {
        println!("check-deps: ok ({} crates ranked)", count_ranked(&packages));
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
/// `sonde_types::schema::all()`, unconditionally. `write == false`
/// ("check-schemas") instead compares what's on disk against what
/// regeneration would produce and fails — naming every drifted file — if
/// they differ. A missing file is treated as drift too (surfaced as an `Err`
/// naming the path, same as any other read failure), not silently skipped,
/// so a schema that was never committed at all is still caught.
fn emit_schemas(write: bool) -> Result<(), Box<dyn std::error::Error>> {
    let schemas = sonde_types::schema::all();
    let drift = diff_or_write(&schemas, Path::new("schemas"), write)?;
    if drift.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "schema drift in: {}. Run `cargo run -p xtask -- emit-schemas` and commit.",
            drift.join(", ")
        )
        .into())
    }
}

/// The pure-ish core of [`emit_schemas`]: given the schema set and a target
/// directory, either writes every schema (returning no drift) or reports
/// which files, if any, differ from what writing would produce. Separated
/// from `emit_schemas` (which always points at `sonde_types::schema::all()`
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

#[cfg(test)]
mod tests {
    use super::*;

    fn pkg(name: &str, deps: &[&str]) -> PackageInfo {
        PackageInfo {
            name: name.to_string(),
            dependencies: deps.iter().map(|d| d.to_string()).collect(),
        }
    }

    #[test]
    fn layer_violation_is_detected() {
        // AC-1.1: sonde-types (layer 0) depending on sonde-scope (layer 1)
        // depends on something at or above its own layer.
        let packages = vec![pkg("sonde-types", &["sonde-scope"])];
        let violations = find_violations(&packages);
        assert_eq!(
            violations.len(),
            1,
            "expected exactly one violation: {violations:?}"
        );
        assert!(violations[0].contains("sonde-types depends on sonde-scope"));
    }

    #[test]
    fn same_layer_dependency_is_a_violation() {
        // A crate depending on a peer at its own rank is >= its own layer.
        let packages = vec![pkg("sonde-probe", &["sonde-probe"])];
        let violations = find_violations(&packages);
        assert_eq!(
            violations.len(),
            1,
            "expected exactly one violation: {violations:?}"
        );
    }

    #[test]
    fn strictly_lower_layer_dependency_is_fine() {
        let packages = vec![pkg("sonde-scope", &["sonde-types"])];
        let violations = find_violations(&packages);
        assert!(
            violations.is_empty(),
            "unexpected violations: {violations:?}"
        );
    }

    #[test]
    fn forbidden_substring_dependency_is_detected() {
        // AC-1.2
        let packages = vec![pkg("sonde-probe", &["async-openai"])];
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
        let packages = vec![pkg("sonde-probe", &["serde"])];
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
        // `sonde_types::schema::all()` would now produce) has changed --
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
}
