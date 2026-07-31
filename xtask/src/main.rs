use std::collections::BTreeMap;

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
        Some(other) => Err(format!("unknown xtask: {other}").into()),
        None => Err("usage: xtask <check-deps>".into()),
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
}
