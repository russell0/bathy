#![forbid(unsafe_code)]

mod prose;
mod readme;

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

/// Crates are listed lowest-level first. A crate may only depend on crates
/// that appear strictly earlier in this list.
const LAYERS: &[&str] = &[
    "bathy-types",
    "bathy-scope",
    "bathy-evidence",
    "bathy-store",
    "bathy-plan",
    "bathy-interpret",
    "bathy-probe",
    "bathy-engine",
    "bathy-packetd",
    "bathy-query",
    "bathy-mcp",
    "bathy",
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
        Some("gen-ports") => gen_ports(),
        Some("check-readme") => readme::check_readme(),
        Some(other) => Err(format!("unknown xtask: {other}").into()),
        None => Err("usage: xtask \
             <check-deps|emit-schemas|check-schemas|check-readme|gen-ports --registry <path>>"
            .into()),
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
    /// The subset of `dependencies` that a downstream consumer of this
    /// package actually builds -- `[dependencies]`, not `[dev-dependencies]`
    /// or `[build-dependencies]`. [`find_pinned_dependency_drift`] needs the
    /// distinction; the layer and forbidden-substring rules deliberately do
    /// not, because a dev-dependency on a higher layer is still a cycle and a
    /// dev-dependency on an inference client still puts one in the repo.
    normal_dependencies: Vec<String>,
}

/// Crates whose documented central claim *is* their direct dependency set,
/// pinned to the set the documentation states.
///
/// `bathy-query`'s purity claim -- "no crate in this layer touches the store,
/// the network, the clock or the filesystem", and it stays true because the
/// graph makes it impossible rather than because anyone remembers -- is a
/// claim about exactly this list. It was stated in four places in prose, and
/// when M5 Task 2 added a fourth dependency all four went on saying three.
/// Prose that counts is prose that rots; this is the source of truth the
/// prose now names instead of counting.
const PINNED_DEPENDENCIES: &[(&str, &[&str])] = &[(
    "bathy-query",
    &[
        "bathy-types",
        "schemars",
        "serde",
        "serde_json",
        "thiserror",
    ],
)];

/// Report every difference between a pinned crate's real direct dependencies
/// and its pinned set, in both directions -- an addition is a purity claim
/// that quietly stopped being true, and a removal is documentation naming a
/// crate that is no longer there. A pinned crate that is not in the workspace
/// at all is reported too: a renamed package must not silently disable its
/// own check.
fn find_pinned_dependency_drift(packages: &[PackageInfo]) -> Vec<String> {
    let mut drift = Vec::new();
    for (name, pinned) in PINNED_DEPENDENCIES {
        let Some(pkg) = packages.iter().find(|p| p.name == *name) else {
            drift.push(format!(
                "{name} has a pinned dependency set but is not in the workspace -- renamed, \
                 or removed without its pin"
            ));
            continue;
        };
        let actual: BTreeSet<&str> = pkg.normal_dependencies.iter().map(String::as_str).collect();
        let expected: BTreeSet<&str> = pinned.iter().copied().collect();
        for added in actual.difference(&expected) {
            drift.push(format!(
                "{name} directly depends on {added}, which is not in its pinned set; \
                 this crate's documented claim is its dependency list, so update both \
                 or drop the dependency"
            ));
        }
        for removed in expected.difference(&actual) {
            drift.push(format!(
                "{name}'s pinned set names {removed}, which it no longer depends on; \
                 the documentation that names it is now wrong"
            ));
        }
    }
    drift
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
            if let Some(own_rank) = own_rank
                && let Some(&dep_rank) = rank.get(dep_name.as_str())
                && dep_rank >= own_rank
            {
                violations.push(format!(
                    "{} depends on {dep_name}, which is not strictly lower in the layer order",
                    pkg.name
                ));
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
        let mut normal_dependencies = Vec::new();
        for dep in pkg["dependencies"].as_array().ok_or("no dependencies")? {
            let dep_name = dep["name"].as_str().ok_or("unnamed dep")?.to_string();
            // `cargo metadata` spells a normal dependency's `kind` as `null`;
            // `"dev"` and `"build"` are the other two.
            if dep["kind"].is_null() {
                normal_dependencies.push(dep_name.clone());
            }
            dependencies.push(dep_name);
        }
        packages.push(PackageInfo {
            name,
            dependencies,
            normal_dependencies,
        });
    }
    Ok(packages)
}

fn check_deps() -> Result<(), Box<dyn std::error::Error>> {
    let meta = std::process::Command::new("cargo")
        .args(["metadata", "--format-version", "1", "--no-deps"])
        .output()?;
    let meta: serde_json::Value = serde_json::from_slice(&meta.stdout)?;
    let packages = parse_packages(&meta)?;
    let mut violations = find_violations(&packages);
    violations.extend(find_pinned_dependency_drift(&packages));

    if violations.is_empty() {
        println!(
            "check-deps: ok ({} crates ranked, {} pinned dependency set(s))",
            count_ranked(&packages),
            PINNED_DEPENDENCIES.len()
        );
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
/// the union of every crate's `schema::all()`, unconditionally. `write == false`
/// ("check-schemas") instead compares what's on disk against what
/// regeneration would produce and fails — naming every drifted file — if
/// they differ. A missing file is treated as drift too (surfaced as an `Err`
/// naming the path, same as any other read failure), not silently skipped,
/// so a schema that was never committed at all is still caught.
fn emit_schemas(write: bool) -> Result<(), Box<dyn std::error::Error>> {
    // Every crate that publishes a wire type owns its own `schema::all()`,
    // and this is the one place they are merged -- so a new published type is
    // drift-checked by the same gate as the first four, rather than growing a
    // second mechanism. `schemars::schema_for!` needs a concrete type, so a
    // type defined in `bathy-query` (M5: `ScanFold`, `ScanDiff`) cannot be
    // named from `bathy-types` without moving the fold below the layer that
    // owns it.
    let schemas = union_schemas(vec![bathy_types::schema::all(), bathy_query::schema::all()])?;
    let dir = Path::new("schemas");
    let drift = diff_or_write(&schemas, dir, write)?;

    // Over every file in the directory, in both modes: a published
    // `description` is contract text an agent reads, and `emit-schemas` must
    // not be able to launder a leaked doc comment into the tree either. See
    // `prose`'s module documentation for why this is not a unit test in the
    // crate that generates the document.
    let leaks = prose::check_dir(dir)?;

    let mut problems = Vec::new();
    if !drift.is_empty() {
        problems.push(format!(
            "schema drift in: {}. Run `cargo run -p xtask -- emit-schemas` and commit.",
            drift.join(", ")
        ));
    }
    if !leaks.is_empty() {
        problems.push(format!(
            "maintainer prose reached a published contract -- make the doc comment a `//` \
             comment, or rewrite it as contract text:\n{}",
            leaks.join("\n")
        ));
    }
    if problems.is_empty() {
        Ok(())
    } else {
        Err(problems.join("\n").into())
    }
}

/// Merge every publishing crate's `schema::all()` into one filename-keyed
/// set, refusing a filename two crates both claim.
///
/// Pure, and separated from [`emit_schemas`] for the same reason
/// `find_violations` and `diff_or_write` are: the collision path is the one
/// that matters and it cannot be reached from the real workspace, where no
/// two crates claim a name. A rule with no way to fail in a test is a rule
/// nobody knows still works.
///
/// Silent overwrite is the failure being prevented. `BTreeMap::insert`
/// returns the displaced value rather than erroring, so a second crate
/// publishing `scan-fold` would replace the first crate's contract, the
/// committed file would follow on the next `emit-schemas`, and every check
/// would stay green.
fn union_schemas(
    sets: Vec<BTreeMap<&'static str, serde_json::Value>>,
) -> Result<BTreeMap<&'static str, serde_json::Value>, Box<dyn std::error::Error>> {
    let mut merged: BTreeMap<&'static str, serde_json::Value> = BTreeMap::new();
    for set in sets {
        for (name, schema) in set {
            if let Some(previous) = merged.insert(name, schema) {
                return Err(
                    format!("two crates both publish `schemas/{name}.json`: {previous}").into(),
                );
            }
        }
    }
    Ok(merged)
}

/// The pure-ish core of [`emit_schemas`]: given the schema set and a target
/// directory, either writes every schema (returning no drift) or reports
/// which files, if any, differ from what writing would produce. Separated
/// from `emit_schemas` (which always points at `bathy_types::schema::all()`
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

/// `gen-ports`: regenerate `data/ports/top-100.txt` and
/// `data/ports/common-1000.txt` from a local copy of the IANA *Service Name
/// and Transport Protocol Port Number Registry* CSV.
///
/// # Clean-room note
///
/// This reads only the file named by `--registry`, which the caller must
/// have fetched from IANA (see `data/ports/README.md`). It never reads,
/// searches for, or consults any Nmap data file, installed or otherwise.
///
/// # The ranking heuristic
///
/// Exactly the two-step ranking documented in `data/ports/README.md`:
///
/// 1. System ports (1-1023, port 0 excluded) with a TCP assignment, ascending.
/// 2. User ports (1024-49151) with a TCP assignment, ascending.
///
/// "Has a TCP assignment" means the registry contains a row for that port
/// with `Transport Protocol == "tcp"` and a non-empty `Service Name` --
/// rows marked `Reserved` or `Unassigned` carry no service name and are
/// excluded, which is what keeps port 0 (always `Reserved` in the registry)
/// out of both datasets even before its own numeric value is checked. See
/// [`rank_ports`] for where each of these rules is enforced.
fn gen_ports() -> Result<(), Box<dyn std::error::Error>> {
    let mut registry: Option<String> = None;
    let mut out_dir = PathBuf::from("data/ports");
    let mut args = std::env::args().skip(2);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--registry" => {
                registry = Some(args.next().ok_or("--registry requires a path argument")?);
            }
            "--out-dir" => {
                out_dir = PathBuf::from(args.next().ok_or("--out-dir requires a path argument")?);
            }
            other => return Err(format!("gen-ports: unknown argument `{other}`").into()),
        }
    }
    let registry_path = registry.ok_or("gen-ports requires --registry <path-to-csv>")?;
    let csv_text = std::fs::read_to_string(&registry_path)
        .map_err(|e| format!("reading registry CSV at {registry_path}: {e}"))?;

    let ranked = rank_ports(&csv_text)?;
    write_datasets(&ranked, &out_dir)?;
    println!(
        "gen-ports: wrote {} ({} ports) and {} ({} ports) from {}",
        out_dir.join("top-100.txt").display(),
        ranked.top_100.len(),
        out_dir.join("common-1000.txt").display(),
        ranked.common_1000.len(),
        registry_path,
    );
    Ok(())
}

/// The two generated datasets. `top_100` and `common_1000` are both prefixes
/// of the same ascending, deduplicated ranking (see [`rank_ports`]), which is
/// what guarantees `top_100` is a strict subset of `common_1000` by
/// construction rather than by a separate check bolted on afterward.
#[derive(Debug)]
struct RankedPorts {
    top_100: Vec<u16>,
    common_1000: Vec<u16>,
}

/// Pure rule logic behind `gen-ports`, exercised directly by tests below
/// against small synthetic CSV fixtures -- mirroring `find_violations` and
/// `diff_or_write` above, this is the I/O-free core the process-shelling
/// parts of `gen_ports` delegate to, so the ranking algorithm itself is
/// testable without a 1MB IANA download on every `cargo test`.
fn rank_ports(csv_text: &str) -> Result<RankedPorts, String> {
    // `flexible(true)`: defensive only. The real IANA file has a consistent
    // 12 columns on every one of its ~14,500 rows (confirmed by parsing it
    // in full before writing this), so this never triggers today -- but a
    // future registry edit that introduces one short row shouldn't make the
    // whole regeneration fail when that row wouldn't have contributed a
    // port anyway.
    let mut reader = csv::ReaderBuilder::new()
        .flexible(true)
        .from_reader(csv_text.as_bytes());
    let headers = reader
        .headers()
        .map_err(|e| format!("reading registry CSV header: {e}"))?
        .clone();
    let col = |name: &str| -> Result<usize, String> {
        headers
            .iter()
            .position(|h| h == name)
            .ok_or_else(|| format!("registry CSV is missing a \"{name}\" column"))
    };
    let service_name_idx = col("Service Name")?;
    let port_number_idx = col("Port Number")?;
    let transport_idx = col("Transport Protocol")?;

    let mut system: BTreeSet<u16> = BTreeSet::new();
    let mut user: BTreeSet<u16> = BTreeSet::new();

    for (row_num, result) in reader.records().enumerate() {
        let record =
            result.map_err(|e| format!("reading registry CSV row {}: {e}", row_num + 2))?;
        if record.get(transport_idx).unwrap_or("").trim() != "tcp" {
            continue;
        }
        if record.get(service_name_idx).unwrap_or("").trim().is_empty() {
            // No service name: "Reserved" or "Unassigned" in the registry's
            // own terms, i.e. not an assignment at all. This is also what
            // excludes port 0, which the registry lists as Reserved.
            continue;
        }
        let port_field = record.get(port_number_idx).unwrap_or("").trim();
        for port in expand_port_field(port_field) {
            match port {
                1..=1023 => {
                    system.insert(port);
                }
                1024..=49151 => {
                    user.insert(port);
                }
                // Port 0, and anything at or above the Dynamic/Private range
                // (49152-65535): out of scope for this heuristic. Port 0 is
                // never a scannable port at all (see `ports::PortError`);
                // dynamic/private ports have no meaningful "assignment" to
                // rank by in the first place.
                _ => {}
            }
        }
    }

    let ranked: Vec<u16> = system.into_iter().chain(user).collect();
    if ranked.len() < 1000 {
        return Err(format!(
            "registry yielded only {} TCP-assigned ports in 1-49151; need at least 1000 to \
             build common-1000 (top-100 needs at least 100)",
            ranked.len()
        ));
    }
    Ok(RankedPorts {
        top_100: ranked[..100].to_vec(),
        common_1000: ranked[..1000].to_vec(),
    })
}

/// Expand a registry "Port Number" field into the concrete ports it names:
/// a single integer (`"22"`), an inclusive range (`"6000-6063"`, e.g. the
/// registry's own `x11` entry), or nothing (a blank field, for a service
/// registered without a specific port yet -- about 360 rows in the current
/// registry). A malformed range (reversed, or a side that doesn't parse) is
/// treated the same as a blank field: `rank_ports` only needs the ports a
/// row legitimately identifies, not to validate every row in the registry,
/// and every value this function has actually been observed to receive
/// besides these three shapes fits one of them (checked against the full
/// downloaded file before writing this).
fn expand_port_field(field: &str) -> Vec<u16> {
    if field.is_empty() {
        return Vec::new();
    }
    if let Ok(p) = field.parse::<u16>() {
        return vec![p];
    }
    if let Some((a, b)) = field.split_once('-')
        && let (Ok(a), Ok(b)) = (a.trim().parse::<u16>(), b.trim().parse::<u16>())
        && a <= b
    {
        return (a..=b).collect();
    }
    Vec::new()
}

/// Write both dataset files under `dir`, creating it if necessary.
fn write_datasets(ranked: &RankedPorts, dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("creating {}: {e}", dir.display()))?;
    write_dataset(&dir.join("top-100.txt"), &ranked.top_100)?;
    write_dataset(&dir.join("common-1000.txt"), &ranked.common_1000)?;
    Ok(())
}

fn write_dataset(path: &Path, ports: &[u16]) -> Result<(), String> {
    let mut body = String::from(
        "# Generated by `cargo run -p xtask -- gen-ports`. Do not hand-edit --\n\
         # see data/ports/README.md for provenance and regeneration.\n",
    );
    for p in ports {
        body.push_str(&p.to_string());
        body.push('\n');
    }
    std::fs::write(path, body).map_err(|e| format!("writing {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkg(name: &str, deps: &[&str]) -> PackageInfo {
        PackageInfo {
            name: name.to_string(),
            dependencies: deps.iter().map(|d| d.to_string()).collect(),
            normal_dependencies: deps.iter().map(|d| d.to_string()).collect(),
        }
    }

    /// A package whose `[dev-dependencies]` differ from its `[dependencies]`.
    fn pkg_with_dev(name: &str, normal: &[&str], dev: &[&str]) -> PackageInfo {
        PackageInfo {
            name: name.to_string(),
            dependencies: normal.iter().chain(dev).map(|d| d.to_string()).collect(),
            normal_dependencies: normal.iter().map(|d| d.to_string()).collect(),
        }
    }

    /// The real pinned set for `bathy-query`, as a fixture.
    fn pinned_query_deps() -> Vec<&'static str> {
        PINNED_DEPENDENCIES
            .iter()
            .find(|(n, _)| *n == "bathy-query")
            .expect("bathy-query is pinned")
            .1
            .to_vec()
    }

    #[test]
    fn a_crate_matching_its_pinned_dependency_set_is_clean() {
        let packages = vec![pkg("bathy-query", &pinned_query_deps())];
        let drift = find_pinned_dependency_drift(&packages);
        assert!(drift.is_empty(), "unexpected drift: {drift:?}");
    }

    #[test]
    fn a_new_direct_dependency_on_a_pinned_crate_is_reported() {
        // The claim `bathy-query`'s documentation makes is that nothing in
        // its graph can reach a socket, a clock or the filesystem. `tokio`
        // arriving is that claim ceasing to be true.
        let mut deps = pinned_query_deps();
        deps.push("tokio");
        let drift = find_pinned_dependency_drift(&[pkg("bathy-query", &deps)]);
        assert_eq!(drift.len(), 1, "{drift:?}");
        assert!(drift[0].contains("tokio"), "{drift:?}");
        assert!(drift[0].contains("pinned set"), "{drift:?}");
    }

    #[test]
    fn a_dependency_that_disappears_from_a_pinned_crate_is_reported_too() {
        // The other direction: documentation naming a crate that is no
        // longer there is wrong in the same way, and only a two-sided check
        // catches it.
        let deps: Vec<&str> = pinned_query_deps()
            .into_iter()
            .filter(|d| *d != "thiserror")
            .collect();
        let drift = find_pinned_dependency_drift(&[pkg("bathy-query", &deps)]);
        assert_eq!(drift.len(), 1, "{drift:?}");
        assert!(drift[0].contains("thiserror"), "{drift:?}");
    }

    #[test]
    fn a_dev_dependency_does_not_count_against_a_pinned_set() {
        // `bathy-query` really does dev-depend on `bathy-engine` and friends
        // to fold the log of a real scan. The pin is about what a *consumer*
        // builds, which is `[dependencies]` only -- a pin that counted dev
        // dependencies would have to be updated by every new test fixture and
        // would be turned off within a milestone.
        let packages = vec![pkg_with_dev(
            "bathy-query",
            &pinned_query_deps(),
            &["bathy-engine", "tempfile", "tokio", "proptest"],
        )];
        let drift = find_pinned_dependency_drift(&packages);
        assert!(drift.is_empty(), "unexpected drift: {drift:?}");
    }

    #[test]
    fn a_pinned_crate_missing_from_the_workspace_is_reported_not_skipped() {
        // A renamed package must not silently disable its own check.
        let drift = find_pinned_dependency_drift(&[pkg("bathy-types", &[])]);
        assert_eq!(drift.len(), 1, "{drift:?}");
        assert!(drift[0].contains("bathy-query"), "{drift:?}");
        assert!(drift[0].contains("not in the workspace"), "{drift:?}");
    }

    #[test]
    fn parse_packages_separates_dev_dependencies_from_normal_ones() {
        // The `kind` field is the whole basis of the distinction above, so
        // the parse of it is asserted directly rather than assumed.
        let meta = serde_json::json!({"packages": [{
            "name": "bathy-query",
            "dependencies": [
                {"name": "bathy-types", "kind": null},
                {"name": "serde", "kind": null},
                {"name": "bathy-engine", "kind": "dev"},
                {"name": "cc", "kind": "build"},
            ],
        }]});
        let packages = parse_packages(&meta).unwrap();
        assert_eq!(
            packages[0].normal_dependencies,
            vec!["bathy-types", "serde"]
        );
        assert_eq!(
            packages[0].dependencies,
            vec!["bathy-types", "serde", "bathy-engine", "cc"],
            "the layer and forbidden-substring rules still see every kind"
        );
    }

    #[test]
    fn layer_violation_is_detected() {
        // AC-1.1: bathy-types (layer 0) depending on bathy-scope (layer 1)
        // depends on something at or above its own layer.
        let packages = vec![pkg("bathy-types", &["bathy-scope"])];
        let violations = find_violations(&packages);
        assert_eq!(
            violations.len(),
            1,
            "expected exactly one violation: {violations:?}"
        );
        assert!(violations[0].contains("bathy-types depends on bathy-scope"));
    }

    #[test]
    fn same_layer_dependency_is_a_violation() {
        // A crate depending on a peer at its own rank is >= its own layer.
        let packages = vec![pkg("bathy-probe", &["bathy-probe"])];
        let violations = find_violations(&packages);
        assert_eq!(
            violations.len(),
            1,
            "expected exactly one violation: {violations:?}"
        );
    }

    #[test]
    fn strictly_lower_layer_dependency_is_fine() {
        let packages = vec![pkg("bathy-scope", &["bathy-types"])];
        let violations = find_violations(&packages);
        assert!(
            violations.is_empty(),
            "unexpected violations: {violations:?}"
        );
    }

    #[test]
    fn forbidden_substring_dependency_is_detected() {
        // AC-1.2
        let packages = vec![pkg("bathy-probe", &["async-openai"])];
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
        let packages = vec![pkg("bathy-probe", &["serde"])];
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
    fn union_schemas_merges_disjoint_sets() {
        let a = BTreeMap::from([("scan-fold", serde_json::json!({"type": "object"}))]);
        let b = BTreeMap::from([("event", serde_json::json!({"type": "object"}))]);
        let merged = union_schemas(vec![a, b]).unwrap();
        assert_eq!(
            merged.keys().copied().collect::<Vec<_>>(),
            vec!["event", "scan-fold"]
        );
    }

    #[test]
    fn union_schemas_refuses_a_filename_two_crates_both_claim() {
        // Unreachable from the real workspace, which is exactly why it needs
        // a test: `insert` would silently replace one published contract with
        // another and every check downstream would stay green.
        let a = BTreeMap::from([("scan-fold", serde_json::json!({"title": "first"}))]);
        let b = BTreeMap::from([("scan-fold", serde_json::json!({"title": "second"}))]);
        let err = union_schemas(vec![a, b]).unwrap_err().to_string();
        assert!(err.contains("scan-fold.json"), "{err}");
        assert!(err.contains("two crates"), "{err}");
        assert!(
            err.contains("first"),
            "the error must show the contract that would have been overwritten: {err}"
        );
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
        // `bathy_types::schema::all()` would now produce) has changed --
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

    // --- gen-ports: expand_port_field ---------------------------------

    #[test]
    fn expand_port_field_parses_a_single_port() {
        assert_eq!(expand_port_field("22"), vec![22]);
    }

    #[test]
    fn expand_port_field_expands_an_inclusive_range() {
        // The registry's own shape for this: `x11` is listed as `6000-6063`.
        assert_eq!(
            expand_port_field("6000-6063"),
            (6000..=6063).collect::<Vec<u16>>()
        );
    }

    #[test]
    fn expand_port_field_treats_a_blank_field_as_no_ports() {
        assert_eq!(expand_port_field(""), Vec::<u16>::new());
    }

    #[test]
    fn expand_port_field_treats_a_reversed_range_as_no_ports_not_a_panic() {
        assert_eq!(expand_port_field("100-50"), Vec::<u16>::new());
    }

    #[test]
    fn expand_port_field_treats_non_numeric_garbage_as_no_ports_not_a_panic() {
        for garbage in ["http", "n/a", "-", "1-", "-1", "1-2-3"] {
            assert_eq!(expand_port_field(garbage), Vec::<u16>::new(), "{garbage}");
        }
    }

    // --- gen-ports: rank_ports -----------------------------------------

    /// The full 12-column header the real IANA registry uses, in its real
    /// order. `rank_ports` looks columns up by name, not position, but this
    /// keeps the fixture honest about the shape it will actually see.
    const REGISTRY_HEADER: &[&str] = &[
        "Service Name",
        "Port Number",
        "Transport Protocol",
        "Description",
        "Assignee",
        "Contact",
        "Registration Date",
        "Modification Date",
        "Reference",
        "Service Code",
        "Unauthorized Use Reported",
        "Assignment Notes",
    ];

    /// Build a row with every column the real registry has, so the fixture
    /// building code below reads as "the fields that matter" rather than a
    /// wall of empty-string positional arguments.
    fn registry_row(
        service_name: &str,
        port: &str,
        transport: &str,
        description: &str,
    ) -> Vec<String> {
        vec![
            service_name.to_string(),
            port.to_string(),
            transport.to_string(),
            description.to_string(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
        ]
    }

    /// Render rows to CSV text through the real `csv` crate's writer, not by
    /// hand-joining with commas -- this is the same quoting/escaping engine
    /// `rank_ports` reads back with, so a fixture built this way proves
    /// round-tripping through embedded commas, quotes, and newlines the same
    /// way the real IANA file needs (see the module doc on why a naive
    /// `split(',')` was rejected for this task).
    fn render_csv(header: &[&str], rows: &[Vec<String>]) -> String {
        let mut writer = csv::Writer::from_writer(Vec::new());
        writer.write_record(header).unwrap();
        for row in rows {
            writer.write_record(row).unwrap();
        }
        String::from_utf8(writer.into_inner().unwrap()).unwrap()
    }

    /// A registry fixture large enough to produce both real datasets:
    /// `system_count` ascending TCP-named system ports (starting at 1) and
    /// `user_count` ascending TCP-named user ports (starting at 1024), plus
    /// a handful of rows that must each be excluded for a different reason
    /// (see the assertions in the tests that use this).
    fn synthetic_registry(system_count: u16, user_count: u16) -> String {
        let mut rows = Vec::new();
        for p in 1..=system_count {
            rows.push(registry_row(
                &format!("svc-sys-{p}"),
                &p.to_string(),
                "tcp",
                "system",
            ));
        }
        for i in 0..user_count {
            let p = 1024 + i;
            rows.push(registry_row(
                &format!("svc-usr-{p}"),
                &p.to_string(),
                "tcp",
                "user",
            ));
        }
        // Port 0: always Reserved in the real registry (empty service name).
        rows.push(registry_row("", "0", "tcp", "Reserved"));
        // UDP-only port: must not leak into the TCP ranking.
        rows.push(registry_row("udp-only", "9999", "udp", "udp only"));
        // Unassigned in the system range: empty service name, must be excluded.
        rows.push(registry_row("", "777", "tcp", "Unassigned"));
        // A blank Port Number: a real registry pattern for a service that
        // hasn't been assigned a specific port yet.
        rows.push(registry_row("no-port-yet", "", "tcp", "pending"));
        // A ranged assignment, the registry's own `x11`-shaped row, with a
        // quoted, comma- and newline-bearing description -- the exact shape
        // that broke a naive comma-split parse during exploration.
        rows.push(registry_row(
            "x11-like",
            "6000-6063",
            "tcp",
            "X Window System, ports 6000-6063\nsee RFC-ish notes, allegedly",
        ));
        render_csv(REGISTRY_HEADER, &rows)
    }

    #[test]
    fn rank_ports_produces_sorted_unique_prefixed_datasets() {
        let csv_text = synthetic_registry(200, 850); // 1050 total, > 1000
        let ranked = rank_ports(&csv_text).unwrap();

        assert_eq!(ranked.top_100.len(), 100);
        assert_eq!(ranked.common_1000.len(), 1000);

        for name in ["top_100", "common_1000"] {
            let v = if name == "top_100" {
                &ranked.top_100
            } else {
                &ranked.common_1000
            };
            let mut sorted = v.clone();
            sorted.sort_unstable();
            sorted.dedup();
            assert_eq!(*v, sorted, "{name} must be sorted and unique");
        }

        assert!(
            ranked
                .top_100
                .iter()
                .all(|p| ranked.common_1000.contains(p)),
            "top_100 must be a subset of common_1000"
        );

        // System ports precede user ports, exactly as the documented
        // heuristic promises, and the synthetic fixture's system range
        // (1..=200) is entirely inside top_100.
        assert_eq!(ranked.top_100, (1..=100).collect::<Vec<u16>>());

        // Exclusions: port 0, the UDP-only port, the unnamed/Unassigned
        // port, and the blank-port row must never appear.
        assert!(!ranked.common_1000.contains(&0));
        assert!(!ranked.common_1000.contains(&9999));
        assert!(!ranked.common_1000.contains(&777));
    }

    #[test]
    fn rank_ports_expands_a_ranged_row_but_it_does_not_affect_the_top_of_the_ranking() {
        // The synthetic fixture's x11-like row (6000-6063) sits far above
        // both cutoffs (200 system + 850 user tops out at 1873), so it must
        // not appear in either dataset even though it's a legitimate TCP
        // assignment -- this is `rank_ports` correctly using *rank*, not
        // just "is it assigned at all".
        let csv_text = synthetic_registry(200, 850);
        let ranked = rank_ports(&csv_text).unwrap();
        assert!(!ranked.common_1000.contains(&6000));
        assert!(!ranked.common_1000.contains(&6063));
    }

    #[test]
    fn rank_ports_fails_clearly_rather_than_panicking_on_too_little_data() {
        let csv_text = synthetic_registry(5, 5); // 10 total, far under 1000
        let err = rank_ports(&csv_text).unwrap_err();
        assert!(
            err.contains("10") || err.to_lowercase().contains("only"),
            "error should explain the shortfall: {err}"
        );
    }

    #[test]
    fn rank_ports_reports_a_missing_required_column_by_name() {
        let csv_text = render_csv(&["Service Name", "Transport Protocol"], &[]);
        let err = rank_ports(&csv_text).unwrap_err();
        assert!(
            err.contains("Port Number"),
            "error should name the missing column: {err}"
        );
    }

    // --- gen-ports: write_datasets --------------------------------------

    #[test]
    fn write_datasets_writes_both_files_sorted_one_port_per_line() {
        let dir = scratch_dir("gen-ports-write");
        let ranked = RankedPorts {
            top_100: (1..=100).collect(),
            common_1000: (1..=1000).collect(),
        };
        write_datasets(&ranked, &dir).unwrap();

        for (file, expected_len) in [("top-100.txt", 100usize), ("common-1000.txt", 1000)] {
            let text = std::fs::read_to_string(dir.join(file)).unwrap();
            let ports: Vec<u16> = text
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty() && !l.starts_with('#'))
                .map(|l| l.parse().unwrap())
                .collect();
            assert_eq!(ports.len(), expected_len, "{file}");
            let mut sorted = ports.clone();
            sorted.sort_unstable();
            sorted.dedup();
            assert_eq!(
                ports, sorted,
                "{file} must already be sorted and unique on disk"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
