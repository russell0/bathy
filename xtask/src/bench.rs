//! AC-7.11 to AC-7.15 — the cross-scanner comparison, and the gate that keeps
//! its published form honest.
//!
//! # What this is for
//!
//! A benchmark against the incumbents is the one artifact in this repository
//! that a reader who does not trust us can check by re-running it. That makes
//! two properties load-bearing, and neither is about speed:
//!
//! 1. **Every tool is asked the same question.** The targets, the port set,
//!    the per-connection timeout and the rate ceiling come from
//!    `lab/ground-truth.json` and `lab/scope.json` — one place — and every
//!    argument vector below is built from them. A comparison run over
//!    different port sets is an anecdote with a table around it.
//! 2. **Accuracy is scored against the lab, never against another scanner.**
//!    `lab/ground-truth.json` was derived from a 65535-port sweep run from
//!    inside `labnet` by a program that shares no code with `bathy` (see
//!    `lab/README.md`). Scoring one tool against another's output would make
//!    the more thorough tool look wrong, and would make our own blind spots
//!    invisible by construction.
//!
//! # The clean-room boundary, restated for this file
//!
//! Running Nmap here is legitimate: it is a benchmark *subject*, and timing it
//! is not deriving from its data. The rule is otherwise unchanged, and it is
//! narrower than "do not run it": no `nmap-service-probes`, `nmap-services` or
//! `nmap-os-db` is read, and **no rule, probe or port list in this repository
//! may be authored, corrected or tuned from Nmap's output.** Its results go in
//! the comparison table and nowhere else. The XML parser below was written
//! from the documented shape of `-oX` output and its fixture is synthetic, so
//! that not even a captured run is checked in.
//!
//! # Why the published document is generated
//!
//! `docs/benchmarks.md` carries a delimited block that is rendered from
//! `bench/results.json`, and `check-bench` re-renders it and fails on drift —
//! the same arrangement as `emit-schemas`/`check-schemas`. Three consecutive
//! milestone reviews in this project found `README.md` asserting things the
//! code did not do; a benchmark document is worse, because its numbers cannot
//! be checked by reading the code at all. Nothing here stops someone editing
//! the prose around the block. It stops the *numbers* drifting from the run
//! that produced them.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::{Deserialize, Serialize};

use crate::gates::FAST_CI_JOB;

type Fallible<T> = Result<T, Box<dyn std::error::Error>>;

pub const GROUND_TRUTH_PATH: &str = "lab/ground-truth.json";
pub const SCOPE_PATH: &str = "lab/scope.json";
pub const RESULTS_PATH: &str = "bench/results.json";
pub const DOC_PATH: &str = "docs/benchmarks.md";
pub const COMPARE_SCRIPT: &str = "bench/compare.sh";

/// The file the per-connection timeout is read out of, so that "every tool
/// got the same timeout" is a statement about the scanner rather than about a
/// number someone typed twice.
pub const SCHEDULER_PATH: &str = "crates/bathy-engine/src/scheduler.rs";

pub const GENERATED_BEGIN: &str = "<!-- BEGIN GENERATED: cargo run -p xtask -- bench-compare -->";
pub const GENERATED_END: &str = "<!-- END GENERATED -->";

// ---------------------------------------------------------------------------
// The lab, as the benchmark asks about it.
// ---------------------------------------------------------------------------

/// The subset of `lab/ground-truth.json` this file needs, parsed once and
/// handed to every argument builder and every scorer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lab {
    /// Every address the scan covers: the hosts *and* the two holes. The
    /// holes are not decoration — a scanner that reports a port open on an
    /// address with no host is wrong in the most expensive direction.
    pub targets: Vec<IpAddr>,
    pub ports: Vec<u16>,
    /// Every `(address, port)` the oracle says is open.
    pub open: BTreeSet<(IpAddr, u16)>,
    /// The endpoints where the oracle establishes a product name, with the
    /// version if it establishes one. `product: null` in the file means the
    /// lab does not establish a product there, so nothing is scored on it.
    pub products: BTreeMap<(IpAddr, u16), Product>,
    /// Endpoints the oracle records as carrying an `identification_gap`:
    /// the lab establishes a product that `bathy` does not report. These are
    /// the losses we already know about before any tool runs.
    pub identification_gaps: BTreeMap<(IpAddr, u16), String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Product {
    pub product: String,
    pub version: Option<String>,
}

impl Lab {
    pub fn parse(json: &str) -> Result<Self, String> {
        let value: serde_json::Value =
            serde_json::from_str(json).map_err(|e| format!("{GROUND_TRUTH_PATH}: {e}"))?;
        let array = |key: &str| -> Result<Vec<serde_json::Value>, String> {
            value
                .get(key)
                .and_then(|v| v.as_array())
                .cloned()
                .ok_or_else(|| format!("{GROUND_TRUTH_PATH} has no `{key}` array"))
        };

        let mut ports = Vec::new();
        for p in array("scanned_ports")? {
            let n = p
                .as_u64()
                .ok_or_else(|| format!("scanned_ports holds a non-number: {p}"))?;
            ports.push(u16::try_from(n).map_err(|_| format!("{n} is not a port"))?);
        }

        let parse_ip = |v: &serde_json::Value| -> Result<IpAddr, String> {
            v.as_str()
                .ok_or_else(|| format!("expected an address string, got {v}"))?
                .parse()
                .map_err(|e| format!("{v} is not an address: {e}"))
        };

        let mut targets = Vec::new();
        let mut open = BTreeSet::new();
        let mut products = BTreeMap::new();
        let mut identification_gaps = BTreeMap::new();
        for host in array("hosts")? {
            let ip = parse_ip(host.get("ip").unwrap_or(&serde_json::Value::Null))?;
            targets.push(ip);
            let listed = host
                .get("open")
                .and_then(|v| v.as_array())
                .ok_or_else(|| format!("host {ip} has no `open` array"))?;
            for entry in listed {
                let port = entry
                    .get("port")
                    .and_then(serde_json::Value::as_u64)
                    .and_then(|n| u16::try_from(n).ok())
                    .ok_or_else(|| format!("host {ip} has an open entry with no port"))?;
                open.insert((ip, port));
                if let Some(product) = entry.get("product").and_then(|v| v.as_str()) {
                    products.insert(
                        (ip, port),
                        Product {
                            product: product.to_owned(),
                            version: entry
                                .get("version")
                                .and_then(|v| v.as_str())
                                .map(str::to_owned),
                        },
                    );
                }
                if let Some(gap) = entry.get("identification_gap").and_then(|v| v.as_str()) {
                    identification_gaps.insert((ip, port), gap.to_owned());
                }
            }
        }
        for absent in array("absent")? {
            targets.push(parse_ip(&absent)?);
        }

        if targets.is_empty() || ports.is_empty() {
            return Err(format!(
                "{GROUND_TRUTH_PATH} yields {} target(s) and {} port(s); a benchmark over \
                 nothing reports every scanner as perfect",
                targets.len(),
                ports.len()
            ));
        }
        Ok(Self {
            targets,
            ports,
            open,
            products,
            identification_gaps,
        })
    }

    /// The addresses, comma-separated. Every tool gets this string or its
    /// space-separated equivalent; nothing builds a target list of its own.
    pub fn targets_csv(&self) -> String {
        self.targets
            .iter()
            .map(IpAddr::to_string)
            .collect::<Vec<_>>()
            .join(",")
    }

    pub fn targets_spaced(&self) -> Vec<String> {
        self.targets.iter().map(IpAddr::to_string).collect()
    }

    pub fn ports_csv(&self) -> String {
        self.ports
            .iter()
            .map(u16::to_string)
            .collect::<Vec<_>>()
            .join(",")
    }
}

/// `maximum_packets_per_second` out of the lab's own scope manifest. The rate
/// ceiling every tool with a rate knob is given is the ceiling the manifest
/// authorizes, not a number chosen here.
pub fn scope_rate_ceiling(json: &str) -> Result<u64, String> {
    let value: serde_json::Value =
        serde_json::from_str(json).map_err(|e| format!("{SCOPE_PATH}: {e}"))?;
    value
        .get("budget_ceiling")
        .and_then(|b| b.get("maximum_packets_per_second"))
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| format!("{SCOPE_PATH} has no budget_ceiling.maximum_packets_per_second"))
}

/// `SchedulerConfig::default`'s `connect_timeout`, in milliseconds, read out
/// of the scheduler's source.
///
/// Read rather than restated. `bathy`'s connect timeout is not configurable
/// from the command line, so the benchmark has to know it in order to give
/// the other tools the same ceiling — and a hand-copied `2000` here would be
/// a second registry of a number that lives somewhere else, which is the
/// defect shape this repository has recorded five times. If the default
/// moves, `check-bench` fails and says the published run is stale, which is
/// true: every timing in it was taken at the old ceiling.
pub fn scheduler_connect_timeout_ms(source: &str) -> Result<u64, String> {
    let at = source
        .find("impl Default for SchedulerConfig")
        .ok_or_else(|| format!("{SCHEDULER_PATH} has no `impl Default for SchedulerConfig`"))?;
    let block = &source[at..];
    let field = block.find("connect_timeout:").ok_or_else(|| {
        format!("{SCHEDULER_PATH}'s `impl Default for SchedulerConfig` sets no connect_timeout")
    })?;
    let rest = &block[field..];
    let end = rest.find(',').unwrap_or(rest.len());
    let expression = &rest[..end];
    let number = |marker: &str| -> Option<u64> {
        let at = expression.find(marker)?;
        let tail = &expression[at + marker.len()..];
        let digits: String = tail.chars().take_while(char::is_ascii_digit).collect();
        digits.parse().ok()
    };
    if let Some(secs) = number("from_secs(") {
        return Ok(secs * 1000);
    }
    if let Some(millis) = number("from_millis(") {
        return Ok(millis);
    }
    Err(format!(
        "{SCHEDULER_PATH}'s default connect_timeout is `{}`, which this reader does not \
         understand. It must be `Duration::from_secs(N)` or `Duration::from_millis(N)`, \
         because the benchmark gives every other tool the same ceiling and cannot do that \
         from an expression it cannot evaluate.",
        expression.trim()
    ))
}

// ---------------------------------------------------------------------------
// The scanners, and the runs each one contributes.
// ---------------------------------------------------------------------------

/// A scanner this comparison covers, present or not.
///
/// The list is fixed at four because that is what AC-7.11 names. What is *not*
/// fixed is which of them are installed: a scanner that is not on `PATH`
/// produces a named "not run" row carrying `remedy`, never a silent omission
/// and never a quiet pass. Install it and re-run `bench/compare.sh`; nothing
/// here changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Scanner {
    pub name: &'static str,
    /// What to look for on `PATH`.
    pub binary: &'static str,
    /// The argument that makes it print its version.
    pub version_arg: &'static str,
    /// What a reader types to make this row real.
    pub remedy: &'static str,
}

pub const SCANNERS: &[Scanner] = &[
    Scanner {
        name: "bathy",
        binary: "bathy",
        version_arg: "--version",
        remedy: "cargo build --release -p bathy (bench/compare.sh does this for you)",
    },
    Scanner {
        name: "nmap",
        binary: "nmap",
        version_arg: "--version",
        remedy: "apt-get install nmap, or BENCH_APT_PACKAGES=\"nmap\" bench/compare.sh",
    },
    Scanner {
        name: "masscan",
        binary: "masscan",
        version_arg: "--version",
        remedy: "BENCH_APT_PACKAGES=\"nmap masscan libpcap0.8\" bench/compare.sh (Debian \
                 packages it, but its package declares no dependency on libpcap and masscan \
                 dlopens it at run time, so masscan alone installs and then refuses to open \
                 an adapter; nothing here installs it for you)",
    },
    Scanner {
        name: "rustscan",
        binary: "rustscan",
        version_arg: "--version",
        remedy: "no Debian package exists; put a Linux rustscan binary in bench/tools/, \
                 which bench/compare.sh prepends to PATH",
    },
];

/// One measured operation. A scanner may contribute several: Nmap's connect
/// scan, its SYN scan and its version scan are three different operations and
/// collapsing them into one row would compare our connect scan against
/// whichever of them happened to be chosen.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Variant {
    pub id: &'static str,
    pub scanner: &'static str,
    /// What the operation is, in words, for the published table.
    pub operation: &'static str,
    /// True where the tool cannot perform this operation without raw-socket
    /// privilege. Reported per run: comparing a tool's unprivileged fallback
    /// against our connect scan as though they were the same operation is the
    /// most common way a scanner benchmark misleads.
    pub needs_raw_sockets: bool,
    /// True where the operation attempts to name the service, so a `0/6`
    /// identification score can be told apart from "did not try".
    pub identifies_services: bool,
}

pub const VARIANTS: &[Variant] = &[
    Variant {
        id: "bathy-ports-only",
        scanner: "bathy",
        operation: "TCP connect scan, service detection off (--no-service-detection)",
        needs_raw_sockets: false,
        identifies_services: false,
    },
    Variant {
        id: "bathy-connect",
        scanner: "bathy",
        operation: "TCP connect scan with service detection (bathy's default)",
        needs_raw_sockets: false,
        identifies_services: true,
    },
    Variant {
        id: "nmap-connect",
        scanner: "nmap",
        operation: "TCP connect scan (-sT), no version detection",
        needs_raw_sockets: false,
        identifies_services: false,
    },
    Variant {
        id: "nmap-syn",
        scanner: "nmap",
        operation: "SYN scan (-sS) — Nmap's own default when privileged",
        needs_raw_sockets: true,
        identifies_services: false,
    },
    Variant {
        id: "nmap-version",
        scanner: "nmap",
        operation: "TCP connect scan with version detection (-sT -sV)",
        needs_raw_sockets: false,
        identifies_services: true,
    },
    Variant {
        id: "masscan-syn",
        scanner: "masscan",
        operation: "SYN scan; masscan has no connect mode and no version detection",
        needs_raw_sockets: true,
        identifies_services: false,
    },
    Variant {
        id: "rustscan-connect",
        scanner: "rustscan",
        operation: "TCP connect scan, no version detection of its own",
        needs_raw_sockets: false,
        identifies_services: false,
    },
];

/// Everything the argument vectors are built from, in one struct so that a
/// test can assert every tool received the same values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Params {
    pub timeout_ms: u64,
    pub rate_ceiling: u64,
    /// Where `bathy` keeps its state for this run. Not part of the
    /// comparison; every scanner writes somewhere.
    pub state_dir: PathBuf,
    pub scope_path: String,
    pub idempotency_key: String,
}

/// The command lines, verbatim (AC-7.13).
///
/// `bathy` needs two: one that scans and one that reads back what it found.
/// Only the first is timed — the second reads a local database and emits no
/// packet, so counting it would charge our scan for our own reporting.
pub fn argv(variant: &Variant, lab: &Lab, params: &Params) -> Vec<Vec<String>> {
    let s = |v: &str| v.to_string();
    let timeout_ms = params.timeout_ms.to_string();
    match variant.id {
        "bathy-connect" | "bathy-ports-only" => vec![
            {
                let mut start = vec![
                    s("bathy"),
                    s("--json"),
                    s("--state-dir"),
                    params.state_dir.display().to_string(),
                    s("scan"),
                    s("start"),
                    s("--scope"),
                    params.scope_path.clone(),
                    s("--idempotency-key"),
                    params.idempotency_key.clone(),
                    s("--targets"),
                    lab.targets_csv(),
                    s("--ports"),
                    lab.ports_csv(),
                    s("--max-packets-per-second"),
                    params.rate_ceiling.to_string(),
                ];
                if variant.id == "bathy-ports-only" {
                    start.push(s("--no-service-detection"));
                }
                start
            },
            vec![
                s("bathy"),
                s("--json"),
                s("--state-dir"),
                params.state_dir.display().to_string(),
                s("result"),
                s("query"),
                s("--scan"),
                s("$SCAN_ID"),
            ],
        ],
        "nmap-connect" | "nmap-syn" | "nmap-version" => {
            let mut out = vec![s("nmap"), s("-n"), s("-Pn")];
            match variant.id {
                "nmap-syn" => out.push(s("-sS")),
                "nmap-version" => {
                    out.push(s("-sT"));
                    out.push(s("-sV"));
                }
                _ => out.push(s("-sT")),
            }
            out.extend([
                s("-p"),
                lab.ports_csv(),
                s("--max-rtt-timeout"),
                format!("{timeout_ms}ms"),
                s("--max-rate"),
                params.rate_ceiling.to_string(),
                s("-oX"),
                s("-"),
            ]);
            out.extend(lab.targets_spaced());
            vec![out]
        }
        "masscan-syn" => {
            let mut out = vec![
                s("masscan"),
                format!("-p{}", lab.ports_csv()),
                s("--rate"),
                params.rate_ceiling.to_string(),
                s("--wait"),
                // masscan's `--wait` is whole seconds of listening after the
                // last packet, rounded up from the same ceiling rather than
                // invented: a sub-second wait would drop replies the other
                // tools are still waiting for.
                params.timeout_ms.div_ceil(1000).to_string(),
                s("-oL"),
                s("-"),
            ];
            out.extend(lab.targets_spaced());
            vec![out]
        }
        "rustscan-connect" => {
            let mut out = vec![s("rustscan"), s("--greppable"), s("--no-config")];
            out.extend([
                s("-a"),
                lab.targets_csv(),
                s("-p"),
                lab.ports_csv(),
                s("-t"),
                timeout_ms.clone(),
            ]);
            vec![out]
        }
        other => panic!("no argument vector for variant `{other}`"),
    }
}

// ---------------------------------------------------------------------------
// What a run observed, and what the lab says about it.
// ---------------------------------------------------------------------------

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Observed {
    pub open: BTreeSet<(IpAddr, u16)>,
    pub identified: BTreeMap<(IpAddr, u16), Identification>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identification {
    pub service: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
}

/// `bathy --json result query`'s document.
pub fn parse_bathy_query(json: &str) -> Result<Observed, String> {
    // The command prints one JSON document per line; the last non-empty line
    // is the result.
    let line = json
        .lines()
        .rev()
        .find(|l| !l.trim().is_empty())
        .ok_or_else(|| "bathy printed nothing on stdout".to_string())?;
    let value: serde_json::Value =
        serde_json::from_str(line).map_err(|e| format!("bathy's output is not JSON: {e}"))?;
    let endpoints = value
        .get("endpoints")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "bathy's result document has no `endpoints` array".to_string())?;
    let mut out = Observed::default();
    for entry in endpoints {
        if entry.get("state").and_then(|v| v.as_str()) != Some("open") {
            continue;
        }
        let ip: IpAddr = entry
            .get("target")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "an endpoint has no target".to_string())?
            .parse()
            .map_err(|e| format!("bathy reported an unparseable target: {e}"))?;
        let port = entry
            .get("endpoint")
            .and_then(|e| e.get("port"))
            .and_then(serde_json::Value::as_u64)
            .and_then(|n| u16::try_from(n).ok())
            .ok_or_else(|| "an endpoint has no port".to_string())?;
        out.open.insert((ip, port));
        if let Some(observation) = entry.get("observation").filter(|v| !v.is_null()) {
            let text = |key: &str| {
                observation
                    .get(key)
                    .and_then(|v| v.as_str())
                    .map(str::to_owned)
            };
            out.identified.insert(
                (ip, port),
                Identification {
                    service: text("service"),
                    product: text("product"),
                    version: text("version"),
                },
            );
        }
    }
    Ok(out)
}

/// Nmap's `-oX` output.
///
/// Hand-written against the documented element shape rather than pulled in as
/// a dependency, and deliberately tolerant: it looks for `<address addr=…>`,
/// `<port … portid=…>`, `<state state=…>` and `<service …>` and ignores
/// everything else, so a new attribute upstream does not break it. What it
/// does *not* do is guess: a run that exits successfully and parses to no
/// open port at all is reported as a harness failure by [`run_variant`],
/// because a parser that silently yields nothing scores a working scanner as
/// having found nothing — which would be the most flattering possible bug for
/// this project to have.
pub fn parse_nmap_xml(xml: &str) -> Observed {
    let mut out = Observed::default();
    let mut host: Option<IpAddr> = None;
    let mut port: Option<u16> = None;
    for tag in xml.split('<') {
        let name = tag.split([' ', '>', '/']).next().unwrap_or("");
        match name {
            "host" => {
                host = None;
                port = None;
            }
            "address" => {
                if attribute(tag, "addrtype").is_none_or(|t| t.starts_with("ipv"))
                    && let Some(addr) = attribute(tag, "addr")
                    && let Ok(ip) = addr.parse::<IpAddr>()
                {
                    host = Some(ip);
                }
            }
            "port" => port = attribute(tag, "portid").and_then(|p| p.parse::<u16>().ok()),
            "state" => {
                if let (Some(ip), Some(p), Some("open")) =
                    (host, port, attribute(tag, "state").as_deref())
                {
                    out.open.insert((ip, p));
                }
            }
            "service" => {
                if let (Some(ip), Some(p)) = (host, port)
                    && out.open.contains(&(ip, p))
                {
                    let named = Identification {
                        service: attribute(tag, "name"),
                        product: attribute(tag, "product"),
                        version: attribute(tag, "version"),
                    };
                    // A bare `name` with no product is Nmap's port-table
                    // guess, not an identification; recorded, but it will not
                    // score a product.
                    out.identified.insert((ip, p), named);
                }
            }
            _ => {}
        }
    }
    out
}

fn attribute(tag: &str, key: &str) -> Option<String> {
    let needle = format!("{key}=\"");
    let at = tag.find(&needle)?;
    let rest = &tag[at + needle.len()..];
    let end = rest.find('"')?;
    Some(unescape_xml(&rest[..end]))
}

fn unescape_xml(text: &str) -> String {
    text.replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

/// masscan's `-oL` list format: `open tcp 80 10.30.0.10 1754320000`.
pub fn parse_masscan_list(text: &str) -> Observed {
    let mut out = Observed::default();
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 || fields[0] != "open" {
            continue;
        }
        if let (Ok(port), Ok(ip)) = (fields[2].parse::<u16>(), fields[3].parse::<IpAddr>()) {
            out.open.insert((ip, port));
        }
    }
    out
}

/// rustscan's `--greppable` format: `10.30.0.10 -> [80,443]`.
pub fn parse_rustscan_greppable(text: &str) -> Observed {
    let mut out = Observed::default();
    for line in text.lines() {
        let Some((left, right)) = line.split_once("->") else {
            continue;
        };
        let Ok(ip) = left.trim().parse::<IpAddr>() else {
            continue;
        };
        let list = right.trim().trim_start_matches('[').trim_end_matches(']');
        for port in list.split(',') {
            if let Ok(port) = port.trim().parse::<u16>() {
                out.open.insert((ip, port));
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Scoring, against the lab and never against another tool.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Accuracy {
    pub expected_open: usize,
    pub found_open: usize,
    pub false_negatives: Vec<String>,
    pub false_positives: Vec<String>,
    /// Endpoints where the oracle establishes a product name.
    pub products_expected: usize,
    pub products_named: usize,
    /// The endpoints where this run named the lab's product, as `ip:port`.
    /// Present because a *count* of identifications hides the case this
    /// benchmark exists to expose: two tools can name five products each and
    /// disagree about which five, which is a loss in both directions that an
    /// aggregate reports as a tie.
    pub products_named_at: Vec<String>,
    pub products_missed: Vec<String>,
    /// Of the endpoints whose oracle entry also carries a version.
    pub versions_expected: usize,
    pub versions_named: usize,
}

/// A product string matches when either name contains the other, folded to
/// lower case: `nginx` against `nginx http server` is agreement about the
/// product, and scoring it as a miss would penalise a tool for being more
/// verbose than the oracle rather than for being wrong.
pub fn product_matches(expected: &str, reported: &str) -> bool {
    let (e, r) = (expected.to_lowercase(), reported.to_lowercase());
    !e.is_empty() && !r.is_empty() && (e.contains(&r) || r.contains(&e))
}

/// A version matches when the oracle's string is a prefix of the reported
/// one, so `10.3` matches `10.3p1` — the same version, spelled with more of
/// the vendor's own suffix.
pub fn version_matches(expected: &str, reported: &str) -> bool {
    !expected.is_empty()
        && reported
            .to_lowercase()
            .starts_with(&expected.to_lowercase())
}

pub fn score(lab: &Lab, observed: &Observed) -> Accuracy {
    let scanned: BTreeSet<u16> = lab.ports.iter().copied().collect();
    let targeted: BTreeSet<IpAddr> = lab.targets.iter().copied().collect();
    let expected: BTreeSet<(IpAddr, u16)> = lab
        .open
        .iter()
        .copied()
        .filter(|(ip, port)| scanned.contains(port) && targeted.contains(ip))
        .collect();

    // Only endpoints inside the scanned set are scored at all: a tool that
    // reports a port nobody asked it about is a finding, but scoring it as a
    // false positive would penalise it for answering a different question.
    let reported: BTreeSet<(IpAddr, u16)> = observed
        .open
        .iter()
        .copied()
        .filter(|(ip, port)| scanned.contains(port) && targeted.contains(ip))
        .collect();

    let show = |(ip, port): &(IpAddr, u16)| format!("{ip}:{port}");
    let false_negatives: Vec<String> = expected.difference(&reported).map(show).collect();
    let false_positives: Vec<String> = reported.difference(&expected).map(show).collect();

    let mut products_named = 0;
    let mut products_named_at = Vec::new();
    let mut products_missed = Vec::new();
    let mut versions_expected = 0;
    let mut versions_named = 0;
    for (key, want) in &lab.products {
        let got = observed.identified.get(key);
        let product = got.and_then(|i| i.product.as_deref());
        if product.is_some_and(|p| product_matches(&want.product, p)) {
            products_named += 1;
            products_named_at.push(show(key));
        } else {
            products_missed.push(format!(
                "{} (lab: {}, reported: {})",
                show(key),
                want.product,
                product.unwrap_or("nothing")
            ));
        }
        if let Some(version) = want.version.as_deref() {
            versions_expected += 1;
            if got
                .and_then(|i| i.version.as_deref())
                .is_some_and(|v| version_matches(version, v))
            {
                versions_named += 1;
            }
        }
    }

    Accuracy {
        expected_open: expected.len(),
        found_open: expected.intersection(&reported).count(),
        false_negatives,
        false_positives,
        products_expected: lab.products.len(),
        products_named,
        products_named_at,
        products_missed,
        versions_expected,
        versions_named,
    }
}

// ---------------------------------------------------------------------------
// The record a run leaves behind.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Results {
    /// One environment for the whole file: AC-7.11 asks for one machine and
    /// one run, and a shape that cannot express two is how that is kept true.
    pub environment: Environment,
    pub parameters: PublishedParams,
    pub scanners: Vec<ScannerStatus>,
    pub runs: Vec<RunRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Environment {
    pub observed_at: String,
    pub host: String,
    pub executed_in: String,
    pub privileged: bool,
    pub repetitions: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublishedParams {
    pub targets: Vec<String>,
    pub ports: Vec<u16>,
    pub timeout_ms: u64,
    pub timeout_source: String,
    pub rate_ceiling: u64,
    pub rate_source: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScannerStatus {
    pub name: String,
    /// `None` when the tool is not installed here.
    pub version: Option<String>,
    pub path: Option<String>,
    pub remedy: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunRecord {
    pub variant: String,
    pub scanner: String,
    pub operation: String,
    pub needs_raw_sockets: bool,
    pub identifies_services: bool,
    /// The verbatim command lines, in order.
    pub command_lines: Vec<String>,
    /// `None` where the tool is absent, with `absent_reason` saying so.
    pub milliseconds: Option<Vec<u64>>,
    pub accuracy: Option<Accuracy>,
    pub absent_reason: Option<String>,
    /// Set where the operation needs raw sockets and could not have them.
    pub privilege_note: Option<String>,
    /// `Tcp: ActiveOpens` delta from `/proc/net/snmp`, where the kernel
    /// offers one.
    pub tcp_active_opens: Option<u64>,
}

impl RunRecord {
    pub fn median_ms(&self) -> Option<u64> {
        let mut times = self.milliseconds.clone()?;
        if times.is_empty() {
            return None;
        }
        times.sort_unstable();
        Some(times[times.len() / 2])
    }
    pub fn ran(&self) -> bool {
        self.absent_reason.is_none()
    }
}

// ---------------------------------------------------------------------------
// Where bathy loses (AC-7.14).
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Loss {
    pub category: String,
    pub detail: String,
}

/// Derived from the run, not asserted by an author.
///
/// A benchmark suite that never loses is marketing: a reader who finds the
/// omission stops believing the rest of the document, which costs more than
/// the loss did. So this is computed from `bench/results.json` and rendered
/// unconditionally, and [`doc_violations`] fails if the document drops a loss
/// the results contain.
pub fn losses(results: &Results, lab: &Lab) -> Vec<Loss> {
    let mut out = Vec::new();
    let ours: Vec<&RunRecord> = results
        .runs
        .iter()
        .filter(|r| r.scanner == "bathy" && r.ran())
        .collect();
    let theirs: Vec<&RunRecord> = results
        .runs
        .iter()
        .filter(|r| r.scanner != "bathy" && r.ran())
        .collect();

    for us in &ours {
        let Some(our_accuracy) = us.accuracy.as_ref() else {
            continue;
        };
        for other in &theirs {
            let Some(their_accuracy) = other.accuracy.as_ref() else {
                continue;
            };

            // Speed, per pair of operations. Both operations are named
            // rather than only the competitor's: "17x slower" against a scan
            // that does less work is a different claim from "17x slower"
            // against the same one, and a reader is entitled to tell them
            // apart without reading the harness.
            if let (Some(our_ms), Some(their_ms)) = (us.median_ms(), other.median_ms())
                && their_ms < our_ms
            {
                out.push(Loss {
                    category: "wall clock".into(),
                    detail: format!(
                        "{} ({}) took {our_ms} ms; {} ({}) took {their_ms} ms — {:.1}x.",
                        us.variant,
                        us.operation,
                        other.variant,
                        other.operation,
                        our_ms as f64 / their_ms.max(1) as f64
                    ),
                });
            }

            // Open ports found. Not gated on identification: a port
            // discovery run that finds more is a loss whether or not either
            // side tried to name what was listening.
            if their_accuracy.found_open > our_accuracy.found_open {
                out.push(Loss {
                    category: "open ports found".into(),
                    detail: format!(
                        "{} found {} of {} known-open ports; {} found {}.",
                        other.variant,
                        their_accuracy.found_open,
                        their_accuracy.expected_open,
                        us.variant,
                        our_accuracy.found_open
                    ),
                });
            }

            // Identification, only between runs that both attempt it.
            if !(us.identifies_services && other.identifies_services) {
                continue;
            }
            let ours_named: BTreeSet<&String> = our_accuracy.products_named_at.iter().collect();
            let theirs_named: BTreeSet<&String> = their_accuracy.products_named_at.iter().collect();
            let lost: Vec<String> = theirs_named
                .difference(&ours_named)
                .map(|s| (*s).clone())
                .collect();
            if !lost.is_empty() {
                out.push(Loss {
                    category: "service identification, per endpoint".into(),
                    detail: format!(
                        "{} named the lab's product at {} and {} did not.",
                        other.variant,
                        lost.join(", "),
                        us.variant
                    ),
                });
            }
            if their_accuracy.products_named > our_accuracy.products_named {
                out.push(Loss {
                    category: "service identification, in total".into(),
                    detail: format!(
                        "{} named {} of {} lab-established products; {} named {}.",
                        other.variant,
                        their_accuracy.products_named,
                        their_accuracy.products_expected,
                        us.variant,
                        our_accuracy.products_named
                    ),
                });
            }
            if their_accuracy.versions_named > our_accuracy.versions_named {
                out.push(Loss {
                    category: "version identification".into(),
                    detail: format!(
                        "{} named {} of {} lab-established versions; {} named {}.",
                        other.variant,
                        their_accuracy.versions_named,
                        their_accuracy.versions_expected,
                        us.variant,
                        our_accuracy.versions_named
                    ),
                });
            }
        }
    }

    // The gap the oracle already knew about, whether or not another tool ran
    // to demonstrate it. Losing to nobody is not the same as not losing, and
    // this is the row that keeps AC-7.14 discharged on a machine where bathy
    // is the only scanner installed.
    for ((ip, port), why) in &lab.identification_gaps {
        out.push(Loss {
            category: "identification gap recorded by the lab".into(),
            detail: format!("{ip}:{port} — {}", first_sentence(why)),
        });
    }
    out
}

fn first_sentence(text: &str) -> String {
    match text.find(". ") {
        Some(at) => text[..=at].trim().to_string(),
        None => text.trim().to_string(),
    }
}

// ---------------------------------------------------------------------------
// Rendering.
// ---------------------------------------------------------------------------

/// The generated half of `docs/benchmarks.md`, a pure function of the results.
pub fn render(results: &Results, lab: &Lab) -> String {
    let mut out = String::new();
    let line = |out: &mut String, s: &str| {
        out.push_str(s);
        out.push('\n');
    };

    line(&mut out, GENERATED_BEGIN);
    line(&mut out, "");
    line(
        &mut out,
        "*Everything between these markers is rendered from `bench/results.json` by \
         `cargo run -p xtask -- bench-compare`. `check-bench` re-renders it in CI and fails \
         on drift, so these numbers cannot quietly stop being the ones the run produced.*",
    );
    line(&mut out, "");

    line(&mut out, "## The run");
    line(&mut out, "");
    line(&mut out, "| | |");
    line(&mut out, "|---|---|");
    line(
        &mut out,
        &format!("| Observed at | {} |", results.environment.observed_at),
    );
    line(
        &mut out,
        &format!("| Host | {} |", results.environment.host),
    );
    line(
        &mut out,
        &format!("| Scanners ran in | {} |", results.environment.executed_in),
    );
    line(
        &mut out,
        &format!(
            "| Raw-socket privilege there | {} |",
            if results.environment.privileged {
                "yes (CAP_NET_RAW)"
            } else {
                "no"
            }
        ),
    );
    line(
        &mut out,
        &format!(
            "| Repetitions per tool | {} |",
            results.environment.repetitions
        ),
    );
    line(
        &mut out,
        &format!("| Targets | {} |", results.parameters.targets.join(", ")),
    );
    line(
        &mut out,
        &format!(
            "| Ports | {} |",
            results
                .parameters
                .ports
                .iter()
                .map(u16::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ),
    );
    line(
        &mut out,
        &format!(
            "| Per-connection timeout | {} ms — {} |",
            results.parameters.timeout_ms, results.parameters.timeout_source
        ),
    );
    line(
        &mut out,
        &format!(
            "| Rate ceiling | {} pps — {} |",
            results.parameters.rate_ceiling, results.parameters.rate_source
        ),
    );
    line(&mut out, "");

    line(&mut out, "## The tools, and which of them ran (AC-7.13)");
    line(&mut out, "");
    line(
        &mut out,
        "| Scanner | Status | Version | If absent, what makes it present |",
    );
    line(&mut out, "|---|---|---|---|");
    for scanner in &results.scanners {
        match &scanner.version {
            Some(version) => line(
                &mut out,
                &format!(
                    "| `{}` | **ran** | {} (`{}`) | — |",
                    scanner.name,
                    version,
                    scanner.path.as_deref().unwrap_or("on PATH")
                ),
            ),
            None => line(
                &mut out,
                &format!(
                    "| `{}` | **NOT RUN — not installed** | — | `{}` |",
                    scanner.name, scanner.remedy
                ),
            ),
        }
    }
    line(&mut out, "");

    line(&mut out, "## Command lines, verbatim (AC-7.13)");
    line(&mut out, "");
    for run in &results.runs {
        line(
            &mut out,
            &format!("**{}** — {}", run.variant, run.operation),
        );
        line(&mut out, "");
        line(&mut out, "```");
        for command in &run.command_lines {
            line(&mut out, command);
        }
        line(&mut out, "```");
        if let Some(reason) = &run.absent_reason {
            line(&mut out, &format!("*Not run: {reason}*"));
            line(&mut out, "");
        }
        if let Some(note) = &run.privilege_note {
            line(&mut out, &format!("*Privilege: {note}*"));
            line(&mut out, "");
        }
    }

    line(
        &mut out,
        "## Speed and accuracy, side by side (AC-7.11, AC-7.12)",
    );
    line(&mut out, "");
    line(
        &mut out,
        "Accuracy is scored against `lab/ground-truth.json`, which was derived from a \
         65535-port sweep run inside the lab network by a program sharing no code with any \
         scanner here. No tool is scored against another tool's output.",
    );
    line(&mut out, "");
    line(
        &mut out,
        "Timings are the median and the observed range over every repetition. Accuracy is \
         scored from the **final** repetition of each run — a scanner whose answer changes \
         between runs is a finding, and folding several answers into one would hide it. \
         `TCP opens` is the `Tcp: ActiveOpens` delta the kernel counted during that final \
         repetition, so a SYN scan reads zero: it emits no connection at all.",
    );
    line(&mut out, "");
    line(
        &mut out,
        "| Run | Median | Min–max | Open found | False neg | False pos | Products named | \
         Versions named | TCP opens |",
    );
    line(&mut out, "|---|---|---|---|---|---|---|---|---|");
    for run in &results.runs {
        let Some(accuracy) = run.accuracy.as_ref() else {
            line(
                &mut out,
                &format!(
                    "| `{}` | **not run** | — | — | — | — | — | — | — |",
                    run.variant
                ),
            );
            continue;
        };
        let times = run.milliseconds.clone().unwrap_or_default();
        let (low, high) = (
            times.iter().min().copied().unwrap_or(0),
            times.iter().max().copied().unwrap_or(0),
        );
        line(
            &mut out,
            &format!(
                "| `{}` | {} ms | {low}–{high} ms | {}/{} | {} | {} | {} | {} | {} |",
                run.variant,
                run.median_ms().unwrap_or(0),
                accuracy.found_open,
                accuracy.expected_open,
                accuracy.false_negatives.len(),
                accuracy.false_positives.len(),
                if run.identifies_services {
                    format!("{}/{}", accuracy.products_named, accuracy.products_expected)
                } else {
                    "n/a (no identification)".to_string()
                },
                if run.identifies_services {
                    format!("{}/{}", accuracy.versions_named, accuracy.versions_expected)
                } else {
                    "n/a".to_string()
                },
                run.tcp_active_opens
                    .map(|n| n.to_string())
                    .unwrap_or_else(|| "unavailable".to_string()),
            ),
        );
    }
    line(&mut out, "");

    let false_findings: Vec<&RunRecord> = results
        .runs
        .iter()
        .filter(|r| {
            r.accuracy
                .as_ref()
                .is_some_and(|a| !a.false_negatives.is_empty() || !a.false_positives.is_empty())
        })
        .collect();
    if !false_findings.is_empty() {
        line(&mut out, "### Every disagreement with the lab, named");
        line(&mut out, "");
        for run in false_findings {
            let accuracy = run.accuracy.as_ref().expect("filtered on is_some");
            if !accuracy.false_negatives.is_empty() {
                line(
                    &mut out,
                    &format!(
                        "- `{}` missed: {}",
                        run.variant,
                        accuracy.false_negatives.join(", ")
                    ),
                );
            }
            if !accuracy.false_positives.is_empty() {
                line(
                    &mut out,
                    &format!(
                        "- `{}` reported open where the lab says shut: {}",
                        run.variant,
                        accuracy.false_positives.join(", ")
                    ),
                );
            }
        }
        line(&mut out, "");
    }

    line(&mut out, "## Where bathy loses (AC-7.14)");
    line(&mut out, "");
    let losses = losses(results, lab);
    if losses.is_empty() {
        line(
            &mut out,
            "This run produced no category where another scanner beat bathy and no \
             identification gap in the lab. That is a claim to distrust, not to celebrate: \
             check that every scanner in the table above actually ran.",
        );
    } else {
        for loss in &losses {
            line(
                &mut out,
                &format!("- **{}** — {}", loss.category, loss.detail),
            );
        }
    }
    line(&mut out, "");
    // No trailing newline: the block ends exactly at its end marker, so
    // splicing it back in is byte-identical to what was spliced out.
    out.push_str(GENERATED_END);
    out
}

/// Replace the generated block in `doc`, or return an error naming the
/// markers that are missing.
pub fn splice(doc: &str, generated: &str) -> Result<String, String> {
    let begin = doc.find(GENERATED_BEGIN).ok_or_else(|| {
        format!(
            "{DOC_PATH} has no `{GENERATED_BEGIN}` marker, so there is nowhere to put the \
                 measured numbers"
        )
    })?;
    let end = doc
        .find(GENERATED_END)
        .ok_or_else(|| format!("{DOC_PATH} has no `{GENERATED_END}` marker"))?;
    if end < begin {
        return Err(format!(
            "{DOC_PATH}'s generated-block markers are in the wrong order"
        ));
    }
    Ok(format!(
        "{}{}{}",
        &doc[..begin],
        generated,
        &doc[end + GENERATED_END.len()..]
    ))
}

// ---------------------------------------------------------------------------
// `check-bench` — the gate.
// ---------------------------------------------------------------------------

/// A criterion benchmark AC-7.15 names, and where it lives.
///
/// A registry rather than a sentence, for the reason every other registry in
/// this repository exists: AC-7.15 lists four subjects, and a list in prose is
/// a list that goes stale the first time a file is renamed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BenchSubject {
    /// What AC-7.15 names.
    pub subject: &'static str,
    pub crate_dir: &'static str,
    pub bench_file: &'static str,
    /// The `[[bench]]` name its manifest must declare.
    pub bench_name: &'static str,
}

pub const BENCH_SUBJECTS: &[BenchSubject] = &[
    BenchSubject {
        subject: "interpret",
        crate_dir: "crates/bathy-interpret",
        bench_file: "crates/bathy-interpret/benches/interpret.rs",
        bench_name: "interpret",
    },
    BenchSubject {
        subject: "canonical_json",
        crate_dir: "crates/bathy-types",
        bench_file: "crates/bathy-types/benches/canonical_json.rs",
        bench_name: "canonical_json",
    },
    BenchSubject {
        subject: "plan construction",
        crate_dir: "crates/bathy-plan",
        bench_file: "crates/bathy-plan/benches/plan_construction.rs",
        bench_name: "plan_construction",
    },
    BenchSubject {
        subject: "log append",
        crate_dir: "crates/bathy-evidence",
        bench_file: "crates/bathy-evidence/benches/log_append.rs",
        bench_name: "log_append",
    },
];

/// The rule, pure: everything `check-bench` asserts about a tree, with the
/// tree's contents passed in.
/// Everything `check-bench` reads out of the tree, gathered into one value.
///
/// A struct rather than eight positional parameters, and not only because
/// clippy says so: `bench_violations` is the rule, and a rule with eight
/// same-typed `&str` arguments is one transposition away from checking the
/// scope manifest against the scheduler and reporting nothing.
pub struct TreeState<'a> {
    /// `docs/benchmarks.md`, whole.
    pub doc: &'a str,
    /// `crates/bathy-engine/src/scheduler.rs`, for the connect-timeout default.
    pub scheduler_source: &'a str,
    /// `lab/scope.json`, for the rate ceiling.
    pub scope_json: &'a str,
    /// `.github/workflows/ci.yml`, for the step that executes the benchmarks.
    pub ci: &'a str,
    pub compare_script_present: bool,
    /// Each registered criterion subject, whether its file exists, and its
    /// crate's manifest.
    pub subjects: &'a [(BenchSubject, bool, Option<String>)],
}

pub fn bench_violations(results: &Results, lab: &Lab, tree: &TreeState<'_>) -> Vec<String> {
    let TreeState {
        doc,
        scheduler_source,
        scope_json,
        ci,
        compare_script_present,
        subjects,
    } = *tree;
    let mut found = Vec::new();

    // 0. The document tells a reader to reproduce this by running one
    //    script. A document naming a command that is not in the tree is a
    //    reproduction claim nobody can act on.
    if !compare_script_present {
        found.push(format!(
            "{COMPARE_SCRIPT} does not exist, and {DOC_PATH} tells a reader to run it."
        ));
    }

    // 1. The published numbers are the ones the run produced.
    match splice(doc, &render(results, lab)) {
        Err(e) => found.push(e),
        Ok(expected) if expected != doc => found.push(format!(
            "{DOC_PATH}'s generated block is not what {RESULTS_PATH} renders to. Re-run \
             `bench/compare.sh`, or `cargo run -p xtask -- bench-compare --render-only` if \
             you only edited the prose around it."
        )),
        Ok(_) => {}
    }

    // 2. Every scanner is accounted for, present or absent (AC-7.13). A
    //    missing tool must be a visible row, which is the whole reason this
    //    check exists: silently dropping masscan would turn a two-scanner
    //    comparison into something a reader takes for a four-scanner one.
    for scanner in SCANNERS {
        match results.scanners.iter().find(|s| s.name == scanner.name) {
            None => found.push(format!(
                "{RESULTS_PATH} has no row for `{}`. Four scanners are named by AC-7.11; a \
                 tool that is not installed gets a `not run` row, never no row.",
                scanner.name
            )),
            Some(row) => {
                if !doc.contains(scanner.name) {
                    found.push(format!("{DOC_PATH} never mentions `{}`.", scanner.name));
                }
                // The remedy is the only instruction a reader gets for making
                // an absent tool present, and `bench/results.json` carries a
                // copy of it taken when the run happened. Nothing else here
                // compares the two, so a corrected remedy would sit in this
                // file while the published record kept quoting the wrong one —
                // and the copy is only *rendered* when the tool is absent, so
                // the drift would be invisible in exactly the case where the
                // instruction has to work.
                if row.remedy != scanner.remedy {
                    found.push(format!(
                        "{RESULTS_PATH} records a different remedy for `{}` than `SCANNERS` \
                         does, so the published record was written by a run of a different \
                         tree. Re-run `bench/compare.sh`.",
                        scanner.name
                    ));
                }
                if row.version.is_none() && !doc.contains(&row.remedy[..30.min(row.remedy.len())]) {
                    found.push(format!(
                        "`{}` did not run and {DOC_PATH} does not carry the remedy that would \
                         make it run.",
                        scanner.name
                    ));
                }
            }
        }
    }

    // 3. Every variant has its command line published verbatim (AC-7.13).
    for run in &results.runs {
        if run.command_lines.is_empty() {
            found.push(format!(
                "run `{}` published no command line; AC-7.13 requires one so a reader can \
                 re-run exactly what we ran.",
                run.variant
            ));
        }
        for command in &run.command_lines {
            if !doc.contains(command) {
                found.push(format!(
                    "{DOC_PATH} does not contain `{}`'s command line verbatim.",
                    run.variant
                ));
            }
        }
    }

    // 4. Timings sit next to accuracy (AC-7.12): a run that produced a timing
    //    and no score is speed reported alone, which is the number every
    //    scanner benchmark gets wrong.
    for run in &results.runs {
        if run.milliseconds.is_some() != run.accuracy.is_some() {
            found.push(format!(
                "run `{}` has {} and {}: AC-7.12 requires accuracy beside timing, so a run \
                 has both or neither.",
                run.variant,
                if run.milliseconds.is_some() {
                    "a timing"
                } else {
                    "no timing"
                },
                if run.accuracy.is_some() {
                    "a score"
                } else {
                    "no score"
                },
            ));
        }
        if run.ran() && run.milliseconds.as_ref().is_none_or(Vec::is_empty) {
            found.push(format!(
                "run `{}` is recorded as having run and carries no timing at all.",
                run.variant
            ));
        }
    }

    // 5. Every loss the results contain appears in the document (AC-7.14).
    for loss in losses(results, lab) {
        if !doc.contains(&loss.detail) {
            found.push(format!(
                "{DOC_PATH} omits a category where bathy loses: {} — {}. AC-7.14 exists \
                 because a benchmark that only flatters us is worth less than none.",
                loss.category, loss.detail
            ));
        }
    }

    // 6. The published run is still the run this tree describes.
    match scheduler_connect_timeout_ms(scheduler_source) {
        Err(e) => found.push(e),
        Ok(ms) if ms != results.parameters.timeout_ms => found.push(format!(
            "the scheduler's default connect timeout is now {ms} ms; {RESULTS_PATH} was taken \
             at {} ms and gave every other tool that ceiling. The published comparison is \
             stale — re-run `bench/compare.sh`.",
            results.parameters.timeout_ms
        )),
        Ok(_) => {}
    }
    match scope_rate_ceiling(scope_json) {
        Err(e) => found.push(e),
        Ok(pps) if pps != results.parameters.rate_ceiling => found.push(format!(
            "{SCOPE_PATH} now authorizes {pps} pps; {RESULTS_PATH} was taken at {}.",
            results.parameters.rate_ceiling
        )),
        Ok(_) => {}
    }
    if results.parameters.ports != lab.ports {
        found.push(format!(
            "{GROUND_TRUTH_PATH}'s scanned port set has changed since {RESULTS_PATH} was \
             written; the published comparison covers a different question."
        ));
    }
    let targets: Vec<String> = lab.targets.iter().map(IpAddr::to_string).collect();
    if results.parameters.targets != targets {
        found.push(format!(
            "{GROUND_TRUTH_PATH}'s addresses have changed since {RESULTS_PATH} was written."
        ));
    }

    // 7. CI executes the benchmarks, rather than only compiling them.
    //
    //    This check exists because the claim was written down and was false:
    //    `cargo test --workspace` does not build bench targets at all --
    //    Cargo's default selection for `test` is lib, bins, tests and
    //    examples -- so a benchmark that panicked at run time would have gone
    //    unnoticed while the document said CI ran it. Prose does not enforce
    //    itself; this does.
    let runs_benches = crate::visibility::job_run_steps(ci, FAST_CI_JOB)
        .iter()
        .any(|step| step.starts_with("cargo test") && step.contains("--benches"));
    if !runs_benches {
        found.push(format!(
            "{}'s `{FAST_CI_JOB}` job has no `cargo test … --benches` step, so AC-7.15's \
             criterion benchmarks are compiled and never executed. A benchmark that builds \
             and then panics -- the `interpret` one reads a corpus off disk -- would go \
             unnoticed.",
            crate::visibility::CI_PATH
        ));
    }

    // 8. AC-7.15's four criterion benchmarks exist and are wired up.
    for (subject, file_exists, manifest) in subjects {
        if !file_exists {
            found.push(format!(
                "AC-7.15 names a criterion benchmark over `{}` and `{}` does not exist.",
                subject.subject, subject.bench_file
            ));
        }
        let Some(manifest) = manifest else {
            found.push(format!(
                "{}/Cargo.toml is unreadable, so the `{}` benchmark's wiring cannot be \
                 checked.",
                subject.crate_dir, subject.subject
            ));
            continue;
        };
        let declares = manifest.contains("[[bench]]")
            && manifest.contains(&format!("name = \"{}\"", subject.bench_name));
        if !declares {
            found.push(format!(
                "{}/Cargo.toml does not declare `[[bench]] name = \"{}\"`, so `cargo bench` \
                 never builds it.",
                subject.crate_dir, subject.bench_name
            ));
        }
        if !manifest.contains("harness = false") {
            found.push(format!(
                "{}/Cargo.toml does not set `harness = false`, which criterion requires — \
                 without it the benchmark runs under libtest and measures nothing.",
                subject.crate_dir
            ));
        }
    }

    found
}

pub fn check_bench() -> Fallible<()> {
    let read = |path: &str| -> Fallible<String> {
        std::fs::read_to_string(path).map_err(|e| format!("reading {path}: {e}").into())
    };
    let lab = Lab::parse(&read(GROUND_TRUTH_PATH)?)?;
    let doc = read(DOC_PATH)?;
    let results: Results =
        serde_json::from_str(&read(RESULTS_PATH)?).map_err(|e| format!("{RESULTS_PATH}: {e}"))?;
    let subjects: Vec<(BenchSubject, bool, Option<String>)> = BENCH_SUBJECTS
        .iter()
        .map(|s| {
            (
                *s,
                Path::new(s.bench_file).exists(),
                std::fs::read_to_string(format!("{}/Cargo.toml", s.crate_dir)).ok(),
            )
        })
        .collect();
    let violations = bench_violations(
        &results,
        &lab,
        &TreeState {
            doc: &doc,
            scheduler_source: &read(SCHEDULER_PATH)?,
            scope_json: &read(SCOPE_PATH)?,
            ci: &read(crate::visibility::CI_PATH)?,
            compare_script_present: Path::new(COMPARE_SCRIPT).exists(),
            subjects: &subjects,
        },
    );
    if violations.is_empty() {
        println!(
            "check-bench: ok ({} scanner(s), {} of them installed at the last run, {} run(s), \
             {} criterion subject(s))",
            results.scanners.len(),
            results
                .scanners
                .iter()
                .filter(|s| s.version.is_some())
                .count(),
            results.runs.len(),
            BENCH_SUBJECTS.len(),
        );
        return Ok(());
    }
    for v in &violations {
        eprintln!("check-bench: {v}");
    }
    Err(format!("{} benchmark-publication violation(s)", violations.len()).into())
}

// ---------------------------------------------------------------------------
// `bench-compare` — actually running them.
// ---------------------------------------------------------------------------

fn which(binary: &str) -> Option<String> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(binary);
        if candidate.is_file() {
            return Some(candidate.display().to_string());
        }
    }
    None
}

fn tool_version(binary: &str, arg: &str) -> Option<String> {
    let out = Command::new(binary).arg(arg).output().ok()?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    text.lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .map(str::to_owned)
}

/// `Tcp: … ActiveOpens` from `/proc/net/snmp`, where there is one.
pub fn tcp_active_opens(snmp: &str) -> Option<u64> {
    let mut lines = snmp.lines().filter(|l| l.starts_with("Tcp:"));
    let header = lines.next()?;
    let values = lines.next()?;
    let column = header
        .split_whitespace()
        .position(|name| name == "ActiveOpens")?;
    values.split_whitespace().nth(column)?.parse().ok()
}

fn read_active_opens() -> Option<u64> {
    tcp_active_opens(&std::fs::read_to_string("/proc/net/snmp").ok()?)
}

struct Ran {
    milliseconds: Vec<u64>,
    observed: Observed,
    active_opens: Option<u64>,
}

/// Run one variant `repetitions` times, keeping the last run's observation.
///
/// The parse guard is the important part. A tool that exits successfully and
/// whose output parses to zero open ports is treated as a **harness failure**,
/// not as a score of zero: the most likely cause is that this file's parser
/// does not understand the tool's output, and a parser bug that scores a
/// working competitor as having found nothing is the most flattering possible
/// bug for this project to ship.
fn run_variant(variant: &Variant, lab: &Lab, params: &Params) -> Result<Ran, String> {
    let mut milliseconds = Vec::new();
    let mut observed = Observed::default();
    let mut active_opens = None;
    for repetition in 0..params_repetitions() {
        let mut params = params.clone();
        params.idempotency_key =
            format!("{}-{}-{}", params.idempotency_key, variant.id, repetition);
        let commands = argv(variant, lab, &params);
        let before = read_active_opens();
        let started = std::time::Instant::now();
        let first = &commands[0];
        let out = Command::new(&first[0])
            .args(&first[1..])
            .output()
            .map_err(|e| format!("running {}: {e}", first.join(" ")))?;
        let elapsed = started.elapsed().as_millis() as u64;
        if let (Some(before), Some(after)) = (before, read_active_opens()) {
            active_opens = Some(after.saturating_sub(before));
        }
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        let stderr = String::from_utf8_lossy(&out.stderr).to_string();
        if !out.status.success() {
            return Err(format!(
                "`{}` exited {}: {}",
                first.join(" "),
                out.status,
                stderr.lines().next_back().unwrap_or("(no message)")
            ));
        }
        milliseconds.push(elapsed);

        observed = match variant.scanner {
            "bathy" => {
                let scan_id = scan_id_of(&stdout)?;
                let query: Vec<String> = commands[1]
                    .iter()
                    .map(|a| {
                        if a == "$SCAN_ID" {
                            scan_id.clone()
                        } else {
                            a.clone()
                        }
                    })
                    .collect();
                let read = Command::new(&query[0])
                    .args(&query[1..])
                    .output()
                    .map_err(|e| format!("running {}: {e}", query.join(" ")))?;
                if !read.status.success() {
                    return Err(format!("`{}` exited {}", query.join(" "), read.status));
                }
                parse_bathy_query(&String::from_utf8_lossy(&read.stdout))?
            }
            "nmap" => parse_nmap_xml(&stdout),
            "masscan" => parse_masscan_list(&stdout),
            "rustscan" => parse_rustscan_greppable(&stdout),
            other => return Err(format!("no parser for `{other}`")),
        };
        if let Some(complaint) = implausible_observation(&observed, lab) {
            return Err(format!(
                "`{}` {complaint} Output was:\n{}",
                first.join(" "),
                stdout.chars().take(2000).collect::<String>()
            ));
        }
    }
    Ok(Ran {
        milliseconds,
        observed,
        active_opens,
    })
}

/// The scan id out of `bathy scan start`'s first document.
///
/// The handle publishes it as `handle.task_id` -- `scan_...`, the same id
/// `result query --scan` takes. The flat `scan_id`/`task_id` spellings are
/// accepted too so that this reads the identifier rather than one document
/// shape, but the nested form is the one the command actually emits and is
/// checked first.
/// `Some(complaint)` when a run's parsed observation cannot be believed.
///
/// A tool that exits successfully and whose output parses to **no open port at
/// all**, on a lab that has twelve, is far more likely to be a parser this
/// benchmark got wrong than a scanner that found nothing. Scoring that as zero
/// would publish a competitor as having failed completely because of a defect
/// on our side — the single most flattering bug this project could ship, and
/// the one a reader would be most right to be angry about. So it is an error
/// that stops the run, not a row in the table.
pub fn implausible_observation(observed: &Observed, lab: &Lab) -> Option<String> {
    if !observed.open.is_empty() || lab.open.is_empty() {
        return None;
    }
    Some(format!(
        "exited successfully and its output parsed to zero open ports, while the lab has {} \
         open port(s) in the scanned set. That is treated as a harness failure rather than a \
         score of zero: the likely cause is that this benchmark's parser does not understand \
         the tool's output.",
        lab.open.len()
    ))
}

fn scan_id_of(stdout: &str) -> Result<String, String> {
    for line in stdout.lines() {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let candidates = [
            value.get("handle").and_then(|h| h.get("task_id")),
            value.get("task_id"),
            value.get("scan_id"),
        ];
        for candidate in candidates.into_iter().flatten() {
            if let Some(id) = candidate.as_str().filter(|id| id.starts_with("scan_")) {
                return Ok(id.to_string());
            }
        }
    }
    Err(format!(
        "bathy's `scan start` printed no scan id. Output was:\n{stdout}"
    ))
}

fn params_repetitions() -> usize {
    std::env::var("BENCH_REPETITIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .filter(|n| *n > 0)
        // Five, not one. A single wall-clock reading on a laptop is not a
        // measurement, and this lab has a specific reason to need several:
        // the two addresses with no host are resolved by ARP, so a run
        // whose negative ARP entry is still cached finishes in a fraction
        // of the time one that has to time out does. The range in the
        // published table is that effect, and it is the honest part.
        .unwrap_or(5)
}

/// `bench-compare`: run every installed scanner, score it, write the record
/// and re-render the document.
///
/// `--render-only` skips the running and re-renders from the committed
/// `bench/results.json`, which is what a prose edit needs.
pub fn bench_compare(render_only: bool) -> Fallible<()> {
    let read = |path: &str| -> Fallible<String> {
        std::fs::read_to_string(path).map_err(|e| format!("reading {path}: {e}").into())
    };
    let lab = Lab::parse(&read(GROUND_TRUTH_PATH)?)?;

    let results: Results = if render_only {
        serde_json::from_str(&read(RESULTS_PATH)?).map_err(|e| format!("{RESULTS_PATH}: {e}"))?
    } else {
        let measured = measure(&lab, &read(SCHEDULER_PATH)?, &read(SCOPE_PATH)?)?;
        std::fs::create_dir_all(Path::new(RESULTS_PATH).parent().expect("bench/"))?;
        std::fs::write(
            RESULTS_PATH,
            format!("{}\n", serde_json::to_string_pretty(&measured)?),
        )?;
        measured
    };

    let doc = read(DOC_PATH)?;
    let spliced = splice(&doc, &render(&results, &lab))?;
    std::fs::write(DOC_PATH, spliced)?;
    println!(
        "bench-compare: wrote {RESULTS_PATH} and the generated block in {DOC_PATH} ({} run(s))",
        results.runs.len()
    );
    Ok(())
}

fn measure(lab: &Lab, scheduler_source: &str, scope_json: &str) -> Fallible<Results> {
    let timeout_ms = scheduler_connect_timeout_ms(scheduler_source)?;
    let rate_ceiling = scope_rate_ceiling(scope_json)?;
    let state = tempdir()?;
    let params = Params {
        timeout_ms,
        rate_ceiling,
        state_dir: state.clone(),
        scope_path: SCOPE_PATH.to_string(),
        idempotency_key: "bench".to_string(),
    };

    let privileged = read_active_opens().is_some() && is_root();
    let mut scanners = Vec::new();
    for scanner in SCANNERS {
        let path = which(scanner.binary);
        scanners.push(ScannerStatus {
            name: scanner.name.to_string(),
            version: path
                .as_ref()
                .and_then(|_| tool_version(scanner.binary, scanner.version_arg)),
            path,
            remedy: scanner.remedy.to_string(),
        });
    }

    let mut runs = Vec::new();
    for variant in VARIANTS {
        let installed = scanners
            .iter()
            .find(|s| s.name == variant.scanner)
            .and_then(|s| s.version.clone());
        let command_lines: Vec<String> = argv(variant, lab, &params)
            .iter()
            .map(|c| c.join(" "))
            .collect();
        let privilege_note = if variant.needs_raw_sockets {
            Some(if privileged {
                "this operation needs raw sockets and had them (running as uid 0 with \
                 CAP_NET_RAW). bathy's own scan is an unprivileged connect scan, so this row \
                 is a different operation, not a faster version of the same one."
                    .to_string()
            } else {
                "this operation needs raw sockets and could not have them here. Whatever the \
                 tool did instead is its fallback, and comparing a fallback against our \
                 connect scan as though they were the same operation is exactly what this \
                 note exists to prevent."
                    .to_string()
            })
        } else {
            None
        };
        let mut record = RunRecord {
            variant: variant.id.to_string(),
            scanner: variant.scanner.to_string(),
            operation: variant.operation.to_string(),
            needs_raw_sockets: variant.needs_raw_sockets,
            identifies_services: variant.identifies_services,
            command_lines,
            milliseconds: None,
            accuracy: None,
            absent_reason: None,
            privilege_note,
            tcp_active_opens: None,
        };
        match installed {
            None => {
                record.absent_reason = Some(format!(
                    "`{}` is not installed on this machine, so this row is empty rather than \
                     absent from the table",
                    variant.scanner
                ));
            }
            Some(_) => {
                eprintln!("bench-compare: running {}", variant.id);
                let ran = run_variant(variant, lab, &params)?;
                record.accuracy = Some(score(lab, &ran.observed));
                record.milliseconds = Some(ran.milliseconds);
                record.tcp_active_opens = ran.active_opens;
            }
        }
        runs.push(record);
    }

    Ok(Results {
        environment: Environment {
            observed_at: now_rfc3339(),
            host: host_description(),
            executed_in: std::env::var("BENCH_EXECUTED_IN")
                .unwrap_or_else(|_| "unrecorded — set BENCH_EXECUTED_IN".to_string()),
            privileged,
            repetitions: params_repetitions(),
        },
        parameters: PublishedParams {
            targets: lab.targets.iter().map(IpAddr::to_string).collect(),
            ports: lab.ports.clone(),
            timeout_ms,
            timeout_source: format!(
                "`SchedulerConfig::default`'s `connect_timeout` in `{SCHEDULER_PATH}`, read \
                 rather than restated; bathy does not expose it as a flag, so every other \
                 tool is given the same ceiling"
            ),
            rate_ceiling,
            rate_source: format!(
                "`budget_ceiling.maximum_packets_per_second` in `{SCOPE_PATH}` — the ceiling \
                 the lab's own manifest authorizes, given to every tool that has a rate knob"
            ),
        },
        scanners,
        runs,
    })
}

fn is_root() -> bool {
    Command::new("id")
        .arg("-u")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "0")
        .unwrap_or(false)
}

fn host_description() -> String {
    let field = |args: &[&str]| {
        Command::new("uname")
            .args(args)
            .output()
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
            .unwrap_or_default()
    };
    format!("{} {}", field(&["-s"]), field(&["-m"]))
        .trim()
        .to_string()
}

fn now_rfc3339() -> String {
    Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

fn tempdir() -> Fallible<PathBuf> {
    let base = std::env::temp_dir().join(format!("bathy-bench-{}", std::process::id()));
    std::fs::create_dir_all(&base)?;
    Ok(base)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Unit tests run with the package directory as the working directory,
    /// so the repository root is one level up — except when someone runs
    /// them from the root. Both are answered here rather than in six places.
    fn repo_root() -> PathBuf {
        let up = PathBuf::from("..");
        if up.join(GROUND_TRUTH_PATH).exists() {
            up
        } else {
            PathBuf::from(".")
        }
    }

    fn read_repo(path: &str) -> String {
        let full = repo_root().join(path);
        std::fs::read_to_string(&full).unwrap_or_else(|e| panic!("reading {}: {e}", full.display()))
    }

    const GROUND_TRUTH_FIXTURE: &str = r#"{
      "subnet": "10.30.0.0/24",
      "scanned_ports": [22, 80, 443, 2222],
      "hosts": [
        { "ip": "10.30.0.10", "up": true, "service": "web",
          "open": [ { "port": 80, "service": "http", "product": "nginx",
                      "version": "1.29.8", "evidence": "Server: nginx/1.29.8" } ] },
        { "ip": "10.30.0.17", "up": true, "service": "tls-web",
          "open": [ { "port": 443, "service": "tls", "product": "nginx",
                      "version": "1.29.8", "evidence": "Server: nginx/1.29.8",
                      "identification_gap": "bathy reports no product here. The cause is detect_service stopping at tls-v1." } ] },
        { "ip": "10.30.0.18", "up": true, "service": "silent", "open": [] }
      ],
      "absent": ["10.30.0.200"]
    }"#;

    fn lab() -> Lab {
        Lab::parse(GROUND_TRUTH_FIXTURE).expect("fixture parses")
    }

    fn params() -> Params {
        Params {
            timeout_ms: 2000,
            rate_ceiling: 100_000,
            state_dir: PathBuf::from("/tmp/bench-state"),
            scope_path: SCOPE_PATH.to_string(),
            idempotency_key: "bench".to_string(),
        }
    }

    fn accuracy(products_named: usize, versions_named: usize) -> Accuracy {
        Accuracy {
            expected_open: 2,
            found_open: 2,
            false_negatives: vec![],
            false_positives: vec![],
            products_expected: 2,
            products_named,
            products_named_at: if products_named < 2 {
                vec!["10.30.0.10:80".into()]
            } else {
                vec!["10.30.0.10:80".into(), "10.30.0.17:443".into()]
            },
            products_missed: if products_named < 2 {
                vec!["10.30.0.17:443 (lab: nginx, reported: nothing)".into()]
            } else {
                vec![]
            },
            versions_expected: 2,
            versions_named,
        }
    }

    fn run(variant: &str, scanner: &str, ms: u64, identifies: bool, a: Accuracy) -> RunRecord {
        RunRecord {
            variant: variant.into(),
            scanner: scanner.into(),
            operation: "an operation".into(),
            needs_raw_sockets: false,
            identifies_services: identifies,
            command_lines: vec![format!("{scanner} --run-it")],
            milliseconds: Some(vec![ms, ms + 10, ms + 20]),
            accuracy: Some(a),
            absent_reason: None,
            privilege_note: None,
            tcp_active_opens: None,
        }
    }

    fn results(runs: Vec<RunRecord>) -> Results {
        let lab = lab();
        Results {
            environment: Environment {
                observed_at: "2026-08-04T00:00:00Z".into(),
                host: "Linux aarch64".into(),
                executed_in: "a container on labnet".into(),
                privileged: true,
                repetitions: 3,
            },
            parameters: PublishedParams {
                targets: lab.targets.iter().map(IpAddr::to_string).collect(),
                ports: lab.ports.clone(),
                timeout_ms: 2000,
                timeout_source: "the scheduler".into(),
                rate_ceiling: 100_000,
                rate_source: "the manifest".into(),
            },
            scanners: SCANNERS
                .iter()
                .map(|s| ScannerStatus {
                    name: s.name.into(),
                    version: if runs.iter().any(|r| r.scanner == s.name && r.ran()) {
                        Some(format!("{} 1.0", s.name))
                    } else {
                        None
                    },
                    path: None,
                    remedy: s.remedy.into(),
                })
                .collect(),
            runs,
        }
    }

    /// A document whose generated block is exactly what these results render
    /// to, which is the state `check-bench` demands.
    fn document_for(results: &Results, lab: &Lab) -> String {
        format!(
            "# Benchmarks\n\nprose\n\n{}\n\nmore prose\n",
            render(results, lab)
        )
    }

    /// A workflow whose fast job does run the benchmarks.
    const CI_FIXTURE: &str = "\
jobs:
  test:
    steps:
      - run: cargo test --workspace
      - run: cargo test --workspace --benches
";

    fn subjects_all_present() -> Vec<(BenchSubject, bool, Option<String>)> {
        BENCH_SUBJECTS
            .iter()
            .map(|s| {
                (
                    *s,
                    true,
                    Some(format!(
                        "[package]\nname = \"x\"\n\n[[bench]]\nname = \"{}\"\nharness = false\n",
                        s.bench_name
                    )),
                )
            })
            .collect()
    }

    const SCHEDULER_FIXTURE: &str =
        "impl Default for SchedulerConfig {\n connect_timeout: Duration::from_secs(2),\n}";
    const SCOPE_FIXTURE: &str = r#"{"budget_ceiling":{"maximum_packets_per_second":100000}}"#;

    /// A tree in the state `check-bench` demands, which each test below then
    /// breaks in exactly one place.
    fn clean_tree<'a>(
        doc: &'a str,
        subjects: &'a [(BenchSubject, bool, Option<String>)],
    ) -> TreeState<'a> {
        TreeState {
            doc,
            scheduler_source: SCHEDULER_FIXTURE,
            scope_json: SCOPE_FIXTURE,
            ci: CI_FIXTURE,
            compare_script_present: true,
            subjects,
        }
    }

    fn violations_of(doc: &str, results: &Results, lab: &Lab) -> Vec<String> {
        bench_violations(results, lab, &clean_tree(doc, &subjects_all_present()))
    }

    // -----------------------------------------------------------------
    // AC-7.11 — one lab, one port set, one timeout, one rate, for all four.
    // -----------------------------------------------------------------

    #[test]
    fn every_scanner_is_asked_about_exactly_the_same_ports() {
        // The whole comparison rests on this. A tool given a different port
        // set is answering a different question, and its timing is then an
        // anecdote with a table around it.
        let (lab, params) = (lab(), params());
        let wanted = lab.ports_csv();
        for variant in VARIANTS {
            let flat = argv(variant, &lab, &params)
                .iter()
                .flatten()
                .cloned()
                .collect::<Vec<_>>();
            assert!(
                flat.iter()
                    .any(|a| a == &wanted || a == &format!("-p{wanted}")),
                "{} was not given the ports `{wanted}`: {flat:?}",
                variant.id
            );
        }
    }

    #[test]
    fn every_scanner_is_asked_about_exactly_the_same_addresses() {
        let (lab, params) = (lab(), params());
        for variant in VARIANTS {
            let flat = argv(variant, &lab, &params)
                .iter()
                .flatten()
                .cloned()
                .collect::<Vec<_>>();
            let joined = flat.join(" ");
            for target in lab.targets_spaced() {
                assert!(
                    joined.contains(&target),
                    "{} was not given {target}: {joined}",
                    variant.id
                );
            }
        }
    }

    #[test]
    fn the_absent_addresses_are_in_every_scanners_target_list() {
        // The two holes are the narrowing control for the whole comparison:
        // without them a scanner that reports everything it touched as open
        // scores perfectly.
        let lab = lab();
        assert!(
            lab.targets
                .contains(&"10.30.0.200".parse::<IpAddr>().unwrap()),
            "the ground truth's `absent` addresses must be scanned, or a false positive \
             cannot be observed"
        );
    }

    #[test]
    fn every_tool_with_a_timeout_knob_gets_the_scheduler_s_own_default() {
        let lab = lab();
        let mut params = params();
        params.timeout_ms = 1500;
        let joined = |id: &str| {
            argv(
                VARIANTS.iter().find(|v| v.id == id).expect("variant"),
                &lab,
                &params,
            )
            .iter()
            .flatten()
            .cloned()
            .collect::<Vec<_>>()
            .join(" ")
        };
        assert!(joined("nmap-connect").contains("--max-rtt-timeout 1500ms"));
        assert!(joined("nmap-syn").contains("--max-rtt-timeout 1500ms"));
        assert!(joined("nmap-version").contains("--max-rtt-timeout 1500ms"));
        assert!(joined("rustscan-connect").contains("-t 1500"));
        // masscan's wait is whole seconds, rounded up rather than truncated:
        // a 1500 ms ceiling truncated to 1 second would stop listening while
        // the other tools were still waiting.
        assert!(
            joined("masscan-syn").contains("--wait 2"),
            "{}",
            joined("masscan-syn")
        );
    }

    #[test]
    fn every_tool_with_a_rate_knob_gets_the_manifests_ceiling() {
        let lab = lab();
        let mut params = params();
        params.rate_ceiling = 4242;
        let joined = |id: &str| {
            argv(
                VARIANTS.iter().find(|v| v.id == id).expect("variant"),
                &lab,
                &params,
            )
            .iter()
            .flatten()
            .cloned()
            .collect::<Vec<_>>()
            .join(" ")
        };
        assert!(joined("nmap-connect").contains("--max-rate 4242"));
        assert!(joined("masscan-syn").contains("--rate 4242"));
        assert!(joined("bathy-connect").contains("--max-packets-per-second 4242"));
    }

    #[test]
    fn the_timeout_is_read_out_of_the_scheduler_rather_than_restated() {
        assert_eq!(
            scheduler_connect_timeout_ms(
                "impl Default for SchedulerConfig {\n  connect_timeout: Duration::from_secs(2),\n}"
            ),
            Ok(2000)
        );
        assert_eq!(
            scheduler_connect_timeout_ms(
                "impl Default for SchedulerConfig {\n  connect_timeout: Duration::from_millis(750),\n}"
            ),
            Ok(750)
        );
        // An earlier `connect_timeout` in some other impl must not be the one
        // that answers.
        assert_eq!(
            scheduler_connect_timeout_ms(
                "fn t() { connect_timeout: Duration::from_millis(5), }\n\
                 impl Default for SchedulerConfig {\n  connect_timeout: Duration::from_secs(9),\n}"
            ),
            Ok(9000)
        );
        assert!(scheduler_connect_timeout_ms("no such impl").is_err());
        assert!(
            scheduler_connect_timeout_ms(
                "impl Default for SchedulerConfig {\n  connect_timeout: elsewhere(),\n}"
            )
            .is_err(),
            "an expression this reader cannot evaluate must fail loudly, not silently \
             publish a timeout no tool was actually given"
        );
    }

    #[test]
    fn the_committed_scheduler_and_manifest_still_answer() {
        // Reads the real files, so a rename or a rewritten default fails here
        // rather than at benchmark time on someone else's machine.
        let ms = scheduler_connect_timeout_ms(&read_repo(SCHEDULER_PATH))
            .expect("the scheduler's default connect timeout must be readable");
        assert!((100..=60_000).contains(&ms), "implausible timeout {ms} ms");
        let pps = scope_rate_ceiling(&read_repo(SCOPE_PATH)).expect("the lab manifest's ceiling");
        assert!(pps > 0);
    }

    #[test]
    fn the_committed_ground_truth_is_what_the_benchmark_scans() {
        let lab = Lab::parse(&read_repo(GROUND_TRUTH_PATH)).expect("the real ground truth parses");
        assert!(lab.targets.len() >= 10, "{:?}", lab.targets);
        assert!(!lab.open.is_empty());
        assert!(
            !lab.products.is_empty(),
            "with no lab-established product, the identification comparison scores nothing \
             and AC-7.14's category cannot exist"
        );
    }

    #[test]
    fn a_lab_with_no_targets_or_no_ports_is_refused() {
        // A benchmark over nothing reports every scanner as perfect.
        let empty = r#"{"scanned_ports":[],"hosts":[],"absent":[]}"#;
        assert!(Lab::parse(empty).is_err());
    }

    // -----------------------------------------------------------------
    // AC-7.12 — accuracy beside timing, scored against the lab.
    // -----------------------------------------------------------------

    #[test]
    fn a_scanner_that_reports_everything_open_is_scored_with_false_positives() {
        let lab = lab();
        let mut observed = Observed::default();
        for ip in &lab.targets {
            for port in &lab.ports {
                observed.open.insert((*ip, *port));
            }
        }
        let scored = score(&lab, &observed);
        assert_eq!(scored.found_open, 2);
        assert!(
            scored.false_positives.len() >= 10,
            "reporting every scanned endpoint open must be scored as wrong: {scored:?}"
        );
        assert!(
            scored
                .false_positives
                .contains(&"10.30.0.200:80".to_string())
        );
    }

    #[test]
    fn a_missed_open_port_is_a_false_negative() {
        let lab = lab();
        let observed = Observed {
            open: [("10.30.0.10".parse().unwrap(), 80u16)]
                .into_iter()
                .collect(),
            identified: BTreeMap::new(),
        };
        let scored = score(&lab, &observed);
        assert_eq!(scored.false_negatives, vec!["10.30.0.17:443".to_string()]);
        assert_eq!(scored.found_open, 1);
        assert_eq!(scored.expected_open, 2);
    }

    #[test]
    fn a_port_nobody_asked_about_is_not_scored_either_way() {
        let lab = lab();
        let observed = Observed {
            open: [
                ("10.30.0.10".parse().unwrap(), 80u16),
                ("10.30.0.17".parse().unwrap(), 443u16),
                // 9999 is not in `scanned_ports`.
                ("10.30.0.10".parse().unwrap(), 9999u16),
            ]
            .into_iter()
            .collect(),
            identified: BTreeMap::new(),
        };
        let scored = score(&lab, &observed);
        assert!(scored.false_positives.is_empty(), "{scored:?}");
    }

    #[test]
    fn a_product_is_scored_against_the_lab_and_not_against_another_scanner() {
        let lab = lab();
        let mut observed = Observed {
            open: lab.open.iter().copied().collect(),
            identified: BTreeMap::new(),
        };
        observed.identified.insert(
            ("10.30.0.10".parse().unwrap(), 80),
            Identification {
                service: Some("http".into()),
                product: Some("nginx".into()),
                version: Some("1.29.8".into()),
            },
        );
        let scored = score(&lab, &observed);
        assert_eq!(scored.products_expected, 2);
        assert_eq!(scored.products_named, 1);
        assert_eq!(scored.versions_named, 1);
        assert_eq!(
            scored.products_missed,
            vec!["10.30.0.17:443 (lab: nginx, reported: nothing)".to_string()]
        );
    }

    #[test]
    fn a_more_verbose_product_string_still_matches_and_a_wrong_one_does_not() {
        assert!(product_matches("nginx", "nginx http server"));
        assert!(product_matches("OpenSSH", "openssh"));
        assert!(!product_matches("nginx", "Apache httpd"));
        assert!(!product_matches("nginx", ""));
        assert!(version_matches("10.3", "10.3p1"));
        assert!(!version_matches("10.3", "9.4.0"));
    }

    #[test]
    fn the_published_table_puts_the_score_in_the_same_row_as_the_time() {
        // AC-7.12 is specifically "next to": a speed table and an accuracy
        // table in different sections is the shape that lets a reader take
        // the first and skip the second.
        let results = results(vec![run(
            "bathy-connect",
            "bathy",
            900,
            true,
            accuracy(1, 1),
        )]);
        let rendered = render(&results, &lab());
        let row = rendered
            .lines()
            .find(|l| l.contains("`bathy-connect`") && l.contains("ms"))
            .expect("a results row");
        // The median of 900/910/920, not the first sample: a benchmark that
        // published its fastest run would be measuring optimism.
        assert!(row.contains("910 ms"), "{row}");
        assert!(row.contains("2/2"), "{row}");
        assert!(row.contains("1/2"), "{row}");
    }

    #[test]
    fn a_timing_without_a_score_is_a_violation() {
        let mut record = run("bathy-connect", "bathy", 900, true, accuracy(1, 1));
        record.accuracy = None;
        let results = results(vec![record]);
        let lab = lab();
        let doc = document_for(&results, &lab);
        let found = violations_of(&doc, &results, &lab);
        assert!(
            found.iter().any(|v| v.contains("accuracy beside timing")),
            "{found:?}"
        );
    }

    // -----------------------------------------------------------------
    // AC-7.13 — versions and command lines, published.
    // -----------------------------------------------------------------

    #[test]
    fn an_uninstalled_scanner_gets_a_named_row_saying_so() {
        // Never a silent omission: a reader must not be able to mistake a
        // two-scanner comparison for a four-scanner one.
        let results = results(vec![run(
            "bathy-connect",
            "bathy",
            900,
            true,
            accuracy(1, 1),
        )]);
        let rendered = render(&results, &lab());
        for absent in ["masscan", "rustscan", "nmap"] {
            let row = rendered
                .lines()
                .find(|l| l.starts_with(&format!("| `{absent}` |")))
                .unwrap_or_else(|| panic!("no row for {absent}:\n{rendered}"));
            assert!(row.contains("NOT RUN"), "{row}");
        }
    }

    #[test]
    fn a_scanner_dropped_from_the_results_is_a_violation() {
        let mut results = results(vec![run(
            "bathy-connect",
            "bathy",
            900,
            true,
            accuracy(1, 1),
        )]);
        let lab = lab();
        let doc = document_for(&results, &lab);
        results.scanners.retain(|s| s.name != "masscan");
        let found = violations_of(&doc, &results, &lab);
        assert!(
            found.iter().any(|v| v.contains("no row for `masscan`")),
            "{found:?}"
        );
    }

    #[test]
    fn a_results_file_quoting_a_stale_remedy_is_a_violation() {
        // The remedy is what a reader runs to make an absent tool present, so
        // a wrong one is a wrong instruction. `masscan`'s was wrong once: it
        // named only `nmap masscan`, and Debian's masscan package declares no
        // dependency on libpcap while masscan dlopens it, so the tool installed
        // and then refused to open an adapter. Correcting the constant without
        // re-running would have left `bench/results.json` quoting the broken
        // one, and nothing else here compares the two.
        let mut results = results(vec![run(
            "bathy-connect",
            "bathy",
            900,
            true,
            accuracy(1, 1),
        )]);
        let lab = lab();
        let doc = document_for(&results, &lab);
        let masscan = results
            .scanners
            .iter_mut()
            .find(|s| s.name == "masscan")
            .expect("SCANNERS names masscan");
        masscan.remedy = "some older instruction".into();
        let found = violations_of(&doc, &results, &lab);
        assert!(
            found
                .iter()
                .any(|v| v.contains("different remedy for `masscan`")),
            "{found:?}"
        );
    }

    #[test]
    fn a_command_line_missing_from_the_document_is_a_violation() {
        let results = results(vec![run(
            "bathy-connect",
            "bathy",
            900,
            true,
            accuracy(1, 1),
        )]);
        let lab = lab();
        let doc = document_for(&results, &lab).replace("bathy --run-it", "bathy --something-else");
        let found = violations_of(&doc, &results, &lab);
        assert!(
            found.iter().any(|v| v.contains("command line verbatim")),
            "{found:?}"
        );
    }

    #[test]
    fn a_run_with_no_command_line_at_all_is_a_violation() {
        let mut record = run("bathy-connect", "bathy", 900, true, accuracy(1, 1));
        record.command_lines.clear();
        let results = results(vec![record]);
        let lab = lab();
        let doc = document_for(&results, &lab);
        let found = violations_of(&doc, &results, &lab);
        assert!(
            found.iter().any(|v| v.contains("no command line")),
            "{found:?}"
        );
    }

    #[test]
    fn a_document_whose_numbers_no_longer_match_the_run_is_a_violation() {
        let results = results(vec![run(
            "bathy-connect",
            "bathy",
            900,
            true,
            accuracy(1, 1),
        )]);
        let lab = lab();
        let doc = document_for(&results, &lab).replace("910 ms", "9 ms");
        let found = violations_of(&doc, &results, &lab);
        assert!(
            found.iter().any(|v| v.contains("generated block")),
            "{found:?}"
        );
    }

    #[test]
    fn a_stale_run_taken_at_a_different_timeout_is_a_violation() {
        let results = results(vec![run(
            "bathy-connect",
            "bathy",
            900,
            true,
            accuracy(1, 1),
        )]);
        let lab = lab();
        let doc = document_for(&results, &lab);
        let subjects = subjects_all_present();
        let found = bench_violations(
            &results,
            &lab,
            &TreeState {
                scheduler_source: "impl Default for SchedulerConfig {\n connect_timeout: \
                     Duration::from_secs(5),\n}",
                ..clean_tree(&doc, &subjects)
            },
        );
        assert!(found.iter().any(|v| v.contains("stale")), "{found:?}");
    }

    #[test]
    fn a_clean_tree_produces_no_violations_at_all() {
        // The other direction: without this, every assertion above could be
        // passing because the checker always finds something.
        let results = results(vec![run(
            "bathy-connect",
            "bathy",
            900,
            true,
            accuracy(1, 1),
        )]);
        let lab = lab();
        let doc = document_for(&results, &lab);
        assert_eq!(violations_of(&doc, &results, &lab), Vec::<String>::new());
    }

    // -----------------------------------------------------------------
    // AC-7.14 — the categories where bathy loses.
    // -----------------------------------------------------------------

    #[test]
    fn a_competitor_that_names_more_products_is_published_as_a_loss() {
        let results = results(vec![
            run("bathy-connect", "bathy", 900, true, accuracy(1, 1)),
            run("nmap-version", "nmap", 900, true, accuracy(2, 2)),
        ]);
        let found = losses(&results, &lab());
        assert!(
            found
                .iter()
                .any(|l| l.category == "service identification, in total"
                    && l.detail.contains("nmap-version")),
            "{found:?}"
        );
        assert!(
            found.iter().any(|l| l.category == "version identification"),
            "{found:?}"
        );
    }

    #[test]
    fn two_tools_that_name_the_same_number_of_products_at_different_endpoints_is_still_a_loss() {
        // The case the real run actually produced, and the one an aggregate
        // count reports as a tie: bathy named MySQL and missed the
        // TLS-fronted nginx; Nmap named the nginx and missed MySQL. Five each.
        // Reporting "5/6 versus 5/6" and stopping there would have hidden the
        // single most concrete identification loss this project has.
        let mut ours = accuracy(1, 1);
        ours.products_named_at = vec!["10.30.0.10:80".into()];
        let mut theirs = accuracy(1, 1);
        theirs.products_named_at = vec!["10.30.0.17:443".into()];
        assert_eq!(
            ours.products_named, theirs.products_named,
            "the fixture must be a tie on the count, or this test proves nothing"
        );
        let results = results(vec![
            run("bathy-connect", "bathy", 900, true, ours),
            run("nmap-version", "nmap", 900, true, theirs),
        ]);
        let found = losses(&results, &lab());
        let per_endpoint = found
            .iter()
            .find(|l| l.category == "service identification, per endpoint")
            .unwrap_or_else(|| panic!("{found:?}"));
        assert!(
            per_endpoint.detail.contains("10.30.0.17:443"),
            "{per_endpoint:?}"
        );
        assert!(
            !found
                .iter()
                .any(|l| l.category == "service identification, in total"),
            "a tie on the total is not a loss on the total: {found:?}"
        );
    }

    #[test]
    fn a_faster_competitor_is_published_as_a_loss() {
        let results = results(vec![
            run("bathy-connect", "bathy", 5000, true, accuracy(2, 2)),
            run("nmap-connect", "nmap", 500, false, accuracy(2, 2)),
        ]);
        let found = losses(&results, &lab());
        let speed = found
            .iter()
            .find(|l| l.category == "wall clock")
            .unwrap_or_else(|| panic!("{found:?}"));
        assert!(speed.detail.contains("nmap-connect"), "{speed:?}");
    }

    #[test]
    fn the_labs_own_identification_gap_is_a_loss_even_when_no_other_scanner_ran() {
        // The honest floor. With only bathy installed there is nobody to lose
        // to, and AC-7.14 still has to be discharged from what the oracle
        // knows: `10.30.0.17:443` carries a product bathy does not report.
        let results = results(vec![run(
            "bathy-connect",
            "bathy",
            900,
            true,
            accuracy(1, 1),
        )]);
        let found = losses(&results, &lab());
        assert!(
            found
                .iter()
                .any(|l| l.category.contains("identification gap")
                    && l.detail.contains("10.30.0.17:443")),
            "{found:?}"
        );
    }

    #[test]
    fn a_loss_the_document_omits_is_a_violation() {
        let results = results(vec![
            run("bathy-connect", "bathy", 900, true, accuracy(1, 1)),
            run("nmap-version", "nmap", 900, true, accuracy(2, 2)),
        ]);
        let lab = lab();
        let doc = document_for(&results, &lab);
        let losses = losses(&results, &lab);
        let censored = doc.replace(&losses[0].detail, "bathy did fine actually");
        assert_ne!(censored, doc, "the fixture must actually contain the loss");
        let found = violations_of(&censored, &results, &lab);
        assert!(
            found
                .iter()
                .any(|v| v.contains("omits a category where bathy loses")),
            "{found:?}"
        );
    }

    #[test]
    fn a_competitor_that_found_more_open_ports_is_published_as_a_loss() {
        let mut ours = accuracy(2, 2);
        ours.found_open = 1;
        ours.false_negatives = vec!["10.30.0.17:443".into()];
        let results = results(vec![
            run("bathy-connect", "bathy", 900, true, ours),
            run("nmap-connect", "nmap", 900, false, accuracy(2, 2)),
        ]);
        let found = losses(&results, &lab());
        assert!(
            found.iter().any(|l| l.category == "open ports found"),
            "{found:?}"
        );
    }

    // -----------------------------------------------------------------
    // AC-7.15 — the criterion benchmarks.
    // -----------------------------------------------------------------

    #[test]
    fn the_registry_names_the_four_subjects_the_criterion_asks_for() {
        let names: Vec<&str> = BENCH_SUBJECTS.iter().map(|s| s.subject).collect();
        assert_eq!(
            names,
            vec![
                "interpret",
                "canonical_json",
                "plan construction",
                "log append"
            ],
            "AC-7.15 names exactly these four"
        );
    }

    #[test]
    fn every_registered_criterion_benchmark_exists_and_is_wired_up() {
        // The test that dies if a bench file is deleted or a `[[bench]]`
        // stanza is dropped from a manifest.
        let root = repo_root();
        for subject in BENCH_SUBJECTS {
            let file = root.join(subject.bench_file);
            assert!(file.exists(), "{} does not exist", file.display());
            let manifest = read_repo(&format!("{}/Cargo.toml", subject.crate_dir));
            assert!(
                manifest.contains(&format!("name = \"{}\"", subject.bench_name)),
                "{}/Cargo.toml does not declare the `{}` bench",
                subject.crate_dir,
                subject.bench_name
            );
            assert!(
                manifest.contains("harness = false"),
                "{}/Cargo.toml must set harness = false",
                subject.crate_dir
            );
        }
    }

    #[test]
    fn a_ci_workflow_that_never_executes_the_benchmarks_is_a_violation() {
        let results = results(vec![run(
            "bathy-connect",
            "bathy",
            900,
            true,
            accuracy(1, 1),
        )]);
        let lab = lab();
        let doc = document_for(&results, &lab);
        let subjects = subjects_all_present();
        let found = bench_violations(
            &results,
            &lab,
            &TreeState {
                ci: "jobs:\n  test:\n    steps:\n      - run: cargo test --workspace\n",
                ..clean_tree(&doc, &subjects)
            },
        );
        assert!(found.iter().any(|v| v.contains("--benches")), "{found:?}");
    }

    #[test]
    fn the_committed_workflow_executes_the_benchmarks() {
        let ci = read_repo(crate::visibility::CI_PATH);
        assert!(
            crate::visibility::job_run_steps(&ci, FAST_CI_JOB)
                .iter()
                .any(|s| s.starts_with("cargo test") && s.contains("--benches")),
            "the real workflow must run the criterion benchmarks, not only compile them"
        );
    }

    #[test]
    fn a_missing_bench_file_is_a_violation() {
        let results = results(vec![run(
            "bathy-connect",
            "bathy",
            900,
            true,
            accuracy(1, 1),
        )]);
        let lab = lab();
        let doc = document_for(&results, &lab);
        let mut subjects = subjects_all_present();
        subjects[0].1 = false;
        let found = bench_violations(&results, &lab, &clean_tree(&doc, &subjects));
        assert!(
            found.iter().any(|v| v.contains("does not exist")),
            "{found:?}"
        );
    }

    #[test]
    fn a_manifest_that_drops_harness_false_is_a_violation() {
        let results = results(vec![run(
            "bathy-connect",
            "bathy",
            900,
            true,
            accuracy(1, 1),
        )]);
        let lab = lab();
        let doc = document_for(&results, &lab);
        let mut subjects = subjects_all_present();
        subjects[1].2 =
            Some("[package]\nname = \"x\"\n\n[[bench]]\nname = \"canonical_json\"\n".into());
        let found = bench_violations(&results, &lab, &clean_tree(&doc, &subjects));
        assert!(
            found.iter().any(|v| v.contains("harness = false")),
            "{found:?}"
        );
    }

    // -----------------------------------------------------------------
    // The parsers, and the guard that stops one of them lying quietly.
    // -----------------------------------------------------------------

    /// Synthetic, hand-written from the documented shape of `-oX` output.
    /// No captured Nmap run is checked in anywhere in this repository.
    const NMAP_XML: &str = r#"<?xml version="1.0"?>
<nmaprun scanner="nmap">
<host><address addr="10.30.0.10" addrtype="ipv4"/>
<ports>
<port protocol="tcp" portid="80"><state state="open" reason="syn-ack"/>
<service name="http" product="nginx" version="1.29.8" method="probed"/></port>
<port protocol="tcp" portid="22"><state state="closed" reason="conn-refused"/>
<service name="ssh" method="table"/></port>
</ports></host>
<host><address addr="10.30.0.200" addrtype="ipv4"/>
<ports><port protocol="tcp" portid="80"><state state="filtered" reason="no-response"/></port>
</ports></host>
</nmaprun>"#;

    #[test]
    fn nmap_xml_yields_open_ports_and_the_products_it_named() {
        let observed = parse_nmap_xml(NMAP_XML);
        assert_eq!(
            observed.open,
            [("10.30.0.10".parse().unwrap(), 80u16)]
                .into_iter()
                .collect()
        );
        let named = &observed.identified[&("10.30.0.10".parse().unwrap(), 80)];
        assert_eq!(named.product.as_deref(), Some("nginx"));
        assert_eq!(named.version.as_deref(), Some("1.29.8"));
    }

    #[test]
    fn an_nmap_state_of_closed_or_filtered_is_not_open() {
        let observed = parse_nmap_xml(NMAP_XML);
        assert!(!observed.open.contains(&("10.30.0.10".parse().unwrap(), 22)));
        assert!(
            !observed
                .open
                .contains(&("10.30.0.200".parse().unwrap(), 80))
        );
    }

    #[test]
    fn masscan_list_output_yields_open_ports() {
        let observed = parse_masscan_list(
            "#masscan\nopen tcp 80 10.30.0.10 1754320000\nopen tcp 443 10.30.0.17 1754320001\n\
             # end\n",
        );
        assert_eq!(observed.open.len(), 2);
        assert!(
            observed
                .open
                .contains(&("10.30.0.17".parse().unwrap(), 443))
        );
    }

    #[test]
    fn rustscan_greppable_output_yields_open_ports() {
        let observed = parse_rustscan_greppable("10.30.0.10 -> [80,443]\n10.30.0.18 -> []\n");
        assert_eq!(observed.open.len(), 2);
        assert!(
            observed
                .open
                .contains(&("10.30.0.10".parse().unwrap(), 443))
        );
    }

    #[test]
    fn bathys_query_document_yields_open_ports_and_observations() {
        // One document per line, which is what `--json` emits (AC-5.10).
        let json = concat!(
            r#"{"scan_id":"scan_01K2","status":"running"}"#,
            "\n",
            r#"{"endpoints":["#,
            r#"{"target":"10.30.0.10","endpoint":{"transport":"tcp","port":80},"state":"open","#,
            r#""observation":{"service":"http","product":"nginx","version":"1.29.8","confidence":0.9},"#,
            r#""evidence_refs":[],"probe_id":"http-get-v1","rule_id":"http.server.nginx.v1"},"#,
            r#"{"target":"10.30.0.17","endpoint":{"transport":"tcp","port":443},"state":"open","#,
            r#""observation":{"service":"tls","confidence":0.8},"#,
            r#""evidence_refs":[],"probe_id":"tls-v1","rule_id":"tls.v1"},"#,
            r#"{"target":"10.30.0.10","endpoint":{"transport":"tcp","port":22},"state":"closed","#,
            r#""observation":null,"evidence_refs":[],"probe_id":null,"rule_id":null}],"#,
            r#""total":3}"#,
            "\n"
        );
        let observed = parse_bathy_query(json).expect("parses");
        assert_eq!(observed.open.len(), 2, "a closed endpoint is not open");
        let tls = &observed.identified[&("10.30.0.17".parse().unwrap(), 443)];
        assert_eq!(tls.service.as_deref(), Some("tls"));
        assert_eq!(
            tls.product, None,
            "this is the identification gap the lab records, and it must survive the parser \
             rather than being filled in from the service name"
        );
    }

    #[test]
    fn a_tool_that_parses_to_nothing_at_all_is_a_harness_failure_not_a_score_of_zero() {
        let lab = lab();
        assert!(
            implausible_observation(&Observed::default(), &lab)
                .is_some_and(|c| c.contains("parser does not understand")),
            "a competitor scored at zero because our parser did not understand its output \
             would be the most flattering possible bug for this project to have"
        );
        let found_something = Observed {
            open: [("10.30.0.10".parse().unwrap(), 80u16)]
                .into_iter()
                .collect(),
            identified: BTreeMap::new(),
        };
        assert_eq!(implausible_observation(&found_something, &lab), None);
    }

    #[test]
    fn the_scan_id_is_read_off_the_handle_bathy_prints_first() {
        // The shape `bathy --json scan start` actually prints.
        let stdout = concat!(
            r#"{"handle":{"estimated_targets":11,"status":"running","task_id":"scan_01K2"},"#,
            r#""policy_decision":"approved","reused":false}"#,
            "\n",
            r#"{"open_ports":12,"units_completed":143}"#,
            "\n"
        );
        assert_eq!(scan_id_of(stdout).as_deref(), Ok("scan_01K2"));
        assert!(scan_id_of("not json at all").is_err());
        assert!(
            scan_id_of(r#"{"handle":{"task_id":"not-a-scan-id"}}"#).is_err(),
            "an identifier that is not a scan id must not be handed to `result query`"
        );
    }

    #[test]
    fn tcp_active_opens_is_read_from_the_kernels_own_counter() {
        let snmp = "Tcp: RtoAlgorithm RtoMin ActiveOpens PassiveOpens\n\
                    Tcp: 1 200 4211 17\n";
        assert_eq!(tcp_active_opens(snmp), Some(4211));
        assert_eq!(tcp_active_opens("Udp: InDatagrams\nUdp: 3\n"), None);
    }

    #[test]
    fn splicing_needs_both_markers() {
        let doc = format!("before\n{GENERATED_BEGIN}\nold\n{GENERATED_END}\nafter\n");
        let out =
            splice(&doc, &format!("{GENERATED_BEGIN}\nnew\n{GENERATED_END}")).expect("splice");
        assert!(out.contains("before") && out.contains("new") && out.contains("after"));
        assert!(!out.contains("old"));
        assert!(splice("no markers here", "x").is_err());
    }
}
