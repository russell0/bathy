//! AC-6.14: SYN scanning agrees with connect scanning **and with the kernel**
//! on every endpoint of the lab.
//!
//! # Three columns, not two
//!
//! The criterion as written compares two scanners. Two scanners that agree
//! with each other and disagree with the network is a *worse* finding than a
//! disagreement, and a two-column test cannot see it: it is the shape of the
//! `10.30.0.17:443` defect M7 Task 1 found in this lab's own oracle, where the
//! ground truth had recorded what the scanner produced instead of what was
//! there.
//!
//! So there is a third column: `lab/ground-truth.json`, derived by
//! `lab/verify-ground-truth.py` from a full 65535-port sweep run inside each
//! container's network namespace, with Python standard-library sockets that
//! share no code, no port table and no fingerprint data with bathy. Every
//! endpoint is judged against it, and the failure report prints all three so
//! that "which one is wrong" is answerable from the output rather than by
//! re-running anything.
//!
//! # What "agreement" means for an endpoint the truth does not list
//!
//! The oracle lists open ports. Everything else on `scanned_ports` is derived,
//! and the derivation is stated once here rather than restated per assertion:
//!
//! - a port on a **present** host that the sweep did not find open is
//!   `closed` -- the lab's containers sit behind a Docker bridge that answers
//!   an unbound port with a reset, which is what makes `closed` the right
//!   expectation rather than `filtered`;
//! - every port on an **absent** address is `filtered` -- there is no host to
//!   answer and no router to refuse, so both methods see silence.
//!
//! If the lab's networking ever stops behaving that way, this test fails
//! naming the endpoint and all three verdicts, which is the correct outcome:
//! the derivation above is an assumption about the fixture and it should not
//! be able to rot quietly.
//!
//! # Where this runs
//!
//! `cargo run -p xtask -- syn-cross-validation`, which is a container on
//! `bathy-lab_labnet` holding `CAP_NET_RAW`, and CI's `syn-cross-validation`
//! job. It is `#[ignore]`d so `cargo test --workspace` lists it rather than
//! pretending to have run it, and `BATHY_LAB_REQUIRED` turns every
//! precondition below from a skip into a failure.

#![cfg(unix)]

use std::collections::BTreeMap;
use std::io::Write;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use bathy_engine::packetd::PacketdConfig;
use bathy_engine::{GroupCommitConfig, GroupCommitLog, Scheduler, SchedulerConfig};
use bathy_evidence::EvidenceStore;
use bathy_plan::ScanPlan;
use bathy_probe::ProbeRegistry;
use bathy_scope::{BudgetLedger, ScopeManifest};
use bathy_store::{StartRequest, TaskStore};
use bathy_types::clock::{Clock, FixedClock};
use bathy_types::event::{EventBody, PortState, ScanMode};
use bathy_types::nonempty::NonEmpty;
use bathy_types::request::{
    Budgets, EvidenceLevel, Objective, PortSelection, ScanRequest, ServiceDetection,
};
use serde::Deserialize;
use tokio_util::sync::CancellationToken;

/// Compiled in rather than read at runtime: a lab file that has been renamed
/// should break the build, not produce a suite that skips.
const GROUND_TRUTH: &str = include_str!("../../../lab/ground-truth.json");
const SCOPE_MANIFEST: &str = include_str!("../../../lab/scope.json");

/// Set by `lab/run.sh test` and by `xtask syn-cross-validation`. Its presence
/// means "the lab and the capability are supposed to be here, so treat their
/// absence as a failure rather than a reason to skip".
const REQUIRE_LAB: &str = "BATHY_LAB_REQUIRED";

// ---------------------------------------------------------------------------
// The oracle, as data.
// ---------------------------------------------------------------------------

/// `deny_unknown_fields` throughout, and load-bearing rather than tidy:
/// without it a key misspelled in the JSON deserializes to an empty list and
/// every comparison below ranges over nothing while reporting success.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GroundTruth {
    #[allow(dead_code)]
    subnet: String,
    #[allow(dead_code)]
    derivation: serde_json::Value,
    scanned_ports: Vec<u16>,
    hosts: Vec<TruthHost>,
    absent: Vec<IpAddr>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TruthHost {
    ip: IpAddr,
    up: bool,
    #[allow(dead_code)]
    service: String,
    open: Vec<TruthPort>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TruthPort {
    port: u16,
    #[allow(dead_code)]
    service: String,
    #[allow(dead_code)]
    product: Option<String>,
    #[allow(dead_code)]
    version: Option<String>,
    #[allow(dead_code)]
    evidence: String,
    #[allow(dead_code)]
    product_inference: Option<String>,
    #[allow(dead_code)]
    identification_gap: Option<String>,
}

impl GroundTruth {
    fn load() -> Self {
        serde_json::from_str(GROUND_TRUTH).expect("lab/ground-truth.json does not parse")
    }

    fn targets(&self) -> Vec<String> {
        self.hosts
            .iter()
            .map(|h| h.ip.to_string())
            .chain(self.absent.iter().map(IpAddr::to_string))
            .collect()
    }

    /// The state the kernel's own bind table implies for every endpoint the
    /// scan covers. See the module doc for the derivation.
    fn expected(&self) -> BTreeMap<(IpAddr, u16), PortState> {
        let mut expected = BTreeMap::new();
        for host in &self.hosts {
            assert!(
                host.up,
                "{} is listed under `hosts` and is not up; this file's own shape says every \
                 entry there is present",
                host.ip
            );
            for port in &self.scanned_ports {
                let state = if host.open.iter().any(|o| o.port == *port) {
                    PortState::Open
                } else {
                    PortState::Closed
                };
                expected.insert((host.ip, *port), state);
            }
        }
        for ip in &self.absent {
            for port in &self.scanned_ports {
                expected.insert((*ip, *port), PortState::Filtered);
            }
        }
        expected
    }
}

// ---------------------------------------------------------------------------
// Preconditions, each of which fails rather than skips under REQUIRE_LAB.
// ---------------------------------------------------------------------------

fn demanded() -> bool {
    std::env::var_os(REQUIRE_LAB).is_some()
}

/// `false` means "skip"; a panic means "you asked for this and it is not
/// here". Never returns `false` when [`REQUIRE_LAB`] is set.
fn precondition(ok: bool, reason: &str) -> bool {
    if ok {
        return true;
    }
    assert!(
        !demanded(),
        "{REQUIRE_LAB} is set, so this is a failure and not a skip: {reason}"
    );
    // Straight to the process's stderr: libtest captures the print macros and
    // discards them for a test that passes.
    let mut err = std::io::stderr().lock();
    let _ = err.write_all(format!("\nSKIPPED: {reason}\n\n").as_bytes());
    let _ = err.flush();
    false
}

fn lab_is_reachable(truth: &GroundTruth) -> bool {
    let (ip, port) = truth
        .hosts
        .iter()
        .find_map(|h| h.open.first().map(|o| (h.ip, o.port)))
        .expect("the ground truth records no open port anywhere");
    TcpStream::connect_timeout(&SocketAddr::from((ip, port)), Duration::from_secs(3)).is_ok()
}

fn this_process_holds_cap_net_raw() -> bool {
    socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::RAW,
        Some(socket2::Protocol::TCP),
    )
    .is_ok()
}

fn packetd_bin() -> PathBuf {
    let mut dir = std::env::current_exe().expect("the test binary has a path");
    dir.pop();
    if dir.ends_with("deps") {
        dir.pop();
    }
    let bin = dir.join("bathy-packetd");
    assert!(
        bin.exists(),
        "{} does not exist; build it with `cargo build --workspace`",
        bin.display()
    );
    bin
}

// ---------------------------------------------------------------------------
// One scan, one mode.
// ---------------------------------------------------------------------------

/// Runs the whole lab with `packetd`, or without it, and returns what the
/// scan *logged* -- not what any in-memory summary said, because the log is
/// the artifact a consumer reads.
async fn scan_lab(truth: &GroundTruth, packetd: PacketdConfig) -> ScanResult {
    let dir = tempfile::tempdir().expect("a temp dir");
    let clock: Arc<dyn Clock> =
        Arc::new(FixedClock::new("2026-08-05T00:00:00.000Z", 7).expect("a fixed clock"));
    let store = Arc::new(TaskStore::open(dir.path(), Arc::clone(&clock)).expect("a store"));
    let manifest = Arc::new(ScopeManifest::load(SCOPE_MANIFEST).expect("lab/scope.json loads"));
    let budgets = Budgets {
        maximum_packets: 100_000,
        maximum_runtime_seconds: 3_600,
        // Well under the manifest's 100000 ceiling, and enough that the
        // serial SYN path is not what dominates the run.
        maximum_packets_per_second: 500,
    };
    let mode = packetd.requested_mode();
    let request = ScanRequest {
        targets: NonEmpty::try_from(truth.targets()).expect("the lab has targets"),
        authorization_scope_id: manifest.id(),
        objective: Objective::InventoryExposedServices,
        ports: PortSelection::Explicit {
            explicit: NonEmpty::try_from(
                truth
                    .scanned_ports
                    .iter()
                    .map(|p| p.to_string())
                    .collect::<Vec<_>>(),
            )
            .expect("the lab has ports"),
        },
        // Identification reconnects with a real TCP connect. A SYN scan that
        // then connected to every open port would not be a SYN scan, and the
        // two runs would not be comparable.
        service_detection: ServiceDetection {
            enabled: false,
            intensity: 0,
        },
        budgets,
        evidence_level: EvidenceLevel::None,
        idempotency_key: format!("syn-vs-connect-{}", mode.code()),
    };
    let plan = ScanPlan::build(&request, 100_000).expect("the plan builds");
    let outcome = store
        .start_or_reuse(&StartRequest {
            idempotency_key: request.idempotency_key.clone(),
            plan_hash: plan.hash(),
            scope_id: request.authorization_scope_id,
            request_json: "{}".to_string(),
            estimated_targets: plan.targets().len() as u64,
            estimated_probes: plan.len(),
        })
        .expect("the scan starts");
    let scan_id = outcome.scan_id();
    let log = Arc::new(std::sync::Mutex::new(
        GroupCommitLog::open(dir.path(), scan_id, GroupCommitConfig::default()).expect("a log"),
    ));
    let scheduler = Scheduler::new(
        BudgetLedger::new(budgets),
        manifest,
        SchedulerConfig {
            concurrency: 64,
            connect_timeout: Duration::from_secs(2),
            progress_every: 500,
            packetd,
        },
        Arc::clone(&log),
        store,
        clock,
        scan_id,
        "0.1.0",
        request.service_detection,
        request.evidence_level,
        Arc::new(EvidenceStore::open(dir.path()).expect("an evidence store")),
        Arc::new(ProbeRegistry::standard()),
    );
    scheduler
        .run(&plan, 0, CancellationToken::new())
        .await
        .expect("the run returns");

    let events = log
        .lock()
        .expect("log mutex")
        .read_from(0)
        .expect("the log reads back");
    let mut endpoints = BTreeMap::new();
    let mut recorded_mode = None;
    let mut failure = None;
    for event in events {
        match event.body {
            EventBody::ScanStarted { scan_mode, .. } => recorded_mode = scan_mode,
            EventBody::PortStateObserved {
                target,
                endpoint,
                state,
                ..
            } => {
                endpoints.insert((target.ip, endpoint.port), state);
            }
            EventBody::ScanFailed {
                reason_code,
                detail,
            } => failure = Some(format!("{reason_code}: {detail}")),
            _ => {}
        }
    }
    ScanResult {
        requested: mode,
        recorded: recorded_mode,
        endpoints,
        failure,
        _dir: dir,
    }
}

struct ScanResult {
    requested: ScanMode,
    recorded: Option<ScanMode>,
    endpoints: BTreeMap<(IpAddr, u16), PortState>,
    failure: Option<String>,
    _dir: tempfile::TempDir,
}

impl ScanResult {
    /// A scan that did not run in the mode it was asked for has not tested
    /// what this file exists to test, and the fallback would make the
    /// comparison connect-versus-connect -- which passes trivially.
    fn assert_ran_as_requested(&self) {
        assert_eq!(
            self.failure,
            None,
            "the {} scan failed",
            self.requested.code()
        );
        assert_eq!(
            self.recorded,
            Some(self.requested),
            "the {} scan recorded {:?} on scan.started. A SYN run that silently fell back \
             would make this whole comparison connect-against-connect, which agrees by \
             construction and proves nothing.",
            self.requested.code(),
            self.recorded,
        );
    }
}

// ---------------------------------------------------------------------------
// AC-6.14.
// ---------------------------------------------------------------------------

/// SYN, connect and the kernel's own bind table, compared on every endpoint.
#[tokio::test]
#[ignore = "requires CAP_NET_RAW and the lab; run `cargo run -p xtask -- syn-cross-validation`"]
async fn syn_and_connect_scans_agree_with_the_ground_truth_on_every_lab_endpoint() {
    let truth = GroundTruth::load();
    if !precondition(
        this_process_holds_cap_net_raw(),
        "this process cannot open a raw socket, so there is no SYN scan to compare",
    ) {
        return;
    }
    if !precondition(
        lab_is_reachable(&truth),
        "the lab is not reachable from here; bring it up with `lab/run.sh up` and run this \
         from a container on `bathy-lab_labnet`",
    ) {
        return;
    }

    let expected = truth.expected();

    // The fixture must exclude something: a lab in which every endpoint had
    // the same expected state would make agreement free.
    let distinct: Vec<PortState> = [PortState::Open, PortState::Closed, PortState::Filtered]
        .into_iter()
        .filter(|want| expected.values().any(|state| state == want))
        .collect();
    assert_eq!(
        distinct,
        vec![PortState::Open, PortState::Closed, PortState::Filtered],
        "the ground truth must demand all three states of both scanners, or agreement is \
         free"
    );

    let connect = scan_lab(&truth, PacketdConfig::default()).await;
    connect.assert_ran_as_requested();
    let syn = scan_lab(&truth, PacketdConfig::syn_via(packetd_bin())).await;
    syn.assert_ran_as_requested();

    let mut rows = Vec::new();
    for (key, want) in &expected {
        let (ip, port) = key;
        let c = connect.endpoints.get(key);
        let s = syn.endpoints.get(key);
        if c != Some(want) || s != Some(want) {
            rows.push(format!(
                "{ip}:{port}  truth={want:?}  connect={c:?}  syn={s:?}"
            ));
        }
    }

    assert!(
        rows.is_empty(),
        "{} of {} endpoints disagree. All three columns are printed so the question is \
         which one is wrong, not whether to tune one scanner until it matches the other:\n{}",
        rows.len(),
        expected.len(),
        rows.join("\n"),
    );

    // Both scans must have covered the whole plan; a scan that stopped early
    // agrees on every endpoint it reached.
    assert_eq!(
        connect.endpoints.len(),
        expected.len(),
        "the connect scan observed {} of {} endpoints",
        connect.endpoints.len(),
        expected.len()
    );
    assert_eq!(
        syn.endpoints.len(),
        expected.len(),
        "the SYN scan observed {} of {} endpoints",
        syn.endpoints.len(),
        expected.len()
    );
    // And the endpoint the whole lab is built around, named explicitly, so a
    // ground truth that lost its open ports fails here rather than passing
    // over a set of all-closed expectations.
    let nginx = ("10.30.0.10".parse::<IpAddr>().expect("an address"), 80u16);
    assert_eq!(syn.endpoints.get(&nginx), Some(&PortState::Open));
    assert_eq!(connect.endpoints.get(&nginx), Some(&PortState::Open));
}
