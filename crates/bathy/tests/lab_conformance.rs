//! The lab conformance suite: AC-7.2 through AC-7.6.
//!
//! # Why this is the oracle
//!
//! Every other test in this workspace either builds its own listener or
//! replays bytes captured earlier. Both are honest, and neither can tell you
//! whether the scanner is right about a *network*. The lab can, because we
//! control the images, we pin them by content digest, and `lab/ground-truth.json`
//! states -- from a full 65535-port sweep run from inside the lab network by
//! a program that shares no code with `bathy` -- exactly what listens where.
//! Correctness then stops being a judgement call and becomes an assertion.
//!
//! That cuts both ways, which is why AC-7.3 exists alongside AC-7.2. A lab
//! that only proves we find open ports is half a test: a scanner that reported
//! every port open would pass it. `lab/ground-truth.json` therefore also
//! records what is *closed*, its `scanned_ports` set includes ports that are
//! shut on hosts that are up, and `xtask check-lab` fails if either of those
//! narrowing controls is ever removed.
//!
//! # Where the lab is not
//!
//! `labnet` is a Docker bridge network. On Linux the host routes to it and
//! these tests run as written. On macOS it is not routable from the host at
//! all -- Docker Desktop runs the daemon inside a VM whose bridges are not
//! exposed to the Mac's routing table -- and in CI there may be no Docker at
//! all. So:
//!
//! * every test here is `#[ignore]`d, so `cargo test --workspace` lists them
//!   as ignored rather than running or silently omitting them;
//! * run with `--ignored` against a lab that is not reachable, each one
//!   prints why and returns, rather than failing with a connection error
//!   that reads like a scanner defect;
//! * and `lab/run.sh test` sets `BATHY_LAB_REQUIRED`, which turns that skip
//!   into a hard failure. The path whose whole purpose is to test the lab
//!   cannot pass without one.
//!
//! Those three together are the honest story. Two of them alone would not be:
//! `#[ignore]` plus a silent skip is a suite that reports success having done
//! nothing.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bathy_engine::{GroupCommitConfig, GroupCommitLog, Scheduler, SchedulerConfig};
use bathy_evidence::EvidenceStore;
use bathy_plan::ScanPlan;
use bathy_probe::ProbeRegistry;
use bathy_query::{ScanFold, diff, fold_events};
use bathy_scope::{BudgetLedger, ScopeManifest};
use bathy_store::{StartRequest, TaskStore};
use bathy_types::clock::{Clock, SystemClock};
use bathy_types::event::{Endpoint, PortState, Transport};
use bathy_types::nonempty::NonEmpty;
use bathy_types::request::{
    Budgets, EvidenceLevel, Objective, PortSelection, ScanRequest, ServiceDetection,
};
use serde::Deserialize;
use tokio_util::sync::CancellationToken;

/// Compiled in rather than read at runtime: a lab file that has been renamed
/// or moved should break the build, not produce a suite that skips.
const GROUND_TRUTH: &str = include_str!("../../../lab/ground-truth.json");
const SCOPE_MANIFEST: &str = include_str!("../../../lab/scope.json");

/// Set by `lab/run.sh test`. Its presence means "the lab is supposed to be
/// up, so treat its absence as a failure rather than a reason to skip".
const REQUIRE_LAB: &str = "BATHY_LAB_REQUIRED";

// ---------------------------------------------------------------------------
// The ground truth, as data.
// ---------------------------------------------------------------------------

/// `deny_unknown_fields` throughout, and this is load-bearing rather than
/// tidy. Without it a key misspelled in the JSON -- `opne` for `open` --
/// deserializes to an empty list, and every assertion below ranges over
/// nothing while reporting success. That is the failure mode the overview's
/// fixture constraint describes, arriving through the data file instead of
/// through the test.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct GroundTruth {
    #[allow(dead_code)]
    subnet: String,
    #[allow(dead_code)]
    derivation: Derivation,
    scanned_ports: Vec<u16>,
    hosts: Vec<TruthHost>,
    absent: Vec<IpAddr>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Derivation {
    #[allow(dead_code)]
    method: String,
    #[allow(dead_code)]
    swept_ports: String,
    #[allow(dead_code)]
    observed_at: String,
    /// The one entry this file is known to have got wrong, kept in the file
    /// rather than only in a review: `10.30.0.17:443` recorded `product: null`
    /// where the bytes say `Server: nginx/1.29.8`, and a null is what AC-7.5
    /// filters on, so the error hid inside the criterion it corrupted.
    #[allow(dead_code)]
    known_to_be_wrong_before: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TruthHost {
    ip: IpAddr,
    /// A container sits on this address. Every host in `hosts` is up by
    /// construction; the field is here because the absent/up distinction is
    /// what AC-7.4 turns on and reading it in the file should not require
    /// knowing that.
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
    /// `None` where the service volunteers nothing that names a product. See
    /// `lab/README.md`: leaving it null is a statement that the lab does not
    /// establish a product here, not a note that we failed to identify one.
    ///
    /// That convention is load-bearing and it was violated once, at
    /// `10.30.0.17:443`, in the direction that is hardest to see: a null there
    /// matched bathy's own output at the one endpoint where the observed bytes
    /// name a product outright. [`Self::identification_gap`] is the honest
    /// spelling of that situation and is what this field must never be used
    /// for again.
    product: Option<String>,
    version: Option<String>,
    evidence: String,
    /// Set only where `product` is real but is *not* a literal in
    /// [`Self::evidence`] -- it names the non-literal basis instead. Exactly
    /// one entry needs it (MySQL, whose handshake gives a version and an auth
    /// plugin but never the vendor string), and `xtask check-lab` requires
    /// every other product to appear verbatim in its own evidence.
    #[allow(dead_code)]
    product_inference: Option<String>,
    /// Set where the lab establishes a product that **bathy cannot see**, with
    /// the reason. This is the opposite of a null: the oracle states the truth
    /// and separately records that the scanner falls short of it, so the gap
    /// is a finding on the record rather than an absence that reads as
    /// agreement. `service_identification_matches_the_ground_truth_products`
    /// holds every such endpoint to being unidentified *today*, and fails the
    /// moment one is identified -- so closing the gap is what deletes the key.
    identification_gap: Option<String>,
}

impl GroundTruth {
    fn load() -> Self {
        serde_json::from_str(GROUND_TRUTH).expect("lab/ground-truth.json does not parse")
    }

    /// Every address the conformance scan targets: the hosts and the holes.
    fn targets(&self) -> Vec<String> {
        self.hosts
            .iter()
            .map(|h| h.ip.to_string())
            .chain(self.absent.iter().map(IpAddr::to_string))
            .collect()
    }

    fn is_open(&self, ip: IpAddr, port: u16) -> bool {
        self.hosts
            .iter()
            .any(|h| h.ip == ip && h.open.iter().any(|o| o.port == port))
    }
}

fn tcp(port: u16) -> Endpoint {
    Endpoint {
        transport: Transport::Tcp,
        port,
    }
}

// ---------------------------------------------------------------------------
// Reachability, and the three-way answer to "is the lab there".
// ---------------------------------------------------------------------------

/// `Some(reason)` when the lab cannot be scanned from here, phrased so that
/// the reason is actionable rather than a bare connection error.
fn lab_unavailable(truth: &GroundTruth) -> Option<String> {
    let (ip, port) = truth
        .hosts
        .iter()
        .find_map(|h| h.open.first().map(|o| (h.ip, o.port)))
        .expect("the ground truth records no open port anywhere, so there is nothing to probe");
    let address = SocketAddr::new(ip, port);
    match TcpStream::connect_timeout(&address, Duration::from_secs(3)) {
        Ok(_) => None,
        Err(e) => Some(format!(
            "the lab is not reachable at {address} ({e}). Bring it up with \
             `lab/run.sh up`. If it is already up, the most likely cause is that this \
             host cannot route to the lab's bridge network: on macOS, Docker Desktop \
             runs the daemon inside a VM and `labnet` is not exposed to the host's \
             routing table, so these tests cannot run there at all. See lab/README.md."
        )),
    }
}

/// `false` means "skip"; a panic means "you asked for the lab and it is not
/// there". Never returns `false` when [`REQUIRE_LAB`] is set.
fn lab_ready(truth: &GroundTruth) -> bool {
    match lab_unavailable(truth) {
        None => true,
        Some(reason) if std::env::var_os(REQUIRE_LAB).is_some() => {
            panic!("{REQUIRE_LAB} is set, so this is a failure and not a skip: {reason}")
        }
        Some(reason) => {
            // Written straight to the process's stderr rather than through
            // `eprintln!`, which libtest captures and then discards for a
            // test that passes: without `--nocapture` the skip would print
            // nothing and libtest would report `ok`. A suite that reports
            // success having scanned nothing, silently, is exactly what this
            // whole arrangement exists to avoid. `write_all` does not go
            // through the capture hook, so the reason is always visible.
            let mut err = std::io::stderr().lock();
            let _ = err.write_all(format!("\nSKIPPED (no lab): {reason}\n\n").as_bytes());
            let _ = err.flush();
            false
        }
    }
}

// ---------------------------------------------------------------------------
// Driving a real scan of the lab.
// ---------------------------------------------------------------------------

/// One complete scan of every lab address over [`GroundTruth::scanned_ports`],
/// folded into the same `ScanFold` the `result.query` tool serves.
///
/// The scope manifest is `lab/scope.json` -- the real one, loaded through
/// `ScopeManifest::load` and not a test-only constructor -- because "there is
/// no way to scan without a manifest" is a property of the product and this
/// suite should exercise it rather than route around it.
async fn scan_the_lab(truth: &GroundTruth, idempotency_key: &str) -> ScanFold {
    let dir = tempfile::tempdir().expect("tempdir");
    // A real clock, not a `FixedClock`: the manifest's expiry is checked
    // against `clock.now_rfc3339()`, and a frozen clock would make
    // `lab/scope.json`'s `not_after` a property of the test rather than of the
    // manifest.
    let clock: Arc<dyn Clock> = Arc::new(SystemClock::default());
    let store = Arc::new(TaskStore::open(dir.path(), Arc::clone(&clock)).expect("task store"));
    let manifest = Arc::new(ScopeManifest::load(SCOPE_MANIFEST).expect("lab/scope.json"));

    let budgets = Budgets {
        maximum_packets: 1_000_000,
        maximum_runtime_seconds: 3_600,
        maximum_packets_per_second: 100_000,
    };
    let request = ScanRequest {
        targets: NonEmpty::try_from(truth.targets()).expect("the lab has addresses"),
        authorization_scope_id: manifest.id(),
        objective: Objective::InventoryExposedServices,
        ports: PortSelection::Explicit {
            explicit: NonEmpty::try_from(
                truth
                    .scanned_ports
                    .iter()
                    .map(u16::to_string)
                    .collect::<Vec<_>>(),
            )
            .expect("the ground truth names a port set"),
        },
        service_detection: ServiceDetection::default(),
        budgets,
        evidence_level: EvidenceLevel::Headers,
        idempotency_key: idempotency_key.to_owned(),
    };

    let plan = ScanPlan::build(&request, 1_000_000).expect("plan");
    let outcome = store
        .start_or_reuse(&StartRequest {
            idempotency_key: request.idempotency_key.clone(),
            plan_hash: plan.hash(),
            scope_id: request.authorization_scope_id,
            request_json: serde_json::to_string(&request).expect("request json"),
            estimated_targets: plan.targets().len() as u64,
            estimated_probes: plan.len(),
        })
        .expect("start");
    let scan_id = outcome.scan_id();

    let log = Arc::new(Mutex::new(
        GroupCommitLog::open(dir.path(), scan_id, GroupCommitConfig::default()).expect("log"),
    ));
    let scheduler = Scheduler::new(
        BudgetLedger::new(budgets),
        manifest,
        SchedulerConfig::default(),
        Arc::clone(&log),
        Arc::clone(&store),
        Arc::clone(&clock),
        scan_id,
        "lab-conformance",
        request.service_detection,
        request.evidence_level,
        Arc::new(EvidenceStore::open(dir.path()).expect("evidence")),
        Arc::new(ProbeRegistry::standard()),
    );
    scheduler
        .run(&plan, 0, CancellationToken::new())
        .await
        .expect("the lab scan itself must not error");

    let events = log.lock().expect("log lock").read_from(0).expect("events");
    fold_events(&events)
}

// ---------------------------------------------------------------------------
// AC-7.2 — zero false negatives.
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires the lab; run with `lab/run.sh test`"]
async fn the_scanner_finds_every_open_port_in_the_ground_truth() {
    let truth = GroundTruth::load();
    if !lab_ready(&truth) {
        return;
    }
    let fold = scan_the_lab(&truth, "lab-conformance-false-negatives").await;

    let mut expected = 0usize;
    let mut missing = Vec::new();
    for host in &truth.hosts {
        for open in &host.open {
            expected += 1;
            let observed = fold
                .endpoints
                .get(&(host.ip, tcp(open.port)))
                .and_then(|e| e.state);
            if observed != Some(PortState::Open) {
                missing.push(format!(
                    "{}:{} ({}) is open in the ground truth but the scanner reported {observed:?}",
                    host.ip, open.port, open.evidence
                ));
            }
        }
    }
    assert!(
        expected >= 10,
        "the ground truth records only {expected} open port(s); this assertion is too \
         thin to mean anything"
    );
    assert!(
        missing.is_empty(),
        "false negatives:\n{}",
        missing.join("\n")
    );
}

// ---------------------------------------------------------------------------
// AC-7.3 — zero false positives.
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires the lab; run with `lab/run.sh test`"]
async fn the_scanner_reports_no_open_port_that_is_not_in_the_ground_truth() {
    let truth = GroundTruth::load();
    if !lab_ready(&truth) {
        return;
    }
    let fold = scan_the_lab(&truth, "lab-conformance-false-positives").await;

    // The narrowing control, asserted here rather than assumed: if every
    // endpoint the scan touched were open in the ground truth, this test
    // would pass for a scanner that reported everything open. `check-lab`
    // enforces the same property over the file; this enforces it over the
    // scan that actually ran.
    let closed_in_truth = fold
        .endpoints
        .keys()
        .filter(|(ip, ep)| !truth.is_open(*ip, ep.port))
        .count();
    assert!(
        closed_in_truth >= 20,
        "only {closed_in_truth} scanned endpoint(s) are closed in the ground truth, so \
         this test has almost nothing to catch"
    );

    let false_positives: Vec<String> = fold
        .open_endpoints()
        .filter(|((ip, ep), _)| !truth.is_open(*ip, ep.port))
        .map(|((ip, ep), state)| {
            format!(
                "{ip}:{} reported open (probe {:?}, rule {:?}); the ground truth has \
                 nothing listening there",
                ep.port, state.probe_id, state.rule_id
            )
        })
        .collect();
    assert!(
        false_positives.is_empty(),
        "false positives:\n{}",
        false_positives.join("\n")
    );
}

// ---------------------------------------------------------------------------
// AC-7.4 — an address with no host is never mistaken for one.
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires the lab; run with `lab/run.sh test`"]
async fn addresses_with_no_host_are_never_reported_open_or_closed() {
    let truth = GroundTruth::load();
    if !lab_ready(&truth) {
        return;
    }
    let fold = scan_the_lab(&truth, "lab-conformance-absent-addresses").await;

    // AC-7.4 as the plan drafted it asserted `!fold.hosts_up.contains(&ip)`.
    // That assertion cannot fail: `Scheduler` has no call to `discover_host`
    // in v0.1 (host discovery needs the raw-socket capability and ships with
    // `packetd` in M6), so `hosts_up` is empty for every scan and the test
    // would pass against a scanner that reported the whole subnet live. It is
    // a decoration test, and the plan has been corrected -- see the Plan
    // Defects note in lab/README.md.
    //
    // The property that is real in v0.1, and that a broken scanner would
    // fail: nothing answers at an address with no host, so every endpoint on
    // one must be `Filtered`. `Open` means we invented a service; `Closed`
    // means we claim an RST arrived, which is itself evidence that a host is
    // there.
    assert!(
        fold.hosts_up.is_empty(),
        "v0.1 emits no host.discovered events, so this must be empty; if it is not, \
         host discovery has been wired in and this test needs the stronger assertion \
         it was written to stand in for"
    );

    let mut checked = 0usize;
    let mut wrong = Vec::new();
    for ip in &truth.absent {
        for port in &truth.scanned_ports {
            let state = fold.endpoints.get(&(*ip, tcp(*port))).and_then(|e| e.state);
            checked += 1;
            match state {
                Some(PortState::Filtered) => {}
                other => wrong.push(format!(
                    "{ip}:{port} has no host in the lab but was reported {other:?}"
                )),
            }
        }
    }
    assert_eq!(
        checked,
        truth.absent.len() * truth.scanned_ports.len(),
        "the scan did not cover every absent address"
    );
    assert!(
        checked >= 20,
        "only {checked} endpoint(s) on absent addresses"
    );
    assert!(wrong.is_empty(), "phantom hosts:\n{}", wrong.join("\n"));
}

// ---------------------------------------------------------------------------
// AC-7.5 — service identification agrees with the lab's own banners.
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires the lab; run with `lab/run.sh test`"]
async fn service_identification_matches_the_ground_truth_products() {
    let truth = GroundTruth::load();
    if !lab_ready(&truth) {
        return;
    }
    let fold = scan_the_lab(&truth, "lab-conformance-service-identification").await;

    // The endpoints the lab establishes a product for AND bathy is expected to
    // reach. An entry carrying `identification_gap` is excluded here and held
    // to the opposite property below -- see the loop after this one, and
    // `TruthPort::identification_gap` for why that is not the same thing as
    // the `product: null` this replaced.
    let mut asserted = 0usize;
    let mut wrong = Vec::new();
    for host in &truth.hosts {
        for open in host
            .open
            .iter()
            .filter(|o| o.product.is_some() && o.identification_gap.is_none())
        {
            asserted += 1;
            let Some(state) = fold.endpoints.get(&(host.ip, tcp(open.port))) else {
                wrong.push(format!("{}:{} was not scanned at all", host.ip, open.port));
                continue;
            };
            let Some(observation) = state.observation.as_ref() else {
                wrong.push(format!(
                    "{}:{} produced no observation; the ground truth expects {:?} from {}",
                    host.ip, open.port, open.product, open.evidence
                ));
                continue;
            };
            if observation.product != open.product {
                wrong.push(format!(
                    "{}:{} product is {:?}, ground truth says {:?} (from {})",
                    host.ip, open.port, observation.product, open.product, open.evidence
                ));
            }
            if open.version.is_some() && observation.version != open.version {
                wrong.push(format!(
                    "{}:{} version is {:?}, ground truth says {:?} (from {})",
                    host.ip, open.port, observation.version, open.version, open.evidence
                ));
            }
            if observation.confidence.get() < 0.70 {
                wrong.push(format!(
                    "{}:{} identified as {:?} at confidence {}, below the 0.70 AC-7.5 \
                     requires",
                    host.ip,
                    open.port,
                    observation.product,
                    observation.confidence.get()
                ));
            }
        }
    }
    // The ground truth deliberately leaves `product` null wherever the
    // service volunteers nothing that names one (PostgreSQL, Redis, the two
    // TLS-wrapped DNS ports), so this loop must not silently range over an
    // empty set if that convention is ever misapplied to everything.
    assert!(
        asserted >= 4,
        "only {asserted} product claim(s) in the ground truth; AC-7.5 needs more than \
         one protocol to mean anything"
    );

    // The other direction, and the reason this criterion is honest rather than
    // merely green. A recorded gap is a claim about bathy -- "the lab
    // establishes this product and we do not report it" -- and a claim about
    // bathy is a thing that can become false. If it does, this fails and names
    // the key to delete, so the exemption cannot outlive the defect it
    // describes. Without this loop `identification_gap` would be exactly the
    // self-exempting null it replaced, spelled longer.
    let mut stale = Vec::new();
    let mut gaps = 0usize;
    for host in &truth.hosts {
        for open in host.open.iter().filter(|o| o.identification_gap.is_some()) {
            gaps += 1;
            let found = fold
                .endpoints
                .get(&(host.ip, tcp(open.port)))
                .and_then(|e| e.observation.as_ref())
                .and_then(|o| o.product.clone());
            if found.is_some() {
                stale.push(format!(
                    "{}:{} is recorded in lab/ground-truth.json as a known identification \
                     gap, but bathy now reports product {found:?}. The gap is closed: \
                     delete that endpoint's `identification_gap` key so AC-7.5 asserts \
                     the product ({:?}) like every other endpoint.",
                    host.ip, open.port, open.product
                ));
            }
        }
    }
    assert!(
        gaps <= 1,
        "{gaps} endpoint(s) claim an identification gap. Exactly one is expected \
         (10.30.0.17:443, the TLS-fronted nginx); a growing list is a scanner \
         regression being written into the oracle rather than fixed"
    );
    assert!(stale.is_empty(), "{}", stale.join("\n"));

    assert!(wrong.is_empty(), "misidentified:\n{}", wrong.join("\n"));
}

// ---------------------------------------------------------------------------
// AC-7.6 — the reproducibility claim, in the only form that is true.
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires the lab; run with `lab/run.sh test`"]
async fn two_consecutive_scans_of_the_static_lab_produce_no_substantive_changes() {
    let truth = GroundTruth::load();
    if !lab_ready(&truth) {
        return;
    }
    // This project does not claim reproducible observations -- the network is
    // not deterministic, and the Global Constraint on the scoped determinism
    // claim says so. What it does claim, and what this measures, is that the
    // lab does not change between two runs, so any *substantive* difference
    // between them is the scanner's own noise. Confidence-only changes are
    // excluded because a confidence that moves without the service, product
    // or version moving is not a different answer.
    let first = scan_the_lab(&truth, "lab-conformance-repeatability-a").await;
    let second = scan_the_lab(&truth, "lab-conformance-repeatability-b").await;

    let mut d = diff(&first, &second);
    assert!(
        d.absence_was_evidence(),
        "the two scans were not comparable ({:?}), so an empty change list would mean \
         nothing",
        d.undecidable
    );
    assert!(
        d.unchanged + d.changes.len() as u64 >= 100,
        "the diff covers only {} endpoint(s); two scans of a lab this size should \
         compare every one of them",
        d.unchanged + d.changes.len() as u64
    );

    d.retain_substantive();
    assert!(
        d.changes.is_empty(),
        "two scans of a static lab disagreed:\n{}",
        d.changes
            .iter()
            .map(|c| format!(
                "{}:{} {:?} {:?} -> {:?}",
                c.target, c.endpoint.port, c.kind, c.before, c.after
            ))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

// ---------------------------------------------------------------------------
// Guards over the fixture itself. These need no lab and are NOT `#[ignore]`d,
// so they run in CI: the ground truth being self-consistent is checkable
// without Docker, and a suite whose every test is ignored on the CI runner is
// a suite CI does not exercise at all.
// ---------------------------------------------------------------------------

#[test]
fn the_ground_truth_parses_and_describes_a_lab_worth_scanning() {
    let truth = GroundTruth::load();
    assert_eq!(truth.subnet, "10.30.0.0/24");
    assert!(
        truth.hosts.iter().all(|h| h.up),
        "`hosts` is the set of addresses a container sits on; an entry with `up: false` \
         belongs in `absent`"
    );
    assert!(
        truth.hosts.len() >= 5 && !truth.absent.is_empty(),
        "hosts {} absent {}",
        truth.hosts.len(),
        truth.absent.len()
    );
    let addresses: BTreeSet<IpAddr> = truth
        .hosts
        .iter()
        .map(|h| h.ip)
        .chain(truth.absent.iter().copied())
        .collect();
    assert_eq!(
        addresses.len(),
        truth.hosts.len() + truth.absent.len(),
        "an address appears twice in the ground truth"
    );
}

#[test]
fn every_open_port_in_the_ground_truth_carries_the_evidence_it_was_derived_from() {
    let truth = GroundTruth::load();
    let mut ports = 0usize;
    for host in &truth.hosts {
        for open in &host.open {
            ports += 1;
            assert!(
                !open.evidence.trim().is_empty(),
                "{}:{} records no evidence. A ground truth derived by reading \
                 docker-compose.yml is not a ground truth -- it is the assumption under \
                 test, written down twice.",
                host.ip,
                open.port
            );
            assert!(
                open.version.is_none() || open.product.is_some(),
                "{}:{} claims a version with no product",
                host.ip,
                open.port
            );
            // `identification_gap` says "the lab establishes a product here
            // and bathy does not report it". With no product it says nothing
            // and merely removes the endpoint from AC-7.5 -- which is the
            // self-exempting null it exists to replace, wearing a longer name.
            assert!(
                open.identification_gap.is_none() || open.product.is_some(),
                "{}:{} declares an identification gap with no product to be missing. \
                 A gap is a claim about what the lab establishes; without a product \
                 there is no claim, only an exemption.",
                host.ip,
                open.port
            );
            // Same shape, the other field: an inference note on an entry with
            // no product would exempt it from check-lab's product-in-evidence
            // rule while claiming nothing.
            assert!(
                open.product_inference.is_none() || open.product.is_some(),
                "{}:{} explains where a product was inferred from but records no product",
                host.ip,
                open.port
            );
        }
    }
    assert!(ports >= 10, "only {ports} open port(s) recorded");
}

#[test]
fn the_scope_manifest_shipped_with_the_lab_authorizes_the_lab_and_nothing_else() {
    let manifest = ScopeManifest::load(SCOPE_MANIFEST).expect("lab/scope.json must load");
    let truth = GroundTruth::load();
    for host in &truth.hosts {
        assert!(manifest.allows(host.ip), "{} is not in scope", host.ip);
    }
    for ip in &truth.absent {
        assert!(manifest.allows(*ip), "{ip} is not in scope");
    }
    // Deny-by-default is the property that matters here, so it is asserted
    // with an address outside the lab rather than only with ones inside it.
    for outside in ["10.31.0.10", "192.0.2.1", "8.8.8.8"] {
        let ip: IpAddr = outside.parse().expect("literal");
        assert!(
            !manifest.allows(ip),
            "{ip} is outside the lab but this manifest authorizes it"
        );
    }
}

#[test]
fn the_scanned_port_set_contains_ports_that_are_shut_on_hosts_that_are_up() {
    // The overview's fixture constraint, applied to the oracle: "a fixture
    // that satisfies every branch tests none of them". If every scanned port
    // were open on every live host, AC-7.3 would pass for a scanner that
    // reported everything it touched as open.
    let truth = GroundTruth::load();
    let mut shut: BTreeMap<IpAddr, Vec<u16>> = BTreeMap::new();
    for host in &truth.hosts {
        let open: BTreeSet<u16> = host.open.iter().map(|o| o.port).collect();
        let closed: Vec<u16> = truth
            .scanned_ports
            .iter()
            .copied()
            .filter(|p| !open.contains(p))
            .collect();
        if !closed.is_empty() {
            shut.insert(host.ip, closed);
        }
    }
    // `shut.len() >= 3` used to stand here alone. It cannot realistically
    // fail: any non-trivial port set leaves most of nine hosts with something
    // shut, and the M7 Task 1 review's attempt to kill it survived for exactly
    // that reason (MINOR-2). It is kept because it is cheap and it is true,
    // and the two assertions that actually bite were added beside it.
    assert!(
        shut.len() >= 3,
        "only {} live host(s) have a scanned port that is shut: {shut:?}",
        shut.len()
    );
    // The control `lab/README.md` documents as "`ssh-openssh` listens on 2222,
    // not 22, so 22 is shut on every host in the lab and is in the scanned
    // port set on purpose". Removing 22 from `scanned_ports` passed this test,
    // `xtask check-lab` and the whole workspace suite before this round --
    // port 8080 independently satisfied every generic property above, so the
    // named control was defended by nothing. `xtask check-lab` now asserts the
    // same thing over the file; this asserts it in the suite that scans with
    // it.
    assert!(
        truth.scanned_ports.contains(&22),
        "22 is not scanned. The lab's SSH server is on 2222 precisely so that a scanner \
         assuming `ssh => 22` is charged a false positive; that costs nothing if 22 is \
         never asked about."
    );
    for host in &truth.hosts {
        assert!(
            !host.open.iter().any(|o| o.port == 22),
            "{} listens on 22, so 22 is no longer shut on every host and the control \
             above has quietly become vacuous",
            host.ip
        );
    }
    for open in truth.hosts.iter().flat_map(|h| &h.open) {
        assert!(
            truth.scanned_ports.contains(&open.port),
            "port {} is recorded open but is never scanned, so AC-7.2 never looks for it",
            open.port
        );
    }
}
