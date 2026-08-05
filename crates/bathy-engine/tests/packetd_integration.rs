//! AC-6.15 and AC-6.16, against the real `bathy-packetd` binary.
//!
//! # Nothing here is mocked
//!
//! The daemon these tests drive is the binary `cargo` just built. The
//! fallback is produced by a machine that genuinely does not hold
//! `CAP_NET_RAW`, not by an injected error; the mid-scan death is produced by
//! `kill -9` on a real pid, not by a channel that was closed on purpose.
//!
//! # Two branches, and each is the other's control
//!
//! [`the_engine_records_which_method_actually_ran`] asserts on **both** sides
//! of the privilege question, because a test that only checked the
//! unprivileged side would pass, having checked nothing, on the one machine
//! where SYN scanning actually works -- which is the shape of M6 Task 2's
//! plan defect #2 and of every test in this repository that turned out to be
//! checking nothing.
//!
//! The privilege question is answered by *this* process opening a raw socket,
//! not by asking `packetd`. A test that derived its expectation from the
//! thing under test would agree with a broken daemon.
//!
//! # `BATHY_PACKETD_PRIVILEGED_TESTS`
//!
//! Set by `cargo run -p xtask -- packetd-privileged`. It turns
//! [`packetd_dying_mid_scan_fails_the_scan_rather_than_silently_degrading`]'s
//! skip into a failure: that test needs a *working* SYN session, which needs
//! the capability, and a privileged run that quietly skipped it would report
//! coverage it does not have.

#![cfg(unix)]

use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bathy_engine::packetd::PacketdConfig;
use bathy_engine::{GroupCommitConfig, GroupCommitLog, Scheduler, SchedulerConfig};
use bathy_evidence::EvidenceStore;
use bathy_plan::ScanPlan;
use bathy_probe::ProbeRegistry;
use bathy_scope::{BudgetLedger, ScopeManifest};
use bathy_store::{StartRequest, TaskStore};
use bathy_types::clock::{Clock, FixedClock};
use bathy_types::event::{EventBody, ScanMode};
use bathy_types::ids::ScopeId;
use bathy_types::nonempty::NonEmpty;
use bathy_types::request::{
    Budgets, EvidenceLevel, Objective, PortSelection, ScanRequest, ServiceDetection,
};
use tokio_util::sync::CancellationToken;

/// Set to `1` by `cargo run -p xtask -- packetd-privileged`.
const DEMAND: &str = "BATHY_PACKETD_PRIVILEGED_TESTS";

const SCOPE: &str = "scope_01K2HZ8V5N3QR7BXMC4TDWF9GJ";

/// The daemon, found the way `crates/bathy-packetd/tests/privilege.rs` finds
/// it: beside the test executable's own target directory.
///
/// `env!("CARGO_BIN_EXE_...")` only names bins of the package under test, and
/// `bathy-packetd` is a different package that this crate deliberately does
/// not depend on (see `bathy_engine::packetd`'s module doc). `cargo test
/// --workspace` builds it; a bare `cargo test -p bathy-engine` may not, which
/// is why an absent binary is reported with the command that produces it.
fn packetd_bin() -> PathBuf {
    let mut dir = std::env::current_exe().expect("the test binary has a path");
    dir.pop(); // deps/
    if dir.ends_with("deps") {
        dir.pop();
    }
    let bin = dir.join("bathy-packetd");
    assert!(
        bin.exists(),
        "{} does not exist. These tests drive the real daemon; build it with \
         `cargo build --workspace` or run `cargo test --workspace`.",
        bin.display()
    );
    bin
}

/// Whether *this* process can open a raw socket, and therefore whether the
/// daemon it spawns will be able to.
///
/// Deliberately not `packetd --self-check`: the expectation a test asserts
/// against must not come from the code under test. `socket2` is already a
/// dev-dependency of this crate, and `Socket::new(IPV4, RAW, TCP)` is
/// `socket(2)` -- the same call `acquire_raw_sockets` makes.
fn this_process_holds_cap_net_raw() -> bool {
    socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::RAW,
        Some(socket2::Protocol::TCP),
    )
    .is_ok()
}

/// This host's primary IPv4 address, as the kernel would choose it.
///
/// A UDP `connect` to a `TEST-NET-1` address (RFC 5737) sends nothing -- it
/// only asks the routing table which source address a packet to there would
/// leave from. Needed because `packetd` refuses loopback outright (AC-6.10),
/// so a SYN session cannot be exercised against `127.0.0.1` at all.
fn primary_ipv4() -> Option<Ipv4Addr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    socket.connect("192.0.2.1:9").ok()?;
    match socket.local_addr().ok()?.ip() {
        IpAddr::V4(v4) if !v4.is_loopback() && !v4.is_unspecified() => Some(v4),
        _ => None,
    }
}

fn manifest(allowed: &str, denied: &str, pps: u32) -> Arc<ScopeManifest> {
    let json = format!(
        r#"{{"id":"{SCOPE}","description":"packetd integration",
            "not_after":"2099-01-01T00:00:00.000Z",
            "allowed_cidrs":[{allowed}],"denied_cidrs":[{denied}],
            "budget_ceiling":{{"maximum_packets":100000,
                               "maximum_runtime_seconds":3600,
                               "maximum_packets_per_second":{pps}}}}}"#
    );
    Arc::new(ScopeManifest::for_tests_allowing_loopback(&json).expect("the fixture manifest loads"))
}

/// Everything a `Scheduler` needs, plus the log so a test can read what the
/// scan actually recorded.
struct Harness {
    _dir: tempfile::TempDir,
    scheduler: Scheduler,
    plan: ScanPlan,
    log: Arc<std::sync::Mutex<GroupCommitLog>>,
}

impl Harness {
    fn events(&self) -> Vec<bathy_types::event::Event> {
        self.log
            .lock()
            .expect("log mutex")
            .read_from(0)
            .expect("the log reads back")
    }

    /// What `scan.started` recorded, which is the AC-6.15 subject.
    fn scan_mode_recorded(&self) -> Option<(Option<ScanMode>, Option<String>)> {
        self.events().into_iter().find_map(|e| match e.body {
            EventBody::ScanStarted {
                scan_mode,
                scan_mode_detail,
                ..
            } => Some((scan_mode, scan_mode_detail)),
            _ => None,
        })
    }

    /// The `scan.failed` reason code, if the scan failed.
    fn terminal_reason(&self) -> Option<String> {
        self.events().into_iter().find_map(|e| match e.body {
            EventBody::ScanFailed { reason_code, .. } => Some(reason_code),
            _ => None,
        })
    }

    fn port_state_count(&self) -> usize {
        self.events()
            .iter()
            .filter(|e| matches!(e.body, EventBody::PortStateObserved { .. }))
            .count()
    }
}

fn harness(
    target: IpAddr,
    ports: &[u16],
    manifest: Arc<ScopeManifest>,
    packetd: PacketdConfig,
    pps: u32,
) -> Harness {
    let dir = tempfile::tempdir().expect("a temp dir");
    let clock: Arc<dyn Clock> =
        Arc::new(FixedClock::new("2026-08-05T00:00:00.000Z", 7).expect("a fixed clock"));
    let store = Arc::new(TaskStore::open(dir.path(), Arc::clone(&clock)).expect("a store"));
    let budgets = Budgets {
        maximum_packets: 100_000,
        maximum_runtime_seconds: 3_600,
        maximum_packets_per_second: pps,
    };
    let request = ScanRequest {
        targets: NonEmpty::try_from(vec![target.to_string()]).expect("one target"),
        authorization_scope_id: SCOPE.parse::<ScopeId>().expect("a scope id"),
        objective: Objective::InventoryExposedServices,
        ports: PortSelection::Explicit {
            explicit: NonEmpty::try_from(ports.iter().map(|p| p.to_string()).collect::<Vec<_>>())
                .expect("at least one port"),
        },
        // Off deliberately: identification reconnects with a real TCP
        // connect, and a SYN scan that then connected to every open port
        // would not be a SYN scan.
        service_detection: ServiceDetection {
            enabled: false,
            intensity: 0,
        },
        budgets,
        evidence_level: EvidenceLevel::None,
        idempotency_key: format!("packetd-integration-{target}-{}", ports.len()),
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
    let evidence = Arc::new(EvidenceStore::open(dir.path()).expect("an evidence store"));
    let scheduler = Scheduler::new(
        BudgetLedger::new(budgets),
        manifest,
        SchedulerConfig {
            concurrency: 16,
            connect_timeout: Duration::from_millis(500),
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
        evidence,
        Arc::new(ProbeRegistry::standard()),
    );
    Harness {
        _dir: dir,
        scheduler,
        plan,
        log,
    }
}

/// AC-6.15, both ways.
///
/// **Unprivileged** (this project's dev host, `linux-gate`, and CI's `test`
/// job): the daemon exits 69 before answering, the engine falls back, the
/// scan *completes* with real port states, and `scan.started` says
/// `tcp-connect` and why.
///
/// **Privileged** (`cargo run -p xtask -- packetd-privileged`): the daemon
/// starts, `scan.started` says `tcp-syn` -- and because the targets here are
/// loopback, `packetd`'s own independent scope check refuses every probe
/// (AC-6.10) even though the engine's manifest permits them, so the scan
/// fails with `packetd_refused`. That is the two-layer design working, and it
/// is the narrowing control this test needs: an engine that never actually
/// used the daemon would record `tcp-connect` here and fail.
#[tokio::test]
async fn the_engine_records_which_method_actually_ran() {
    let privileged = this_process_holds_cap_net_raw();
    // Bound for the whole test: a port whose listener has gone away is a port
    // the kernel may have handed to a sibling test (`check-fixtures`'s
    // vacated-port rule).
    let open_listener = TcpListener::bind("127.0.0.1:0").expect("a loopback listener");
    let ports: Vec<u16> = vec![open_listener.local_addr().expect("an address").port()];
    let h = harness(
        "127.0.0.1".parse().expect("loopback parses"),
        &ports,
        manifest(r#""127.0.0.0/8""#, "", 1000),
        PacketdConfig::syn_via(packetd_bin()),
        1000,
    );
    let summary = h
        .scheduler
        .run(&h.plan, 0, CancellationToken::new())
        .await
        .expect("the run returns");
    let (mode, detail) = h
        .scan_mode_recorded()
        .expect("the scan announced itself on scan.started");

    if privileged {
        assert_eq!(
            mode,
            Some(ScanMode::TcpSyn),
            "this host can open a raw socket, so packetd started and the scan really was a \
             SYN scan; recording tcp-connect here would mean the engine never used it"
        );
        assert_eq!(
            detail, None,
            "nothing was degraded, so there is nothing to explain: {detail:?}"
        );
        assert_eq!(
            h.terminal_reason().as_deref(),
            Some("packetd_refused"),
            "packetd refuses loopback regardless of what the engine's manifest allows \
             (AC-6.10), and a refusal is an authorization disagreement, not a missing row"
        );
        assert!(summary.packetd_unavailable);
    } else {
        assert_eq!(
            mode,
            Some(ScanMode::TcpConnect),
            "this host cannot open a raw socket, so packetd cannot have started"
        );
        let detail = detail.expect("a fallback must say why it happened");
        assert!(
            detail.contains("CAP_NET_RAW"),
            "the reason must reach the log, because the process that knew it has exited: \
             {detail}"
        );
        assert!(
            detail.contains("setcap cap_net_raw+ep"),
            "AC-6.6's copy-pasteable command is what makes the fallback actionable: {detail}"
        );
        assert!(
            !summary.packetd_unavailable,
            "a daemon that never started is a fallback, not a scan failure"
        );
        assert_eq!(
            h.terminal_reason(),
            None,
            "the scan must still COMPLETE, which is half of what AC-6.15 asks for"
        );
        assert_eq!(
            h.port_state_count(),
            ports.len(),
            "and it must produce real results, not an empty completed scan"
        );
        assert_eq!(summary.open_ports, 1, "the listener above is open");
    }
    assert!(
        open_listener.local_addr().is_ok(),
        "the listener is still bound at the end of the test, which is what makes the port \
         above a port nothing else could have taken"
    );
}

/// The narrowing control for the fallback itself: a scan that never asked for
/// SYN scanning records `tcp-connect` with **no** detail.
///
/// Without this, a `scan_mode_detail` that was always populated -- or a
/// `scan_mode` hard-coded to `tcp-connect` -- would satisfy the unprivileged
/// branch above.
#[tokio::test]
async fn a_scan_that_never_asked_for_syn_records_connect_with_nothing_to_explain() {
    let open_listener = TcpListener::bind("127.0.0.1:0").expect("a loopback listener");
    let port = open_listener.local_addr().expect("an address").port();
    let h = harness(
        "127.0.0.1".parse().expect("loopback parses"),
        &[port],
        manifest(r#""127.0.0.0/8""#, "", 1000),
        PacketdConfig::default(),
        1000,
    );
    h.scheduler
        .run(&h.plan, 0, CancellationToken::new())
        .await
        .expect("the run returns");
    assert_eq!(
        h.scan_mode_recorded(),
        Some((Some(ScanMode::TcpConnect), None)),
        "connect scanning that was asked for is not a degradation and has nothing to explain"
    );
    assert!(open_listener.local_addr().is_ok(), "still bound");
}

/// A port that is genuinely closed and genuinely *held*, on `ip`.
///
/// `check-fixtures`'s vacated-port rule: a port whose listener has been
/// dropped is back in the kernel's ephemeral pool and any sibling test's
/// `bind(:0)` can take it -- measured at 16 red runs in 30. This is
/// `bathy_engine::test_support::closed_port`'s technique, written here
/// because that module is behind a `test-util` feature this crate cannot
/// reach from an integration test without a self-dependency, which
/// `check-deps`' layer order forbids.
///
/// The listener is created **without** `SO_REUSEADDR` (which `std` sets
/// unconditionally and offers no way off): with it, the reservation can be
/// shared away and the whole fixture is pointless. The listener falls out of
/// scope at the end of this function; the established connection returned
/// with the port is what keeps the port occupied, and new connections to it
/// are refused because nothing is accepting any more.
fn sealed_closed_port(ip: Ipv4Addr) -> (u16, TcpStream, TcpStream) {
    let socket = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::STREAM, None)
        .expect("a stream socket");
    socket
        .bind(&SocketAddr::from((ip, 0)).into())
        .expect("binding an ephemeral port");
    socket.listen(1).expect("listening");
    let listener = TcpListener::from(socket);
    let port = listener.local_addr().expect("an address").port();
    let client = TcpStream::connect(SocketAddr::from((ip, port))).expect("connecting to it");
    let (server, _) = listener.accept().expect("accepting");
    (port, client, server)
}

/// A shim that `exec`s the real daemon, having first written its own pid.
///
/// `exec` replaces the shell **in place**, so the pid in the file is the pid
/// of `bathy-packetd` itself. Nothing about the daemon is substituted: the
/// engine spawns this path, the kernel runs the real binary, and the kill
/// below lands on the real process. It exists only because the engine spawns
/// the daemon from inside `run`, so a test outside `run` has no other way to
/// learn which process to kill.
fn pid_announcing_shim(dir: &std::path::Path) -> (PathBuf, PathBuf) {
    let pidfile = dir.join("packetd.pid");
    let shim = dir.join("packetd-shim.sh");
    let mut file = std::fs::File::create(&shim).expect("the shim is writable");
    write!(
        file,
        "#!/bin/sh\necho $$ > {pid}\nexec {bin} \"$@\"\n",
        pid = pidfile.display(),
        bin = packetd_bin().display(),
    )
    .expect("the shim is written");
    drop(file);
    std::fs::set_permissions(&shim, std::fs::Permissions::from_mode(0o755))
        .expect("the shim is executable");
    (shim, pidfile)
}

/// AC-6.16: `packetd` dying mid-scan fails the scan with
/// `packetd_unavailable` rather than silently changing method.
///
/// The kill is `kill -9` on the daemon's real pid, delivered while the scan
/// is running and after it has already recorded results. The assertion that
/// matters is the *pair*: the terminal reason is `packetd_unavailable`, and
/// the scan did **not** go on to produce a full set of port states -- a
/// silent downgrade would have completed every endpoint and looked like a
/// success.
// The default current-thread runtime is enough: the worker that talks to
// `packetd` is an OS thread of its own, and the killer runs on the blocking
// pool, so neither is competing for the runtime's single worker.
#[tokio::test]
async fn packetd_dying_mid_scan_fails_the_scan_rather_than_silently_degrading() {
    if !this_process_holds_cap_net_raw() {
        let reason = "this process cannot open a raw socket, so packetd cannot hold a session \
                      to lose";
        assert!(
            std::env::var_os(DEMAND).is_none(),
            "{DEMAND} is set, so this is a failure and not a skip: {reason}"
        );
        // Straight to the process's stderr: libtest captures the print
        // macros and discards them for a test that passes, so without this
        // the skip would be invisible and the run would report `ok`.
        let mut err = std::io::stderr().lock();
        let _ = err.write_all(format!("\nSKIPPED (no CAP_NET_RAW): {reason}\n\n").as_bytes());
        let _ = err.flush();
        return;
    }
    let Some(local) = primary_ipv4() else {
        panic!(
            "no non-loopback IPv4 address on this host. packetd refuses loopback (AC-6.10), \
             so there is nowhere to send a SYN that this host will also receive."
        );
    };

    // Enough endpoints, paced slowly enough, that the scan is still running
    // when the kill lands. `packetd` paces itself from the session's
    // `packets_per_second`, which comes from the manifest ceiling.
    // Deliberately below the kernel's ephemeral floor and unbound, so every
    // one answers with a reset: this test is about the daemon dying, not
    // about what it finds. Paced at 4 packets per second by the manifest
    // ceiling below, so forty of them take ten seconds and the kill lands
    // while the scan is still running.
    let ports: Vec<u16> = (9_000u16..9_040).collect();
    let dir = tempfile::tempdir().expect("a temp dir");
    let (shim, pidfile) = pid_announcing_shim(dir.path());
    let h = harness(
        IpAddr::V4(local),
        &ports,
        manifest(&format!(r#""{local}/32""#), "", 4),
        PacketdConfig::syn_via(shim),
        4,
    );
    let log = Arc::clone(&h.log);

    let killer = tokio::task::spawn_blocking(move || {
        let deadline = Instant::now() + Duration::from_secs(20);
        let pid = loop {
            if let Ok(text) = std::fs::read_to_string(&pidfile)
                && let Ok(pid) = text.trim().parse::<u32>()
            {
                break pid;
            }
            assert!(Instant::now() < deadline, "the shim never announced a pid");
            std::thread::sleep(Duration::from_millis(20));
        };
        // Wait until the scan has actually recorded something, so this is a
        // death *mid*-scan and not a death before it began.
        loop {
            let recorded = log
                .lock()
                .expect("log mutex")
                .read_from(0)
                .expect("the log reads back")
                .iter()
                .filter(|e| matches!(e.body, EventBody::PortStateObserved { .. }))
                .count();
            if recorded > 0 {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "the scan recorded nothing before the deadline"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        let killed = std::process::Command::new("sh")
            .arg("-c")
            .arg(format!("kill -9 {pid}"))
            .status()
            .expect("sh runs");
        assert!(killed.success(), "kill -9 {pid} failed");
        pid
    });

    let summary = h
        .scheduler
        .run(&h.plan, 0, CancellationToken::new())
        .await
        .expect("the run returns rather than panicking");
    let pid = killer.await.expect("the killer thread finished");

    assert_eq!(
        h.scan_mode_recorded().map(|(mode, _)| mode),
        Some(Some(ScanMode::TcpSyn)),
        "the scan started as a SYN scan; that is what makes the degradation silent if it \
         happens"
    );
    assert!(
        summary.packetd_unavailable,
        "killing pid {pid} must be visible in the summary"
    );
    assert_eq!(
        h.terminal_reason().as_deref(),
        Some("packetd_unavailable"),
        "the terminal reason is the whole criterion"
    );
    assert!(
        h.port_state_count() < ports.len(),
        "a scan that silently switched method would have finished all {} endpoints; it \
         recorded {}",
        ports.len(),
        h.port_state_count()
    );
    assert!(
        h.port_state_count() > 0,
        "and it must have recorded the results it did get -- a death mid-scan does not \
         invalidate the endpoints already observed"
    );
}

/// The narrowing control for the test above: with nothing killed, the same
/// shim, the same address and the same ports produce a **completed** SYN scan
/// over every endpoint.
///
/// Without it, `packetd_dying_mid_scan...` would be satisfied by an engine
/// that failed with `packetd_unavailable` unconditionally.
// The default current-thread runtime is enough: the worker that talks to
// `packetd` is an OS thread of its own, and the killer runs on the blocking
// pool, so neither is competing for the runtime's single worker.
#[tokio::test]
async fn an_unmolested_syn_scan_completes_every_endpoint() {
    if !this_process_holds_cap_net_raw() {
        let reason = "this process cannot open a raw socket";
        assert!(
            std::env::var_os(DEMAND).is_none(),
            "{DEMAND} is set, so this is a failure and not a skip: {reason}"
        );
        let mut err = std::io::stderr().lock();
        let _ = err.write_all(format!("\nSKIPPED (no CAP_NET_RAW): {reason}\n\n").as_bytes());
        let _ = err.flush();
        return;
    }
    let Some(local) = primary_ipv4() else {
        panic!("no non-loopback IPv4 address on this host");
    };
    let open_listener = TcpListener::bind(SocketAddr::from((local, 0))).expect("a local listener");
    let open = open_listener.local_addr().expect("an address").port();
    let (closed, _client, _server) = sealed_closed_port(local);
    let ports = vec![open, closed];
    let h = harness(
        IpAddr::V4(local),
        &ports,
        manifest(&format!(r#""{local}/32""#), "", 200),
        PacketdConfig::syn_via(packetd_bin()),
        200,
    );
    let summary = h
        .scheduler
        .run(&h.plan, 0, CancellationToken::new())
        .await
        .expect("the run returns");
    assert_eq!(
        h.scan_mode_recorded(),
        Some((Some(ScanMode::TcpSyn), None)),
        "a SYN scan that worked has nothing to explain"
    );
    assert_eq!(h.terminal_reason(), None, "nothing failed");
    assert_eq!(
        h.port_state_count(),
        ports.len(),
        "every endpoint was observed"
    );
    assert_eq!(
        summary.open_ports, 1,
        "the bound listener is open and the sealed port is not, so the SYN path \
         distinguishes them"
    );
    assert!(open_listener.local_addr().is_ok(), "still bound");
}
