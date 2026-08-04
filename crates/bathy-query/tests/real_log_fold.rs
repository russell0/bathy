//! Folding an event log produced by a **real scan against real sockets**,
//! rather than one built by hand out of `Event` literals.
//!
//! `crates/bathy-query/src/fold.rs`'s unit tests construct every event
//! themselves, which means they test the fold against this author's model of
//! what `bathy-engine` emits. If that model is wrong -- a field populated
//! differently, an event that never actually appears, an ordering that never
//! actually occurs -- every one of those tests still passes and the fold is
//! still broken for every real log it will ever see. `bathy-query` sits under
//! the CLI, the eleven MCP tools and M5 Task 2's diff, so an error here is
//! inherited by every consumer above it.
//!
//! This file therefore drives the identical stack
//! `crates/bathy-engine/tests/end_to_end_scan.rs` drives -- `ScopeManifest`
//! -> `ScanPlan` -> `TaskStore` -> `GroupCommitLog` -> `Scheduler`, against
//! REAL bound loopback listeners serving captured nginx bytes -- reads the
//! resulting gap-free log back, and folds *that*. The last test runs the
//! scan twice, either side of shutting a listener down, because a single
//! scan's log observes each endpoint once and so cannot exercise
//! supersession or order-dependence at all.
//!
//! Everything below `bathy-query` in the layer order is a `[dev-dependencies]`
//! edge only (see this crate's `Cargo.toml`); the library itself still depends
//! on `bathy-types` and nothing else.

use std::sync::Arc;

use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

use bathy_engine::{GroupCommitConfig, GroupCommitLog, Scheduler, SchedulerConfig};
use bathy_evidence::EvidenceStore;
use bathy_plan::ScanPlan;
use bathy_probe::ProbeRegistry;
use bathy_query::{Terminal, fold_events};
use bathy_scope::{BudgetLedger, ScopeManifest};
use bathy_store::{StartRequest, TaskStore};
use bathy_types::clock::{Clock, FixedClock};
use bathy_types::event::{Endpoint, Event, PortState, Transport};
use bathy_types::ids::ScopeId;
use bathy_types::nonempty::NonEmpty;
use bathy_types::request::{
    Budgets, EvidenceLevel, Objective, PortSelection, ScanRequest, ServiceDetection,
};

fn scope_id() -> ScopeId {
    "scope_01ARZ3NDEKTSV4RRFFQ69G5FAV".parse().unwrap()
}

fn loopback() -> std::net::IpAddr {
    "127.0.0.1".parse().unwrap()
}

fn tcp(port: u16) -> Endpoint {
    Endpoint {
        transport: Transport::Tcp,
        port,
    }
}

/// Same test-only door `bathy-engine`'s own end-to-end test uses:
/// `ScopeManifest::allows` refuses loopback unconditionally otherwise.
fn manifest() -> Arc<ScopeManifest> {
    Arc::new(
        ScopeManifest::for_tests_allowing_loopback(
            r#"{
              "id": "scope_01ARZ3NDEKTSV4RRFFQ69G5FAV",
              "description": "M5 Task 1 real-log fold fixture",
              "not_after": "2099-01-01T00:00:00.000Z",
              "allowed_cidrs": ["127.0.0.1/32"],
              "budget_ceiling": {
                "maximum_packets": 1000000,
                "maximum_runtime_seconds": 3600,
                "maximum_packets_per_second": 1000000
              }
            }"#,
        )
        .unwrap(),
    )
}

/// The same manifest with `not_after` already in the past relative to the
/// `FixedClock` every scan below runs on. Loading it is the one-line change
/// that turns a good scan into a refused one -- which is the whole point of
/// CRITICAL-1: this is a *routine* operational state, not an exotic one.
fn expired_manifest() -> Arc<ScopeManifest> {
    Arc::new(
        ScopeManifest::for_tests_allowing_loopback(
            r#"{
              "id": "scope_01ARZ3NDEKTSV4RRFFQ69G5FAV",
              "description": "M5 Task 1 real-log fold fixture, expired",
              "not_after": "2026-07-01T00:00:00.000Z",
              "allowed_cidrs": ["127.0.0.1/32"],
              "budget_ceiling": {
                "maximum_packets": 1000000,
                "maximum_runtime_seconds": 3600,
                "maximum_packets_per_second": 1000000
              }
            }"#,
        )
        .unwrap(),
    )
}

/// A port that accepts and immediately drops every connection: seen `Open`,
/// but every service-detection candidate gets `ProbeError::EmptyResponse`, so
/// no `service.observed` can be produced for it. Kept alongside
/// [`open_port_serving_nginx`] so one fold covers both an identified endpoint
/// and an open-but-unidentified one.
async fn silent_open_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            drop(stream);
        }
    });
    port
}

/// The exact response bytes captured from `docker.io/library/nginx:1.27-alpine`
/// in M4 Task 2 -- the same constant `bathy-engine`'s own end-to-end test and
/// `testdata/captures/http-nginx-with-version.json` use.
const NGINX_RESPONSE: &[u8] =
    b"HTTP/1.1 200 OK\r\nServer: nginx/1.26.0\r\nConnection: close\r\n\r\n<html></html>";

/// Answers the scheduler's bare connect probe with nothing (so it is simply
/// `Open`) and `http-get-v1`'s reconnect with [`NGINX_RESPONSE`], keyed on
/// whether any byte arrives rather than on accept order.
async fn open_port_serving_nginx() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        while let Ok((mut sock, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                let n = tokio::time::timeout(
                    std::time::Duration::from_millis(200),
                    sock.read(&mut buf),
                )
                .await
                .ok()
                .and_then(Result::ok)
                .unwrap_or(0);
                if n > 0 {
                    let _ = sock.write_all(NGINX_RESPONSE).await;
                }
            });
        }
    });
    port
}

/// [`open_port_serving_nginx`] with a shutdown handle, so a later scan of the
/// same port can observe it *closed* -- the differential-scanning case, and
/// the only way to get real supersession into a real log without hand-writing
/// an `Event`.
async fn closeable_port_serving_nginx() -> (u16, CancellationToken) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let shutdown = CancellationToken::new();
    let listen_until = shutdown.clone();
    tokio::spawn(async move {
        loop {
            let accepted = tokio::select! {
                _ = listen_until.cancelled() => break,
                accepted = listener.accept() => accepted,
            };
            let Ok((mut sock, _)) = accepted else { break };
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = [0u8; 4096];
                let n = tokio::time::timeout(
                    std::time::Duration::from_millis(200),
                    sock.read(&mut buf),
                )
                .await
                .ok()
                .and_then(Result::ok)
                .unwrap_or(0);
                if n > 0 {
                    let _ = sock.write_all(NGINX_RESPONSE).await;
                }
            });
        }
        // Dropping the listener unbinds the port, so the next connect to it
        // gets a genuine OS-produced refusal rather than a timeout.
        drop(listener);
    });
    (port, shutdown)
}

/// Runs one real scan against `ports` and returns its event log. Each call
/// gets its own store, evidence store and log under its own temporary
/// directory, and its own idempotency key, so two calls are two independent
/// scans rather than one scan resumed.
async fn scan_real_ports(ports: &[u16], idempotency_key: &str) -> Vec<Event> {
    scan_real_ports_under(ports, idempotency_key, manifest()).await
}

/// [`scan_real_ports`] with the scope manifest as a parameter, so the same
/// real stack can also produce the log of a *refused* scan.
async fn scan_real_ports_under(
    ports: &[u16],
    idempotency_key: &str,
    manifest: Arc<ScopeManifest>,
) -> Vec<Event> {
    let dir = tempfile::tempdir().unwrap();
    let clock: Arc<dyn Clock> = Arc::new(FixedClock::new("2026-08-01T15:04:31.182Z", 7).unwrap());
    let store = Arc::new(TaskStore::open(dir.path(), Arc::clone(&clock)).unwrap());

    let budgets = Budgets {
        maximum_packets: 1_000_000,
        maximum_runtime_seconds: 3_600,
        maximum_packets_per_second: 1_000_000,
    };
    let request = ScanRequest {
        targets: NonEmpty::try_from(vec!["127.0.0.1".to_string()]).unwrap(),
        authorization_scope_id: scope_id(),
        objective: Objective::InventoryExposedServices,
        ports: PortSelection::Explicit {
            explicit: NonEmpty::try_from(ports.iter().map(u16::to_string).collect::<Vec<_>>())
                .unwrap(),
        },
        service_detection: ServiceDetection::default(),
        budgets,
        evidence_level: EvidenceLevel::Headers,
        idempotency_key: idempotency_key.into(),
    };
    let plan = ScanPlan::build(&request, 1_000_000).unwrap();

    let outcome = store
        .start_or_reuse(&StartRequest {
            idempotency_key: request.idempotency_key.clone(),
            plan_hash: plan.hash(),
            scope_id: request.authorization_scope_id,
            request_json: "{}".to_string(),
            estimated_targets: plan.targets().len() as u64,
            estimated_probes: plan.len(),
        })
        .unwrap();
    let scan_id = outcome.scan_id();

    let log = Arc::new(std::sync::Mutex::new(
        GroupCommitLog::open(dir.path(), scan_id, GroupCommitConfig::default()).unwrap(),
    ));
    let scheduler = Scheduler::new(
        BudgetLedger::new(budgets),
        manifest,
        SchedulerConfig::default(),
        Arc::clone(&log),
        Arc::clone(&store),
        Arc::clone(&clock),
        scan_id,
        "0.1.0",
        request.service_detection,
        request.evidence_level,
        Arc::new(EvidenceStore::open(dir.path()).unwrap()),
        Arc::new(ProbeRegistry::standard()),
    );

    scheduler
        .run(&plan, 0, CancellationToken::new())
        .await
        .unwrap();

    log.lock().unwrap().read_from(0).unwrap()
}

/// Runs the two-port scan the first two tests share.
async fn scan_two_real_ports() -> (Vec<Event>, u16, u16) {
    let nginx_port = open_port_serving_nginx().await;
    let silent_port = silent_open_port().await;
    assert_ne!(nginx_port, silent_port, "fixture sanity: ports must differ");
    let events = scan_real_ports(&[nginx_port, silent_port], "m5-task-1-real-log-fold").await;
    (events, nginx_port, silent_port)
}

#[tokio::test]
async fn folding_a_real_scan_log_answers_what_the_scan_actually_found() {
    let (events, nginx_port, silent_port) = scan_two_real_ports().await;

    // Sanity: this is the genuine article, not a hand-built stand-in.
    assert_eq!(
        events.iter().map(|e| e.sequence).collect::<Vec<_>>(),
        (1..=events.len() as u64).collect::<Vec<_>>(),
        "fixture sanity: a real log is gap-free and monotonic"
    );

    let fold = fold_events(&events);

    // Both ports were probed, so both are in the fold -- and nothing else is.
    assert_eq!(fold.endpoints.len(), 2, "folded {fold:#?}");
    assert_eq!(fold.open_endpoints().count(), 2);

    // The nginx endpoint: reachability AND identification, folded onto one
    // record from two separate events, which is the fold's whole job.
    let nginx = &fold.endpoints[&(loopback(), tcp(nginx_port))];
    assert_eq!(nginx.state, Some(PortState::Open));
    let observation = nginx
        .observation
        .as_ref()
        .expect("the nginx port must carry a service observation");
    assert_eq!(observation.service, "http");
    assert_eq!(observation.product.as_deref(), Some("nginx"));
    assert_eq!(observation.version.as_deref(), Some("1.26.0"));
    assert_eq!(nginx.probe_id.as_deref(), Some("http-get-v1"));
    assert_eq!(
        nginx.evidence_refs.len(),
        1,
        "the identification cites exactly the one captured response"
    );

    // The silent endpoint: open, but nothing was identified on it. The fold
    // must not borrow the other endpoint's observation, and must not drop the
    // endpoint for having none.
    let silent = &fold.endpoints[&(loopback(), tcp(silent_port))];
    assert_eq!(silent.state, Some(PortState::Open));
    assert!(silent.observation.is_none());
    assert!(silent.probe_id.is_none());
    assert!(silent.evidence_refs.is_empty());

    // A completed scan folds to a completed terminal, carrying the counters
    // the engine actually reported.
    match fold.terminal {
        Some(Terminal::Completed {
            probes_sent,
            packets_spent,
            ..
        }) => {
            assert!(probes_sent > 0, "a real run sent probes");
            assert!(packets_spent > 0, "a real run spent packets");
        }
        other => panic!("a completed scan must fold to Terminal::Completed, got {other:?}"),
    }

    // This engine emits no `host.discovered` for an explicit-target scan --
    // asserted rather than assumed, because the fold's `hosts_up` would
    // otherwise be silently untested against reality.
    assert!(fold.hosts_up.is_empty());
}

#[tokio::test]
async fn a_real_log_of_a_port_that_closed_supersedes_by_sequence_in_any_order() {
    // AC-5.1 and AC-5.2 against real event shapes.
    //
    // A *single* scan's log cannot test either one: it observes each endpoint
    // exactly once, so nothing in it supersedes anything and folding it in any
    // order gives the same answer whether the fold sorts or not. Written that
    // way, a real-log order-independence test passes with the sort deleted --
    // measured, not assumed: an earlier version of this test rotated a
    // single-scan log through every pivot and survived every mutant in this
    // task's mutation sweep, which is exactly the decoration shape this
    // project has now found ten times.
    //
    // So this drives two real scans of the *same* port, with the listener shut
    // down in between: `Open` plus an nginx identification, then `Closed`. That
    // is the differential-scanning case M5 Task 2 is built on, and it is the
    // smallest real log in which order actually decides the answer.
    let (port, shutdown) = closeable_port_serving_nginx().await;
    let first = scan_real_ports(&[port], "m5-task-1-supersession-open").await;
    shutdown.cancel();
    // Let the accept loop observe the cancellation and drop the listener, so
    // the second scan meets a genuinely unbound port.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let second = scan_real_ports(&[port], "m5-task-1-supersession-closed").await;

    // Splice the two into the one log a resumed scan would have left behind:
    // the second scan's sequences continue after the first's. Renumbering is
    // the only edit -- every event's body is exactly what the engine emitted.
    let offset = first.len() as u64;
    let log: Vec<Event> = first
        .iter()
        .cloned()
        .chain(second.iter().cloned().map(|mut e| {
            e.sequence += offset;
            e
        }))
        .collect();
    assert_eq!(
        log.iter().map(|e| e.sequence).collect::<Vec<_>>(),
        (1..=log.len() as u64).collect::<Vec<_>>(),
        "the spliced log must still be gap-free and monotonic"
    );

    let endpoint = (loopback(), tcp(port));
    let forward = fold_events(&log);

    // AC-5.2 on real events: the later observation wins.
    assert_eq!(
        forward.endpoints[&endpoint].state,
        Some(PortState::Closed),
        "the second scan found the port closed and is the later event"
    );
    // AC-5.3 on real events: a closed endpoint is kept, not discarded.
    assert_eq!(forward.endpoints.len(), 1);
    assert_eq!(forward.open_endpoints().count(), 0);
    // The identification from the first scan is still reachable -- superseding
    // a port state does not erase what was learned about the service, which is
    // what lets a diff say "nginx 1.26.0 was here on Monday and the port is
    // shut today" rather than just "something changed".
    assert_eq!(
        forward.endpoints[&endpoint]
            .observation
            .as_ref()
            .unwrap()
            .product
            .as_deref(),
        Some("nginx")
    );

    // AC-5.1: every rotation of that log, and its reverse, folds identically.
    let mut reversed = log.clone();
    reversed.reverse();
    assert_eq!(fold_events(&reversed), forward);
    for pivot in 1..log.len() {
        let mut rotated = log.clone();
        rotated.rotate_left(pivot);
        assert_ne!(rotated, log, "rotation by {pivot} must reorder");
        assert_eq!(
            format!("{:?}", fold_events(&rotated)),
            format!("{forward:?}"),
            "rotating a real log by {pivot} changed the fold"
        );
    }
}

#[tokio::test]
async fn a_real_log_truncated_before_its_terminal_event_folds_to_no_terminal() {
    // "An unfinished scan has no terminal state", against a real log: this is
    // the shape a cancelled or still-running scan leaves behind, and it is the
    // one an MCP client polling a running scan will fold most often.
    let (events, nginx_port, _) = scan_two_real_ports().await;
    let truncated = &events[..events.len() - 1];
    assert!(
        !matches!(
            truncated.last().unwrap().body,
            bathy_types::event::EventBody::ScanCompleted { .. }
        ),
        "fixture sanity: the terminal event must be the one removed"
    );

    let fold = fold_events(truncated);
    assert!(
        fold.terminal.is_none(),
        "a truncated log must not fold to something that looks completed"
    );
    // Everything learned before the truncation point survives: a partial fold
    // is still a useful answer, not an empty one.
    assert_eq!(fold.open_endpoints().count(), 2);
    assert!(
        fold.endpoints[&(loopback(), tcp(nginx_port))]
            .observation
            .is_some()
    );
}

#[tokio::test]
async fn a_real_log_of_a_policy_denied_scan_folds_to_a_denied_terminal() {
    // CRITICAL-1 against a real engine log rather than a hand-built one, and
    // against a real listener that must never be touched.
    //
    // The reproduction the fold has to survive: an operator's manifest
    // expires. `Scheduler::run` refuses before dispatching anything, the
    // store records `TaskStatus::Denied`, and the log it leaves behind is
    // exactly one event. If the fold discards that event -- as it did -- the
    // result is `{endpoints: {}, hosts_up: {}, terminal: None}`, which is
    // byte-identical to folding an empty log, and M5 Task 2's diff of
    // yesterday's good scan against it can only classify every endpoint as
    // having disappeared. No packet was sent.
    let listener_port = open_port_serving_nginx().await;
    let good = scan_real_ports(&[listener_port], "m5-task-1-denied-baseline").await;
    let refused = scan_real_ports_under(
        &[listener_port],
        "m5-task-1-denied-expired",
        expired_manifest(),
    )
    .await;

    // Fixture sanity, asserted against the engine rather than assumed: a
    // scope-validity denial emits exactly one event and no `scan.started`
    // (`bathy-engine`'s own `a_scope_validity_denial_emits_no_scan_started`).
    assert_eq!(
        refused.len(),
        1,
        "fixture sanity: a refused scan's log is one event, got {refused:#?}"
    );

    let yesterday = fold_events(&good);
    let today = fold_events(&refused);
    let never_ran = fold_events(&[]);

    assert_eq!(yesterday.endpoints.len(), 1);
    assert!(matches!(
        yesterday.terminal,
        Some(Terminal::Completed { .. })
    ));

    // The endpoints really are gone from today's fold -- that part is honest,
    // because nothing was probed. What must NOT be gone is the reason.
    assert!(today.endpoints.is_empty());
    match &today.terminal {
        Some(Terminal::Denied { reason_code, .. }) => assert_eq!(
            reason_code.code(),
            "scope_expired",
            "the engine's typed DenyReason must survive the fold"
        ),
        other => panic!("a refused scan must fold to Terminal::Denied, got {other:?}"),
    }
    assert_ne!(
        format!("{today:?}"),
        format!("{never_ran:?}"),
        "a refused scan must not be byte-identical to a scan that never ran"
    );
}
