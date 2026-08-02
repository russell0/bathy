//! M3's milestone exit criteria (`docs/superpowers/plans/2026-07-31-bathy-m3-planner-engine.md`)
//! require: "An end-to-end test scans `127.0.0.1` against two locally bound
//! ports and produces a valid, gap-free event log containing `scan.started`,
//! two `port.state` events with `state: open`, and `scan.completed`."
//!
//! M3 whole-branch review: no such test existed in-tree, and nothing
//! anywhere asserted sequence gap-freeness after a real scheduler run --
//! `EventLog` itself refuses to accept a gap on `append`/`open` (see
//! `bathy-evidence/src/log.rs`), which is a real guarantee, but a component
//! never *tripping* its own internal consistency check is not the same
//! claim as "the exit criterion's own words were ever checked against a
//! real run." This test checks them directly: it drives the full public
//! stack (`ScopeManifest` -> `ScanPlan` -> `TaskStore` -> `GroupCommitLog`
//! -> `Scheduler`) exactly the way an M5 orchestrator will, against two
//! REAL bound loopback listeners, and reads the resulting log back to
//! assert on its literal shape -- not a mock, and not `bathy-engine`'s own
//! `#[cfg(test)]` unit-test harness (this file lives outside the crate, in
//! `tests/`, and uses only the crate's public API).

use std::sync::Arc;

use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

use bathy_engine::{GroupCommitConfig, GroupCommitLog, RunSummary, Scheduler, SchedulerConfig};
use bathy_plan::ScanPlan;
use bathy_scope::{BudgetLedger, ScopeManifest};
use bathy_store::{StartRequest, TaskStore};
use bathy_types::clock::{Clock, FixedClock};
use bathy_types::event::{EventBody, PortState};
use bathy_types::ids::ScopeId;
use bathy_types::nonempty::NonEmpty;
use bathy_types::request::{
    Budgets, EvidenceLevel, Objective, PortSelection, ScanRequest, ServiceDetection,
};

fn scope_id() -> ScopeId {
    "scope_01ARZ3NDEKTSV4RRFFQ69G5FAV".parse().unwrap()
}

/// A manifest authorizing loopback, built via the same test-only door
/// `bathy-engine`'s own scheduler tests use (`ScopeManifest::allows`
/// refuses loopback unconditionally otherwise -- see that constructor's own
/// doc comment in `bathy-scope`). Reachable here because this crate's
/// `[dev-dependencies]` enables `bathy-scope`'s `test-util` feature for all
/// of its own test targets, including this integration test.
fn manifest() -> Arc<ScopeManifest> {
    Arc::new(
        ScopeManifest::for_tests_allowing_loopback(
            r#"{
              "id": "scope_01ARZ3NDEKTSV4RRFFQ69G5FAV",
              "description": "M3 exit-criteria end-to-end test fixture",
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

/// Binds a real listener on 127.0.0.1 and spawns a background task that
/// accepts (and immediately drops) every connection made to it, for the
/// lifetime of the test process -- exactly what the exit criterion's own
/// words describe: "two locally bound ports."
async fn open_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            drop(stream);
        }
    });
    port
}

#[tokio::test]
async fn scanning_127_0_0_1_against_two_open_ports_produces_a_gap_free_log_matching_the_exit_criteria()
 {
    let port_a = open_port().await;
    let port_b = open_port().await;
    // Two distinct ports, named explicitly, as the exit criteria's own text
    // ("two locally bound ports") requires -- not a range that might
    // happen to contain exactly two, and not the same port twice.
    assert_ne!(port_a, port_b, "test fixture sanity: ports must differ");

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
            explicit: NonEmpty::try_from(vec![port_a.to_string(), port_b.to_string()]).unwrap(),
        },
        service_detection: ServiceDetection::default(),
        budgets,
        evidence_level: EvidenceLevel::Headers,
        idempotency_key: "m3-exit-criteria-end-to-end".into(),
    };
    let plan = ScanPlan::build(&request, 1_000_000).unwrap();
    assert_eq!(plan.len(), 2, "two ports on one target must be two units");

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

    let ledger = BudgetLedger::new(budgets);
    let scheduler = Scheduler::new(
        ledger,
        manifest(),
        SchedulerConfig::default(),
        Arc::clone(&log),
        Arc::clone(&store),
        Arc::clone(&clock),
        scan_id,
        "0.1.0",
    );

    let summary: RunSummary = scheduler
        .run(&plan, 0, CancellationToken::new())
        .await
        .unwrap();

    // The scan itself: both ports are real, live listeners, so both units
    // must resolve `Open`, and nothing about this run should look like
    // cancellation, budget exhaustion, time exhaustion, or a policy denial.
    assert_eq!(summary.units_completed, 2);
    assert_eq!(summary.open_ports, 2);
    assert!(!summary.cancelled);
    assert!(!summary.budget_exhausted);
    assert!(!summary.time_exhausted);
    assert!(!summary.policy_denied);

    let events = log.lock().unwrap().read_from(0).unwrap();

    // The exit criterion's own words, checked directly against the log's
    // actual content: `scan.started`, two `port.state` events with
    // `state: open`, and `scan.completed` -- nothing else, and in that
    // relative order.
    assert!(
        matches!(events.first().unwrap().body, EventBody::ScanStarted { .. }),
        "first event must be scan.started, got {:?}",
        events.first()
    );
    assert!(
        matches!(events.last().unwrap().body, EventBody::ScanCompleted { .. }),
        "last event must be scan.completed, got {:?}",
        events.last()
    );
    let open_port_states: Vec<_> = events
        .iter()
        .filter(|e| {
            matches!(
                &e.body,
                EventBody::PortStateObserved {
                    state: PortState::Open,
                    ..
                }
            )
        })
        .collect();
    assert_eq!(
        open_port_states.len(),
        2,
        "expected exactly two port.state events with state: open, got {events:#?}"
    );
    // Confirm those two events name the two ports actually scanned, not
    // just any two `Open` observations.
    let observed_ports: std::collections::BTreeSet<u16> = open_port_states
        .iter()
        .map(|e| match &e.body {
            EventBody::PortStateObserved { endpoint, .. } => endpoint.port,
            _ => unreachable!(),
        })
        .collect();
    assert_eq!(
        observed_ports,
        std::collections::BTreeSet::from([port_a, port_b])
    );
    assert_eq!(
        events.len(),
        4,
        "exactly scan.started, port.state x2, scan.completed -- nothing else \
         (no host.discovered, no scan.progress, no policy.denied), got {events:#?}"
    );

    // Gap-freeness, asserted directly against the exit criterion's own
    // words -- not merely relied upon because `EventLog` would have
    // refused to construct a gappy log in the first place. Sequences start
    // at 1 and increase by exactly 1, with no gap and no duplicate.
    let sequences: Vec<u64> = events.iter().map(|e| e.sequence).collect();
    let expected: Vec<u64> = (1..=events.len() as u64).collect();
    assert_eq!(
        sequences, expected,
        "event log is not gap-free/monotonic: got sequences {sequences:?}"
    );
    // Every event shares the one scan_id this run was for.
    assert!(events.iter().all(|e| e.scan_id == scan_id));

    // And the persisted task record agrees: the scan completed, and its
    // resumption cursor points at the log's own last sequence -- the same
    // "derived index, never a second source of truth" relationship
    // `bathy-evidence`'s own module doc describes.
    let record = store.get(scan_id).unwrap().unwrap();
    assert_eq!(record.status, bathy_types::task::TaskStatus::Completed);
    assert_eq!(record.last_sequence, events.last().unwrap().sequence);
}
