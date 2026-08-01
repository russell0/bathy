//! C2, whole-branch review: before this fix, `TaskStore::open` took
//! `clock: Box<dyn Clock>` *by value*, so no caller could ever hand the same
//! clock instance to both a `TaskStore` and a `bathy_evidence::EventLog` --
//! the two halves M2 delivers. In real usage that forces two independently
//! constructed clocks: two `SystemClock`s means two independent instances of
//! `ulid`'s `Generator` type (no shared monotonicity across a scan), and two
//! `FixedClock`s built with the same seed produce byte-identical id
//! sequences -- which is exactly what forced `bathy-store`'s own
//! cross-connection race test (`tasks.rs`) to use *disjoint* seeds as a
//! workaround, because there was no way to share one clock instead.
//!
//! `TaskStore::open` now takes `Arc<dyn Clock>`, and `bathy-types` gained
//! `impl<T: Clock + ?Sized> Clock for Arc<T>`. This test is the actual
//! requirement the dispatch names: one shared clock drives both an
//! `EventLog` and a `TaskStore`, and every identifier either one produces
//! stays distinct -- using the SAME seed everywhere, which would have
//! collided under the old API and only doesn't here because it is
//! genuinely the same shared instance, not because the seeds happen to
//! differ.

use std::sync::Arc;

use bathy_evidence::EventLog;
use bathy_store::{StartRequest, TaskStore};
use bathy_types::clock::{Clock, FixedClock};
use bathy_types::event::EventBody;
use bathy_types::ids::{Digest, ScopeId};

fn scope_id() -> ScopeId {
    "scope_01ARZ3NDEKTSV4RRFFQ69G5FAV".parse().unwrap()
}

fn start_request(key: &str, plan_bytes: &[u8]) -> StartRequest {
    StartRequest {
        idempotency_key: key.to_string(),
        plan_hash: Digest::of_bytes(plan_bytes),
        scope_id: scope_id(),
        request_json: "{}".to_string(),
        estimated_targets: 1,
        estimated_probes: 1,
    }
}

#[test]
fn one_shared_clock_drives_two_task_stores_and_an_event_log_with_no_id_collisions() {
    let shared: Arc<dyn Clock> = Arc::new(FixedClock::new("2026-08-01T15:04:31.182Z", 7).unwrap());

    // Two TaskStores, each backed by a clone of the SAME clock instance --
    // the identical seed here is deliberate: under the old Box-by-value API
    // this exact setup was the documented collision hazard, worked around
    // in `bathy-store`'s own test suite with disjoint seeds. Sharing the
    // instance, not choosing different seeds, is what must prevent it now.
    let dir_a = tempfile::tempdir().unwrap();
    let dir_b = tempfile::tempdir().unwrap();
    let store_a = TaskStore::open(dir_a.path(), Arc::clone(&shared)).unwrap();
    let store_b = TaskStore::open(dir_b.path(), Arc::clone(&shared)).unwrap();

    let a = store_a
        .start_or_reuse(&start_request("key-a", b"plan-a"))
        .unwrap();
    let b = store_b
        .start_or_reuse(&start_request("key-b", b"plan-b"))
        .unwrap();

    assert_ne!(
        a.scan_id(),
        b.scan_id(),
        "two TaskStores drawing from the SAME shared clock instance must \
         never produce the same ScanId, even with an identical seed -- \
         sharing the instance is what prevents the collision, not the seed"
    );

    // The same shared clock also drives an EventLog -- the other half of
    // M2 -- via `&dyn Clock`, obtained from the `Arc` without needing a
    // second clock at all.
    let events_dir = tempfile::tempdir().unwrap();
    let mut log = EventLog::open(events_dir.path(), a.scan_id()).unwrap();
    let event = log
        .append(
            EventBody::Progress {
                probes_sent: 1,
                probes_total: 1,
                packets_spent: 1,
            },
            shared.as_ref(),
            "0.1.0",
        )
        .unwrap();

    let record_a = store_a.get(a.scan_id()).unwrap().unwrap();
    assert_eq!(
        event.timestamp, record_a.created_at,
        "the event log and the task store must observe identical \
         timestamps from the one literal shared clock instance"
    );

    // Draw further identifiers directly from the shared clock (standing in
    // for whatever else a real caller assembles per event/scan) and confirm
    // none of them, nor the two ScanIds above, ever collide -- the
    // generator's monotonic counter must be genuinely shared, not
    // per-consumer.
    let mut seen = std::collections::HashSet::new();
    seen.insert(a.scan_id().to_string());
    seen.insert(b.scan_id().to_string());
    for _ in 0..20 {
        let id = shared.new_event_id();
        assert!(
            seen.insert(id.to_string()),
            "duplicate id drawn from the shared clock: {id}"
        );
    }
}
