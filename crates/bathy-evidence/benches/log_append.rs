//! AC-7.15 — event-log append throughput, with and without the durability
//! barrier.
//!
//! The event log is on the scan's critical path: every port state and every
//! service observation goes through [`EventLog::append`], and since C1 that
//! call `sync_data`s before returning. That is the right default — a resumed
//! scan's `last_sequence` must never be ahead of what a crash actually left on
//! disk — and it is also, by orders of magnitude, the most expensive thing a
//! scan does per observation.
//!
//! Both are measured because the *ratio* is the number that matters. Publishing
//! only the fast one would advertise a throughput no shipped configuration
//! reaches; publishing only the slow one would hide what the barrier costs, and
//! `bathy-engine`'s group-commit layer exists precisely because of that cost.

use std::net::{IpAddr, Ipv4Addr};

use bathy_evidence::log::EventLog;
use bathy_types::clock::FixedClock;
use bathy_types::event::{Endpoint, EventBody, PortState, Target, Transport};
use bathy_types::ids::ScanId;
use criterion::{Criterion, criterion_group, criterion_main};

fn scan_id() -> ScanId {
    "scan_01ARZ3NDEKTSV4RRFFQ69G5FAV"
        .parse()
        .expect("a valid scan id")
}

/// One `port.state` record — the commonest event in any scan by a wide
/// margin, and the one whose rate bounds a large sweep.
fn body(index: u32) -> EventBody {
    EventBody::PortStateObserved {
        target: Target {
            ip: IpAddr::V4(Ipv4Addr::from(0x0a1e0000 + index)),
        },
        endpoint: Endpoint {
            transport: Transport::Tcp,
            port: 80,
        },
        state: PortState::Open,
        evidence_refs: None,
    }
}

fn bench(c: &mut Criterion) {
    let clock = FixedClock::new("2026-08-04T12:00:00.000Z", 7).expect("a valid fixed clock");

    let mut group = c.benchmark_group("log_append");
    group.throughput(criterion::Throughput::Elements(1));

    group.bench_function("durable_fsync_per_record", |b| {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut log = EventLog::open(dir.path(), scan_id()).expect("open");
        let mut index = 0u32;
        b.iter(|| {
            index = index.wrapping_add(1);
            log.append(body(index), &clock, "bench").expect("append")
        });
    });

    group.bench_function("without_durability_barrier", |b| {
        let dir = tempfile::tempdir().expect("tempdir");
        let mut log =
            EventLog::open_without_durability_barrier(dir.path(), scan_id()).expect("open");
        let mut index = 0u32;
        b.iter(|| {
            index = index.wrapping_add(1);
            log.append(body(index), &clock, "bench").expect("append")
        });
    });
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
