//! AC-7.15 — building a plan, including the `/16` the plan text names.
//!
//! Planning is the half of this project that is deterministic, and it is also
//! the half an agent waits on synchronously: `scan.preview` returns a
//! `plan_hash` and an estimate before a single packet is emitted, so the time
//! this takes is time the caller spends looking at nothing.
//!
//! A `/16` is 65534 usable addresses. It is here because that is the size at
//! which target expansion stops being free, and because `expand_targets`
//! allocates the whole address vector — a change that makes that allocation
//! quadratic would be invisible at `/24` and unmissable here.

use bathy_plan::ScanPlan;
use bathy_types::ids::ScopeId;
use bathy_types::nonempty::NonEmpty;
use bathy_types::request::{
    Budgets, EvidenceLevel, Objective, PortSelection, ScanRequest, ServiceDetection,
};
use criterion::{Criterion, criterion_group, criterion_main};

fn request(targets: &[&str], ports: &[&str]) -> ScanRequest {
    ScanRequest {
        targets: NonEmpty::try_from(targets.iter().map(|s| s.to_string()).collect::<Vec<_>>())
            .expect("a benchmark target list is never empty"),
        authorization_scope_id: "scope_01ARZ3NDEKTSV4RRFFQ69G5FAV"
            .parse::<ScopeId>()
            .expect("a valid scope id"),
        objective: Objective::InventoryExposedServices,
        ports: PortSelection::Explicit {
            explicit: NonEmpty::try_from(ports.iter().map(|s| s.to_string()).collect::<Vec<_>>())
                .expect("a benchmark port list is never empty"),
        },
        service_detection: ServiceDetection::default(),
        budgets: Budgets {
            maximum_packets: 100_000_000,
            maximum_runtime_seconds: 3_600,
            maximum_packets_per_second: 100_000,
        },
        evidence_level: EvidenceLevel::Headers,
        idempotency_key: "bench".into(),
    }
}

fn bench(c: &mut Criterion) {
    // The lab's own shape: eleven addresses over thirteen ports.
    let lab = request(
        &["10.30.0.10-10.30.0.18", "10.30.0.200", "10.30.0.201"],
        &[
            "22", "25", "53", "80", "443", "587", "853", "2222", "3306", "5432", "6379", "8080",
            "33060",
        ],
    );
    let slash_sixteen = request(&["10.20.0.0/16"], &["80", "443"]);
    let slash_twentyfour = request(&["10.20.30.0/24"], &["80", "443"]);

    let mut group = c.benchmark_group("plan_construction");
    group.sample_size(20);
    group.bench_function("lab_11_addresses_13_ports", |b| {
        b.iter(|| ScanPlan::build(std::hint::black_box(&lab), 100_000).expect("plans"))
    });
    group.bench_function("slash_24_two_ports", |b| {
        b.iter(|| ScanPlan::build(std::hint::black_box(&slash_twentyfour), 100_000).expect("plans"))
    });
    group.bench_function("slash_16_two_ports", |b| {
        b.iter(|| ScanPlan::build(std::hint::black_box(&slash_sixteen), 100_000).expect("plans"))
    });

    // The hash on its own, because `scan.preview`'s answer is the hash and a
    // regression in canonicalization would otherwise hide inside the build.
    let built = ScanPlan::build(&slash_sixteen, 100_000).expect("plans");
    group.bench_function("plan_hash_of_a_slash_16", |b| {
        b.iter(|| std::hint::black_box(&built).hash())
    });
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
