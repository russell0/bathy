//! AC-7.15 — RFC 8785 canonicalization, and the digest built on it.
//!
//! Every `plan_hash` in this project is a BLAKE3 digest over
//! [`bathy_types::canonical::canonical_json`]'s output, and the deterministic
//! planning claim — same request plus same manifest gives the same hash — is
//! the one claim the project makes without qualification. So this is measured
//! on the shape it actually runs on: a scan plan's normalized request
//! document, not a synthetic blob.
//!
//! The interesting cost is key sorting, which is why the third case is a
//! document whose keys arrive in reverse order. Canonicalization that is fast
//! only on already-sorted input is fast only on input that did not need it.

use bathy_types::canonical::{canonical_json, plan_digest};
use criterion::{Criterion, criterion_group, criterion_main};
use serde_json::{Value, json};

/// A plan document of the shape `bathy-plan` hashes: the request with its
/// targets, ports and idempotency key replaced by the resolved expansion.
fn plan_document(targets: usize, ports: usize) -> Value {
    json!({
        "objective": "inventory_exposed_services",
        "authorization_scope_id": "scope_01ARZ3NDEKTSV4RRFFQ69G5FAV",
        "evidence_level": "headers",
        "service_detection": { "enabled": true, "intensity": 4 },
        "budgets": {
            "maximum_packets": 1_000_000,
            "maximum_runtime_seconds": 3600,
            "maximum_packets_per_second": 100_000
        },
        "resolved_targets": (0..targets)
            .map(|i| format!("10.{}.{}.{}", i / 65536, (i / 256) % 256, i % 256))
            .collect::<Vec<_>>(),
        "resolved_ports": (0..ports).map(|p| 1024 + p as u64).collect::<Vec<_>>(),
    })
}

/// The same content with its object keys in descending order, so the sort has
/// something to do.
fn reversed_keys(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut out = serde_json::Map::new();
            for (k, v) in map.iter().rev() {
                out.insert(k.clone(), reversed_keys(v));
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(reversed_keys).collect()),
        other => other.clone(),
    }
}

fn bench(c: &mut Criterion) {
    let small = plan_document(4, 13);
    let large = plan_document(1024, 100);
    let unsorted = reversed_keys(&large);

    let mut group = c.benchmark_group("canonical_json");
    group.bench_function("small_plan", |b| {
        b.iter(|| canonical_json(std::hint::black_box(&small)).expect("canonicalizes"))
    });
    group.bench_function("plan_over_1024_targets", |b| {
        b.iter(|| canonical_json(std::hint::black_box(&large)).expect("canonicalizes"))
    });
    group.bench_function("plan_with_keys_in_reverse_order", |b| {
        b.iter(|| canonical_json(std::hint::black_box(&unsorted)).expect("canonicalizes"))
    });
    // Canonicalization plus BLAKE3, which is what a caller actually pays for
    // a `plan_hash`: reporting only the first half would understate it.
    group.bench_function("plan_digest_over_1024_targets", |b| {
        b.iter(|| plan_digest(std::hint::black_box(&large)).expect("digests"))
    });
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
