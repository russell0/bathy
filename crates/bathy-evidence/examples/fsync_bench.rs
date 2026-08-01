//! Throughput measurement for C1's durability barrier, requested by the M2
//! fix-wave dispatch ("Measure and report the throughput cost of the fsyncs
//! on the append path"). Not part of the crate's public surface or its test
//! suite -- a one-shot tool run manually to produce the numbers quoted in
//! the fix-wave report, then removed.
//!
//! Run with `cargo run --release -p bathy-evidence --example fsync_bench`.

use std::time::Instant;

use bathy_evidence::{EventLog, EvidenceStore};
use bathy_types::clock::{Clock, FixedClock};
use bathy_types::event::EventBody;

const N: u64 = 2_000;
const BLOB_LEN: usize = 512;

fn bench_evidence_put(durable: bool, n: u64) -> std::time::Duration {
    let dir = tempfile::tempdir().unwrap();
    let store = if durable {
        EvidenceStore::open(dir.path()).unwrap()
    } else {
        EvidenceStore::open_without_durability_barrier(dir.path()).unwrap()
    };
    let start = Instant::now();
    for i in 0..n {
        let bytes = format!("evidence-blob-{i:08}-{}", "x".repeat(BLOB_LEN)).into_bytes();
        store.put(&bytes).unwrap();
    }
    start.elapsed()
}

fn bench_log_append(durable: bool, n: u64) -> std::time::Duration {
    let dir = tempfile::tempdir().unwrap();
    let scan_id = "scan_01ARZ3NDEKTSV4RRFFQ69G5FAV".parse().unwrap();
    let mut log = if durable {
        EventLog::open(dir.path(), scan_id).unwrap()
    } else {
        EventLog::open_without_durability_barrier(dir.path(), scan_id).unwrap()
    };
    let clock: Box<dyn Clock> = Box::new(FixedClock::new("2026-08-01T15:04:31.182Z", 7).unwrap());
    let start = Instant::now();
    for i in 0..n {
        log.append(
            EventBody::Progress {
                probes_sent: i,
                probes_total: n,
                packets_spent: i,
            },
            clock.as_ref(),
            "0.1.0",
        )
        .unwrap();
    }
    start.elapsed()
}

fn report(label: &str, durable: std::time::Duration, non_durable: std::time::Duration, n: u64) {
    let durable_per_op = durable.as_secs_f64() * 1e6 / n as f64;
    let non_durable_per_op = non_durable.as_secs_f64() * 1e6 / n as f64;
    let ratio = durable.as_secs_f64() / non_durable.as_secs_f64().max(1e-12);
    println!(
        "{label}: n={n} durable={durable:?} ({durable_per_op:.2} us/op) \
         non_durable={non_durable:?} ({non_durable_per_op:.2} us/op) ratio={ratio:.2}x"
    );
}

fn main() {
    // Warm up the filesystem/allocator once before the timed runs.
    let _ = bench_evidence_put(true, 50);
    let _ = bench_log_append(true, 50);

    let put_durable = bench_evidence_put(true, N);
    let put_non_durable = bench_evidence_put(false, N);
    report("EvidenceStore::put", put_durable, put_non_durable, N);

    let append_durable = bench_log_append(true, N);
    let append_non_durable = bench_log_append(false, N);
    report("EventLog::append", append_durable, append_non_durable, N);
}
