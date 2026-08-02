//! Throughput measurement for M3 Task 7's group commit, requested by the
//! task dispatch ("Measure and report the throughput after batching"). Not
//! part of the crate's public surface or test suite -- a one-shot tool run
//! manually to produce the numbers quoted in this task's report. Mirrors
//! `bathy-evidence/examples/fsync_bench.rs`'s own shape, and re-measures its
//! "before" (per-event durable `EventLog::append`) baseline fresh in this
//! same environment, run immediately before the "after" number, rather than
//! reusing the M2 report's number cold -- so the comparison is apples to
//! apples against identical hardware, load, and filesystem state.
//!
//! Run with `cargo run --release -p bathy-engine --example group_commit_bench`.

use std::time::Instant;

use bathy_engine::{GroupCommitConfig, GroupCommitLog};
use bathy_evidence::EventLog;
use bathy_types::clock::{Clock, FixedClock};
use bathy_types::event::EventBody;

const N: u64 = 5_000;

fn body(i: u64, n: u64) -> EventBody {
    EventBody::Progress {
        probes_sent: i,
        probes_total: n,
        packets_spent: i,
    }
}

/// BEFORE: `EventLog::open`'s default, durable constructor -- `sync_data()`
/// on every single `append`. What `Scheduler::run` must NOT be wired to,
/// per the M2 durability contract this task carries forward.
fn bench_durable_append(n: u64) -> std::time::Duration {
    let dir = tempfile::tempdir().unwrap();
    let scan_id = "scan_01ARZ3NDEKTSV4RRFFQ69G5FAV".parse().unwrap();
    let mut log = EventLog::open(dir.path(), scan_id).unwrap();
    let clock: Box<dyn Clock> = Box::new(FixedClock::new("2026-08-01T15:04:31.182Z", 7).unwrap());
    let start = Instant::now();
    for i in 0..n {
        log.append(body(i, n), clock.as_ref(), "0.1.0").unwrap();
    }
    start.elapsed()
}

/// AFTER: `GroupCommitLog::append`, batching `sync_data()` over
/// `config.max_events`. `force_sync()` at the end accounts for the trailing
/// partial batch, matching exactly what `Scheduler::run` does once,
/// unconditionally, before returning.
fn bench_group_commit_append(n: u64, config: GroupCommitConfig) -> std::time::Duration {
    let dir = tempfile::tempdir().unwrap();
    let scan_id = "scan_01ARZ3NDEKTSV4RRFFQ69G5FAV".parse().unwrap();
    let mut log = GroupCommitLog::open(dir.path(), scan_id, config).unwrap();
    let clock: Box<dyn Clock> = Box::new(FixedClock::new("2026-08-01T15:04:31.182Z", 7).unwrap());
    let start = Instant::now();
    for i in 0..n {
        log.append(body(i, n), clock.as_ref(), "0.1.0").unwrap();
    }
    log.force_sync().unwrap();
    start.elapsed()
}

fn report(label: &str, d: std::time::Duration, n: u64) -> f64 {
    let per_op_us = d.as_secs_f64() * 1e6 / n as f64;
    println!("{label}: n={n} total={d:?} ({per_op_us:.3} us/op)");
    per_op_us
}

fn main() {
    // Warm up the filesystem/allocator once before the timed runs.
    let _ = bench_durable_append(50);
    let _ = bench_group_commit_append(50, GroupCommitConfig::default());

    let durable = bench_durable_append(N);
    let durable_per_op = report("BEFORE  EventLog::append (per-event fsync)", durable, N);

    let grouped = bench_group_commit_append(N, GroupCommitConfig::default());
    let grouped_per_op = report(
        "AFTER   GroupCommitLog::append (batched fsync, default config)",
        grouped,
        N,
    );

    let ratio = durable.as_secs_f64() / grouped.as_secs_f64().max(1e-12);
    println!("speedup: {ratio:.2}x");

    // Projected full-scan cost at the workspace's 1,000,000-packet budget
    // ceiling, one `port.state` event per unit -- extrapolated from the
    // per-op cost measured just above (same environment, same run), the
    // way the M2 report projected the per-event number to ~88 minutes.
    const CEILING: f64 = 1_000_000.0;
    let projected_before_s = durable_per_op * CEILING / 1e6;
    let projected_after_s = grouped_per_op * CEILING / 1e6;
    println!(
        "projected at the 1,000,000-event ceiling: before={projected_before_s:.1}s (~{:.1}min), after={projected_after_s:.2}s",
        projected_before_s / 60.0
    );
}
