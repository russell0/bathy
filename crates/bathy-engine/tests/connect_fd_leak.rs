//! `probe_connect` must release its file descriptor before it returns.
//!
//! WHY THIS TEST OWNS A WHOLE TEST BINARY, AND MUST STAY THE ONLY TEST IN IT.
//!
//! The only way to count open descriptors on Linux without `unsafe` (this
//! workspace is `#![forbid(unsafe_code)]` outside `bathy-packetd`, so
//! `libc::getrlimit`/`fcntl` are not available) is to read `/proc/self/fd`.
//! That directory is **process-wide**: it lists every descriptor open in the
//! process, not the ones this test opened.
//!
//! This test previously lived in `crates/bathy-engine/src/connect.rs`'s
//! `#[cfg(test)] mod tests`, where it shared a process with the other ~104
//! unit tests of `bathy-engine` -- dozens of which bind loopback listeners,
//! open SQLite databases and spawn tokio runtimes. `cargo test` runs those
//! tests **concurrently** in that one process, so `/proc/self/fd` counted
//! before and after this test's probe loop measured *the whole suite's*
//! descriptors and attributed the difference to `probe_connect`. It failed
//! on every Linux CI run from 2026-08-01 onward with "probe_connect is not
//! closing its socket promptly," which was never true. The measurement that
//! proves it: the reported growth tracks `--test-threads`, not `PROBES` --
//! at `--test-threads=1` and `2` the delta is under 20, at `4` it was 110,
//! at `8` it was 428, with `PROBES` fixed at 300 throughout. A genuine
//! per-probe leak would be ~300 at every level of parallelism. It never
//! reproduced on macOS because the assertion is `#[cfg(target_os = "linux")]`
//! -- there is no `/proc` to read -- so nobody's local run ever executed it.
//!
//! An integration test is compiled into its own binary and `cargo test` runs
//! test binaries one at a time, so here this test is the sole occupant of its
//! process and `/proc/self/fd` means what the assertion below assumes it
//! means. `assert_process_is_quiescent` re-checks that precondition at
//! runtime rather than trusting the file to stay single-test: if a second
//! test is ever added here, the failure says *the measurement is invalid*
//! instead of blaming production code for five days.

use std::time::Duration;

use bathy_engine::{ConnectOutcome, probe_connect};

/// Descriptors open in THIS PROCESS. Linux only: macOS mounts no `/proc` by
/// default, and every other way to ask needs `unsafe`.
#[cfg(target_os = "linux")]
fn open_fd_count() -> usize {
    std::fs::read_dir("/proc/self/fd")
        .map(|d| d.count())
        .unwrap_or(0)
}

/// Fails if anything *other* than this test is opening or closing
/// descriptors, because that makes the delta measured below meaningless.
///
/// Three samples spread over ~150ms, taken after the runtime is already up.
/// A quiet process holds the count exactly steady; a process running other
/// tests concurrently does not (measured: hundreds of descriptors of
/// movement inside the unit-test binary). The message names the real problem
/// -- this test no longer owns its process -- rather than reporting a leak.
#[cfg(target_os = "linux")]
async fn assert_process_is_quiescent() {
    let mut samples = Vec::new();
    for _ in 0..3 {
        samples.push(open_fd_count());
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let (lo, hi) = (
        *samples.iter().min().unwrap(),
        *samples.iter().max().unwrap(),
    );
    assert!(
        hi - lo <= 2,
        "this process is not quiescent (fd count moved {samples:?} with nothing running but \
         this test), so a process-wide /proc/self/fd delta cannot be attributed to \
         probe_connect. Something else was added to this test binary -- see this file's \
         module comment. This is a broken measurement, NOT evidence of an fd leak."
    );
}

/// A scan issues one `probe_connect` per port, so a per-call leak becomes a
/// leak per probe and a large scan exhausts the local descriptor table.
///
/// `PROBES = 300`, not 2,000: each iteration is a real TCP connect that is
/// immediately closed from the client side, and an actively-closed
/// connection's local (ephemeral) port sits in `TIME_WAIT` for a fixed
/// OS interval before it is reusable. At 2,000 this single test was measured
/// consuming ~2,023 ephemeral ports per run and reproduced outright
/// exhaustion of macOS's 16,384-port range. The property holds identically at
/// 300 (confirmed at both sizes); the cost is a seventh.
#[tokio::test]
async fn many_open_probes_in_sequence_do_not_leak_the_socket() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    // A real acceptor, continuously draining the queue: this test needs many
    // successful connects, so nothing may be left unaccepted.
    let acceptor = tokio::spawn(async move {
        while let Ok((s, _)) = listener.accept().await {
            drop(s);
        }
    });

    #[cfg(target_os = "linux")]
    assert_process_is_quiescent().await;

    #[cfg(target_os = "linux")]
    let before = open_fd_count();

    const PROBES: usize = 300;
    // Runs on every platform, Linux or not: `PROBES` sequential probes must
    // neither hang nor error out. Only the descriptor arithmetic is
    // Linux-gated.
    for _ in 0..PROBES {
        let out = probe_connect(addr.ip(), addr.port(), Duration::from_secs(2)).await;
        assert_eq!(out, ConnectOutcome::Open);
    }

    #[cfg(target_os = "linux")]
    {
        let after = open_fd_count();
        // Slack for the acceptor task and the runtime's own descriptors --
        // but PROBES leaked client sockets would show up as hundreds more,
        // not a handful.
        assert!(
            after.saturating_sub(before) < 20,
            "fd count grew from {before} to {after} after {PROBES} probes -- probe_connect is \
             not closing its socket promptly"
        );
    }

    acceptor.abort();
}
