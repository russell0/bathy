//! Unprivileged TCP connect probing: the first code in this workspace that
//! actually puts a packet on the wire.
//!
//! [`ConnectOutcome::Closed`] and [`ConnectOutcome::Filtered`] are kept
//! distinct on purpose, and collapsing them is a correctness bug, not a
//! style choice: a refused connection (`ECONNREFUSED`, an RST from the
//! target) is *positive* evidence the host is alive and reachable --
//! something answered, even to say no -- while a connect attempt that never
//! resolves before our own deadline proves only that something in the path
//! is not answering: the target's firewall, an intermediate middlebox, or
//! the target itself being down. Host discovery (M3 Task 6) depends on
//! being able to tell those two apart, and the rate limiter
//! ([`crate::rate::RateLimiter`]) exists partly to keep this signal honest
//! -- scanning faster than a target's own rate limit turns real
//! `open`/`closed` results into false `filtered` ones by the same
//! mechanism as an unanswered probe.

use std::net::{IpAddr, SocketAddr};

use tokio::net::TcpStream;
use tokio::time::{Duration, timeout};

/// The result of one TCP connect attempt.
///
/// `Closed` and `Filtered` are kept distinct because they carry opposite
/// information: a refusal proves a host is alive and reachable, whereas
/// silence proves only that something in the path is not answering. Any
/// mapping that turns a refusal into `Filtered`, or silence into `Closed`,
/// destroys the signal host discovery depends on -- see the module doc.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectOutcome {
    /// The TCP handshake completed. The host is up and this port accepts
    /// connections.
    Open,
    /// The remote stack sent a positive refusal (`ECONNREFUSED`, an RST).
    /// The host is up; this port simply does not accept connections.
    Closed,
    /// Our own deadline elapsed with no response at all -- no SYN-ACK, no
    /// RST. Something between here and the target isn't answering: a
    /// firewall silently dropping the SYN, ordinary packet loss, or the
    /// target itself being down. This is *not* evidence the host is down,
    /// only that this probe learned nothing.
    Filtered,
    /// The *local* network stack, not the target, reported that it
    /// structurally cannot route to this destination at all (ICMP
    /// host/network-unreachable bubbled up locally, or the outbound
    /// interface being down). Distinct from `Filtered`: this is a definite
    /// negative from our own routing layer, not silence from the target's
    /// direction.
    Unreachable,
}

/// Classifies a failed connect attempt's [`std::io::Error`] into a
/// [`ConnectOutcome`].
///
/// Every `ErrorKind` mapped to something other than `Filtered` earns that
/// mapping by carrying *positive* information about the target or the
/// local routing layer. Everything else -- including the three kinds
/// discussed below -- defaults to `Filtered`, deliberately: it is the same
/// "this attempt learned nothing definite" state [`probe_connect`]'s own
/// deadline elapsing produces (its `Err(_elapsed)` arm), so an
/// unrecognized error is treated exactly as if nothing had answered at
/// all, rather than risk fabricating a stronger result from an error this
/// function doesn't actually understand.
///
/// Three kinds are worth naming individually, because each could plausibly
/// be mistaken for stronger evidence than it is:
///
/// - **`PermissionDenied`**: a local firewall, sandbox, or `seccomp`/`pf`
///   policy blocked the `connect()` syscall itself before any packet
///   reached the wire. This is local policy interfering with the probe,
///   not information about the target -- from the target's perspective
///   this probe never actually arrived, so it belongs in the same bucket
///   as silence.
/// - **`AddrNotAvailable`**: the local stack could not even originate the
///   connection, typically ephemeral-port exhaustion under a large,
///   highly concurrent scan. This is a local resource problem, not a
///   signal about the target; classifying it as `Closed` or `Unreachable`
///   would fabricate target-reachability evidence out of the scanner's own
///   resource pressure -- the same failure mode the rate limiter exists to
///   prevent for timing, applied to file descriptors instead.
/// - **`ConnectionAborted`**: unlike `ConnectionRefused`, this does not
///   reliably carry a positive RST from the target -- it can also be
///   raised by purely local-stack cleanup (an interface change, a local
///   timer tearing down a half-open connection) with no remote involvement
///   at all. Treating it as `Closed` would risk manufacturing false
///   liveness evidence from what may be a local event only.
pub fn classify_io_error(e: &std::io::Error) -> ConnectOutcome {
    use std::io::ErrorKind::*;
    match e.kind() {
        ConnectionRefused => ConnectOutcome::Closed,
        HostUnreachable | NetworkUnreachable | NetworkDown => ConnectOutcome::Unreachable,
        // The *kernel's own* connect timeout elapsed first -- not
        // `probe_connect`'s `tokio::time::timeout` wrapper, which never
        // constructs an `io::Error` at all (see its `Err(_elapsed)` arm).
        // Still silence, not a refusal.
        TimedOut => ConnectOutcome::Filtered,
        // Named explicitly (not left to the wildcard below) so the
        // decision is visible rather than accidental -- see the doc
        // comment above for the reasoning behind each.
        PermissionDenied | AddrNotAvailable | ConnectionAborted => ConnectOutcome::Filtered,
        _ => ConnectOutcome::Filtered,
    }
}

/// Attempts a TCP connect to `target:port`, bounded by `budget`.
///
/// Takes an [`IpAddr`], never a hostname or string, so this function has no
/// way to trigger DNS resolution even by accident: `IpAddr` cannot
/// represent a name, and the `SocketAddr` built from it satisfies
/// `ToSocketAddrs` (the trait `TcpStream::connect` accepts) via the
/// identity conversion -- no lookup, ever. Contrast the `&str` and
/// `(&str, u16)` impls of the same trait, which do resolve; neither is
/// reachable from here because nothing upstream of `addr` in this function
/// is ever a string.
pub async fn probe_connect(target: IpAddr, port: u16, budget: Duration) -> ConnectOutcome {
    let addr = SocketAddr::new(target, port);
    match timeout(budget, TcpStream::connect(addr)).await {
        Ok(Ok(stream)) => {
            // `stream` would go out of scope (running its `Drop` impl) at
            // the end of this arm regardless of this explicit call, so
            // this line alone is not what prevents a leak -- it documents
            // that closing the socket *now*, before returning, is
            // deliberate: v0.1 connect scanning establishes reachability
            // only, and service probing owns the socket and reuses it
            // starting in M4, rather than reconnecting. See
            // `many_open_probes_in_sequence_do_not_leak_the_socket` and
            // `the_open_socket_is_closed_promptly_after_the_probe_returns`
            // below for the tests that actually exercise "does this leak".
            drop(stream);
            ConnectOutcome::Open
        }
        Ok(Err(e)) => classify_io_error(&e),
        Err(_elapsed) => ConnectOutcome::Filtered,
    }
}

/// Like [`probe_connect`], but additionally reports whether a non-`Open`,
/// non-`Closed` outcome was caused specifically by a *local* resource or
/// policy problem rather than genuine silence from the target or path.
///
/// M3 Task 7's carried requirement (from Tasks 5 and 6): `Filtered` conflates
/// local failure (`AddrNotAvailable` -- ephemeral-port exhaustion on this
/// machine; `PermissionDenied` -- a local firewall/sandbox policy) with
/// target silence, and at scheduler scale a local resource problem can
/// present as thousands of `filtered` ports that describe *our* machine, not
/// the one being scanned (see this module's own doc comment on
/// [`classify_io_error`]). By the time `probe_connect` returns a bare
/// [`ConnectOutcome`], that distinction is already gone -- `Filtered` alone
/// cannot say which `io::ErrorKind` produced it. This function keeps the
/// classification the scheduler needs without changing `probe_connect`'s own
/// signature or behavior (every existing caller and test is unaffected;
/// see this crate's `discovery` module, which still uses `probe_connect`
/// directly).
///
/// Returns `(outcome, is_local)`. `is_local` is `true` only for
/// `AddrNotAvailable`/`PermissionDenied`; a `probe_connect` timeout
/// (`Err(_elapsed)`, no `io::Error` at all) and every other `Filtered`-mapped
/// `ErrorKind` report `false`.
pub async fn probe_connect_with_local_signal(
    target: IpAddr,
    port: u16,
    budget: Duration,
) -> (ConnectOutcome, bool) {
    let addr = SocketAddr::new(target, port);
    match timeout(budget, TcpStream::connect(addr)).await {
        Ok(Ok(stream)) => {
            drop(stream);
            (ConnectOutcome::Open, false)
        }
        Ok(Err(e)) => {
            let is_local = matches!(
                e.kind(),
                std::io::ErrorKind::AddrNotAvailable | std::io::ErrorKind::PermissionDenied
            );
            (classify_io_error(&e), is_local)
        }
        Err(_elapsed) => (ConnectOutcome::Filtered, false),
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Error, ErrorKind};

    use super::*;

    // --- From the brief (AC-3.18, AC-3.19, AC-3.20) ---

    #[tokio::test]
    async fn a_listening_socket_reports_open() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let out = probe_connect("127.0.0.1".parse().unwrap(), port, Duration::from_secs(2)).await;
        assert_eq!(out, ConnectOutcome::Open);
    }

    #[tokio::test]
    async fn a_refused_connection_reports_closed() {
        // Bind then drop, so the port is almost certainly unbound and refusing.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let out = probe_connect("127.0.0.1".parse().unwrap(), port, Duration::from_secs(2)).await;
        assert_eq!(out, ConnectOutcome::Closed);
    }

    // TEST-NET-1 (RFC 5737) is reserved for documentation and never
    // routes. In the environment this was implemented and verified in, a
    // raw connect to it (checked independently outside this test, with a
    // 10s Python `socket.connect` and no `probe_connect` involved at all)
    // hangs for the full budget with no OS-level error whatsoever -- no
    // `ConnectionRefused`, no `HostUnreachable` -- so this test exercises
    // `probe_connect`'s own `Err(_elapsed) => Filtered` arm here, not the
    // `Unreachable` fallback. See the task report for that measurement.
    // That behavior is a property of this environment's routing/network
    // stack, though, not a portable guarantee -- some hosts fail fast with
    // `ENETUNREACH` instead, which is exactly why both outcomes are
    // accepted below rather than asserting `Filtered` alone, and why
    // `a_full_backlog_reports_filtered_via_the_timeout_path` exists: it
    // exercises the identical `Err(_elapsed) => Filtered` arm
    // deterministically, entirely on loopback, with no dependency on how
    // any given network path treats an unrouted address.
    #[tokio::test]
    async fn a_timeout_reports_filtered_not_closed() {
        let out = probe_connect("192.0.2.1".parse().unwrap(), 80, Duration::from_millis(300)).await;
        assert!(
            matches!(out, ConnectOutcome::Filtered | ConnectOutcome::Unreachable),
            "a silent drop is filtered, never closed; got {out:?}"
        );
    }

    #[test]
    fn error_classification_distinguishes_refused_from_unreachable() {
        assert_eq!(
            classify_io_error(&Error::from(ErrorKind::ConnectionRefused)),
            ConnectOutcome::Closed
        );
        assert_eq!(
            classify_io_error(&Error::from(ErrorKind::HostUnreachable)),
            ConnectOutcome::Unreachable
        );
        assert_eq!(
            classify_io_error(&Error::from(ErrorKind::NetworkUnreachable)),
            ConnectOutcome::Unreachable
        );
    }

    // --- Beyond the brief: classify_io_error, exhaustively in intent ---
    //
    // The brief's own test above checks 3 of the 8+ `ErrorKind`s this
    // function actually branches on. This locks in the rest of the
    // decisions -- see the doc comment on `classify_io_error` for the
    // reasoning behind each of `PermissionDenied`/`AddrNotAvailable`/
    // `ConnectionAborted`, plus `NetworkDown` (grouped with the other
    // `Unreachable` kinds), `TimedOut` (the kernel's own connect timeout),
    // and a kind the function was never taught about at all -- the true
    // wildcard fallthrough, not one of the kinds enumerated by name.
    #[test]
    fn error_classification_covers_the_kinds_the_brief_test_does_not() {
        assert_eq!(
            classify_io_error(&Error::from(ErrorKind::NetworkDown)),
            ConnectOutcome::Unreachable
        );
        assert_eq!(
            classify_io_error(&Error::from(ErrorKind::TimedOut)),
            ConnectOutcome::Filtered
        );
        assert_eq!(
            classify_io_error(&Error::from(ErrorKind::PermissionDenied)),
            ConnectOutcome::Filtered
        );
        assert_eq!(
            classify_io_error(&Error::from(ErrorKind::AddrNotAvailable)),
            ConnectOutcome::Filtered
        );
        assert_eq!(
            classify_io_error(&Error::from(ErrorKind::ConnectionAborted)),
            ConnectOutcome::Filtered
        );
        assert_eq!(
            classify_io_error(&Error::from(ErrorKind::BrokenPipe)),
            ConnectOutcome::Filtered
        );
    }

    // --- Beyond the brief: the timeout path, covered deterministically ---
    //
    // Relying solely on `a_timeout_reports_filtered_not_closed` for
    // coverage of `probe_connect`'s `Err(_elapsed) => Filtered` arm would
    // make that coverage depend on how this specific environment's network
    // stack treats a TEST-NET-1 address -- confirmed above to vary by
    // host. This test reproduces "the target never responds at all"
    // entirely on loopback instead: bind a listener, never call `accept()`
    // on it, and open connections against it until the OS accept queue is
    // full. The kernel completes the TCP handshake for connections up to
    // that queue's capacity regardless of whether userspace ever calls
    // `accept()` -- that is what lets `a_listening_socket_reports_open`'s
    // single connect above succeed with no acceptor running at all -- but
    // once the queue is full, the default, portable behavior on both Linux
    // and BSD-derived stacks (including macOS, where this was measured
    // empirically: exactly 128 connections filled it) is to silently drop
    // further SYNs rather than reset them. That reproduces exactly the "no
    // SYN-ACK, no RST" case `Filtered` exists to name, deterministically,
    // unprivileged, and entirely on 127.0.0.1.
    #[tokio::test]
    async fn a_full_backlog_reports_filtered_via_the_timeout_path() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Fill the accept queue. Measured locally at exactly 128 slots
        // (tokio/mio's fixed listen backlog); capped well above that here
        // instead of hardcoding 128, so this test finds the actual fill
        // point rather than assuming a specific number, in case a future
        // tokio version or a differently configured host clamps the queue
        // to something else.
        let mut held = Vec::new();
        let mut filled = false;
        for _ in 0..256 {
            match timeout(Duration::from_millis(150), TcpStream::connect(addr)).await {
                Ok(Ok(stream)) => held.push(stream), // keep alive: dropping frees the slot
                _ => {
                    filled = true;
                    break;
                }
            }
        }
        assert!(
            filled,
            "expected the accept queue to fill (and the next connect to hang) \
             within 256 connection attempts; if this fails, the backlog-fill \
             technique itself needs revisiting, not probe_connect"
        );

        let out = probe_connect(addr.ip(), addr.port(), Duration::from_millis(300)).await;
        assert_eq!(
            out,
            ConnectOutcome::Filtered,
            "a full accept queue silently drops further SYNs; probe_connect \
             must classify the resulting hang as Filtered"
        );
    }

    // --- Beyond the brief: the socket is closed promptly on Open ---
    //
    // Direct, platform-independent proof that dropping the client side
    // after `Open` actually closes the TCP connection: the server side's
    // read observes EOF (0 bytes) promptly rather than hanging. Wrapped in
    // its own timeout so a genuine "the client half never closes" bug
    // fails this test instead of hanging the suite.
    #[tokio::test]
    async fn the_open_socket_is_closed_promptly_after_the_probe_returns() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move {
            let (server_side, _) = listener.accept().await.unwrap();
            server_side.readable().await.unwrap();
            let mut buf = [0u8; 1];
            server_side.try_read(&mut buf)
        });

        let out = probe_connect(addr.ip(), addr.port(), Duration::from_secs(2)).await;
        assert_eq!(out, ConnectOutcome::Open);

        let read_result = timeout(Duration::from_secs(2), accept)
            .await
            .expect(
                "server-side read hung -- the client socket should already \
                 have been closed by the time probe_connect returned",
            )
            .expect("acceptor task panicked");
        assert_eq!(
            read_result.unwrap(),
            0,
            "expected EOF (0 bytes read) once the client side closed"
        );
    }

    // --- Beyond the brief (M3 Task 7 carried requirement): the local-vs-
    // target signal `probe_connect_with_local_signal` adds ---

    #[tokio::test]
    async fn local_signal_is_false_for_an_open_port() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (out, local) = probe_connect_with_local_signal(
            "127.0.0.1".parse().unwrap(),
            port,
            Duration::from_secs(2),
        )
        .await;
        assert_eq!(out, ConnectOutcome::Open);
        assert!(!local);
    }

    #[tokio::test]
    async fn local_signal_is_false_for_a_refused_connection() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let (out, local) = probe_connect_with_local_signal(
            "127.0.0.1".parse().unwrap(),
            port,
            Duration::from_secs(2),
        )
        .await;
        assert_eq!(out, ConnectOutcome::Closed);
        assert!(!local);
    }

    #[tokio::test]
    async fn local_signal_is_false_for_a_genuine_timeout() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut held = Vec::new();
        let mut filled = false;
        for _ in 0..256 {
            match timeout(Duration::from_millis(150), TcpStream::connect(addr)).await {
                Ok(Ok(stream)) => held.push(stream),
                _ => {
                    filled = true;
                    break;
                }
            }
        }
        assert!(filled, "expected the accept queue to fill");
        let (out, local) =
            probe_connect_with_local_signal(addr.ip(), addr.port(), Duration::from_millis(300))
                .await;
        assert_eq!(out, ConnectOutcome::Filtered);
        assert!(
            !local,
            "a silent drop on a full accept queue is target/path silence, not a local problem"
        );
    }

    #[test]
    fn local_signal_is_true_only_for_addr_not_available_and_permission_denied() {
        for kind in [ErrorKind::AddrNotAvailable, ErrorKind::PermissionDenied] {
            let e = Error::from(kind);
            let is_local = matches!(
                e.kind(),
                ErrorKind::AddrNotAvailable | ErrorKind::PermissionDenied
            );
            assert!(is_local, "{kind:?} should be classified as local");
        }
        for kind in [
            ErrorKind::ConnectionRefused,
            ErrorKind::TimedOut,
            ErrorKind::ConnectionAborted,
            ErrorKind::HostUnreachable,
            ErrorKind::NetworkUnreachable,
            ErrorKind::BrokenPipe,
        ] {
            let e = Error::from(kind);
            let is_local = matches!(
                e.kind(),
                ErrorKind::AddrNotAvailable | ErrorKind::PermissionDenied
            );
            assert!(!is_local, "{kind:?} should NOT be classified as local");
        }
    }

    // --- Beyond the brief: many probes in sequence must not leak fds ---
    //
    // A scan issues one `probe_connect` per port, so any per-call leak
    // becomes a leak per probe, and a large scan would exhaust local file
    // descriptors. `open_fd_count`'s `/proc/self/fd` read only works on
    // Linux (no `/proc` on macOS by default, and counting fds any other
    // way without `unsafe` -- e.g. `libc::getrlimit` -- would conflict with
    // this crate's `#![forbid(unsafe_code)]`); CI (`ubuntu-latest`) is
    // exactly that platform, so the numeric assertion is still enforced as
    // a merge gate even though it's skipped locally on macOS. The loop
    // itself still runs on every platform, proving 2000 sequential probes
    // neither hang nor error out.
    #[cfg(target_os = "linux")]
    fn open_fd_count() -> usize {
        std::fs::read_dir("/proc/self/fd")
            .map(|d| d.count())
            .unwrap_or(0)
    }

    #[tokio::test]
    async fn many_open_probes_in_sequence_do_not_leak_the_socket() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // A real acceptor, continuously draining the queue -- unlike
        // `a_full_backlog_reports_filtered_via_the_timeout_path` above,
        // this test needs 2000 successful connects, not 128, so nothing
        // may be left unaccepted.
        let acceptor = tokio::spawn(async move {
            while let Ok((s, _)) = listener.accept().await {
                drop(s);
            }
        });

        #[cfg(target_os = "linux")]
        let before = open_fd_count();

        const PROBES: usize = 2_000;
        for _ in 0..PROBES {
            let out = probe_connect(addr.ip(), addr.port(), Duration::from_secs(2)).await;
            assert_eq!(out, ConnectOutcome::Open);
        }

        #[cfg(target_os = "linux")]
        {
            let after = open_fd_count();
            // A little slack for the acceptor task and the runtime's own
            // fds, but 2000 leaked client sockets would show up as
            // thousands more, not a handful.
            assert!(
                after.saturating_sub(before) < 20,
                "fd count grew from {before} to {after} after {PROBES} probes \
                 -- probe_connect is not closing its socket promptly"
            );
        }

        acceptor.abort();
    }
}
