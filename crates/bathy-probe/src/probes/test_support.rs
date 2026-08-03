//! Shared test doubles for the eight probe test suites: a stub TCP server
//! that replays a fixed script (matching the shape sketched in the M4 Task
//! 2 brief's own `Step 1`), a flooding stub for the hostile-peer cap tests,
//! and a `run_probe` helper that wires a [`Probe`] up to a real loopback
//! socket. Living in one place so eight files don't each reinvent it.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use crate::framework::{Probe, ProbeError, ProbeIo};
use bathy_types::ProbeCapture;

/// Short but generous: real loopback round-trips complete in well under a
/// millisecond, so this only ever gets fully consumed by the tests that
/// deliberately want it to (a silent peer, a dribbling peer) -- see each
/// such test's own comment.
pub const TEST_DEADLINE: Duration = Duration::from_millis(300);

/// Spawns a one-shot server on an ephemeral loopback port that replays
/// `script` to whatever connects.
///
/// `expect_request` mirrors the two `ProbeKind`s: `true` (send-first --
/// HTTP, TLS, DNS, Postgres, Redis) drains one read from the client before
/// writing `script`, matching a server that would not have anything to say
/// until the client speaks; `false` (listen-first -- SSH, MySQL, and SMTP's
/// initial greeting) writes `script` immediately without waiting on a read
/// at all, so a probe that (incorrectly) wrote first would be writing into
/// a socket nothing is yet draining.
///
/// After writing `script`, the stub drains (and discards) anything further
/// the client sends for a short grace window -- long enough for a
/// two-phase probe like SMTP's post-greeting `EHLO` to complete its write
/// without seeing a reset -- and then closes. This is what keeps every
/// test in this crate fast: a real, well-behaved server for most of these
/// protocols keeps the connection open indefinitely rather than closing it
/// (confirmed against real containers -- see this task's report), which
/// would otherwise force every happy-path test to wait out a full
/// deadline. `stub` intentionally does not reproduce that "stays open"
/// realism; see each probe module's own doc comment for the real-world
/// timing consequence this implies for `execute` itself.
pub async fn stub(script: &'static [u8], expect_request: bool) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let Ok((mut sock, _)) = listener.accept().await else {
            return;
        };
        if expect_request {
            let mut buf = [0u8; 4096];
            let _ = tokio::time::timeout(Duration::from_millis(500), sock.read(&mut buf)).await;
        }
        let _ = sock.write_all(script).await;
        let mut buf = [0u8; 4096];
        let _ = tokio::time::timeout(Duration::from_millis(150), sock.read(&mut buf)).await;
    });
    port
}

/// Like [`stub`], but accepts exactly two connections on the same fixed
/// port in sequence, replaying `script` to each. Exists to prove
/// request-byte determinism (AC-4.9) for a probe (HTTP) whose request
/// legitimately varies with the peer address it dials -- comparing two
/// executions against the literal same address is what isolates "did this
/// probe inject any randomness/timestamp/nonce" from "the Host header
/// reflects who we actually dialed", which a literal-bytes comparison
/// (as used for the other seven probes, all of which are peer-independent)
/// cannot do on its own.
pub async fn stub_twice(script: &'static [u8]) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        for _ in 0..2 {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let mut buf = [0u8; 4096];
            let _ = tokio::time::timeout(Duration::from_millis(500), sock.read(&mut buf)).await;
            let _ = sock.write_all(script).await;
            let _ = tokio::time::timeout(Duration::from_millis(100), sock.read(&mut buf)).await;
        }
    });
    port
}

/// Spawns a server that floods `0x41` bytes forever and never reads
/// anything, for the AC-4.7 cap-truncation tests. Mirrors the brief's own
/// `stub_flood` sketch.
pub async fn stub_flood() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let Ok((mut sock, _)) = listener.accept().await else {
            return;
        };
        let chunk = [0x41u8; 4096];
        loop {
            if sock.write_all(&chunk).await.is_err() {
                break;
            }
        }
    });
    port
}

/// Spawns a server that sends one byte every `interval`, forever, and
/// never reads anything. For the dribbling-peer case named explicitly in
/// this task's dispatch: a peer that keeps every individual read
/// succeeding (defeating a naive per-read timeout) while never actually
/// finishing.
pub async fn stub_dribble(byte: u8, interval: Duration) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let Ok((mut sock, _)) = listener.accept().await else {
            return;
        };
        loop {
            if sock.write_all(&[byte]).await.is_err() {
                break;
            }
            tokio::time::sleep(interval).await;
        }
    });
    port
}

/// Spawns a server that accepts and then does nothing at all -- neither
/// writing, reading, nor closing -- until the test itself ends and the
/// listener (and the accepted socket, held inside the spawned task) is
/// dropped. For the AC-4.8 silent-peer tests where a probe execution must
/// still return (as an error or an empty-but-not-hung capture) once its
/// own deadline elapses.
pub async fn stub_silent() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        if let Ok((sock, _)) = listener.accept().await {
            // Hold the connection open and silent until the test process
            // itself tears it down; there is deliberately nothing else to
            // do here.
            tokio::time::sleep(Duration::from_secs(30)).await;
            drop(sock);
        }
    });
    port
}

/// Connects to `port` on loopback and runs `probe` against it with
/// [`TEST_DEADLINE`].
pub async fn run_probe(probe: &dyn Probe, port: u16) -> Result<ProbeCapture, ProbeError> {
    let stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect to stub server");
    let mut io = ProbeIo::new(stream, port, TEST_DEADLINE);
    probe.execute(&mut io).await
}

/// Like [`run_probe`], with an explicit deadline for tests that need to
/// control timing precisely (e.g. the dribbling-peer test).
pub async fn run_probe_with_deadline(
    probe: &dyn Probe,
    port: u16,
    deadline: Duration,
) -> Result<ProbeCapture, ProbeError> {
    let stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect to stub server");
    let mut io = ProbeIo::new(stream, port, deadline);
    probe.execute(&mut io).await
}
