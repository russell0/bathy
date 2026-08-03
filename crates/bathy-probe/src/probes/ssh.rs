//! `ssh-banner-v1`: reads the SSH identification string without sending
//! anything first.
//!
//! source: RFC 4253 §4.2 ("Protocol Version Exchange"): "When the
//! connection has been established, both sides MUST send an
//! identification string... The server MAY send other lines of data
//! before sending the version string." Nothing in the exchange requires
//! (or expects) the client to speak before the server's identification
//! string arrives, which is what lets this probe read the banner while
//! sending nothing at all (AC-4.6). Corroborated against a real server:
//! `docker.io/linuxserver/openssh-server:latest`
//! (digest `sha256:96b9a4d3b5106746d08d43a6911650d4d21f7d5c7f2ac9660e792bdb5e63157c`),
//! which sent `SSH-2.0-OpenSSH_10.3\r\n` immediately on connect, before
//! anything else touched the socket -- see this task's report.
//!
//! A real SSH server does not close the connection after sending its
//! banner (it waits for the client's own identification string next), so
//! against a real peer `read_bounded` will typically consume this probe's
//! whole deadline to be sure nothing more is coming, even though the
//! banner itself (one CRLF-terminated line) usually arrives in the very
//! first read. This is an accepted consequence of `ProbeIo` having no
//! protocol-specific framing (see this crate's top-level doc comment), the
//! same tradeoff already documented on [`ProbeIo::read_bounded`] itself,
//! not a defect introduced here.

use async_trait::async_trait;
use bathy_types::ProbeCapture;

use crate::framework::{Probe, ProbeError, ProbeIo, ProbeKind};

pub struct SshBannerProbe;

#[async_trait]
impl Probe for SshBannerProbe {
    fn id(&self) -> &'static str {
        "ssh-banner-v1"
    }
    fn kind(&self) -> ProbeKind {
        ProbeKind::ListenFirst
    }
    fn affinity(&self, port: u16) -> u8 {
        match port {
            22 | 2222 => 100,
            _ => 8,
        }
    }
    async fn execute(&self, io: &mut ProbeIo) -> Result<ProbeCapture, ProbeError> {
        let start = std::time::Instant::now();
        let (response, truncated) = io.read_bounded().await?;
        if response.is_empty() {
            return Err(ProbeError::EmptyResponse);
        }
        Ok(super::finish_capture(
            self.id(),
            io,
            None,
            start,
            response,
            truncated,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probes::test_support::*;

    // --- From the brief (Step 1) ---

    #[tokio::test]
    async fn ssh_probe_reads_the_banner_without_sending_first() {
        let port = stub(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n", false).await;
        let cap = run_probe(&SshBannerProbe, port).await.unwrap();
        assert!(
            cap.request.is_none(),
            "listen-first probes must not speak first"
        );
        assert!(cap.response.starts_with(b"SSH-2.0-"));
    }

    #[tokio::test]
    async fn a_probe_against_a_silent_socket_returns_empty_response_not_a_hang() {
        let port = stub(b"", false).await;
        let r = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            run_probe(&SshBannerProbe, port),
        )
        .await
        .expect("hung past a generous outer bound");
        assert!(matches!(r, Err(ProbeError::EmptyResponse) | Ok(_)));
    }

    #[tokio::test]
    async fn a_probe_against_a_flood_of_bytes_stops_at_the_cap() {
        let port = stub_flood().await;
        let cap = run_probe(&SshBannerProbe, port).await.unwrap();
        assert!(cap.truncated);
        assert!(cap.response.len() <= ProbeIo::DEFAULT_READ_CAP);
    }

    // --- Beyond the brief: AC-4.6 proven structurally, not just observed ---

    #[tokio::test]
    async fn ssh_probe_never_writes_to_the_socket_even_when_it_would_be_read() {
        // Drives the server side directly (rather than through `stub`) so
        // it can assert on the *absence* of a write, not just on
        // `capture.request` being `None`.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let (mut sock, _) = listener.accept().await.unwrap();
            sock.write_all(b"SSH-2.0-test\r\n").await.unwrap();
            let mut buf = [0u8; 1];
            let n = sock.read(&mut buf).await.unwrap_or(0);
            assert_eq!(n, 0, "a listen-first probe must never speak first");
        });

        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut io = ProbeIo::new(stream, addr.port(), TEST_DEADLINE);
        let cap = SshBannerProbe.execute(&mut io).await.unwrap();
        assert!(cap.request.is_none());
        assert_eq!(cap.response, b"SSH-2.0-test\r\n");

        drop(io); // close the client side so the server's read sees EOF
        server.await.unwrap();
    }

    #[tokio::test]
    async fn ssh_probe_against_a_dribbling_peer_is_bounded_by_the_deadline_not_the_dribble() {
        // Named explicitly in this task's dispatch: a peer that sends one
        // byte every few tens of milliseconds forever, so every
        // individual read succeeds and only the overall deadline (not a
        // naive per-read timeout) can end the call. `ProbeIo::read_bounded`
        // already proves this at the framework level (`framework.rs`'s
        // own `read_bounded_is_bounded_by_the_overall_deadline_against_a_
        // peer_that_dribbles_forever`); this test proves the probe built
        // on top of it inherits the guarantee rather than working around
        // it.
        let port = stub_dribble(0x41, std::time::Duration::from_millis(20)).await;
        const DEADLINE: std::time::Duration = std::time::Duration::from_millis(150);
        let start = std::time::Instant::now();
        let cap = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            run_probe_with_deadline(&SshBannerProbe, port, DEADLINE),
        )
        .await
        .expect("hung past a generous outer bound")
        .unwrap();
        let elapsed = start.elapsed();
        assert!(
            cap.truncated,
            "the peer was still sending when the deadline hit"
        );
        assert!(!cap.response.is_empty());
        assert!(elapsed >= DEADLINE);
        assert!(
            elapsed < DEADLINE + std::time::Duration::from_millis(500),
            "the deadline, not the dribble, must bound this; took {elapsed:?}"
        );
    }

    // --- Beyond the brief: immediate close (AC-4.8) ---

    #[tokio::test]
    async fn ssh_probe_against_an_immediately_closed_socket_errors() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (client, accepted) =
            tokio::join!(tokio::net::TcpStream::connect(addr), listener.accept());
        drop(accepted.unwrap()); // close before sending anything
        let mut io = ProbeIo::new(client.unwrap(), addr.port(), TEST_DEADLINE);
        let result = SshBannerProbe.execute(&mut io).await;
        assert!(matches!(result, Err(ProbeError::EmptyResponse)));
    }
}
