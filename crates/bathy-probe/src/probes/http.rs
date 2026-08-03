//! `http-get-v1`: a plain HTTP/1.1 `GET /` sent over the raw socket.
//!
//! source: RFC 9112 §3 ("Request Line") and §3.2 ("Request Target") for
//! the request-line shape; RFC 9110 §7.2 ("Host and :authority") for the
//! `Host:` header field itself -- corrected here from an earlier version
//! of this comment that mis-cited RFC 9112 §3.2 for `Host:`, which is
//! actually about request-target forms (origin-form, absolute-form, etc.),
//! not the `Host` header; RFC 9112 §9.6/RFC 9110 §7.6.1 for
//! `Connection: close` -- also corrected from an earlier `§9.5`; RFC 9110
//! §10.1.5 for `User-Agent` being a free-form product token (so
//! `bathy/<version> (+<url>)` is a conformant value, not a spoof of any
//! other client). Corroborated against a real server:
//! `docker.io/library/nginx:1.27-alpine`
//! (digest `sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10`),
//! which replied to exactly the request this probe builds with
//! `HTTP/1.1 200 OK\r\nServer: nginx/1.27.5\r\n...\r\n\r\n<body>` -- see
//! this task's report for the full captured bytes.
//!
//! `Connection: close` also means a real server closes the connection once
//! it has sent its reply, so (unlike most of this crate's other
//! send-first-then-read probes) the happy path here does not have to wait
//! out the full deadline: `read_bounded` sees a clean EOF instead.

use async_trait::async_trait;
use bathy_types::ProbeCapture;

use crate::framework::{Probe, ProbeError, ProbeIo, ProbeKind};

/// Identifies bathy's traffic to whoever receives it (AC-4.5): an operator
/// who notices this `User-Agent` can find out what it is and why in one
/// search. There is no anonymous or evasive mode in v0.1 -- see
/// `SECURITY.md` (M7).
pub const USER_AGENT: &str = concat!(
    "bathy/",
    env!("CARGO_PKG_VERSION"),
    " (+https://github.com/russell0/bathy)"
);

pub struct HttpGetProbe;

#[async_trait]
impl Probe for HttpGetProbe {
    fn id(&self) -> &'static str {
        "http-get-v1"
    }
    fn kind(&self) -> ProbeKind {
        ProbeKind::SendFirst
    }
    fn affinity(&self, port: u16) -> u8 {
        match port {
            80 | 8080 | 8000 | 8008 => 100,
            443 | 8443 => 40, // TLS wraps it; try TLS first
            _ => 55,
        }
    }
    async fn execute(&self, io: &mut ProbeIo) -> Result<ProbeCapture, ProbeError> {
        let request = format!(
            "GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {USER_AGENT}\r\n\
             Accept: */*\r\nConnection: close\r\n\r\n",
            host = io.peer_host_header()
        )
        .into_bytes();
        let start = std::time::Instant::now();
        io.write_all(&request).await?;
        let (response, truncated) = io.read_bounded().await?;
        if response.is_empty() {
            return Err(ProbeError::EmptyResponse);
        }
        Ok(super::finish_capture(
            self.id(),
            io,
            Some(request),
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
    async fn http_probe_sends_a_get_and_captures_the_status_line_and_headers() {
        let port = stub(
            b"HTTP/1.1 200 OK\r\nServer: nginx/1.26.0\r\n\r\n<html>",
            true,
        )
        .await;
        let cap = run_probe(&HttpGetProbe, port).await.unwrap();
        assert_eq!(cap.probe_id, "http-get-v1");
        let req = String::from_utf8(cap.request.clone().unwrap()).unwrap();
        assert!(req.starts_with("GET / HTTP/1.1\r\n"));
        assert!(req.contains("Host: "));
        assert!(req.contains("Connection: close"));
        assert!(cap.response.starts_with(b"HTTP/1.1 200 OK"));
    }

    #[tokio::test]
    async fn http_probe_identifies_itself_in_the_user_agent() {
        let port = stub(b"HTTP/1.1 200 OK\r\n\r\n", true).await;
        let cap = run_probe(&HttpGetProbe, port).await.unwrap();
        let req = String::from_utf8(cap.request.unwrap()).unwrap();
        assert!(
            req.contains("User-Agent: bathy/"),
            "scanners must be identifiable to the operators they contact"
        );
    }

    // --- Beyond the brief: hostile peer (AC-4.7, AC-4.8) ---

    #[tokio::test]
    async fn http_probe_against_a_flood_stops_at_the_cap() {
        let port = stub_flood().await;
        let cap = run_probe(&HttpGetProbe, port).await.unwrap();
        assert!(cap.truncated);
        assert!(cap.response.len() <= ProbeIo::DEFAULT_READ_CAP);
    }

    #[tokio::test]
    async fn http_probe_against_a_silent_peer_times_out_rather_than_hangs() {
        let port = stub_silent().await;
        let start = std::time::Instant::now();
        let r = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            run_probe(&HttpGetProbe, port),
        )
        .await
        .expect("hung past a generous outer bound");
        assert!(matches!(r, Err(ProbeError::EmptyResponse)));
        assert!(start.elapsed() < std::time::Duration::from_secs(1));
    }

    #[tokio::test]
    async fn http_probe_against_an_immediately_closed_socket_errors() {
        let port = stub(b"", false).await; // stub closes right after (not) writing
        let r = run_probe(&HttpGetProbe, port).await;
        assert!(matches!(r, Err(ProbeError::EmptyResponse)));
    }

    // --- Beyond the brief: AC-4.9 determinism ---

    #[tokio::test]
    async fn http_probe_request_bytes_are_identical_across_two_connections_to_the_same_peer() {
        let port = stub_twice(b"HTTP/1.1 200 OK\r\n\r\n").await;
        let cap1 = run_probe(&HttpGetProbe, port).await.unwrap();
        let cap2 = run_probe(&HttpGetProbe, port).await.unwrap();
        assert_eq!(
            cap1.request, cap2.request,
            "AC-4.9: no randomness, timestamp, or nonce in the request bytes"
        );
    }

    // --- Beyond the brief: metadata correctness ---

    #[tokio::test]
    async fn http_probe_capture_carries_transport_and_port() {
        let port = stub(b"HTTP/1.1 200 OK\r\n\r\n", true).await;
        let cap = run_probe(&HttpGetProbe, port).await.unwrap();
        assert_eq!(cap.transport, bathy_types::Transport::Tcp);
        assert_eq!(cap.port, port);
    }
}
