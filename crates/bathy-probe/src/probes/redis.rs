//! `redis-ping-v1`: a RESP-encoded `PING` command.
//!
//! source: Redis's own protocol specification, "RESP protocol
//! description" (<https://redis.io/docs/latest/develop/reference/protocol-spec/>):
//! a command is sent as a RESP array of bulk strings, `*<argc>\r\n`
//! followed by `$<len>\r\n<bytes>\r\n` per argument -- so `PING` with no
//! arguments is `*1\r\n$4\r\nPING\r\n`. Corroborated against a real server:
//! `docker.io/library/redis:7-alpine`
//! (digest `sha256:e7723ff73d963f5cc6d9c4643ea3d989527a402a319239054e9472a7fb9219a2`),
//! which replied `+PONG\r\n` to exactly these bytes -- see this task's
//! report.

use async_trait::async_trait;
use bathy_types::ProbeCapture;

use crate::framework::{Probe, ProbeError, ProbeIo, ProbeKind};

/// Fixed RESP encoding of `PING` -- see this module's `source:` note.
const PING: &[u8] = b"*1\r\n$4\r\nPING\r\n";

pub struct RedisPingProbe;

#[async_trait]
impl Probe for RedisPingProbe {
    fn id(&self) -> &'static str {
        "redis-ping-v1"
    }
    fn kind(&self) -> ProbeKind {
        ProbeKind::SendFirst
    }
    fn affinity(&self, port: u16) -> u8 {
        if port == 6379 { 100 } else { 5 }
    }
    async fn execute(&self, io: &mut ProbeIo) -> Result<ProbeCapture, ProbeError> {
        let request = PING.to_vec();
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
    async fn redis_probe_sends_a_resp_ping() {
        let port = stub(b"+PONG\r\n", true).await;
        let cap = run_probe(&RedisPingProbe, port).await.unwrap();
        assert_eq!(cap.request.unwrap(), b"*1\r\n$4\r\nPING\r\n".to_vec());
        assert_eq!(cap.response, b"+PONG\r\n".to_vec());
    }

    // --- Beyond the brief: AC-4.9 determinism ---

    #[tokio::test]
    async fn redis_probe_request_bytes_are_fixed_across_two_connections() {
        let port_a = stub(b"+PONG\r\n", true).await;
        let cap_a = run_probe(&RedisPingProbe, port_a).await.unwrap();
        let port_b = stub(b"+PONG\r\n", true).await;
        let cap_b = run_probe(&RedisPingProbe, port_b).await.unwrap();
        assert_eq!(cap_a.request, cap_b.request);
    }

    // --- Beyond the brief: hostile peer (AC-4.7, AC-4.8) ---

    #[tokio::test]
    async fn redis_probe_against_a_flood_stops_at_the_cap() {
        let port = stub_flood().await;
        let cap = run_probe(&RedisPingProbe, port).await.unwrap();
        assert!(cap.truncated);
        assert!(cap.response.len() <= ProbeIo::DEFAULT_READ_CAP);
    }

    #[tokio::test]
    async fn redis_probe_against_a_silent_peer_errors_rather_than_hangs() {
        let port = stub_silent().await;
        let r = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            run_probe(&RedisPingProbe, port),
        )
        .await
        .expect("hung past a generous outer bound");
        assert!(matches!(r, Err(ProbeError::EmptyResponse)));
    }

    #[tokio::test]
    async fn redis_probe_against_an_immediately_closed_socket_errors() {
        let port = stub(b"", false).await;
        let r = run_probe(&RedisPingProbe, port).await;
        assert!(matches!(r, Err(ProbeError::EmptyResponse)));
    }
}
