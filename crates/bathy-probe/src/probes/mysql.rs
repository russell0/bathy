//! `mysql-greeting-v1`: reads the server's initial handshake packet
//! without sending anything first.
//!
//! source: MySQL's own "Connection Phase" documentation
//! (<https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase.html>),
//! under "Initial Handshake": "The initial handshake starts with the
//! server sending the Protocol::Handshake packet." That server-speaks-
//! first shape is exactly what this probe relies on (AC-4.6) -- though the
//! same page states it is the ordinary case rather than a guarantee: a
//! server "may send a ERR packet and finish the handshake" instead, which
//! is one of the shapes this probe must capture without interpreting. The
//! packet's own field layout (`int<1> protocol version`, "Always 10",
//! immediately followed by `string<NUL> server version`) is on the
//! separate "Protocol::HandshakeV10" page
//! (<https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_packets_protocol_handshake_v10.html>),
//! which is what `bathy_interpret::rules`'s `mysql.handshake.v10` reads.
//!
//! (An earlier version of this comment quoted the Connection Phase page as
//! saying "the server sends a handshake packet as soon as the connection
//! is established". That sentence does not appear on the page in any form
//! -- the string "as soon as" does not occur on it at all -- and its
//! absolutism concealed the ERR-packet alternative the page does document.
//! It also cited the overview page for the field layout the overview page
//! does not contain, which is the same defect `rules.rs` already records
//! as fixed on its own side and which was never swept across the branch.
//! Found by the M4 whole-branch fix wave's citation sweep, not by the
//! review; it is the second fabricated quotation of the same species as
//! the SMTP one in IMPORTANT-3. The probe's wire behaviour -- it writes
//! nothing at all -- was and is correct.) Corroborated
//! against a real server: `docker.io/library/mysql:8.4`
//! (digest `sha256:b3b90af2a6552ae30c266fdb7d5dd55f3afb72404bb78d37fe8a23eb857fd3fb`),
//! which sent (hex) `4a0000000a382e342e3131...` -- a `HandshakeV10` packet
//! whose protocol-version byte is `0x0a` and whose null-terminated
//! server-version string reads `8.4.11` -- immediately on connect, before
//! this probe or anything else wrote a byte. See this task's report for
//! the full captured bytes.
//!
//! Real MySQL keeps the connection open after sending this packet (it
//! waits for the client's handshake response next), so -- like the SSH and
//! DNS probes in this crate -- the happy path here will typically consume
//! this probe's whole deadline against a real server, per
//! [`ProbeIo::read_bounded`]'s own documented tradeoff.

use async_trait::async_trait;
use bathy_types::ProbeCapture;

use crate::framework::{Probe, ProbeError, ProbeIo, ProbeKind};

pub struct MysqlGreetingProbe;

#[async_trait]
impl Probe for MysqlGreetingProbe {
    fn id(&self) -> &'static str {
        "mysql-greeting-v1"
    }
    fn kind(&self) -> ProbeKind {
        ProbeKind::ListenFirst
    }
    fn affinity(&self, port: u16) -> u8 {
        if port == 3306 { 100 } else { 5 }
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

    // The real handshake packet captured from `mysql:8.4` (see this
    // module's `source:` note), replayed here so this crate's own test
    // exercises real bytes rather than an invented fixture.
    const MYSQL_GREETING_HEX: &str = "4a0000000a382e342e3131000800000062215a7649740441\
                                       00ffffff0200ffdf1500000000000000000000441e1b514b\
                                       4e6e53084a5c270063616368696e675f736861325f706173\
                                       73776f726400";

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    #[tokio::test]
    async fn mysql_probe_reads_the_greeting_without_sending_first() {
        let script: &'static [u8] = Box::leak(hex_to_bytes(MYSQL_GREETING_HEX).into_boxed_slice());
        let port = stub(script, false).await;
        let cap = run_probe(&MysqlGreetingProbe, port).await.unwrap();
        assert!(
            cap.request.is_none(),
            "listen-first probes must not speak first"
        );
        assert_eq!(cap.response, hex_to_bytes(MYSQL_GREETING_HEX));
        // Byte 4 (0-indexed) of a HandshakeV10 packet is the protocol
        // version, always 0x0a -- a structural sanity check on the
        // fixture, not interpretation performed by the probe itself.
        assert_eq!(cap.response[4], 0x0a);
    }

    #[tokio::test]
    async fn mysql_probe_never_writes_to_the_socket() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let (mut sock, _) = listener.accept().await.unwrap();
            sock.write_all(b"\x07\x00\x00\x00\x0agreeting")
                .await
                .unwrap();
            let mut buf = [0u8; 1];
            let n = sock.read(&mut buf).await.unwrap_or(0);
            assert_eq!(n, 0, "a listen-first probe must never speak first");
        });
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut io = ProbeIo::new(stream, addr.port(), TEST_DEADLINE);
        let cap = MysqlGreetingProbe.execute(&mut io).await.unwrap();
        assert!(cap.request.is_none());
        drop(io);
        server.await.unwrap();
    }

    // --- Beyond the brief: hostile peer (AC-4.7, AC-4.8) ---

    #[tokio::test]
    async fn mysql_probe_against_a_flood_stops_at_the_cap() {
        let port = stub_flood().await;
        let cap = run_probe(&MysqlGreetingProbe, port).await.unwrap();
        assert!(cap.truncated);
        assert!(cap.response.len() <= ProbeIo::DEFAULT_READ_CAP);
    }

    #[tokio::test]
    async fn mysql_probe_against_a_silent_peer_errors_rather_than_hangs() {
        let port = stub_silent().await;
        let r = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            run_probe(&MysqlGreetingProbe, port),
        )
        .await
        .expect("hung past a generous outer bound");
        assert!(matches!(r, Err(ProbeError::EmptyResponse)));
    }

    #[tokio::test]
    async fn mysql_probe_against_an_immediately_closed_socket_errors() {
        let port = stub(b"", false).await;
        let r = run_probe(&MysqlGreetingProbe, port).await;
        assert!(matches!(r, Err(ProbeError::EmptyResponse)));
    }
}
