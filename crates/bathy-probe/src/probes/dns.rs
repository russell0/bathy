//! `dns-version-bind-v1`: a `version.bind`/TXT/CHAOS query sent over TCP.
//!
//! source: RFC 1035 §4.1.1 (12-byte header: ID, flags, QDCOUNT/ANCOUNT/
//! NSCOUNT/ARCOUNT), §4.1.2 (question section: length-prefixed labels
//! terminated by a zero-length root label, then QTYPE, then QCLASS), and
//! §3.2.4/§3.2.5 for the `TXT` (type 16) and `CH`/Chaos (class 3) values;
//! RFC 1035 §4.2.2 for DNS-over-TCP's mandatory 2-byte big-endian length
//! prefix. Querying `version.bind`/TXT/CH to learn a nameserver's software
//! version is a convention documented by BIND's own manual
//! (<https://bind9.readthedocs.io/en/latest/reference.html>, "Built-in
//! Server Information Zones"), not anything specific to a scanning tool.
//! Corroborated against a real server:
//! `docker.io/internetsystemsconsortium/bind9:9.18`
//! (digest `sha256:1ffb29c718ee2540c5643c1e8166629a07bbd505f99107baae535e9f86eb7eef`),
//! which replied to exactly the query bytes this probe builds with a TXT
//! record containing `9.18.50` under the same transaction id echoed back
//! -- see this task's report for the full hex capture.
//!
//! The transaction id is fixed at `0x5344` rather than drawn from an RNG
//! (AC-4.9): Task 3's replay corpus needs every captured request to be
//! byte-for-byte reproducible, and the id has no security role here --
//! this probe never resolves a name, follows a referral, or trusts a
//! reply against anything; it only records the raw bytes that came back.

use async_trait::async_trait;
use bathy_types::ProbeCapture;

use crate::framework::{Probe, ProbeError, ProbeIo, ProbeKind};

/// Fixed transaction id -- see this module's doc comment.
const TRANSACTION_ID: u16 = 0x5344;

/// Builds the `version.bind`/TXT/CHAOS query, TCP-framed with its 2-byte
/// length prefix. Pure and fixed: identical bytes on every call (AC-4.9).
fn build_query() -> Vec<u8> {
    let mut msg = Vec::with_capacity(30);
    msg.extend_from_slice(&TRANSACTION_ID.to_be_bytes());
    msg.extend_from_slice(&0x0000u16.to_be_bytes()); // flags: standard query, RD=0
    msg.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
    msg.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    msg.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    msg.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    for label in ["version", "bind"] {
        msg.push(label.len() as u8);
        msg.extend_from_slice(label.as_bytes());
    }
    msg.push(0); // root label
    msg.extend_from_slice(&16u16.to_be_bytes()); // QTYPE = TXT
    msg.extend_from_slice(&3u16.to_be_bytes()); // QCLASS = CH (Chaos)

    let mut framed = Vec::with_capacity(2 + msg.len());
    framed.extend_from_slice(&(msg.len() as u16).to_be_bytes());
    framed.extend_from_slice(&msg);
    framed
}

pub struct DnsVersionBindProbe;

#[async_trait]
impl Probe for DnsVersionBindProbe {
    fn id(&self) -> &'static str {
        "dns-version-bind-v1"
    }
    fn kind(&self) -> ProbeKind {
        ProbeKind::SendFirst
    }
    fn affinity(&self, port: u16) -> u8 {
        if port == 53 { 100 } else { 5 }
    }
    async fn execute(&self, io: &mut ProbeIo) -> Result<ProbeCapture, ProbeError> {
        let request = build_query();
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

    // A real reply captured from `internetsystemsconsortium/bind9:9.18`
    // (see this module's `source:` note) to exactly this probe's own
    // query: transaction id `0x5344` echoed, one answer, a TXT record
    // reading `9.18.50`. Used as the stub script below so this crate's own
    // tests replay real bytes rather than an invented fixture.
    const BIND_REPLY_HEX: &str = "00405344840000010001000100000776657273696f6e0462696e6400001000\
                                   03c00c0010000300000000000807392e31382e3530c00c00020003000000000\
                                   002c00c";

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn build_query_matches_the_captured_real_bind_request() {
        // The exact bytes this probe sent to the real bind9 container that
        // produced `BIND_REPLY_HEX` (captured alongside it -- see this
        // task's report), pinned here so a future edit that changes the
        // wire format is caught immediately, not just by a live container.
        let expected: Vec<u8> = [
            0x00, 0x1e, // TCP length prefix = 30
            0x53, 0x44, // transaction id 0x5344
            0x00, 0x00, // flags
            0x00, 0x01, // QDCOUNT
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // AN/NS/ARCOUNT
            7, b'v', b'e', b'r', b's', b'i', b'o', b'n', 4, b'b', b'i', b'n', b'd', 0, // root
            0x00, 0x10, // QTYPE TXT
            0x00, 0x03, // QCLASS CH
        ]
        .to_vec();
        assert_eq!(build_query(), expected);
    }

    #[tokio::test]
    async fn dns_probe_sends_the_fixed_transaction_id_and_captures_a_real_bind_reply() {
        let script: &'static [u8] = Box::leak(hex_to_bytes(BIND_REPLY_HEX).into_boxed_slice());
        let port = stub(script, true).await;
        let cap = run_probe(&DnsVersionBindProbe, port).await.unwrap();
        let request = cap.request.unwrap();
        assert_eq!(&request[2..4], &[0x53, 0x44], "fixed transaction id 0x5344");
        assert_eq!(cap.response, hex_to_bytes(BIND_REPLY_HEX));
        // The reply echoes the same transaction id back, at the same
        // offset, per RFC 1035 -- confirming this is a real, matched
        // reply, not coincidental bytes.
        assert_eq!(&cap.response[2..4], &[0x53, 0x44]);
    }

    #[tokio::test]
    async fn dns_probe_request_bytes_are_fixed_across_two_runs() {
        let port_a = stub(b"", true).await;
        let port_b = stub(b"", true).await;
        // Two independent stub servers -- `stub`'s server side never sends
        // anything back here, so both calls error, but `build_query`'s
        // determinism (no clock, no RNG) is what this test actually
        // pins: it is a pure function, asserted directly.
        let _ = (port_a, port_b);
        assert_eq!(build_query(), build_query());
    }

    // --- Beyond the brief: hostile peer (AC-4.7, AC-4.8) ---

    #[tokio::test]
    async fn dns_probe_against_a_flood_stops_at_the_cap() {
        let port = stub_flood().await;
        let cap = run_probe(&DnsVersionBindProbe, port).await.unwrap();
        assert!(cap.truncated);
        assert!(cap.response.len() <= ProbeIo::DEFAULT_READ_CAP);
    }

    #[tokio::test]
    async fn dns_probe_against_a_silent_peer_errors_rather_than_hangs() {
        let port = stub_silent().await;
        let r = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            run_probe(&DnsVersionBindProbe, port),
        )
        .await
        .expect("hung past a generous outer bound");
        assert!(matches!(r, Err(ProbeError::EmptyResponse)));
    }
}
