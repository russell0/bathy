//! `postgres-startup-v1`: sends an `SSLRequest` and captures the
//! single-byte `S`/`N` reply.
//!
//! source: PostgreSQL's own Frontend/Backend Protocol documentation,
//! "Message Formats" §`SSLRequest`
//! (<https://www.postgresql.org/docs/current/protocol-message-formats.html>):
//! an 8-byte message -- `Int32(8)` ("Length of message contents in bytes,
//! including self") followed by `Int32(80877103)`, the fixed SSL request
//! code, documented on that same page under `SSLRequest` itself: "The
//! value is chosen to contain 1234 in the most significant 16 bits, and
//! 5679 in the least significant 16 bits. (To avoid confusion, this code
//! must not be the same as any protocol version number.)" The server's
//! reply is documented separately, in "Message Flow" §54.2.10 ("SSL
//! Session Encryption",
//! <https://www.postgresql.org/docs/current/protocol-flow.html>): "The
//! server then responds with a single byte containing S or N, indicating
//! that it is willing or unwilling to perform SSL, respectively."
//!
//! (An earlier version of this comment attributed the request code's
//! rationale to a section named "Initiating the Protocol". No such section
//! exists in PostgreSQL's Frontend/Backend Protocol chapter -- the word
//! "Initiating" appears nowhere in it. The rationale is on the Message
//! Formats page under `SSLRequest`, as quoted above. M4 whole-branch fix
//! wave citation sweep.) Corroborated against a real server:
//! `docker.io/library/postgres:16-alpine`
//! (digest `sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777`,
//! run without SSL configured), which replied `N` to exactly the 8 bytes
//! this probe sends -- see this task's report.
//!
//! Real PostgreSQL keeps the connection open after this single byte
//! (waiting for either a TLS handshake or a plaintext startup packet next)
//! rather than closing it, so the reply's completeness can't be learned
//! from an EOF -- but the protocol documents the reply as a single byte
//! ("The server then responds with a single byte containing S or N"),
//! which is framing knowledge, not interpretation of what the byte *means*
//! (`S` vs `N`). §54.2.10 also directs frontends to read exactly that one
//! byte and treat anything queued behind it as suspect, which is why
//! `truncated` is reported honestly below rather than being drained:
//! "If additional bytes are available to read at this point, it likely
//! means that a man-in-the-middle is attempting to perform a
//! buffer-stuffing attack (CVE-2021-23222)."
//!
//! Not an unconditional guarantee, and this comment previously overstated
//! it as one (M4 whole-branch fix wave citation sweep): the same section
//! records that "the frontend should also be prepared to handle an
//! ErrorMessage response to SSLRequest from the server", which is longer
//! than one byte. This probe captures whatever arrived and leaves that
//! distinction entirely to `bathy-interpret`, which is the correct split
//! either way. [`ProbeIo::read_at_most`] exists precisely
//! for this: it returns as soon as that one byte has arrived instead of
//! waiting out the whole deadline the way a generic `read_bounded` call
//! would, while still reporting `truncated` honestly (see that method's
//! own doc comment) if a hostile peer had more than one byte queued up
//! behind the reply -- `postgres_probe_against_a_flood_stops_at_the_cap`
//! below asserts this directly, the same way every other probe's own
//! flood test does.

use async_trait::async_trait;
use bathy_types::ProbeCapture;

use crate::framework::{Probe, ProbeError, ProbeIo, ProbeKind};

/// `SSLRequest`: length = 8 (u32 BE), request code = 80877103 (u32 BE).
/// Fixed by the protocol itself -- see this module's `source:` note.
const SSL_REQUEST: [u8; 8] = [0x00, 0x00, 0x00, 0x08, 0x04, 0xD2, 0x16, 0x2F];

pub struct PostgresStartupProbe;

#[async_trait]
impl Probe for PostgresStartupProbe {
    fn id(&self) -> &'static str {
        "postgres-startup-v1"
    }
    fn kind(&self) -> ProbeKind {
        ProbeKind::SendFirst
    }
    fn affinity(&self, port: u16) -> u8 {
        if port == 5432 { 100 } else { 5 }
    }
    async fn execute(&self, io: &mut ProbeIo) -> Result<ProbeCapture, ProbeError> {
        let request = SSL_REQUEST.to_vec();
        let start = std::time::Instant::now();
        io.write_all(&request).await?;
        let (response, truncated) = io.read_at_most(1).await?;
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

    #[tokio::test]
    async fn postgres_probe_sends_the_fixed_sslrequest_bytes() {
        let port = stub(b"N", true).await;
        let cap = run_probe(&PostgresStartupProbe, port).await.unwrap();
        assert_eq!(
            cap.request.unwrap(),
            vec![0x00, 0x00, 0x00, 0x08, 0x04, 0xD2, 0x16, 0x2F]
        );
    }

    #[tokio::test]
    async fn postgres_probe_captures_exactly_the_single_reply_byte_without_hitting_the_deadline() {
        // A stub that behaves like a real server: it does not close after
        // sending its one byte. Proves `read_at_most` -- not the full
        // deadline -- is what bounds this probe's happy path.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            let (mut sock, _) = listener.accept().await.unwrap();
            sock.write_all(b"N").await.unwrap();
            // Deliberately keep the socket open, unread, for far longer
            // than the deadline used below -- a real server does not
            // close here either.
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            drop(sock);
        });
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut io = ProbeIo::new(stream, addr.port(), TEST_DEADLINE);
        let start = std::time::Instant::now();
        let cap = PostgresStartupProbe.execute(&mut io).await.unwrap();
        let elapsed = start.elapsed();
        assert_eq!(cap.response, b"N".to_vec());
        assert!(
            !cap.truncated,
            "one full requested byte arrived: this is complete, not truncated"
        );
        assert!(
            elapsed < TEST_DEADLINE,
            "read_at_most must return well within the deadline -- its own byte read \
             plus a short boundary peek (see ProbeIo::BOUNDARY_PEEK_TIMEOUT), not the \
             full deadline; took {elapsed:?}"
        );
    }

    #[tokio::test]
    async fn postgres_probe_request_bytes_are_fixed() {
        // A literal comparison against two independent stub servers
        // directly proves AC-4.9: if any randomness, timestamp, or nonce
        // were involved, this could not hold across separate connections.
        let port_a = stub(b"S", true).await;
        let cap_a = run_probe(&PostgresStartupProbe, port_a).await.unwrap();
        let port_b = stub(b"S", true).await;
        let cap_b = run_probe(&PostgresStartupProbe, port_b).await.unwrap();
        assert_eq!(cap_a.request, cap_b.request);
    }

    // --- Beyond the brief: hostile peer (AC-4.7, AC-4.8) ---

    #[tokio::test]
    async fn postgres_probe_against_a_flood_stops_at_the_cap() {
        // `read_at_most(1)` caps at 1 byte regardless of `read_cap`, so a
        // flooding peer cannot make this probe's *response* exceed one
        // byte either -- a stronger bound than `DEFAULT_READ_CAP`, and
        // still within it. `truncated` must still be `true`: the flood had
        // far more than one byte queued, so this is not a complete reply
        // by `ProbeCapture::truncated`'s own documented meaning -- see
        // `read_at_most`'s doc comment and this task's follow-up report
        // for the bug this assertion catches (an earlier version of
        // `read_at_most` always reported `truncated: false` here).
        let port = stub_flood().await;
        let cap = run_probe(&PostgresStartupProbe, port).await.unwrap();
        assert_eq!(cap.response.len(), 1);
        assert!(cap.response.len() <= ProbeIo::DEFAULT_READ_CAP);
        assert!(
            cap.truncated,
            "a flood had far more than one byte queued behind the reply"
        );
    }

    #[tokio::test]
    async fn postgres_probe_against_a_silent_peer_errors_rather_than_hangs() {
        let port = stub_silent().await;
        let r = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            run_probe(&PostgresStartupProbe, port),
        )
        .await
        .expect("hung past a generous outer bound");
        assert!(matches!(r, Err(ProbeError::EmptyResponse)));
    }

    #[tokio::test]
    async fn postgres_probe_against_an_immediately_closed_socket_errors() {
        let port = stub(b"", false).await;
        let r = run_probe(&PostgresStartupProbe, port).await;
        assert!(matches!(r, Err(ProbeError::EmptyResponse)));
    }
}
