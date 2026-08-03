//! `smtp-banner-v1`: reads the greeting, then sends a fixed `EHLO` and
//! captures whatever follows.
//!
//! source: RFC 5321 §3.1 ("Session Initiation"): "the SMTP server MUST
//! send a 220 'Service ready' reply... after which the client sends its
//! own greeting"; RFC 5321 §4.1.1.1 for the `EHLO <domain>` command shape.
//! `bathy.invalid` is used as the client domain per RFC 6761 §6.4 (`.invalid`
//! is reserved for use in obviously invalid contexts, exactly this one --
//! a probe that never intends to actually receive mail at this name).
//! Corroborated against a real server: `docker.io/boky/postfix:latest`
//! (digest `sha256:aafc772384232497bed875e1eb66b4d3e54ba1ebc86e2e185a6dc1dbc48182ef`),
//! which replied `220 <host> ESMTP Postfix (Debian)\r\n` and then, to
//! exactly `EHLO bathy.invalid\r\n`, a multi-line `250-`/`250 ` capability
//! list -- see this task's report for the full captured bytes.
//!
//! This probe deliberately does not inspect the greeting's content (e.g.
//! checking it starts with `220`) before sending `EHLO` -- doing so would
//! be a judgment call about what the bytes mean, which belongs to
//! `bathy-interpret` (M4 Task 3), not here. It sends `EHLO` unconditionally
//! after any non-empty, non-truncated first read, and lets the interpreter
//! decide later what to make of whatever came back.
//!
//! `response` is the greeting and the capability-list reply concatenated,
//! which is why it starts with `220 ` (per this probe's own test) even
//! though the request that produced the *rest* of it was the `EHLO`.
//!
//! # Cap accounting across the two reads
//!
//! Each of the two `read_bounded` calls here is independently bounded by
//! `DEFAULT_READ_CAP`, so a peer that starts flooding only *after* a
//! normal-sized greeting could in principle push the combined `response`
//! up to a little under `2 * DEFAULT_READ_CAP` before the second call's own
//! cap stops it -- mirroring the "up to `2 * deadline` in the worst case"
//! tradeoff [`ProbeIo`] itself already documents for any write-then-read
//! probe, not a new one introduced here. The realistic "floods from the
//! very first byte" case (this probe's own hostile-peer test) is fully
//! bounded to exactly `DEFAULT_READ_CAP`: this probe treats the greeting
//! phase as a flood -- and skips `EHLO` entirely -- only when the *cap*,
//! not merely the deadline, is what stopped the read
//! (`greeting.len() >= io.read_cap()`, together with `truncated`).
//!
//! That distinction matters: `read_bounded`'s `truncated` flag alone is
//! `true` in two very different situations -- a genuine flood (cap
//! reached fast) and the ordinary case of a well-behaved server that just
//! keeps the connection open after a short greeting (so the read only
//! ends when the deadline, not the cap, elapses). A real SMTP server does
//! the latter (confirmed against a real Postfix container -- this
//! module's `source:` note), so gating on `truncated` alone would skip
//! `EHLO` on every ordinary connection, not just flooding ones -- this was
//! caught by this probe's own
//! `smtp_probe_captures_the_capability_list_appended_after_the_greeting`
//! test failing against that simpler check during development; see this
//! task's report.
//!
//! # The EHLO phase is best-effort, not `?`-propagated
//!
//! Unlike every other probe in this crate, a failure writing `EHLO` or
//! reading its reply does not turn into `Err` here: the greeting was
//! already fully captured by that point, and discarding real evidence
//! because a *later*, separate step failed would be a worse outcome than
//! returning the partial capture. A peer that sends its greeting and then
//! immediately closes (not hypothetical -- this crate's own test stub
//! does exactly this to close a connection quickly) is exactly the case
//! this exists for: `request` is `None` if `EHLO` could not even be sent,
//! `Some(EHLO)` with `response` still holding only the greeting if it was
//! sent but nothing usable came back, and the greeting plus the
//! capability list in the ordinary case.

use async_trait::async_trait;
use bathy_types::ProbeCapture;

use crate::framework::{Probe, ProbeError, ProbeIo, ProbeKind};

/// Fixed per AC-4.9: no hostname lookups, no timestamps, always exactly
/// this line.
const EHLO: &[u8] = b"EHLO bathy.invalid\r\n";

pub struct SmtpBannerProbe;

#[async_trait]
impl Probe for SmtpBannerProbe {
    fn id(&self) -> &'static str {
        "smtp-banner-v1"
    }
    fn kind(&self) -> ProbeKind {
        ProbeKind::ListenFirst
    }
    fn affinity(&self, port: u16) -> u8 {
        match port {
            25 | 465 | 587 => 100,
            _ => 5,
        }
    }
    async fn execute(&self, io: &mut ProbeIo) -> Result<ProbeCapture, ProbeError> {
        let start = std::time::Instant::now();
        let (greeting, greeting_truncated) = io.read_bounded().await?;
        if greeting.is_empty() {
            return Err(ProbeError::EmptyResponse);
        }
        // A genuine flood, not just a server that (normally) kept the
        // connection open past the deadline -- see this module's doc
        // comment for why both conditions, not `truncated` alone, are
        // required here.
        if greeting_truncated && greeting.len() >= io.read_cap() {
            return Ok(super::finish_capture(
                self.id(),
                io,
                None,
                start,
                greeting,
                true,
            ));
        }

        // Best-effort past this point: a greeting was already captured, and
        // that is real evidence worth keeping even if the EHLO round trip
        // itself fails (a peer that closes right after its banner is not
        // hypothetical -- see this module's own hostile-peer-adjacent test
        // below). Losing an already-complete greeting because a *later*
        // step errored would throw away good evidence for no reason, so
        // unlike every other probe in this crate, this one does not `?`
        // its way out of the second phase.
        let ehlo = EHLO.to_vec();
        let (request, response, truncated) = match io.write_all(&ehlo).await {
            Ok(()) => match io.read_bounded().await {
                Ok((capabilities, caps_truncated)) => {
                    let mut full = greeting;
                    full.extend_from_slice(&capabilities);
                    (Some(ehlo), full, caps_truncated)
                }
                // EHLO went out, but nothing (usable) came back -- keep the
                // greeting.
                Err(_) => (Some(ehlo), greeting, false),
            },
            // Could not even send EHLO -- keep the greeting.
            Err(_) => (None, greeting, false),
        };
        Ok(super::finish_capture(
            self.id(),
            io,
            request,
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
    async fn smtp_probe_reads_the_greeting_then_sends_ehlo() {
        let port = stub(b"220 mail.example.com ESMTP Postfix\r\n", false).await;
        let cap = run_probe(&SmtpBannerProbe, port).await.unwrap();
        assert!(cap.response.starts_with(b"220 "));
    }

    // --- Beyond the brief: the EHLO bytes actually sent, and AC-4.9 ---
    //
    // `stub`'s generic close-shortly-after-writing behavior is a race
    // against a probe that (like this one) writes a *second* time after
    // its first read completes: whether the EHLO write lands before or
    // after the stub has torn the connection down is a coin flip, not
    // something a test should depend on (this was caught as an
    // intermittent `ConnectionReset` failure during development -- see
    // this task's report). A dedicated stub that actively reads the EHLO
    // line (rather than racing a timeout against it) avoids that
    // entirely, and is what the two tests below use.

    async fn smtp_stub_that_answers_ehlo(
        greeting: &'static [u8],
        caps_reply: &'static [u8],
    ) -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            let _ = sock.write_all(greeting).await;
            let mut buf = [0u8; 256];
            if let Ok(n) = sock.read(&mut buf).await {
                assert_eq!(&buf[..n], b"EHLO bathy.invalid\r\n");
            }
            let _ = sock.write_all(caps_reply).await;
        });
        port
    }

    #[tokio::test]
    async fn smtp_probe_sends_the_fixed_ehlo_line() {
        let port =
            smtp_stub_that_answers_ehlo(b"220 mail.example.com ESMTP Postfix\r\n", b"250 OK\r\n")
                .await;
        let cap = run_probe(&SmtpBannerProbe, port).await.unwrap();
        assert_eq!(cap.request.unwrap(), b"EHLO bathy.invalid\r\n".to_vec());
    }

    #[tokio::test]
    async fn smtp_probe_captures_the_capability_list_appended_after_the_greeting() {
        let port = smtp_stub_that_answers_ehlo(
            b"220 mail.example.com ESMTP Postfix\r\n",
            b"250-mail.example.com\r\n250 PIPELINING\r\n",
        )
        .await;
        let cap = run_probe(&SmtpBannerProbe, port).await.unwrap();
        assert_eq!(
            cap.response,
            b"220 mail.example.com ESMTP Postfix\r\n250-mail.example.com\r\n250 PIPELINING\r\n"
                .to_vec()
        );
    }

    #[tokio::test]
    async fn smtp_probe_keeps_the_greeting_when_the_peer_closes_right_after_it() {
        // The scenario this probe's best-effort EHLO phase exists for: a
        // peer that sends its greeting and then closes immediately,
        // before EHLO can be sent at all. The greeting must still come
        // back as a successful (not `Err`) capture.
        let port = stub(b"220 closes-immediately.example\r\n", false).await;
        let cap = run_probe(&SmtpBannerProbe, port).await.unwrap();
        assert!(cap.response.starts_with(b"220 closes-immediately.example"));
    }

    // --- Beyond the brief: hostile peer (AC-4.7, AC-4.8) ---

    #[tokio::test]
    async fn smtp_probe_against_a_flood_stops_at_the_cap_without_sending_ehlo() {
        let port = stub_flood().await;
        let cap = run_probe(&SmtpBannerProbe, port).await.unwrap();
        assert!(cap.truncated);
        assert!(cap.response.len() <= ProbeIo::DEFAULT_READ_CAP);
        assert!(
            cap.request.is_none(),
            "a flooding greeting must short-circuit before EHLO is ever sent"
        );
    }

    #[tokio::test]
    async fn smtp_probe_against_a_silent_socket_returns_empty_response_not_a_hang() {
        let port = stub(b"", false).await;
        let r = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            run_probe(&SmtpBannerProbe, port),
        )
        .await
        .expect("hung past a generous outer bound");
        assert!(matches!(r, Err(ProbeError::EmptyResponse)));
    }
}
