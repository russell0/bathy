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
//! returning the partial capture. `request` is `None` if `EHLO` could not
//! even be sent, `Some(EHLO)` with `response` still holding only the
//! greeting if it was sent but nothing usable came back (proven, not just
//! asserted: `smtp_probe_survives_an_i_o_error_reading_the_ehlo_reply`
//! forces a real `ConnectionReset` on the EHLO reply's own read and checks
//! the greeting is still there -- reverting this handling to a plain `?`
//! makes that specific test fail, not merely a synthetic one; see this
//! task's follow-up report for the mutation), and the greeting plus the
//! capability list in the ordinary case.
//!
//! **This protects the greeting only from a failure that happens after
//! the greeting's own read has already completed successfully** -- an
//! `EHLO`-phase problem, specifically. It does **not** protect against an
//! I/O error occurring *during* the greeting's own `read_bounded` call
//! (e.g. a peer that sends the greeting and then immediately sends a raw
//! `RST` rather than a clean `FIN`, if the `RST` arrives before that call
//! has finished draining): `read_bounded` (`framework.rs`) discards
//! whatever it had already accumulated into `out` when it hits an I/O
//! error mid-read, rather than returning the partial bytes, so a
//! greeting-phase `RST` still loses the whole capture. That is a
//! limitation of `read_bounded` itself, shared by every probe in this
//! crate that uses it, not something this probe's own fix reaches --
//! fixing it would mean changing `read_bounded`'s return contract for all
//! eight probes at once, out of scope for this one probe's fix. Recorded
//! here rather than left implicit, per this task's root-cause rule.

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

    #[tokio::test]
    async fn smtp_probe_survives_an_i_o_error_reading_the_ehlo_reply() {
        // Unlike the test above (which closes early enough that EHLO is
        // never attempted at all), this one is built to force the EHLO
        // phase specifically to fail with a real I/O error, so it
        // exercises the `Err` arm on `read_bounded` in `execute`'s `match`,
        // not only the "EHLO was never sent" path.
        //
        // Getting a deterministic I/O error here without racing anything
        // takes two deliberate choices:
        //
        // 1. The greeting phase's completion is governed purely by the
        //    *client's own* short deadline elapsing (the server never
        //    touches the connection during that window at all), not by
        //    anything the server does -- so it cannot race against the
        //    server's close.
        // 2. The server is scheduled to force-close (`SO_LINGER(0)`, which
        //    sends a TCP `RST` instead of a graceful `FIN`) at a delay
        //    chosen to land safely *after* the greeting phase has already
        //    finished and the `EHLO` write has already gone out, but
        //    *while* the client is blocked inside the second
        //    `read_bounded` call waiting for a reply that will now never
        //    come. That is what turns a generic "the peer went away" into
        //    a real, observed `Err` from `read_bounded`, on that call
        //    specifically -- and, per this task's follow-up report, not
        //    from the *first* `read_bounded` call (the greeting), which is
        //    important: an RST landing *during* the greeting read instead
        //    would hit a separate, known `read_bounded` limitation (it
        //    discards already-read bytes on any I/O error, not just this
        //    probe's own logic) rather than the EHLO-phase fix this test
        //    means to prove.
        //
        // An earlier version of this test instead used `stub`'s generic
        // close-shortly-after-writing timing and was intermittently flaky
        // (an occasional `ConnectionReset` reached `.unwrap()` in the test
        // itself); a later version tried a plain `drop(sock)` after a
        // generous fixed delay and never observed a failure at all on this
        // platform -- a graceful `FIN` closely followed by an `EHLO` write
        // did not reliably produce a write- or read-side error here. Both
        // are why this version uses `SO_LINGER(0)` (a guaranteed `RST`,
        // not relying on OS/timing-dependent close semantics) and pins its
        // arrival to a specific phase by clock, not by racing a close
        // against a read.
        // `ProbeIo`'s `deadline` is a fixed *per-call* budget reused fresh
        // for every `read_bounded`/`write_all` call (see `ProbeIo`'s own
        // doc comment), so the second `read_bounded` (the EHLO reply) gets
        // its own fresh `GREETING_DEADLINE`-long window starting right
        // after the first one ends: roughly
        // `[GREETING_DEADLINE, 2 * GREETING_DEADLINE]`. `SERVER_CLOSE_DELAY`
        // is chosen to land in the middle of that second window, with
        // margin on both sides, not at either boundary.
        const GREETING_DEADLINE: std::time::Duration = std::time::Duration::from_millis(80);
        const SERVER_CLOSE_DELAY: std::time::Duration = std::time::Duration::from_millis(120);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            let (mut sock, _) = listener.accept().await.unwrap();
            sock.write_all(b"220 mail.example.com ESMTP Postfix\r\n")
                .await
                .unwrap();
            // Deliberately idle past `GREETING_DEADLINE` (the client's
            // greeting-phase read times out on its own) and past when the
            // EHLO write will have landed, before forcing an RST.
            tokio::time::sleep(SERVER_CLOSE_DELAY).await;
            sock.set_zero_linger().unwrap();
            drop(sock); // SO_LINGER(0): an abortive close -- sends RST
        });

        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut io = ProbeIo::new(stream, addr.port(), GREETING_DEADLINE);
        let cap = SmtpBannerProbe
            .execute(&mut io)
            .await
            .expect("an I/O error reading the EHLO reply must not discard the greeting");
        assert_eq!(
            cap.response,
            b"220 mail.example.com ESMTP Postfix\r\n".to_vec(),
            "response must be exactly the greeting -- the RST arrived before any EHLO reply"
        );
        assert_eq!(
            cap.request.as_deref(),
            Some(b"EHLO bathy.invalid\r\n".as_slice()),
            "EHLO must have actually been sent for this to be the scenario under test"
        );
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

    #[tokio::test]
    async fn smtp_probe_against_an_immediately_closed_socket_errors() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (client, accepted) =
            tokio::join!(tokio::net::TcpStream::connect(addr), listener.accept());
        drop(accepted.unwrap()); // close before sending anything
        let mut io = ProbeIo::new(client.unwrap(), addr.port(), TEST_DEADLINE);
        let result = SmtpBannerProbe.execute(&mut io).await;
        assert!(matches!(result, Err(ProbeError::EmptyResponse)));
    }
}
