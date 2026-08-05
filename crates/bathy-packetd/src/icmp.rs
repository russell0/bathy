//! ICMP echo host discovery (M6 Task 5), on the SYN path's authorization.
//!
//! # AC-6.19: what this module deliberately does not contain
//!
//! There is no scope check here and no packet counter here. Both probe kinds
//! reach the wire through [`Prober::admit`], which is the only function in
//! this crate that asks "may I touch this address" or "have I any budget
//! left". A grep of this file for `check_session_scope`, `max_packets` or
//! `allowed` finds nothing, and that absence is the criterion: a second probe
//! type carrying a second copy of the authorization would be a second place
//! for the answer to be wrong, in the one process that holds `CAP_NET_RAW`.
//!
//! Two counters that happen to agree still pass a test that exhausts the
//! budget with one probe kind, which is why
//! `the_ceiling_counts_icmp_and_syn_probes_against_one_budget` spends it with
//! a mix of both and asserts the *next* probe of either kind is refused.
//!
//! # AC-6.18: three states, and `Unknown` is an answer
//!
//! - **echo reply → [`HostState::Up`]**. Something at that address answered.
//! - **destination unreachable → [`HostState::Down`]**. Somebody on the path
//!   said there is nothing there. Attributed by the datagram the unreachable
//!   *quotes* (RFC 792), never by the address it arrived from, which is a
//!   router's.
//! - **silence → [`HostState::Unknown`]**. Not `Down`. Dropping echo requests
//!   is the single most common firewall policy on the internet, so a scanner
//!   that read silence as absence would report most of it as empty. `Unknown`
//!   is what AC-6.20's fallback to TCP keys off, and folding it into `Down`
//!   would delete the fallback as well as the finding.
//!
//! A **local** failure -- no route, a refused `sendto` -- is also `Unknown`,
//! and that is not the conflation `syn.rs` refuses when it answers
//! `Indeterminate` rather than `Filtered`. `Filtered` is a claim about the
//! network, which a process that never reached the network must not make;
//! `Unknown` is the *absence* of a claim, which is exactly what a probe that
//! never left this host established.
//!
//! # Nothing here is privileged
//!
//! `acquire_raw_sockets` already opens the ICMP receive socket, and the
//! sending socket is `IPPROTO_RAW` with `IP_HDRINCL`, so an echo request is
//! the same `sendto` a SYN is. This module therefore adds **no line** to the
//! privileged window `check-packetd` measures: every function here runs after
//! the capability drop, holding sockets that were opened before it.

use std::net::{IpAddr, Ipv4Addr};

use crate::protocol::{HostState, RefusalReason, SessionScope};
use crate::syn::{PROTO_ICMP, Prober, be16, checksum, ip_header, payload};

/// ICMP type 8: Echo Request (RFC 792).
pub(crate) const ICMP_ECHO_REQUEST: u8 = 8;
/// ICMP type 0: Echo Reply (RFC 792).
pub(crate) const ICMP_ECHO_REPLY: u8 = 0;
/// ICMP type 3: Destination Unreachable (RFC 792). Read by this module and by
/// [`crate::syn`], which is why it is declared once.
pub(crate) const ICMP_UNREACHABLE: u8 = 3;

/// The bytes of an ICMP header this process reads or writes: type, code,
/// checksum, identifier, sequence.
const ICMP_HEADER_LEN: u16 = 8;

/// What came back for one echo request, if anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpReply {
    EchoReply,
    DestinationUnreachable,
    None,
}

/// AC-6.18. The three states, and the one place the mapping is written.
pub fn classify_icmp(reply: IcmpReply) -> HostState {
    match reply {
        IcmpReply::EchoReply => HostState::Up,
        IcmpReply::DestinationUnreachable => HostState::Down,
        IcmpReply::None => HostState::Unknown,
    }
}

/// One 28-byte IPv4+ICMP echo request, with no data.
///
/// The data field is optional (RFC 792) and this process has nothing to put
/// in it: the identifier and sequence number are what attribute the reply,
/// and a payload would only be more bytes at a third party for no more
/// information. The IP header comes from [`ip_header`], so an echo request
/// carries [`crate::syn::PROBE_MARKER`] exactly as a SYN does and a capture
/// can tell this process's packets from the kernel's.
pub(crate) fn echo_request(src: Ipv4Addr, dst: Ipv4Addr, ident: u16, seq: u16) -> Vec<u8> {
    let mut icmp: Vec<u8> = vec![ICMP_ECHO_REQUEST, 0, 0, 0];
    icmp.extend_from_slice(&ident.to_be_bytes());
    icmp.extend_from_slice(&seq.to_be_bytes());
    // The ICMP checksum covers the ICMP message and nothing else -- there is
    // no pseudo-header, which is the one structural difference from `segment`.
    let sum = checksum(&icmp);
    if let Some(field) = icmp.get_mut(2..4) {
        field.copy_from_slice(&sum.to_be_bytes());
    }
    let mut packet = ip_header(src, dst, PROTO_ICMP, ICMP_HEADER_LEN);
    packet.extend_from_slice(&icmp);
    packet
}

/// What an inbound packet says about the echo request identified by
/// `(dst, ident, seq)`, or `None` if it says nothing about it.
///
/// A packet that fails any test here belongs to somebody else's traffic --
/// the host's own `ping`, another `packetd` -- and is dropped rather than
/// guessed at. The identifier alone is not enough: two probes in one session
/// differ in it, but two *processes* can collide, so the sequence number and
/// the address are checked too.
pub(crate) fn match_echo(packet: &[u8], dst: Ipv4Addr, ident: u16, seq: u16) -> Option<IcmpReply> {
    if packet.get(9).copied()? != PROTO_ICMP {
        return None;
    }
    let source: [u8; 4] = packet.get(12..16)?.try_into().ok()?;
    let icmp = payload(packet)?;
    match icmp.first().copied()? {
        ICMP_ECHO_REPLY => {
            // An echo reply comes from the host itself and echoes the
            // identifier and sequence number back verbatim.
            if Ipv4Addr::from(source) != dst || be16(icmp, 4)? != ident || be16(icmp, 6)? != seq {
                return None;
            }
            Some(IcmpReply::EchoReply)
        }
        ICMP_UNREACHABLE => {
            // RFC 792: the IP header and the first 8 bytes of the datagram
            // that provoked it -- for an echo request, that is the whole
            // header including the identifier and sequence number. The quote
            // is what attributes it; the source address is a router's.
            let quoted = icmp.get(8..)?;
            if quoted.get(9).copied()? != PROTO_ICMP {
                return None;
            }
            let quoted_dst: [u8; 4] = quoted.get(16..20)?.try_into().ok()?;
            let echo = payload(quoted)?;
            if echo.first().copied()? != ICMP_ECHO_REQUEST
                || Ipv4Addr::from(quoted_dst) != dst
                || be16(echo, 4)? != ident
                || be16(echo, 6)? != seq
            {
                return None;
            }
            Some(IcmpReply::DestinationUnreachable)
        }
        _ => None,
    }
}

impl Prober {
    /// One ICMP echo probe: the shared admission, then an echo request, then
    /// whatever answers it before the deadline (AC-6.18, AC-6.19).
    ///
    /// The first line is the whole of AC-6.19. Everything authorization-
    /// related has already happened by the time this function has an
    /// `Ipv4Addr` to build a packet for, and it happened in the same function
    /// [`Prober::probe`] calls.
    pub fn icmp_probe(
        &mut self,
        scope: &SessionScope,
        target: IpAddr,
    ) -> Result<HostState, RefusalReason> {
        let (addr, counter) = self.admit(scope, target)?;
        let ident = Prober::discriminator(counter);
        let seq = u16::try_from(counter & 0xffff).unwrap_or(0);
        let Ok(src) = self.source_for(addr) else {
            return Ok(HostState::Unknown);
        };
        let request = echo_request(src, addr, ident, seq);
        if !self.send(&request, addr, scope.packets_per_second()) {
            return Ok(HostState::Unknown);
        }
        let reply = self
            .await_matching(|packet| match_echo(packet, addr, ident, seq))
            .unwrap_or(IcmpReply::None);
        Ok(classify_icmp(reply))
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::protocol::{PortState, Response};
    use crate::syn::tests::{
        Answer, Shared, ip, probe_fields, prober_with, scope_of, session_allowing, session_with, v4,
    };
    use crate::syn::{PROBE_MARKER, TTL};

    /// The router that answers with an unreachable. Not the target, on
    /// purpose: the attribution must come from the quote.
    const ROUTER: Ipv4Addr = Ipv4Addr::new(10, 30, 0, 1);

    fn scope(max: u64) -> SessionScope {
        scope_of(vec!["10.30.0.0/24".parse().unwrap()], vec![], 100_000, max)
    }

    /// The host answers the echo request it actually received, echoing the
    /// identifier and sequence number out of *that* packet -- so the fixture
    /// agrees with the code rather than with a copy of its derivation.
    fn answer_echo_reply(request: &[u8]) -> Vec<Vec<u8>> {
        let (src, dst, ident, seq) = echo_fields(request);
        let mut icmp: Vec<u8> = vec![ICMP_ECHO_REPLY, 0, 0, 0];
        icmp.extend_from_slice(&ident.to_be_bytes());
        icmp.extend_from_slice(&seq.to_be_bytes());
        let mut ip = ip_header(dst, src, PROTO_ICMP, ICMP_HEADER_LEN);
        ip.extend_from_slice(&icmp);
        vec![ip]
    }

    /// A router answers with a destination-unreachable quoting the request,
    /// as RFC 792 requires -- the IP header and the first 8 bytes.
    fn answer_unreachable(request: &[u8]) -> Vec<Vec<u8>> {
        let (src, _, _, _) = echo_fields(request);
        let mut icmp: Vec<u8> = vec![ICMP_UNREACHABLE, 1, 0, 0, 0, 0, 0, 0];
        icmp.extend_from_slice(request);
        let mut ip = ip_header(ROUTER, src, PROTO_ICMP, 0);
        ip.extend_from_slice(&icmp);
        vec![ip]
    }

    /// The addresses, identifier and sequence of an echo request we emitted,
    /// read back off the wire.
    fn echo_fields(request: &[u8]) -> (Ipv4Addr, Ipv4Addr, u16, u16) {
        let (src, dst, _, _) = probe_fields(request);
        (
            src,
            dst,
            be16(request, 24).unwrap(),
            be16(request, 26).unwrap(),
        )
    }

    /// Drives one ICMP probe against a wire answering with `answer`.
    fn icmp_answered_by(
        answer: Option<Answer>,
        deadline: Duration,
    ) -> (Result<HostState, RefusalReason>, Shared) {
        let wire = Shared::default();
        wire.0.borrow_mut().answer = answer;
        let mut prober = prober_with(Box::new(wire.clone()), deadline);
        let state = prober.icmp_probe(&scope(10), ip("10.30.0.10"));
        (state, wire)
    }

    /// One echo request emitted for real, so the matching tests below are fed
    /// the bytes the code actually produces.
    fn one_emitted_request() -> Vec<u8> {
        let (_, wire) = icmp_answered_by(None, Duration::ZERO);
        let request = wire.0.borrow().sent.first().map(|(_, p)| p.clone());
        request.expect("one packet")
    }

    // -- AC-6.18 ------------------------------------------------------------

    #[test]
    fn a_destination_unreachable_reply_marks_the_host_down_not_merely_silent() {
        assert_eq!(classify_icmp(IcmpReply::EchoReply), HostState::Up);
        assert_eq!(
            classify_icmp(IcmpReply::DestinationUnreachable),
            HostState::Down
        );
        assert_eq!(classify_icmp(IcmpReply::None), HostState::Unknown);
    }

    #[test]
    fn an_echo_reply_on_the_wire_marks_the_host_up() {
        let (state, wire) = icmp_answered_by(Some(answer_echo_reply), Duration::from_millis(400));
        assert_eq!(state, Ok(HostState::Up));
        assert_eq!(
            wire.0.borrow().sent.len(),
            1,
            "one echo request and no teardown: there is nothing to tear down"
        );
    }

    /// `Down` like an absent host, but it *arrived*. The narrowing control is
    /// the wall clock: an implementation that ignored unreachables would
    /// reach `Unknown` only by waiting out the whole deadline, so this
    /// asserts the answer came back fast as well as that it came back `Down`.
    #[test]
    fn an_unreachable_on_the_wire_marks_the_host_down_without_waiting_out_the_deadline() {
        let started = std::time::Instant::now();
        let (state, _) = icmp_answered_by(Some(answer_unreachable), Duration::from_millis(400));
        assert_eq!(state, Ok(HostState::Down));
        assert!(
            started.elapsed() < Duration::from_millis(400),
            "the unreachable was not recognised; this is the silence path wearing its \
             answer, and it took {:?}",
            started.elapsed()
        );
    }

    /// The state `Down` must not be reachable by silence, and the state
    /// `Unknown` must not be reachable by an answer. This is the pair the
    /// criterion is about: three states, three causes.
    #[test]
    fn silence_past_the_deadline_is_unknown_and_never_down() {
        let (state, wire) = icmp_answered_by(None, Duration::from_millis(120));
        assert_eq!(state, Ok(HostState::Unknown));
        assert_eq!(wire.0.borrow().sent.len(), 1, "the request was still sent");
    }

    /// A local failure produces `Unknown` -- the absence of a claim -- and
    /// emits nothing. The control is the same probe over a working wire.
    #[test]
    fn a_local_failure_is_unknown_and_emits_nothing() {
        #[derive(Debug)]
        struct Broken {
            route: bool,
        }
        impl crate::syn::Wire for Broken {
            fn source_for(&self, _target: Ipv4Addr) -> std::io::Result<Ipv4Addr> {
                if self.route {
                    Ok(crate::syn::tests::HOST)
                } else {
                    Err(std::io::Error::other("no route"))
                }
            }
            fn emit(&mut self, _packet: &[u8], _target: Ipv4Addr) -> std::io::Result<()> {
                Err(std::io::Error::other("the send failed"))
            }
            fn poll(&mut self, _buf: &mut [u8]) -> Option<usize> {
                None
            }
        }
        for route in [true, false] {
            let mut prober = prober_with(Box::new(Broken { route }), Duration::ZERO);
            assert_eq!(
                prober.icmp_probe(&scope(10), ip("10.30.0.10")),
                Ok(HostState::Unknown),
                "route={route}"
            );
            assert_eq!(prober.packets_emitted(), 0, "nothing reached the wire");
        }
    }

    // -- the emitted packet itself ------------------------------------------

    #[test]
    fn an_echo_request_is_well_formed_and_carries_the_marker() {
        let request = one_emitted_request();
        assert_eq!(request.len(), 28, "20-byte IP header plus an 8-byte ICMP");
        assert_eq!(request.first().copied(), Some(0x45));
        assert_eq!(be16(&request, 2), Some(28), "total length");
        assert_eq!(be16(&request, 4), Some(PROBE_MARKER));
        assert_eq!(request.get(8).copied(), Some(TTL));
        assert_eq!(request.get(9).copied(), Some(PROTO_ICMP));
        assert_eq!(request.get(20).copied(), Some(ICMP_ECHO_REQUEST));
        assert_eq!(request.get(21).copied(), Some(0), "code 0");
        // A receiver validates this, and a wrong one is a request that is
        // silently discarded -- which reads as `Unknown` for every host.
        let icmp = request.get(20..).unwrap();
        assert_eq!(
            checksum(icmp),
            0,
            "the one's-complement sum of a correctly checksummed message is zero"
        );
    }

    /// Two probes in one session must not carry the same identity, or the
    /// second one's reply matcher accepts the first one's reply.
    #[test]
    fn successive_probes_carry_distinct_identifiers() {
        let wire = Shared::default();
        let mut prober = prober_with(Box::new(wire.clone()), Duration::ZERO);
        let scope = scope(10);
        for target in ["10.30.0.10", "10.30.0.11"] {
            let _ = prober.icmp_probe(&scope, ip(target));
        }
        let sent = wire.0.borrow().sent.clone();
        assert_eq!(sent.len(), 2);
        let first = echo_fields(&sent.first().unwrap().1);
        let second = echo_fields(&sent.get(1).unwrap().1);
        assert_ne!((first.2, first.3), (second.2, second.3));
    }

    // -- reply attribution --------------------------------------------------

    #[test]
    fn a_reply_for_a_different_probe_is_not_attributed_to_this_one() {
        let request = one_emitted_request();
        let (_, dst, ident, seq) = echo_fields(&request);
        let reply = answer_echo_reply(&request).pop().unwrap();
        assert_eq!(
            match_echo(&reply, dst, ident, seq),
            Some(IcmpReply::EchoReply),
            "the control: the reply this probe actually earned"
        );
        assert_eq!(match_echo(&reply, dst, ident ^ 1, seq), None);
        assert_eq!(match_echo(&reply, dst, ident, seq ^ 1), None);
        assert_eq!(match_echo(&reply, v4("10.30.0.11"), ident, seq), None);
    }

    /// An unreachable is attributed by the datagram it quotes. The fixture
    /// above already proves the *right* one is accepted from an address that
    /// is not the target's; these are the wrong ones.
    #[test]
    fn an_unreachable_quoting_a_different_datagram_is_not_ours() {
        let request = one_emitted_request();
        let (_, dst, ident, seq) = echo_fields(&request);
        let ours = answer_unreachable(&request).pop().unwrap();
        assert_eq!(
            match_echo(&ours, dst, ident, seq),
            Some(IcmpReply::DestinationUnreachable),
            "the control: an unreachable quoting this probe, from a router"
        );
        assert_eq!(match_echo(&ours, dst, ident ^ 1, seq), None);
        assert_eq!(match_echo(&ours, dst, ident, seq ^ 1), None);
        // A quote naming a different destination.
        let mut elsewhere = ours.clone();
        elsewhere
            .get_mut(44..48)
            .unwrap()
            .copy_from_slice(&v4("10.30.0.11").octets());
        assert_eq!(match_echo(&elsewhere, dst, ident, seq), None);
        // A quote of something that is not an echo request. Byte 48 is the
        // quoted ICMP type: 20 IP + 8 ICMP + 20 quoted IP.
        let mut not_an_echo = ours.clone();
        *not_an_echo.get_mut(48).unwrap() = ICMP_UNREACHABLE;
        assert_eq!(match_echo(&not_an_echo, dst, ident, seq), None);
        // And a quote of a datagram that is not ICMP at all. Byte 37 is the
        // quoted IP header's protocol field (20 + 8 + 9). Without this check
        // a TCP segment whose bytes 4..8 happened to equal our identifier
        // and sequence number would be read as a host being unreachable.
        let mut not_icmp = ours;
        *not_icmp.get_mut(37).unwrap() = 6;
        assert_eq!(match_echo(&not_icmp, dst, ident, seq), None);
    }

    /// Only types 0 and 3 mean anything here. A time-exceeded quoting this
    /// same probe is a routing loop, not a host state, and reading it as
    /// either would put an answer on a host nothing answered for.
    #[test]
    fn no_other_icmp_type_is_read_as_a_host_state() {
        let request = one_emitted_request();
        let (_, dst, ident, seq) = echo_fields(&request);
        let mut reply = answer_echo_reply(&request).pop().unwrap();
        for other in [8u8, 11, 12, 13, 5] {
            *reply.get_mut(20).unwrap() = other;
            assert_eq!(match_echo(&reply, dst, ident, seq), None, "type {other}");
        }
    }

    /// A TCP segment is never an ICMP answer, and vice versa. Both probe
    /// kinds share one receive path, so each matcher has to reject the
    /// other's traffic -- an unreachable quoting an *echo request* has
    /// 0x0800 where a quoted TCP segment has its source port.
    #[test]
    fn the_two_matchers_do_not_read_each_others_traffic() {
        let request = one_emitted_request();
        let (_, dst, ident, seq) = echo_fields(&request);
        let unreachable = answer_unreachable(&request).pop().unwrap();
        assert_eq!(
            match_echo(&unreachable, dst, ident, seq),
            Some(IcmpReply::DestinationUnreachable),
            "the control"
        );
        // The ports `match_reply` WOULD read out of the quote if it did not
        // check the quoted datagram's protocol: bytes 0..2 of a quoted ICMP
        // header (type 8, code 0) sit where a quoted TCP segment's source
        // port would, and bytes 2..4 (its checksum) where the destination
        // port would. Handing it exactly those numbers is what makes this a
        // falsifier rather than a coincidence -- with the guard removed, this
        // assertion is the one that fails.
        let echo = request.get(20..).unwrap();
        let would_be_sport = be16(echo, 0).unwrap();
        let would_be_port = be16(echo, 2).unwrap();
        assert_eq!(
            crate::syn::match_reply(&unreachable, dst, would_be_port, would_be_sport),
            None,
            "an unreachable quoting an echo request is not a port's state"
        );
    }

    #[test]
    fn a_truncated_packet_is_dropped_rather_than_panicking() {
        let request = one_emitted_request();
        let (_, dst, ident, seq) = echo_fields(&request);
        for full in [
            answer_echo_reply(&request).pop().unwrap(),
            answer_unreachable(&request).pop().unwrap(),
        ] {
            assert!(
                match_echo(&full, dst, ident, seq).is_some(),
                "the whole packet must match, or the cuts below range over nothing"
            );
            for cut in 0..full.len() {
                let _ = match_echo(full.get(..cut).unwrap(), dst, ident, seq);
            }
        }
    }

    // -- AC-6.19: one scope check, one budget -------------------------------

    #[test]
    fn icmp_probes_are_scope_checked_on_the_same_path_as_syn_probes() {
        let (mut s, wire) = session_allowing("10.30.0.0/24");
        let r = s.handle_icmp_probe(1, ip("8.8.8.8"));
        assert!(
            matches!(&r, Response::Refused { reason, .. }
                     if *reason == RefusalReason::OutOfSessionScope),
            "{r:?}"
        );
        assert_eq!(s.packets_emitted(), 0);
        assert!(wire.0.borrow().sent.is_empty());
        // The control: the same call at an address that is in scope emits.
        assert!(matches!(
            s.handle_icmp_probe(2, ip("10.30.0.10")),
            Response::HostResult { .. }
        ));
        assert_eq!(s.packets_emitted(), 1);
    }

    /// The reserved-range refusal (AC-6.10) is the same one, not a second
    /// copy: an ICMP probe under an allowlist of `0.0.0.0/0` reaches none of
    /// them. Without this, an `icmp_probe` that called only a CIDR test would
    /// pass the allowlist test above and ping the broadcast address.
    #[test]
    fn reserved_ranges_are_refused_for_icmp_too() {
        let (mut s, wire) = session_allowing("0.0.0.0/0");
        for bad in ["127.0.0.1", "224.0.0.1", "255.255.255.255", "169.254.1.1"] {
            let r = s.handle_icmp_probe(1, ip(bad));
            assert!(matches!(r, Response::Refused { .. }), "{bad}: {r:?}");
        }
        assert_eq!(wire.0.borrow().sent.len(), 0);
        // The control that makes `0.0.0.0/0` mean something here.
        assert!(matches!(
            s.handle_icmp_probe(9, ip("198.51.100.7")),
            Response::HostResult { .. }
        ));
    }

    #[test]
    fn the_session_denylist_refuses_icmp_probes_too() {
        let (mut s, _) = session_with("\"10.30.0.0/24\"", "\"10.30.0.1/32\"", 1000);
        assert!(matches!(
            s.handle_icmp_probe(1, ip("10.30.0.1")),
            Response::Refused { .. }
        ));
        assert!(matches!(
            s.handle_icmp_probe(2, ip("10.30.0.2")),
            Response::HostResult { .. }
        ));
    }

    /// **AC-6.19's own test.** The budget is spent by a *mix* of both probe
    /// kinds, which is the only shape that can tell one shared counter from
    /// two counters that agree. Four admitted probes -- ICMP, SYN, ICMP, SYN
    /// -- against a ceiling of four, and then neither kind is admitted.
    ///
    /// With two counters this passes only if both happen to be exhausted,
    /// which four alternating probes against a ceiling of four never do: each
    /// counter would stand at two.
    #[test]
    fn the_ceiling_counts_icmp_and_syn_probes_against_one_budget() {
        let (mut s, wire) = session_with("\"10.30.0.0/24\"", "", 4);
        let target = ip("10.30.0.2");
        assert!(matches!(
            s.handle_icmp_probe(1, target),
            Response::HostResult { .. }
        ));
        assert!(matches!(
            s.handle_probe(2, target, 80),
            Response::Result { .. }
        ));
        assert!(matches!(
            s.handle_icmp_probe(3, target),
            Response::HostResult { .. }
        ));
        assert!(matches!(
            s.handle_probe(4, target, 81),
            Response::Result { .. }
        ));
        assert_eq!(wire.0.borrow().sent.len(), 4);
        // The ceiling is spent, and it is spent for BOTH kinds.
        for r in [
            s.handle_icmp_probe(5, target),
            s.handle_probe(6, target, 82),
        ] {
            assert!(
                matches!(&r, Response::Refused { reason, .. }
                         if *reason == RefusalReason::SessionBudgetExhausted),
                "{r:?}"
            );
        }
        assert_eq!(
            wire.0.borrow().sent.len(),
            4,
            "neither refused probe may reach the wire"
        );
    }

    /// The shared out-of-state guard, reached the way only a direct call
    /// reaches it: `handle_line`'s dispatch answers a pre-`init` line from its
    /// own arm, so a test that goes through the line protocol never gets here.
    /// Found by mutation -- neutering this guard left every ICMP test passing,
    /// and only `syn.rs`'s equivalent test failed.
    #[test]
    fn handle_icmp_probe_called_directly_before_init_is_fatal_and_emits_nothing() {
        let wire = Shared::default();
        let mut session = crate::protocol::Session::new(true, Box::new(wire.clone()));
        session.set_reply_deadline(Duration::ZERO);
        let r = session.handle_icmp_probe(1, ip("10.30.0.10"));
        assert!(matches!(r, Response::Fatal { .. }), "{r:?}");
        assert!(
            session.is_terminated() && session.ended_fatally(),
            "a probe before init must end the session, not be refused one probe at a time"
        );
        assert!(wire.0.borrow().sent.is_empty(), "and emit nothing");
    }

    /// The mirror of `the_ceiling_counts_icmp_and_syn_probes_against_one_
    /// budget`: a budget spent entirely by ICMP refuses a SYN probe. A SYN
    /// path reading its own counter would still admit this one.
    #[test]
    fn a_budget_spent_by_icmp_refuses_a_syn_probe() {
        let (mut s, _) = session_with("\"10.30.0.0/24\"", "", 2);
        let target = ip("10.30.0.2");
        for id in 1..=2 {
            assert!(matches!(
                s.handle_icmp_probe(id, target),
                Response::HostResult { .. }
            ));
        }
        let r = s.handle_probe(3, target, 80);
        assert!(
            matches!(&r, Response::Refused { reason, .. }
                     if *reason == RefusalReason::SessionBudgetExhausted),
            "{r:?}"
        );
    }

    /// Scope before the ceiling, for ICMP as for SYN (AC-6.11's ordering).
    /// Both refusals apply to this probe; the one reported must be the
    /// authorization one, because a privileged process must not answer
    /// "budget spent" about an address it was never allowed to touch.
    #[test]
    fn an_out_of_scope_icmp_probe_is_refused_for_scope_even_with_no_budget() {
        let (mut s, _) = session_with("\"10.30.0.0/24\"", "", 1);
        assert!(matches!(
            s.handle_icmp_probe(1, ip("10.30.0.2")),
            Response::HostResult { .. }
        ));
        let r = s.handle_icmp_probe(2, ip("8.8.8.8"));
        assert!(
            matches!(&r, Response::Refused { reason, .. }
                     if *reason == RefusalReason::OutOfSessionScope),
            "{r:?}"
        );
    }

    /// A refused ICMP probe does not consume budget, so a refusal cannot be
    /// used to starve the session. The SYN path has the same property by
    /// construction -- `admit` returns before the counter advances -- and
    /// this asserts it survives on the shared path.
    #[test]
    fn a_refused_probe_of_either_kind_costs_no_budget() {
        let (mut s, _) = session_with("\"10.30.0.0/24\"", "", 2);
        for id in 0..10 {
            assert!(matches!(
                s.handle_icmp_probe(id, ip("8.8.8.8")),
                Response::Refused { .. }
            ));
        }
        assert!(matches!(
            s.handle_probe(11, ip("10.30.0.2"), 80),
            Response::Result { .. }
        ));
        assert!(matches!(
            s.handle_icmp_probe(12, ip("10.30.0.2")),
            Response::HostResult { .. }
        ));
    }

    /// One session, both kinds, one rate and one emission counter.
    #[test]
    fn both_probe_kinds_are_counted_by_one_emission_counter() {
        let wire = Shared::default();
        wire.0.borrow_mut().answer = None;
        let mut prober = prober_with(Box::new(wire), Duration::ZERO);
        let scope = scope(10);
        assert_eq!(
            prober.probe(&scope, ip("10.30.0.10"), 80),
            Ok(PortState::Filtered)
        );
        assert_eq!(prober.packets_emitted(), 1);
        assert_eq!(
            prober.icmp_probe(&scope, ip("10.30.0.10")),
            Ok(HostState::Unknown)
        );
        assert_eq!(prober.packets_emitted(), 2);
    }
}
