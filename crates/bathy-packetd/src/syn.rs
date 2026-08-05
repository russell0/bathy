//! Half-open SYN probing, and the **second, independent** scope check that
//! decides whether any packet is built at all.
//!
//! # Why this file does not call `bathy-scope`
//!
//! The engine already checked scope. `packetd` is the only process in this
//! workspace that can put an arbitrary packet on the wire, so it must not
//! delegate the question of whether it is allowed to: a bug or a compromise in
//! the unprivileged half has to be *unable* to become a packet at an address
//! nobody authorized. Delegating would make that one implementation and one
//! bug away from both checks failing together.
//!
//! So [`check_session_scope`] shares no code with `bathy_scope`. It does not
//! import it, it does not use `IpNet::contains` (the containment test is
//! [`covers`], a mask comparison written here), and it does not use `std`'s
//! `is_loopback`/`is_multicast`/`is_broadcast`/`is_link_local` predicates that
//! `bathy_scope::manifest::is_ordinary_unicast` is built out of --
//! [`is_reserved`] decides from the octets directly.
//!
//! Two implementations of one policy is worth nothing unless somebody checks
//! that they agree, and a disagreement is a finding either way round. So the
//! test module ends with a proptest that generates a CIDR pair and an address
//! and asserts that this module and a real `bathy_scope::ScopeManifest` reach
//! the *same* verdict, over the same inputs -- `the_two_scope_implementations_
//! agree_on_every_generated_address`. `bathy-scope` is a **dev**-dependency;
//! no edge from it reaches the privileged binary.
//!
//! # The three refusals, in the order they are asked
//!
//! 1. **Reserved** (AC-6.10). Asked *first*, before either CIDR set, so that
//!    an allowlist of `0.0.0.0/0` cannot reach multicast, broadcast, loopback
//!    or link-local. An operator writing `0.0.0.0/0` is saying "I am
//!    authorized for the internet"; they are not saying "send this at
//!    255.255.255.255", and the two are different sentences.
//! 2. **Denied** (AC-6.9). Deny beats allow, always, and it is asked before
//!    the allow set so that no "more specific prefix wins" rule can ever be
//!    introduced by accident.
//! 3. **Allowed** (AC-6.9). Deny by default: only an explicit match reaches
//!    `Ok`.
//!
//! # The ceiling, and the one packet that is exempt from it
//!
//! [`Prober`] carries its own counter (AC-6.11). It is not the engine's
//! `BudgetLedger`, it does not consult it, and it cannot be widened after
//! `Init` because [`crate::protocol::SessionScope`] is immutable.
//!
//! The ceiling admits **probes**. A teardown RST is exempt, deliberately, and
//! the reasoning is the same one the ceiling itself exists for: the ceiling
//! bounds what this process does *to a third party*, and refusing to send the
//! RST would leave a half-open connection on that third party's listen queue
//! -- more harm, not less, for the sake of a tidier number. `packets_emitted`
//! counts every packet including RSTs, so the exemption is visible rather than
//! hidden, and `at_the_ceiling_an_open_ports_teardown_rst_is_still_sent` pins
//! it.
//!
//! # AC-6.13: every SYN-ACK is answered with an RST
//!
//! Leaving half-open connections is the antisocial part of SYN scanning and
//! there is no reason to do it. Every emitted packet carries
//! [`PROBE_MARKER`] in its IP identification field, which is what lets a
//! capture -- and `tests/wire.rs`, which sniffs the wire with a raw socket of
//! its own -- tell *our* RST from the one the host kernel sends on its own
//! account when a SYN-ACK arrives for a socket it does not have.

use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use ipnet::IpNet;
use socket2::SockAddr;

use crate::icmp::ICMP_UNREACHABLE;
use crate::privilege::RawSockets;
use crate::protocol::{PortState, RefusalReason, SessionScope};

/// The IP identification field every packet `packetd` emits carries.
///
/// It is not a security mechanism and nothing trusts it: it is a *marker*, so
/// that a packet capture can attribute a packet to this process. That matters
/// for AC-6.13 specifically, because when a SYN-ACK arrives for a port the
/// host kernel has no socket on, the kernel sends an RST of its own -- with
/// the same sequence number ours has. Without a discriminator, "the RST was
/// observed" would be a claim satisfied by a packet this code did not send.
pub const PROBE_MARKER: u16 = 0xba71;

/// How long a probe waits for a reply before calling it `Filtered`.
pub const REPLY_DEADLINE: Duration = Duration::from_millis(1200);

/// How long one `recv` blocks, set on both receive sockets by
/// `acquire_raw_sockets`. It is also the granularity at which [`Prober::
/// await_reply`] notices its deadline.
pub const RECV_TIMEOUT: Duration = Duration::from_millis(10);

/// The source ports probes are sent from: 20000..30000, deliberately *below*
/// Linux's default ephemeral range (32768-60999). A raw SYN sent from a port
/// the kernel has since handed to a real socket would have that socket's owner
/// receiving our replies.
const SOURCE_PORT_BASE: u16 = 20_000;
const SOURCE_PORT_SPAN: u32 = 10_000;

pub(crate) const PROTO_ICMP: u8 = 1;
const PROTO_TCP: u8 = 6;
const FLAG_SYN: u8 = 0x02;
const FLAG_RST: u8 = 0x04;
const FLAG_ACK: u8 = 0x10;
pub(crate) const TTL: u8 = 64;

// ---------------------------------------------------------------------------
// AC-6.12 — what a reply means.
// ---------------------------------------------------------------------------

/// What came back, if anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reply {
    SynAck,
    Rst,
    IcmpUnreachable,
    None,
}

/// AC-6.12. `Filtered` for both the ICMP refusal and the silence, because in
/// both cases something between us and the port declined to let us find out,
/// and claiming to know which would be a claim this process did not observe.
pub fn classify_reply(reply: Reply) -> PortState {
    match reply {
        Reply::SynAck => PortState::Open,
        Reply::Rst => PortState::Closed,
        Reply::IcmpUnreachable | Reply::None => PortState::Filtered,
    }
}

// ---------------------------------------------------------------------------
// AC-6.9 / AC-6.10 — the independent scope check.
// ---------------------------------------------------------------------------

/// Addresses that are never a legitimate scan target, decided from the octets
/// rather than from `std`'s predicates, so that this is a second
/// implementation and not the same one twice.
///
/// - `0.0.0.0/8` -- "this network" (RFC 1122), and the unspecified address.
/// - `127.0.0.0/8` -- loopback. Scanning it is scanning ourselves.
/// - `224.0.0.0/3` -- multicast (`224.0.0.0/4`, RFC 5771) and the
///   IANA-reserved `240.0.0.0/4` (RFC 1112), which contains the limited
///   broadcast address `255.255.255.255`. One comparison, two RFCs, and the
///   comment is what says so.
/// - `169.254.0.0/16` -- link-local (RFC 3927).
pub fn is_reserved(addr: Ipv4Addr) -> bool {
    let [a, b, _, _] = addr.octets();
    a == 0 || a == 127 || a >= 224 || (a == 169 && b == 254)
}

/// Whether `net` covers `addr`, by masking both to the prefix length.
///
/// Deliberately not `IpNet::contains`: sharing `ipnet`'s *parser* with
/// `bathy-scope` is unavoidable and harmless, sharing its *matcher* would
/// undo the independence this whole module is for.
fn covers(net: &IpNet, addr: Ipv4Addr) -> bool {
    let IpNet::V4(v4) = net else {
        return false;
    };
    // `checked_shl` returns `None` for a shift of 32 or more, which is the
    // `/0` case, and `unwrap_or(0)` is the mask that matches everything.
    let mask = u32::MAX
        .checked_shl(u32::from(32u8.saturating_sub(v4.prefix_len())))
        .unwrap_or(0);
    u32::from(addr) & mask == u32::from(v4.addr()) & mask
}

/// The whole of AC-6.9 and AC-6.10, in the order the module header states.
///
/// Returns the target as an `Ipv4Addr` on success, so that the only way to get
/// an address this module will build a packet for is to have passed this
/// function. An `IpAddr::V6` target is refused unconditionally: v0.1 does not
/// scan IPv6, `acquire_raw_sockets` opens `Domain::IPV4` sockets, and a
/// refusal is the honest answer for an address this process could not reach
/// even if it were authorized to.
pub fn check_session_scope(
    scope: &SessionScope,
    target: IpAddr,
) -> Result<Ipv4Addr, RefusalReason> {
    let IpAddr::V4(addr) = target else {
        return Err(RefusalReason::OutOfSessionScope);
    };
    let denied = scope.denied().iter().any(|net| covers(net, addr));
    let allowed = scope.allowed().iter().any(|net| covers(net, addr));
    if is_reserved(addr) || denied || !allowed {
        return Err(RefusalReason::OutOfSessionScope);
    }
    Ok(addr)
}

// ---------------------------------------------------------------------------
// Bytes on and off the wire.
// ---------------------------------------------------------------------------

/// A big-endian `u16` at `at`, or `None` if the packet is shorter than that.
///
/// Every read of an inbound packet in this file goes through this or through
/// [`slice::get`]. `clippy::indexing_slicing` is denied in this crate, and the
/// bytes below arrive from whatever is on the network.
pub(crate) fn be16(bytes: &[u8], at: usize) -> Option<u16> {
    let field: [u8; 2] = bytes.get(at..at.checked_add(2)?)?.try_into().ok()?;
    Some(u16::from_be_bytes(field))
}

/// Everything after an IPv4 header, using that header's own IHL.
pub(crate) fn payload(packet: &[u8]) -> Option<&[u8]> {
    packet.get(usize::from(packet.first()? & 0x0f).checked_mul(4)?..)
}

/// The internet checksum (RFC 1071): one's-complement sum of 16-bit words,
/// complemented. An odd trailing byte is padded with zero, which is what the
/// RFC specifies and what makes the pseudo-header case below correct.
pub(crate) fn checksum(bytes: &[u8]) -> u16 {
    let word = |w: &[u8]| {
        u16::from_be_bytes([
            w.first().copied().unwrap_or(0),
            w.get(1).copied().unwrap_or(0),
        ])
    };
    let mut sum = bytes
        .chunks(2)
        .fold(0u32, |acc, w| acc.wrapping_add(u32::from(word(w))));
    while sum > 0xffff {
        sum = (sum & 0xffff).wrapping_add(sum.wrapping_shr(16));
    }
    !u16::try_from(sum & 0xffff).unwrap_or(0)
}

/// One 40-byte IPv4+TCP segment with no options and no payload.
///
/// The IP header is built here rather than by the kernel because the sending
/// socket is `IPPROTO_RAW` with `IP_HDRINCL` (see `privilege.rs`). Linux
/// recomputes the IP checksum on such a socket and preserves a non-zero
/// identification field, which is why [`PROBE_MARKER`] survives to the wire.
///
/// `src` has to be the real outbound address: it is covered by the TCP
/// pseudo-header checksum, so a wrong one is a segment the target discards.
fn segment(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16, seq: u32, flags: u8) -> Vec<u8> {
    let mut tcp: Vec<u8> = [sport.to_be_bytes(), dport.to_be_bytes()].concat();
    tcp.extend_from_slice(&seq.to_be_bytes());
    // acknowledgement 0, data offset 5 words, flags, window 1024, checksum
    // and urgent pointer zeroed for the checksum computation below.
    tcp.extend_from_slice(&[0, 0, 0, 0, 0x50, flags, 0x04, 0x00, 0, 0, 0, 0]);
    let mut pseudo: Vec<u8> = [src.octets(), dst.octets()].concat();
    pseudo.extend_from_slice(&[0, PROTO_TCP, 0, 20]);
    pseudo.extend_from_slice(&tcp);
    let tcp_sum = checksum(&pseudo);
    if let Some(field) = tcp.get_mut(16..18) {
        field.copy_from_slice(&tcp_sum.to_be_bytes());
    }
    let mut ip = ip_header(src, dst, PROTO_TCP, 20);
    ip.extend_from_slice(&tcp);
    ip
}

/// The 20-byte IPv4 header every packet this process emits carries, checksum
/// included.
///
/// Shared with [`crate::icmp`] so that [`PROBE_MARKER`], the TTL and the
/// Don't-Fragment bit are one decision rather than two: a marker that only
/// SYNs carried would leave `tests/wire.rs` unable to attribute an echo
/// request to this process, which is the discriminator AC-6.13's capture
/// already depends on.
pub(crate) fn ip_header(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, payload_len: u16) -> Vec<u8> {
    // version 4, IHL 5, DSCP 0, then the total length including this header.
    let mut ip: Vec<u8> = vec![0x45, 0];
    ip.extend_from_slice(&payload_len.saturating_add(20).to_be_bytes());
    ip.extend_from_slice(&PROBE_MARKER.to_be_bytes());
    // Don't Fragment, no offset, TTL, protocol, checksum placeholder.
    ip.extend_from_slice(&[0x40, 0, TTL, protocol, 0, 0]);
    ip.extend_from_slice(&src.octets());
    ip.extend_from_slice(&dst.octets());
    let ip_sum = checksum(&ip);
    if let Some(field) = ip.get_mut(10..12) {
        field.copy_from_slice(&ip_sum.to_be_bytes());
    }
    ip
}

/// What an inbound IPv4 packet says about the probe identified by
/// `(dst, port, sport)`, or `None` if it says nothing about it.
///
/// The source port is unique per probe, so it is what attributes a reply; a
/// packet that fails any test here belongs to somebody else's traffic and is
/// dropped rather than guessed at.
pub(crate) fn match_reply(packet: &[u8], dst: Ipv4Addr, port: u16, sport: u16) -> Option<Reply> {
    let source: [u8; 4] = packet.get(12..16)?.try_into().ok()?;
    match packet.get(9).copied()? {
        PROTO_TCP => {
            let tcp = payload(packet)?;
            if Ipv4Addr::from(source) != dst || be16(tcp, 0)? != port || be16(tcp, 2)? != sport {
                return None;
            }
            let flags = tcp.get(13).copied()?;
            if flags & FLAG_SYN != 0 && flags & FLAG_ACK != 0 {
                Some(Reply::SynAck)
            } else if flags & FLAG_RST != 0 {
                Some(Reply::Rst)
            } else {
                None
            }
        }
        // An unreachable quotes the IP header and first 8 bytes of the
        // datagram that provoked it (RFC 792), which is exactly the source
        // port, destination port and sequence number -- so the quote is what
        // attributes it, not the address it arrived from. It may legitimately
        // come from a router rather than from the target.
        PROTO_ICMP => {
            let icmp = payload(packet)?;
            if icmp.first().copied()? != ICMP_UNREACHABLE {
                return None;
            }
            let quoted = icmp.get(8..)?;
            let quoted_dst: [u8; 4] = quoted.get(16..20)?.try_into().ok()?;
            let seg = payload(quoted)?;
            // The quoted datagram's own protocol, checked since M6 Task 5:
            // this session emits ICMP echo requests too, and an unreachable
            // quoting one of *those* has 0x0800 (type 8, code 0) where a
            // quoted TCP segment has its source port. Reading it here would
            // put a `Filtered` on a port nothing refused, and the numbers
            // happen not to collide today only because the source-port range
            // starts at 20000.
            if quoted.get(9).copied()? != PROTO_TCP {
                return None;
            }
            if Ipv4Addr::from(quoted_dst) != dst || be16(seg, 0)? != sport || be16(seg, 2)? != port
            {
                return None;
            }
            Some(Reply::IcmpUnreachable)
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// The wire, and the prober that drives it.
// ---------------------------------------------------------------------------

/// The one way a packet leaves this process.
///
/// It is a trait so that "a refused target emits zero packets" (AC-6.9) can be
/// asserted at the *emission boundary* rather than inferred from a log line: a
/// test substitutes a recorder and counts what was handed to the wire. The
/// on-the-wire confirmation is `tests/wire.rs`, which watches a raw socket.
pub trait Wire: std::fmt::Debug {
    /// The address this host would send to `target` from. Needed before the
    /// segment is built, because it is covered by the TCP checksum.
    fn source_for(&self, target: Ipv4Addr) -> std::io::Result<Ipv4Addr>;
    /// Put one packet on the wire.
    fn emit(&mut self, packet: &[u8], target: Ipv4Addr) -> std::io::Result<()>;
    /// Read one inbound packet, waiting no longer than [`RECV_TIMEOUT`].
    fn poll(&mut self, buf: &mut [u8]) -> Option<usize>;
}

/// The real thing. `RawSockets` *is* the wire: implementing the trait on it
/// rather than on a wrapper is what keeps "there is no method here that opens
/// another socket" true of the type that sends as well as of the type that
/// holds. The receive timeouts are set in `acquire_raw_sockets`, while still
/// privileged, so nothing after the drop has to configure anything.
impl Wire for RawSockets {
    /// A connected UDP socket's local address is the kernel's own answer to
    /// "which interface would this go out of", and connecting a UDP socket
    /// sends nothing -- it is a route lookup. It needs no privilege, which is
    /// why it is allowed to happen after the drop.
    fn source_for(&self, target: Ipv4Addr) -> std::io::Result<Ipv4Addr> {
        let route = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))?;
        route.connect(SocketAddr::from((target, 9)))?;
        match route.local_addr()?.ip() {
            IpAddr::V4(v4) => Ok(v4),
            IpAddr::V6(_) => Err(std::io::Error::other("no IPv4 route to the target")),
        }
    }

    fn emit(&mut self, packet: &[u8], target: Ipv4Addr) -> std::io::Result<()> {
        let to = SockAddr::from(SocketAddr::from((target, 0)));
        self.send().send_to(packet, &to).map(|_| ())
    }

    /// TCP first, then ICMP, each blocking for at most [`RECV_TIMEOUT`]. A
    /// timed-out read is indistinguishable from an unparseable one here on
    /// purpose: both mean "nothing yet", and the caller's deadline is what
    /// ends the wait. Nothing is lost by reading one socket at a time --
    /// packets queue in the other one's buffer meanwhile.
    fn poll(&mut self, buf: &mut [u8]) -> Option<usize> {
        Read::read(&mut { self.recv_tcp() }, buf)
            .or_else(|_| Read::read(&mut { self.recv_icmp() }, buf))
            .ok()
    }
}

/// Session-scoped probing state: the packet ceiling, the rate, and the
/// per-probe identities. One per process, like the session it belongs to.
#[derive(Debug)]
pub struct Prober {
    wire: Box<dyn Wire>,
    /// Every packet this process has put on the wire, including teardown
    /// RSTs. Reported; not what the ceiling is checked against.
    emitted: u64,
    /// Probes admitted. This is what AC-6.11's ceiling bounds.
    probes: u64,
    /// The source-port and sequence-number counter. It *starts* at the
    /// process id -- one process is one session here, so two `packetd`
    /// processes scanning at once do not collide on source ports -- and
    /// advances once per probe. It is not, and is not claimed to be,
    /// cryptographic randomness.
    counter: u32,
    next_send: Option<Instant>,
    /// How long a probe waits for a reply, [`REPLY_DEADLINE`] by default.
    ///
    /// Public and directly writable: a test shortens it so silence costs no
    /// wall-clock time, `fuzz/fuzz_targets/ipc.rs` sets it to zero so a probe
    /// in a fuzz input does not stall the run, and M6 Task 4's engine will
    /// want the scan's own connect timeout here. It bounds a wait; it is not
    /// part of the authorization decision, and nothing below reads it except
    /// [`Prober::await_reply`].
    pub deadline: Duration,
}

impl Prober {
    pub fn new(wire: Box<dyn Wire>) -> Self {
        Self {
            wire,
            emitted: 0,
            probes: 0,
            counter: std::process::id(),
            next_send: None,
            deadline: REPLY_DEADLINE,
        }
    }

    pub fn packets_emitted(&self) -> u64 {
        self.emitted
    }

    /// The address this host would send to `target` from. The one accessor
    /// through which both probe kinds reach the wire's route lookup, so that
    /// [`Prober::wire`] itself stays private to this module.
    pub(crate) fn source_for(&self, target: Ipv4Addr) -> std::io::Result<Ipv4Addr> {
        self.wire.source_for(target)
    }

    /// **The one authorization path in this crate** — scope, then the
    /// ceiling, then the per-probe identity (AC-6.19).
    ///
    /// Both probe kinds go through this and neither restates any part of it.
    /// That is the whole of AC-6.19: `packetd` is the only process here that
    /// can emit an arbitrary packet, and a second probe type carrying a
    /// second copy of "may I" and "have I any budget left" would be a second
    /// place for the answer to be wrong. `crate::icmp`'s probe calls this
    /// function; it does not call [`check_session_scope`], and it does not
    /// touch [`Prober::probes`].
    ///
    /// The order is AC-6.11's: **scope is decided before the ceiling**, so a
    /// target this process was never authorized to touch is never answered
    /// with "budget spent". `scope_is_decided_before_the_ceiling_is_consulted`
    /// pins it for SYN and
    /// `an_out_of_scope_icmp_probe_is_refused_for_scope_even_with_no_budget`
    /// pins the same interleaving for ICMP.
    ///
    /// Returns the target as an `Ipv4Addr` -- the only way to obtain one --
    /// and the identity counter this probe advanced it to.
    pub(crate) fn admit(
        &mut self,
        scope: &SessionScope,
        target: IpAddr,
    ) -> Result<(Ipv4Addr, u32), RefusalReason> {
        let addr = check_session_scope(scope, target)?;
        if self.probes >= scope.max_packets() {
            return Err(RefusalReason::SessionBudgetExhausted);
        }
        self.probes = self.probes.saturating_add(1);
        self.counter = self.counter.wrapping_add(1);
        Ok((addr, self.counter))
    }

    /// The 16-bit per-probe discriminator: a TCP source port for a SYN, an
    /// ICMP identifier for an echo request. Shared so that two probes of
    /// either kind in one session never carry the same one.
    pub(crate) fn discriminator(counter: u32) -> u16 {
        let offset = counter.checked_rem(SOURCE_PORT_SPAN).unwrap_or(0);
        SOURCE_PORT_BASE.saturating_add(u16::try_from(offset).unwrap_or(0))
    }

    /// One probe: scope, then ceiling, then a SYN, then a reply, then -- if it
    /// was a SYN-ACK -- an RST (AC-6.13).
    ///
    /// `Ok(Indeterminate)` is what a local failure produces (no route, a
    /// refused `sendto`). It is deliberately not `Filtered`: `Filtered` is a
    /// claim about the network, and this process did not observe the network.
    pub fn probe(
        &mut self,
        scope: &SessionScope,
        target: IpAddr,
        port: u16,
    ) -> Result<PortState, RefusalReason> {
        let (addr, counter) = self.admit(scope, target)?;
        let sport = Self::discriminator(counter);
        let seq = counter.wrapping_mul(2_654_435_761);
        let Ok(src) = self.source_for(addr) else {
            return Ok(PortState::Indeterminate);
        };
        let pps = scope.packets_per_second();
        if !self.send(&segment(src, addr, sport, port, seq, FLAG_SYN), addr, pps) {
            return Ok(PortState::Indeterminate);
        }
        let reply = self.await_reply(addr, port, sport);
        if reply == Reply::SynAck {
            // AC-6.13, and not conditional on the ceiling: see the module
            // header. `seq + 1` is the sequence the SYN-ACK acknowledged, so
            // this RST is inside the target's receive window.
            let rst = segment(src, addr, sport, port, seq.wrapping_add(1), FLAG_RST);
            self.send(&rst, addr, pps);
        }
        Ok(classify_reply(reply))
    }

    /// Emits one packet, no sooner than the session's rate permits.
    ///
    /// The rate is `packets_per_second` from `Init`, enforced here and not by
    /// asking the engine -- the same reason as the ceiling. A `pps` of zero
    /// divides to `None` and paces at no delay rather than panicking.
    pub(crate) fn send(&mut self, packet: &[u8], target: Ipv4Addr, pps: u32) -> bool {
        if let Some(at) = self.next_send {
            std::thread::sleep(at.saturating_duration_since(Instant::now()));
        }
        let gap = Duration::from_secs(1)
            .checked_div(pps)
            .unwrap_or(Duration::ZERO);
        self.next_send = Instant::now().checked_add(gap);
        let sent = self.wire.emit(packet, target).is_ok();
        if sent {
            self.emitted = self.emitted.saturating_add(1);
        }
        sent
    }

    /// Reads inbound packets until `matcher` recognises one as this probe's
    /// answer, or the deadline passes.
    ///
    /// Generic over the answer so that the ICMP path reuses the deadline, the
    /// buffer bound and the "a packet that is not ours is dropped rather than
    /// guessed at" rule rather than restating them.
    pub(crate) fn await_matching<T>(&mut self, matcher: impl Fn(&[u8]) -> Option<T>) -> Option<T> {
        let mut buf = [0u8; 256];
        let until = Instant::now().checked_add(self.deadline);
        while until.is_some_and(|at| Instant::now() < at) {
            if let Some(read) = self.wire.poll(&mut buf)
                && let Some(answer) = buf.get(..read).and_then(&matcher)
            {
                return Some(answer);
            }
        }
        None
    }

    /// Reads until something answers this SYN probe or the deadline passes.
    fn await_reply(&mut self, addr: Ipv4Addr, port: u16, sport: u16) -> Reply {
        self.await_matching(|packet| match_reply(packet, addr, port, sport))
            .unwrap_or(Reply::None)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::protocol::{Request, Response, Session};

    /// The address `source_for` reports, so the fixtures know which address a
    /// reply has to be sent back to.
    pub(crate) const HOST: Ipv4Addr = Ipv4Addr::new(10, 30, 0, 99);

    /// A wire that emits nothing and records everything, so "zero packets" is
    /// asserted where the packet would have left rather than inferred.
    ///
    /// `answer` is what makes the reply fixtures honest: it is handed the
    /// packet that was actually emitted and builds its reply out of *that*
    /// packet's own source port and addresses. The alternative -- a canned
    /// reply built from a re-derivation of the source port -- is a fixture
    /// that agrees with a copy of the code rather than with the code, and it
    /// silently stops matching the moment the derivation changes.
    /// How a fixture answers a probe: given the emitted SYN, the replies the
    /// network should produce.
    pub(crate) type Answer = fn(&[u8]) -> Vec<Vec<u8>>;

    #[derive(Debug, Default)]
    pub(crate) struct Recorder {
        pub(crate) sent: Vec<(Ipv4Addr, Vec<u8>)>,
        pub(crate) inbound: Vec<Vec<u8>>,
        pub(crate) answer: Option<Answer>,
    }

    impl Recorder {
        pub(crate) fn flags(&self) -> Vec<u8> {
            self.sent
                .iter()
                .filter_map(|(_, packet)| packet.get(33).copied())
                .collect()
        }
        pub(crate) fn rsts(&self) -> usize {
            self.flags().iter().filter(|f| **f & FLAG_RST != 0).count()
        }
    }

    impl Wire for Recorder {
        fn source_for(&self, _target: Ipv4Addr) -> std::io::Result<Ipv4Addr> {
            Ok(HOST)
        }
        fn emit(&mut self, packet: &[u8], target: Ipv4Addr) -> std::io::Result<()> {
            self.sent.push((target, packet.to_vec()));
            // Only a probe is answered, never a teardown RST -- and since M6
            // Task 5, "a probe" means a bare SYN *or* an ICMP echo request,
            // because both kinds now travel this wire.
            let is_probe = match packet.get(9).copied() {
                Some(PROTO_TCP) => packet.get(33).copied() == Some(FLAG_SYN),
                Some(PROTO_ICMP) => true,
                _ => false,
            };
            if let Some(answer) = self.answer
                && is_probe
            {
                self.inbound.extend(answer(packet));
            }
            Ok(())
        }
        fn poll(&mut self, buf: &mut [u8]) -> Option<usize> {
            let packet = self.inbound.pop()?;
            let room = buf.get_mut(..packet.len())?;
            room.copy_from_slice(&packet);
            Some(packet.len())
        }
    }

    /// The addresses and ports of a probe we emitted, read back off the wire.
    pub(crate) fn probe_fields(syn: &[u8]) -> (Ipv4Addr, Ipv4Addr, u16, u16) {
        let src: [u8; 4] = syn.get(12..16).unwrap().try_into().unwrap();
        let dst: [u8; 4] = syn.get(16..20).unwrap().try_into().unwrap();
        (
            Ipv4Addr::from(src),
            Ipv4Addr::from(dst),
            be16(syn, 20).unwrap(),
            be16(syn, 22).unwrap(),
        )
    }

    /// The target answers the probe it actually received, with `flags`.
    fn answer_tcp(syn: &[u8], flags: u8) -> Vec<Vec<u8>> {
        let (src, dst, sport, dport) = probe_fields(syn);
        vec![segment(dst, src, dport, sport, 0xdead_beef, flags)]
    }

    fn answer_syn_ack(syn: &[u8]) -> Vec<Vec<u8>> {
        answer_tcp(syn, FLAG_SYN | FLAG_ACK)
    }

    fn answer_rst(syn: &[u8]) -> Vec<Vec<u8>> {
        answer_tcp(syn, FLAG_RST | FLAG_ACK)
    }

    /// A router answers with a destination-unreachable quoting the probe, as
    /// RFC 792 requires -- the IP header and the first 8 bytes.
    fn answer_icmp_unreachable(syn: &[u8]) -> Vec<Vec<u8>> {
        let (src, _, _, _) = probe_fields(syn);
        let mut icmp: Vec<u8> = vec![ICMP_UNREACHABLE, 3, 0, 0, 0, 0, 0, 0];
        icmp.extend_from_slice(syn);
        let mut ip: Vec<u8> = vec![0x45, 0, 0, 0, 0, 0, 0x40, 0, TTL, PROTO_ICMP, 0, 0];
        ip.extend_from_slice(&Ipv4Addr::new(10, 30, 0, 1).octets());
        ip.extend_from_slice(&src.octets());
        ip.extend_from_slice(&icmp);
        vec![ip]
    }

    /// A shared recorder, so a test can read what the session emitted after
    /// the session has borrowed it.
    #[derive(Debug, Default, Clone)]
    pub(crate) struct Shared(pub(crate) std::rc::Rc<std::cell::RefCell<Recorder>>);

    impl Wire for Shared {
        fn source_for(&self, target: Ipv4Addr) -> std::io::Result<Ipv4Addr> {
            self.0.borrow().source_for(target)
        }
        fn emit(&mut self, packet: &[u8], target: Ipv4Addr) -> std::io::Result<()> {
            self.0.borrow_mut().emit(packet, target)
        }
        fn poll(&mut self, buf: &mut [u8]) -> Option<usize> {
            self.0.borrow_mut().poll(buf)
        }
    }

    /// A prober with a shortened reply deadline, so a test does not spend a
    /// second per probe waiting for a recorder that will never answer.
    pub(crate) fn prober_with(wire: Box<dyn Wire>, deadline: Duration) -> Prober {
        let mut prober = Prober::new(wire);
        prober.deadline = deadline;
        prober
    }

    pub(crate) fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    pub(crate) fn v4(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    /// A session scope built directly, without an `Init` line. The fields
    /// are `pub(crate)`, so this is the same value the protocol would build.
    pub(crate) fn scope_of(
        allowed: Vec<IpNet>,
        denied: Vec<IpNet>,
        packets_per_second: u32,
        max_packets: u64,
    ) -> SessionScope {
        SessionScope {
            allowed,
            denied,
            packets_per_second,
            max_packets,
        }
    }

    pub(crate) fn init(allow: &str, deny: &str, max: u64) -> String {
        format!(
            r#"{{"type":"init","allowed_cidrs":[{allow}],"denied_cidrs":[{deny}],
               "packets_per_second":100000,"max_packets":{max}}}"#
        )
    }

    /// A session wired to a recorder that answers nothing, with a zero reply
    /// deadline so silence is instant.
    pub(crate) fn session_with(allow: &str, deny: &str, max: u64) -> (Session, Shared) {
        let wire = Shared::default();
        let mut session = Session::new(true, Box::new(wire.clone()));
        session.set_reply_deadline(Duration::ZERO);
        assert!(matches!(
            session.handle_line(&init(allow, deny, max)),
            Some(Response::Ready { .. })
        ));
        (session, wire)
    }

    pub(crate) fn session_allowing(allow: &str) -> (Session, Shared) {
        session_with(&format!("\"{allow}\""), "", 1000)
    }

    // -- AC-6.9 -------------------------------------------------------------

    #[test]
    fn a_target_outside_the_session_allowlist_is_refused_without_emitting() {
        let (mut s, wire) = session_allowing("10.30.0.0/24");
        let r = s.handle_probe(1, ip("8.8.8.8"), 80);
        assert!(
            matches!(&r, Response::Refused { reason, .. }
                     if *reason == RefusalReason::OutOfSessionScope),
            "{r:?}"
        );
        assert_eq!(s.packets_emitted(), 0, "a refused probe must emit nothing");
        assert!(
            wire.0.borrow().sent.is_empty(),
            "nothing may reach the wire for a refused target"
        );
    }

    /// The narrowing control for the test above: the same session, the same
    /// call, an address that *is* in scope -- and now a packet does leave.
    /// Without this, a `handle_probe` that refused everything would pass.
    #[test]
    fn an_in_scope_target_does_emit_so_the_refusal_test_is_not_vacuous() {
        let (mut s, wire) = session_allowing("10.30.0.0/24");
        let r = s.handle_probe(1, ip("10.30.0.10"), 80);
        assert!(matches!(r, Response::Result { .. }), "{r:?}");
        assert_eq!(s.packets_emitted(), 1);
        assert_eq!(wire.0.borrow().sent.len(), 1);
        assert_eq!(
            wire.0.borrow().sent.first().map(|(to, _)| *to),
            Some(v4("10.30.0.10"))
        );
    }

    #[test]
    fn the_session_denylist_overrides_its_allowlist() {
        let (mut s, wire) = session_with("\"10.30.0.0/24\"", "\"10.30.0.1/32\"", 1000);
        let r = s.handle_probe(1, ip("10.30.0.1"), 80);
        assert!(matches!(r, Response::Refused { .. }), "{r:?}");
        assert_eq!(wire.0.borrow().sent.len(), 0);
        // The control: the neighbour the denylist does not name is allowed,
        // so the deny entry excludes exactly one address and not the subnet.
        assert!(matches!(
            s.handle_probe(2, ip("10.30.0.2"), 80),
            Response::Result { .. }
        ));
    }

    #[test]
    fn a_denied_subnet_beats_an_allowed_supernet_regardless_of_specificity() {
        let (mut s, _) = session_with("\"10.30.0.0/16\"", "\"10.30.7.0/24\"", 1000);
        assert!(matches!(
            s.handle_probe(1, ip("10.30.7.9"), 80),
            Response::Refused { .. }
        ));
        assert!(matches!(
            s.handle_probe(2, ip("10.30.8.9"), 80),
            Response::Result { .. }
        ));
    }

    // -- AC-6.10 ------------------------------------------------------------

    #[test]
    fn reserved_ranges_are_refused_even_if_the_allowlist_permits_them() {
        let (mut s, wire) = session_allowing("0.0.0.0/0");
        for bad in [
            "127.0.0.1",
            "224.0.0.1",
            "239.255.255.250",
            "255.255.255.255",
            "240.0.0.1",
            "169.254.1.1",
            "0.0.0.0",
            "0.1.2.3",
        ] {
            let r = s.handle_probe(1, ip(bad), 80);
            assert!(matches!(r, Response::Refused { .. }), "{bad}: {r:?}");
        }
        assert_eq!(
            wire.0.borrow().sent.len(),
            0,
            "AC-6.10: not one packet for any reserved address"
        );
        // The control that makes `0.0.0.0/0` mean something: an ordinary
        // address under the same allowlist is not refused, so these eight are
        // refused for being reserved and not because nothing is allowed.
        assert!(matches!(
            s.handle_probe(9, ip("198.51.100.7"), 80),
            Response::Result { .. }
        ));
    }

    #[test]
    fn the_reserved_boundaries_are_where_the_rfcs_put_them() {
        for reserved in [
            "0.255.255.255",
            "127.255.255.255",
            "224.0.0.0",
            "169.254.0.0",
        ] {
            assert!(is_reserved(v4(reserved)), "{reserved}");
        }
        for ordinary in [
            "1.0.0.0",
            "126.255.255.255",
            "128.0.0.1",
            "223.255.255.255",
            "169.253.255.255",
            "169.255.0.0",
        ] {
            assert!(!is_reserved(v4(ordinary)), "{ordinary}");
        }
    }

    // -- AC-6.11 ------------------------------------------------------------

    #[test]
    fn the_session_packet_ceiling_is_enforced_independently_of_the_engine() {
        let (mut s, wire) = session_with("\"10.30.0.0/24\"", "", 5);
        for i in 0..5 {
            let r = s.handle_probe(i, ip("10.30.0.2"), 80);
            assert!(!matches!(r, Response::Refused { .. }), "probe {i}: {r:?}");
        }
        let r = s.handle_probe(6, ip("10.30.0.2"), 80);
        assert!(
            matches!(&r, Response::Refused { reason, .. }
                     if *reason == RefusalReason::SessionBudgetExhausted),
            "{r:?}"
        );
        assert_eq!(
            wire.0.borrow().sent.len(),
            5,
            "the sixth probe must not reach the wire"
        );
    }

    /// The *order* of the two refusals, not merely their presence. Swapping
    /// them leaves every other assertion in this file passing and changes the
    /// reason the engine is given for an out-of-scope target once the budget
    /// is spent -- and scope is the first question a process holding
    /// `CAP_NET_RAW` has to ask, not the second.
    #[test]
    fn scope_is_decided_before_the_ceiling_is_consulted() {
        let (mut s, wire) = session_with("\"10.30.0.0/24\"", "", 1);
        assert!(matches!(
            s.handle_probe(1, ip("10.30.0.2"), 80),
            Response::Result { .. }
        ));
        // The budget is now spent, so both refusals apply to the next probe.
        // The one that must be reported is the scope refusal.
        let r = s.handle_probe(2, ip("8.8.8.8"), 80);
        assert!(
            matches!(&r, Response::Refused { reason, .. }
                     if *reason == RefusalReason::OutOfSessionScope),
            "an out-of-scope target must be refused for being out of scope, \
             whatever the budget says: {r:?}"
        );
        // The control: in scope, budget spent, so the budget is what answers.
        let r = s.handle_probe(3, ip("10.30.0.2"), 80);
        assert!(
            matches!(&r, Response::Refused { reason, .. }
                     if *reason == RefusalReason::SessionBudgetExhausted),
            "{r:?}"
        );
        assert_eq!(wire.0.borrow().sent.len(), 1);
    }

    // -- AC-6.12 ------------------------------------------------------------

    #[test]
    fn response_classification_matches_tcp_semantics() {
        assert_eq!(classify_reply(Reply::SynAck), PortState::Open);
        assert_eq!(classify_reply(Reply::Rst), PortState::Closed);
        assert_eq!(classify_reply(Reply::IcmpUnreachable), PortState::Filtered);
        assert_eq!(classify_reply(Reply::None), PortState::Filtered);
    }

    /// Drives one probe against a wire that answers with `answer`, and
    /// reports the state, the flags of every packet that reached the wire,
    /// and how many of them were RSTs.
    fn probe_answered_by(answer: Option<Answer>) -> (PortState, Vec<u8>, usize) {
        let wire = Shared::default();
        wire.0.borrow_mut().answer = answer;
        let mut prober = prober_with(Box::new(wire.clone()), Duration::from_millis(400));
        let scope = scope_of(vec!["10.30.0.0/24".parse().unwrap()], vec![], 100_000, 10);
        let state = prober
            .probe(&scope, ip("10.30.0.10"), 80)
            .expect("in scope and inside the ceiling");
        let recorder = wire.0.borrow();
        (state, recorder.flags(), recorder.rsts())
    }

    #[test]
    fn a_syn_ack_on_the_wire_reads_as_open() {
        let (state, _, _) = probe_answered_by(Some(answer_syn_ack));
        assert_eq!(state, PortState::Open);
    }

    #[test]
    fn an_rst_on_the_wire_reads_as_closed() {
        let (state, flags, rsts) = probe_answered_by(Some(answer_rst));
        assert_eq!(state, PortState::Closed);
        assert_eq!(rsts, 0, "a closed port has nothing to tear down");
        assert_eq!(flags, vec![FLAG_SYN]);
    }

    #[test]
    fn silence_past_the_deadline_reads_as_filtered() {
        let (state, flags, _) = probe_answered_by(None);
        assert_eq!(state, PortState::Filtered);
        assert_eq!(flags, vec![FLAG_SYN]);
    }

    /// `Filtered` like silence is -- but it arrived. The narrowing control is
    /// the wall clock: an implementation that ignored ICMP would reach the
    /// same verdict only by waiting out the whole deadline, so this asserts
    /// the answer came back fast as well as that it came back `Filtered`.
    #[test]
    fn an_icmp_unreachable_reads_as_filtered_and_is_not_merely_silence() {
        let started = Instant::now();
        let (state, flags, _) = probe_answered_by(Some(answer_icmp_unreachable));
        assert_eq!(state, PortState::Filtered);
        assert_eq!(flags, vec![FLAG_SYN], "an unreachable is not torn down");
        assert!(
            started.elapsed() < Duration::from_millis(400),
            "the unreachable was not recognised; this is the silence path \
             wearing its answer, and it took {:?}",
            started.elapsed()
        );
    }

    /// Only ICMP type 3 is an unreachable. A packet of another type quoting
    /// the same probe says something else entirely -- a time exceeded is a
    /// routing loop, an echo reply is Task 5's business -- and reading any of
    /// them as "unreachable" would put a `Filtered` on a port nothing refused.
    #[test]
    fn only_a_destination_unreachable_is_read_as_one() {
        let syn = one_emitted_syn();
        let sport = be16(&syn, 20).unwrap();
        let mut unreachable = answer_icmp_unreachable(&syn).pop().unwrap();
        assert_eq!(
            match_reply(&unreachable, v4("10.30.0.10"), 80, sport),
            Some(Reply::IcmpUnreachable),
            "the control: type 3 quoting this probe"
        );
        for other_type in [0u8, 8, 11, 12] {
            if let Some(field) = unreachable.get_mut(20) {
                *field = other_type;
            }
            assert_eq!(
                match_reply(&unreachable, v4("10.30.0.10"), 80, sport),
                None,
                "ICMP type {other_type} is not a destination unreachable"
            );
        }
    }

    /// The checksum, against an oracle this code did not produce: the worked
    /// example in RFC 1071 section 3. Checking `checksum` by feeding it a
    /// header `checksum` already stamped is self-consistent and stays green
    /// when the algorithm is wrong in both directions at once -- the carry
    /// fold deleted survived exactly that, until this test existed.
    #[test]
    fn the_checksum_matches_rfc_1071s_worked_example() {
        assert_eq!(
            checksum(&[0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7]),
            0x220d
        );
        // An odd trailing byte is padded with zero, not dropped.
        assert_ne!(checksum(&[0x00, 0x01, 0xf2]), checksum(&[0x00, 0x01]));
        assert_eq!(
            checksum(&[0x00, 0x01, 0xf2]),
            checksum(&[0x00, 0x01, 0xf2, 0x00])
        );
    }

    /// A reply carrying IP options. Every other fixture here has a 20-byte
    /// header, so a `payload` that ignored the IHL and assumed 20 would pass
    /// all of them and mis-read every packet from a stack that uses options.
    #[test]
    fn a_reply_with_ip_options_is_parsed_at_the_offset_its_header_declares() {
        let syn = one_emitted_syn();
        let sport = be16(&syn, 20).unwrap();
        let plain = answer_syn_ack(&syn).pop().unwrap();
        let mut with_options = plain.clone();
        // IHL 6 words, and four bytes of no-op options spliced in after the
        // fixed header.
        if let Some(byte) = with_options.get_mut(0) {
            *byte = 0x46;
        }
        for (at, value) in [(20usize, 1u8), (20, 1), (20, 1), (20, 1)] {
            with_options.insert(at, value);
        }
        assert_eq!(
            match_reply(&plain, v4("10.30.0.10"), 80, sport),
            Some(Reply::SynAck),
            "the control: the same reply without options"
        );
        assert_eq!(
            match_reply(&with_options, v4("10.30.0.10"), 80, sport),
            Some(Reply::SynAck),
            "a header of 24 bytes puts the TCP header at 24, not at 20"
        );
    }

    /// A bare SYN is not a SYN-ACK. Reading one as `Open` would report a port
    /// open on the strength of a packet that acknowledged nothing -- a stray
    /// SYN, or a simultaneous open, answering a question nobody asked.
    #[test]
    fn a_reply_must_acknowledge_before_it_can_mean_open() {
        let syn = one_emitted_syn();
        let sport = be16(&syn, 20).unwrap();
        let mut reply = answer_syn_ack(&syn).pop().unwrap();
        assert_eq!(
            match_reply(&reply, v4("10.30.0.10"), 80, sport),
            Some(Reply::SynAck),
            "the control"
        );
        if let Some(flags) = reply.get_mut(33) {
            *flags = FLAG_SYN;
        }
        assert_eq!(
            match_reply(&reply, v4("10.30.0.10"), 80, sport),
            None,
            "a SYN with no ACK says nothing about this probe"
        );
    }

    /// An unreachable is attributed by the datagram it *quotes*, not by the
    /// address it came from -- a router sends it, so the source address is
    /// nobody's business. A stray unreachable for somebody else's traffic
    /// must not mark this probe's port `Filtered`.
    #[test]
    fn an_unreachable_quoting_a_different_datagram_is_not_ours() {
        let syn = one_emitted_syn();
        let sport = be16(&syn, 20).unwrap();
        let ours = answer_icmp_unreachable(&syn).pop().unwrap();
        assert_eq!(
            match_reply(&ours, v4("10.30.0.10"), 80, sport),
            Some(Reply::IcmpUnreachable),
            "the control: an unreachable quoting this probe"
        );
        // The quoted datagram, with each attributing field wrong in turn. The
        // quote starts 28 bytes in (20 IP + 8 ICMP), so the quoted source
        // port is at 48 and the quoted destination port at 50.
        for (at, field) in [(48usize, "source port"), (50, "destination port")] {
            let mut stray = ours.clone();
            if let Some(bytes) = stray.get_mut(at..at.saturating_add(2)) {
                bytes.copy_from_slice(&9999u16.to_be_bytes());
            }
            assert_eq!(
                match_reply(&stray, v4("10.30.0.10"), 80, sport),
                None,
                "an unreachable quoting a different {field} is not this probe's"
            );
        }
        // And one quoting a datagram sent to a different host.
        let mut elsewhere = ours;
        if let Some(bytes) = elsewhere.get_mut(44..48) {
            bytes.copy_from_slice(&v4("10.30.0.11").octets());
        }
        assert_eq!(match_reply(&elsewhere, v4("10.30.0.10"), 80, sport), None);
    }

    /// A local failure is `Indeterminate`, never `Filtered`. `Filtered` is a
    /// claim about the network, and a `sendto` that failed means this process
    /// never reached the network to have an opinion about it.
    #[test]
    fn a_send_that_fails_is_indeterminate_rather_than_filtered() {
        #[derive(Debug)]
        struct Broken {
            route: bool,
        }
        impl Wire for Broken {
            fn source_for(&self, _target: Ipv4Addr) -> std::io::Result<Ipv4Addr> {
                if self.route {
                    Ok(HOST)
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
        let scope = scope_of(vec!["10.30.0.0/24".parse().unwrap()], vec![], 100_000, 10);
        for route in [true, false] {
            let mut prober = prober_with(Box::new(Broken { route }), Duration::ZERO);
            assert_eq!(
                prober.probe(&scope, ip("10.30.0.10"), 80),
                Ok(PortState::Indeterminate),
                "route={route}"
            );
            assert_eq!(prober.packets_emitted(), 0, "nothing reached the wire");
        }
        // The control: the same probe over a wire that works is not
        // `Indeterminate`, so the assertion above is about the failure and
        // not about the code path always saying so.
        let wire = Shared::default();
        let mut prober = prober_with(Box::new(wire), Duration::ZERO);
        assert_eq!(
            prober.probe(&scope, ip("10.30.0.10"), 80),
            Ok(PortState::Filtered)
        );
    }

    /// A probe emitted for real, so the reply-matching tests below are fed the
    /// bytes the code actually produces rather than a hand-written imitation.
    fn one_emitted_syn() -> Vec<u8> {
        let wire = Shared::default();
        let mut prober = prober_with(Box::new(wire.clone()), Duration::ZERO);
        let scope = scope_of(vec!["10.30.0.0/24".parse().unwrap()], vec![], 100_000, 10);
        let _ = prober.probe(&scope, ip("10.30.0.10"), 80);
        let recorder = wire.0.borrow();
        recorder
            .sent
            .first()
            .map(|(_, p)| p.clone())
            .expect("one packet")
    }

    #[test]
    fn a_reply_for_a_different_probe_is_not_attributed_to_this_one() {
        let syn = one_emitted_syn();
        let sport = be16(&syn, 20).unwrap();
        let reply = answer_syn_ack(&syn).pop().unwrap();
        assert_eq!(
            match_reply(&reply, v4("10.30.0.10"), 80, sport),
            Some(Reply::SynAck),
            "the control: the reply this probe actually earned"
        );
        // Each of the three fields that attribute a reply, wrong in turn.
        assert_eq!(match_reply(&reply, v4("10.30.0.10"), 80, sport ^ 1), None);
        assert_eq!(match_reply(&reply, v4("10.30.0.11"), 80, sport), None);
        assert_eq!(match_reply(&reply, v4("10.30.0.10"), 81, sport), None);
    }

    #[test]
    fn a_truncated_packet_is_dropped_rather_than_panicking() {
        let syn = one_emitted_syn();
        let sport = be16(&syn, 20).unwrap();
        for full in [
            answer_syn_ack(&syn).pop().unwrap(),
            answer_icmp_unreachable(&syn).pop().unwrap(),
        ] {
            assert!(
                match_reply(&full, v4("10.30.0.10"), 80, sport).is_some(),
                "the whole packet must match, or the cuts below range over nothing"
            );
            for cut in 0..full.len() {
                let _ = match_reply(full.get(..cut).unwrap(), v4("10.30.0.10"), 80, sport);
            }
        }
    }

    // -- AC-6.13 ------------------------------------------------------------

    #[test]
    fn an_open_port_receives_a_rst_so_no_half_open_connection_is_left_behind() {
        let (state, flags, rsts) = probe_answered_by(Some(answer_syn_ack));
        assert_eq!(state, PortState::Open);
        assert_eq!(
            rsts, 1,
            "a SYN-ACK must be answered with RST, not abandoned"
        );
        assert_eq!(
            flags,
            vec![FLAG_SYN, FLAG_RST],
            "the SYN first, then the teardown, and nothing else"
        );
    }

    /// The teardown RST carries the sequence number the SYN-ACK acknowledged
    /// and is addressed to the same endpoint as the SYN. An RST outside the
    /// target's receive window is discarded, which would leave the half-open
    /// connection this criterion exists to close.
    #[test]
    fn the_teardown_rst_is_addressed_and_sequenced_to_close_the_connection() {
        let wire = Shared::default();
        wire.0.borrow_mut().answer = Some(answer_syn_ack);
        let mut prober = prober_with(Box::new(wire.clone()), Duration::from_millis(400));
        let scope = scope_of(vec!["10.30.0.0/24".parse().unwrap()], vec![], 100_000, 10);
        assert_eq!(
            prober.probe(&scope, ip("10.30.0.10"), 80),
            Ok(PortState::Open)
        );
        let recorder = wire.0.borrow();
        let syn = recorder.sent.first().map(|(_, p)| p.clone()).unwrap();
        let (to, rst) = recorder.sent.get(1).cloned().unwrap();
        assert_eq!(to, v4("10.30.0.10"));
        assert_eq!(rst.get(33).copied(), Some(FLAG_RST));
        assert_eq!(be16(&rst, 20), be16(&syn, 20), "same source port");
        assert_eq!(be16(&rst, 22), Some(80));
        let syn_seq = u32::from_be_bytes(syn.get(24..28).unwrap().try_into().unwrap());
        let rst_seq = u32::from_be_bytes(rst.get(24..28).unwrap().try_into().unwrap());
        assert_eq!(rst_seq, syn_seq.wrapping_add(1));
        assert_eq!(be16(&rst, 4), Some(PROBE_MARKER), "ours, not the kernel's");
    }

    #[test]
    fn at_the_ceiling_an_open_ports_teardown_rst_is_still_sent() {
        let wire = Shared::default();
        wire.0.borrow_mut().answer = Some(answer_syn_ack);
        let mut prober = prober_with(Box::new(wire.clone()), Duration::from_millis(400));
        let scope = scope_of(vec!["10.30.0.0/24".parse().unwrap()], vec![], 100_000, 1);
        assert_eq!(
            prober.probe(&scope, ip("10.30.0.10"), 80),
            Ok(PortState::Open)
        );
        assert_eq!(wire.0.borrow().rsts(), 1);
        assert_eq!(
            prober.packets_emitted(),
            2,
            "the ceiling of 1 admitted one probe; the RST is exempt and counted"
        );
        assert_eq!(
            prober.probe(&scope, ip("10.30.0.11"), 80),
            Err(RefusalReason::SessionBudgetExhausted)
        );
    }

    // -- the emitted packet itself -------------------------------------------

    #[test]
    fn a_probe_is_a_well_formed_syn_carrying_the_marker() {
        let (mut s, wire) = session_allowing("10.30.0.0/24");
        s.handle_probe(1, ip("10.30.0.10"), 80);
        let recorder = wire.0.borrow();
        let (_, packet) = recorder.sent.first().expect("one packet");
        assert_eq!(packet.len(), 40);
        assert_eq!(packet.first().copied(), Some(0x45));
        assert_eq!(be16(packet, 2), Some(40));
        assert_eq!(be16(packet, 4), Some(PROBE_MARKER));
        // Non-zero, and this is not a taste question. Linux fills in the IP
        // identification field on an `IP_HDRINCL` socket **when it is zero**,
        // so a marker of 0 is a marker the kernel overwrites -- and the whole
        // reason it exists is to tell our teardown RST from the one the
        // kernel sends on its own account, which carries id 0. A zero marker
        // makes `tests/wire.rs` attribute the kernel's packets to us.
        assert_ne!(PROBE_MARKER, 0, "a zero IP id is filled in by the kernel");
        assert_eq!(packet.get(9).copied(), Some(PROTO_TCP));
        assert_eq!(be16(packet, 22), Some(80));
        assert_eq!(packet.get(33).copied(), Some(FLAG_SYN));
        // Data offset 5 words. This segment carries no options, and a header
        // length that disagrees with the bytes present is a segment the
        // target's stack discards -- silently, as a `Filtered` we would then
        // report about a port we never actually reached.
        assert_eq!(packet.get(32).copied(), Some(0x50), "data offset");
        assert_eq!(be16(packet, 34), Some(1024), "window");
        assert_eq!(
            packet.get(28..32),
            Some([0u8, 0, 0, 0].as_slice()),
            "a SYN acknowledges nothing"
        );
        // The checksums a target will verify. `checksum` over a header that
        // already carries its own checksum is zero when it is correct.
        assert_eq!(checksum(packet.get(..20).unwrap()), 0, "IP checksum");
        let mut pseudo: Vec<u8> = packet.get(12..20).unwrap().to_vec();
        pseudo.extend_from_slice(&[0, PROTO_TCP, 0, 20]);
        pseudo.extend_from_slice(packet.get(20..).unwrap());
        assert_eq!(checksum(&pseudo), 0, "TCP checksum");
    }

    #[test]
    fn source_ports_come_from_below_the_ephemeral_range_and_differ_per_probe() {
        let (mut s, wire) = session_allowing("10.30.0.0/24");
        for i in 0..4 {
            s.handle_probe(i, ip("10.30.0.10"), 80);
        }
        let recorder = wire.0.borrow();
        let ports: Vec<u16> = recorder
            .sent
            .iter()
            .filter_map(|(_, p)| be16(p, 20))
            .collect();
        assert_eq!(ports.len(), 4);
        for port in &ports {
            assert!(
                (SOURCE_PORT_BASE..32768).contains(port),
                "{port} is inside the kernel's ephemeral range"
            );
        }
        let unique: std::collections::BTreeSet<u16> = ports.iter().copied().collect();
        assert_eq!(unique.len(), 4, "each probe needs its own source port");
    }

    #[test]
    fn the_session_rate_paces_emission() {
        let wire = Shared::default();
        let mut prober = prober_with(Box::new(wire.clone()), Duration::ZERO);
        let scope = scope_of(vec!["10.30.0.0/24".parse().unwrap()], vec![], 4, 10);
        let started = Instant::now();
        for _ in 0..3 {
            let _ = prober.probe(&scope, ip("10.30.0.10"), 80);
        }
        // Three packets at 4/s is two gaps of 250 ms. A lower bound only:
        // an upper bound on a shared machine is a flaky test.
        assert!(
            started.elapsed() >= Duration::from_millis(500),
            "three packets at 4/s took {:?}",
            started.elapsed()
        );
    }

    // -- the protocol seam ---------------------------------------------------

    #[test]
    fn a_probe_before_init_is_still_fatal_and_emits_nothing() {
        let wire = Shared::default();
        let mut session = Session::new(true, Box::new(wire.clone()));
        session.set_reply_deadline(Duration::ZERO);
        let line = r#"{"type":"probe","id":1,"target":"10.30.0.10","port":80}"#;
        assert!(matches!(
            session.handle_line(line),
            Some(Response::Fatal { .. })
        ));
        assert_eq!(wire.0.borrow().sent.len(), 0);
    }

    /// The guard inside `handle_probe` itself. `dispatch` refuses a probe
    /// before `init` on its own arm, so this one is only reachable by a
    /// caller inside this crate -- and it survived a mutation that replaced
    /// it with an ordinary refusal until this test existed. A privileged
    /// process asked to emit before it knows its scope must stop, not answer.
    #[test]
    fn handle_probe_called_directly_before_init_is_fatal_and_emits_nothing() {
        let wire = Shared::default();
        let mut session = Session::new(true, Box::new(wire.clone()));
        session.set_reply_deadline(Duration::ZERO);
        let response = session.handle_probe(1, ip("10.30.0.10"), 80);
        assert!(matches!(response, Response::Fatal { .. }), "{response:?}");
        assert!(session.is_terminated() && session.ended_fatally());
        assert_eq!(wire.0.borrow().sent.len(), 0);
        // And after a clean shutdown, which is a terminated session that was
        // never fatal -- the other way into that guard.
        let (mut after, wire) = session_allowing("10.30.0.0/24");
        assert_eq!(after.handle_line(r#"{"type":"shutdown"}"#), None);
        let response = after.handle_probe(2, ip("10.30.0.10"), 80);
        assert!(matches!(response, Response::Fatal { .. }), "{response:?}");
        assert_eq!(wire.0.borrow().sent.len(), 0);
    }

    #[test]
    fn a_probe_line_takes_the_same_path_as_handle_probe() {
        let (mut s, wire) = session_allowing("10.30.0.0/24");
        let line = r#"{"type":"probe","id":7,"target":"8.8.8.8","port":80}"#;
        let r = s.handle_line(line);
        assert!(
            matches!(&r, Some(Response::Refused { id: 7, reason })
                     if *reason == RefusalReason::OutOfSessionScope),
            "{r:?}"
        );
        assert_eq!(wire.0.borrow().sent.len(), 0);
        assert!(!s.is_terminated(), "a refusal is about one probe");
    }

    #[test]
    fn the_request_type_still_round_trips() {
        let line = r#"{"type":"probe","id":1,"target":"10.30.0.10","port":80}"#;
        let parsed: Request = serde_json::from_str(line).unwrap();
        assert_eq!(
            parsed,
            Request::Probe {
                id: 1,
                target: ip("10.30.0.10"),
                port: 80
            }
        );
    }

    // -- covers() ------------------------------------------------------------

    #[test]
    fn covers_masks_at_the_prefix_length() {
        let net = |s: &str| s.parse::<IpNet>().unwrap();
        assert!(covers(&net("0.0.0.0/0"), v4("1.2.3.4")));
        assert!(covers(&net("10.30.0.5/32"), v4("10.30.0.5")));
        assert!(!covers(&net("10.30.0.5/32"), v4("10.30.0.6")));
        assert!(covers(&net("10.30.0.0/24"), v4("10.30.0.255")));
        assert!(!covers(&net("10.30.0.0/24"), v4("10.30.1.0")));
        assert!(covers(&net("10.30.0.0/23"), v4("10.30.1.0")));
        // A host-bit-set CIDR must match on its network, not on its literal.
        assert!(covers(&net("10.30.0.7/24"), v4("10.30.0.1")));
        // An IPv6 net never covers an IPv4 address.
        assert!(!covers(&net("::/0"), v4("1.2.3.4")));
    }

    // -- the cross-check against `bathy-scope` -------------------------------

    /// A `bathy-scope` manifest with the same allow and deny sets.
    fn scope_manifest(allow: &[String], deny: &[String]) -> bathy_scope::ScopeManifest {
        let quote = |v: &[String]| {
            v.iter()
                .map(|c| format!("\"{c}\""))
                .collect::<Vec<_>>()
                .join(",")
        };
        let json = format!(
            r#"{{"id":"scope_01K0000000000000000000000A","description":"cross-check",
                 "not_after":"2099-01-01T00:00:00.000Z",
                 "allowed_cidrs":[{}],"denied_cidrs":[{}],
                 "budget_ceiling":{{"maximum_packets":1000,"maximum_runtime_seconds":60,
                 "maximum_packets_per_second":100}}}}"#,
            quote(allow),
            quote(deny)
        );
        bathy_scope::ScopeManifest::load(&json).expect("a well-formed manifest")
    }

    /// One case of the cross-check, so it can be driven by the property test
    /// *and* by the table below that proves the property reaches both
    /// verdicts. Returns what each implementation decided.
    fn both_verdicts(allow: &str, deny: &str, addr: Ipv4Addr) -> (bool, bool) {
        let scope = scope_of(
            vec![allow.parse().unwrap()],
            vec![deny.parse().unwrap()],
            1000,
            1000,
        );
        let ours = check_session_scope(&scope, IpAddr::V4(addr)).is_ok();
        let theirs =
            scope_manifest(&[allow.to_string()], &[deny.to_string()]).allows(IpAddr::V4(addr));
        (ours, theirs)
    }

    /// The property test below generates prefixes and addresses, and most
    /// random pairs miss: a run in which *nothing* was ever allowed would
    /// prove only that both implementations can say no. This walks the cases
    /// by hand and asserts each verdict is reached, and reached by both.
    #[test]
    fn the_cross_check_reaches_an_allowed_verdict_and_a_refused_one() {
        let cases = [
            ("10.30.0.0/24", "10.30.0.1/32", v4("10.30.0.2"), true),
            ("10.30.0.0/24", "10.30.0.1/32", v4("10.30.0.1"), false),
            ("10.30.0.0/24", "10.30.0.1/32", v4("10.31.0.2"), false),
            ("0.0.0.0/0", "255.255.255.255/32", v4("8.8.8.8"), true),
            ("0.0.0.0/0", "255.255.255.255/32", v4("127.0.0.1"), false),
            ("0.0.0.0/0", "255.255.255.255/32", v4("224.0.0.1"), false),
            ("0.0.0.0/0", "255.255.255.255/32", v4("169.254.1.1"), false),
            ("0.0.0.0/0", "255.255.255.255/32", v4("0.1.2.3"), false),
        ];
        let mut allowed = 0usize;
        for (allow, deny, addr, expected) in cases {
            let (ours, theirs) = both_verdicts(allow, deny, addr);
            assert_eq!(ours, expected, "packetd on {addr} under {allow}/{deny}");
            assert_eq!(
                theirs, expected,
                "bathy-scope on {addr} under {allow}/{deny}"
            );
            if ours {
                allowed = allowed.saturating_add(1);
            }
        }
        assert!(allowed >= 2, "the table must contain allowed cases too");
    }

    /// Addresses biased towards the boundaries where two implementations of
    /// one policy are most likely to disagree.
    ///
    /// A uniform `[u8; 4]` reaches `100.64.0.0/10` -- to pick the range that
    /// actually caught this -- about once in a thousand cases, so a
    /// divergence confined to it survived the cross-check on luck. Two
    /// implementations agreeing on random addresses is a much weaker
    /// statement than two implementations agreeing on the edges of every
    /// range either of them special-cases.
    fn interesting_address() -> impl proptest::strategy::Strategy<Value = Ipv4Addr> {
        use proptest::prelude::*;
        let octet = |edges: Vec<u8>| {
            prop_oneof![
                3 => proptest::sample::select(edges),
                1 => any::<u8>(),
            ]
        };
        (
            octet(vec![
                0, 1, 9, 10, 100, 126, 127, 128, 169, 172, 192, 198, 223, 224, 239, 240, 255,
            ]),
            octet(vec![0, 63, 64, 127, 128, 253, 254, 255]),
            any::<u8>(),
            any::<u8>(),
        )
            .prop_map(|(a, b, c, d)| Ipv4Addr::new(a, b, c, d))
    }

    proptest::proptest! {
        // 1024 rather than the default 256: the cross-check is the only test
        // here whose value is in how much of the address space it covers, and
        // a divergence confined to one /10 survived it at 256.
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(1024))]

        /// Two implementations of one policy are worth nothing unless somebody
        /// checks that they agree. This drives generated CIDRs and generated
        /// addresses through *both* `check_session_scope` and a real
        /// `bathy_scope::ScopeManifest::allows`, and fails on any
        /// disagreement -- which would be a finding in whichever one is wrong.
        ///
        /// The allow prefix is generated *from the target's own octets* half
        /// the time, so the generated cases actually reach the allowed
        /// branch rather than bouncing off a prefix that could never match;
        /// `the_cross_check_reaches_an_allowed_verdict_and_a_refused_one`
        /// above is the fixed table that says so without depending on luck.
        #[test]
        fn the_two_scope_implementations_agree_on_every_generated_address(
            target in interesting_address(),
            allow_octets in proptest::array::uniform4(0u8..=255),
            allow_prefix in 0u8..=32,
            allow_from_target in proptest::bool::ANY,
            deny_octets in proptest::array::uniform4(0u8..=255),
            deny_prefix in 0u8..=32,
            deny_from_target in proptest::bool::ANY,
        ) {
            let addr = target;
            let base = |from_target: bool, octets: [u8; 4]| {
                if from_target { addr } else { Ipv4Addr::from(octets) }
            };
            let allow = format!("{}/{allow_prefix}", base(allow_from_target, allow_octets));
            let deny = format!("{}/{deny_prefix}", base(deny_from_target, deny_octets));
            let (ours, theirs) = both_verdicts(&allow, &deny, addr);
            proptest::prop_assert_eq!(
                ours, theirs,
                "packetd and bathy-scope disagree about {} under allow={} deny={}",
                addr, allow, deny
            );
        }

        /// The same question for IPv6, where both refuse everything: `packetd`
        /// because its sockets are IPv4 and v0.1 does not scan IPv6, and
        /// `bathy-scope` by the v0.1 scope decision in `is_ordinary_unicast`.
        #[test]
        fn neither_implementation_ever_permits_an_ipv6_target(
            segments in proptest::array::uniform8(0u16..=u16::MAX),
        ) {
            let scope = scope_of(
                vec!["0.0.0.0/0".parse().unwrap(), "::/0".parse().unwrap()],
                vec![],
                1000,
                1000,
            );
            let addr = IpAddr::V6(std::net::Ipv6Addr::from(segments));
            proptest::prop_assert!(check_session_scope(&scope, addr).is_err());
            proptest::prop_assert!(
                !scope_manifest(&["0.0.0.0/0".to_string()], &[]).allows(addr)
            );
        }
    }
}
