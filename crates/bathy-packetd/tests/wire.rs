//! AC-6.9, AC-6.12 and AC-6.13 established **on the wire**, by a second raw
//! socket that watches what this process actually put on it.
//!
//! # Why counting at the socket is not enough
//!
//! `syn.rs`'s unit tests count emissions at the `Wire` boundary, which is
//! where a packet would leave. That is the right place to make a refusal
//! testable, and it is not the same claim as "nothing reached the network":
//! a `Wire` implementation that lied, or a `sendto` nobody checked, would
//! satisfy it. So this file asks the kernel instead. It opens its own
//! `AF_INET`/`SOCK_RAW` socket -- the same thing `tcpdump` reads, one layer
//! up -- and asserts over the packets that were really delivered.
//!
//! # The address these tests probe, and why it is this host
//!
//! Every target here is **this container's own primary address**. A packet
//! sent to it is routed through `lo` and therefore delivered locally, which
//! is what makes it visible to a raw socket at all: an `AF_INET` raw socket
//! receives *inbound* packets, so a probe at an off-host address would be
//! unobservable from here and "zero packets seen" would be vacuous. Probing
//! this host keeps every assertion in this file a real observation.
//!
//! It also means the refusal cases have to be refusals of a **local** target
//! -- one denied by the session denylist, and one reserved -- because those
//! are the ones where an emitted packet would have been seen. A refusal test
//! aimed somewhere unobservable would pass over an implementation that
//! emitted freely.
//!
//! # Telling our RST from the kernel's
//!
//! When the SYN-ACK comes back for a source port the host kernel has no
//! socket on, the kernel sends an RST of its own, with the same sequence
//! number ours carries. Every packet `packetd` emits carries
//! [`bathy_packetd::PROBE_MARKER`] in its IP identification field, and every
//! assertion below filters on it -- so "the RST was observed" is a claim
//! about a packet this code sent, and not one the kernel sent on its behalf.

#![cfg(target_os = "linux")]

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

use bathy_packetd::protocol::{HostState, PortState, RefusalReason, Response, Session};
use bathy_packetd::{PROBE_MARKER, acquire_raw_sockets};
use socket2::{Domain, Protocol, Socket, Type};

/// Set to `1` by `cargo run -p xtask -- packetd-privileged`. Its only job is
/// to turn a skip into a failure: a privileged test that silently does
/// nothing on an unprivileged machine is how a suite comes to report coverage
/// it does not have.
const DEMAND: &str = "BATHY_PACKETD_PRIVILEGED_TESTS";

const FLAG_SYN: u8 = 0x02;
const FLAG_RST: u8 = 0x04;

fn announce(reason: &str) {
    // `write_all`, not a print macro: libtest throws away the capture for a
    // test that passes, and a test that returns early passes.
    let mut stderr = std::io::stderr();
    let _ = stderr.write_all(reason.as_bytes());
    let _ = stderr.write_all(b"\n");
    let _ = stderr.flush();
}

/// A raw socket this process can watch the wire with, or `None` when it has
/// no `CAP_NET_RAW` -- in which case nothing in this file can run at all.
fn sniffer(test: &str) -> Option<Socket> {
    sniffer_for(test, 6)
}

/// The same, listening on one IP protocol number: 6 for the SYN tests, 1 for
/// the ICMP one. An `AF_INET` raw socket is bound to a protocol, so a TCP
/// sniffer sees no ICMP at all and "no ICMP was emitted" over one would be
/// vacuous.
fn sniffer_for(test: &str, protocol: i32) -> Option<Socket> {
    let opened = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::from(protocol)));
    let demanded = std::env::var(DEMAND).as_deref() == Ok("1");
    match opened {
        Ok(socket) => {
            socket
                .set_read_timeout(Some(Duration::from_millis(20)))
                .expect("a read timeout on a socket this process just opened");
            Some(socket)
        }
        Err(e) => {
            assert!(
                !demanded,
                "{DEMAND}=1 was set, so {test} must run, but opening a raw socket failed: {e}. \
                 Run it under `cargo run -p xtask -- packetd-privileged`."
            );
            announce(&format!(
                "PRECONDITION ABSENT: {test} needs CAP_NET_RAW to watch the wire and this \
                 process has none ({e}). It did not run. `cargo run -p xtask -- \
                 packetd-privileged` runs this file in a container that has it."
            ));
            None
        }
    }
}

/// This host's primary IPv4 address, from the kernel's own routing table.
/// Connecting a UDP socket sends nothing; it is a route lookup.
fn this_host() -> Ipv4Addr {
    let route = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).expect("a UDP socket");
    route
        .connect(SocketAddr::from((Ipv4Addr::new(198, 51, 100, 1), 9)))
        .expect("a default route");
    match route.local_addr().expect("a local address").ip() {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(v6) => panic!("this host routes IPv4 through {v6}"),
    }
}

/// Every packet the sniffer has queued, read until it goes quiet.
fn drain(sniffer: &Socket, quiet_for: Duration) -> Vec<Vec<u8>> {
    let mut packets = Vec::new();
    let mut last = Instant::now();
    let mut buf = [0u8; 512];
    while last.elapsed() < quiet_for {
        match Read::read(&mut { sniffer }, &mut buf) {
            Ok(read) if read > 0 => {
                packets.push(buf[..read].to_vec());
                last = Instant::now();
            }
            _ => {}
        }
    }
    packets
}

fn be16(bytes: &[u8], at: usize) -> u16 {
    u16::from_be_bytes(bytes[at..at + 2].try_into().unwrap_or([0, 0]))
}

/// The packets in `captured` that this process emitted *for the probe of
/// `port`*: IP identification equal to the marker, destination port equal to
/// the one under test.
///
/// Both halves are load-bearing. The marker excludes the kernel's own RSTs
/// and everything else on this host's wire, and the port excludes the other
/// tests in this file -- libtest runs them concurrently in one process, and a
/// raw socket sees every packet delivered to the host, so a filter on the
/// marker alone would attribute another test's SYN to this one. That is not
/// hypothetical: it is how the first run of this file failed.
fn ours(captured: &[Vec<u8>], port: u16) -> Vec<&Vec<u8>> {
    captured
        .iter()
        .filter(|packet| {
            packet.len() >= 40 && be16(packet, 4) == PROBE_MARKER && be16(packet, 22) == port
        })
        .collect()
}

fn init_line(allow: &str, deny: &str) -> String {
    format!(
        r#"{{"type":"init","allowed_cidrs":[{allow}],"denied_cidrs":[{deny}],"packets_per_second":1000,"max_packets":100}}"#
    )
}

/// A session over the real raw sockets, initialized with the given scope.
fn session(allow: &str, deny: &str) -> Session {
    let sockets = acquire_raw_sockets().expect("CAP_NET_RAW, checked by the caller");
    let mut session = Session::new(true, Box::new(sockets));
    let ready = session.handle_line(&init_line(allow, deny));
    assert!(
        matches!(ready, Some(Response::Ready { .. })),
        "the fixture must start from an accepted init, got {ready:?}"
    );
    session
}

/// A port on this host that nothing is listening on, determined by asking:
/// a `connect` that is refused is a closed port, not a guess. Binding a
/// listener and dropping it would be the flaky shape `check-fixtures` names.
fn a_refused_port(host: Ipv4Addr) -> u16 {
    for port in 39000..39100 {
        match TcpStream::connect_timeout(
            &SocketAddr::from((host, port)),
            Duration::from_millis(100),
        ) {
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionRefused => return port,
            _ => continue,
        }
    }
    panic!("no refused port found in 39000..39100 on {host}");
}

/// The echo requests in `captured` that this process emitted: the marker, the
/// ICMP protocol, type 8, and this host as the destination.
///
/// The marker excludes the host's own `ping` and everything else on the wire;
/// nothing else in this file emits ICMP, so unlike [`ours`] there is no port
/// to disambiguate concurrent tests with.
fn our_echo_requests(captured: &[Vec<u8>], to: Ipv4Addr) -> Vec<&Vec<u8>> {
    captured
        .iter()
        .filter(|packet| {
            packet.len() >= 28
                && be16(packet, 4) == PROBE_MARKER
                && packet[9] == 1
                && packet[20] == 8
                && packet[16..20] == to.octets()
        })
        .collect()
}

/// AC-6.18 and AC-6.19 **on the wire**, in one test because a raw ICMP socket
/// sees every ICMP packet delivered to this host and two concurrent ICMP tests
/// would read each other's.
///
/// The refusals come first, then the allowed probe as their control: without
/// it, a watcher that could see nothing would satisfy "zero packets emitted".
#[test]
fn an_icmp_probe_reaches_the_wire_only_for_a_target_the_session_allows() {
    let Some(watch) = sniffer_for(
        "an_icmp_probe_reaches_the_wire_only_for_a_target_the_session_allows",
        1,
    ) else {
        return;
    };
    let host = this_host();

    // AC-6.19: the same two refusals SYN probes get, asked by the same
    // function. Both targets are ones whose packets this watcher could see.
    let mut denied = session("\"0.0.0.0/0\"", &format!("\"{host}/32\""));
    drain(&watch, Duration::from_millis(60));
    let by_denylist = denied.handle_icmp_probe(1, IpAddr::V4(host));
    let by_reserved = denied.handle_icmp_probe(2, IpAddr::V4(Ipv4Addr::LOCALHOST));
    let captured = drain(&watch, Duration::from_millis(200));
    for (name, response) in [("denylist", by_denylist), ("reserved", by_reserved)] {
        assert!(
            matches!(&response, Response::Refused { reason, .. }
                     if *reason == RefusalReason::OutOfSessionScope),
            "{name}: {response:?}"
        );
    }
    assert_eq!(denied.packets_emitted(), 0);
    assert!(
        our_echo_requests(&captured, host).is_empty(),
        "a refused ICMP target must emit zero packets, and {} carrying our marker reached \
         the wire",
        our_echo_requests(&captured, host).len()
    );

    // AC-6.18: the host answers its own echo request, so this is `Up` --
    // observed, not reported, because the request itself is on the wire.
    let mut allowed = session(&format!("\"{host}/32\""), "");
    drain(&watch, Duration::from_millis(60));
    let response = allowed.handle_icmp_probe(3, IpAddr::V4(host));
    let captured = drain(&watch, Duration::from_millis(300));
    let ours = our_echo_requests(&captured, host);
    assert_eq!(
        ours.len(),
        1,
        "exactly one echo request carrying our marker should have reached the wire; \
         captured {} ICMP packet(s) in total",
        captured.len()
    );
    assert_eq!(allowed.packets_emitted(), 1, "one packet, and no teardown");
    assert_eq!(
        response,
        Response::HostResult {
            id: 3,
            state: HostState::Up
        },
        "{host} did not answer its own echo request. If this container sets \
         net.ipv4.icmp_echo_ignore_all, the daemon is right and the environment is not the \
         one this test assumes."
    );
    // The reply has to have been attributed to *this* probe, so the request's
    // identifier and sequence number are what the matcher had to read.
    let request = ours[0];
    assert_eq!(
        be16(request, 2),
        28,
        "20-byte IP header plus an 8-byte ICMP"
    );
    assert_ne!(
        be16(request, 24),
        0,
        "the identifier must be set, or every session's replies match every probe"
    );
}

/// AC-6.12 (`Open`) and AC-6.13, both observed rather than reported.
#[test]
fn an_open_port_reads_as_open_and_its_teardown_rst_is_seen_on_the_wire() {
    let Some(watch) =
        sniffer("an_open_port_reads_as_open_and_its_teardown_rst_is_seen_on_the_wire")
    else {
        return;
    };
    let host = this_host();
    // Held for the whole test, deliberately: the port is only "the open port"
    // for as long as something is listening on it, and a listener bound and
    // then dropped hands the port back to the kernel's ephemeral pool where a
    // sibling test's `bind(:0)` can take it (`check-fixtures`'s vacated-port
    // rule, measured at 16 red runs in 30).
    let _listener = TcpListener::bind((host, 0)).expect("a listener on this host");
    let port = _listener.local_addr().expect("a bound address").port();

    let mut session = session(&format!("\"{host}/32\""), "");
    drain(&watch, Duration::from_millis(60));
    let response = session.handle_probe(1, IpAddr::V4(host), port);
    let captured = drain(&watch, Duration::from_millis(200));

    assert_eq!(
        response,
        Response::Result {
            id: 1,
            state: PortState::Open
        },
        "a port with a listener on it must read as open"
    );

    let mine = ours(&captured, port);
    let syns: Vec<_> = mine.iter().filter(|p| p[33] == FLAG_SYN).collect();
    let rsts: Vec<_> = mine.iter().filter(|p| p[33] & FLAG_RST != 0).collect();
    assert_eq!(syns.len(), 1, "exactly one SYN carrying our marker");
    assert_eq!(
        rsts.len(),
        1,
        "AC-6.13: the SYN-ACK must be answered with an RST that this process sent. \
         Captured {} of our packets: {:?}",
        mine.len(),
        mine.iter().map(|p| p[33]).collect::<Vec<_>>()
    );
    // The RST has to be able to close the connection, not merely exist: same
    // endpoints, and the sequence the SYN-ACK acknowledged.
    let syn = syns[0];
    let rst = rsts[0];
    assert_eq!(be16(rst, 20), be16(syn, 20), "same source port");
    let syn_seq = u32::from_be_bytes(syn[24..28].try_into().unwrap());
    let rst_seq = u32::from_be_bytes(rst[24..28].try_into().unwrap());
    assert_eq!(rst_seq, syn_seq.wrapping_add(1));
    assert_eq!(session.packets_emitted(), 2, "one SYN and one RST");
}

/// AC-6.12 (`Closed`). The narrowing control for the test above: same host,
/// same code path, a port that refuses -- and no teardown, because there is
/// no connection to tear down.
#[test]
fn a_port_that_refuses_reads_as_closed_and_gets_no_teardown() {
    let Some(watch) = sniffer("a_port_that_refuses_reads_as_closed_and_gets_no_teardown") else {
        return;
    };
    let host = this_host();
    let port = a_refused_port(host);

    let mut session = session(&format!("\"{host}/32\""), "");
    drain(&watch, Duration::from_millis(60));
    let response = session.handle_probe(1, IpAddr::V4(host), port);
    let captured = drain(&watch, Duration::from_millis(200));

    assert_eq!(
        response,
        Response::Result {
            id: 1,
            state: PortState::Closed
        }
    );
    let mine = ours(&captured, port);
    assert!(
        mine.iter().all(|p| p[33] == FLAG_SYN),
        "a closed port must be probed and left alone; saw flags {:?}",
        mine.iter().map(|p| p[33]).collect::<Vec<_>>()
    );
    assert_eq!(session.packets_emitted(), 1, "the SYN, and nothing else");
}

/// AC-6.9 and AC-6.10 on the wire: a refused target emits **zero packets**,
/// and the last assertion is the control that proves the watcher would have
/// seen them.
#[test]
fn a_refused_target_puts_nothing_at_all_on_the_wire() {
    let Some(watch) = sniffer("a_refused_target_puts_nothing_at_all_on_the_wire") else {
        return;
    };
    let host = this_host();
    // Held for the whole test, deliberately: the port is only "the open port"
    // for as long as something is listening on it, and a listener bound and
    // then dropped hands the port back to the kernel's ephemeral pool where a
    // sibling test's `bind(:0)` can take it (`check-fixtures`'s vacated-port
    // rule, measured at 16 red runs in 30).
    let _listener = TcpListener::bind((host, 0)).expect("a listener on this host");
    let port = _listener.local_addr().expect("a bound address").port();

    // Allow everything, then deny this host: both refusal reasons are about
    // a target whose packets this process could see.
    let mut denied = session("\"0.0.0.0/0\"", &format!("\"{host}/32\""));
    drain(&watch, Duration::from_millis(60));
    let by_denylist = denied.handle_probe(1, IpAddr::V4(host), port);
    // AC-6.10: loopback, under an allowlist of `0.0.0.0/0`.
    let by_reserved = denied.handle_probe(2, IpAddr::V4(Ipv4Addr::LOCALHOST), port);
    let captured = drain(&watch, Duration::from_millis(200));

    for (name, response) in [("denylist", by_denylist), ("reserved", by_reserved)] {
        assert!(
            matches!(&response, Response::Refused { reason, .. }
                     if *reason == RefusalReason::OutOfSessionScope),
            "{name}: {response:?}"
        );
    }
    assert_eq!(denied.packets_emitted(), 0);
    assert!(
        ours(&captured, port).is_empty(),
        "AC-6.9: a refused target must emit zero packets, and {} carrying our marker \
         reached the wire",
        ours(&captured, port).len()
    );

    // The control. Same host, same port, same watcher, a session that allows
    // it -- and now packets do appear. Without this, a watcher that could see
    // nothing at all would satisfy the assertion above.
    let mut allowed = session(&format!("\"{host}/32\""), "");
    drain(&watch, Duration::from_millis(60));
    let permitted = allowed.handle_probe(3, IpAddr::V4(host), port);
    let captured = drain(&watch, Duration::from_millis(200));
    assert!(
        matches!(permitted, Response::Result { .. }),
        "{permitted:?}"
    );
    assert!(
        !ours(&captured, port).is_empty(),
        "the watcher saw nothing for an allowed target either, so the refusal assertion \
         above was ranging over nothing"
    );
    assert!(
        ours(&captured, port).iter().any(|p| p[33] == FLAG_SYN),
        "the allowed probe's SYN is what should have appeared"
    );
}
