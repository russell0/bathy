//! Fixtures for tests that need a port nothing can listen on.
//!
//! Reachable from outside this crate through the `test-util` feature, and
//! only through a dev-dependency edge. It started as this crate's
//! private module; the same defect was then found above it, in
//! `bathy-query`'s `tests/real_log_fold.rs` and `bathy`'s
//! `tests/workflow.rs`, and the argument below is a page of kernel
//! behaviour on two platforms -- the kind of thing that is right once and
//! subtly wrong in its second copy.
//!
//! # Why this module exists: "a port with nothing listening"
//!
//! Four tests in this crate need an endpoint whose connect is *refused* --
//! the `Closed`/`tcp-connect-refused` outcome, as distinct from the
//! `Filtered` one. Every one of them used to obtain it the obvious way:
//!
//! ```ignore
//! let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
//! let port = l.local_addr().unwrap().port();
//! drop(l);                       // "now nothing is listening on `port`"
//! ```
//!
//! That comment is a claim about the whole machine, and no process can make
//! it true. The instant `l` is dropped the port returns to the kernel's
//! ephemeral pool, and `cargo test` runs the ~105 tests in this binary
//! concurrently in one process -- dozens of which are binding
//! `127.0.0.1:0` at that exact moment. If one of them is handed the port
//! back, the vacating test sees `Open` instead of `Closed`.
//!
//! The damage does not stop at the vacating test, which is what makes this
//! worth a module rather than a comment. The test that *won* the port is
//! usually holding it as ground truth for something else -- and now a
//! stranger connects to it. Measured on Linux (`rust:1-bookworm`, 10 cores)
//! with the ephemeral range narrowed to 2,000 ports so the collision rate
//! is observable rather than rare, over 30 runs of this crate's unit-test
//! binary:
//!
//! | test | failures |
//! |---|---|
//! | `scheduler::every_port_state_produces_exactly_one_event_open_closed_and_filtered` | 16/30 |
//! | `scheduler::packet_ceiling_is_enforced_across_a_cancel_resume_loop_via_a_fresh_scheduler` | 3/30 |
//! | `scheduler::intensity_bounds_how_many_probe_candidates_are_attempted_not_a_hardcoded_value` | 1/30 |
//! | `discovery::a_refusing_port_still_proves_the_host_is_up` | 1/30 |
//! | `connect::a_refused_connection_reports_closed` | 1/30 |
//!
//! `packet_ceiling_...` never vacates a port at all. It fails as a
//! *bystander*: it holds 20 real listeners and asserts the ceiling by
//! counting accepts on them, and the diagnostic captured on a red run shows
//! its own accounting was perfect (`run1=3 run2=7`, ten probes for a
//! ceiling of ten, exactly one accept on each of ten ports) while a single
//! port carried **three** -- its one legitimate probe plus two from
//! `every_port_state_...`, which had vacated that port, watched this test
//! bind it, and then scanned it (one connect, then one service-detection
//! reconnect). Run that test alone under the same amplification and it
//! passes 50/50. So one racy fixture makes *other* tests red, and the
//! bystander's failure message accuses production code of a budget breach
//! that did not happen.
//!
//! # What [`closed_port`] does instead
//!
//! It keeps the port. A [`ClosedPort`] holds both ends of a real,
//! established loopback connection whose server end is bound to that port,
//! and closes the listener that produced it. The result is a port that is
//! simultaneously:
//!
//! * **impossible for anything else to listen on** -- the server end sits
//!   in the kernel's bind table, so the ephemeral allocator will not hand
//!   the port out. Verified by execution on both platforms rather than
//!   assumed: 80,000 consecutive `bind(127.0.0.1:0)` calls with
//!   `SO_REUSEADDR` set (what `tokio::net::TcpListener::bind` does) never
//!   returned a reserved port, on Linux and on macOS -- and on macOS those
//!   80,000 calls covered 16,373 distinct ports, i.e. the entire ephemeral
//!   range, so the reserved one was skipped rather than merely missed.
//! * **refusing every connection** -- an inbound SYN carries a different
//!   four-tuple from the established connection and finds no listening
//!   socket, so the kernel answers `RST`. `ECONNREFUSED` in under a
//!   millisecond, on Linux and on macOS.
//!
//! The listener is created *without* `SO_REUSEADDR`. That is load-bearing
//! on Linux, where two sockets that both set it may share a port when
//! neither is listening -- which would hand the port straight back to the
//! ephemeral allocator this fixture exists to hide it from.
//!
//! Both halves are asserted, not merely described -- this module's own
//! `tests` probes a reserved port three times and requires `Closed` each
//! time, and asserts the kernel itself reports the port as in use. A third
//! test asserts the *mechanism*, that the holder is a live established
//! connection, because the first two cannot tell that apart from a
//! `TIME_WAIT` remnant and both passed against a mutation that reverted
//! `closed_port` to vacating. `TIME_WAIT` also refuses and also reports
//! `EADDRINUSE`, but any `SO_REUSEADDR` bind steps over it -- and every
//! bind `tokio` and `std` make sets `SO_REUSEADDR`.
//!
//! # The residual risks, stated plainly
//!
//! Two, both far narrower than the race removed, and neither reachable by
//! anything in this workspace:
//!
//! 1. A process *outside* this one could bind the port between the moment
//!    the listener is created and the moment the connection is established
//!    -- microseconds, against the previous approach's window of the whole
//!    test. Nothing in userspace closes that completely without root.
//! 2. On macOS (not Linux) a socket that sets `SO_REUSEADDR` may bind a
//!    port whose only holder is non-listening, so a *deliberate*
//!    `bind(127.0.0.1:P)` naming the reserved number would succeed there.
//!    Every bind in this workspace is `:0`, which is the ephemeral path,
//!    and that one is closed on both platforms.
//!
//! What this removes entirely is the in-process ephemeral race, which is
//! the one that was actually firing.

use std::net::{Ipv4Addr, SocketAddr};

use socket2::{Domain, Protocol, Socket, Type};

/// A loopback port this test owns, and on which no listener can appear.
///
/// Connections to [`ClosedPort::port`] are refused (`ECONNREFUSED` ->
/// [`crate::ConnectOutcome::Closed`]) for as long as this value is alive,
/// and the port is released only when it is dropped. Bind it to a named
/// local; a temporary would drop at the end of the statement and give the
/// port straight back.
///
/// See this module's doc comment for the measurements behind both claims.
#[must_use = "dropping a ClosedPort releases the port it is reserving, which \
              is the race this fixture exists to remove"]
pub struct ClosedPort {
    /// The client end. Held only so the connection stays established.
    _client: Socket,
    /// The server end, whose *local* address is `port`. This is what holds
    /// the port in the kernel's bind table.
    _server: Socket,
    port: u16,
}

impl ClosedPort {
    /// The reserved port. Refused, and unavailable to any ephemeral bind,
    /// for as long as `self` is alive.
    pub fn port(&self) -> u16 {
        self.port
    }
}

/// Reserves a loopback port that refuses connections. See [`ClosedPort`].
///
/// Synchronous, and safe to call from an async test: the only blocking call
/// is a loopback `connect` to a socket that is already listening with a
/// free backlog slot, which the kernel completes inline.
pub fn closed_port() -> ClosedPort {
    closed_port_on(Ipv4Addr::LOCALHOST)
}

/// [`closed_port`] on an address other than `127.0.0.1`.
///
/// `crates/bathy/tests/workflow.rs` needs one on the machine's *routable*
/// IP, because the workflow it drives scans that address. That case is the
/// worse of the two the vacating form left: the ephemeral pool for a
/// routable interface is shared with every other process on the box, not
/// just with sibling tests.
pub fn closed_port_on(ip: Ipv4Addr) -> ClosedPort {
    seal(reserving_listener(SocketAddr::from((ip, 0))))
}

/// A bound, listening TCP socket that [`seal`] can later turn into a
/// [`ClosedPort`] **on the same port it was serving**.
///
/// This exists for the open-then-closed case: `bathy-query`'s
/// `real_log_fold.rs` serves an nginx banner on a port, shuts the listener
/// down, and scans it a second time expecting `closed` -- which is how a
/// real log gets real supersession in it. [`closed_port`] cannot serve that
/// case, because the port has to be open first.
///
/// Returned blocking; a caller handing it to `tokio::net::TcpListener::from_std`
/// must set it non-blocking itself, and [`seal`] puts it back either way.
///
/// The reason this is a constructor and not "bind it however you like, then
/// call `seal`" is `SO_REUSEADDR`. `std` and `tokio` set it unconditionally
/// on every listener and expose no way off, and on Linux a socket that sets
/// it may share a port with another that sets it whenever neither is
/// listening -- which is exactly the state a sealed port is in. A listener
/// built by `std` and then sealed would hand the port straight back to the
/// allocator this whole module exists to hide it from, silently, with every
/// assertion still passing.
pub fn reserving_listener(addr: SocketAddr) -> std::net::TcpListener {
    let listener = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))
        .expect("creating a TCP socket");
    // Deliberately NO `set_reuse_address(true)` -- see above.
    listener.bind(&addr.into()).expect("binding the address");
    listener.listen(128).expect("listening");
    listener.into()
}

/// Turns a listener into a [`ClosedPort`] holding the port it was on.
///
/// Establishes a real connection to the listener, accepts it, and closes
/// the listener. From that moment the port has no listening socket -- every
/// inbound SYN carries a four-tuple the established connection does not
/// match, so the kernel answers `RST` -- while the accepted socket's local
/// address keeps the number out of the ephemeral pool.
///
/// The listener must have been created by [`reserving_listener`]; see there
/// for why its `SO_REUSEADDR` state decides whether any of this works.
pub fn seal(listener: std::net::TcpListener) -> ClosedPort {
    // A listener handed to `tokio` comes back non-blocking, and the connect
    // and accept below are deliberately blocking: on loopback, to a socket
    // that is already listening with a free backlog slot, the kernel
    // completes both inline.
    listener
        .set_nonblocking(false)
        .expect("a blocking listener for the handshake below");
    let listener = Socket::from(listener);
    let addr: SocketAddr = listener
        .local_addr()
        .expect("a bound socket has a local address")
        .as_socket()
        .expect("an IPv4 socket address");

    let client = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))
        .expect("creating the client end");
    client
        .connect(&addr.into())
        .expect("connecting to a listening socket");
    let client_addr: SocketAddr = client
        .local_addr()
        .expect("a connected socket has a local address")
        .as_socket()
        .expect("an IPv4 socket address");

    // Accept until the connection just made comes back, rather than
    // accepting once. A listener that has been serving may have completed
    // handshakes still sitting in its backlog, and accepting one of those
    // instead would leave the deliberate connection unaccepted -- and then
    // RST when the listener drops, releasing the port. Any established
    // socket bound to the port would in fact hold it, but "in fact" is the
    // register this module is trying not to write in.
    let mut server = None;
    for _ in 0..64 {
        let (candidate, peer) = listener.accept().expect("accepting a connection");
        if peer.as_socket() == Some(client_addr) {
            server = Some(candidate);
            break;
        }
        // A leftover from whatever this listener was serving. Closing it is
        // what dropping the listener would have done to it anyway.
        drop(candidate);
    }
    let server = server.expect(
        "the connection this fixture made was not in the listener's backlog after 64 accepts",
    );

    // From here the port has no listener, but the established connection
    // keeps it out of the ephemeral pool.
    drop(listener);

    ClosedPort {
        _client: client,
        _server: server,
        port: addr.port(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Half of the guarantee: every connection is refused, not dropped --
    /// `Closed`, not `Filtered`. Repeated, because a fixture that only held
    /// for the first connect would still break every caller that probes
    /// more than once (a service-detection reconnect is a second connect).
    ///
    /// Asserted rather than described: a fixture whose guarantee lives only
    /// in prose is the same shape as the `drop(listener)` comment it
    /// replaces.
    #[tokio::test]
    async fn a_reserved_port_refuses_every_connection_and_releases_on_drop() {
        let reserved = closed_port();
        for attempt in 0..3 {
            let out = crate::connect::probe_connect(
                "127.0.0.1".parse().unwrap(),
                reserved.port(),
                std::time::Duration::from_secs(2),
            )
            .await;
            assert_eq!(
                out,
                crate::ConnectOutcome::Closed,
                "attempt {attempt}: a reserved port must refuse, not drop"
            );
        }

        // The reservation really is what is holding the port: once dropped,
        // it is bindable again. Without this, the in-use assertion in the
        // next test would still pass if `closed_port` had simply leaked a
        // listener somewhere.
        let port = reserved.port();
        drop(reserved);
        tokio::net::TcpListener::bind(("127.0.0.1", port))
            .await
            .expect("a released port must be bindable again");
    }

    /// The open-then-closed path: a listener that has been *serving* is
    /// still holding its port after [`seal`], and refuses.
    ///
    /// This is the case `bathy-query`'s `real_log_fold.rs` needs and
    /// [`closed_port`] cannot supply, and it is not the same test as the one
    /// above it. Two things are true here that are not true of a fresh
    /// listener: the port has already been advertised to whatever scanned
    /// it, and the backlog may hold completed handshakes. The second is why
    /// [`seal`] accepts until it recognises its own connection -- accepting
    /// a leftover instead leaves the deliberate one to be RST when the
    /// listener drops. So the fixture below deliberately leaves an
    /// unaccepted connection in the backlog before sealing.
    #[tokio::test]
    async fn a_port_that_was_serving_is_still_reserved_and_refusing_after_it_is_sealed() {
        let listener = reserving_listener(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)));
        let port = listener.local_addr().expect("a local address").port();

        // One connection served and accepted, and one left in the backlog:
        // the state a real fixture is in when its scan ends.
        let served = std::net::TcpStream::connect(("127.0.0.1", port)).expect("a first connect");
        let (accepted, _) = listener.accept().expect("accepting the first connection");
        drop(accepted);
        drop(served);
        let _pending = std::net::TcpStream::connect(("127.0.0.1", port)).expect("a second connect");

        let reserved = seal(listener);
        assert_eq!(
            reserved.port(),
            port,
            "sealing must keep the port it served"
        );

        for attempt in 0..3 {
            assert_eq!(
                crate::connect::probe_connect(
                    "127.0.0.1".parse().unwrap(),
                    port,
                    std::time::Duration::from_secs(2),
                )
                .await,
                crate::ConnectOutcome::Closed,
                "attempt {attempt}: a sealed port must refuse like any other reserved one"
            );
        }

        let conflicting = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))
            .expect("creating the conflicting socket");
        let same: SocketAddr = format!("127.0.0.1:{port}")
            .parse()
            .expect("a literal loopback address");
        assert_eq!(
            conflicting
                .bind(&same.into())
                .expect_err("a sealed port must still be in use")
                .kind(),
            std::io::ErrorKind::AddrInUse,
            "the kernel does not consider the sealed port {port} in use, so the \
             ephemeral allocator can hand it out again"
        );
    }

    /// What actually holds the port: a **live, established** connection
    /// whose server end is bound to it.
    ///
    /// This exists because the two behavioural tests either side of it
    /// cannot tell that state apart from a `TIME_WAIT` remnant, and the
    /// difference decides whether the fixture works. Measured: replacing
    /// `closed_port`'s body with the vacating technique it was written to
    /// replace -- close both ends, keep the number -- leaves the port in
    /// `TIME_WAIT`, which also refuses connections and also reports
    /// `EADDRINUSE` to a bind without `SO_REUSEADDR`. Both of those tests
    /// passed against that mutation. A `TIME_WAIT` port is nonetheless
    /// available to any `SO_REUSEADDR` bind -- which is every bind `tokio`
    /// and `std` make, i.e. every sibling test -- so the fixture would be
    /// exactly as racy as before while its own tests stayed green.
    ///
    /// So this asserts the mechanism directly rather than a symptom two
    /// different mechanisms share. It is the assertion that dies under that
    /// mutation.
    #[test]
    fn the_port_is_held_by_a_live_connection_not_a_time_wait_remnant() {
        let reserved = closed_port();
        let held = reserved
            ._server
            .local_addr()
            .expect("a bound socket has a local address")
            .as_socket()
            .expect("an IPv4 socket address");
        assert_eq!(
            held.port(),
            reserved.port(),
            "the socket being held is not the one bound to the reserved port"
        );
        reserved._server.peer_addr().expect(
            "the reserved port must be held by an ESTABLISHED connection -- a \
             closed one leaves only a TIME_WAIT remnant, which any \
             SO_REUSEADDR bind steps over, and every sibling test's bind sets \
             SO_REUSEADDR",
        );
        reserved
            ._client
            .peer_addr()
            .expect("the client end must still be connected too");
    }

    /// The other half, and the one the whole fixture exists for: the
    /// kernel considers a reserved port to be IN USE, so the ephemeral
    /// allocator every sibling test goes through cannot hand it out.
    ///
    /// Asserted at the kernel's own bind table rather than by sampling the
    /// allocator. A statistical version of this test (bind `127.0.0.1:0` N
    /// times, assert the reserved port never comes back) was written first
    /// and thrown away: how much of the range N binds actually cover is a
    /// property of the machine and its load, so the test needed a "did this
    /// sweep see enough ports to mean anything" guard -- and that guard is
    /// the same defect as the fixture it is checking, an environment-
    /// dependent number asserted as if it were not. It duly went red 3
    /// times in 30 on a contended container whose allocator returned 2
    /// distinct ports out of 20,000 binds. Fixing a flake by adding one is
    /// not fixing it.
    ///
    /// `EADDRINUSE` here is the exact condition `inet_csk_get_port` (Linux)
    /// and `in_pcbbind` (macOS/BSD) consult when they pick an ephemeral
    /// port, so this asserts the mechanism instead of its statistics -- and
    /// it is deterministic, instant, and identical on both platforms. The
    /// sampled form was still run, out of band, as corroboration: 80,000
    /// ephemeral binds on each platform returned a reserved port zero
    /// times, and on macOS those binds covered 16,373 distinct ports, the
    /// whole range.
    ///
    /// The conflicting socket deliberately does NOT set `SO_REUSEADDR`.
    /// With it, macOS (not Linux) permits binding a port whose only holder
    /// is non-listening -- a divergence that would force this assertion to
    /// be `cfg(target_os = "linux")`, and a Linux-only assertion invisible
    /// on the machines this is developed on is precisely how CI here went
    /// red for five days. Nothing in this workspace binds a specific port
    /// anyway; every bind is `:0`.
    #[test]
    fn the_kernel_reports_a_reserved_port_as_in_use() {
        let reserved = closed_port();

        let conflicting = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))
            .expect("creating the conflicting socket");
        let same: SocketAddr = format!("127.0.0.1:{}", reserved.port())
            .parse()
            .expect("a literal loopback address");
        let err = conflicting
            .bind(&same.into())
            .expect_err("binding a port an established connection holds must fail");
        assert_eq!(
            err.kind(),
            std::io::ErrorKind::AddrInUse,
            "the kernel does not consider port {} in use -- the ephemeral \
             allocator consults this same answer, so every caller's \
             'nothing can be listening here' is a guess again on this \
             platform. Got {err:?}",
            reserved.port()
        );

        // And it is the reservation saying so, not something else on the
        // machine that happened to hold this port: once released, the same
        // bind succeeds. `SO_REUSEADDR` is required for THIS bind and only
        // this one -- closing an established connection leaves the port in
        // `TIME_WAIT` for a minute or so, and stepping over `TIME_WAIT` is
        // exactly what that option is for. It is off above, where the
        // question is whether a LIVE connection holds the port.
        let port = reserved.port();
        drop(reserved);
        let after = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))
            .expect("creating the post-release socket");
        after
            .set_reuse_address(true)
            .expect("SO_REUSEADDR on a fresh socket");
        after
            .bind(&same.into())
            .expect("a released port must be bindable again");
        assert_eq!(
            after
                .local_addr()
                .expect("a bound socket has a local address")
                .as_socket()
                .expect("an IPv4 socket address")
                .port(),
            port
        );
    }
}
