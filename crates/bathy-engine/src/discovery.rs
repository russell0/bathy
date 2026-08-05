//! Unprivileged TCP host discovery.
//!
//! The insight this module is built on: **a refused connection is positive
//! evidence the host is alive.** [`crate::connect::ConnectOutcome::Closed`]
//! means something at the target answered, even to say no -- exactly as
//! conclusive as [`crate::connect::ConnectOutcome::Open`]. Only silence
//! ([`crate::connect::ConnectOutcome::Filtered`]) and a definite local
//! routing failure ([`crate::connect::ConnectOutcome::Unreachable`]) are
//! inconclusive, so discovery keeps trying the next configured port on
//! either of those and stops the moment it sees `Open` or `Closed`. That
//! short-circuit is also what makes discovery cheap: a live host normally
//! costs one packet, not the whole probe list.
//!
//! Neither `Filtered` nor `Unreachable` is ever treated as evidence about
//! the *target* here -- both fall through to the same `continue`, and a
//! host that exhausts every configured port without a conclusive answer is
//! reported down, never up. That matters because `Filtered` is not a pure
//! signal about the target to begin with: per `crate::connect`'s own module
//! doc, it currently conflates "the probe never left this machine" (local
//! ephemeral-port exhaustion, a local firewall/sandbox policy) with "the
//! probe left and nobody answered". This module does not resolve that
//! conflation -- `DiscoveryResult` has no way to tell those apart either,
//! it only ever reports `method: "no-response"` for both -- so a scheduler
//! consuming a run of "down" results has no way to distinguish "this
//! subnet is empty" from "this machine is out of ephemeral ports". See the
//! task report for a recommendation on giving `DiscoveryResult` a distinct
//! signal for that case in M3 Task 7.
//!
//! # A library-only deliverable in v0.1 (M3 whole-branch review, IMPORTANT-4)
//!
//! [`discover_host`] has no caller in this crate outside its own tests, and
//! [`EventBody::HostDiscovered`](bathy_types::event::EventBody::HostDiscovered)
//! is constructed nowhere in production. This is a deliberate scope
//! decision, not an oversight left over from M3, and not the same shape as
//! CRITICAL-1 (nothing on the emission path consulting scope): scope
//! authorization is a boundary every scan must cross regardless of what it
//! is scanning *for*; host discovery is one specific technique among
//! several this crate offers for *finding* hosts, and `crate::scheduler`'s
//! v0.1 scan loop always probes every configured port on every plan unit
//! directly, for every [`bathy_types::request::Objective`] -- it does not
//! yet branch on objective at all (that routing decision, including what
//! `Objective::HostInventory` should actually DO differently, does not
//! exist yet and is out of this fix wave's scope).
//!
//! M6 Task 5 delivered the other half: [`discover_host_combined`] tries
//! privileged ICMP first (via `bathy-packetd`) and falls back to exactly this
//! module's TCP method on an inconclusive result, returning whichever method
//! actually produced the answer in [`DiscoveryResult::method`].
//!
//! **`EventBody::HostDiscovered` is still constructed nowhere in production,
//! and that is now the only part of AC-6.20 left open.** The remaining step
//! is not in this module and could not be: an emitter needs the event log,
//! the evidence store (`HostDiscovered::evidence_refs` is a
//! `NonEmpty<Digest>`, so there is no event without a stored blob) and a
//! decision about *when* discovery runs -- and that last one still does not
//! exist. `bathy_plan::ScanPlan` carries no
//! [`bathy_types::request::Objective`], so `crate::scheduler` cannot tell a
//! `HostInventory` scan from an `InventoryExposedServices` one, and running
//! discovery unconditionally would change the packet cost and the event
//! stream of every scan this engine has ever run -- three tests pin the
//! current shape (`crates/bathy-engine/tests/end_to_end_scan.rs`,
//! `crates/bathy/tests/lab_conformance.rs`,
//! `crates/bathy-query/tests/real_log_fold.rs`). See M6 Task 5's report for
//! the recommendation.
//!
//! `discover_host`/[`discover_host_combined`]/[`DiscoveryConfig`]/
//! [`DiscoveryResult`] therefore ship as correct, independently tested
//! library building blocks, publicly exported from this crate (see
//! `crate::lib`'s own doc comment), with no production caller yet.

use std::net::IpAddr;

use tokio::time::Duration;

use crate::connect::{ConnectOutcome, probe_connect};
use crate::packetd::{HostState, PacketdClient, PacketdError};
use crate::rate::RateLimiter;

/// [`DiscoveryConfig::new`]'s single failure mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DiscoveryConfigError {
    /// A carried requirement from M3 Tasks 5/6, closed in Task 7 fix round
    /// 1 (IMPORTANT, "Also"): an empty `probe_ports` list must be a hard
    /// error at construction, not a legal "probe nothing" configuration --
    /// see [`DiscoveryConfig`]'s own doc comment for why.
    #[error(
        "DiscoveryConfig::probe_ports must not be empty -- a config with \
         nothing to probe reports every host down without a single \
         measurement ever having been taken, which is a config mistake \
         silently reporting an entire subnet as down, not a legitimate \
         result"
    )]
    EmptyProbePorts,
}

/// Configuration for one [`discover_host`] call.
///
/// `probe_ports` and `timeout` are private; [`Self::new`] is the only
/// fallible constructor, and [`Default::default`] the sanctioned
/// (non-empty) default -- there is no way to construct a `DiscoveryConfig`
/// with an empty `probe_ports`. An earlier version of this type had public
/// fields and no constructor at all, so `DiscoveryConfig { probe_ports:
/// vec![], .. }` compiled and ran, silently reporting every target "down"
/// with zero packets spent -- indistinguishable, from the caller's side,
/// from a genuinely exhaustive probe that found nothing. That is a config
/// MISTAKE (an empty port list was never meant, or a filter upstream
/// emptied it by accident), not a deliberate "probe nothing and report
/// down" request, and letting it construct at all buries the mistake
/// instead of surfacing it. See [`DiscoveryConfigError::EmptyProbePorts`].
#[derive(Debug)]
pub struct DiscoveryConfig {
    /// Tried in order. Defaults to 443, 80, 22 -- chosen because a host that
    /// answers on none of these and is silent is usually genuinely absent.
    probe_ports: Vec<u16>,
    timeout: Duration,
}

impl DiscoveryConfig {
    pub fn new(probe_ports: Vec<u16>, timeout: Duration) -> Result<Self, DiscoveryConfigError> {
        if probe_ports.is_empty() {
            return Err(DiscoveryConfigError::EmptyProbePorts);
        }
        Ok(Self {
            probe_ports,
            timeout,
        })
    }

    pub fn probe_ports(&self) -> &[u16] {
        &self.probe_ports
    }

    pub fn timeout(&self) -> Duration {
        self.timeout
    }
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            probe_ports: vec![443, 80, 22],
            timeout: Duration::from_secs(2),
        }
    }
}

/// A TCP connect that was accepted: the host is up and something is
/// listening.
pub const METHOD_TCP_OPEN: &str = "tcp-connect-open";
/// A TCP connect that was refused. Still positive evidence the host is up --
/// something answered, even to say no.
pub const METHOD_TCP_REFUSED: &str = "tcp-connect-refused";
/// Every configured TCP port tried and none of them conclusive.
pub const METHOD_NO_RESPONSE: &str = "no-response";
/// An ICMP echo reply: the host answered a ping (AC-6.18, AC-6.20).
pub const METHOD_ICMP_UP: &str = "icmp-echo-reply";
/// An ICMP destination unreachable: somebody on the path said there is
/// nothing at that address. A *conclusive negative*, and therefore not a
/// fallback case -- see [`discover_host_combined`].
pub const METHOD_ICMP_DOWN: &str = "icmp-unreachable";

/// The outcome of one [`discover_host`] call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryResult {
    pub up: bool,
    /// Recorded on the `host.discovered` event so a finding can be
    /// explained. Exactly one of [`METHOD_TCP_OPEN`],
    /// [`METHOD_TCP_REFUSED`], [`METHOD_NO_RESPONSE`], [`METHOD_ICMP_UP`] or
    /// [`METHOD_ICMP_DOWN`] -- these strings are a contract other components
    /// branch on, not incidental logging text, and must not be reworded
    /// without a version bump.
    ///
    /// It names the method that **decided**, never the method that was
    /// tried first (AC-6.20). A combined discovery that pinged, got nothing,
    /// and then found an open port reports the TCP method, because that is
    /// what the finding rests on.
    pub method: String,
    /// The number of probes actually attempted -- i.e. the number of times
    /// `limiter.acquire` and `probe_connect` were called -- not a count
    /// derived from `config.probe_ports.len()`. This is what lets a caller
    /// tell a cheap discovery (one packet, a conclusive answer) from an
    /// expensive one (every configured port exhausted).
    pub packets_spent: u64,
}

/// Unprivileged host discovery.
///
/// Both an accepted and a refused connection prove the host is up; only
/// silence and unreachability are inconclusive. Probing stops at the first
/// conclusive answer, so a live host normally costs one packet rather than
/// the whole probe list. Every probe -- including the first -- passes
/// through `limiter.acquire` before it is issued: discovery emits packets,
/// and the rate limiter that keeps `open`/`closed` results honest (see
/// `crate::rate`'s module doc) is on that emission path unconditionally,
/// never bypassed for the sake of a "cheap" single-probe case.
///
/// `config.probe_ports` is never empty by the time it reaches here --
/// [`DiscoveryConfig::new`] refuses to construct one that is (M3 Task 7 fix
/// round 1, carried from Tasks 5/6: an earlier version of this function's
/// own doc comment framed an empty list as "deliberate, not degenerate" and
/// let it construct and run, silently reporting every target down with zero
/// measurements taken).
pub async fn discover_host(
    target: IpAddr,
    config: &DiscoveryConfig,
    limiter: &RateLimiter,
) -> DiscoveryResult {
    let mut spent = 0u64;
    for port in config.probe_ports() {
        limiter.acquire(1).await;
        spent += 1;
        match probe_connect(target, *port, config.timeout()).await {
            ConnectOutcome::Open => {
                return DiscoveryResult {
                    up: true,
                    method: METHOD_TCP_OPEN.into(),
                    packets_spent: spent,
                };
            }
            ConnectOutcome::Closed => {
                return DiscoveryResult {
                    up: true,
                    method: METHOD_TCP_REFUSED.into(),
                    packets_spent: spent,
                };
            }
            // Neither variant is evidence about the target -- see the
            // module doc for why `Filtered` in particular must not be
            // promoted to a stronger claim. Keep trying the remaining
            // configured ports.
            ConnectOutcome::Filtered | ConnectOutcome::Unreachable => continue,
        }
    }
    DiscoveryResult {
        up: false,
        method: METHOD_NO_RESPONSE.into(),
        packets_spent: spent,
    }
}

/// AC-6.20. ICMP first when there is a privileged daemon to do it, TCP when
/// there is not and when ICMP was **inconclusive**.
///
/// # Which answers end it, and which fall through
///
/// | ICMP said | what happens | `method` |
/// |---|---|---|
/// | [`HostState::Up`] | done -- the host answered | [`METHOD_ICMP_UP`] |
/// | [`HostState::Down`] | done -- somebody refused for it | [`METHOD_ICMP_DOWN`] |
/// | [`HostState::Unknown`] | the TCP method decides | whatever it returns |
///
/// Only `Unknown` is inconclusive, and that is the whole reason
/// [`HostState`] has three values rather than two. A `Down` is a router
/// saying there is nothing at that address; spending the TCP probe list on it
/// would be paying three more packets to learn what has already been said.
/// Silence is the opposite: dropping echo requests is the single most common
/// firewall policy there is, so `Unknown` about a host says almost nothing
/// about the host and everything about the network in front of it.
///
/// # The ICMP probe is not free, and is not exempt from the limiter
///
/// It costs one packet, it goes through `limiter.acquire` like every other
/// probe this module issues (see [`discover_host`]), and it is counted in
/// [`DiscoveryResult::packets_spent`] whether or not it decided anything --
/// so a caller can tell a cheap discovery from one that pinged, waited out
/// the deadline and then probed three ports.
///
/// # Why this returns a `Result` when [`discover_host`] does not
///
/// A [`PacketdError`] here is not "ICMP did not answer". It is one of the two
/// situations M6 Task 4 made terminal: the daemon **refused** the target,
/// meaning its own independent scope check (AC-6.9, AC-6.10) disagrees with
/// the engine's about an authorization boundary, or the daemon is **gone**
/// (AC-6.16). Falling back to TCP on either would be this engine emitting
/// connect probes at an address a privileged process just declined to touch,
/// or silently changing method mid-scan -- the exact two defects
/// `PacketdError::terminal_reason` exists to keep separate from a fallback.
/// The plan's own sketch for this function returns a bare `DiscoveryResult`
/// and therefore cannot express either; see M6 Task 5's report.
pub async fn discover_host_combined(
    target: IpAddr,
    config: &DiscoveryConfig,
    limiter: &RateLimiter,
    packetd: Option<&PacketdClient>,
) -> Result<DiscoveryResult, PacketdError> {
    let Some(client) = packetd else {
        return Ok(discover_host(target, config, limiter).await);
    };
    limiter.acquire(1).await;
    match client.icmp_probe(target).await? {
        HostState::Up => Ok(DiscoveryResult {
            up: true,
            method: METHOD_ICMP_UP.into(),
            packets_spent: 1,
        }),
        HostState::Down => Ok(DiscoveryResult {
            up: false,
            method: METHOD_ICMP_DOWN.into(),
            packets_spent: 1,
        }),
        HostState::Unknown => {
            let mut tcp = discover_host(target, config, limiter).await;
            // The echo request was still sent and still cost a packet. A
            // count that dropped it would report an ICMP-filtering host as
            // costing the same as one that was never pinged.
            tcp.packets_spent = tcp.packets_spent.saturating_add(1);
            Ok(tcp)
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use tokio::net::{TcpListener, TcpStream};
    use tokio::time::timeout;

    use super::*;

    /// A rate limiter permissive enough that it never meaningfully delays a
    /// test -- the tests here are about discovery's own logic, not the
    /// limiter's, except for `every_probe_passes_through_the_rate_limiter`
    /// below, which deliberately uses a slow one.
    fn limiter() -> RateLimiter {
        RateLimiter::new(1_000)
    }

    // --- From the brief (AC-3.21, AC-3.22, AC-3.23) ---

    #[tokio::test]
    async fn a_listening_host_is_discovered_via_the_open_port() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let cfg = DiscoveryConfig::new(vec![port], Duration::from_secs(2)).unwrap();
        let r = discover_host("127.0.0.1".parse().unwrap(), &cfg, &limiter()).await;
        assert!(r.up);
        assert_eq!(r.method, "tcp-connect-open");
    }

    #[tokio::test]
    async fn a_refusing_port_still_proves_the_host_is_up() {
        // A port this test owns and refuses on. Vacating one (bind, read
        // the port, drop) put the answer in the hands of whichever sibling
        // test grabbed it next: a re-bind flips `method` to
        // `tcp-connect-open` and this test reports a defect that is not
        // there. See `test_support`'s module doc.
        let refusing = crate::test_support::closed_port();
        let cfg = DiscoveryConfig::new(vec![refusing.port()], Duration::from_secs(2)).unwrap();
        let r = discover_host("127.0.0.1".parse().unwrap(), &cfg, &limiter()).await;
        assert!(r.up, "a refusal is positive evidence of a live host");
        assert_eq!(r.method, "tcp-connect-refused");
    }

    #[tokio::test]
    async fn discovery_stops_at_the_first_conclusive_probe() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let open = listener.local_addr().unwrap().port();
        let cfg = DiscoveryConfig::new(vec![open, 9, 9, 9], Duration::from_secs(2)).unwrap();
        let r = discover_host("127.0.0.1".parse().unwrap(), &cfg, &limiter()).await;
        assert_eq!(
            r.packets_spent, 1,
            "must not probe remaining ports after a conclusive answer"
        );
    }

    /// The one test in this crate that depends on how the *network* treats
    /// an address, and the only claim it adds over
    /// `a_full_backlog_host_is_reported_down_deterministically` below is
    /// that a genuinely unrouted destination behaves like a silent one.
    ///
    /// What would have to be true for this to go red, stated so a future
    /// reader can judge it instead of re-deriving it:
    ///
    /// * something on the path would have to *answer* for TEST-NET-1
    ///   (RFC 5737) -- a captive portal, a hijacking resolver-cum-proxy, a
    ///   corporate default route that RSTs unknown destinations. Then the
    ///   probe is `Open` or `Closed`, `up` is true, and this test is red
    ///   while `discover_host` is right. The failure messages below say so.
    ///
    /// It is NOT at risk from the `method` string, which the class sweep
    /// flagged: `discover_host` maps `Filtered` and `Unreachable` to the
    /// same `"no-response"` (see the loop above), so a host that fails fast
    /// with `ENETUNREACH` and one that drops silently produce identical
    /// results here. That was the sweep reasoning about the test rather than
    /// about the function.
    ///
    /// It does nothing to its neighbours: two 200 ms probes to an address
    /// nothing in this binary uses, no bind, no listener, no load.
    #[tokio::test]
    async fn an_unroutable_host_is_reported_down_after_exhausting_probes() {
        let cfg = DiscoveryConfig::new(vec![80, 443], Duration::from_millis(200)).unwrap();
        let r = discover_host("192.0.2.1".parse().unwrap(), &cfg, &limiter()).await;
        assert!(
            !r.up,
            "192.0.2.1 (TEST-NET-1, RFC 5737: reserved for documentation, routed nowhere) \
             answered a TCP connect with `{}`. Something on this network path is speaking \
             for an address that must not route -- a captive portal or a default route that \
             answers for unknown destinations. `discover_host` is behaving correctly; the \
             environment is not the one this test assumes. \
             `a_full_backlog_host_is_reported_down_deterministically` covers the same claim \
             on loopback and is unaffected.",
            r.method
        );
        assert_eq!(
            r.packets_spent, 2,
            "both configured ports must be probed before giving up: an inconclusive answer \
             is not a stopping condition"
        );
        assert_eq!(
            r.method, "no-response",
            "`Filtered` and `Unreachable` are both inconclusive and both report \
             `no-response`; a different string here means the mapping changed"
        );
    }

    // --- Beyond the brief: deterministic silence, no network dependency ---
    //
    // `an_unroutable_host_is_reported_down_after_exhausting_probes` above
    // depends on how this environment's routing stack treats TEST-NET-1
    // (RFC 5737) -- `crate::connect`'s own task report measured that
    // dependency directly and found it varies by host/network path. This
    // reproduces "every configured probe is silently dropped" entirely on
    // loopback instead, using the same accept-queue-filling technique
    // `crate::connect`'s tests use: once a listener's accept queue is full,
    // further SYNs are silently dropped rather than reset, which is
    // `ConnectOutcome::Filtered` by construction, deterministically and
    // without touching the network.
    async fn fill_accept_queue(addr: SocketAddr) -> Vec<TcpStream> {
        let mut held = Vec::new();
        for _ in 0..256 {
            match timeout(Duration::from_millis(150), TcpStream::connect(addr)).await {
                Ok(Ok(stream)) => held.push(stream),
                _ => return held,
            }
        }
        panic!(
            "expected the accept queue to fill within 256 connection \
             attempts; if this fails, the backlog-fill technique itself \
             needs revisiting, not discover_host"
        );
    }

    #[tokio::test]
    async fn a_full_backlog_host_is_reported_down_deterministically() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _held = fill_accept_queue(addr).await;

        // Same overloaded port three times: every attempt against it is
        // silently dropped, so this also proves discovery doesn't give up
        // early on a run of `Filtered` results.
        let cfg = DiscoveryConfig::new(vec![addr.port(); 3], Duration::from_millis(100)).unwrap();
        let r = discover_host(addr.ip(), &cfg, &limiter()).await;
        assert!(
            !r.up,
            "silence on every configured port must never be reported as up"
        );
        assert_eq!(r.packets_spent, 3, "every configured port must be tried");
        assert_eq!(r.method, "no-response");
    }

    // --- M3 Task 7 fix round 1 (carried from Tasks 5/6): empty probe_ports
    // is a HARD ERROR at construction, not a legal "probe nothing" config.
    //
    // An earlier version of this module treated an empty `probe_ports` as
    // "deliberate, not degenerate" and let it construct and run, reporting
    // `up: false`/`packets_spent: 0` -- the SAME shape a genuinely
    // exhaustive, inconclusive probe produces, with no way for a caller to
    // tell "this subnet is empty" from "this config was a mistake and
    // nothing was ever actually probed". `DiscoveryConfig::new` now refuses
    // to construct at all, per the carried requirement's own headline
    // ("hard error at construction").

    #[test]
    fn discovery_config_new_rejects_an_empty_probe_ports_list() {
        let err = DiscoveryConfig::new(vec![], Duration::from_secs(2)).unwrap_err();
        assert_eq!(err, DiscoveryConfigError::EmptyProbePorts);
    }

    #[test]
    fn discovery_config_new_accepts_a_non_empty_probe_ports_list() {
        assert!(DiscoveryConfig::new(vec![80], Duration::from_secs(2)).is_ok());
    }

    #[test]
    fn discovery_config_default_is_non_empty() {
        assert!(!DiscoveryConfig::default().probe_ports().is_empty());
    }

    // --- Beyond the brief: the rate limiter is not optional ---
    //
    // None of the tests above can tell a `discover_host` that calls
    // `limiter.acquire` apart from one that skips it entirely -- they all
    // use the permissive `limiter()` helper, which never blocks long enough
    // to notice. This test uses a deliberately slow limiter (1 pps) against
    // three probes that are all forced to be inconclusive (via the same
    // full-backlog technique above, so every probe actually executes
    // instead of short-circuiting), and pauses the tokio clock so the
    // assertion is on deterministic virtual time rather than a wall-clock
    // sleep. The bucket starts full (one free token), so the first
    // `acquire` is immediate; the second and third must each wait ~1s to
    // refill at 1 pps. If `discover_host` skipped `limiter.acquire` for any
    // probe, total elapsed time would be a small fraction of this -- just
    // the three ~100ms probe timeouts, no rate-limiter wait at all.
    // --- M6 AC-6.20: combined discovery -----------------------------------
    //
    // The daemon is scripted here rather than real, and deliberately: the
    // subject is the ENGINE's fallback decision, and a real `packetd` cannot
    // be asked to answer `down` on demand -- that answer depends on a router
    // on the path. The half these cannot check (that the daemon's three wire
    // strings are the three this side parses) is checked by execution in
    // `crates/bathy-engine/tests/packetd_integration.rs`, which runs the real
    // binary. Each test below is built so that the TCP path, if it ran, would
    // give a DIFFERENT answer -- that is what makes "did not fall back"
    // observable rather than assumed.

    #[cfg(unix)]
    mod combined {
        use std::net::TcpListener as StdTcpListener;

        use super::*;
        use crate::packetd::PacketdClient;
        use crate::packetd::tests::{LAB_MANIFEST, manifest, probing_responder};

        /// A daemon that answers one ICMP probe with `state`.
        fn daemon(dir: &std::path::Path, name: &str, answer: &str) -> PacketdClient {
            let path = probing_responder(dir, name, &[answer]);
            PacketdClient::start(&path, &manifest(LAB_MANIFEST)).expect("the script says ready")
        }

        /// A listener whose port a TCP probe would find **open**, held for
        /// the life of the test. It is the falsifier for every "no fallback"
        /// assertion below: if the TCP method ran, `up` and `method` change.
        fn open_port() -> (StdTcpListener, DiscoveryConfig) {
            let listener = StdTcpListener::bind("127.0.0.1:0").unwrap();
            let port = listener.local_addr().unwrap().port();
            let config = DiscoveryConfig::new(vec![port], Duration::from_secs(2)).unwrap();
            (listener, config)
        }

        #[tokio::test]
        async fn an_echo_reply_answers_discovery_without_a_tcp_probe() {
            let dir = tempfile::tempdir().unwrap();
            let client = daemon(
                dir.path(),
                "up.sh",
                r#"{"type":"host_result","id":1,"state":"up"}"#,
            );
            let (_held, cfg) = open_port();
            let r = discover_host_combined(
                "127.0.0.1".parse().unwrap(),
                &cfg,
                &limiter(),
                Some(&client),
            )
            .await
            .unwrap();
            assert!(r.up);
            assert_eq!(r.method, METHOD_ICMP_UP);
            assert_eq!(
                r.packets_spent, 1,
                "one echo request and no TCP probe: ICMP was conclusive"
            );
        }

        /// The criterion's sharpest case. `Down` is a conclusive negative, so
        /// discovery stops -- and the configured TCP port is one that WOULD
        /// answer, so an implementation that fell back on anything other than
        /// `Unknown` reports `up: true` here and fails.
        #[tokio::test]
        async fn an_unreachable_is_conclusive_and_does_not_fall_back_to_tcp() {
            let dir = tempfile::tempdir().unwrap();
            let client = daemon(
                dir.path(),
                "down.sh",
                r#"{"type":"host_result","id":1,"state":"down"}"#,
            );
            let (_held, cfg) = open_port();
            let r = discover_host_combined(
                "127.0.0.1".parse().unwrap(),
                &cfg,
                &limiter(),
                Some(&client),
            )
            .await
            .unwrap();
            assert!(
                !r.up,
                "a destination unreachable is evidence of absence; falling back to a port \
                 that answers turns it into the opposite finding"
            );
            assert_eq!(r.method, METHOD_ICMP_DOWN);
            assert_eq!(r.packets_spent, 1);
        }

        /// And the fallback itself: `Unknown` is the one state that hands the
        /// question to TCP, and the method recorded is TCP's, not ICMP's.
        #[tokio::test]
        async fn an_unknown_falls_back_to_tcp_and_reports_the_method_that_decided() {
            let dir = tempfile::tempdir().unwrap();
            let client = daemon(
                dir.path(),
                "unknown.sh",
                r#"{"type":"host_result","id":1,"state":"unknown"}"#,
            );
            let (_held, cfg) = open_port();
            let r = discover_host_combined(
                "127.0.0.1".parse().unwrap(),
                &cfg,
                &limiter(),
                Some(&client),
            )
            .await
            .unwrap();
            assert!(r.up);
            assert_eq!(
                r.method, METHOD_TCP_OPEN,
                "the method recorded is the one that DECIDED, not the one tried first"
            );
            assert_eq!(
                r.packets_spent, 2,
                "the echo request was still sent and still cost a packet"
            );
        }

        /// A refusal is the daemon's own independent scope check disagreeing
        /// with the engine's about an authorization boundary (M6 Task 4).
        /// Falling back would mean this engine sending connect probes at an
        /// address a privileged process just declined to touch -- so it is an
        /// error, with the same terminal reason a refused port probe carries.
        ///
        /// The control that makes "no TCP probe was sent" observable rather
        /// than asserted: the listener is asked, after the fact, whether
        /// anything connected to it.
        #[tokio::test]
        async fn a_refused_icmp_probe_is_terminal_and_sends_no_tcp_probe() {
            let dir = tempfile::tempdir().unwrap();
            let client = daemon(
                dir.path(),
                "refused.sh",
                r#"{"type":"refused","id":1,"reason":"out_of_session_scope"}"#,
            );
            let (held, cfg) = open_port();
            held.set_nonblocking(true).unwrap();
            let e = discover_host_combined(
                "127.0.0.1".parse().unwrap(),
                &cfg,
                &limiter(),
                Some(&client),
            )
            .await
            .expect_err("a refusal is not a discovery result");
            assert_eq!(e.terminal_reason(), Some("packetd_refused"), "{e}");
            assert!(
                held.accept().is_err(),
                "nothing may have connected: the daemon refused this address, and probing \
                 it by another method is the disagreement being papered over"
            );
        }

        /// A daemon that has stopped answering is terminal too, for AC-6.16's
        /// reason: quietly finishing by another method produces one result
        /// set assembled two ways.
        #[tokio::test]
        async fn a_daemon_that_stops_answering_is_terminal_rather_than_a_fallback() {
            let dir = tempfile::tempdir().unwrap();
            let client = daemon(
                dir.path(),
                "gone.sh",
                r#"{"type":"host_result","id":1,"state":"unknown"}"#,
            );
            let (_held, cfg) = open_port();
            let target: IpAddr = "127.0.0.1".parse().unwrap();
            // The control: while it answers, it answers.
            discover_host_combined(target, &cfg, &limiter(), Some(&client))
                .await
                .expect("the first probe is answered");
            // The script has no second answer, so the next read is the end.
            client.kill();
            let e = discover_host_combined(target, &cfg, &limiter(), Some(&client))
                .await
                .expect_err("a dead daemon cannot report a host state");
            assert_eq!(e.terminal_reason(), Some("packetd_unavailable"), "{e}");
        }
    }

    /// Without a daemon there is nothing to try first, and combined discovery
    /// is exactly the TCP method -- same answer, same packet count. This is
    /// the control that says the ICMP path is what costs the extra packet
    /// above, rather than the combined wrapper always adding one.
    #[tokio::test]
    async fn without_a_daemon_combined_discovery_is_the_tcp_method_alone() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let cfg = DiscoveryConfig::new(vec![port], Duration::from_secs(2)).unwrap();
        let target: IpAddr = "127.0.0.1".parse().unwrap();
        let combined = discover_host_combined(target, &cfg, &limiter(), None)
            .await
            .unwrap();
        let plain = discover_host(target, &cfg, &limiter()).await;
        assert_eq!(combined, plain);
        assert_eq!(combined.method, METHOD_TCP_OPEN);
        assert_eq!(combined.packets_spent, 1);
    }

    /// The five method strings are a wire contract other components branch
    /// on. Spelled out rather than derived, so a rename is a failing test.
    #[test]
    fn the_method_strings_are_the_contract_they_are_documented_as() {
        assert_eq!(METHOD_TCP_OPEN, "tcp-connect-open");
        assert_eq!(METHOD_TCP_REFUSED, "tcp-connect-refused");
        assert_eq!(METHOD_NO_RESPONSE, "no-response");
        assert_eq!(METHOD_ICMP_UP, "icmp-echo-reply");
        assert_eq!(METHOD_ICMP_DOWN, "icmp-unreachable");
    }

    #[tokio::test]
    async fn every_probe_passes_through_the_rate_limiter() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _held = fill_accept_queue(addr).await;

        tokio::time::pause();
        let l = RateLimiter::new(1);
        let cfg = DiscoveryConfig::new(vec![addr.port(); 3], Duration::from_millis(100)).unwrap();
        let t = tokio::time::Instant::now();
        let r = discover_host(addr.ip(), &cfg, &l).await;
        let elapsed = t.elapsed();

        assert_eq!(r.packets_spent, 3);
        assert!(
            elapsed >= Duration::from_millis(1_500),
            "took {elapsed:?}; expected at least ~1.9s (two refills at 1 pps \
             after the initial free token) -- a much shorter time means at \
             least one probe skipped the rate limiter entirely"
        );
    }
}
