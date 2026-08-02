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
//! Wiring `discover_host` into the scheduler now would be premature for a
//! second reason: `docs/superpowers/plans/2026-07-31-bathy-m6-packetd.md`
//! already specifies `discover_host_combined`, which tries privileged ICMP
//! first (via `bathy-packetd`) and falls back to exactly this module's TCP
//! method on an inconclusive result -- recording whichever method actually
//! produced the answer on `host.discovered`. That is the real integration
//! point for `host.discovered` events; wiring this crate's TCP-only method
//! into the scheduler ahead of it would mean redoing the same wiring twice,
//! once here and once in M6, or shipping a "discovery" that silently never
//! uses ICMP even once packetd exists. M3's own exit-criteria end-to-end
//! test (`crates/bathy-engine/tests/`) reflects this directly: it expects
//! exactly `scan.started`, `port.state` x2, `scan.completed` for a plain
//! port scan -- no `host.discovered` -- which is what a scheduler that
//! does not call this module at all correctly produces.
//!
//! `discover_host`/[`DiscoveryConfig`]/[`DiscoveryResult`] therefore ship in
//! v0.1 as a correct, independently tested library building block, publicly
//! exported from this crate (see `crate::lib`'s own doc comment), with no
//! production caller yet -- exactly the shape M6's plan already expects to
//! consume.

use std::net::IpAddr;

use tokio::time::Duration;

use crate::connect::{ConnectOutcome, probe_connect};
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

/// The outcome of one [`discover_host`] call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryResult {
    pub up: bool,
    /// Recorded on the `host.discovered` event so a finding can be
    /// explained. Exactly one of `"tcp-connect-open"`,
    /// `"tcp-connect-refused"`, or `"no-response"` -- these three strings
    /// are a contract other components branch on, not incidental logging
    /// text, and must not be reworded without a version bump.
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
                    method: "tcp-connect-open".into(),
                    packets_spent: spent,
                };
            }
            ConnectOutcome::Closed => {
                return DiscoveryResult {
                    up: true,
                    method: "tcp-connect-refused".into(),
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
        method: "no-response".into(),
        packets_spent: spent,
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
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let cfg = DiscoveryConfig::new(vec![port], Duration::from_secs(2)).unwrap();
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

    #[tokio::test]
    async fn an_unroutable_host_is_reported_down_after_exhausting_probes() {
        let cfg = DiscoveryConfig::new(vec![80, 443], Duration::from_millis(200)).unwrap();
        let r = discover_host("192.0.2.1".parse().unwrap(), &cfg, &limiter()).await;
        assert!(!r.up);
        assert_eq!(r.packets_spent, 2);
        assert_eq!(r.method, "no-response");
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
