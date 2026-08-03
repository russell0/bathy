//! The bounded I/O layer: turns a live [`TcpStream`] into raw,
//! uninterpreted bytes, and chooses which [`Probe`]s to run against one
//! endpoint.
//!
//! Two independent jobs live in this file, deliberately kept separate:
//!
//! - [`ProbeIo`] bounds a single socket's I/O against a hostile peer (see
//!   its own doc comment for the threat model this exists to close).
//! - [`select_probes`] bounds how *many* probes an endpoint receives, via
//!   `intensity`, without ever being able to say *which* endpoint to
//!   contact -- that decision belongs to scope and the scheduler, not to
//!   service detection. See [`select_probes`]'s own doc comment for how
//!   that is proven, not just claimed.

use std::time::Duration;

use async_trait::async_trait;
use bathy_types::ProbeCapture;
use bathy_types::event::Transport;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeKind {
    /// The server speaks first (SSH, SMTP, FTP). Read before writing.
    ListenFirst,
    /// The client speaks first (HTTP, TLS, Redis).
    SendFirst,
}

#[derive(Debug, thiserror::Error)]
pub enum ProbeError {
    #[error("probe io: {0}")]
    Io(#[from] std::io::Error),
    #[error("probe timed out after {0:?}")]
    Timeout(Duration),
    #[error("connection closed before any response")]
    EmptyResponse,
}

/// Bounded socket wrapper handed to a probe.
///
/// The peer on the other end is hostile by assumption -- a scan touches
/// thousands of endpoints, and one of them will misbehave, deliberately or
/// not. `ProbeIo` is what stands between that peer and the rest of the
/// system: [`Self::read_bounded`] must not be inducible into unbounded
/// memory use, and must not hang past its deadline, regardless of what the
/// peer does. Both are load-bearing, not defensive politeness.
///
/// TCP-only today: every M4 probe (see the milestone plan's Task 2) speaks
/// TCP, including the DNS probe, which deliberately queries over TCP rather
/// than UDP. [`Self::transport`] exists as a single accessor precisely so
/// that if a future milestone adds a UDP-backed `ProbeIo`, every call site
/// that needs to know the transport already asks the object instead of
/// assuming a literal.
///
/// `deadline` is a **per-call** budget, not a total budget shared across a
/// probe's whole execution: [`Self::write_all`] gets up to `deadline`, and a
/// following [`Self::read_bounded`] gets its own, fresh `deadline` after
/// that. A probe that writes a request and then reads a response can
/// therefore take up to `2 * deadline` in the worst case. This is a
/// deliberate choice, not an oversight: the nastiest hostile-peer case this
/// type defends against -- see [`Self::read_bounded`]'s own doc comment --
/// is specific to the read path (a peer that dribbles bytes forever, never
/// triggering a naive per-read timeout), and giving each operation its own
/// full budget keeps that guarantee simple to state and to test: "no single
/// `ProbeIo` call outlives `deadline`" is what every test in this module
/// proves, rather than a cross-call accounting scheme this task has no
/// requirement to build.
pub struct ProbeIo {
    stream: TcpStream,
    port: u16,
    read_cap: usize,
    deadline: Duration,
}

impl ProbeIo {
    pub const DEFAULT_READ_CAP: usize = 64 * 1024;

    /// Wraps an already-connected `stream` with [`Self::DEFAULT_READ_CAP`].
    ///
    /// `port` is supplied by the caller (whoever dialed `stream`) rather
    /// than read back off the socket, so it stays available even if a
    /// later `peer_addr()` call would fail (e.g. after the peer resets the
    /// connection).
    pub fn new(stream: TcpStream, port: u16, deadline: Duration) -> Self {
        Self::with_read_cap(stream, port, Self::DEFAULT_READ_CAP, deadline)
    }

    /// Like [`Self::new`], with an explicit cap instead of
    /// [`Self::DEFAULT_READ_CAP`]. Exists primarily so tests can drive
    /// [`Self::read_bounded`]'s cap-enforcement behavior without needing to
    /// move tens of kilobytes of fixture data.
    pub fn with_read_cap(
        stream: TcpStream,
        port: u16,
        read_cap: usize,
        deadline: Duration,
    ) -> Self {
        Self {
            stream,
            port,
            read_cap,
            deadline,
        }
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn read_cap(&self) -> usize {
        self.read_cap
    }

    pub fn deadline(&self) -> Duration {
        self.deadline
    }

    /// The transport this `ProbeIo` speaks. Always [`Transport::Tcp`] today
    /// -- see this type's own doc comment.
    pub fn transport(&self) -> Transport {
        Transport::Tcp
    }

    /// A `Host:` header value (or, absent a hostname -- bathy never performs
    /// DNS resolution, see the crate-level "no DNS" guarantee -- its closest
    /// honest substitute) for the peer this socket is connected to: the
    /// literal `ip:port` pair actually dialed. Falls back to `:port` if the
    /// socket cannot report its own peer address (e.g. it has already been
    /// reset); this only reads already-known local socket state and never
    /// itself performs any lookup.
    pub fn peer_host_header(&self) -> String {
        match self.stream.peer_addr() {
            Ok(addr) => format!("{}:{}", addr.ip(), addr.port()),
            Err(_) => format!(":{}", self.port),
        }
    }

    /// Writes `bytes` in full, bounded by `deadline`. See this type's own
    /// doc comment for why `deadline` applies fresh to this call rather
    /// than being shared with a following [`Self::read_bounded`].
    pub async fn write_all(&mut self, bytes: &[u8]) -> Result<(), ProbeError> {
        tokio::time::timeout(self.deadline, self.stream.write_all(bytes))
            .await
            .map_err(|_elapsed| ProbeError::Timeout(self.deadline))??;
        Ok(())
    }

    /// Reads until `read_cap`, `deadline`, or a clean EOF -- whichever
    /// comes first. Returns `(bytes, truncated)`; never returns more than
    /// `read_cap` bytes.
    ///
    /// # The hostile-peer cases this closes
    ///
    /// **Unbounded memory.** A peer that floods forever cannot make `bytes`
    /// grow past `read_cap`: every read into the internal chunk buffer asks
    /// for at most the room still left under the cap, so the accumulated
    /// output can never exceed it, no matter how much the peer sends or how
    /// long it keeps sending. This is `deadline`'s job to bound only
    /// incidentally, not primarily: `tokio::time::timeout` polls the wrapped
    /// read first and only consults the timer if that read is not already
    /// ready, so a peer whose data is *always* immediately available (a true
    /// flood) can in principle starve the deadline check across many
    /// iterations. The cap's own byte-counted termination -- `room` reaching
    /// zero -- does not depend on that race at all, which is why it, not the
    /// deadline, is the actual guarantee against unbounded growth. This was
    /// not a theoretical concern: an earlier version of this function was
    /// tested with the cap check replaced by an unconditional `room =
    /// usize::MAX`, against exactly this test's flooding peer, and the
    /// process had to be force-killed after climbing past 4.9 GiB resident
    /// and still growing -- see this task's report for the measurement.
    ///
    /// **A naive per-read timeout.** The obvious-looking bug this type
    /// avoids: resetting a fresh `deadline`-long timeout before every
    /// individual `read()` call. That defeats itself against a peer that
    /// dribbles one byte every few hundred milliseconds forever, because
    /// each individual read still completes well inside its own timeout --
    /// the read never times out, so a per-read timeout alone never fires,
    /// and the call never returns. **The behavior actually implemented
    /// here is a single absolute deadline**, computed once on entry
    /// (`Instant::now() + deadline`); every read attempt, including the
    /// boundary check described below, is given whatever time remains
    /// until *that* fixed instant, not a fresh full `deadline` of its own.
    /// A dribbling peer still gets every individual read to succeed, but
    /// the remaining budget shrinks on every iteration regardless, and the
    /// call returns once it hits zero -- proven by
    /// `read_bounded_is_bounded_by_the_overall_deadline_against_a_peer_that_dribbles_forever`
    /// below, which does not pass under the naive per-read reset (see that
    /// test's own comment for the mutation that was run to confirm it).
    ///
    /// **A silent peer.** One that accepts a connection and then sends
    /// nothing at all: the same absolute deadline bounds this case too --
    /// the first read attempt itself times out once `deadline` has passed,
    /// and `read_bounded` returns `(vec![], false)` rather than hanging.
    ///
    /// # `truncated`, precisely
    ///
    /// `truncated` is `true` when `bytes` might not be the peer's whole
    /// reply, and `false` when it is believed complete:
    ///
    /// - Reaching `read_cap` sets `truncated = true` **only if the peer
    ///   actually had more to send**. A peer that sends *precisely*
    ///   `read_cap` bytes and then closes cleanly is read to the last byte
    ///   with `truncated = false` -- this function performs one extra,
    ///   zero-byte-buffered read exactly at the boundary to tell "the peer
    ///   was done" apart from "the peer kept going and we cut it off",
    ///   rather than assuming the latter just because the cap was reached.
    ///   See
    ///   `read_bounded_reports_not_truncated_when_the_peer_sends_exactly_the_cap_then_closes`
    ///   below for the case this exists to get right, and the doc comment
    ///   on [`bathy_types::ProbeCapture::truncated`] for why this
    ///   distinction matters to whatever later trusts the flag.
    /// - The deadline elapsing sets `truncated = true` only if at least one
    ///   byte had already been captured; a deadline that elapses with
    ///   nothing captured at all reports `(vec![], false)` -- there is
    ///   nothing to call incomplete.
    /// - A clean EOF (the peer closing its write side) always sets
    ///   `truncated = false`: the peer said everything it was going to say.
    pub async fn read_bounded(&mut self) -> Result<(Vec<u8>, bool), ProbeError> {
        const CHUNK: usize = 8192;
        let mut chunk = [0u8; CHUNK];
        let mut out = Vec::new();
        // One absolute deadline, computed once -- see the doc comment above
        // for why this, and not a fresh per-read timeout, is what actually
        // bounds this function against a peer that never stops sending a
        // trickle of bytes.
        let deadline = tokio::time::Instant::now() + self.deadline;

        loop {
            let room = self.read_cap.saturating_sub(out.len());
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());

            if room == 0 {
                // At the cap already. Read one more byte -- into a buffer
                // that is never appended to `out`, so `out` itself never
                // exceeds `read_cap`, even transiently -- purely to learn
                // whether the peer had more to say. See the doc comment
                // above for why this is not the same question as "did we
                // stop early".
                let mut probe_byte = [0u8; 1];
                return match tokio::time::timeout(remaining, self.stream.read(&mut probe_byte))
                    .await
                {
                    Ok(Ok(0)) => Ok((out, false)), // clean EOF exactly at the cap
                    Ok(Ok(_)) => Ok((out, true)),  // at least one more byte existed
                    Ok(Err(e)) => Err(ProbeError::Io(e)),
                    Err(_elapsed) => Ok((out, true)), // deadline hit, peer still not done
                };
            }

            match tokio::time::timeout(remaining, self.stream.read(&mut chunk[..room.min(CHUNK)]))
                .await
            {
                Ok(Ok(0)) => return Ok((out, false)), // clean EOF: response is complete
                Ok(Ok(n)) => out.extend_from_slice(&chunk[..n]),
                Ok(Err(e)) => return Err(ProbeError::Io(e)),
                Err(_elapsed) => {
                    let truncated = !out.is_empty();
                    return Ok((out, truncated));
                }
            }
        }
    }

    /// Reads up to `n` bytes (capped by `read_cap`, like [`Self::read_bounded`]),
    /// but -- unlike `read_bounded` -- returns as soon as `n` bytes have
    /// arrived, rather than continuing to wait out the rest of `deadline`
    /// to confirm the peer has nothing more to say.
    ///
    /// This exists for the narrow case of a protocol whose reply at a given
    /// step has a length fixed by the spec itself, where the peer is not
    /// expected to close the connection afterward (so `read_bounded` alone
    /// would have no way to detect completion short of waiting out the
    /// whole deadline). `postgres-startup-v1` is the one probe in this
    /// crate that needs this: PostgreSQL's reply to an `SSLRequest` is
    /// defined by the wire protocol to be exactly one byte (`S` or `N`),
    /// and a real server keeps the connection open afterward rather than
    /// closing it (confirmed against a real `postgres:16-alpine` container
    /// -- see this task's report). Knowing "the reply here is exactly N
    /// bytes" is protocol *framing* knowledge, the same category as the
    /// length this crate already relies on to build requests (e.g. the
    /// DNS probe's TCP length prefix) -- not protocol *interpretation* of
    /// what the bytes mean, which stays out of this crate entirely (see
    /// this crate's top-level doc comment).
    ///
    /// How long [`Self::read_at_most`] is willing to wait, after collecting
    /// its full `n` bytes, to find out whether the peer already has *more*
    /// queued up (see that method's own doc comment for why this exists
    /// and why it is short rather than `deadline`-length).
    const BOUNDARY_PEEK_TIMEOUT: Duration = Duration::from_millis(20);

    /// Returns `(bytes, truncated)`. `truncated`'s meaning matches
    /// [`Self::read_bounded`]'s documented contract (see
    /// [`bathy_types::ProbeCapture::truncated`]) in the cases this method
    /// shares with it: `true` if the deadline elapsed with fewer than `n`
    /// bytes collected, `false` on a clean EOF before `n` bytes arrived.
    ///
    /// The one case unique to this method -- collecting the full `n`
    /// bytes requested -- is *not* automatically `false`. Unlike
    /// `read_bounded`, which only stops at `n` because it ran out of room
    /// to buffer more, this method stops at `n` **on purpose**, before it
    /// has any information about whether the peer is done or has much
    /// more queued (a flood). Reporting `false` unconditionally there --
    /// this method's behavior before this fix -- let a flooding peer
    /// produce `truncated: false`, contradicting
    /// [`bathy_types::ProbeCapture::truncated`]'s own documented meaning
    /// ("`false` means the peer closed the connection on its own"), which
    /// a flooding peer has certainly not done. Measured effect before this
    /// fix: [`Self::read_at_most`] against an unbounded flood returned
    /// `(1 byte, truncated: false)` -- see this task's follow-up report
    /// for the exact reproduction.
    ///
    /// The fix is a short, bounded, **non-consuming** [`TcpStream::peek`]
    /// (see [`Self::BOUNDARY_PEEK_TIMEOUT`]) immediately after collecting
    /// the `n`th byte: if anything is already sitting in the socket's
    /// receive buffer (a flood already has bytes queued the instant this
    /// runs) or the deadline is spent finding out, `truncated` is `true`;
    /// a clean EOF observed during the peek, or nothing arriving within
    /// the short window, is `false`. That window is deliberately **not**
    /// `deadline`-length: this method's entire reason to exist is to avoid
    /// waiting out the full deadline against a real, well-behaved server
    /// that has nothing more to send but also never closes (see this
    /// method's own opening doc comment and `postgres-startup-v1`'s), and
    /// a full-length peek here would silently reintroduce exactly that
    /// cost. This makes the check a bounded best-effort, not a hard
    /// guarantee -- a peer that waits *longer* than
    /// [`Self::BOUNDARY_PEEK_TIMEOUT`] before flooding would still read as
    /// `truncated: false`. That tradeoff, and why it is accepted, is
    /// documented here rather than left implicit.
    pub async fn read_at_most(&mut self, n: usize) -> Result<(Vec<u8>, bool), ProbeError> {
        let target = n.min(self.read_cap);
        let mut out = vec![0u8; target];
        let mut filled = 0usize;
        let deadline = tokio::time::Instant::now() + self.deadline;

        while filled < target {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            match tokio::time::timeout(remaining, self.stream.read(&mut out[filled..])).await {
                Ok(Ok(0)) => {
                    out.truncate(filled);
                    return Ok((out, false)); // clean EOF before `n` bytes arrived
                }
                Ok(Ok(k)) => filled += k,
                Ok(Err(e)) => return Err(ProbeError::Io(e)),
                Err(_elapsed) => {
                    out.truncate(filled);
                    return Ok((out, filled > 0));
                }
            }
        }

        if target == 0 {
            // Nothing was ever asked for; there is no "more" to speak of.
            return Ok((out, false));
        }
        let mut peek_buf = [0u8; 1];
        let truncated = match tokio::time::timeout(
            Self::BOUNDARY_PEEK_TIMEOUT,
            self.stream.peek(&mut peek_buf),
        )
        .await
        {
            Ok(Ok(0)) => false,     // clean EOF: the peer is done
            Ok(Ok(_)) => true,      // more was already waiting -- a flood, most likely
            Ok(Err(_)) => false,    // a peek error tells us nothing new; don't invent truncation
            Err(_elapsed) => false, // nothing arrived within the short window
        };
        Ok((out, truncated))
    }
}

/// A single protocol probe.
///
/// A trait object (`ProbeRegistry` holds `Vec<Box<dyn Probe>>`,
/// `select_probes` returns `Vec<&dyn Probe>`), so `execute` is boxed via
/// `#[async_trait]` rather than a native `async fn` -- see the `async-trait`
/// dependency comment in this crate's `Cargo.toml` for why a native
/// `async fn` in a trait cannot be made into a trait object at all.
#[async_trait]
pub trait Probe: Send + Sync {
    /// Stable and versioned, e.g. `http-get-v1`. Recorded on every
    /// `service.observed` event so a finding can be traced to the exact
    /// probe that produced it. Never reuse an id with different behavior;
    /// bump the version instead. Enforced structurally by
    /// [`ProbeRegistry::new`], not just by convention -- see that
    /// function's own doc comment.
    fn id(&self) -> &'static str;
    fn kind(&self) -> ProbeKind;
    /// 0-100. Higher runs earlier on this port. Purely an ordering hint --
    /// it does not gate whether a probe is a candidate at all, only where
    /// it lands in the order `select_probes` picks from.
    fn affinity(&self, port: u16) -> u8;
    async fn execute(&self, io: &mut ProbeIo) -> Result<ProbeCapture, ProbeError>;
}

/// The set of probes an endpoint may be tested with.
pub struct ProbeRegistry {
    probes: Vec<Box<dyn Probe>>,
}

impl ProbeRegistry {
    /// Builds a registry from `probes`, rejecting an invalid set outright
    /// rather than accepting it and letting `every_registered_probe_has_a_
    /// unique_versioned_id`-style tests be the only thing standing between
    /// a bad id and production. Probe ids are contract -- they land on
    /// every `service.observed` event -- so the same two rules that test
    /// asserts (unique, version-suffixed) are enforced here, at
    /// construction, for every caller, not verified only for
    /// `ProbeRegistry::standard()`'s own contents by a single test that
    /// could bitrot if a probe is ever added elsewhere.
    ///
    /// # Panics
    ///
    /// If any two probes share an id, or any id lacks a proper version
    /// suffix (a trailing `-v` followed by one or more digits). This is a
    /// programmer error in a statically known probe list, not a runtime
    /// condition callers need to recover from -- the same category of bug
    /// `xtask check-deps`'s layer-order check exists to catch at build time
    /// rather than in production.
    pub fn new(probes: Vec<Box<dyn Probe>>) -> Self {
        let ids: Vec<&str> = probes.iter().map(|p| p.id()).collect();
        let violations = probe_id_violations(&ids);
        assert!(
            violations.is_empty(),
            "invalid probe registry: {}",
            violations.join("; ")
        );
        Self { probes }
    }

    /// The eight real, clean-room protocol probes (M4 Task 2). Each
    /// submodule under `crate::probes` documents its own wire behavior and
    /// names the exact source (RFC section, vendor doc, or captured
    /// container image + digest) its request bytes come from -- see
    /// `crate::probes`' own doc comment for the structural check that no
    /// probe's source mentions Nmap.
    ///
    /// Two ids are load-bearing beyond this module: `tls-v1` and
    /// `ssh-banner-v1` are asserted by name in `probes_are_ordered_by_port_
    /// affinity` below, carried over unchanged from M4 Task 1's own
    /// placeholder registry (which reserved exactly these two ids for this
    /// task to fill in for real).
    pub fn standard() -> Self {
        Self::new(vec![
            Box::new(crate::probes::http::HttpGetProbe),
            Box::new(crate::probes::tls::TlsProbe),
            Box::new(crate::probes::ssh::SshBannerProbe),
            Box::new(crate::probes::smtp::SmtpBannerProbe),
            Box::new(crate::probes::dns::DnsVersionBindProbe),
            Box::new(crate::probes::postgres::PostgresStartupProbe),
            Box::new(crate::probes::mysql::MysqlGreetingProbe),
            Box::new(crate::probes::redis::RedisPingProbe),
        ])
    }

    pub fn all(&self) -> Vec<&dyn Probe> {
        self.probes.iter().map(AsRef::as_ref).collect()
    }
}

/// Whether `id` carries a proper version suffix: a trailing `-v` followed
/// by one or more ASCII digits (e.g. `tls-v1`, `http-get-v12`).
///
/// Stricter than "contains the substring `-v`" on purpose: that looser
/// check (the one the M4 Task 1 brief's own example test uses) passes
/// `average-vendor` -- containing `-v` with no version digits after it --
/// which is exactly the false positive this function exists to reject. See
/// `has_version_suffix_rejects_a_bare_dash_v_substring_without_digits`
/// below.
fn has_version_suffix(id: &str) -> bool {
    match id.rfind("-v") {
        Some(idx) => {
            let digits = &id[idx + 2..];
            !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
        }
        None => false,
    }
}

/// Pure check over a set of probe ids: every id unique, every id
/// version-suffixed (per [`has_version_suffix`]). Returns every violation
/// as a human-readable message. Factored out so it is unit-testable
/// against synthetic fixtures directly -- mirroring `xtask::find_
/// violations`'s own "pure rule, human-readable output, tested against
/// fixtures" shape -- rather than only ever being exercised indirectly
/// through whatever [`ProbeRegistry::standard`] happens to contain today.
fn probe_id_violations(ids: &[&str]) -> Vec<String> {
    let mut violations = Vec::new();
    let mut seen = std::collections::BTreeSet::new();
    for id in ids {
        if !seen.insert(*id) {
            violations.push(format!("duplicate probe id `{id}`"));
        }
        if !has_version_suffix(id) {
            violations.push(format!(
                "probe id `{id}` has no version suffix (expected e.g. `-v1`)"
            ));
        }
    }
    violations
}

/// Chooses which probes to run on one endpoint.
///
/// `intensity` bounds how *many* probes an endpoint may receive -- it is a
/// per-endpoint knob with no way to reach outside the one endpoint it was
/// called for. Structurally, not just by convention: this function's own
/// signature has no target-shaped parameter at all (no `IpAddr`,
/// `SocketAddr`, or hostname), so there is nothing for scanning-wider
/// decisions to be smuggled through even by accident --
/// `select_probes_signature_cannot_accept_a_target` below pins the exact
/// signature so a future edit that added one would fail to compile, not
/// merely fail a test.
pub fn select_probes(port: u16, intensity: u8, registry: &ProbeRegistry) -> Vec<&dyn Probe> {
    let mut candidates: Vec<&dyn Probe> = registry.all();
    candidates.sort_by_key(|p| std::cmp::Reverse(p.affinity(port)));
    let budget = if intensity == 0 {
        1
    } else {
        intensity as usize
    };
    candidates.truncate(budget.min(candidates.len()));
    candidates
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    use tokio::net::{TcpListener, TcpStream};

    use super::*;

    // --- From the brief (Step 1) ---

    #[test]
    fn probes_are_ordered_by_port_affinity() {
        let reg = ProbeRegistry::standard();
        let for_443 = select_probes(443, 9, &reg);
        assert_eq!(
            for_443.first().unwrap().id(),
            "tls-v1",
            "TLS must be tried first on 443"
        );
        let for_22 = select_probes(22, 9, &reg);
        assert_eq!(for_22.first().unwrap().id(), "ssh-banner-v1");
    }

    #[test]
    fn intensity_bounds_the_number_of_probes_attempted() {
        let reg = ProbeRegistry::standard();
        assert!(
            select_probes(8080, 0, &reg).len() <= 1,
            "intensity 0 tries at most one probe"
        );
        let low = select_probes(8080, 2, &reg).len();
        let high = select_probes(8080, 9, &reg).len();
        assert!(
            low < high,
            "higher intensity must authorize more probes: {low} vs {high}"
        );
    }

    #[test]
    fn intensity_never_changes_which_hosts_are_touched_only_how_hard() {
        // Regression guard on a safety property: intensity is a per-endpoint
        // knob. Nothing in probe selection may consult or return a target.
        let reg = ProbeRegistry::standard();
        for i in 0..=9 {
            for probe in select_probes(80, i, &reg) {
                assert!(probe.affinity(80) <= 100);
            }
        }
    }

    #[test]
    fn every_registered_probe_has_a_unique_versioned_id() {
        let reg = ProbeRegistry::standard();
        let ids: Vec<&str> = reg.all().iter().map(|p| p.id()).collect();
        let unique: std::collections::BTreeSet<&&str> = ids.iter().collect();
        assert_eq!(ids.len(), unique.len(), "duplicate probe id");
        for id in ids {
            assert!(
                id.ends_with("-v1") || id.contains("-v"),
                "probe id `{id}` must carry a version so evidence stays interpretable"
            );
        }
    }

    // --- Beyond the brief: select_probes cannot even be given a target ---

    #[test]
    fn select_probes_signature_cannot_accept_a_target() {
        // This line only compiles if `select_probes`'s signature is exactly
        // `fn(u16, u8, &ProbeRegistry) -> Vec<&dyn Probe>` -- no `IpAddr`,
        // `SocketAddr`, or hostname parameter could be added without this
        // assignment failing to compile. That is the structural proof: it
        // is not merely undocumented to pass a target here, it is
        // impossible without editing this pinned signature too.
        let _f: fn(u16, u8, &ProbeRegistry) -> Vec<&dyn Probe> = select_probes;
    }

    // --- Beyond the brief: probe ids are contract, checked exactly ---

    #[test]
    fn has_version_suffix_rejects_a_bare_dash_v_substring_without_digits() {
        // The brief's own check (`ends_with("-v1") || contains("-v")`) would
        // wrongly accept these: both contain the substring "-v" with no
        // version digits after it.
        assert!(!has_version_suffix("average-vendor"));
        assert!(!has_version_suffix("no-version-here"));
        assert!(!has_version_suffix("trailing-v"));
        assert!(has_version_suffix("tls-v1"));
        assert!(has_version_suffix("http-get-v12"));
    }

    #[test]
    fn probe_id_violations_catches_a_duplicate_id_and_a_missing_version_suffix() {
        let ids = ["dup-v1", "dup-v1", "no-version"];
        let violations = probe_id_violations(&ids);
        assert!(
            violations
                .iter()
                .any(|v| v.contains("duplicate probe id `dup-v1`")),
            "violations: {violations:?}"
        );
        assert!(
            violations.iter().any(|v| v.contains("no-version")),
            "violations: {violations:?}"
        );
    }

    #[test]
    fn probe_id_violations_is_empty_for_the_standard_registrys_own_ids() {
        let reg = ProbeRegistry::standard();
        let ids: Vec<&str> = reg.all().iter().map(|p| p.id()).collect();
        assert!(
            probe_id_violations(&ids).is_empty(),
            "{:?}",
            probe_id_violations(&ids)
        );
    }

    #[test]
    fn constructing_a_registry_with_a_duplicate_id_panics() {
        // AC-4.4 is enforced at construction (`ProbeRegistry::new`), not
        // only asserted by a test against `standard()`'s own contents --
        // this proves the enforcement itself is load-bearing by
        // constructing the exact violation it exists to reject.
        struct DupA;
        #[async_trait]
        impl Probe for DupA {
            fn id(&self) -> &'static str {
                "dup-v1"
            }
            fn kind(&self) -> ProbeKind {
                ProbeKind::ListenFirst
            }
            fn affinity(&self, _port: u16) -> u8 {
                1
            }
            async fn execute(&self, _io: &mut ProbeIo) -> Result<ProbeCapture, ProbeError> {
                unreachable!("never called by this test")
            }
        }
        struct DupB;
        #[async_trait]
        impl Probe for DupB {
            fn id(&self) -> &'static str {
                "dup-v1"
            }
            fn kind(&self) -> ProbeKind {
                ProbeKind::ListenFirst
            }
            fn affinity(&self, _port: u16) -> u8 {
                1
            }
            async fn execute(&self, _io: &mut ProbeIo) -> Result<ProbeCapture, ProbeError> {
                unreachable!("never called by this test")
            }
        }

        let result =
            std::panic::catch_unwind(|| ProbeRegistry::new(vec![Box::new(DupA), Box::new(DupB)]));
        assert!(
            result.is_err(),
            "constructing a registry with a duplicate id must panic"
        );
    }

    #[test]
    fn constructing_a_registry_with_an_unversioned_id_panics() {
        struct NoVersion;
        #[async_trait]
        impl Probe for NoVersion {
            fn id(&self) -> &'static str {
                "totally-unversioned"
            }
            fn kind(&self) -> ProbeKind {
                ProbeKind::ListenFirst
            }
            fn affinity(&self, _port: u16) -> u8 {
                1
            }
            async fn execute(&self, _io: &mut ProbeIo) -> Result<ProbeCapture, ProbeError> {
                unreachable!("never called by this test")
            }
        }
        let result = std::panic::catch_unwind(|| ProbeRegistry::new(vec![Box::new(NoVersion)]));
        assert!(
            result.is_err(),
            "constructing a registry with an unversioned id must panic"
        );
    }

    // --- Beyond the brief: ProbeIo::read_bounded against a hostile peer
    // (AC-4.1) ---
    //
    // `client` is the side wrapped in `ProbeIo` (the scanner); `server` is
    // driven directly by each test to play the hostile peer.

    async fn loopback_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        let (client, accepted) = tokio::join!(TcpStream::connect(addr), listener.accept());
        let (server, _peer_addr) = accepted.unwrap();
        (client.unwrap(), server)
    }

    #[tokio::test]
    async fn read_bounded_stops_exactly_at_the_cap_against_a_peer_that_never_stops_sending() {
        let (client, mut server) = loopback_pair().await;
        let flood = tokio::spawn(async move {
            let chunk = [0x41u8; 4096];
            loop {
                if server.write_all(&chunk).await.is_err() {
                    break;
                }
            }
        });

        const CAP: usize = 5_000; // not a multiple of the 4096-byte flood chunk
        let mut io = ProbeIo::with_read_cap(client, 9, CAP, Duration::from_secs(2));
        let start = std::time::Instant::now();
        let (bytes, truncated) = io.read_bounded().await.unwrap();
        let elapsed = start.elapsed();

        assert_eq!(bytes.len(), CAP, "must return exactly the cap, no more");
        assert!(truncated, "a flooding peer's response must be truncated");
        assert!(
            elapsed < Duration::from_millis(500),
            "the cap, not the 2s deadline, should have bounded this call; took {elapsed:?}"
        );

        flood.abort();
    }

    #[tokio::test]
    async fn read_bounded_reports_not_truncated_on_clean_eof_under_the_cap() {
        let (client, mut server) = loopback_pair().await;
        server.write_all(b"hello").await.unwrap();
        drop(server); // clean EOF

        let mut io = ProbeIo::with_read_cap(client, 9, 1024, Duration::from_secs(2));
        let (bytes, truncated) = io.read_bounded().await.unwrap();
        assert_eq!(bytes, b"hello");
        assert!(!truncated);
    }

    #[tokio::test]
    async fn read_bounded_reports_not_truncated_when_the_peer_sends_exactly_the_cap_then_closes() {
        // The false-positive case a "return true as soon as the cap is
        // reached" implementation gets wrong: the peer had nothing more to
        // say, so this is not truncation. (Manually reverting the
        // boundary-peek in `read_bounded` back to that simpler shape and
        // rerunning this test is exactly the AC-4.1 mutation this task's
        // report records.)
        const CAP: usize = 16;
        let payload = vec![0x99u8; CAP];
        let (client, mut server) = loopback_pair().await;
        server.write_all(&payload).await.unwrap();
        drop(server);

        let mut io = ProbeIo::with_read_cap(client, 9, CAP, Duration::from_secs(2));
        let (bytes, truncated) = io.read_bounded().await.unwrap();
        assert_eq!(bytes, payload);
        assert!(
            !truncated,
            "exactly `read_cap` bytes followed by a clean close is not truncation"
        );
    }

    #[tokio::test]
    async fn read_bounded_reports_truncated_when_more_than_the_cap_was_waiting() {
        const CAP: usize = 16;
        let payload = vec![0x77u8; CAP + 24]; // finite, but more than the cap
        let (client, mut server) = loopback_pair().await;
        server.write_all(&payload).await.unwrap();
        drop(server);

        let mut io = ProbeIo::with_read_cap(client, 9, CAP, Duration::from_secs(2));
        let (bytes, truncated) = io.read_bounded().await.unwrap();
        assert_eq!(bytes.len(), CAP);
        assert!(
            truncated,
            "more than the cap was available; this must be reported as truncated"
        );
    }

    #[tokio::test]
    async fn read_bounded_never_hangs_against_a_peer_that_accepts_and_says_nothing() {
        let (client, server) = loopback_pair().await;
        const DEADLINE: Duration = Duration::from_millis(150);
        let mut io = ProbeIo::with_read_cap(client, 9, 1024, DEADLINE);

        let start = std::time::Instant::now();
        // Outer safety net: a genuine hang (a regression reintroducing the
        // naive-per-read-timeout bug for the zero-bytes-ever case) fails
        // this test outright instead of hanging the whole suite.
        let (bytes, truncated) = tokio::time::timeout(Duration::from_secs(2), io.read_bounded())
            .await
            .expect("read_bounded hung past a generous outer bound")
            .unwrap();
        let elapsed = start.elapsed();

        assert!(bytes.is_empty());
        assert!(
            !truncated,
            "nothing was ever received, so nothing was cut off"
        );
        assert!(
            elapsed >= DEADLINE,
            "must not return before its own deadline; took {elapsed:?}"
        );
        assert!(
            elapsed < DEADLINE + Duration::from_millis(500),
            "must not hang well past its deadline either; took {elapsed:?}"
        );

        drop(server); // keep the peer alive (silent, not closed) until here
    }

    #[tokio::test]
    async fn read_bounded_is_bounded_by_the_overall_deadline_against_a_peer_that_dribbles_forever()
    {
        // The nastiest hostile-peer case named in this task's dispatch: a
        // peer that sends one byte every few tens of milliseconds, forever.
        // Every individual read succeeds, so a naive implementation that
        // resets a fresh per-read timeout on each iteration would never
        // return at all. This test was run once against exactly that
        // mutation (replacing the shrinking `remaining` in `read_bounded`'s
        // read calls with a fresh `self.deadline` each time) to confirm it
        // hangs -- caught here only by the outer `tokio::time::timeout`
        // below, which is why that wrapper exists in this test even though
        // the real implementation does not need it.
        let (client, mut server) = loopback_pair().await;
        let dribble = tokio::spawn(async move {
            loop {
                if server.write_all(&[0xABu8]).await.is_err() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        });

        const DEADLINE: Duration = Duration::from_millis(150);
        const CAP: usize = 4096; // far more than a 150ms/20ms-interval dribble can fill
        let mut io = ProbeIo::with_read_cap(client, 9, CAP, DEADLINE);

        let start = std::time::Instant::now();
        let (bytes, truncated) = tokio::time::timeout(Duration::from_secs(2), io.read_bounded())
            .await
            .expect("read_bounded hung against a dribbling peer -- the overall deadline did not bound it")
            .unwrap();
        let elapsed = start.elapsed();

        assert!(
            !bytes.is_empty() && bytes.len() < CAP,
            "expected a handful of dribbled bytes, well under the cap; got {}",
            bytes.len()
        );
        assert!(
            truncated,
            "the peer was still sending when the deadline hit"
        );
        assert!(
            elapsed >= DEADLINE,
            "must not return before its own deadline; took {elapsed:?}"
        );
        assert!(
            elapsed < DEADLINE + Duration::from_millis(500),
            "the overall deadline, not the peer's continued dribbling, must bound this call; \
             took {elapsed:?}"
        );

        dribble.abort();
    }

    #[tokio::test]
    async fn write_all_delivers_exactly_the_given_bytes() {
        let (client, mut server) = loopback_pair().await;
        let mut io = ProbeIo::new(client, 9, Duration::from_secs(2));
        io.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();

        let mut received = [0u8; 18];
        server.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"GET / HTTP/1.1\r\n\r\n");
    }

    #[tokio::test]
    async fn write_all_respects_its_deadline_when_the_peer_never_reads() {
        let (client, server) = loopback_pair().await;
        const DEADLINE: Duration = Duration::from_millis(100);
        let mut io = ProbeIo::new(client, 9, DEADLINE);

        // Large enough to overflow the OS's send/receive socket buffers on
        // any platform this workspace targets (typically far under a few
        // MB by default), so the write genuinely blocks rather than being
        // fully buffered by the kernel before the deadline is even checked.
        let payload = vec![0u8; 64 * 1024 * 1024];

        let start = std::time::Instant::now();
        let result = tokio::time::timeout(Duration::from_secs(5), io.write_all(&payload))
            .await
            .expect("write_all hung past a generous outer bound");
        let elapsed = start.elapsed();

        assert!(
            matches!(result, Err(ProbeError::Timeout(_))),
            "expected a Timeout error, got {result:?}"
        );
        assert!(
            elapsed < DEADLINE + Duration::from_secs(2),
            "must not hang well past its deadline; took {elapsed:?}"
        );

        drop(server); // hold the peer open (never reading) until here
    }

    // --- read_at_most: direct tests (M4 Task 2 follow-up review) ---
    //
    // `read_at_most` is a new public method with its own contract (see its
    // doc comment): it stops at `n` bytes on purpose, before it can know
    // whether the peer is done. These tests exercise it directly against
    // real loopback sockets, the same way every `read_bounded` case above
    // is exercised, rather than only indirectly through
    // `postgres-startup-v1`.

    #[tokio::test]
    async fn read_at_most_returns_exactly_n_bytes_and_is_not_truncated_when_nothing_else_arrives() {
        let (client, mut server) = loopback_pair().await;
        server.write_all(b"N").await.unwrap();
        // Deliberately do not close or send more -- mirrors a real
        // PostgreSQL server, which keeps the connection open after its
        // one-byte SSLRequest reply.
        let mut io = ProbeIo::new(client, 9, Duration::from_millis(300));
        let start = std::time::Instant::now();
        let (bytes, truncated) = io.read_at_most(1).await.unwrap();
        let elapsed = start.elapsed();
        assert_eq!(bytes, b"N".to_vec());
        assert!(!truncated);
        assert!(
            elapsed < Duration::from_millis(150),
            "must not wait out the full deadline for the ordinary case; took {elapsed:?}"
        );
        drop(server);
    }

    #[tokio::test]
    async fn read_at_most_reports_truncated_when_more_is_already_queued_behind_n() {
        // The exact bug this test exists to catch: before the fix,
        // `read_at_most` reported `truncated: false` unconditionally once
        // it had collected its `n` bytes, regardless of how much more the
        // peer had queued up -- see this method's own doc comment and this
        // task's follow-up report for the measured `(1 byte, truncated:
        // false)` result against an actual flood.
        let (client, mut server) = loopback_pair().await;
        let flood = tokio::spawn(async move {
            let chunk = [0x41u8; 4096];
            loop {
                if server.write_all(&chunk).await.is_err() {
                    break;
                }
            }
        });
        let mut io = ProbeIo::new(client, 9, Duration::from_secs(2));
        let start = std::time::Instant::now();
        let (bytes, truncated) = io.read_at_most(1).await.unwrap();
        let elapsed = start.elapsed();
        assert_eq!(bytes.len(), 1, "must still return exactly `n`, not more");
        assert!(truncated, "a flood was queued behind the requested byte");
        assert!(
            elapsed < Duration::from_millis(200),
            "the boundary peek must be short, not deadline-length; took {elapsed:?}"
        );
        flood.abort();
    }

    #[tokio::test]
    async fn read_at_most_reports_not_truncated_when_the_peer_sends_exactly_n_then_closes() {
        let (client, mut server) = loopback_pair().await;
        server.write_all(b"N").await.unwrap();
        drop(server); // clean EOF right behind the one byte
        let mut io = ProbeIo::new(client, 9, Duration::from_millis(300));
        let (bytes, truncated) = io.read_at_most(1).await.unwrap();
        assert_eq!(bytes, b"N".to_vec());
        assert!(
            !truncated,
            "a clean close immediately behind `n` bytes is not truncation"
        );
    }

    #[tokio::test]
    async fn read_at_most_returns_fewer_bytes_on_clean_eof_before_n_arrives() {
        let (client, mut server) = loopback_pair().await;
        server.write_all(b"ab").await.unwrap();
        drop(server);
        let mut io = ProbeIo::new(client, 9, Duration::from_millis(300));
        let (bytes, truncated) = io.read_at_most(5).await.unwrap();
        assert_eq!(bytes, b"ab".to_vec());
        assert!(!truncated, "the peer closed on its own; this is complete");
    }

    #[tokio::test]
    async fn read_at_most_is_truncated_when_the_deadline_elapses_with_a_partial_n() {
        // The deadline-with-partial-bytes branch, exercised with `n > 1`
        // so it is reachable at all (with `n == 1`, as `postgres-startup-v1`
        // uses it, a partial read is impossible -- 0 or 1 byte, nothing
        // between -- so this branch is otherwise dead code for that call
        // site).
        let (client, mut server) = loopback_pair().await;
        server.write_all(b"ab").await.unwrap();
        // Hold the connection open, unclosed, sending nothing further, so
        // the deadline -- not an EOF -- is what ends the call.
        let mut io = ProbeIo::new(client, 9, Duration::from_millis(150));
        let start = std::time::Instant::now();
        let (bytes, truncated) = io.read_at_most(5).await.unwrap();
        let elapsed = start.elapsed();
        assert_eq!(bytes, b"ab".to_vec());
        assert!(truncated, "the deadline elapsed with fewer than n bytes");
        assert!(elapsed >= Duration::from_millis(150));
        drop(server);
    }

    #[tokio::test]
    async fn read_at_most_is_bounded_by_the_overall_deadline_against_a_peer_that_dribbles_forever()
    {
        // The postgres-specific answer to the dispatch's dribbling-peer
        // case: `ssh-banner-v1`'s own dribble test proves `read_bounded`'s
        // dribble-bound transfers to the six other probes built on it, but
        // (per this task's follow-up review) that argument does not reach
        // `postgres-startup-v1`, which is built on the separate
        // `read_at_most` instead. This is the direct proof for that
        // method, mirroring
        // `read_bounded_is_bounded_by_the_overall_deadline_against_a_peer_that_dribbles_forever`
        // above: a peer sending one byte every 20ms forever, asked for far
        // more (`n = 4096`) than it will ever deliver, so every individual
        // read succeeds and only the absolute deadline -- not a naive
        // per-read timeout -- can end the call.
        let (client, mut server) = loopback_pair().await;
        let dribble = tokio::spawn(async move {
            loop {
                if server.write_all(&[0xABu8]).await.is_err() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        });

        const DEADLINE: Duration = Duration::from_millis(150);
        let mut io = ProbeIo::new(client, 9, DEADLINE);
        let start = std::time::Instant::now();
        let (bytes, truncated) =
            tokio::time::timeout(Duration::from_secs(2), io.read_at_most(4096))
                .await
                .expect("read_at_most hung against a dribbling peer")
                .unwrap();
        let elapsed = start.elapsed();

        assert!(
            !bytes.is_empty() && bytes.len() < 4096,
            "expected a handful of dribbled bytes, well under n; got {}",
            bytes.len()
        );
        assert!(
            truncated,
            "the peer was still sending when the deadline hit"
        );
        assert!(elapsed >= DEADLINE);
        assert!(
            elapsed < DEADLINE + Duration::from_millis(500),
            "the overall deadline, not the peer's continued dribbling, must bound this; \
             took {elapsed:?}"
        );

        dribble.abort();
    }

    #[tokio::test]
    async fn read_at_most_never_hangs_against_a_peer_that_sends_nothing() {
        let (client, server) = loopback_pair().await;
        const DEADLINE: Duration = Duration::from_millis(150);
        let mut io = ProbeIo::new(client, 9, DEADLINE);
        let start = std::time::Instant::now();
        let (bytes, truncated) = tokio::time::timeout(Duration::from_secs(2), io.read_at_most(1))
            .await
            .expect("read_at_most hung past a generous outer bound")
            .unwrap();
        let elapsed = start.elapsed();
        assert!(bytes.is_empty());
        assert!(!truncated, "nothing ever arrived, so nothing was cut off");
        assert!(elapsed >= DEADLINE);
        drop(server);
    }

    #[tokio::test]
    async fn read_at_most_of_zero_bytes_returns_immediately() {
        let (client, server) = loopback_pair().await;
        let mut io = ProbeIo::new(client, 9, Duration::from_secs(2));
        let start = std::time::Instant::now();
        let (bytes, truncated) = io.read_at_most(0).await.unwrap();
        assert!(bytes.is_empty());
        assert!(!truncated);
        assert!(start.elapsed() < Duration::from_millis(50));
        drop(server);
    }

    #[tokio::test]
    async fn read_at_most_is_bounded_by_read_cap_not_just_n() {
        let (client, mut server) = loopback_pair().await;
        server.write_all(b"abcdef").await.unwrap();
        let mut io = ProbeIo::with_read_cap(client, 9, 3, Duration::from_millis(300));
        let (bytes, _truncated) = io.read_at_most(5).await.unwrap();
        assert_eq!(
            bytes.len(),
            3,
            "read_at_most must not exceed read_cap even if n asks for more"
        );
        drop(server);
    }

    // --- Beyond the brief: ProbeIo's other accessors ---

    #[tokio::test]
    async fn port_and_transport_reflect_construction() {
        let (client, _server) = loopback_pair().await;
        let io = ProbeIo::new(client, 4242, Duration::from_secs(1));
        assert_eq!(io.port(), 4242);
        assert_eq!(io.transport(), Transport::Tcp);
        assert_eq!(io.read_cap(), ProbeIo::DEFAULT_READ_CAP);
    }

    #[tokio::test]
    async fn peer_host_header_reports_the_actual_connected_peer() {
        let (client, _server) = loopback_pair().await;
        let expected = client.peer_addr().unwrap();
        let io = ProbeIo::new(client, expected.port(), Duration::from_secs(1));
        assert_eq!(io.peer_host_header(), format!("{expected}"));
    }

    // --- Beyond the brief: a placeholder Probe end to end, through the
    // trait object, proving the pieces this task built actually compose ---

    #[tokio::test]
    async fn ssh_banner_v1_reads_the_banner_without_writing_first() {
        let (client, mut server) = loopback_pair().await;
        let banner = tokio::spawn(async move {
            server.write_all(b"SSH-2.0-test\r\n").await.unwrap();
            // Prove the probe never wrote anything: reading here must hang
            // until the peer (test harness) side is dropped, never because
            // data actually arrived.
            let mut buf = [0u8; 1];
            let n = server.read(&mut buf).await.unwrap_or(0);
            assert_eq!(n, 0, "a listen-first probe must never speak first");
        });

        let mut io = ProbeIo::new(client, 22, Duration::from_secs(2));
        let reg = ProbeRegistry::standard();
        let probe = reg
            .all()
            .into_iter()
            .find(|p| p.id() == "ssh-banner-v1")
            .unwrap();
        let capture = probe.execute(&mut io).await.unwrap();

        assert!(capture.request.is_none());
        assert_eq!(capture.response, b"SSH-2.0-test\r\n");
        assert_eq!(capture.probe_id, "ssh-banner-v1");
        assert_eq!(capture.transport, Transport::Tcp);
        assert_eq!(capture.port, 22);

        drop(io); // close the client side so the spawned task's read sees EOF
        banner.await.unwrap();
    }

    #[tokio::test]
    async fn a_probe_against_an_immediately_closed_socket_returns_empty_response_error() {
        let (client, server) = loopback_pair().await;
        drop(server); // closes before sending anything

        let mut io = ProbeIo::new(client, 22, Duration::from_secs(2));
        let reg = ProbeRegistry::standard();
        let probe = reg
            .all()
            .into_iter()
            .find(|p| p.id() == "ssh-banner-v1")
            .unwrap();
        let result = probe.execute(&mut io).await;
        assert!(
            matches!(result, Err(ProbeError::EmptyResponse)),
            "expected EmptyResponse, got {result:?}"
        );
    }

    // --- No-DNS structural note ---
    //
    // There is no test named for this because there is nothing to test:
    // no function in this module ever calls `TcpStream::connect`,
    // `ToSocketAddrs`, or any other resolver-shaped API at all --
    // `ProbeIo` is constructed from an already-connected `TcpStream` the
    // caller supplies (see `ProbeIo::new`'s own doc comment: `port` is
    // supplied by whoever already dialed `stream`). `grep -n
    // 'TcpStream::connect\|to_socket_addrs\|lookup_host' src/framework.rs`
    // outside this `tests` module (which only dials literal loopback
    // `SocketAddr`s, never a hostname) returns nothing -- see this task's
    // report for that grep's actual output.
}
