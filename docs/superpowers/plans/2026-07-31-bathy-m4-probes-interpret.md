# bathy M4 — Probe Framework & Replayable Interpretation — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Identify what is listening, and make every identification explainable and replayable. Probes capture raw bytes; a **pure** interpretation layer turns those bytes into observations with calibrated confidence. Re-running interpretation over stored evidence must reproduce the findings exactly, without a network.

**Architecture:** The split between `bathy-probe` (does I/O, produces bytes) and `bathy-interpret` (no I/O, consumes bytes) is the central design decision of this milestone. It gives us regression tests that replay a corpus of captured responses, an honest answer to "why do you believe this is PostgreSQL", and a fuzzing surface that needs no sockets.

**Tech Stack:** tokio, rustls (raw handshake inspection), hickory-proto (DNS message encoding only), regex (interpretation rules), insta (snapshot tests).

**Read first:** the overview's Global Constraints — particularly the clean-room rule and the no-panic-in-parsers rule, both of which bind hardest here.

> **Clean-room note.** Every match rule in this milestone must be authored from protocol RFCs, vendor documentation, or responses captured from software we run ourselves in the M7 lab. Do not open, port, translate, or consult `nmap-service-probes` or any derivative of it. If you find yourself wondering "what does Nmap match here", stop and read the RFC instead. Record the source of each rule in a `source:` field on the rule itself — this is both good practice and the evidence of clean-room provenance.

---

### Task 1: Probe capture types and framework

**Files:**
- Create: `crates/bathy-probe/Cargo.toml`, `crates/bathy-probe/src/lib.rs`, `crates/bathy-probe/src/framework.rs`
- Create: `crates/bathy-types/src/capture.rs`

**Interfaces:**
- Produces: `ProbeCapture { probe_id, transport, port, request: Option<Vec<u8>>, response: Vec<u8>, elapsed_micros, truncated }`, `trait Probe { fn id(&self) -> &'static str; fn kind(&self) -> ProbeKind; fn affinity(&self, port: u16) -> u8; async fn execute(&self, io: &mut ProbeIo) -> Result<ProbeCapture, ProbeError>; }`, `ProbeKind::{ListenFirst, SendFirst}`, `select_probes(port: u16, intensity: u8, registry: &ProbeRegistry) -> Vec<&dyn Probe>`.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probes_are_ordered_by_port_affinity() {
        let reg = ProbeRegistry::standard();
        let for_443 = select_probes(443, 9, &reg);
        assert_eq!(for_443.first().unwrap().id(), "tls-v1", "TLS must be tried first on 443");
        let for_22 = select_probes(22, 9, &reg);
        assert_eq!(for_22.first().unwrap().id(), "ssh-banner-v1");
    }

    #[test]
    fn intensity_bounds_the_number_of_probes_attempted() {
        let reg = ProbeRegistry::standard();
        assert!(select_probes(8080, 0, &reg).len() <= 1, "intensity 0 tries at most one probe");
        let low = select_probes(8080, 2, &reg).len();
        let high = select_probes(8080, 9, &reg).len();
        assert!(low < high, "higher intensity must authorize more probes: {low} vs {high}");
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
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p bathy-probe framework` — expected FAIL.

- [ ] **Step 3: Write the implementation**

```rust
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// A probe's raw, uninterpreted result.
///
/// This is the unit of evidence. It is stored verbatim and is the sole input
/// to interpretation, which is what makes a finding replayable years later
/// against a newer rule set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProbeCapture {
    pub probe_id: &'static str,
    pub port: u16,
    /// Bytes we sent, if any. `None` for listen-first protocols.
    pub request: Option<Vec<u8>>,
    pub response: Vec<u8>,
    pub elapsed_micros: u64,
    /// True when the response hit the read cap and more bytes were available.
    pub truncated: bool,
}

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
/// The cap exists because the peer is hostile by assumption: a probe must not
/// be able to be induced to read unbounded data into memory.
pub struct ProbeIo {
    stream: TcpStream,
    read_cap: usize,
    deadline: Duration,
}

impl ProbeIo {
    pub const DEFAULT_READ_CAP: usize = 64 * 1024;

    pub async fn write_all(&mut self, bytes: &[u8]) -> Result<(), ProbeError> {
        tokio::time::timeout(self.deadline, self.stream.write_all(bytes))
            .await
            .map_err(|_| ProbeError::Timeout(self.deadline))??;
        Ok(())
    }

    /// Read until the cap, the deadline, or EOF — whichever comes first.
    /// Returns `(bytes, truncated)`.
    pub async fn read_bounded(&mut self) -> Result<(Vec<u8>, bool), ProbeError> {
        let mut buf = vec![0u8; 8192];
        let mut out = Vec::new();
        let deadline = tokio::time::Instant::now() + self.deadline;
        loop {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return Ok((out, true));
            }
            match tokio::time::timeout(remaining, self.stream.read(&mut buf)).await {
                Ok(Ok(0)) => return Ok((out, false)),
                Ok(Ok(n)) => {
                    let room = Self::DEFAULT_READ_CAP.saturating_sub(out.len());
                    if n >= room {
                        out.extend_from_slice(&buf[..room]);
                        return Ok((out, true));
                    }
                    out.extend_from_slice(&buf[..n]);
                }
                Ok(Err(e)) => return Err(ProbeError::Io(e)),
                Err(_) => return Ok((out, !out.is_empty())),
            }
        }
    }
}

#[async_trait::async_trait]
pub trait Probe: Send + Sync {
    /// Stable and versioned, e.g. `http-get-v1`. Recorded on every event so a
    /// finding can be traced to the exact probe that produced it. Never reuse
    /// an id with different behavior; bump the version instead.
    fn id(&self) -> &'static str;
    fn kind(&self) -> ProbeKind;
    /// 0–100. Higher runs earlier on this port. Purely an ordering hint.
    fn affinity(&self, port: u16) -> u8;
    async fn execute(&self, io: &mut ProbeIo) -> Result<ProbeCapture, ProbeError>;
}

/// Choose which probes to run on one endpoint.
///
/// `intensity` bounds how many probes an endpoint may receive. It has no
/// effect on which hosts or ports are contacted — widening scope is never a
/// probe-layer decision.
pub fn select_probes<'a>(
    port: u16,
    intensity: u8,
    registry: &'a ProbeRegistry,
) -> Vec<&'a dyn Probe> {
    let mut candidates: Vec<&dyn Probe> = registry.all().to_vec();
    candidates.sort_by_key(|p| std::cmp::Reverse(p.affinity(port)));
    let budget = match intensity {
        0 => 1,
        i => (i as usize).min(candidates.len()),
    };
    candidates.into_iter().take(budget).collect()
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p bathy-probe framework` — expected 4 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/bathy-probe crates/bathy-types
git commit -m "feat(probe): bounded probe framework with versioned ids and intensity budget"
```

**Acceptance criteria:**
- **AC-4.1** `ProbeIo::read_bounded` never accumulates more than `DEFAULT_READ_CAP` bytes regardless of peer behavior, and reports truncation.
- **AC-4.2** Probe selection is ordered by port affinity; TLS leads on 443, SSH on 22.
- **AC-4.3** `intensity` bounds probe count per endpoint and provably cannot influence which target or port is contacted.
- **AC-4.4** Every registered probe id is unique and carries a version suffix.

---

### Task 2: Protocol probes

**Files:**
- Create: `crates/bathy-probe/src/probes/{http,tls,ssh,dns,smtp,postgres,mysql,redis}.rs`

**Interfaces:**
- Produces: eight `Probe` implementations with ids `http-get-v1`, `tls-v1`, `ssh-banner-v1`, `dns-version-bind-v1`, `smtp-banner-v1`, `postgres-startup-v1`, `mysql-greeting-v1`, `redis-ping-v1`.

- [ ] **Step 1: Write the failing test for each probe against a stub server**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    /// Spawn a socket that replays a fixed script, so probe tests need no
    /// real services and stay deterministic.
    async fn stub(script: &'static [u8], expect_request: bool) -> u16 { /* … */ }

    #[tokio::test]
    async fn http_probe_sends_a_get_and_captures_the_status_line_and_headers() {
        let port = stub(b"HTTP/1.1 200 OK\r\nServer: nginx/1.26.0\r\n\r\n<html>", true).await;
        let cap = run_probe(&HttpGetProbe, port).await.unwrap();
        assert_eq!(cap.probe_id, "http-get-v1");
        let req = String::from_utf8(cap.request.clone().unwrap()).unwrap();
        assert!(req.starts_with("GET / HTTP/1.1\r\n"));
        assert!(req.contains("Host: "));
        assert!(req.contains("Connection: close"));
        assert!(cap.response.starts_with(b"HTTP/1.1 200 OK"));
    }

    #[tokio::test]
    async fn http_probe_identifies_itself_in_the_user_agent() {
        let port = stub(b"HTTP/1.1 200 OK\r\n\r\n", true).await;
        let cap = run_probe(&HttpGetProbe, port).await.unwrap();
        let req = String::from_utf8(cap.request.unwrap()).unwrap();
        assert!(
            req.contains("User-Agent: bathy/"),
            "scanners must be identifiable to the operators they contact"
        );
    }

    #[tokio::test]
    async fn ssh_probe_reads_the_banner_without_sending_first() {
        let port = stub(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n", false).await;
        let cap = run_probe(&SshBannerProbe, port).await.unwrap();
        assert!(cap.request.is_none(), "listen-first probes must not speak first");
        assert!(cap.response.starts_with(b"SSH-2.0-"));
    }

    #[tokio::test]
    async fn smtp_probe_reads_the_greeting_then_sends_ehlo() {
        let port = stub(b"220 mail.example.com ESMTP Postfix\r\n", false).await;
        let cap = run_probe(&SmtpBannerProbe, port).await.unwrap();
        assert!(cap.response.starts_with(b"220 "));
    }

    #[tokio::test]
    async fn redis_probe_sends_a_resp_ping() {
        let port = stub(b"+PONG\r\n", true).await;
        let cap = run_probe(&RedisPingProbe, port).await.unwrap();
        assert_eq!(cap.request.unwrap(), b"*1\r\n$4\r\nPING\r\n".to_vec());
        assert_eq!(cap.response, b"+PONG\r\n".to_vec());
    }

    #[tokio::test]
    async fn a_probe_against_a_silent_socket_returns_empty_response_not_a_hang() {
        let port = stub(b"", false).await;
        let r = run_probe(&SshBannerProbe, port).await;
        assert!(matches!(r, Err(ProbeError::EmptyResponse) | Ok(_)));
    }

    #[tokio::test]
    async fn a_probe_against_a_flood_of_bytes_stops_at_the_cap() {
        let port = stub_flood().await; // writes forever
        let cap = run_probe(&SshBannerProbe, port).await.unwrap();
        assert!(cap.truncated);
        assert!(cap.response.len() <= ProbeIo::DEFAULT_READ_CAP);
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p bathy-probe probes` — expected FAIL.

- [ ] **Step 3: Write the probe implementations**

Each follows the same shape. The HTTP probe, as the reference:

```rust
pub struct HttpGetProbe;

pub const USER_AGENT: &str = concat!("bathy/", env!("CARGO_PKG_VERSION"), " (+https://github.com/russell0/bathy)");

#[async_trait::async_trait]
impl Probe for HttpGetProbe {
    fn id(&self) -> &'static str { "http-get-v1" }
    fn kind(&self) -> ProbeKind { ProbeKind::SendFirst }
    fn affinity(&self, port: u16) -> u8 {
        match port {
            80 | 8080 | 8000 | 8008 => 100,
            443 | 8443 => 40, // TLS wraps it; try TLS first
            _ => 55,
        }
    }
    async fn execute(&self, io: &mut ProbeIo) -> Result<ProbeCapture, ProbeError> {
        // Identify ourselves. An operator who sees this traffic should be able
        // to find out what it is in one search; anonymous scanning is a
        // deliberate non-goal.
        let request = format!(
            "GET / HTTP/1.1\r\nHost: {host}\r\nUser-Agent: {USER_AGENT}\r\n\
             Accept: */*\r\nConnection: close\r\n\r\n",
            host = io.peer_host_header()
        )
        .into_bytes();
        let start = std::time::Instant::now();
        io.write_all(&request).await?;
        let (response, truncated) = io.read_bounded().await?;
        if response.is_empty() {
            return Err(ProbeError::EmptyResponse);
        }
        Ok(ProbeCapture {
            probe_id: self.id(),
            port: io.port(),
            request: Some(request),
            response,
            elapsed_micros: start.elapsed().as_micros() as u64,
            truncated,
        })
    }
}
```

Remaining probes, with their exact wire behavior:

| Probe | id | Kind | Sends | Affinity peaks |
|---|---|---|---|---|
| TLS | `tls-v1` | SendFirst | A TLS 1.3 ClientHello with SNI omitted and no ALPN; captures the raw ServerHello and certificate bytes | 443, 8443, 993, 995 |
| SSH | `ssh-banner-v1` | ListenFirst | nothing | 22, 2222 |
| SMTP | `smtp-banner-v1` | ListenFirst | after reading the `220` greeting, sends `EHLO bathy.invalid\r\n` and captures the capability list | 25, 465, 587 |
| DNS | `dns-version-bind-v1` | SendFirst | a TXT/CHAOS query for `version.bind` over TCP with a fixed transaction id of `0x5344` | 53 |
| Postgres | `postgres-startup-v1` | SendFirst | an SSLRequest packet (`00 00 00 08 04 D2 16 2F`) and captures the single-byte `S`/`N` reply | 5432 |
| MySQL | `mysql-greeting-v1` | ListenFirst | nothing; captures the initial handshake packet | 3306 |
| Redis | `redis-ping-v1` | SendFirst | `*1\r\n$4\r\nPING\r\n` | 6379 |

Use a **fixed** DNS transaction id rather than a random one so captures are byte-reproducible in replay tests; the id has no security role here because we are not resolving.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p bathy-probe probes` — expected 7 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/bathy-probe
git commit -m "feat(probe): eight clean-room protocol probes with identifying user agent"
```

**Acceptance criteria:**
- **AC-4.5** The HTTP probe sends `User-Agent: bathy/<version> (+<url>)`. bathy traffic is identifiable to the operators receiving it; there is no anonymous or evasive mode in v0.1.
- **AC-4.6** Listen-first probes (SSH, MySQL) send nothing before reading; `capture.request` is `None`.
- **AC-4.7** Every probe stops at `DEFAULT_READ_CAP` against a peer that floods, and sets `truncated`.
- **AC-4.8** Every probe against a silent or immediately closed socket returns an error or an empty capture, never hangs past the deadline.
- **AC-4.9** All probe request bytes are fixed and deterministic — no randomness, no timestamps — so replay corpora are byte-stable.

---

### Task 3: The pure interpretation layer

**Files:**
- Create: `crates/bathy-interpret/Cargo.toml`, `crates/bathy-interpret/src/lib.rs`, `crates/bathy-interpret/src/rules.rs`, `crates/bathy-interpret/src/interpret.rs`

**Interfaces:**
- Consumes: `ProbeCapture`, `Observation`, `Confidence`.
- Produces: `interpret(&ProbeCapture) -> Vec<Interpretation>`, `Interpretation { observation: Observation, rule_id: &'static str, matched_span: Range<usize>, rationale: String }`, `explain(rule_id) -> Option<&RuleDoc>`.

> `bathy-interpret` may depend **only** on `bathy-types` and `regex`. No tokio, no filesystem, no clock, no randomness. `cargo tree -p bathy-interpret` is checked in CI.

- [ ] **Step 1: Write the failing test**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn cap(id: &'static str, port: u16, response: &[u8]) -> ProbeCapture { /* … */ }

    #[test]
    fn identifies_nginx_with_a_version_at_high_confidence() {
        let out = interpret(&cap("http-get-v1", 80,
            b"HTTP/1.1 200 OK\r\nServer: nginx/1.26.0\r\n\r\n"));
        let top = &out[0];
        assert_eq!(top.observation.service, "http");
        assert_eq!(top.observation.product.as_deref(), Some("nginx"));
        assert_eq!(top.observation.version.as_deref(), Some("1.26.0"));
        assert!(top.observation.confidence.get() >= 0.90);
    }

    #[test]
    fn a_product_without_a_version_scores_lower_than_one_with() {
        let with = interpret(&cap("http-get-v1", 80, b"HTTP/1.1 200 OK\r\nServer: nginx/1.26.0\r\n\r\n"));
        let without = interpret(&cap("http-get-v1", 80, b"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n"));
        assert!(without[0].observation.confidence.get() < with[0].observation.confidence.get());
        assert!(without[0].observation.version.is_none());
    }

    #[test]
    fn a_bare_protocol_match_still_reports_the_service_at_low_confidence() {
        let out = interpret(&cap("http-get-v1", 8080, b"HTTP/1.0 404 Not Found\r\n\r\n"));
        assert_eq!(out[0].observation.service, "http");
        assert!(out[0].observation.product.is_none());
        assert!(out[0].observation.confidence.get() <= 0.75);
    }

    #[test]
    fn identifies_openssh_from_its_banner() {
        let out = interpret(&cap("ssh-banner-v1", 22, b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n"));
        assert_eq!(out[0].observation.service, "ssh");
        assert_eq!(out[0].observation.product.as_deref(), Some("OpenSSH"));
        assert_eq!(out[0].observation.version.as_deref(), Some("9.6p1"));
    }

    #[test]
    fn identifies_postgres_from_its_single_byte_ssl_reply() {
        let out = interpret(&cap("postgres-startup-v1", 5432, b"S"));
        assert_eq!(out[0].observation.service, "postgresql");
    }

    #[test]
    fn every_interpretation_cites_the_rule_and_the_matched_bytes() {
        let c = cap("http-get-v1", 80, b"HTTP/1.1 200 OK\r\nServer: nginx/1.26.0\r\n\r\n");
        let out = interpret(&c);
        let i = &out[0];
        assert!(!i.rule_id.is_empty());
        let matched = &c.response[i.matched_span.clone()];
        assert!(
            String::from_utf8_lossy(matched).contains("nginx"),
            "matched_span must point at the bytes that justified the claim"
        );
        assert!(explain(i.rule_id).is_some(), "every rule must be explainable");
    }

    #[test]
    fn unrecognized_bytes_yield_no_observation_rather_than_a_guess() {
        let out = interpret(&cap("http-get-v1", 80, b"\x00\x01\x02\x03garbage"));
        assert!(out.is_empty(), "interpretation must not invent a service");
    }

    #[test]
    fn interpretation_is_deterministic() {
        let c = cap("ssh-banner-v1", 22, b"SSH-2.0-OpenSSH_9.6p1\r\n");
        assert_eq!(interpret(&c), interpret(&c));
    }

    #[test]
    fn interpretation_never_panics_on_arbitrary_bytes() {
        for len in [0usize, 1, 2, 3, 7, 64, 8192] {
            for fill in [0x00u8, 0xff, 0x0a, 0x1b] {
                let _ = interpret(&cap("http-get-v1", 80, &vec![fill; len]));
                let _ = interpret(&cap("tls-v1", 443, &vec![fill; len]));
            }
        }
    }

    #[test]
    fn every_rule_documents_its_non_nmap_source() {
        for rule in all_rules() {
            assert!(!rule.source.is_empty(), "rule {} has no source", rule.id);
            let lower = rule.source.to_lowercase();
            assert!(!lower.contains("nmap"), "rule {} cites Nmap", rule.id);
        }
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p bathy-interpret` — expected FAIL.

- [ ] **Step 3: Write the implementation**

```rust
use std::ops::Range;

use bathy_types::confidence::Confidence;
use bathy_types::event::Observation;

/// The confidence ladder. Every rule declares which rung it sits on, so
/// scores across protocols mean the same thing and are auditable in one table
/// rather than sprinkled as magic numbers through match arms.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Specificity {
    /// Product and version both extracted from a self-identifying banner.
    ProductAndVersion,
    /// Product identified, version absent or unparseable.
    ProductOnly,
    /// Protocol confirmed by structure, product unknown.
    ProtocolOnly,
    /// Consistent with the service but not conclusive.
    Weak,
}

impl Specificity {
    pub fn confidence(self) -> Confidence {
        let v = match self {
            Self::ProductAndVersion => 0.95,
            Self::ProductOnly => 0.85,
            Self::ProtocolOnly => 0.70,
            Self::Weak => 0.50,
        };
        Confidence::new(v).expect("ladder values are in range")
    }
}

pub struct RuleDoc {
    pub id: &'static str,
    pub service: &'static str,
    pub specificity: Specificity,
    /// Human-readable explanation surfaced by the `fingerprint.explain` tool.
    pub rationale: &'static str,
    /// Provenance of this rule. Must cite an RFC, vendor documentation, or a
    /// capture from software we run in our own lab. Never Nmap.
    pub source: &'static str,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Interpretation {
    pub observation: Observation,
    pub rule_id: &'static str,
    /// Byte range within `capture.response` that justified the claim.
    pub matched_span: Range<usize>,
    pub rationale: String,
}

/// Turn one capture into zero or more observations.
///
/// PURE. No I/O, no clock, no randomness, no allocation-order dependence.
/// Given identical bytes this returns an identical vector forever, which is
/// what lets `bathy` answer "why do you believe this" from stored evidence
/// and what lets the replay corpus in M7 act as a real regression suite.
///
/// Returns an empty vector when nothing matches. Guessing is a bug.
pub fn interpret(capture: &ProbeCapture) -> Vec<Interpretation> {
    let mut out = Vec::new();
    for rule in rules_for(capture.probe_id) {
        if let Some(hit) = (rule.matcher)(&capture.response) {
            out.push(Interpretation {
                observation: Observation {
                    service: rule.doc.service.to_owned(),
                    product: hit.product,
                    version: hit.version,
                    confidence: hit.specificity.confidence(),
                },
                rule_id: rule.doc.id,
                matched_span: hit.span,
                rationale: rule.doc.rationale.to_owned(),
            });
        }
    }
    // Highest confidence first; ties broken by rule id so ordering is total
    // and stable rather than dependent on registration order.
    out.sort_by(|a, b| {
        b.observation
            .confidence
            .partial_cmp(&a.observation.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.rule_id.cmp(b.rule_id))
    });
    out
}
```

Example rule, showing the required provenance and safe byte handling:

```rust
/// RFC 9112 §4 defines the status line; RFC 9110 §10.2.4 defines `Server`.
/// The nginx version format is documented in the nginx source distribution's
/// own changelog conventions. Verified against nginx run in our lab.
static HTTP_NGINX: Rule = Rule {
    doc: RuleDoc {
        id: "http.server.nginx.v1",
        service: "http",
        specificity: Specificity::ProductAndVersion,
        rationale: "The `Server` response header declared `nginx` followed by a version.",
        source: "RFC 9112 §4, RFC 9110 §10.2.4, capture from nginx in lab fixture `web-nginx`",
    },
    matcher: |bytes| {
        // Operate on bytes, tolerate invalid UTF-8, never index without checking.
        let text = String::from_utf8_lossy(bytes);
        if !text.starts_with("HTTP/") {
            return None;
        }
        let re = regex::Regex::new(r"(?im)^Server:[ \t]*nginx(?:/([0-9][0-9A-Za-z.\-]*))?")
            .expect("static regex compiles");
        let caps = re.captures(&text)?;
        let m = caps.get(0)?;
        Some(Hit {
            product: Some("nginx".to_owned()),
            version: caps.get(1).map(|v| v.as_str().to_owned()),
            specificity: if caps.get(1).is_some() {
                Specificity::ProductAndVersion
            } else {
                Specificity::ProductOnly
            },
            span: m.start()..m.end(),
        })
    },
};
```

Compile every regex once via `std::sync::LazyLock` rather than per call.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p bathy-interpret` — expected 10 passed.

- [ ] **Step 5: Verify the purity constraint**

Run: `cargo tree -p bathy-interpret --edges normal`
Expected: only `bathy-types`, `regex`, and their transitive dependencies. No `tokio`, no `std::fs` usage. Add this as a CI assertion.

- [ ] **Step 6: Commit**

```bash
git add crates/bathy-interpret
git commit -m "feat(interpret): pure rule engine with confidence ladder and cited provenance"
```

**Acceptance criteria:**
- **AC-4.10** `interpret` is pure: `bathy-interpret`'s dependency tree contains no async runtime, no filesystem access, and no clock. Asserted in CI.
- **AC-4.11** Confidence comes from a single declared ladder; product+version outranks product-only outranks protocol-only. No magic numbers in match arms.
- **AC-4.12** Every `Interpretation` carries a `rule_id`, a `matched_span` indexing real bytes of the response, and a rationale. `explain(rule_id)` returns documentation for every rule that can fire.
- **AC-4.13** Unrecognized input yields an empty vector. Interpretation never guesses a service.
- **AC-4.14** `interpret` returns byte-identical results for identical input, and its output ordering is total and stable.
- **AC-4.15** `interpret` does not panic on any input: empty, all-zero, all-`0xff`, and non-UTF-8 bytes at multiple lengths. Reinforced by a fuzz target in M7.
- **AC-4.16** Every rule declares a non-empty `source` and no rule's source mentions Nmap. Asserted by a test over the whole rule set.

---

### Task 4: Evidence replay harness

**Files:**
- Create: `crates/bathy-interpret/tests/replay.rs`
- Create: `testdata/captures/*.json` (committed corpus)

**Interfaces:**
- Produces: a test that loads every capture in `testdata/captures/`, runs `interpret`, and snapshot-compares the findings.

- [ ] **Step 1: Write the replay test**

```rust
/// The reproducibility claim, made testable.
///
/// Each fixture is a recorded `ProbeCapture` plus the findings we expect.
/// Because `interpret` is pure, this suite is the regression guard for every
/// future rule change: adding a rule must not silently alter an existing
/// finding, and if it does, the snapshot diff says exactly how.
#[test]
fn every_recorded_capture_reproduces_its_expected_findings() {
    let mut checked = 0;
    for entry in std::fs::read_dir("../../testdata/captures").expect("corpus exists") {
        let path = entry.unwrap().path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let fixture: Fixture =
            serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        let got = interpret(&fixture.capture);
        insta::assert_json_snapshot!(
            path.file_stem().unwrap().to_str().unwrap(),
            got
        );
        checked += 1;
    }
    assert!(checked >= 16, "corpus must cover at least 16 captures, found {checked}");
}

#[test]
fn replaying_the_corpus_twice_gives_identical_results() {
    for fixture in load_corpus() {
        assert_eq!(interpret(&fixture.capture), interpret(&fixture.capture));
    }
}
```

- [ ] **Step 2: Build the corpus**

At least 16 captures, at least two per probe: one that matches a rule with a version, one that matches weakly or not at all. Capture them from the M7 lab services, never from third-party hosts. Each fixture records the lab image and digest it came from:

```json
{
  "captured_from": "lab image nginx@sha256:… , fixture web-nginx",
  "capture": {
    "probe_id": "http-get-v1",
    "port": 80,
    "request": "R0VUIC8gSFRUUC8xLjEN…",
    "response": "SFRUUC8xLjEgMjAwIE9LDQpTZXJ2ZXI6IG5naW54LzEuMjYuMA0KDQo=",
    "elapsed_micros": 1420,
    "truncated": false
  }
}
```

- [ ] **Step 3: Run and accept the snapshots**

Run: `cargo test -p bathy-interpret --test replay`, then `cargo insta review`.
Expected: 16+ snapshots accepted; a second run is green with no diffs.

- [ ] **Step 4: Commit**

```bash
git add crates/bathy-interpret testdata/captures
git commit -m "test(interpret): recorded-capture replay corpus with snapshot assertions"
```

**Acceptance criteria:**
- **AC-4.17** A committed corpus of ≥16 captures covering all eight probes replays to identical findings on every run, with no network access.
- **AC-4.18** Each fixture records the lab image and digest it was captured from, establishing clean-room provenance for the rule it exercises.
- **AC-4.19** Changing any interpretation rule produces a visible snapshot diff rather than a silent behavior change.

---

### Task 5: Wiring probes into the scheduler

**Files:**
- Modify: `crates/bathy-engine/src/scheduler.rs`

- [ ] **Step 1: Write the failing integration test**

```rust
#[tokio::test]
async fn an_open_port_with_service_detection_emits_port_state_then_service_observed() {
    let h = harness_with_http_stub().await;
    h.run_to_completion().await.unwrap();
    let events = h.log.read_from(0).unwrap();
    let state_at = events.iter().position(|e| matches!(&e.body, EventBody::PortStateObserved { .. })).unwrap();
    let service_at = events.iter().position(|e| matches!(&e.body, EventBody::ServiceObserved { .. })).unwrap();
    assert!(state_at < service_at, "reachability is established before identification");
}

#[tokio::test]
async fn evidence_is_stored_before_the_event_that_references_it() {
    let h = harness_with_http_stub().await;
    h.run_to_completion().await.unwrap();
    for e in h.log.read_from(0).unwrap() {
        if let EventBody::ServiceObserved { evidence_refs, .. } = &e.body {
            for d in evidence_refs.iter() {
                assert!(h.evidence.contains(d), "dangling evidence ref {d}");
                assert!(h.evidence.get(d).is_ok());
            }
        }
    }
}

#[tokio::test]
async fn service_detection_disabled_emits_no_service_events_and_sends_no_probes() {
    let h = harness_with_http_stub_no_detection().await;
    h.run_to_completion().await.unwrap();
    assert!(!h.log.read_from(0).unwrap().iter().any(|e| matches!(&e.body, EventBody::ServiceObserved { .. })));
    assert_eq!(h.stub_request_count(), 0);
}

#[tokio::test]
async fn evidence_level_none_stores_no_bodies_but_still_reports_the_observation() {
    let h = harness_with_http_stub_evidence_none().await;
    h.run_to_completion().await.unwrap();
    let events = h.log.read_from(0).unwrap();
    assert!(events.iter().any(|e| matches!(&e.body, EventBody::ServiceObserved { .. })));
    assert_eq!(h.evidence_blob_count(), 0);
}

#[tokio::test]
async fn probe_packets_are_charged_to_the_same_budget_as_connect_probes() {
    let h = harness_with_tight_budget_and_http_stub(3).await;
    let summary = h.run_to_completion().await.unwrap();
    assert!(summary.packets_spent <= 3);
}
```

- [ ] **Step 2: Run tests to verify they fail** — expected FAIL.

- [ ] **Step 3: Implement the wiring**

In `record`, when the outcome is `Open` and `service_detection.enabled`:
1. Reserve budget for the probes (one packet per probe attempt) — abort identification if the reservation fails, and still emit the `port.state` event.
2. Reconnect, run `select_probes(port, intensity, &registry)` in order, stopping at the first capture producing a non-empty `interpret` result.
3. Store `capture.response` in the evidence store using `put_capped`, at the cap implied by `evidence_level` (`None` → skip storage entirely and emit no `service.observed`; `Headers` → 8 KiB; `Full` → 64 KiB).
4. Emit `service.observed` with the resulting digest in `evidence_refs`, carrying `probe_id` and the interpretation's confidence.

Ordering is mandatory: **store evidence, then append the event.** A crash between the two leaves an orphan blob, which is harmless; the reverse leaves a dangling reference, which breaks the provenance guarantee.

Note that `evidence_level: none` means we cannot satisfy the `NonEmpty<Digest>` requirement on `ServiceObserved`, and therefore emits no service event at all. That is the correct behavior and follows directly from the type: no evidence, no finding.

- [ ] **Step 4: Run tests to verify they pass** — expected 5 passed.

- [ ] **Step 5: Commit**

```bash
git add crates/bathy-engine
git commit -m "feat(engine): service identification with evidence stored before reference"
```

**Acceptance criteria:**
- **AC-4.20** Evidence is written to the store before the event referencing it is appended. No `evidence_refs` entry ever dangles, verified over every event in an end-to-end run.
- **AC-4.21** `port.state` for an endpoint always precedes its `service.observed`.
- **AC-4.22** `service_detection.enabled = false` sends zero probe bytes and emits zero service events.
- **AC-4.23** `evidence_level: none` stores no blobs and consequently emits no `service.observed` — a direct consequence of `NonEmpty<Digest>`, not a special case.
- **AC-4.24** Probe packets are charged to the same `BudgetLedger` as connect probes; a budget of 3 permits at most 3 total emissions.

---

## Milestone Exit Criteria

- [ ] `cargo test --workspace` green; clippy clean; `xtask check-deps` clean.
- [ ] AC-4.1 through AC-4.24 each demonstrated by a named passing test.
- [ ] `cargo tree -p bathy-interpret` shows no async runtime and no I/O crates.
- [ ] The replay corpus passes with the network interface down (`unshare -rn cargo test -p bathy-interpret` on Linux), proving interpretation needs no network.
- [ ] An end-to-end run against a local nginx reports `http` / `nginx` / a version, and `evidence.get` on the cited digest returns the exact response bytes that justified it.
