//! The confidence ladder, the rule registry, and every protocol rule.
//!
//! # The ladder (AC-4.11)
//!
//! [`Specificity`] is the *only* place a confidence number is written down.
//! Every rule below declares a rung, never a literal `f64` -- so a `0.95`
//! anywhere means the same thing ("product and version both extracted from
//! a self-identifying banner") regardless of which protocol produced it,
//! and the whole table is auditable in one place rather than sprinkled as
//! magic numbers through match arms.
//!
//! # Byte safety (verification beyond the brief)
//!
//! Every matcher below is a plain `fn(&[u8]) -> Option<Hit>` operating on
//! attacker-controlled bytes. None of them may panic, and every
//! [`Hit::span`] they produce must be a valid range into the slice they
//! were handed. Two disciplines make that provable rather than merely
//! asserted:
//!
//! - Text-shaped rules (HTTP, SSH, SMTP) never call
//!   `String::from_utf8_lossy` over the *whole* response and then reuse
//!   `regex`'s match offsets as indices into the original bytes. That
//!   combination is unsound: a lossy conversion can change the byte length
//!   of anything after the first invalid byte (a single invalid byte
//!   becomes a 3-byte U+FFFD), so an offset computed against the lossy
//!   `String` does not necessarily land on the same byte -- or even inside
//!   bounds -- of the original slice. **This is a real defect in this
//!   task's own brief**: its worked `HTTP_NGINX` example does exactly this
//!   (`String::from_utf8_lossy(bytes)` over the whole response, then reuses
//!   `caps.get(0)`'s offsets as `matched_span` into the original `bytes`).
//!   It is also, independently, a second defect against this task's own
//!   dispatch instruction ("compile every regex once via `LazyLock`, not
//!   per call"): the brief's example constructs a fresh `regex::Regex` on
//!   every single invocation of the matcher closure. Both are fixed here:
//!   [`utf8_lines`] validates each line's bytes with `std::str::from_utf8`
//!   (strict, not lossy) *before* that line's bytes are ever used to
//!   compute an offset, skipping a line that isn't valid UTF-8 rather than
//!   guessing at where it ends; and every regex below is a module-level
//!   `LazyLock<Regex>`, compiled once for the life of the process. A
//!   response with a binary body after clean text headers (an ordinary
//!   HTTP reply with an image body, for instance) still gets its headers
//!   matched correctly under this scheme, because invalidity in one line
//!   never poisons another line's offsets.
//! - Binary-shaped rules (Postgres, MySQL, DNS, TLS) use only checked
//!   arithmetic (`checked_add`, slice `.get`) and never index past a bound
//!   they have not just verified, so a truncated, malformed, or hostile
//!   packet yields `None` rather than a panic or an out-of-range span.
//!
//! `crate::interpret::tests` property-tests both disciplines' end result
//! (span validity) over arbitrary bytes for the whole rule set at once, not
//! just per protocol.
//!
//! # Provenance
//!
//! Every rule's `source` names an RFC section, a vendor's own protocol
//! documentation, or a capture this project ran itself in Task 2 of this
//! milestone (image, digest, and observed bytes -- see that task's report,
//! `.superpowers/sdd/2026-07-31-bathy-m4-probes-interpret/task-2-report.md`).
//! `nmap` and `nmap-service-probes`, both present on this development
//! machine, were never opened or consulted while writing any rule below --
//! confirmed structurally, not just by this comment, by
//! `crate::tests::every_rule_documents_its_non_nmap_source`.

use std::ops::Range;
use std::sync::LazyLock;

use bathy_types::confidence::Confidence;
use regex::Regex;

/// The confidence ladder. Every rule declares which rung it sits on, so
/// scores across protocols mean the same thing and are auditable in one
/// table rather than sprinkled as magic numbers through match arms
/// (AC-4.11).
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

/// Documentation for one rule, surfaced verbatim by [`explain`] (the
/// `fingerprint.explain` tool's data source in M5).
pub struct RuleDoc {
    pub id: &'static str,
    pub service: &'static str,
    pub specificity: Specificity,
    /// Human-readable explanation of what pattern justified the claim.
    pub rationale: &'static str,
    /// Provenance of this rule. Must cite an RFC, vendor documentation, or
    /// a capture from software run in this project's own lab. Never Nmap.
    pub source: &'static str,
}

/// What a rule's matcher found, before it is wrapped into a public
/// [`crate::interpret::Interpretation`].
pub(crate) struct Hit {
    pub product: Option<String>,
    pub version: Option<String>,
    /// Overrides the rule's own `doc.specificity` when a rule's confidence
    /// genuinely depends on what was found (e.g. product-with-version vs.
    /// product-without-version from the same regex). Rules whose rung never
    /// varies just echo `doc.specificity` here.
    pub specificity: Specificity,
    /// Byte range within the response that justified the claim.
    pub span: Range<usize>,
}

/// One interpretation rule: which probe it applies to, its documentation,
/// and the pure function that decides whether a response matches it.
pub(crate) struct Rule {
    pub probe_id: &'static str,
    pub doc: RuleDoc,
    pub matcher: fn(&[u8]) -> Option<Hit>,
}

/// Every rule applicable to a given probe, in registration order (the order
/// `interpret` iterates them in before its own sort makes order
/// irrelevant).
pub(crate) fn rules_for(probe_id: &str) -> impl Iterator<Item = &'static Rule> {
    ALL_RULES.iter().filter(move |r| r.probe_id == probe_id)
}

/// Every rule's documentation, for exhaustive checks like "no rule cites
/// Nmap" (AC-4.16) and for tools that want to list what this crate can
/// recognize at all.
pub fn all_rules() -> impl Iterator<Item = &'static RuleDoc> {
    ALL_RULES.iter().map(|r| &r.doc)
}

/// Documentation for one rule by id, surfaced by the `fingerprint.explain`
/// tool in M5 (AC-4.12: every rule that can fire must be explainable).
pub fn explain(rule_id: &str) -> Option<&'static RuleDoc> {
    ALL_RULES.iter().map(|r| &r.doc).find(|d| d.id == rule_id)
}

/// Every distinct probe id this crate has at least one rule for -- the
/// "registry" M4 Task 4's replay corpus (`crates/bathy-interpret/tests/replay.rs`)
/// checks each fixture's `probe_id` against, closing that task's own "the
/// corpus is data, so test the data" requirement.
///
/// Deliberately *not* `bathy_probe::framework::ProbeRegistry`'s own id list:
/// depending on `bathy-probe` from this crate, even as a dev-dependency,
/// would contradict this crate's own `src/lib.rs` doc comment (this crate
/// sits *below* `bathy-probe` in the workspace layer order specifically so
/// its tests need no upward dependency at all) and would fail
/// `xtask check-deps`, which inspects a package's dev-dependencies too, not
/// only its normal ones (`find_violations` in `xtask/src/main.rs` does not
/// filter `cargo metadata`'s dependency list by kind). This crate's own rule
/// registry is the authoritative "what probe ids do I know how to interpret"
/// answer from *inside* this crate, which is the only registry `interpret`
/// itself actually consults (see [`rules_for`]) -- a fixture naming a probe
/// id this function doesn't return could never produce a real rule match
/// regardless of what `bathy-probe` itself knows about, so it is exactly the
/// right check for a corpus that exists to regression-test `interpret`.
pub fn known_probe_ids() -> impl Iterator<Item = &'static str> {
    let mut ids: Vec<&'static str> = ALL_RULES.iter().map(|r| r.probe_id).collect();
    ids.sort_unstable();
    ids.dedup();
    ids.into_iter()
}

/// Splits `bytes` on `\n` and returns each line's starting byte offset
/// (relative to `bytes`) together with its content as `&str` -- but only
/// for lines that are themselves valid UTF-8. See this module's doc
/// comment ("Byte safety") for why per-line validation, not a single
/// whole-response `String::from_utf8_lossy`, is what keeps a match's byte
/// offsets valid indices into `bytes` itself.
fn utf8_lines(bytes: &[u8]) -> Vec<(usize, &str)> {
    let mut out = Vec::new();
    let mut start = 0usize;
    for (i, &b) in bytes.iter().enumerate() {
        if b == b'\n' {
            if let Ok(s) = std::str::from_utf8(&bytes[start..i]) {
                out.push((start, s));
            }
            start = i + 1;
        }
    }
    if start < bytes.len()
        && let Ok(s) = std::str::from_utf8(&bytes[start..])
    {
        out.push((start, s));
    }
    out
}

/// Reads a big-endian `u16` at `bytes[at..at+2]`, or `None` if that range
/// runs off the end of `bytes`. The one primitive every binary-shaped
/// matcher below builds its bounds-checked parsing on.
fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    let s = bytes.get(at..at.checked_add(2)?)?;
    Some(u16::from_be_bytes([s[0], s[1]]))
}

// =====================================================================
// HTTP -- source: RFC 9112 §4 ("Status Line": `status-line = HTTP-version
// SP status-code SP [ reason-phrase ]`), RFC 9110 §10.2.4 (`Server`).
// (Root-cause fix, M4 Task 3 review round 1: this previously cited §3,
// which is "Request Line" -- the ABNF for what a *client* sends, not a
// server's response. §4 is the section that actually defines the
// status-line shape these rules match against.) Corroborated against a
// real server: `docker.io/library/nginx:1.27-alpine`, digest
// `sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10`
// (M4 Task 2 report), which replied `HTTP/1.1 200 OK\r\nServer:
// nginx/1.27.5\r\n...`.
// =====================================================================

/// The response's first line that is valid UTF-8 -- not unconditionally its
/// literal first line. A well-formed HTTP status line is always plain
/// ASCII and therefore always valid UTF-8, so for any real HTTP response
/// this distinction is moot: the first valid-UTF-8 line *is* byte 0.
/// [`utf8_lines`] is still what supplies the "valid UTF-8" half of that
/// guarantee, which is why this function is phrased in terms of it rather
/// than indexing `bytes` directly.
fn http_status_line(bytes: &[u8]) -> Option<(usize, &str)> {
    let (start, first) = *utf8_lines(bytes).first()?;
    if first.starts_with("HTTP/") {
        Some((start, first))
    } else {
        None
    }
}

static NGINX_SERVER_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?i)^Server:[ \t]*nginx(?:/([0-9][0-9A-Za-z.\-]*))?")
        .expect("static regex compiles")
});

fn http_nginx(bytes: &[u8]) -> Option<Hit> {
    http_status_line(bytes)?;
    for (line_start, line) in utf8_lines(bytes) {
        let Some(caps) = NGINX_SERVER_RE.captures(line) else {
            continue;
        };
        let m = caps.get(0)?;
        let version = caps.get(1).map(|v| v.as_str().to_owned());
        let specificity = if version.is_some() {
            Specificity::ProductAndVersion
        } else {
            Specificity::ProductOnly
        };
        return Some(Hit {
            product: Some("nginx".to_owned()),
            version,
            specificity,
            span: (line_start + m.start())..(line_start + m.end()),
        });
    }
    None
}

fn http_bare_protocol(bytes: &[u8]) -> Option<Hit> {
    let (start, first) = http_status_line(bytes)?;
    Some(Hit {
        product: None,
        version: None,
        specificity: Specificity::ProtocolOnly,
        span: start..(start + first.len()),
    })
}

// =====================================================================
// SSH -- source: RFC 4253 §4.2 ("Protocol Version Exchange"). Corroborated
// against `docker.io/linuxserver/openssh-server:latest`, digest
// `sha256:96b9a4d3b5106746d08d43a6911650d4d21f7d5c7f2ac9660e792bdb5e63157c`
// (M4 Task 2 report), which sent `SSH-2.0-OpenSSH_10.3\r\n` unprompted.
//
// Both matchers below scan *every* line, not just the first, and stop at
// the first one that matches. This is not defensive-for-its-own-sake:
// §4.2 itself says "The server MAY send other lines of data before
// sending the version string... Such lines MUST NOT begin with 'SSH-'...
// Clients MUST be able to process such lines." A matcher that only ever
// looked at line 0 would false-negative on exactly this RFC-sanctioned
// case -- a real, spec-compliant server whose banner isn't byte 0. (Root-
// cause fix, M4 Task 3 review round 1: an earlier version of both
// functions here called `utf8_lines(bytes).first()`, which is *always*
// offset 0 by construction -- so it both missed this case and made the
// `line_start + …` term in `Hit::span` provably dead code, indistinguishable
// by any test from a version that dropped the offset entirely. See
// `tests::ssh_openssh_finds_the_identification_line_after_a_preamble_line`.)
// =====================================================================

static SSH_OPENSSH_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^SSH-\d\.\d+-OpenSSH_(\S+)").expect("static regex compiles"));

static SSH_BANNER_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^SSH-\d\.\d+-").expect("static regex compiles"));

fn ssh_openssh(bytes: &[u8]) -> Option<Hit> {
    for (line_start, line) in utf8_lines(bytes) {
        let Some(caps) = SSH_OPENSSH_RE.captures(line) else {
            continue;
        };
        let m = caps.get(0)?;
        let version = caps.get(1)?.as_str().to_owned();
        return Some(Hit {
            product: Some("OpenSSH".to_owned()),
            version: Some(version),
            specificity: Specificity::ProductAndVersion,
            span: (line_start + m.start())..(line_start + m.end()),
        });
    }
    None
}

fn ssh_bare_protocol(bytes: &[u8]) -> Option<Hit> {
    for (line_start, line) in utf8_lines(bytes) {
        if let Some(m) = SSH_BANNER_RE.find(line) {
            return Some(Hit {
                product: None,
                version: None,
                specificity: Specificity::ProtocolOnly,
                span: (line_start + m.start())..(line_start + m.end()),
            });
        }
    }
    None
}

// =====================================================================
// PostgreSQL -- source: PostgreSQL's own Frontend/Backend Protocol
// documentation, split across two pages of the same doc set, not one:
//
// - The *request* bytes (an 8-byte message: length 8, then the fixed
//   SSLRequest code 80877103) are "Message Formats" §SSLRequest
//   (<https://www.postgresql.org/docs/current/protocol-message-formats.html>).
//   That page defines what the client sends; it does not document the
//   server's reply at all.
// - The *reply*'s meaning is documented separately, in "Protocol Flow"
//   §54.2.10 ("SSL Session Encryption",
//   <https://www.postgresql.org/docs/current/protocol-flow.html>): "The
//   server then responds with a single byte containing S or N, indicating
//   that it is willing or unwilling to perform SSL, respectively." (Root-
//   cause fix, M4 Task 3 review round 1: both rules below previously cited
//   only the request-format page for this fact too -- verified against the
//   live page, which covers the request shape only.)
//
// Corroborated against `docker.io/library/postgres:16-alpine`, digest
// `sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777`
// (M4 Task 2 report), which replied `N` (run without SSL configured) to
// exactly the 8 bytes `postgres-startup-v1` sends.
// =====================================================================

fn postgres_ssl_accepted(bytes: &[u8]) -> Option<Hit> {
    if bytes == b"S" {
        Some(Hit {
            product: None,
            version: None,
            specificity: Specificity::ProtocolOnly,
            span: 0..1,
        })
    } else {
        None
    }
}

fn postgres_ssl_declined(bytes: &[u8]) -> Option<Hit> {
    if bytes == b"N" {
        Some(Hit {
            product: None,
            version: None,
            specificity: Specificity::ProtocolOnly,
            span: 0..1,
        })
    } else {
        None
    }
}

// =====================================================================
// Redis -- source: Redis's own RESP protocol specification
// (<https://redis.io/docs/latest/develop/reference/protocol-spec/>): a
// simple string reply is `+<text>\r\n`. Corroborated against
// `docker.io/library/redis:7-alpine`, digest
// `sha256:e7723ff73d963f5cc6d9c4643ea3d989527a402a319239054e9472a7fb9219a2`
// (M4 Task 2 report), which replied `+PONG\r\n` to exactly the RESP `PING`
// `redis-ping-v1` sends.
// =====================================================================

fn redis_pong(bytes: &[u8]) -> Option<Hit> {
    let prefix = b"+PONG";
    if bytes.starts_with(prefix) {
        Some(Hit {
            product: None,
            version: None,
            specificity: Specificity::ProtocolOnly,
            span: 0..prefix.len(),
        })
    } else {
        None
    }
}

/// Weak-tier fallback: *some* RESP-shaped reply came back (one of the five
/// type sigils RESP defines -- simple string, error, integer, bulk string,
/// array), but not literally `+PONG`. Genuinely weaker evidence than
/// [`redis_pong`]: several Redis-protocol-compatible servers (e.g. KeyDB,
/// Dragonfly) reply to `PING` with a valid but non-identical RESP value, so
/// this recognizes the *wire format*, not the product -- exactly
/// [`Specificity::Weak`]'s definition ("consistent with the service but not
/// conclusive"), not a guess that it is Redis itself.
///
/// Requires an actual `\r\n` terminator (RESP's own line terminator, per
/// the RESP protocol specification's "Simple strings" section: "terminated
/// by CRLF") after the sigil, not just a matching first byte. (Root-cause
/// fix, M4 Task 3 review round 1: a single stray byte from an arbitrary
/// binary protocol -- `0x2b` alone, say -- happens to equal `+` and
/// previously matched on its own; requiring the terminator this rule's own
/// rationale claims to have found is what makes "RESP-shaped" an honest
/// description rather than a one-byte coincidence.)
fn redis_resp_shaped_reply(bytes: &[u8]) -> Option<Hit> {
    let sigil = *bytes.first()?;
    if !matches!(sigil, b'+' | b'-' | b':' | b'$' | b'*') {
        return None;
    }
    let crlf_at = bytes.windows(2).position(|w| w == b"\r\n")?;
    Some(Hit {
        product: None,
        version: None,
        specificity: Specificity::Weak,
        span: 0..(crlf_at + 2),
    })
}

// =====================================================================
// MySQL -- source: MySQL's own "Protocol::HandshakeV10" *packet-layout*
// page
// (<https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase_packets_protocol_handshake_v10.html>)
// -- not the "Connection Phase" overview page this previously cited, which
// only links to the packet layout without itself listing the fields
// (verified against the live page; root-cause fix, M4 Task 3 review round
// 1). The layout page's own field table lists `protocol_version` as
// `int<1>`, "Always 10", as the first field, with `server_version` --
// `string<NUL>` -- immediately after it. Byte 4 of the packet is therefore
// `protocol_version` (0x0a for HandshakeV10), followed immediately by the
// NUL-terminated `server_version` string. Corroborated against
// `docker.io/library/mysql:8.4`, digest
// `sha256:b3b90af2a6552ae30c266fdb7d5dd55f3afb72404bb78d37fe8a23eb857fd3fb`
// (M4 Task 2 report), whose captured `HandshakeV10` packet's version string
// reads `8.4.11` -- the exact bytes reused as this rule's own test fixture
// below.
// =====================================================================

fn mysql_handshake_v10(bytes: &[u8]) -> Option<Hit> {
    const PROTOCOL_VERSION_OFFSET: usize = 4;
    const VERSION_STRING_START: usize = 5;
    if *bytes.get(PROTOCOL_VERSION_OFFSET)? != 0x0a {
        return None;
    }
    let rest = bytes.get(VERSION_STRING_START..)?;
    let nul = rest.iter().position(|&b| b == 0)?;
    if nul == 0 {
        return None; // empty version string: nothing to report
    }
    let version_end = VERSION_STRING_START + nul;
    let version = std::str::from_utf8(&bytes[VERSION_STRING_START..version_end]).ok()?;
    Some(Hit {
        product: Some("MySQL".to_owned()),
        version: Some(version.to_owned()),
        specificity: Specificity::ProductAndVersion,
        span: VERSION_STRING_START..version_end,
    })
}

// =====================================================================
// DNS (version.bind/TXT/CHAOS) -- source: RFC 1035 §4.1.1 (header),
// §4.1.2 (question section), §3.2.2 (TXT, type 16), §3.2.4 (CH/Chaos,
// class 3), §4.2.2 (TCP's 2-byte length prefix), §3.3.14 (TXT RDATA is a
// sequence of length-prefixed character-strings); the `version.bind`
// convention itself is documented by BIND's own manual
// (<https://bind9.readthedocs.io/en/latest/reference.html>, "Built-in
// Server Information Zones"). Corroborated against
// `docker.io/internetsystemsconsortium/bind9:9.18`, digest
// `sha256:1ffb29c718ee2540c5643c1e8166629a07bbd505f99107baae535e9f86eb7eef`
// (M4 Task 2 report), whose captured reply carries a TXT record reading
// `9.18.50` -- the exact bytes reused as this rule's own test fixture
// below.
// =====================================================================

/// Skips one DNS name starting at `at` (a run of length-prefixed labels
/// terminated by a zero-length label, or a two-byte compression pointer --
/// RFC 1035 §4.1.4), returning the offset just past it, or `None` if the
/// name runs off the end of `bytes`.
fn dns_skip_name(bytes: &[u8], mut at: usize) -> Option<usize> {
    loop {
        let len = *bytes.get(at)?;
        if len == 0 {
            return at.checked_add(1);
        }
        if len & 0xC0 == 0xC0 {
            // Compression pointer: exactly 2 bytes, does not recurse into
            // the name it points at -- not needed for this rule's purpose.
            bytes.get(at.checked_add(1)?)?;
            return at.checked_add(2);
        }
        at = at.checked_add(1)?.checked_add(len as usize)?;
    }
}

fn dns_bind_version(bytes: &[u8]) -> Option<Hit> {
    let msg_len = u16_at(bytes, 0)? as usize;
    let msg_start = 2usize;
    let msg_end = msg_start.checked_add(msg_len)?;
    if msg_end > bytes.len() {
        return None;
    }

    let flags = u16_at(bytes, msg_start.checked_add(2)?)?;
    if flags & 0x8000 == 0 {
        return None; // QR bit: must be a response, not a query
    }
    let qdcount = u16_at(bytes, msg_start.checked_add(4)?)?;
    let ancount = u16_at(bytes, msg_start.checked_add(6)?)?;
    if ancount == 0 {
        return None;
    }

    let mut at = msg_start.checked_add(12)?; // past the fixed 12-byte header
    for _ in 0..qdcount {
        at = dns_skip_name(bytes, at)?;
        at = at.checked_add(4)?; // QTYPE + QCLASS
        if at > msg_end {
            return None;
        }
    }

    for _ in 0..ancount {
        at = dns_skip_name(bytes, at)?;
        let rtype = u16_at(bytes, at)?;
        let rclass = u16_at(bytes, at.checked_add(2)?)?;
        let rdlength = u16_at(bytes, at.checked_add(8)?)? as usize; // TYPE+CLASS+TTL = 8
        let rdata_start = at.checked_add(10)?;
        let rdata_end = rdata_start.checked_add(rdlength)?;
        if rdata_end > msg_end || rdata_end > bytes.len() {
            return None;
        }

        if rtype == 16 && rclass == 3 {
            // TXT/CH: RDATA is a length-prefixed character-string.
            let txt_len = *bytes.get(rdata_start)? as usize;
            let txt_start = rdata_start.checked_add(1)?;
            let txt_end = txt_start.checked_add(txt_len)?;
            if txt_end > rdata_end {
                return None;
            }
            let version = std::str::from_utf8(&bytes[txt_start..txt_end]).ok()?;
            if version.is_empty() {
                return None;
            }
            return Some(Hit {
                product: Some("BIND".to_owned()),
                version: Some(version.to_owned()),
                specificity: Specificity::ProductAndVersion,
                span: txt_start..txt_end,
            });
        }
        at = rdata_end;
    }
    None
}

// =====================================================================
// SMTP -- source: RFC 5321 §3.1 ("Session Initiation": "An SMTP session is
// initiated when a client opens a connection to a server and the server
// responds with an opening message" -- §3.1 itself permits a 554 reply
// here instead of 220, so this is a description of the usual case, not a
// promise about wording); §4.3.1 ("Sequencing Overview": "Normally, a
// receiver will send a 220 'Service ready' reply" -- likewise descriptive);
// §4.2 ("SMTP Replies": the `nnn-`/`nnn ` multiline reply ABNF these
// rules' regexes depend on). (Root-cause fix, M4 Task 3 review round 1:
// this previously attributed the quotation "the SMTP server MUST send a
// 220 'Service ready' reply" to §3.1 -- that sentence does not appear
// anywhere in §3.1, RFC 5321 makes no MUST-level promise about the
// greeting at all, and the real "Normally... will send" sentence is in
// §4.3.1, not §3.1. The multiline-reply ABNF was also miscited to §4.3.1
// -- it is in §4.2, "SMTP Replies". Verified against the live RFC text for
// this fix, not re-derived from the earlier, uncorroborated citation.)
// Corroborated against `docker.io/boky/postfix:latest`,
// digest `sha256:aafc772384232497bed875e1eb66b4d3e54ba1ebc86e2e185a6dc1dbc48182ef`
// (M4 Task 2 report), which replied `220 <host> ESMTP Postfix (Debian)\r\n`.
// =====================================================================

static SMTP_GREETING_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^220[ -]").expect("static regex compiles"));

static SMTP_POSTFIX_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^220[ -].*\bPostfix\b").expect("static regex compiles"));

/// Scans every line, not just the first: RFC 5321 §4.2's own ABNF for the
/// `Greeting` allows a *multiline* 220 reply (`"220-" Domain [SP text] CRLF
/// *("220-" [text] CRLF) "220" SP [text] CRLF`), so the text naming a
/// product may legitimately be on a continuation line rather than the very
/// first one. (Root-cause fix, M4 Task 3 review round 1: an earlier
/// version only checked `utf8_lines(bytes).first()`, which is always
/// offset 0 -- making `Hit::span`'s offset term dead code for every
/// realistic single-line-greeting test, the same issue fixed in
/// `ssh_openssh` above. See
/// `tests::smtp_postfix_finds_the_product_on_a_continuation_line`.)
fn smtp_postfix(bytes: &[u8]) -> Option<Hit> {
    for (line_start, line) in utf8_lines(bytes) {
        if let Some(m) = SMTP_POSTFIX_RE.find(line) {
            return Some(Hit {
                product: Some("Postfix".to_owned()),
                version: None,
                specificity: Specificity::ProductOnly,
                span: (line_start + m.start())..(line_start + m.end()),
            });
        }
    }
    None
}

fn smtp_bare_protocol(bytes: &[u8]) -> Option<Hit> {
    let (start, first) = *utf8_lines(bytes).first()?;
    let m = SMTP_GREETING_RE.find(first)?;
    Some(Hit {
        product: None,
        version: None,
        specificity: Specificity::ProtocolOnly,
        span: (start + m.start())..(start + m.end()),
    })
}

// =====================================================================
// TLS -- source: RFC 8446 §5.1 (record layer: content type `0x16` =
// handshake) and §4 (`HandshakeType::server_hello` = `0x02`). Corroborated
// against `docker.io/library/nginx:1.27-alpine` (same digest as the HTTP
// rule above) terminating TLS 1.3 with a locally generated self-signed
// certificate (M4 Task 2 report): sending `tls-v1`'s `ClientHello` elicited
// a real `ServerHello` with exactly this record/handshake-type header.
// Structural only, deliberately: RFC 8446 §4.4 moves `Certificate` into the
// encrypted handshake flight for TLS 1.3, so no product or version can be
// read from these bytes without first decrypting them, which this probe
// (and this rule) never does -- see `bathy_probe::probes::tls`'s own doc
// comment for the same point made about the probe side.
// =====================================================================

fn tls_server_hello(bytes: &[u8]) -> Option<Hit> {
    const CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
    const HANDSHAKE_TYPE_SERVER_HELLO: u8 = 0x02;
    const HEADER_LEN: usize = 6; // 5-byte record header + 1-byte handshake type
    let header = bytes.get(0..HEADER_LEN)?;
    if header[0] != CONTENT_TYPE_HANDSHAKE || header[5] != HANDSHAKE_TYPE_SERVER_HELLO {
        return None;
    }
    Some(Hit {
        product: None,
        version: None,
        specificity: Specificity::ProtocolOnly,
        span: 0..HEADER_LEN,
    })
}

// =====================================================================
// The registry.
// =====================================================================

static ALL_RULES: &[Rule] = &[
    Rule {
        probe_id: "http-get-v1",
        doc: RuleDoc {
            id: "http.server.nginx.v1",
            service: "http",
            specificity: Specificity::ProductAndVersion,
            rationale: "The `Server` response header declared `nginx`, optionally followed by a version.",
            source: "RFC 9112 §4 (\"Status Line\"), RFC 9110 §10.2.4 (`Server`); capture from \
                      nginx:1.27-alpine (digest sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10), \
                      M4 Task 2 report",
        },
        matcher: http_nginx,
    },
    Rule {
        probe_id: "http-get-v1",
        doc: RuleDoc {
            id: "http.protocol.bare.v1",
            service: "http",
            specificity: Specificity::ProtocolOnly,
            rationale: "The response's first line is a well-formed HTTP status line, but no \
                        `Server` header matched any known product.",
            source: "RFC 9112 §4 (\"Status Line\": `status-line = HTTP-version SP status-code SP \
                      [ reason-phrase ]`)",
        },
        matcher: http_bare_protocol,
    },
    Rule {
        probe_id: "ssh-banner-v1",
        doc: RuleDoc {
            id: "ssh.banner.openssh.v1",
            service: "ssh",
            specificity: Specificity::ProductAndVersion,
            rationale: "The SSH identification string named the OpenSSH software version, per \
                        the `SSH-protoversion-softwareversion` format.",
            source: "RFC 4253 §4.2 (\"Protocol Version Exchange\"); capture from \
                      linuxserver/openssh-server:latest \
                      (digest sha256:96b9a4d3b5106746d08d43a6911650d4d21f7d5c7f2ac9660e792bdb5e63157c), \
                      M4 Task 2 report",
        },
        matcher: ssh_openssh,
    },
    Rule {
        probe_id: "ssh-banner-v1",
        doc: RuleDoc {
            id: "ssh.protocol.bare.v1",
            service: "ssh",
            specificity: Specificity::ProtocolOnly,
            rationale: "The response is a well-formed SSH identification string, but the \
                        software field did not match any known product.",
            source: "RFC 4253 §4.2 (\"Protocol Version Exchange\": SSH-protoversion-softwareversion)",
        },
        matcher: ssh_bare_protocol,
    },
    Rule {
        probe_id: "postgres-startup-v1",
        doc: RuleDoc {
            id: "postgres.sslrequest.accepted.v1",
            service: "postgresql",
            specificity: Specificity::ProtocolOnly,
            rationale: "The server replied with the single byte `S`, PostgreSQL's documented \
                        SSLRequest reply meaning it will negotiate SSL.",
            source: "PostgreSQL \"Protocol Flow\" §54.2.10 (\"SSL Session Encryption\": \"The \
                      server then responds with a single byte containing S or N, indicating \
                      that it is willing or unwilling to perform SSL, respectively.\" -- \
                      postgresql.org/docs/current/protocol-flow.html); capture from \
                      postgres:16-alpine (digest sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777), \
                      M4 Task 2 report",
        },
        matcher: postgres_ssl_accepted,
    },
    Rule {
        probe_id: "postgres-startup-v1",
        doc: RuleDoc {
            id: "postgres.sslrequest.declined.v1",
            service: "postgresql",
            specificity: Specificity::ProtocolOnly,
            rationale: "The server replied with the single byte `N`, PostgreSQL's documented \
                        SSLRequest reply meaning it will not negotiate SSL.",
            source: "PostgreSQL \"Protocol Flow\" §54.2.10 (\"SSL Session Encryption\": \"The \
                      server then responds with a single byte containing S or N, indicating \
                      that it is willing or unwilling to perform SSL, respectively.\" -- \
                      postgresql.org/docs/current/protocol-flow.html); capture from \
                      postgres:16-alpine (digest sha256:57c72fd2a128e416c7fcc499958864df5301e940bca0a56f58fddf30ffc07777), \
                      M4 Task 2 report -- the container itself replied `N`",
        },
        matcher: postgres_ssl_declined,
    },
    Rule {
        probe_id: "redis-ping-v1",
        doc: RuleDoc {
            id: "redis.ping.pong.v1",
            service: "redis",
            specificity: Specificity::ProtocolOnly,
            rationale: "The server replied `+PONG`, RESP's documented reply to the `PING` command.",
            source: "Redis RESP protocol specification \
                      (redis.io/docs/latest/develop/reference/protocol-spec/); capture from \
                      redis:7-alpine (digest sha256:e7723ff73d963f5cc6d9c4643ea3d989527a402a319239054e9472a7fb9219a2), \
                      M4 Task 2 report",
        },
        matcher: redis_pong,
    },
    Rule {
        probe_id: "redis-ping-v1",
        doc: RuleDoc {
            id: "redis.protocol.resp_shaped.v1",
            service: "redis",
            specificity: Specificity::Weak,
            rationale: "The reply began with a valid RESP type sigil and carried a proper CRLF \
                        line terminator, but was not the literal `+PONG` a real Redis server \
                        sends -- consistent with a RESP-compatible service, not a confirmed \
                        product.",
            source: "Redis RESP protocol specification, \"Simple strings\" (a reply is \
                      \"terminated by CRLF\") \
                      (redis.io/docs/latest/develop/reference/protocol-spec/), structural only",
        },
        matcher: redis_resp_shaped_reply,
    },
    Rule {
        probe_id: "mysql-greeting-v1",
        doc: RuleDoc {
            id: "mysql.handshake.v10.v1",
            service: "mysql",
            specificity: Specificity::ProductAndVersion,
            rationale: "The greeting's protocol-version byte was 0x0a (HandshakeV10), followed \
                        by a NUL-terminated server-version string.",
            source: "MySQL \"Protocol::HandshakeV10\" field-layout table (protocol_version: \
                      int<1>, \"Always 10\"; immediately followed by server_version: \
                      string<NUL>) -- dev.mysql.com/doc/dev/mysql-server/latest/\
                      page_protocol_connection_phase_packets_protocol_handshake_v10.html; \
                      capture from mysql:8.4 \
                      (digest sha256:b3b90af2a6552ae30c266fdb7d5dd55f3afb72404bb78d37fe8a23eb857fd3fb), \
                      M4 Task 2 report",
        },
        matcher: mysql_handshake_v10,
    },
    Rule {
        probe_id: "dns-version-bind-v1",
        doc: RuleDoc {
            id: "dns.version_bind.txt_chaos.v1",
            service: "dns",
            specificity: Specificity::ProductAndVersion,
            rationale: "The reply's answer section carried a TXT/CH record -- the documented \
                        response to a `version.bind` query -- containing a version string.",
            source: "RFC 1035 §4.1.1 (header), §4.1.2 (question), §3.2.2 (TXT), §3.2.4 (CH), \
                      §4.2.2 (TCP length prefix), §3.3.14 (TXT RDATA); BIND manual, \"Built-in \
                      Server Information Zones\" (bind9.readthedocs.io/en/latest/reference.html); \
                      capture from internetsystemsconsortium/bind9:9.18 \
                      (digest sha256:1ffb29c718ee2540c5643c1e8166629a07bbd505f99107baae535e9f86eb7eef), \
                      M4 Task 2 report",
        },
        matcher: dns_bind_version,
    },
    Rule {
        probe_id: "smtp-banner-v1",
        doc: RuleDoc {
            id: "smtp.banner.postfix.v1",
            service: "smtp",
            specificity: Specificity::ProductOnly,
            rationale: "The 220 greeting named Postfix. Postfix's greeting does not carry a \
                        version number, so no version can be extracted.",
            source: "RFC 5321 §4.2 (\"SMTP Replies\": the `nnn-`/`nnn ` multiline reply ABNF \
                      this rule's regex scans every line for a match against); capture from \
                      boky/postfix:latest \
                      (digest sha256:aafc772384232497bed875e1eb66b4d3e54ba1ebc86e2e185a6dc1dbc48182ef), \
                      M4 Task 2 report",
        },
        matcher: smtp_postfix,
    },
    Rule {
        probe_id: "smtp-banner-v1",
        doc: RuleDoc {
            id: "smtp.protocol.bare.v1",
            service: "smtp",
            specificity: Specificity::ProtocolOnly,
            rationale: "The response is a well-formed 220 SMTP greeting, but no product name in \
                        it matched any known rule.",
            source: "RFC 5321 §4.3.1 (\"Sequencing Overview\": \"Normally, a receiver will send \
                      a 220 'Service ready' reply\" -- descriptive, not a MUST; §3.1 explicitly \
                      permits a 554 reply instead), §4.2 (\"SMTP Replies\": `nnn-`/`nnn ` \
                      multiline reply ABNF)",
        },
        matcher: smtp_bare_protocol,
    },
    Rule {
        probe_id: "tls-v1",
        doc: RuleDoc {
            id: "tls.serverhello.structural.v1",
            service: "tls",
            specificity: Specificity::ProtocolOnly,
            rationale: "The reply's record layer carried content type 0x16 (handshake) with an \
                        inner handshake type of 0x02 (ServerHello) -- confirms a TLS server \
                        answered, but (for TLS 1.3) the certificate is encrypted, so no product \
                        or version can be read from these bytes.",
            source: "RFC 8446 §5.1 (record layer), §4 (handshake type registry); capture from \
                      nginx:1.27-alpine (same digest as http.server.nginx.v1) terminating TLS \
                      1.3 with a locally generated self-signed certificate, M4 Task 2 report",
        },
        matcher: tls_server_hello,
    },
];

#[cfg(test)]
mod tests {
    use super::*;

    // --- known_probe_ids ---

    #[test]
    fn known_probe_ids_lists_every_probe_this_crate_has_rules_for_deduped_and_sorted() {
        // Pinned against M4 Task 2's eight real probe ids by name -- a
        // change here (an id added, removed, or renamed) is exactly the
        // kind of thing M4 Task 4's replay corpus depends on staying in
        // sync with the fixtures under `testdata/captures/`.
        let ids: Vec<&str> = known_probe_ids().collect();
        assert_eq!(
            ids,
            vec![
                "dns-version-bind-v1",
                "http-get-v1",
                "mysql-greeting-v1",
                "postgres-startup-v1",
                "redis-ping-v1",
                "smtp-banner-v1",
                "ssh-banner-v1",
                "tls-v1",
            ]
        );
    }

    // --- The ladder ---

    #[test]
    fn ladder_orders_product_and_version_above_product_only_above_protocol_only_above_weak() {
        assert!(
            Specificity::ProductAndVersion.confidence().get()
                > Specificity::ProductOnly.confidence().get()
        );
        assert!(
            Specificity::ProductOnly.confidence().get()
                > Specificity::ProtocolOnly.confidence().get()
        );
        assert!(
            Specificity::ProtocolOnly.confidence().get() > Specificity::Weak.confidence().get()
        );
    }

    // --- utf8_lines ---

    #[test]
    fn utf8_lines_splits_on_newline_and_reports_correct_offsets() {
        let bytes = b"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n";
        let lines = utf8_lines(bytes);
        assert_eq!(lines[0], (0, "HTTP/1.1 200 OK\r"));
        assert_eq!(lines[1].0, 17);
        assert!(lines[1].1.starts_with("Server: nginx"));
    }

    #[test]
    fn utf8_lines_skips_a_line_that_is_not_valid_utf8_but_keeps_earlier_and_later_lines() {
        let mut bytes = b"clean line one\n".to_vec();
        bytes.extend_from_slice(&[0xff, 0xfe, b'\n']); // not valid UTF-8
        bytes.extend_from_slice(b"clean line three\n");
        let lines = utf8_lines(&bytes);
        let texts: Vec<&str> = lines.iter().map(|(_, s)| *s).collect();
        assert_eq!(texts, vec!["clean line one", "clean line three"]);
    }

    #[test]
    fn utf8_lines_never_panics_on_empty_input() {
        assert!(utf8_lines(&[]).is_empty());
    }

    // --- HTTP ---

    #[test]
    fn http_nginx_extracts_product_and_version() {
        let bytes = b"HTTP/1.1 200 OK\r\nServer: nginx/1.27.5\r\n\r\n";
        let hit = http_nginx(bytes).unwrap();
        assert_eq!(hit.product.as_deref(), Some("nginx"));
        assert_eq!(hit.version.as_deref(), Some("1.27.5"));
        assert_eq!(hit.specificity, Specificity::ProductAndVersion);
        assert_eq!(&bytes[hit.span.clone()], b"Server: nginx/1.27.5");
    }

    #[test]
    fn http_nginx_without_a_version_is_product_only() {
        let hit = http_nginx(b"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n").unwrap();
        assert!(hit.version.is_none());
        assert_eq!(hit.specificity, Specificity::ProductOnly);
    }

    #[test]
    fn http_nginx_does_not_match_a_non_http_response() {
        assert!(http_nginx(b"Server: nginx/1.27.5\r\n").is_none());
    }

    #[test]
    fn http_nginx_does_not_match_a_different_server_header() {
        assert!(http_nginx(b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.62\r\n\r\n").is_none());
    }

    // --- Soundness regression: the brief's own worked example reused
    // `String::from_utf8_lossy` offsets as indices into the original
    // bytes, which silently cites the wrong bytes (or panics) once
    // anything before the match isn't valid UTF-8. These two tests are
    // built to fail under that unsound version specifically -- reverting
    // `http_nginx` to a whole-response-lossy-conversion implementation and
    // running the suite is this task's own review-round-1 finding; see the
    // fix report for the reproduced failure. ---

    #[test]
    fn http_nginx_cites_the_correct_bytes_when_invalid_utf8_precedes_the_match() {
        // A stray 0x80 (a lone UTF-8 continuation byte, invalid on its own)
        // sits on an earlier header line, strictly before the `Server:`
        // line that actually matches. `utf8_lines` skips only that one
        // invalid line; `http_nginx` must still report a span pointing at
        // the real `Server:` bytes, at their real offset in the original
        // buffer -- not an offset computed against a lossy re-encoding of
        // the whole response (which would grow by 2 bytes at the one
        // invalid byte, a `String::from_utf8_lossy` implementation would
        // silently misalign every offset after it).
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"HTTP/1.1 200 OK\r\n");
        bytes.extend_from_slice(b"X-Bad: \x80\r\n");
        bytes.extend_from_slice(b"Server: nginx/1.26.0\r\n");
        bytes.extend_from_slice(b"\r\n");
        let hit = http_nginx(&bytes).unwrap();
        assert_eq!(hit.version.as_deref(), Some("1.26.0"));
        assert_eq!(
            &bytes[hit.span.clone()],
            b"Server: nginx/1.26.0",
            "span must index the real bytes even with invalid UTF-8 earlier in the response"
        );
    }

    #[test]
    fn http_nginx_span_stays_in_bounds_when_the_match_ends_at_the_last_byte() {
        // No trailing CRLF at all: the `Server:` line is both the match
        // and the literal last byte of the buffer. A lossy-offset
        // implementation whose earlier invalid byte inflated every
        // downstream offset by 2 would push `span.end` past
        // `bytes.len()`, which panics on the slice index below rather than
        // merely being wrong.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"HTTP/1.1 200 OK\r\n");
        bytes.extend_from_slice(b"X-Bad: \x80\r\n");
        bytes.extend_from_slice(b"Server: nginx/1.26.0"); // ends the buffer, no CRLF
        let hit = http_nginx(&bytes).unwrap();
        assert_eq!(
            hit.span.end,
            bytes.len(),
            "the match ends exactly at the buffer's end"
        );
        assert_eq!(&bytes[hit.span.clone()], b"Server: nginx/1.26.0");
    }

    #[test]
    fn http_bare_protocol_matches_any_status_line() {
        let bytes = b"HTTP/1.0 404 Not Found\r\n\r\n";
        let hit = http_bare_protocol(bytes).unwrap();
        assert_eq!(
            &bytes[hit.span.clone()],
            b"HTTP/1.0 404 Not Found\r",
            "span must be exactly the status line, not the whole response"
        );
    }

    // --- SSH ---

    #[test]
    fn ssh_openssh_extracts_version_and_ignores_the_trailing_comment() {
        let bytes = b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n";
        let hit = ssh_openssh(bytes).unwrap();
        assert_eq!(hit.product.as_deref(), Some("OpenSSH"));
        assert_eq!(hit.version.as_deref(), Some("9.6p1"));
        assert_eq!(&bytes[hit.span.clone()], b"SSH-2.0-OpenSSH_9.6p1");
    }

    #[test]
    fn ssh_openssh_matches_the_real_captured_banner_with_no_comment() {
        // The exact banner captured from linuxserver/openssh-server:latest
        // in M4 Task 2 (see this module's source note).
        let hit = ssh_openssh(b"SSH-2.0-OpenSSH_10.3\r\n").unwrap();
        assert_eq!(hit.version.as_deref(), Some("10.3"));
    }

    #[test]
    fn ssh_openssh_does_not_match_a_non_openssh_banner() {
        assert!(ssh_openssh(b"SSH-2.0-libssh_0.9.6\r\n").is_none());
    }

    // RFC 4253 §4.2: "The server MAY send other lines of data before
    // sending the version string... Clients MUST be able to process such
    // lines." A matcher that only ever looked at line 0 would false-
    // negative here; it would also make `Hit::span`'s line-offset term
    // untestable (offset 0 either way). This is both the false-negative
    // fix and its own regression test, together.
    #[test]
    fn ssh_openssh_finds_the_identification_line_after_a_preamble_line() {
        let bytes = b"Some preamble the server sent first\r\nSSH-2.0-OpenSSH_9.6p1\r\n";
        let hit = ssh_openssh(bytes).unwrap();
        assert_eq!(hit.version.as_deref(), Some("9.6p1"));
        assert_eq!(&bytes[hit.span.clone()], b"SSH-2.0-OpenSSH_9.6p1");
        assert!(
            hit.span.start > 0,
            "the identification line is not at offset 0 here, so this also proves the \
             line-offset term in Hit::span is real, not dead code"
        );
    }

    #[test]
    fn ssh_bare_protocol_matches_any_ssh_banner() {
        let bytes = b"SSH-2.0-libssh_0.9.6\r\n";
        let hit = ssh_bare_protocol(bytes).unwrap();
        assert_eq!(&bytes[hit.span.clone()], b"SSH-2.0-");
    }

    #[test]
    fn ssh_bare_protocol_finds_the_identification_line_after_a_preamble_line() {
        let bytes = b"Some preamble the server sent first\r\nSSH-2.0-libssh_0.9.6\r\n";
        let hit = ssh_bare_protocol(bytes).unwrap();
        assert_eq!(&bytes[hit.span.clone()], b"SSH-2.0-");
        assert!(hit.span.start > 0);
    }

    // --- Postgres ---

    #[test]
    fn postgres_ssl_accepted_matches_exactly_s() {
        let hit = postgres_ssl_accepted(b"S").unwrap();
        assert_eq!(&b"S"[hit.span.clone()], b"S");
        assert!(postgres_ssl_accepted(b"N").is_none());
        assert!(postgres_ssl_accepted(b"SS").is_none());
    }

    #[test]
    fn postgres_ssl_declined_matches_the_real_captured_reply() {
        // postgres:16-alpine (M4 Task 2 report) replied exactly `N`.
        let hit = postgres_ssl_declined(b"N").unwrap();
        assert_eq!(&b"N"[hit.span.clone()], b"N");
        assert!(postgres_ssl_declined(b"S").is_none());
    }

    // --- Redis ---

    #[test]
    fn redis_pong_matches_the_real_captured_reply() {
        let bytes = b"+PONG\r\n";
        let hit = redis_pong(bytes).unwrap();
        assert_eq!(&bytes[hit.span.clone()], b"+PONG");
    }

    #[test]
    fn redis_resp_shaped_reply_is_weak_for_a_non_pong_resp_value() {
        let bytes = b"-ERR unknown command\r\n";
        let hit = redis_resp_shaped_reply(bytes).unwrap();
        assert_eq!(hit.specificity, Specificity::Weak);
        assert_eq!(&bytes[hit.span.clone()], b"-ERR unknown command\r\n");
    }

    #[test]
    fn redis_resp_shaped_reply_does_not_match_non_resp_bytes() {
        assert!(redis_resp_shaped_reply(b"HTTP/1.1 200 OK\r\n").is_none());
        assert!(redis_resp_shaped_reply(b"").is_none());
    }

    // --- Root-cause fix, M4 Task 3 review round 1: a single stray sigil
    // byte with no CRLF terminator used to match on its own -- one byte
    // from an arbitrary binary protocol is not meaningful RESP evidence.
    #[test]
    fn redis_resp_shaped_reply_rejects_a_lone_sigil_byte_with_no_crlf() {
        assert!(redis_resp_shaped_reply(b"+").is_none());
        assert!(redis_resp_shaped_reply(b"+X").is_none());
        assert!(redis_resp_shaped_reply(b"+no terminator here").is_none());
    }

    // --- MySQL ---

    // The real handshake packet captured from `mysql:8.4` (M4 Task 2
    // report), reused verbatim here as this rule's own fixture.
    const MYSQL_GREETING_HEX: &str = "4a0000000a382e342e3131000800000062215a7649740441\
                                       00ffffff0200ffdf1500000000000000000000441e1b514b\
                                       4e6e53084a5c270063616368696e675f736861325f706173\
                                       73776f726400";

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn mysql_handshake_v10_extracts_the_real_captured_version() {
        let bytes = hex_to_bytes(MYSQL_GREETING_HEX);
        let hit = mysql_handshake_v10(&bytes).unwrap();
        assert_eq!(hit.product.as_deref(), Some("MySQL"));
        assert_eq!(hit.version.as_deref(), Some("8.4.11"));
        // Asserted independently of `hit.version` above: `version` and
        // `span` are computed from the same offsets in the real code, but
        // a mutant that shifts only `Hit::span` (leaving the string
        // extraction that produces `.version` untouched) would pass the
        // assertion above while citing the wrong bytes. Re-deriving the
        // expected text from `hit.span` itself is what catches that.
        assert_eq!(&bytes[hit.span.clone()], b"8.4.11");
    }

    #[test]
    fn mysql_handshake_v10_rejects_a_short_packet() {
        assert!(mysql_handshake_v10(b"\x0a\x00").is_none());
    }

    #[test]
    fn mysql_handshake_v10_rejects_a_non_handshake_v10_protocol_byte() {
        let mut bytes = hex_to_bytes(MYSQL_GREETING_HEX);
        bytes[4] = 0x09; // not HandshakeV10
        assert!(mysql_handshake_v10(&bytes).is_none());
    }

    #[test]
    fn mysql_handshake_v10_rejects_a_missing_nul_terminator() {
        let bytes = vec![0u8, 0, 0, 0, 0x0a, b'8', b'.', b'4']; // no trailing NUL
        assert!(mysql_handshake_v10(&bytes).is_none());
    }

    // --- DNS ---

    // The real reply captured from `internetsystemsconsortium/bind9:9.18`
    // (M4 Task 2 report), reused verbatim as this rule's own fixture.
    const BIND_REPLY_HEX: &str = "00405344840000010001000100000776657273696f6e0462696e6400001000\
                                   03c00c0010000300000000000807392e31382e3530c00c00020003000000000\
                                   002c00c";

    #[test]
    fn dns_bind_version_extracts_the_real_captured_version() {
        let bytes = hex_to_bytes(BIND_REPLY_HEX);
        let hit = dns_bind_version(&bytes).unwrap();
        assert_eq!(hit.product.as_deref(), Some("BIND"));
        assert_eq!(hit.version.as_deref(), Some("9.18.50"));
        // See the identical comment on the MySQL test above: re-derive the
        // expected text from `hit.span` itself, independent of whatever
        // internal offsets produced `.version`, so a span-only shift is
        // caught even when `.version` still happens to be correct.
        assert_eq!(&bytes[hit.span.clone()], b"9.18.50");
    }

    #[test]
    fn dns_bind_version_rejects_a_query_not_a_response() {
        // Same shape as the real query bathy_probe::probes::dns::build_query
        // sends (QR bit clear).
        let query: Vec<u8> = [
            0x00, 0x1e, 0x53, 0x44, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 7,
            b'v', b'e', b'r', b's', b'i', b'o', b'n', 4, b'b', b'i', b'n', b'd', 0, 0x00, 0x10,
            0x00, 0x03,
        ]
        .to_vec();
        assert!(dns_bind_version(&query).is_none());
    }

    #[test]
    fn dns_bind_version_rejects_truncated_bytes_without_panicking() {
        let full = hex_to_bytes(BIND_REPLY_HEX);
        for cut in 0..full.len() {
            assert!(dns_bind_version(&full[..cut]).is_none());
        }
    }

    #[test]
    fn dns_skip_name_rejects_a_label_length_that_runs_past_the_end() {
        // A label byte of 63 (top two bits clear, so a genuine label
        // length -- not a compression pointer, which needs the top two
        // bits set per RFC 1035 §4.1.4) claiming 63 more bytes in a
        // 3-byte buffer must not panic or wrap; it must simply fail to
        // resolve.
        assert!(dns_skip_name(&[63, 1, 2], 0).is_none());
    }

    #[test]
    fn dns_skip_name_treats_a_top_bits_set_byte_as_a_two_byte_compression_pointer() {
        // 200 = 0b1100_1000: top two bits set, so RFC 1035 §4.1.4 defines
        // this as a compression pointer, not a 200-byte label -- it
        // consumes exactly 2 bytes regardless of what follows.
        assert_eq!(dns_skip_name(&[200, 1, 2], 0), Some(2));
    }

    // --- SMTP ---

    #[test]
    fn smtp_postfix_matches_the_real_captured_greeting() {
        let bytes = b"220 mail.example.com ESMTP Postfix\r\n";
        let hit = smtp_postfix(bytes).unwrap();
        assert_eq!(hit.product.as_deref(), Some("Postfix"));
        assert!(hit.version.is_none());
        assert_eq!(
            &bytes[hit.span.clone()],
            b"220 mail.example.com ESMTP Postfix"
        );
    }

    #[test]
    fn smtp_postfix_does_not_match_a_non_postfix_greeting() {
        assert!(smtp_postfix(b"220 mail.example.com ESMTP Sendmail\r\n").is_none());
    }

    // RFC 5321 §4.2's own `Greeting` ABNF allows a multiline 220 reply
    // (`"220-" Domain [SP text] CRLF *("220-" [text] CRLF) "220" SP [text]
    // CRLF`); the product name may legitimately be on a continuation line,
    // not the first one. This also forces `line_start > 0`, which is what
    // makes the offset term in `Hit::span` observable at all -- see the
    // identical point made on the SSH tests above.
    #[test]
    fn smtp_postfix_finds_the_product_on_a_continuation_line() {
        let bytes = b"220-mail.example.com ESMTP\r\n220 Postfix ready\r\n";
        let hit = smtp_postfix(bytes).unwrap();
        assert_eq!(hit.product.as_deref(), Some("Postfix"));
        assert!(
            hit.span.start > 0,
            "the matching line is not at offset 0 here"
        );
        assert_eq!(&bytes[hit.span.clone()], b"220 Postfix");
    }

    #[test]
    fn smtp_bare_protocol_matches_any_220_greeting() {
        let bytes = b"220 mail.example.com ESMTP Sendmail\r\n";
        let hit = smtp_bare_protocol(bytes).unwrap();
        assert_eq!(&bytes[hit.span.clone()], b"220 ");
    }

    // --- TLS ---

    #[test]
    fn tls_server_hello_matches_the_structural_header() {
        let reply: &[u8] = &[0x16, 0x03, 0x03, 0x00, 0x02, 0x02, 0x00];
        let hit = tls_server_hello(reply).unwrap();
        assert_eq!(
            &reply[hit.span.clone()],
            &[0x16, 0x03, 0x03, 0x00, 0x02, 0x02]
        );
    }

    #[test]
    fn tls_server_hello_does_not_match_a_non_handshake_record() {
        let alert: &[u8] = &[0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x00];
        assert!(tls_server_hello(alert).is_none());
    }

    #[test]
    fn tls_server_hello_rejects_a_too_short_buffer_without_panicking() {
        for len in 0..6 {
            assert!(tls_server_hello(&vec![0x16; len]).is_none());
        }
    }
}
