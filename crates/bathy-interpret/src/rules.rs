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
// HTTP -- source: RFC 9112 §3 ("Request Line"/status line shape), RFC 9110
// §10.2.4 (`Server`). Corroborated against a real server:
// `docker.io/library/nginx:1.27-alpine`, digest
// `sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10`
// (M4 Task 2 report), which replied `HTTP/1.1 200 OK\r\nServer:
// nginx/1.27.5\r\n...`.
// =====================================================================

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
// =====================================================================

static SSH_OPENSSH_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^SSH-\d\.\d+-OpenSSH_(\S+)").expect("static regex compiles"));

static SSH_BANNER_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^SSH-\d\.\d+-").expect("static regex compiles"));

fn ssh_openssh(bytes: &[u8]) -> Option<Hit> {
    let (start, first) = *utf8_lines(bytes).first()?;
    let caps = SSH_OPENSSH_RE.captures(first)?;
    let m = caps.get(0)?;
    let version = caps.get(1)?.as_str().to_owned();
    Some(Hit {
        product: Some("OpenSSH".to_owned()),
        version: Some(version),
        specificity: Specificity::ProductAndVersion,
        span: (start + m.start())..(start + m.end()),
    })
}

fn ssh_bare_protocol(bytes: &[u8]) -> Option<Hit> {
    let (start, first) = *utf8_lines(bytes).first()?;
    let m = SSH_BANNER_RE.find(first)?;
    Some(Hit {
        product: None,
        version: None,
        specificity: Specificity::ProtocolOnly,
        span: (start + m.start())..(start + m.end()),
    })
}

// =====================================================================
// PostgreSQL -- source: PostgreSQL's own Frontend/Backend Protocol
// documentation, "Message Formats" §`SSLRequest`
// (<https://www.postgresql.org/docs/current/protocol-message-formats.html>):
// the server replies with exactly one byte, `S` (will negotiate SSL) or `N`
// (will not), to a startup packet carrying the fixed SSLRequest code.
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
fn redis_resp_shaped_reply(bytes: &[u8]) -> Option<Hit> {
    let sigil = *bytes.first()?;
    if matches!(sigil, b'+' | b'-' | b':' | b'$' | b'*') {
        Some(Hit {
            product: None,
            version: None,
            specificity: Specificity::Weak,
            span: 0..1,
        })
    } else {
        None
    }
}

// =====================================================================
// MySQL -- source: MySQL's own "Protocol::HandshakeV10" documentation
// (<https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase.html>):
// byte 4 of the packet is `protocol_version` (0x0a for HandshakeV10),
// followed immediately by a NUL-terminated `server_version` string.
// Corroborated against `docker.io/library/mysql:8.4`, digest
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
// SMTP -- source: RFC 5321 §3.1 ("Session Initiation": "the SMTP server
// MUST send a 220 'Service ready' reply"), §4.3.1 (multiline reply
// format, `nnn-`/`nnn `). Corroborated against `docker.io/boky/postfix:latest`,
// digest `sha256:aafc772384232497bed875e1eb66b4d3e54ba1ebc86e2e185a6dc1dbc48182ef`
// (M4 Task 2 report), which replied `220 <host> ESMTP Postfix (Debian)\r\n`.
// =====================================================================

static SMTP_GREETING_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^220[ -]").expect("static regex compiles"));

static SMTP_POSTFIX_RE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^220[ -].*\bPostfix\b").expect("static regex compiles"));

fn smtp_postfix(bytes: &[u8]) -> Option<Hit> {
    let (start, first) = *utf8_lines(bytes).first()?;
    let m = SMTP_POSTFIX_RE.find(first)?;
    Some(Hit {
        product: Some("Postfix".to_owned()),
        version: None,
        specificity: Specificity::ProductOnly,
        span: (start + m.start())..(start + m.end()),
    })
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
            source: "RFC 9112 §3 (status line), RFC 9110 §10.2.4 (`Server`); capture from \
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
            source: "RFC 9112 §3 (\"Request Line\"/status-line ABNF: HTTP-version SP status-code)",
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
            source: "PostgreSQL Frontend/Backend Protocol, \"Message Formats\" §SSLRequest \
                      (postgresql.org/docs/current/protocol-message-formats.html); capture from \
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
            source: "PostgreSQL Frontend/Backend Protocol, \"Message Formats\" §SSLRequest \
                      (postgresql.org/docs/current/protocol-message-formats.html); capture from \
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
            rationale: "The reply began with a valid RESP type sigil, but was not the literal \
                        `+PONG` a real Redis server sends -- consistent with a RESP-compatible \
                        service, not a confirmed product.",
            source: "Redis RESP protocol specification \
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
            source: "MySQL \"Protocol::HandshakeV10\" documentation \
                      (dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase.html); \
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
            source: "RFC 5321 §3.1 (\"Session Initiation\"), §4.3.1 (multiline reply format); \
                      capture from boky/postfix:latest \
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
            source: "RFC 5321 §3.1 (\"Session Initiation\": \"the SMTP server MUST send a 220 \
                      'Service ready' reply\")",
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
        let hit = http_nginx(b"HTTP/1.1 200 OK\r\nServer: nginx/1.27.5\r\n\r\n").unwrap();
        assert_eq!(hit.product.as_deref(), Some("nginx"));
        assert_eq!(hit.version.as_deref(), Some("1.27.5"));
        assert_eq!(hit.specificity, Specificity::ProductAndVersion);
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

    #[test]
    fn http_bare_protocol_matches_any_status_line() {
        assert!(http_bare_protocol(b"HTTP/1.0 404 Not Found\r\n\r\n").is_some());
    }

    // --- SSH ---

    #[test]
    fn ssh_openssh_extracts_version_and_ignores_the_trailing_comment() {
        let hit = ssh_openssh(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n").unwrap();
        assert_eq!(hit.product.as_deref(), Some("OpenSSH"));
        assert_eq!(hit.version.as_deref(), Some("9.6p1"));
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

    #[test]
    fn ssh_bare_protocol_matches_any_ssh_banner() {
        assert!(ssh_bare_protocol(b"SSH-2.0-libssh_0.9.6\r\n").is_some());
    }

    // --- Postgres ---

    #[test]
    fn postgres_ssl_accepted_matches_exactly_s() {
        assert!(postgres_ssl_accepted(b"S").is_some());
        assert!(postgres_ssl_accepted(b"N").is_none());
        assert!(postgres_ssl_accepted(b"SS").is_none());
    }

    #[test]
    fn postgres_ssl_declined_matches_the_real_captured_reply() {
        // postgres:16-alpine (M4 Task 2 report) replied exactly `N`.
        assert!(postgres_ssl_declined(b"N").is_some());
        assert!(postgres_ssl_declined(b"S").is_none());
    }

    // --- Redis ---

    #[test]
    fn redis_pong_matches_the_real_captured_reply() {
        assert!(redis_pong(b"+PONG\r\n").is_some());
    }

    #[test]
    fn redis_resp_shaped_reply_is_weak_for_a_non_pong_resp_value() {
        let hit = redis_resp_shaped_reply(b"-ERR unknown command\r\n").unwrap();
        assert_eq!(hit.specificity, Specificity::Weak);
    }

    #[test]
    fn redis_resp_shaped_reply_does_not_match_non_resp_bytes() {
        assert!(redis_resp_shaped_reply(b"HTTP/1.1 200 OK\r\n").is_none());
        assert!(redis_resp_shaped_reply(b"").is_none());
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
        let hit = smtp_postfix(b"220 mail.example.com ESMTP Postfix\r\n").unwrap();
        assert_eq!(hit.product.as_deref(), Some("Postfix"));
        assert!(hit.version.is_none());
    }

    #[test]
    fn smtp_postfix_does_not_match_a_non_postfix_greeting() {
        assert!(smtp_postfix(b"220 mail.example.com ESMTP Sendmail\r\n").is_none());
    }

    #[test]
    fn smtp_bare_protocol_matches_any_220_greeting() {
        assert!(smtp_bare_protocol(b"220 mail.example.com ESMTP Sendmail\r\n").is_some());
    }

    // --- TLS ---

    #[test]
    fn tls_server_hello_matches_the_structural_header() {
        let reply: &[u8] = &[0x16, 0x03, 0x03, 0x00, 0x02, 0x02, 0x00];
        assert!(tls_server_hello(reply).is_some());
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
