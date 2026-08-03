//! `tls-v1`: a raw TLS 1.3 `ClientHello`, with SNI omitted and no ALPN.
//!
//! # Approach: hand-built wire bytes, not a TLS client library
//!
//! This probe assembles the `ClientHello` record byte-for-byte from RFC
//! 8446 and sends it over the raw socket; it does not use `rustls`, or any
//! other TLS implementation, to negotiate anything. It never proceeds past
//! sending that one record: it does not attempt a key exchange, does not
//! derive any handshake secret, does not decrypt anything, and does not
//! validate a certificate. Whatever bytes come back -- a `ServerHello` and
//! (for TLS 1.3) whatever encrypted handshake records follow it, or a
//! plaintext alert if the peer has nothing to say back to a 1.3-only
//! offer -- are captured raw and returned uninterpreted, exactly like
//! every other probe in this crate. There is no dependency this crate
//! could be "induced to trust" here, because nothing in this probe ever
//! evaluates trust at all.
//!
//! source: RFC 8446 (TLS 1.3) -- §4.1.2 for `ClientHello`'s layout
//! (`legacy_version`, `random`, `legacy_session_id`, `cipher_suites`,
//! `legacy_compression_methods`, `extensions`); §5.1 for the record layer
//! (content type `0x16` = handshake, and the `0x0301` legacy record
//! version this document explicitly allows for the first `ClientHello`);
//! §4.2.1 for `supported_versions`; §4.2.7/RFC 8422 for the `x25519`
//! (`0x001D`) named group and `key_share`'s wire format; §4.2.3 for
//! `signature_algorithms` (a server MUST abort the handshake if this
//! extension is missing, per that section, which is why it -- unlike SNI
//! and ALPN -- is included even though this probe never needs it for
//! anything past eliciting a real `ServerHello`); §B.4 for the five
//! defined TLS 1.3 cipher suite identifiers.
//!
//! Corroborated against a real server: `docker.io/library/nginx:1.27-alpine`
//! (digest `sha256:65645c7bb6a0661892a8b03b89d0743208a18dd2f3f17a54ef4b76fb8e2f2a10`)
//! running with a locally generated self-signed certificate (`openssl req
//! -x509 -newkey rsa:2048 ...`, generated fresh for this task, not copied
//! or derived from any other tool's fixtures). Sending exactly the bytes
//! [`build_client_hello`] constructs elicited a
//! real `ServerHello` selecting `TLS_AES_128_GCM_SHA256` and echoing back
//! the `x25519` key-share group -- see this task's report for the full hex
//! capture and the script used to produce it.
//!
//! # Every field is fixed, not generated (AC-4.9)
//!
//! A conformant `ClientHello` needs a 32-byte `random` and a key-share
//! public value, both normally drawn from an RNG by a real TLS client --
//! but this probe never completes a handshake or derives a secret from
//! either, so there is nothing for randomness to protect here, and AC-4.9
//! requires every probe's request bytes to be reproducible for Task 3's
//! replay corpus regardless. Both fields below are therefore fixed
//! constants, documented as such rather than quietly hard-coded.
//!
//! # Why this can't literally capture "certificate bytes" (a plan defect)
//!
//! The M4 Task 2 brief's wire-behavior table describes this probe as
//! capturing "the raw ServerHello and certificate bytes". For a
//! **TLS 1.3** `ClientHello` specifically, that is not achievable: RFC
//! 8446 §4.4 moves `Certificate` (along with `EncryptedExtensions` and
//! `CertificateVerify`) into the encrypted handshake flight, derived from
//! key material this probe deliberately never computes. Only
//! `ClientHello` and `ServerHello` (and a possible `HelloRetryRequest`)
//! are ever sent in the clear under TLS 1.3 -- the certificate is
//! ciphertext to any observer that has not derived the handshake traffic
//! keys, which this probe does not do and must not do (see "Approach"
//! above). This probe therefore captures the `ServerHello` plus whatever
//! raw bytes follow it up to the read cap or deadline -- opaque
//! ciphertext for a real TLS 1.3 peer -- without claiming to have
//! extracted a certificate from them; doing that extraction, on the rare
//! peer that negotiates back down to a plaintext-certificate version
//! instead of aborting, is `bathy-interpret`'s job (M4 Task 3), not this
//! probe's. This is flagged here, rather than silently worked around, per
//! this task's root-cause rule.

use async_trait::async_trait;
use bathy_types::ProbeCapture;

use crate::framework::{Probe, ProbeError, ProbeIo, ProbeKind};

/// Fixed 32-byte `ClientHello.random` -- not real entropy. See this
/// module's "Every field is fixed" note.
const CLIENT_RANDOM: [u8; 32] = {
    let mut r = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        r[i] = i as u8;
        i += 1;
    }
    r
};

/// Fixed 32-byte placeholder `x25519` public key. Never used to derive a
/// real shared secret (this probe never performs the key exchange at
/// all), so it does not need to be, and is not, a genuine ephemeral key.
const FIXED_X25519_KEY: [u8; 32] = [0xAA; 32];

fn u16be(n: u16) -> [u8; 2] {
    n.to_be_bytes()
}

/// Builds the raw `ClientHello` record: TLS 1.3, SNI omitted, no ALPN.
/// Pure and fixed -- identical bytes on every call (AC-4.9).
fn build_client_hello() -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // legacy_version = TLS 1.2 (RFC 8446 4.1.2)
    body.extend_from_slice(&CLIENT_RANDOM);
    body.push(0); // legacy_session_id: empty (no middlebox-compat need here)

    let cipher_suites: [u16; 5] = [0x1301, 0x1302, 0x1303, 0x1304, 0x1305]; // RFC 8446 B.4
    body.extend_from_slice(&u16be((cipher_suites.len() * 2) as u16));
    for cs in cipher_suites {
        body.extend_from_slice(&u16be(cs));
    }
    body.extend_from_slice(&[1, 0]); // legacy_compression_methods = [null]

    let mut ext = Vec::new();
    // supported_versions (0x002b): TLS 1.3 only.
    ext.extend_from_slice(&u16be(0x002b));
    ext.extend_from_slice(&u16be(3)); // extension_data length
    ext.push(2); // versions list length in bytes
    ext.extend_from_slice(&u16be(0x0304));
    // supported_groups (0x000a).
    let groups: [u16; 3] = [0x001D, 0x0017, 0x0018]; // x25519, secp256r1, secp384r1
    ext.extend_from_slice(&u16be(0x000a));
    ext.extend_from_slice(&u16be(2 + groups.len() as u16 * 2));
    ext.extend_from_slice(&u16be(groups.len() as u16 * 2));
    for g in groups {
        ext.extend_from_slice(&u16be(g));
    }
    // signature_algorithms (0x000d) -- mandatory per RFC 8446 4.2.3.
    let sigalgs: [u16; 10] = [
        0x0403, 0x0503, 0x0603, // ecdsa_secp{256r1,384r1,521r1}_sha{256,384,512}
        0x0804, 0x0805, 0x0806, // rsa_pss_rsae_sha{256,384,512}
        0x0401, 0x0501, 0x0601, // rsa_pkcs1_sha{256,384,512}
        0x0807, // ed25519
    ];
    ext.extend_from_slice(&u16be(0x000d));
    ext.extend_from_slice(&u16be(2 + sigalgs.len() as u16 * 2));
    ext.extend_from_slice(&u16be(sigalgs.len() as u16 * 2));
    for s in sigalgs {
        ext.extend_from_slice(&u16be(s));
    }
    // key_share (0x0033): one entry, x25519.
    let mut ks_entry = Vec::new();
    ks_entry.extend_from_slice(&u16be(0x001D)); // x25519
    ks_entry.extend_from_slice(&u16be(32));
    ks_entry.extend_from_slice(&FIXED_X25519_KEY);
    ext.extend_from_slice(&u16be(0x0033));
    ext.extend_from_slice(&u16be(2 + ks_entry.len() as u16));
    ext.extend_from_slice(&u16be(ks_entry.len() as u16));
    ext.extend_from_slice(&ks_entry);
    // Deliberately omitted, per this probe's spec: server_name (SNI) and
    // application_layer_protocol_negotiation (ALPN).

    body.extend_from_slice(&u16be(ext.len() as u16));
    body.extend_from_slice(&ext);

    let mut handshake = vec![0x01]; // HandshakeType::client_hello
    let len = body.len() as u32;
    handshake.extend_from_slice(&len.to_be_bytes()[1..]); // u24 length
    handshake.extend_from_slice(&body);

    let mut record = vec![0x16, 0x03, 0x01]; // handshake, legacy_record_version 0x0301
    record.extend_from_slice(&u16be(handshake.len() as u16));
    record.extend_from_slice(&handshake);
    record
}

pub struct TlsProbe;

#[async_trait]
impl Probe for TlsProbe {
    fn id(&self) -> &'static str {
        "tls-v1"
    }
    fn kind(&self) -> ProbeKind {
        ProbeKind::SendFirst
    }
    fn affinity(&self, port: u16) -> u8 {
        match port {
            443 | 8443 | 993 | 995 => 100,
            _ => 10,
        }
    }
    async fn execute(&self, io: &mut ProbeIo) -> Result<ProbeCapture, ProbeError> {
        let request = build_client_hello();
        let start = std::time::Instant::now();
        io.write_all(&request).await?;
        let (response, truncated) = io.read_bounded().await?;
        if response.is_empty() {
            return Err(ProbeError::EmptyResponse);
        }
        Ok(super::finish_capture(
            self.id(),
            io,
            Some(request),
            start,
            response,
            truncated,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probes::test_support::*;

    #[test]
    fn client_hello_starts_with_a_handshake_record_header() {
        let ch = build_client_hello();
        assert_eq!(ch[0], 0x16, "content type: handshake");
        assert_eq!(&ch[1..3], &[0x03, 0x01], "legacy_record_version 0x0301");
        assert_eq!(ch[5], 0x01, "handshake type: client_hello");
    }

    /// Walks the `extensions` list structurally (skipping
    /// `legacy_version`/`random`/`legacy_session_id`/`cipher_suites`/
    /// `legacy_compression_methods` by their own length prefixes) and
    /// returns each extension's `(type, data)`.
    ///
    /// A naive substring search over the raw bytes for e.g. `[0x00, 0x00]`
    /// (the `server_name` extension type) is unsound here: this
    /// `ClientHello`'s fixed `random` field ends in `...0x1e, 0x1f`,
    /// immediately followed by the zero-length `legacy_session_id` and the
    /// high byte of `cipher_suites`' length, which together produce an
    /// incidental `0x00, 0x00` in the byte stream with nothing to do with
    /// any extension -- caught by writing exactly that substring check
    /// first and watching it wrongly fail; see this task's report. Parsing
    /// the actual TLV structure instead of pattern-matching bytes is the
    /// fix.
    fn extension_types(ch: &[u8]) -> Vec<(u16, &[u8])> {
        let body = &ch[9..]; // skip the 5-byte record header + 4-byte handshake header
        let mut i = 0usize;
        i += 2; // legacy_version
        i += 32; // random
        let session_id_len = body[i] as usize;
        i += 1 + session_id_len;
        let cipher_suites_len = u16::from_be_bytes([body[i], body[i + 1]]) as usize;
        i += 2 + cipher_suites_len;
        let compression_len = body[i] as usize;
        i += 1 + compression_len;
        let extensions_len = u16::from_be_bytes([body[i], body[i + 1]]) as usize;
        i += 2;
        let end = i + extensions_len;
        assert_eq!(
            end,
            body.len(),
            "extensions length must account for every byte"
        );

        let mut out = Vec::new();
        while i < end {
            let ty = u16::from_be_bytes([body[i], body[i + 1]]);
            let len = u16::from_be_bytes([body[i + 2], body[i + 3]]) as usize;
            out.push((ty, &body[i + 4..i + 4 + len]));
            i += 4 + len;
        }
        out
    }

    #[test]
    fn client_hello_advertises_tls_1_3_only_in_supported_versions() {
        let ch = build_client_hello();
        let exts = extension_types(&ch);
        let supported_versions = exts
            .iter()
            .find(|(ty, _)| *ty == 0x002b)
            .expect("supported_versions extension must be present")
            .1;
        assert_eq!(
            supported_versions,
            &[0x02, 0x03, 0x04],
            "must offer exactly one version: TLS 1.3 (0x0304)"
        );
    }

    #[test]
    fn client_hello_omits_sni_and_alpn_but_carries_the_required_extensions() {
        let ch = build_client_hello();
        let types: Vec<u16> = extension_types(&ch).iter().map(|(ty, _)| *ty).collect();
        assert!(
            !types.contains(&0x0000),
            "server_name (SNI) must be omitted"
        );
        assert!(!types.contains(&0x0010), "ALPN must be omitted");
        assert!(types.contains(&0x002b), "supported_versions required");
        assert!(types.contains(&0x000a), "supported_groups required");
        assert!(
            types.contains(&0x000d),
            "signature_algorithms required (RFC 8446 4.2.3: a server MUST abort without it)"
        );
        assert!(types.contains(&0x0033), "key_share required");
    }

    #[test]
    fn client_hello_bytes_are_fixed_across_two_calls() {
        assert_eq!(build_client_hello(), build_client_hello());
    }

    #[test]
    fn client_hello_matches_the_bytes_sent_to_a_real_nginx_tls_1_3_server() {
        // Pinned from the capture recorded in this task's report: sending
        // `build_client_hello()`'s exact output to a real, locally run
        // `nginx:1.27-alpine` container terminating TLS 1.3 produced a
        // genuine `ServerHello` (content type 0x16, handshake type 0x02)
        // selecting `TLS_AES_128_GCM_SHA256`. This test pins the request
        // side of that capture so a future edit changing the wire format
        // is caught here, without needing Docker to run this test.
        let ch = build_client_hello();
        assert_eq!(ch.len(), 147);
        assert_eq!(&ch[0..6], &[0x16, 0x03, 0x01, 0x00, 0x8e, 0x01]);
    }

    #[tokio::test]
    async fn tls_probe_sends_a_client_hello_and_captures_the_raw_reply() {
        // A minimal synthetic ServerHello-shaped reply (content type
        // 0x16, handshake type 0x02) -- this crate never parses it, only
        // proves the bytes flow through uninterpreted.
        let reply: &[u8] = &[0x16, 0x03, 0x03, 0x00, 0x02, 0x02, 0x00];
        let port = stub(reply, true).await;
        let cap = run_probe(&TlsProbe, port).await.unwrap();
        assert_eq!(cap.probe_id, "tls-v1");
        assert_eq!(cap.request.unwrap(), build_client_hello());
        assert_eq!(cap.response, reply.to_vec());
    }

    // --- Beyond the brief: hostile peer (AC-4.7, AC-4.8) ---

    #[tokio::test]
    async fn tls_probe_against_a_flood_stops_at_the_cap() {
        let port = stub_flood().await;
        let cap = run_probe(&TlsProbe, port).await.unwrap();
        assert!(cap.truncated);
        assert!(cap.response.len() <= ProbeIo::DEFAULT_READ_CAP);
    }

    #[tokio::test]
    async fn tls_probe_against_a_silent_peer_errors_rather_than_hangs() {
        let port = stub_silent().await;
        let r = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            run_probe(&TlsProbe, port),
        )
        .await
        .expect("hung past a generous outer bound");
        assert!(matches!(r, Err(ProbeError::EmptyResponse)));
    }

    #[tokio::test]
    async fn tls_probe_against_an_immediately_closed_socket_errors() {
        let port = stub(b"", false).await;
        let r = run_probe(&TlsProbe, port).await;
        assert!(matches!(r, Err(ProbeError::EmptyResponse)));
    }

    // --- Beyond the brief: a real, ignored, Docker-gated integration test ---
    //
    // Not run by `cargo test` (requires Docker + the locally generated
    // self-signed cert set up for this task; see this task's report for
    // the exact commands). Run manually with:
    //   cargo test -p bathy-probe --features "" -- --ignored tls_probe_against_a_real_nginx_tls_1_3_server
    // after starting the container described in this task's report.
    #[tokio::test]
    #[ignore = "requires a local Docker nginx TLS 1.3 container; see task report"]
    async fn tls_probe_against_a_real_nginx_tls_1_3_server() {
        let stream = tokio::net::TcpStream::connect("127.0.0.1:18543")
            .await
            .expect("start the nginx-tls container from this task's report first");
        let mut io = ProbeIo::new(stream, 18543, std::time::Duration::from_secs(3));
        let cap = TlsProbe.execute(&mut io).await.unwrap();
        assert_eq!(cap.response[0], 0x16, "handshake record");
        assert_eq!(cap.response[5], 0x02, "ServerHello");
    }
}
