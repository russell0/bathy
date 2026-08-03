//! `interpret`: the single pure entry point that turns a [`ProbeCapture`]
//! into zero or more [`Interpretation`]s.

use std::ops::Range;

use bathy_types::ProbeCapture;
use bathy_types::event::Observation;

use crate::rules::rules_for;

/// One claim `interpret` made about a capture, and the evidence for it.
///
/// Every field here exists to make the claim falsifiable: `rule_id` names
/// exactly which rule fired (`explain(rule_id)` always resolves it,
/// AC-4.12), and `matched_span` indexes the *real bytes* of the response
/// that justified it -- not a paraphrase, the actual slice.
#[derive(Clone, Debug, PartialEq)]
pub struct Interpretation {
    pub observation: Observation,
    pub rule_id: &'static str,
    /// Byte range within `capture.response` that justified the claim.
    /// Always a valid range into that slice: `matched_span.start <=
    /// matched_span.end <= capture.response.len()`.
    pub matched_span: Range<usize>,
    pub rationale: String,
}

/// Turn one capture into zero or more observations.
///
/// PURE. No I/O, no clock, no randomness, no allocation-order dependence.
/// Given identical bytes this returns an identical vector forever, which is
/// what lets `bathy` answer "why do you believe this" from stored evidence
/// and what lets the replay corpus in M4 Task 4 act as a real regression
/// suite.
///
/// Returns an empty vector when nothing matches (AC-4.13). Guessing a
/// service from bytes that do not structurally confirm it is a bug, not a
/// feature -- see `tests::unrecognized_bytes_yield_no_observation_rather_than_a_guess`.
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
    sort_stable(out)
}

/// Highest confidence first; ties broken by `rule_id` so the ordering is
/// total and stable rather than dependent on registration order or (were
/// this ever backed by a hash-based collection) iteration order (AC-4.14).
/// Factored out of `interpret` so this ordering guarantee is directly unit-
/// and property-testable without needing a real rule match to exercise it.
pub(crate) fn sort_stable(mut out: Vec<Interpretation>) -> Vec<Interpretation> {
    out.sort_by(|a, b| {
        b.observation
            .confidence
            .partial_cmp(&a.observation.confidence)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.rule_id.cmp(b.rule_id))
    });
    out
}

#[cfg(test)]
mod tests {
    use bathy_types::Transport;
    use bathy_types::confidence::Confidence;
    use proptest::prelude::*;

    use super::*;

    fn cap(id: &'static str, port: u16, response: &[u8]) -> ProbeCapture {
        ProbeCapture {
            probe_id: id,
            transport: Transport::Tcp,
            port,
            request: None,
            response: response.to_vec(),
            elapsed_micros: 0,
            truncated: false,
        }
    }

    // --- Determinism / ordering (AC-4.14), isolated from any specific
    // rule's matching logic -- this is `interpret`'s own sort behavior. ---

    fn observation(confidence: f64) -> Observation {
        Observation {
            service: "test".to_string(),
            product: None,
            version: None,
            confidence: Confidence::new(confidence).unwrap(),
        }
    }

    fn interp(rule_id: &'static str, confidence: f64) -> Interpretation {
        Interpretation {
            observation: observation(confidence),
            rule_id,
            matched_span: 0..0,
            rationale: String::new(),
        }
    }

    #[test]
    fn sort_stable_orders_by_confidence_descending() {
        let out = sort_stable(vec![interp("a", 0.5), interp("b", 0.9), interp("c", 0.7)]);
        let ids: Vec<&str> = out.iter().map(|i| i.rule_id).collect();
        assert_eq!(ids, vec!["b", "c", "a"]);
    }

    #[test]
    fn tie_break_is_by_rule_id_not_registration_order() {
        // Three equal-confidence interpretations registered in a
        // deliberately non-alphabetical order: the sort must still produce
        // ascending rule_id, proving the tiebreak is the id itself, not
        // whatever order they happened to be pushed in.
        let out = sort_stable(vec![
            interp("zebra", 0.8),
            interp("apple", 0.8),
            interp("mango", 0.8),
        ]);
        let ids: Vec<&str> = out.iter().map(|i| i.rule_id).collect();
        assert_eq!(ids, vec!["apple", "mango", "zebra"]);
    }

    proptest! {
        #[test]
        fn sort_stable_is_deterministic_and_produces_a_total_order(
            confidences in proptest::collection::vec(0.0f64..=1.0, 0..8),
        ) {
            let ids = ["a", "b", "c", "d", "e", "f", "g", "h"];
            let items: Vec<Interpretation> = confidences
                .iter()
                .enumerate()
                .map(|(i, &c)| interp(ids[i], c))
                .collect();
            let sorted_once = sort_stable(items.clone());
            let sorted_twice = sort_stable(items);
            prop_assert_eq!(&sorted_once, &sorted_twice);
            for w in sorted_once.windows(2) {
                let a = w[0].observation.confidence.get();
                let b = w[1].observation.confidence.get();
                prop_assert!(
                    a > b || (a == b && w[0].rule_id <= w[1].rule_id),
                    "not totally ordered: {a} ({}) then {b} ({})",
                    w[0].rule_id,
                    w[1].rule_id
                );
            }
        }
    }

    // --- From the brief (Step 1) ---

    #[test]
    fn identifies_nginx_with_a_version_at_high_confidence() {
        let out = interpret(&cap(
            "http-get-v1",
            80,
            b"HTTP/1.1 200 OK\r\nServer: nginx/1.26.0\r\n\r\n",
        ));
        let top = &out[0];
        assert_eq!(top.observation.service, "http");
        assert_eq!(top.observation.product.as_deref(), Some("nginx"));
        assert_eq!(top.observation.version.as_deref(), Some("1.26.0"));
        assert!(top.observation.confidence.get() >= 0.90);
    }

    #[test]
    fn a_product_without_a_version_scores_lower_than_one_with() {
        let with = interpret(&cap(
            "http-get-v1",
            80,
            b"HTTP/1.1 200 OK\r\nServer: nginx/1.26.0\r\n\r\n",
        ));
        let without = interpret(&cap(
            "http-get-v1",
            80,
            b"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n",
        ));
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
        let out = interpret(&cap(
            "ssh-banner-v1",
            22,
            b"SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13\r\n",
        ));
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
        let c = cap(
            "http-get-v1",
            80,
            b"HTTP/1.1 200 OK\r\nServer: nginx/1.26.0\r\n\r\n",
        );
        let out = interpret(&c);
        let i = &out[0];
        assert!(!i.rule_id.is_empty());
        let matched = &c.response[i.matched_span.clone()];
        assert!(
            String::from_utf8_lossy(matched).contains("nginx"),
            "matched_span must point at the bytes that justified the claim"
        );
        assert!(
            crate::explain(i.rule_id).is_some(),
            "every rule must be explainable"
        );
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

    // --- Verification beyond the brief ---

    #[test]
    fn interpretation_never_panics_on_lone_surrogate_shaped_byte_sequences() {
        // `0xED 0xA0 0x80` is the WTF-8-style attempted encoding of U+D800
        // (a lone high surrogate) -- invalid per RFC 3629 (UTF-8 excludes
        // the surrogate range D800-DFFF), so `std::str::from_utf8` must
        // reject it. Exercised at several lengths and against every probe
        // id this crate has rules for, not just http/tls.
        let surrogate: [u8; 3] = [0xED, 0xA0, 0x80];
        for probe_id in [
            "http-get-v1",
            "tls-v1",
            "ssh-banner-v1",
            "smtp-banner-v1",
            "dns-version-bind-v1",
            "postgres-startup-v1",
            "mysql-greeting-v1",
            "redis-ping-v1",
        ] {
            for reps in [1usize, 5, 500] {
                let bytes: Vec<u8> = surrogate.iter().cycle().take(reps * 3).copied().collect();
                let _ = interpret(&cap(probe_id, 1, &bytes));
            }
        }
    }

    #[test]
    fn interpretation_never_panics_across_every_known_probe_id_and_many_byte_shapes() {
        let probe_ids = [
            "http-get-v1",
            "tls-v1",
            "ssh-banner-v1",
            "smtp-banner-v1",
            "dns-version-bind-v1",
            "postgres-startup-v1",
            "mysql-greeting-v1",
            "redis-ping-v1",
            "totally-unknown-probe-id",
        ];
        for probe_id in probe_ids {
            for len in [0usize, 1, 2, 4, 5, 6, 8, 9, 10, 11, 45, 66, 300] {
                for fill in [0x00u8, 0xff, 0x0a, 0x16, 0x02, b'S', b'N'] {
                    let _ = interpret(&cap(probe_id, 1, &vec![fill; len]));
                }
            }
        }
    }

    // --- Structured strategies for the property tests below ---
    //
    // Root-cause fix, M4 Task 3 review round 1: the original version of
    // both property tests below generated *fully arbitrary* bytes
    // (`proptest::collection::vec(any::<u8>(), 0..300)`) and picked among
    // 8 known probe ids uniformly. Reviewed at 4096 cases: only 6 ever
    // produced a non-empty `interpret` result, and none of those 6
    // produced a span with `end > 6` -- meaning the property never once
    // reached the offset arithmetic in `http_nginx`, `ssh_openssh`,
    // `smtp_postfix`, `dns_bind_version`, or `mysql_handshake_v10`. A
    // property test that (almost) never exercises the code path it claims
    // to cover is not evidence for that coverage; citing it as AC-4.12
    // evidence, as this task's own report did, was not supportable.
    //
    // The strategies below generate a *protocol-shaped* response for a
    // matching probe id most of the time (weight 3 per protocol below,
    // 24 total), each parameterized by proptest-chosen random fields
    // (version numbers, hostnames, DNS record content, ...) and passed
    // through `with_corruption`, which -- itself randomly, per case --
    // either leaves the bytes alone, truncates them at a random point, or
    // splices a random extra byte in at a random point. That keeps every
    // rule's happy path, near-miss path, and truncation/corruption path
    // all live and reachable, not just the near-certain "matches nothing"
    // outcome of pure `any::<u8>()` bytes. A residual arm (weight 6) still
    // generates fully arbitrary bytes against an arbitrary probe id
    // (including an unknown one), preserving the original "never panics /
    // never guesses on garbage" coverage the vacuous version did provide.

    /// Randomly leaves `valid` bytes alone, truncates them at a random
    /// point, or splices one random extra byte in at a random point.
    fn with_corruption(valid: impl Strategy<Value = Vec<u8>>) -> impl Strategy<Value = Vec<u8>> {
        (valid, 0u8..3, any::<usize>(), any::<u8>()).prop_map(|(bytes, mode, at, extra)| match mode
        {
            0 => bytes,
            1 => {
                if bytes.is_empty() {
                    bytes
                } else {
                    let cut = at % (bytes.len() + 1);
                    bytes[..cut].to_vec()
                }
            }
            _ => {
                let mut b = bytes;
                let pos = at % (b.len() + 1);
                b.insert(pos, extra);
                b
            }
        })
    }

    fn http_valid_bytes() -> impl Strategy<Value = Vec<u8>> {
        (1u16..500, 0u16..500, 0u16..500, any::<bool>()).prop_map(
            |(major, minor, patch, with_version)| {
                let server = if with_version {
                    format!("nginx/{major}.{minor}.{patch}")
                } else {
                    "nginx".to_string()
                };
                format!("HTTP/1.1 200 OK\r\nServer: {server}\r\n\r\n").into_bytes()
            },
        )
    }

    fn ssh_valid_bytes() -> impl Strategy<Value = Vec<u8>> {
        (1u16..50, 0u16..50, any::<bool>()).prop_map(|(major, minor, with_patch)| {
            let patch = if with_patch {
                format!("p{minor}")
            } else {
                String::new()
            };
            format!("SSH-2.0-OpenSSH_{major}.{minor}{patch}\r\n").into_bytes()
        })
    }

    fn smtp_valid_bytes() -> impl Strategy<Value = Vec<u8>> {
        (0u32..1000, any::<bool>()).prop_map(|(host_n, is_postfix)| {
            let software = if is_postfix { "Postfix" } else { "Sendmail" };
            format!("220 host{host_n}.example.com ESMTP {software}\r\n").into_bytes()
        })
    }

    fn mysql_valid_bytes() -> impl Strategy<Value = Vec<u8>> {
        (
            0u8..30,
            0u8..30,
            0u8..30,
            proptest::collection::vec(any::<u8>(), 0..20),
        )
            .prop_map(|(major, minor, patch, trailing)| {
                let mut bytes = vec![0u8, 0, 0, 0, 0x0a]; // header + protocol_version
                bytes.extend_from_slice(format!("{major}.{minor}.{patch}").as_bytes());
                bytes.push(0); // NUL terminator
                bytes.extend_from_slice(&trailing);
                bytes
            })
    }

    /// Builds a synthetic-but-wire-valid `version.bind`/TXT/CHAOS reply
    /// (the same shape `dns_bind_version` in `rules.rs` parses, and the
    /// same shape the real BIND capture in that module's tests has), with
    /// a proptest-chosen transaction id and version string.
    fn build_synthetic_dns_reply(id: u16, version: &str) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(&id.to_be_bytes());
        msg.extend_from_slice(&0x8400u16.to_be_bytes()); // flags: response
        msg.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        msg.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT
        msg.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        msg.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
        for label in ["version", "bind"] {
            msg.push(label.len() as u8);
            msg.extend_from_slice(label.as_bytes());
        }
        msg.push(0); // root label
        msg.extend_from_slice(&16u16.to_be_bytes()); // QTYPE TXT
        msg.extend_from_slice(&3u16.to_be_bytes()); // QCLASS CH
        msg.extend_from_slice(&[0xC0, 0x0C]); // answer name: pointer to offset 12
        msg.extend_from_slice(&16u16.to_be_bytes()); // TYPE TXT
        msg.extend_from_slice(&3u16.to_be_bytes()); // CLASS CH
        msg.extend_from_slice(&0u32.to_be_bytes()); // TTL
        let rdata_len = 1 + version.len();
        msg.extend_from_slice(&(rdata_len as u16).to_be_bytes());
        msg.push(version.len() as u8);
        msg.extend_from_slice(version.as_bytes());

        let mut framed = Vec::with_capacity(2 + msg.len());
        framed.extend_from_slice(&(msg.len() as u16).to_be_bytes());
        framed.extend_from_slice(&msg);
        framed
    }

    fn dns_valid_bytes() -> impl Strategy<Value = Vec<u8>> {
        (any::<u16>(), 1usize..15).prop_map(|(id, version_len)| {
            let version: String = (0..version_len)
                .map(|i| (b'0' + (i % 10) as u8) as char)
                .collect();
            build_synthetic_dns_reply(id, &version)
        })
    }

    fn tls_valid_bytes() -> impl Strategy<Value = Vec<u8>> {
        proptest::collection::vec(any::<u8>(), 0..50).prop_map(|trailing| {
            let mut bytes = vec![0x16, 0x03, 0x03, 0x00, 0x02, 0x02];
            bytes.extend_from_slice(&trailing);
            bytes
        })
    }

    fn redis_valid_bytes() -> impl Strategy<Value = Vec<u8>> {
        prop_oneof![
            Just(b"+PONG\r\n".to_vec()),
            Just(b"-ERR unknown command\r\n".to_vec()),
            Just(b":1000\r\n".to_vec()),
            Just(b"$-1\r\n".to_vec()),
        ]
    }

    fn postgres_valid_bytes() -> impl Strategy<Value = Vec<u8>> {
        prop_oneof![Just(b"S".to_vec()), Just(b"N".to_vec())]
    }

    fn probe_and_response_strategy() -> impl Strategy<Value = (&'static str, Vec<u8>)> {
        prop_oneof![
            3 => with_corruption(http_valid_bytes()).prop_map(|b| ("http-get-v1", b)),
            3 => with_corruption(ssh_valid_bytes()).prop_map(|b| ("ssh-banner-v1", b)),
            3 => with_corruption(smtp_valid_bytes()).prop_map(|b| ("smtp-banner-v1", b)),
            3 => with_corruption(mysql_valid_bytes()).prop_map(|b| ("mysql-greeting-v1", b)),
            3 => with_corruption(dns_valid_bytes()).prop_map(|b| ("dns-version-bind-v1", b)),
            3 => with_corruption(tls_valid_bytes()).prop_map(|b| ("tls-v1", b)),
            3 => with_corruption(redis_valid_bytes()).prop_map(|b| ("redis-ping-v1", b)),
            3 => with_corruption(postgres_valid_bytes()).prop_map(|b| ("postgres-startup-v1", b)),
            6 => (
                prop_oneof![
                    Just("http-get-v1"),
                    Just("tls-v1"),
                    Just("ssh-banner-v1"),
                    Just("smtp-banner-v1"),
                    Just("dns-version-bind-v1"),
                    Just("postgres-startup-v1"),
                    Just("mysql-greeting-v1"),
                    Just("redis-ping-v1"),
                    Just("totally-unknown-probe-id"),
                ],
                proptest::collection::vec(any::<u8>(), 0..300),
            ),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2048))]

        // AC-4.12 / verification beyond the brief: every span the rule set
        // can ever produce is a valid range into the response it was
        // computed from. Uses `probe_and_response_strategy` (see above)
        // so this actually exercises the offset arithmetic in every rule,
        // not just the "nothing matched" path -- see this test module's
        // note on why the earlier, fully-arbitrary-bytes version of this
        // property was near-vacuous.
        #[test]
        fn matched_span_is_always_a_valid_range_into_the_response(
            (probe_id, response) in probe_and_response_strategy(),
        ) {
            let c = cap(probe_id, 1, &response);
            let interpretations = interpret(&c);
            for i in &interpretations {
                prop_assert!(i.matched_span.start <= i.matched_span.end);
                prop_assert!(i.matched_span.end <= c.response.len());
            }
        }

        // AC-4.14: same bytes in, byte-identical vector out, over inputs
        // that actually reach real rule matches (not just arbitrary bytes
        // that almost always produce an empty, trivially-equal vector).
        #[test]
        fn interpret_is_deterministic_over_arbitrary_input(
            (probe_id, response) in probe_and_response_strategy(),
        ) {
            let c = cap(probe_id, 1, &response);
            prop_assert_eq!(interpret(&c), interpret(&c));
        }

    }

    // Companion to the two properties above, run directly rather than as a
    // `proptest!` property: measures, with real counts, that
    // `probe_and_response_strategy` actually reaches matches and deep
    // spans most of the time -- not just "less vacuous in theory". The
    // original strategy this replaces was independently audited at 4096
    // cases: 6 non-empty results, 0 with `matched_span.end > 6` (i.e. it
    // essentially never reached any rule's offset arithmetic). This test
    // is what backs the claim that the replacement strategy is different
    // in kind, not just in case count.
    #[test]
    fn structured_strategy_reaches_real_matches_and_deep_spans_most_of_the_time() {
        use proptest::strategy::ValueTree;
        use proptest::test_runner::TestRunner;
        let mut runner = TestRunner::default();
        let strategy = probe_and_response_strategy();
        const TOTAL: usize = 2000;
        let mut non_empty = 0usize;
        let mut deep_span = 0usize;
        for _ in 0..TOTAL {
            let (probe_id, response) = strategy.new_tree(&mut runner).unwrap().current();
            let interpretations = interpret(&cap(probe_id, 1, &response));
            if !interpretations.is_empty() {
                non_empty += 1;
            }
            if interpretations.iter().any(|i| i.matched_span.end > 6) {
                deep_span += 1;
            }
        }
        assert!(
            non_empty * 100 >= TOTAL * 30,
            "expected at least 30% of {TOTAL} structured cases to produce a match, got {non_empty}"
        );
        assert!(
            deep_span * 100 >= TOTAL * 20,
            "expected at least 20% of {TOTAL} structured cases to produce a span past byte 6 \
             (i.e. actually reach a rule's own offset arithmetic), got {deep_span}"
        );
    }
}
