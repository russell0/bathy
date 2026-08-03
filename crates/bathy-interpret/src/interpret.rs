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

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(512))]

        // AC-4.12 / verification beyond the brief: every span the rule set
        // can ever produce is a valid range into the response it was
        // computed from, over arbitrary bytes and arbitrary probe ids --
        // not just the specific fixtures the brief's own tests use.
        #[test]
        fn matched_span_is_always_a_valid_range_into_the_response(
            probe_idx in 0usize..9,
            response in proptest::collection::vec(any::<u8>(), 0..300),
        ) {
            let probe_ids = [
                "http-get-v1",
                "tls-v1",
                "ssh-banner-v1",
                "smtp-banner-v1",
                "dns-version-bind-v1",
                "postgres-startup-v1",
                "mysql-greeting-v1",
                "redis-ping-v1",
            ];
            let probe_id = probe_ids[probe_idx % probe_ids.len()];
            let c = cap(probe_id, 1, &response);
            for i in interpret(&c) {
                prop_assert!(i.matched_span.start <= i.matched_span.end);
                prop_assert!(i.matched_span.end <= c.response.len());
            }
        }

        // AC-4.14: same bytes in, byte-identical vector out, over arbitrary
        // input -- not just the one fixture the brief's own determinism
        // test pins.
        #[test]
        fn interpret_is_deterministic_over_arbitrary_input(
            probe_idx in 0usize..9,
            response in proptest::collection::vec(any::<u8>(), 0..300),
        ) {
            let probe_ids = [
                "http-get-v1",
                "tls-v1",
                "ssh-banner-v1",
                "smtp-banner-v1",
                "dns-version-bind-v1",
                "postgres-startup-v1",
                "mysql-greeting-v1",
                "redis-ping-v1",
            ];
            let probe_id = probe_ids[probe_idx % probe_ids.len()];
            let c = cap(probe_id, 1, &response);
            prop_assert_eq!(interpret(&c), interpret(&c));
        }
    }
}
