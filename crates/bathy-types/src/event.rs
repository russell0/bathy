use std::net::IpAddr;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::confidence::Confidence;
use crate::ids::{Digest, ScanId};
use crate::nonempty::NonEmpty;

// `Ord` is derived, and it is load-bearing rather than incidental:
// `bathy-query`'s `ScanFold` keys a `BTreeMap` on `(IpAddr, Endpoint)`
// specifically so that iteration order over a scan's results is total and
// stable, which is what makes a fold byte-reproducible and a diff of two
// folds free of phantom reorderings. A `BTreeMap` cannot be keyed on a type
// with no `Ord`, so without this derive the whole query layer would have to
// fall back to a `HashMap` and give up determinism. The derived order is
// declaration order (`Tcp` before `Udp`); it is a stable sort key, not a
// statement that TCP ranks above UDP in any domain sense. Pinned by
// `transport_orders_by_declaration_order` below so a reordering of these
// variants -- which would silently permute every consumer's output -- fails
// a test rather than passing review.
//
// Deliberately a `//` comment, not a `///` doc comment: schemars copies doc
// comments on a wire type into that type's published JSON Schema as
// `description`, and `schemas/*.json` is the contract agents read. Internal
// rationale about why a Rust trait is derived does not belong in it -- see
// the drift `xtask check-schemas` reported when this text was first written
// as a doc comment. Doc comments here are for prose an agent needs (e.g.
// `PortState`'s, below); `//` is for prose a maintainer needs.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    Tcp,
    Udp,
}

// See `Transport` above for why `Ord` is derived here, and for why this is a
// `//` comment rather than a `///` one. Field order matters to the derived
// `Ord`: `transport` first, then `port`, so endpoints group by transport and
// then ascend by port -- the order an operator reading a port list expects.
// Pinned by `endpoints_order_by_transport_then_port`.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(deny_unknown_fields)]
pub struct Endpoint {
    pub transport: Transport,
    pub port: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub ip: IpAddr,
}

/// The observed reachability of one endpoint.
///
/// `Filtered` and `Closed` are distinct on purpose: a closed port is positive
/// evidence that a host is up, a filtered port is evidence of a middlebox.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PortState {
    Open,
    Closed,
    Filtered,
    /// Probed, but the response was contradictory across retries.
    Indeterminate,
}

/// What a probe concluded about one endpoint. Every field beyond `service` is
/// optional because partial identification is normal and honest.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub service: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub confidence: Confidence,
}

/// Stable, machine-readable reasons a scan request can be denied by policy.
/// The four wire strings below are the whole set -- agents branch on them, so
/// they are part of the public contract and must not be reworded without a
/// version bump.
//
// Said "exactly [`DenyReason::code`]'s four strings" until the M5 Task 2
// residual round. rustdoc resolves an intra-doc link; a JSON Schema consumer
// receives the literal brackets and a Rust path it cannot follow.
// Proven to match code(), not just documented to match: see
// `deny_reason_wire_values_match_code` below.
//
// C5: this type originated in `bathy-scope`, defined as free-standing
// strings duplicated ad hoc wherever a `reason_code` was needed --
// `EventBody::PolicyDenied` below used to be a bare
// `{ reason_code: String, detail: String }`, and two of its fixtures
// constructed it with `"out_of_scope"`, a string `DenyReason::code` can
// never actually emit (it emits `target_out_of_scope`). Moved here, into
// `bathy-types`, so `PolicyDenied.reason_code` can be typed as
// `DenyReason` instead of an unconstrained `String`: `bathy-types` is the
// lowest layer (nothing may be its dependency), and `bathy-scope` may
// depend on `bathy-types`, so this is the only direction the move can go.
// `bathy_scope::policy` re-exports this type rather than redefining it, so
// existing call sites referencing `bathy_scope::DenyReason` or
// `bathy_scope::policy::DenyReason` are unaffected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DenyReason {
    ScopeMismatch,
    ScopeExpired,
    TargetOutOfScope,
    BudgetExceedsCeiling,
}

impl DenyReason {
    /// Stable identifiers. Agents branch on these, so they are part of the
    /// public contract and must not be reworded.
    pub fn code(self) -> &'static str {
        match self {
            Self::ScopeMismatch => "scope_mismatch",
            Self::ScopeExpired => "scope_expired",
            Self::TargetOutOfScope => "target_out_of_scope",
            Self::BudgetExceedsCeiling => "budget_exceeds_ceiling",
        }
    }
}

// `#[serde(deny_unknown_fields)]` lives on `EventBody` here, not on `Event`
// (see below `Event`'s own doc comment) -- see that comment for why.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "event_type", deny_unknown_fields)]
pub enum EventBody {
    #[serde(rename = "scan.started")]
    ScanStarted {
        plan_hash: Digest,
        estimated_targets: u64,
        estimated_probes: u64,
    },

    #[serde(rename = "host.discovered")]
    HostDiscovered {
        target: Target,
        method: String,
        evidence_refs: NonEmpty<Digest>,
    },

    #[serde(rename = "port.state")]
    PortStateObserved {
        target: Target,
        endpoint: Endpoint,
        state: PortState,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        evidence_refs: Option<NonEmpty<Digest>>,
    },

    #[serde(rename = "service.observed")]
    ServiceObserved {
        target: Target,
        endpoint: Endpoint,
        observation: Observation,
        evidence_refs: NonEmpty<Digest>,
        probe_id: String,
        /// The interpretation rule that produced `observation`, and the name
        /// `fingerprint.explain` takes. `probe_id` names what was sent;
        /// this names what decided, and the two are different namespaces.
        //
        // Maintainer note, deliberately a `//` comment so it stays out of the
        // published schema: one probe's bytes can be matched by any of
        // several rules, so the probe id does not determine this. Until M5's
        // whole-branch review nothing bathy emitted ever named a rule -- the
        // interpretation's `rule_id` was dropped at the point of emission --
        // so `fingerprint.explain` was reachable only by first listing every
        // rule in the build, and never *from a finding*, which is the one
        // direction an agent holding a result actually needs.
        rule_id: String,
    },

    #[serde(rename = "scan.progress")]
    Progress {
        probes_sent: u64,
        probes_total: u64,
        packets_spent: u64,
    },

    #[serde(rename = "policy.denied")]
    PolicyDenied {
        reason_code: DenyReason,
        detail: String,
    },

    #[serde(rename = "scan.completed")]
    ScanCompleted {
        probes_sent: u64,
        packets_spent: u64,
        findings: u64,
    },

    #[serde(rename = "scan.failed")]
    ScanFailed { reason_code: String, detail: String },
}

impl EventBody {
    pub const KNOWN_TAGS: &'static [&'static str] = &[
        "scan.started",
        "host.discovered",
        "port.state",
        "service.observed",
        "scan.progress",
        "policy.denied",
        "scan.completed",
        "scan.failed",
    ];
}

/// One immutable entry in a scan's append-only log.
///
/// `sequence` is gap-free and monotonic per scan; resumption replays from the
/// last persisted sequence, so a gap means data loss and is a hard error.
// Rationale below is deliberately a `//` comment, not a `///` one:
// schemars copies doc comments on a wire type into `schemas/*.json` as
// `description`, and that file is the contract agents read. Notes about
// serde/schemars internals are for maintainers, not for a caller
// deciding what to put on the wire.
// Deliberately **not** `#[serde(deny_unknown_fields)]` on this struct, even
// though every other wire type in this crate carries that attribute.
// Combining `#[serde(deny_unknown_fields)]` on a container with
// `#[serde(flatten)]` on one of its fields is a known sharp edge in serde:
// flatten forces the derived `Deserialize` impl to buffer the document
// through a generic content map to figure out which keys belong to the
// flattened field, and `deny_unknown_fields` on that *same* container runs
// its "is this key one of my own fields" check against that buffering step
// -- which doesn't know about the flattened type's fields at all. The
// practical effect, confirmed empirically with a throwaway probe crate
// against this workspace's exact serde version: it does not merely fail to
// reject unknown fields, it rejects *every* input, including fully valid
// ones, with `unknown field `event_type``. `deny_unknown_fields` and
// `flatten` cannot both live here.
//
// The guarantee is not weakened, only relocated: `#[serde(deny_unknown_fields)]`
// is on `EventBody` (below) instead. Every field of a wire document that
// isn't one of `Event`'s own four direct fields (`scan_id`, `sequence`,
// `timestamp`, `engine_version`) is, by construction of `#[serde(flatten)]`,
// exactly the set of fields handed to `EventBody`'s deserializer -- so
// `EventBody`'s `deny_unknown_fields` rejects anything that isn't the
// `event_type` discriminator or one of the matched variant's own fields,
// which is the same "no unrecognized field anywhere in the document"
// guarantee `Event`'s own `deny_unknown_fields` would have provided, had it
// been usable. Confirmed with the same probe crate: an unrelated top-level
// field (not part of `Event`'s direct fields, not part of any `EventBody`
// variant) is still rejected. What's lost is only where the guarantee is
// enforced, not whether it is enforced. See `event::tests::
// unknown_top_level_field_is_rejected_via_event_body` and `event::tests::
// unknown_field_inside_a_variant_is_rejected` below for the two concrete
// cases this covers.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct Event {
    pub scan_id: ScanId,
    pub sequence: u64,
    /// RFC 3339 UTC with milliseconds. Supplied by an injected `Clock`.
    // C3: the Global Constraint ("All timestamps are RFC 3339 UTC with
    // milliseconds") had zero enforcement anywhere in M1, unlike every
    // other invariant in this crate, which is pinned in both the type and
    // the published schema. `#[schemars(extend("format" = "date-time"))]`
    // below makes the published contract at least honest about the
    // intended shape. Deliberately NOT runtime-parsed here: `Clock` (which
    // actually produces this value) is created in M2 Task 1, and that is
    // the right place to validate it -- now discharged by
    // `FixedClock::new`, which is fallible specifically so a value that
    // does not have this shape (e.g. `"banana"`) can never be stored as a
    // clock's `now` in the first place, let alone reach this field. See
    // `bathy_types::clock`'s `validate_rfc3339_millis` and the
    // `fixed_clock_rejects_banana` test.
    #[schemars(extend("format" = "date-time"))]
    pub timestamp: String,
    pub engine_version: String,
    #[serde(flatten)]
    pub body: EventBody,
}

#[cfg(test)]
mod tests {
    use super::*;

    const SERVICE_OBSERVED_EXAMPLE: &str = r#"{
      "event_type": "service.observed",
      "scan_id": "scan_01ARZ3NDEKTSV4RRFFQ69G5FAV",
      "sequence": 1842,
      "target": { "ip": "10.30.0.42" },
      "endpoint": { "transport": "tcp", "port": 443 },
      "observation": {
        "service": "https",
        "product": "nginx",
        "version": "1.26.x",
        "confidence": 0.91
      },
      "evidence_refs": ["blake3:9c37000000000000000000000000000000000000000000000000000000000000"],
      "probe_id": "tls-http-v3",
      "rule_id": "https.server.nginx.v1",
      "engine_version": "0.1.0",
      "timestamp": "2026-08-01T15:04:31.182Z"
    }"#;

    #[test]
    fn service_observed_matches_the_designed_wire_format() {
        let json = SERVICE_OBSERVED_EXAMPLE;
        let e: Event = serde_json::from_str(json).unwrap();
        assert_eq!(e.sequence, 1842);
        let Event {
            body: EventBody::ServiceObserved { observation, .. },
            ..
        } = &e
        else {
            panic!("wrong variant");
        };
        assert_eq!(observation.service, "https");
        assert_eq!(observation.confidence.get(), 0.91);
    }

    #[test]
    fn service_observed_requires_at_least_one_evidence_ref() {
        let json = r#"{
          "event_type": "service.observed",
          "scan_id": "scan_01ARZ3NDEKTSV4RRFFQ69G5FAV",
          "sequence": 1,
          "target": { "ip": "10.30.0.42" },
          "endpoint": { "transport": "tcp", "port": 443 },
          "observation": { "service": "https", "confidence": 0.9 },
          "evidence_refs": [],
          "probe_id": "tls-http-v3",
          "rule_id": "https.server.nginx.v1",
          "engine_version": "0.1.0",
          "timestamp": "2026-08-01T15:04:31.182Z"
        }"#;
        assert!(serde_json::from_str::<Event>(json).is_err());
    }

    #[test]
    fn event_type_tag_round_trips_for_every_variant() {
        for tag in [
            "scan.started",
            "host.discovered",
            "port.state",
            "service.observed",
            "scan.progress",
            "policy.denied",
            "scan.completed",
            "scan.failed",
        ] {
            assert!(EventBody::KNOWN_TAGS.contains(&tag), "missing {tag}");
        }
    }

    // --- Verification beyond the brief's minimal test list ---

    fn digest_fixture(byte: u8) -> Digest {
        Digest::of_bytes(&[byte])
    }

    fn scan_id_fixture() -> ScanId {
        "scan_01ARZ3NDEKTSV4RRFFQ69G5FAV".parse().unwrap()
    }

    fn wrap(body: EventBody) -> Event {
        Event {
            scan_id: scan_id_fixture(),
            sequence: 7,
            timestamp: "2026-08-01T15:04:31.182Z".to_string(),
            engine_version: "0.1.0".to_string(),
            body,
        }
    }

    // AC-1.18, exercised structurally rather than just against the static
    // `KNOWN_TAGS` list: build one concrete value of every variant, serialize
    // it, and confirm the `event_type` key on the wire is exactly the tag
    // `KNOWN_TAGS` claims for it. `KNOWN_TAGS` matching itself (the brief's
    // own test) would not catch a `#[serde(rename = "...")]` on a variant
    // drifting out of sync with the constant.
    #[test]
    fn every_variant_serializes_under_its_known_tag() {
        let bodies: Vec<(&str, EventBody)> = vec![
            (
                "scan.started",
                EventBody::ScanStarted {
                    plan_hash: digest_fixture(1),
                    estimated_targets: 10,
                    estimated_probes: 100,
                },
            ),
            (
                "host.discovered",
                EventBody::HostDiscovered {
                    target: Target {
                        ip: "10.0.0.1".parse().unwrap(),
                    },
                    method: "icmp_echo".to_string(),
                    evidence_refs: NonEmpty::new(digest_fixture(2)),
                },
            ),
            (
                "port.state",
                EventBody::PortStateObserved {
                    target: Target {
                        ip: "10.0.0.1".parse().unwrap(),
                    },
                    endpoint: Endpoint {
                        transport: Transport::Tcp,
                        port: 22,
                    },
                    state: PortState::Open,
                    evidence_refs: Some(NonEmpty::new(digest_fixture(3))),
                },
            ),
            (
                "service.observed",
                EventBody::ServiceObserved {
                    target: Target {
                        ip: "10.0.0.1".parse().unwrap(),
                    },
                    endpoint: Endpoint {
                        transport: Transport::Tcp,
                        port: 443,
                    },
                    observation: Observation {
                        service: "https".to_string(),
                        product: None,
                        version: None,
                        confidence: Confidence::new(0.5).unwrap(),
                    },
                    evidence_refs: NonEmpty::new(digest_fixture(4)),
                    probe_id: "tls-http-v3".to_string(),
                    rule_id: "https.server.nginx.v1".to_string(),
                },
            ),
            (
                "scan.progress",
                EventBody::Progress {
                    probes_sent: 1,
                    probes_total: 2,
                    packets_spent: 3,
                },
            ),
            (
                "policy.denied",
                EventBody::PolicyDenied {
                    reason_code: DenyReason::TargetOutOfScope,
                    detail: "target not in authorization scope".to_string(),
                },
            ),
            (
                "scan.completed",
                EventBody::ScanCompleted {
                    probes_sent: 1,
                    packets_spent: 2,
                    findings: 3,
                },
            ),
            (
                "scan.failed",
                EventBody::ScanFailed {
                    reason_code: "budget_exhausted".to_string(),
                    detail: "maximum_packets reached".to_string(),
                },
            ),
        ];

        assert_eq!(bodies.len(), EventBody::KNOWN_TAGS.len());

        for (tag, body) in bodies {
            assert!(EventBody::KNOWN_TAGS.contains(&tag), "missing {tag}");
            let event = wrap(body);
            let value = serde_json::to_value(&event).unwrap();
            assert_eq!(
                value.get("event_type").and_then(|v| v.as_str()),
                Some(tag),
                "event_type mismatch for {tag}: {value:#}"
            );
        }
    }

    // Round-trip every variant through JSON, not just `service.observed`
    // (the brief's own test only exercises that one variant). `flatten`
    // combined with an internally tagged enum has sharp edges (see `Event`'s
    // doc comment above); a round trip through `serde_json::Value` catches a
    // regression that a one-way "does it parse" test would miss, e.g. a
    // field silently not coming back out the same way it went in.
    #[test]
    fn every_variant_round_trips_through_json() {
        let bodies = vec![
            EventBody::ScanStarted {
                plan_hash: digest_fixture(10),
                estimated_targets: 500,
                estimated_probes: 5000,
            },
            EventBody::HostDiscovered {
                target: Target {
                    ip: "192.168.1.1".parse().unwrap(),
                },
                method: "arp".to_string(),
                evidence_refs: NonEmpty::try_from(vec![digest_fixture(11), digest_fixture(12)])
                    .unwrap(),
            },
            EventBody::PortStateObserved {
                target: Target {
                    ip: "192.168.1.1".parse().unwrap(),
                },
                endpoint: Endpoint {
                    transport: Transport::Udp,
                    port: 53,
                },
                state: PortState::Filtered,
                evidence_refs: None,
            },
            EventBody::PortStateObserved {
                target: Target {
                    ip: "192.168.1.1".parse().unwrap(),
                },
                endpoint: Endpoint {
                    transport: Transport::Tcp,
                    port: 3389,
                },
                state: PortState::Closed,
                evidence_refs: Some(NonEmpty::new(digest_fixture(13))),
            },
            EventBody::ServiceObserved {
                target: Target {
                    ip: "10.30.0.42".parse().unwrap(),
                },
                endpoint: Endpoint {
                    transport: Transport::Tcp,
                    port: 443,
                },
                observation: Observation {
                    service: "https".to_string(),
                    product: Some("nginx".to_string()),
                    version: Some("1.26.x".to_string()),
                    confidence: Confidence::new(0.91).unwrap(),
                },
                evidence_refs: NonEmpty::new(digest_fixture(14)),
                probe_id: "tls-http-v3".to_string(),
                rule_id: "https.server.nginx.v1".to_string(),
            },
            EventBody::Progress {
                probes_sent: 100,
                probes_total: 1000,
                packets_spent: 2000,
            },
            EventBody::PolicyDenied {
                reason_code: DenyReason::TargetOutOfScope,
                detail: "target not in authorization scope".to_string(),
            },
            EventBody::ScanCompleted {
                probes_sent: 1000,
                packets_spent: 2000,
                findings: 42,
            },
            EventBody::ScanFailed {
                reason_code: "budget_exhausted".to_string(),
                detail: "maximum_packets reached".to_string(),
            },
        ];

        // Nine bodies for eight tags: `PortStateObserved` is exercised twice
        // (once with `evidence_refs: None`, once with `Some(..)`), since that
        // field's optionality is itself a behavior worth round-tripping both
        // ways.
        assert_eq!(bodies.len(), EventBody::KNOWN_TAGS.len() + 1);

        for body in bodies {
            let event = wrap(body);
            let json = serde_json::to_string(&event).unwrap();
            let back: Event = serde_json::from_str(&json).unwrap();
            assert_eq!(event, back, "round trip mismatch for json: {json}");
        }
    }

    // AC-1.17: assert the exact wire format field-for-field, not just that
    // the document parses. Property-by-property rather than a single
    // whole-document `assert_eq!` against a literal, so a future formatting
    // change (key order, whitespace) doesn't make this assertion fragile for
    // reasons unrelated to the actual contract.
    #[test]
    fn service_observed_wire_format_matches_field_for_field() {
        let event = wrap(EventBody::ServiceObserved {
            target: Target {
                ip: "10.30.0.42".parse().unwrap(),
            },
            endpoint: Endpoint {
                transport: Transport::Tcp,
                port: 443,
            },
            observation: Observation {
                service: "https".to_string(),
                product: Some("nginx".to_string()),
                version: Some("1.26.x".to_string()),
                confidence: Confidence::new(0.91).unwrap(),
            },
            evidence_refs: NonEmpty::new(
                "blake3:9c37000000000000000000000000000000000000000000000000000000000000"
                    .parse()
                    .unwrap(),
            ),
            probe_id: "tls-http-v3".to_string(),
            rule_id: "https.server.nginx.v1".to_string(),
        });
        let event = Event {
            sequence: 1842,
            ..event
        };
        let value = serde_json::to_value(&event).unwrap();

        assert_eq!(value["event_type"], "service.observed");
        assert_eq!(value["scan_id"], "scan_01ARZ3NDEKTSV4RRFFQ69G5FAV");
        assert_eq!(value["sequence"], 1842);
        assert_eq!(value["target"]["ip"], "10.30.0.42");
        assert_eq!(value["endpoint"]["transport"], "tcp");
        assert_eq!(value["endpoint"]["port"], 443);
        assert_eq!(value["observation"]["service"], "https");
        assert_eq!(value["observation"]["product"], "nginx");
        assert_eq!(value["observation"]["version"], "1.26.x");
        assert_eq!(value["observation"]["confidence"], 0.91);
        assert_eq!(
            value["evidence_refs"],
            serde_json::json!([
                "blake3:9c37000000000000000000000000000000000000000000000000000000000000"
            ])
        );
        assert_eq!(value["probe_id"], "tls-http-v3");
        // What was sent, and what decided. Two questions, two fields.
        assert_eq!(value["rule_id"], "https.server.nginx.v1");
        assert_eq!(value["engine_version"], "0.1.0");
        assert_eq!(value["timestamp"], "2026-08-01T15:04:31.182Z");

        // Exactly these keys -- no more, no fewer -- confirming the field
        // list in AC-1.17 is complete.
        let mut keys: Vec<&str> = value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        let mut expected = vec![
            "event_type",
            "scan_id",
            "sequence",
            "target",
            "endpoint",
            "observation",
            "evidence_refs",
            "probe_id",
            "rule_id",
            "engine_version",
            "timestamp",
        ];
        expected.sort_unstable();
        assert_eq!(keys, expected);
    }

    // AC-1.19: `PortState` distinguishes all four states on the wire, using
    // exactly the snake_case spellings the brief specifies.
    #[test]
    fn port_state_wire_values_are_snake_case_and_distinct() {
        for (state, wire) in [
            (PortState::Open, "\"open\""),
            (PortState::Closed, "\"closed\""),
            (PortState::Filtered, "\"filtered\""),
            (PortState::Indeterminate, "\"indeterminate\""),
        ] {
            assert_eq!(serde_json::to_string(&state).unwrap(), wire, "{state:?}");
            let back: PortState = serde_json::from_str(wire).unwrap();
            assert_eq!(back, state);
        }
        // All four are pairwise distinct, i.e. this isn't secretly collapsed
        // to fewer than four discriminants anywhere upstream.
        let all = [
            PortState::Open,
            PortState::Closed,
            PortState::Filtered,
            PortState::Indeterminate,
        ];
        for i in 0..all.len() {
            for j in 0..all.len() {
                assert_eq!(i == j, all[i] == all[j]);
            }
        }
    }

    // The two concrete cases the `Event` doc comment above promises:
    // deny_unknown_fields, relocated onto `EventBody`, still rejects an
    // unrecognized field wherever it appears in the document.

    #[test]
    fn unknown_top_level_field_is_rejected_via_event_body() {
        // `mystery_field` is not one of `Event`'s own four direct fields,
        // and not a field of the `service.observed` variant either -- it
        // only exists to prove nothing silently swallows it.
        let json = SERVICE_OBSERVED_EXAMPLE.replacen(
            "\"event_type\": \"service.observed\",",
            "\"event_type\": \"service.observed\", \"mystery_field\": true,",
            1,
        );
        let err = serde_json::from_str::<Event>(&json).unwrap_err();
        assert!(
            err.to_string().contains("unknown field"),
            "expected an unknown-field error, got: {err}"
        );
    }

    #[test]
    fn unknown_field_inside_a_variant_is_rejected() {
        let json = SERVICE_OBSERVED_EXAMPLE.replacen(
            "\"probe_id\": \"tls-http-v3\",",
            "\"probe_id\": \"tls-http-v3\", \"stealth_mode\": true,",
            1,
        );
        let err = serde_json::from_str::<Event>(&json).unwrap_err();
        assert!(
            err.to_string().contains("unknown field"),
            "expected an unknown-field error, got: {err}"
        );
    }

    // Also confirm a genuinely valid document (used as the basis for the two
    // rejection tests above) actually parses -- otherwise a broken `replacen`
    // pattern could make both rejection tests pass for the wrong reason
    // (the *unmodified* JSON already failing to parse).
    #[test]
    fn the_fixture_used_by_the_rejection_tests_parses_on_its_own() {
        assert!(serde_json::from_str::<Event>(SERVICE_OBSERVED_EXAMPLE).is_ok());
    }

    // --- C5: deny codes were defined in `bathy-scope` (`DenyReason::code()`)
    // but consumed as free text in `bathy-types`
    // (`EventBody::PolicyDenied.reason_code: String`). The symptom was
    // already in the tree: two fixtures above used to construct
    // `EventBody::PolicyDenied { reason_code: "out_of_scope".to_string(),
    // .. }`, a string `DenyReason::code()` can never emit (it emits
    // `target_out_of_scope`) -- nothing caught that mismatch because the
    // field was an unconstrained `String`. Now that it is typed as
    // `DenyReason`, that particular mistake cannot even compile; the two
    // tests below prove the wire values genuinely match `code()` (not just
    // that the type compiles), and that an unrecognized reason code is
    // rejected outright rather than silently accepted as free text. ---

    #[test]
    fn deny_reason_wire_values_match_code() {
        for (reason, code) in [
            (DenyReason::ScopeMismatch, "scope_mismatch"),
            (DenyReason::ScopeExpired, "scope_expired"),
            (DenyReason::TargetOutOfScope, "target_out_of_scope"),
            (DenyReason::BudgetExceedsCeiling, "budget_exceeds_ceiling"),
        ] {
            assert_eq!(reason.code(), code);
            assert_eq!(
                serde_json::to_string(&reason).unwrap(),
                format!("\"{code}\""),
                "{reason:?} must serialize to exactly its code()"
            );
            let back: DenyReason = serde_json::from_str(&format!("\"{code}\"")).unwrap();
            assert_eq!(back, reason, "{code} must deserialize back to {reason:?}");
        }
    }

    #[test]
    fn policy_denied_rejects_a_reason_code_that_is_not_a_real_deny_reason() {
        // "out_of_scope" is exactly the wrong string the two fixtures above
        // used to carry -- close to, but not, "target_out_of_scope". Before
        // this fix (reason_code: String), this would have parsed
        // successfully; now that it is typed as DenyReason, it must be
        // rejected.
        let json = r#"{
            "event_type": "policy.denied",
            "reason_code": "out_of_scope",
            "detail": "target not in authorization scope"
        }"#;
        assert!(
            serde_json::from_str::<EventBody>(json).is_err(),
            "\"out_of_scope\" is not a value DenyReason::code() can produce \
             and must be rejected"
        );

        // The real code, by contrast, must parse.
        let good = json.replace("out_of_scope", "target_out_of_scope");
        let body: EventBody = serde_json::from_str(&good).unwrap();
        assert!(matches!(
            body,
            EventBody::PolicyDenied {
                reason_code: DenyReason::TargetOutOfScope,
                ..
            }
        ));
    }

    // --- Prove the schema carries the constraints the type does. ---
    //
    // Dumped once with `schema_for!(Event)` + `println!` before writing
    // these assertions (see the task report for the full dump). Because
    // `body` is `#[serde(flatten)]`, schemars does not give `EventBody` its
    // own `$defs` entry the way `Observation`/`Endpoint`/`Target` get one:
    // the internally tagged enum's `oneOf` is spliced directly onto
    // `Event`'s own top-level schema object, alongside `Event`'s own
    // `properties`/`required` for its four direct fields. So the `oneOf` to
    // search is `value["oneOf"]` directly, not `value["$defs"]["EventBody"]
    // ["oneOf"]`.

    #[test]
    fn event_schema_has_event_type_discriminator_and_min_items_on_evidence_refs() {
        let schema = schemars::schema_for!(Event);
        let value = serde_json::to_value(&schema).unwrap();

        // `Event`'s own direct fields are present and required, confirming
        // the flatten splice didn't lose them.
        for direct_field in ["scan_id", "sequence", "timestamp", "engine_version"] {
            assert!(
                value["properties"].get(direct_field).is_some(),
                "missing direct property {direct_field}: schema was {value:#}"
            );
            assert!(
                value["required"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|v| v.as_str() == Some(direct_field)),
                "direct field {direct_field} should be required: schema was {value:#}"
            );
        }

        // Each variant requires `event_type` pinned to its own tag via
        // `const` -- this is the discriminator.
        let variants = value["oneOf"]
            .as_array()
            .expect("Event should have a oneOf over EventBody's variants");
        assert_eq!(variants.len(), EventBody::KNOWN_TAGS.len());

        let service_observed_arm = variants
            .iter()
            .find(|arm| {
                arm["properties"]["event_type"]["const"].as_str() == Some("service.observed")
            })
            .unwrap_or_else(|| panic!("no service.observed arm in {variants:#?}"));

        assert!(
            service_observed_arm["required"]
                .as_array()
                .unwrap()
                .iter()
                .any(|v| v.as_str() == Some("event_type")),
            "event_type should be required on the service.observed arm: {service_observed_arm:#}"
        );

        // `minItems: 1` on `evidence_refs`, followed through its `$ref`.
        let ref_path = service_observed_arm["properties"]["evidence_refs"]["$ref"]
            .as_str()
            .expect("evidence_refs should be a $ref, not an inline schema")
            .strip_prefix("#/$defs/")
            .unwrap();
        assert_eq!(
            value["$defs"][ref_path]["minItems"].as_u64(),
            Some(1),
            "schema was {value:#}"
        );
        assert_eq!(value["$defs"][ref_path]["type"].as_str(), Some("array"));

        // Every other variant's event_type is also a `const` tag, matching
        // KNOWN_TAGS as a set (AC-1.18 at the schema level, not just the
        // runtime level the earlier tests cover).
        let mut schema_tags: Vec<&str> = variants
            .iter()
            .map(|arm| arm["properties"]["event_type"]["const"].as_str().unwrap())
            .collect();
        schema_tags.sort_unstable();
        let mut known_tags: Vec<&str> = EventBody::KNOWN_TAGS.to_vec();
        known_tags.sort_unstable();
        assert_eq!(schema_tags, known_tags);
    }

    // Documents a genuine, deliberate limitation rather than papering over
    // it: unlike `Observation`/`Endpoint`/`Target` (each `additionalProperties:
    // false` in `$defs`, since each carries `#[serde(deny_unknown_fields)]`
    // directly with no flatten involved), the top-level `Event` schema and
    // its `oneOf` variant arms carry no `additionalProperties: false`
    // anywhere, even though `EventBody`'s `#[serde(deny_unknown_fields)]`
    // does reject unknown fields at *runtime* (see
    // `unknown_top_level_field_is_rejected_via_event_body` and
    // `unknown_field_inside_a_variant_is_rejected` above). This is not an
    // oversight in this crate: JSON Schema's `additionalProperties` applies
    // only relative to the `properties` declared in that *same* schema
    // object. `Event`'s four direct fields live in the outer object's
    // `properties`, while each variant's own fields live in its `oneOf` arm's
    // `properties` -- there is no single schema object whose `properties`
    // covers both, so no placement of `additionalProperties: false` could
    // express "reject anything not in the union of both" without incorrectly
    // rejecting `Event`'s own legitimate direct fields inside each arm (or
    // vice versa). schemars 1.2.2 does not attempt to route around this, and
    // neither does this implementation. The runtime guarantee (proved above)
    // and the published schema's `additionalProperties` claim are genuinely
    // divergent here; a schema consumer validating documents against this
    // schema alone, rather than against this crate's `Deserialize` impl,
    // would accept an extra field that the real deserializer rejects.
    #[test]
    fn schema_does_not_express_deny_unknown_fields_this_is_a_known_limitation() {
        let schema = schemars::schema_for!(Event);
        let value = serde_json::to_value(&schema).unwrap();

        assert!(
            value.get("additionalProperties").is_none(),
            "schema was {value:#}"
        );
        for arm in value["oneOf"].as_array().unwrap() {
            assert!(arm.get("additionalProperties").is_none(), "arm was {arm:#}");
        }
    }

    // --- C3: the Global Constraint promises RFC 3339 UTC with milliseconds
    // for every timestamp; the published schema must actually say so.
    // Proven concretely, the same way as every other pinned invariant in
    // this crate (e.g. `digest_json_schema_has_expected_pattern` in
    // `ids.rs`): generate the schema and assert the exact `format` value is
    // present, not just that the attribute was written somewhere. ---

    #[test]
    fn event_timestamp_schema_declares_date_time_format() {
        let schema = schemars::schema_for!(Event);
        let value = serde_json::to_value(&schema).unwrap();
        assert_eq!(
            value["properties"]["timestamp"]["format"].as_str(),
            Some("date-time"),
            "schema was {value:#}"
        );
        assert_eq!(
            value["properties"]["timestamp"]["type"].as_str(),
            Some("string"),
            "schema was {value:#}"
        );
    }

    // --- The derived total order on `Transport`/`Endpoint`. Derived for
    // `bathy-query`'s `BTreeMap<(IpAddr, Endpoint), _>` key; see those types'
    // own doc comments. The two tests below exist because a derived `Ord` is
    // silently defined by *source order* -- swapping two enum variants or two
    // struct fields is a one-line diff that reviews as cosmetic and permutes
    // every downstream consumer's output. ---

    #[test]
    fn transport_orders_by_declaration_order() {
        assert!(Transport::Tcp < Transport::Udp);
    }

    #[test]
    fn endpoints_order_by_transport_then_port() {
        let tcp = |port| Endpoint {
            transport: Transport::Tcp,
            port,
        };
        let udp = |port| Endpoint {
            transport: Transport::Udp,
            port,
        };
        // Transport dominates: every TCP endpoint sorts before every UDP one,
        // even one with a far lower port.
        assert!(tcp(65535) < udp(1));
        // Within one transport, ports ascend numerically.
        assert!(tcp(80) < tcp(443));
        let mut sorted = vec![udp(53), tcp(443), tcp(80), udp(5353)];
        sorted.sort();
        assert_eq!(sorted, vec![tcp(80), tcp(443), udp(53), udp(5353)]);
    }
}
