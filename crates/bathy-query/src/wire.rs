//! The published wire shape of [`ScanFold`] and [`crate::diff::ScanDiff`].
//!
//! # Why this module exists at all
//!
//! `ScanFold::endpoints` is a `BTreeMap<(IpAddr, Endpoint), EndpointState>`,
//! and JSON object keys must be strings. A derived `Serialize` on that
//! compiles and then fails **at runtime**, for every `serde_json` caller, with
//! "key must be a string" -- which is why M5 Task 1 deliberately shipped
//! `ScanFold` with no `Serialize` at all rather than a derive that looked
//! right. The encoding is therefore an **entry array**: `endpoints` is a JSON
//! array of
//! `{ target, endpoint, state, observation, evidence_refs, probe_id, rule_id }`
//! objects, in the map's own key order (target, then transport, then port).
//!
//! # One spelling of `(target, endpoint)`
//!
//! [`FoldEntry`], [`crate::diff::Change`] and [`crate::diff::Undetermined`]
//! all address an endpoint with the same two fields, named the same way,
//! typed the same way: `target` (a bare IP string) and `endpoint` (an object
//! `{ transport, port }`). Two spellings of the same pair is the specific
//! risk that got this design moved out of M5 Task 4 -- eleven MCP tools
//! declaring `outputSchema` against a beta SDK is the worst place to discover
//! that a fold entry and a diff change disagree about how to name a port. It
//! is enforced by
//! `the_three_published_types_spell_the_endpoint_pair_identically`, not by
//! this comment.
//!
//! # Nothing is omitted
//!
//! No field in this crate's wire types carries `skip_serializing_if`. Every
//! field is always present, and `null` is used where a value is genuinely
//! unknown -- `state: null` means "no `port.state` event was ever seen for
//! this endpoint", which is a fact the fold went to some trouble to preserve
//! (see [`crate::fold::EndpointState::state`]) and which an *absent* field
//! would render as an accident of encoding. The cost is a few bytes per
//! entry; the benefit is that an agent can read every field without asking
//! whether its absence meant anything.
//!
//! Both halves of that are enforced. The schema says every property is
//! required (`every_property_of_every_type_this_crate_publishes_is_required`),
//! and the encoder is checked against those published `required` lists over a
//! fold and a diff with every nullable field at its null
//! (`every_required_property_is_physically_present_in_a_maximally_null_document`).
//!
//! # Ordering of duplicate-`sequence` events (AC-5.36)
//!
//! A serialized fold is exactly the artefact two different builds can
//! compare, so the fold's tiebreak for events that share a `sequence` is part
//! of this contract. It is keyed on the events' own typed fields
//! ([`crate::fold`]'s `tie_key`) and depends on no rendering this project
//! does not own, so it is stable across builds and toolchain releases. The
//! published schemas say so in their own `description`, because a caller
//! reading the schema cannot see this module.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use schemars::{JsonSchema, Schema, SchemaGenerator};
use serde::{Deserialize, Serialize};

use bathy_types::event::{Endpoint, Observation, PortState};
use bathy_types::ids::Digest;

use crate::fold::{EndpointState, ScanFold, Terminal};

/// One endpoint's record, addressed by the `(target, endpoint)` pair that is
/// spelled the same way in every document published here.
// `required` is stated explicitly because `schemars` marks every `Option`
// field optional, while this crate's encoder never omits a field (see the
// module docs: `null` is how an unknown value is spelled, not absence). The
// derived list would therefore promise less than the encoder delivers.
// `every_property_of_every_type_this_crate_publishes_is_required` fails if a
// field is added and left out of this list.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(extend("required" = [
    "target", "endpoint", "state", "observation", "evidence_refs", "probe_id",
    "rule_id"
]))]
pub struct FoldEntry {
    /// The host this endpoint lives on.
    pub target: IpAddr,
    /// The transport and port.
    pub endpoint: Endpoint,
    /// The last observed reachability, or `null` if the log contained no
    /// `port.state` event for this endpoint. `null` is not `closed`: it means
    /// nothing was ever observed.
    pub state: Option<PortState>,
    /// The last service identification, or `null` if nothing identified it.
    pub observation: Option<Observation>,
    /// Every distinct evidence digest cited for this endpoint, in
    /// first-cited order.
    pub evidence_refs: Vec<Digest>,
    /// The probe that produced `observation`, or `null`.
    pub probe_id: Option<String>,
    /// The interpretation rule that produced `observation`, or `null`. This
    /// is the name `fingerprint.explain` takes; `probe_id` is not.
    pub rule_id: Option<String>,
}

/// The wire form of [`ScanFold`]. See this module's documentation.
//
// `ScanFold` itself keeps its `BTreeMap`, because lookup by endpoint is what
// the diff needs and an array would make that linear. This type is the
// crossing point, and it is public so that a consumer can name the shape it
// receives.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(rename = "ScanFold")]
#[schemars(extend("required" = ["endpoints", "hosts_up", "terminal", "plan_hash"]))]
#[schemars(description = "\
A scan's event log folded into per-endpoint state. `endpoints` is an entry \
array rather than an object because its key is a (target, endpoint) pair and \
JSON object keys must be strings; entries are in key order -- target, then \
transport, then port -- and no two entries may share a key. Where a log \
contains two events with the same `sequence` (which an append-only bathy \
event log cannot produce), the fold orders them by the events' own typed \
fields, so this document is stable across builds and toolchain releases.")]
pub struct ScanFoldWire {
    /// Every endpoint the log says anything about -- including the ones found
    /// closed or filtered, which are findings in their own right -- in key
    /// order: target, then transport, then port.
    pub endpoints: Vec<FoldEntry>,
    /// Hosts a `host.discovered` event named.
    ///
    /// **Empty is not evidence that no host is up.** No scan emits
    /// `host.discovered` in v0.1, so this array is empty for every log the
    /// engine produces today; read it as "the log said nothing about host
    /// liveness", never as "these are all the hosts that were up".
    pub hosts_up: Vec<IpAddr>,
    /// How the scan ended, or `null` if it is still running or was cancelled
    /// mid-flight. `null` never means "refused".
    pub terminal: Option<Terminal>,
    /// The plan the scan announced when it started, or `null` if it never
    /// started. Two scans of the same plan cover the same work, which is what
    /// makes an endpoint missing from one of them meaningful.
    pub plan_hash: Option<Digest>,
}

impl From<&ScanFold> for ScanFoldWire {
    fn from(fold: &ScanFold) -> Self {
        Self {
            endpoints: fold
                .endpoints
                .iter()
                .map(|((target, endpoint), state)| FoldEntry {
                    target: *target,
                    endpoint: *endpoint,
                    state: state.state,
                    observation: state.observation.clone(),
                    evidence_refs: state.evidence_refs.clone(),
                    probe_id: state.probe_id.clone(),
                    rule_id: state.rule_id.clone(),
                })
                .collect(),
            hosts_up: fold.hosts_up.iter().copied().collect(),
            terminal: fold.terminal.clone(),
            plan_hash: fold.plan_hash,
        }
    }
}

/// A wire document that does not describe a fold any log could produce.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum WireError {
    /// Two entries claimed the same endpoint. The map they decode into can
    /// hold only one, so accepting this would silently drop data -- and which
    /// one survived would depend on array order, which is exactly the
    /// caller-order dependence the fold exists to remove.
    #[error("duplicate endpoint entry for {target} {transport:?}/{port}")]
    DuplicateEndpoint {
        target: IpAddr,
        transport: bathy_types::event::Transport,
        port: u16,
    },
}

impl TryFrom<ScanFoldWire> for ScanFold {
    type Error = WireError;

    fn try_from(wire: ScanFoldWire) -> Result<Self, Self::Error> {
        let mut endpoints = BTreeMap::new();
        for entry in wire.endpoints {
            let key = (entry.target, entry.endpoint);
            let state = EndpointState {
                state: entry.state,
                observation: entry.observation,
                evidence_refs: entry.evidence_refs,
                probe_id: entry.probe_id,
                rule_id: entry.rule_id,
            };
            if endpoints.insert(key, state).is_some() {
                return Err(WireError::DuplicateEndpoint {
                    target: entry.target,
                    transport: entry.endpoint.transport,
                    port: entry.endpoint.port,
                });
            }
        }
        Ok(Self {
            endpoints,
            hosts_up: BTreeSet::from_iter(wire.hosts_up),
            terminal: wire.terminal,
            plan_hash: wire.plan_hash,
        })
    }
}

impl Serialize for ScanFold {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        ScanFoldWire::from(self).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ScanFold {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        ScanFoldWire::deserialize(deserializer)?
            .try_into()
            .map_err(serde::de::Error::custom)
    }
}

/// Delegated to [`ScanFoldWire`], which is what a `ScanFold` actually encodes
/// as. Written out rather than derived because a derived `JsonSchema` on
/// `ScanFold` would describe the `BTreeMap` -- a JSON object -- which is the
/// document `serde_json` refuses to produce.
impl JsonSchema for ScanFold {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        ScanFoldWire::schema_name()
    }
    fn schema_id() -> std::borrow::Cow<'static, str> {
        ScanFoldWire::schema_id()
    }
    fn json_schema(generator: &mut SchemaGenerator) -> Schema {
        ScanFoldWire::json_schema(generator)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use bathy_types::event::{DenyReason, PortState, Transport};

    use crate::diff::{ChangeKind, ScanDiff, diff};
    use crate::fold::fold_events;
    use crate::fold::tests::{completed, denied, digest, ev, ip, port_state, tcp};
    use bathy_types::event::{EventBody, Observation, Target};
    use bathy_types::nonempty::NonEmpty;

    fn rich_fold() -> ScanFold {
        // One identified endpoint, one open-but-unidentified one, one closed
        // one, one UDP one, and a terminal -- so the round trip below carries
        // every field the encoding has to survive, not just the easy ones.
        fold_events(&[
            ev(
                1,
                EventBody::ScanStarted {
                    plan_hash: digest("plan"),
                    estimated_targets: 1,
                    estimated_probes: 4,
                    scan_mode: None,
                    scan_mode_detail: None,
                },
            ),
            port_state(2, "10.0.0.1", 443, PortState::Open),
            ev(
                3,
                EventBody::ServiceObserved {
                    target: Target { ip: ip("10.0.0.1") },
                    endpoint: tcp(443),
                    observation: Observation {
                        service: "https".into(),
                        product: Some("nginx".into()),
                        version: Some("1.26.0".into()),
                        confidence: bathy_types::confidence::Confidence::new(0.95).unwrap(),
                    },
                    evidence_refs: NonEmpty::try_from(vec![digest("a"), digest("b")]).unwrap(),
                    probe_id: "http-get-v1".into(),
                    rule_id: Some("http.server.nginx.v1".into()),
                },
            ),
            port_state(4, "10.0.0.1", 80, PortState::Open),
            port_state(5, "10.0.0.2", 81, PortState::Closed),
            ev(
                6,
                EventBody::PortStateObserved {
                    target: Target { ip: ip("10.0.0.1") },
                    endpoint: Endpoint {
                        transport: Transport::Udp,
                        port: 53,
                    },
                    state: PortState::Filtered,
                    evidence_refs: None,
                },
            ),
            ev(
                7,
                EventBody::HostDiscovered {
                    target: Target { ip: ip("10.0.0.1") },
                    method: "tcp-connect".into(),
                    evidence_refs: NonEmpty::new(digest("host")),
                },
            ),
            completed(8),
        ])
    }

    #[test]
    fn a_fold_round_trips_through_its_entry_array_encoding() {
        // AC-5.35. The property a derived `Serialize` could not have: the
        // document parses back to an *equal* fold, evidence order, terminal,
        // plan hash and all.
        let fold = rich_fold();
        let json = serde_json::to_string(&fold).expect("a fold serializes");
        let back: ScanFold = serde_json::from_str(&json).expect("and deserializes");
        assert_eq!(back, fold);
        assert_eq!(
            format!("{back:?}"),
            format!("{fold:?}"),
            "equal is not enough: the entry order must survive too"
        );
    }

    #[test]
    fn the_endpoint_map_encodes_as_an_array_in_key_order_not_as_an_object() {
        // The runtime failure a derived `Serialize` would have shipped: a
        // `BTreeMap` with a tuple key cannot be a JSON object at all.
        let json: serde_json::Value = serde_json::to_value(rich_fold()).unwrap();
        let entries = json["endpoints"]
            .as_array()
            .expect("endpoints must be an array of entries");
        assert_eq!(entries.len(), 4);
        let keys: Vec<(String, String, u64)> = entries
            .iter()
            .map(|e| {
                (
                    e["target"].as_str().unwrap().to_string(),
                    e["endpoint"]["transport"].as_str().unwrap().to_string(),
                    e["endpoint"]["port"].as_u64().unwrap(),
                )
            })
            .collect();
        assert_eq!(
            keys,
            vec![
                ("10.0.0.1".into(), "tcp".into(), 80),
                ("10.0.0.1".into(), "tcp".into(), 443),
                ("10.0.0.1".into(), "udp".into(), 53),
                ("10.0.0.2".into(), "tcp".into(), 81),
            ],
            "entries are in the map's own key order: target, transport, port"
        );
    }

    #[test]
    fn an_unknown_port_state_encodes_as_null_rather_than_vanishing() {
        // `state: null` is data (see `EndpointState::state`). An omitted
        // field would make "we never observed this port" indistinguishable
        // from an encoding accident.
        let fold = fold_events(&[ev(
            1,
            EventBody::ServiceObserved {
                target: Target { ip: ip("10.0.0.1") },
                endpoint: tcp(443),
                observation: Observation {
                    service: "https".into(),
                    product: None,
                    version: None,
                    confidence: bathy_types::confidence::Confidence::new(0.5).unwrap(),
                },
                evidence_refs: NonEmpty::new(digest("a")),
                probe_id: "http-get-v1".into(),
                rule_id: Some("http.server.nginx.v1".into()),
            },
        )]);
        let json = serde_json::to_value(&fold).unwrap();
        assert!(
            json["endpoints"][0]
                .get("state")
                .is_some_and(|v| v.is_null()),
            "state must be present and null: {json:#}"
        );
        assert!(json["terminal"].is_null());
        assert!(json["plan_hash"].is_null());
    }

    #[test]
    fn every_required_property_is_physically_present_in_a_maximally_null_document() {
        // The schema side of "nothing is omitted" is guarded type-wide by
        // `every_property_of_every_type_this_crate_publishes_is_required`.
        // This is the encoder side, and it was one field wide: an
        // `an_unknown_port_state_encodes_as_null` test pins `FoldEntry::state`
        // and nothing pinned the other eight nullable fields, so
        // `skip_serializing_if` on `FoldEntry::probe_id` or on
        // `EndpointState::state` produced a document violating the committed
        // `required` list with every test green.
        //
        // The `required` lists are read back out of the published schemas
        // rather than restated here, so the encoder is checked against the
        // one source of truth a consumer actually validates against.
        fn required(node: &serde_json::Value, what: &str) -> Vec<String> {
            node["required"]
                .as_array()
                .unwrap_or_else(|| panic!("{what} publishes no `required` list: {node:#}"))
                .iter()
                .map(|v| {
                    v.as_str()
                        .expect("required entries are strings")
                        .to_string()
                })
                .collect()
        }
        fn assert_present(value: &serde_json::Value, fields: &[String], what: &str) {
            let object = value
                .as_object()
                .unwrap_or_else(|| panic!("{what} is not an object: {value:#}"));
            assert!(!fields.is_empty(), "{what} has an empty `required` list");
            for field in fields {
                assert!(
                    object.contains_key(field),
                    "{what}: `{field}` is required by the published schema but absent from \
                     the encoded document -- `null` is how this crate spells absence, and a \
                     missing key is not `null`: {value:#}"
                );
            }
        }

        let fold_schema = &crate::schema::all()["scan-fold"];
        let diff_schema = &crate::schema::all()["scan-diff"];

        // Every nullable field at its null: no port state, no observation, no
        // probe, no evidence, no terminal, no plan hash.
        let blank = EndpointState {
            state: None,
            observation: None,
            evidence_refs: Vec::new(),
            probe_id: None,
            rule_id: None,
        };
        let before = ScanFold {
            endpoints: BTreeMap::from([
                ((ip("10.0.0.1"), tcp(1)), blank.clone()),
                // One-sided the *other* way: in the earlier fold and not in
                // the later one. Without it every one-sided endpoint sits on
                // the later side, so no `Change` and no `Undetermined` in
                // this fixture ever carries a null `after`, and
                // `skip_serializing_if` on `Change::after` or
                // `Undetermined::after` survives -- which is exactly what the
                // fix re-review found (S16, S17) against a commit whose
                // subject said "type-wide". Both sides, or the name is a
                // claim the fixture cannot support.
                ((ip("10.0.0.3"), tcp(3)), blank.clone()),
            ]),
            hosts_up: BTreeSet::new(),
            terminal: None,
            plan_hash: None,
        };
        let after = ScanFold {
            endpoints: BTreeMap::from([
                (
                    (ip("10.0.0.1"), tcp(1)),
                    EndpointState {
                        state: Some(PortState::Open),
                        ..blank.clone()
                    },
                ),
                // One-sided, so it lands in `undetermined` with a null
                // `before` and an all-null `after`.
                ((ip("10.0.0.2"), tcp(2)), blank.clone()),
            ]),
            hosts_up: BTreeSet::new(),
            terminal: None,
            plan_hash: None,
        };

        // A fold of a log with nothing in it: the only shape in which
        // `endpoints` itself is empty, and so the only one that would catch
        // an `is_empty` skip on the two collection fields.
        let empty = ScanFold::default();

        // Asserted over the loop's own input, not over a fixture the loop
        // might no longer use. Deleting a case below is otherwise silent --
        // it narrows what the loop covers and nothing fails, which is the
        // defect this whole test was re-opened for.
        let folds = [("before", &before), ("after", &after), ("empty", &empty)];
        assert!(
            folds
                .iter()
                .any(|(_, f)| f.endpoints.is_empty() && f.hosts_up.is_empty()),
            "no fold under test has both collections empty, so an `is_empty` skip on \
             either would encode a document missing a required property and survive"
        );
        assert!(
            folds.iter().any(|(_, f)| !f.endpoints.is_empty()),
            "and none has an entry, so `FoldEntry`'s own fields are never reached"
        );

        for (label, fold) in folds {
            let json = serde_json::to_value(fold).unwrap();
            assert_present(&json, &required(fold_schema, "ScanFold"), label);
            let entry_required = required(&fold_schema["$defs"]["FoldEntry"], "FoldEntry");
            for (index, entry) in json["endpoints"].as_array().unwrap().iter().enumerate() {
                assert_present(
                    entry,
                    &entry_required,
                    &format!("{label}.endpoints[{index}]"),
                );
            }
        }

        // Three diffs, because no single one can put every field at its
        // empty: `undecidable` is null only when both scans completed the
        // same plan, and both terminals are null only when neither did.
        //
        // `incomparable` covers `undecidable: non-null`, both terminals null,
        // and a populated `undetermined` carrying a null on *each* side --
        // one endpoint only the later fold has, one only the earlier fold
        // has. `comparable` covers `undecidable: null` and a `Change` with a
        // null `before` (an appearance, which only a comparable pair can
        // produce) and one with a null `after` (a disappearance).
        // `nothing_moved` covers both list fields empty.
        let completed = Terminal::Completed {
            probes_sent: 0,
            packets_spent: 0,
            findings: 0,
        };
        let comparable_before = ScanFold {
            terminal: Some(completed.clone()),
            plan_hash: Some(digest("plan")),
            ..before.clone()
        };
        let comparable_after = ScanFold {
            terminal: Some(completed),
            plan_hash: Some(digest("plan")),
            ..after.clone()
        };
        let incomparable = diff(&before, &after);
        let comparable = diff(&comparable_before, &comparable_after);
        // Each guard below is a field of the fixture the assertions cannot
        // otherwise prove they reached. A fixture that stops producing one of
        // these shapes must fail here, loudly, rather than quietly narrowing
        // what the loop at the bottom covers.
        assert!(
            incomparable.undecidable.is_some() && !incomparable.undetermined.is_empty(),
            "the incomparable fixture must reach `undetermined`: {incomparable:?}"
        );
        assert!(
            incomparable.undetermined.iter().any(|u| u.before.is_none())
                && incomparable.undetermined.iter().any(|u| u.after.is_none()),
            "`undetermined` must carry a null on each side, or `after` is never \
             exercised: {incomparable:?}"
        );
        assert!(
            comparable.undecidable.is_none()
                && comparable
                    .changes
                    .iter()
                    .any(|c| c.kind == ChangeKind::EndpointAppeared),
            "the comparable fixture must reach an appearance: {comparable:?}"
        );
        assert!(
            comparable
                .changes
                .iter()
                .any(|c| c.kind == ChangeKind::EndpointDisappeared),
            "and a disappearance, which is the only `Change` with a null `after`: \
             {comparable:?}"
        );

        // A fold against itself: the only shape with `changes` *and*
        // `undetermined` both empty, which is what an `is_empty` skip on
        // either would need to be caught.
        let nothing_moved = diff(&comparable_before, &comparable_before);

        let diffs = [
            ("incomparable", &incomparable),
            ("comparable", &comparable),
            ("nothing_moved", &nothing_moved),
        ];
        assert!(
            diffs
                .iter()
                .any(|(_, d)| d.changes.is_empty() && d.undetermined.is_empty()),
            "no diff under test has both lists empty, so an `is_empty` skip on either \
             would survive: {diffs:?}"
        );
        assert!(
            diffs.iter().any(|(_, d)| !d.changes.is_empty())
                && diffs.iter().any(|(_, d)| !d.undetermined.is_empty()),
            "and none has entries in both lists, so `Change`'s and `Undetermined`'s own \
             fields are never reached: {diffs:?}"
        );

        let state_required = required(&diff_schema["$defs"]["EndpointState"], "EndpointState");
        let diff_required = required(diff_schema, "ScanDiff");
        for (label, d) in diffs {
            let json = serde_json::to_value(d).unwrap();
            assert_present(&json, &diff_required, &format!("{label} ScanDiff"));
            for (list, name) in [("changes", "Change"), ("undetermined", "Undetermined")] {
                let entry_required = required(&diff_schema["$defs"][name], name);
                for (index, entry) in json[list].as_array().unwrap().iter().enumerate() {
                    let what = format!("{label}.{list}[{index}]");
                    assert_present(entry, &entry_required, &what);
                    for side in ["before", "after"] {
                        if entry[side].is_object() {
                            assert_present(
                                &entry[side],
                                &state_required,
                                &format!("{what}.{side}"),
                            );
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn two_entries_for_one_endpoint_are_refused_rather_than_silently_collapsed() {
        // A map holds one value per key, so accepting this document would
        // drop one of them and let array order decide which -- the caller
        // ordering dependence the fold exists to remove.
        let mut json = serde_json::to_value(rich_fold()).unwrap();
        let duplicate = json["endpoints"][0].clone();
        json["endpoints"].as_array_mut().unwrap().push(duplicate);
        let err = serde_json::from_value::<ScanFold>(json).unwrap_err();
        assert!(
            err.to_string().contains("duplicate endpoint entry"),
            "got: {err}"
        );
    }

    #[test]
    fn the_three_terminal_outcomes_are_distinguishable_on_the_wire() {
        // A wire shape that cannot tell "refused" from "finished" or from
        // "still running" re-opens the M5 Task 1 CRITICAL one layer up.
        let completed_json = serde_json::to_value(fold_events(&[completed(1)])).unwrap();
        let denied_json = serde_json::to_value(fold_events(&[denied(1)])).unwrap();
        let failed_json = serde_json::to_value(fold_events(&[ev(
            1,
            EventBody::ScanFailed {
                reason_code: "budget_exhausted".into(),
                detail: "spent".into(),
            },
        )]))
        .unwrap();
        let running_json = serde_json::to_value(fold_events(&[])).unwrap();

        assert_eq!(completed_json["terminal"]["outcome"], "completed");
        assert_eq!(denied_json["terminal"]["outcome"], "denied");
        assert_eq!(denied_json["terminal"]["reason_code"], "scope_expired");
        assert_eq!(failed_json["terminal"]["outcome"], "failed");
        assert!(running_json["terminal"].is_null());

        for json in [completed_json, denied_json, failed_json, running_json] {
            let back: ScanFold = serde_json::from_value(json.clone()).unwrap();
            assert_eq!(
                serde_json::to_value(&back).unwrap(),
                json,
                "every terminal shape must survive the round trip"
            );
        }
    }

    #[test]
    fn a_diff_round_trips_and_carries_both_terminals() {
        let monday = rich_fold();
        let tuesday = fold_events(&[denied(1)]);
        let d = diff(&monday, &tuesday);
        let json = serde_json::to_string(&d).unwrap();
        let back: ScanDiff = serde_json::from_str(&json).unwrap();
        assert_eq!(back, d);

        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["undecidable"], "scan_incomplete");
        assert_eq!(value["before_terminal"]["outcome"], "completed");
        assert_eq!(value["after_terminal"]["outcome"], "denied");
        assert_eq!(value["undetermined"].as_array().unwrap().len(), 4);
    }

    #[test]
    fn change_kinds_have_stable_snake_case_wire_names() {
        // An agent branches on these strings, so they are contract.
        let rendered: Vec<String> = [
            ChangeKind::EndpointAppeared,
            ChangeKind::EndpointDisappeared,
            ChangeKind::StateChanged,
            ChangeKind::ServiceChanged,
            ChangeKind::ProductChanged,
            ChangeKind::VersionChanged,
            ChangeKind::ConfidenceOnly,
        ]
        .iter()
        .map(|k| {
            serde_json::to_value(k)
                .unwrap()
                .as_str()
                .unwrap()
                .to_string()
        })
        .collect();
        assert_eq!(
            rendered,
            vec![
                "endpoint_appeared",
                "endpoint_disappeared",
                "state_changed",
                "service_changed",
                "product_changed",
                "version_changed",
                "confidence_only",
            ]
        );
        assert_eq!(
            serde_json::to_value(DenyReason::ScopeExpired).unwrap(),
            "scope_expired",
            "and the deny reason a denied terminal carries is bathy-types' own"
        );
    }

    #[test]
    fn the_three_published_types_spell_the_endpoint_pair_identically() {
        // The whole reason this encoding was designed here rather than in
        // Task 4: `FoldEntry`, `Change` and `Undetermined` must address an
        // endpoint the same way, or eleven MCP tools publish two spellings of
        // one pair. Compared structurally -- `description` is prose and is
        // allowed to differ; `type`, `format` and `$ref` are the contract.
        let fold = serde_json::to_value(schemars::schema_for!(ScanFold)).unwrap();
        let scan_diff = serde_json::to_value(schemars::schema_for!(ScanDiff)).unwrap();

        fn structure(
            schema: &serde_json::Value,
            name: &str,
            fields: &[&str],
        ) -> Vec<serde_json::Value> {
            let node = &schema["$defs"][name];
            let required = node["required"]
                .as_array()
                .unwrap_or_else(|| panic!("{name} has no required list: {node:#}"));
            fields
                .iter()
                .map(|field| {
                    assert!(
                        required.iter().any(|r| r == field),
                        "{name} must require `{field}`: {node:#}"
                    );
                    let mut property = node["properties"][field].clone();
                    property
                        .as_object_mut()
                        .unwrap_or_else(|| panic!("{name}.{field} is missing: {node:#}"))
                        .remove("description");
                    property
                })
                .collect()
        }

        const PAIR: &[&str] = &["target", "endpoint"];
        let entry = structure(&fold, "FoldEntry", PAIR);
        assert_eq!(
            entry,
            structure(&scan_diff, "Change", PAIR),
            "FoldEntry and Change spell the endpoint pair differently"
        );
        assert_eq!(
            entry,
            structure(&scan_diff, "Undetermined", PAIR),
            "Change and Undetermined spell the endpoint pair differently"
        );
        assert_eq!(
            entry[1]["$ref"], "#/$defs/Endpoint",
            "the endpoint half must be the shared bathy-types Endpoint, not a local copy"
        );

        // And the record half: a `FoldEntry` is a `(target, endpoint)` pair
        // plus exactly the fields of the `EndpointState` that a `Change`
        // carries as `before`/`after`.
        const RECORD: &[&str] = &[
            "state",
            "observation",
            "evidence_refs",
            "probe_id",
            "rule_id",
        ];
        assert_eq!(
            structure(&fold, "FoldEntry", RECORD),
            structure(&scan_diff, "EndpointState", RECORD),
            "a fold entry and a change's before/after describe the same record differently"
        );
    }
}
