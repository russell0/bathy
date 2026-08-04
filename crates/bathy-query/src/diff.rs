//! The diff: two folds in, a classified list of what changed out.
//!
//! The question this answers is "what changed since Monday", and the failure
//! mode it exists to avoid is the **phantom change** -- telling an operator
//! that a service appeared or vanished when nothing happened on the network.
//! Every rule below is a consequence of one discipline: *before classifying
//! anything as a change, ask what else could have produced this same pair of
//! folds.* A scan that was refused, cancelled, budget-exhausted, or aimed at
//! a different set of ports is not a scan that found less.

use std::collections::BTreeSet;
use std::net::IpAddr;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use bathy_types::event::Endpoint;

use crate::fold::{EndpointKey, EndpointState, ScanFold, Terminal};

/// What changed between two scans, and what could not be decided.
// `required` is stated explicitly here and on the other published types
// because `schemars` marks every `Option` field optional, while this crate's
// encoder never omits a field (see `crate::wire`'s module docs: `null` is how
// an unknown value is spelled, not absence). The derived list would promise
// less than the encoder delivers.
// `every_property_of_every_type_this_crate_publishes_is_required` fails if a
// field is added and left out of one of these lists.
// A `//` comment, not a `///` one: this is maintainer rationale and must not
// reach the published schema's `description` (M5 Task 1, the `$defs` sweep).
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(extend("required" = [
    "changes", "unchanged", "undetermined", "undecidable",
    "before_terminal", "after_terminal"
]))]
pub struct ScanDiff {
    /// Every classified change, ordered by target, then transport, then
    /// port. At most one entry per endpoint.
    pub changes: Vec<Change>,
    /// Endpoints present in both folds that the classifier found no
    /// difference in. A count rather than a list: "nothing changed here" is
    /// the answer for most of a network most of the time, and an agent
    /// paying by the token does not want it enumerated.
    pub unchanged: u64,
    /// Endpoints one scan reported and the other did not, where the silent
    /// scan never proved it looked.
    ///
    /// **These are not changes, and they are not "no change" either.** They
    /// are the honest answer to a question the two scans cannot settle.
    pub undetermined: Vec<Undetermined>,
    /// Whether an endpoint's absence from one fold counted as evidence, and
    /// if not, why not.
    ///
    /// `null` means both scans ran the same plan to completion, so absence
    /// is evidence and `undetermined` is empty. Any other value is the reason
    /// every one-sided endpoint was reported as undetermined instead of being
    /// classified. It is a property of the *pair* of scans, not of any one
    /// endpoint, which is why it is recorded once.
    pub undecidable: Option<Undecidable>,
    /// How each side's scan ended, copied through from the folds.
    ///
    /// Carried on the result rather than left for the caller to fetch
    /// separately because it is *the* thing that makes `undetermined`
    /// actionable: "the later scan was refused because the scope manifest had
    /// expired" is a sentence an agent can act on, and "2 endpoints could not
    /// be compared" on its own is not.
    pub before_terminal: Option<Terminal>,
    /// See [`ScanDiff::before_terminal`].
    pub after_terminal: Option<Terminal>,
}

/// One endpoint that changed, and how, with its full record on each side.
//
// `target` and `endpoint` are spelled exactly as in `crate::wire::FoldEntry`
// and `Undetermined` -- one spelling of the pair across every type this crate
// publishes, enforced by
// `the_three_published_types_spell_the_endpoint_pair_identically`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(extend("required" = ["target", "endpoint", "kind", "before", "after"]))]
pub struct Change {
    /// The host this endpoint lives on.
    pub target: IpAddr,
    /// The transport and port.
    pub endpoint: Endpoint,
    pub kind: ChangeKind,
    /// The endpoint's record in the earlier fold, or `None` if it was absent
    /// from it.
    pub before: Option<EndpointState>,
    /// The endpoint's record in the later fold, or `None` if it was absent
    /// from it.
    pub after: Option<EndpointState>,
}

/// How one endpoint changed. Exactly one kind is reported per endpoint: the
/// first that matches, in the order below, which runs from the most
/// consequential to the least. An endpoint whose reachability *and* version
/// both moved is reported as the state change -- the thing an operator acts
/// on -- rather than as a version bump on a port that is no longer open.
/// `before` and `after` carry the full records either way, so nothing is
/// lost.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum ChangeKind {
    /// The endpoint is in the later scan and not in the earlier one, and the
    /// earlier scan proved it looked. Never inferred from a scan that did not
    /// complete, or from two scans of different plans.
    EndpointAppeared,
    /// The endpoint is in the earlier scan and not in the later one, and the
    /// later scan proved it looked. Never inferred from a scan that did not
    /// complete, or from two scans of different plans.
    EndpointDisappeared,
    /// The endpoint's reachability differs -- including to or from `null`,
    /// which is a transition into or out of "we never observed this port's
    /// reachability". The endpoint is present in both scans either way, so
    /// this is never an appearance or a disappearance.
    StateChanged,
    /// The identified service differs -- `ssh` answering where `http` used
    /// to, or an endpoint identified for the first time.
    //
    // Not in the M5 plan's original six kinds; added here and reported as a
    // plan defect, because without it a service replaced by a different
    // service on the same port -- with no product or version on either side,
    // which is the ordinary shape for anything the probes identify by
    // protocol alone -- classifies as *unchanged*. See
    // `a_service_replaced_by_another_on_the_same_port_is_not_unchanged`.
    ServiceChanged,
    /// The product differs -- `apache` where `nginx` used to answer, or a
    /// product named for the first time.
    ProductChanged,
    /// The version differs and the product does not -- a patched or upgraded
    /// service.
    VersionChanged,
    /// Nothing differs except the confidence.
    ///
    /// Separated from every other kind because confidence legitimately
    /// wobbles between runs -- a slow response, a truncated banner -- and an
    /// operator asking "what changed since Monday" does not want that in the
    /// same bucket as a version bump. It is the single loudest source of
    /// false positives in a differential scanner.
    ConfidenceOnly,
}

/// An endpoint one scan reported and the other did not, where the silent
/// scan never proved it looked. Exactly one of `before`/`after` is present.
//
// The shape is `Change` minus the classification, deliberately: the same
// `(target, endpoint)` spelling. An endpoint present in both folds is always
// decidable, because both scans demonstrably looked at it.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
#[schemars(extend("required" = ["target", "endpoint", "before", "after"]))]
pub struct Undetermined {
    /// The host this endpoint lives on.
    pub target: IpAddr,
    /// The transport and port.
    pub endpoint: Endpoint,
    /// The endpoint's record in the earlier fold, or `None` if it was absent
    /// from it.
    pub before: Option<EndpointState>,
    /// The endpoint's record in the later fold, or `None` if it was absent
    /// from it.
    pub after: Option<EndpointState>,
}

/// Why an endpoint's fate could not be decided.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, JsonSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum Undecidable {
    /// One of the two scans did not run to completion -- it was refused,
    /// it failed, it exhausted its budget, or it was cancelled -- so its
    /// silence about an endpoint is not evidence that the endpoint is gone.
    //
    // `bathy-engine` reaches `scan.completed` on exactly one path -- plan
    // exhaustion (`scheduler.rs`'s final `else`). A refused scan folds to
    // `Terminal::Denied`, a budget- or time-exhausted one to
    // `Terminal::Failed`, and a cancelled or still-running one to
    // `terminal: None`.
    ScanIncomplete,
    /// Both scans completed, but they did not run the same plan, so an
    /// endpoint one of them never mentions may simply never have been in its
    /// plan. A re-run of the same request against the same scope produces the
    /// same `plan_hash` and is comparable; a scan of a different port range
    /// is not.
    //
    // `bathy-plan` excludes the idempotency key from `plan_hash` and
    // canonicalizes target and port order, so "the same work" really is the
    // same hash. Without this rule, diffing a 1000-port scan against a
    // 2-port one reports 998 disappearances.
    CoverageDiffers,
}

impl ScanDiff {
    /// The changes an operator asked about: everything except
    /// [`ChangeKind::ConfidenceOnly`].
    ///
    /// This is the `include_confidence_only: false` half of the M5 plan's
    /// `result.diff` tool contract, implemented once here rather than once
    /// per adapter -- the CLI and the MCP server must not each re-derive what
    /// "substantive" means and drift.
    pub fn substantive_changes(&self) -> impl Iterator<Item = &Change> {
        self.changes
            .iter()
            .filter(|c| c.kind != ChangeKind::ConfidenceOnly)
    }

    /// Whether absence of an endpoint from one side counted as evidence.
    ///
    /// `false` means every endpoint the two folds disagree about is in
    /// [`ScanDiff::undetermined`] rather than classified as appeared or
    /// disappeared.
    pub fn absence_was_evidence(&self) -> bool {
        self.undecidable.is_none()
    }
}

/// Classify what changed between two folds.
///
/// Pure, and total: no input pair is rejected, and no pair produces a panic.
///
/// # What is a change, and what only looks like one
///
/// - **Appearance and disappearance are decided by presence in
///   [`ScanFold::endpoints`]**, and only when both scans proved they looked.
///   `state: None -> Some(_)` is a [`ChangeKind::StateChanged`] on an
///   endpoint that was in both folds all along (AC-5.33).
/// - **A fold with no endpoints is not a scan that found nothing.** A
///   refused scan's whole log is one `policy.denied` event; a cancelled
///   scan's log stops mid-stream. Reading either as "everything
///   disappeared" is the phantom change this crate was built around
///   (AC-5.34).
/// - **Two completed scans of different plans are not comparable either.**
///   The narrower scan's silence is about its plan, not about the network.
/// - **Evidence digests and `probe_id` are not compared.** The same
///   conclusion reached from different bytes (an HTTP `Date` header moves
///   every second) or by a different probe is the same conclusion. Comparing
///   them would make every re-scan a wall of changes.
pub fn diff(before: &ScanFold, after: &ScanFold) -> ScanDiff {
    let plans_agree = before.plan_hash.is_some() && before.plan_hash == after.plan_hash;
    let undecidable = comparability(&before.terminal, &after.terminal, plans_agree);

    let mut result = ScanDiff {
        before_terminal: before.terminal.clone(),
        after_terminal: after.terminal.clone(),
        undecidable,
        ..ScanDiff::default()
    };

    // The union of both key sets, through a `BTreeSet`, so the output is
    // ordered by target, then transport, then port -- `Endpoint`'s derived
    // `Ord` is transport-dominant, and `EndpointKey`'s is the tuple order
    // over it (AC-5.7).
    let keys: BTreeSet<&EndpointKey> = before
        .endpoints
        .keys()
        .chain(after.endpoints.keys())
        .collect();

    for key in keys {
        let (target, endpoint) = *key;
        let seen_before = before.endpoints.get(key);
        let seen_after = after.endpoints.get(key);

        match (seen_before, seen_after) {
            (Some(b), Some(a)) => match classify(b, a) {
                Some(kind) => result.changes.push(Change {
                    target,
                    endpoint,
                    kind,
                    before: Some(b.clone()),
                    after: Some(a.clone()),
                }),
                None => result.unchanged += 1,
            },
            // Present on one side only. Whether that is a change at all
            // depends on whether the silent side proved it looked.
            (b, a) => {
                let kind = if b.is_some() {
                    ChangeKind::EndpointDisappeared
                } else {
                    ChangeKind::EndpointAppeared
                };
                match undecidable {
                    Some(_) => result.undetermined.push(Undetermined {
                        target,
                        endpoint,
                        before: b.cloned(),
                        after: a.cloned(),
                    }),
                    None => result.changes.push(Change {
                        target,
                        endpoint,
                        kind,
                        before: b.cloned(),
                        after: a.cloned(),
                    }),
                }
            }
        }
    }

    result
}

/// Whether one fold's silence about an endpoint may be read as evidence that
/// the endpoint is not there, and if not, why not.
///
/// `None` means "absence is evidence": both scans ran their plan to the end,
/// and it was the same plan.
fn comparability(
    before: &Option<Terminal>,
    after: &Option<Terminal>,
    plans_agree: bool,
) -> Option<Undecidable> {
    let completed = |t: &Option<Terminal>| matches!(t, Some(Terminal::Completed { .. }));
    if !completed(before) || !completed(after) {
        Some(Undecidable::ScanIncomplete)
    } else if !plans_agree {
        Some(Undecidable::CoverageDiffers)
    } else {
        None
    }
}

/// Classify a difference between two records of the *same* endpoint, or
/// `None` if there is none. First match wins, in the order
/// [`ChangeKind`] declares.
fn classify(before: &EndpointState, after: &EndpointState) -> Option<ChangeKind> {
    let (b, a) = (before.observation.as_ref(), after.observation.as_ref());

    if before.state != after.state {
        Some(ChangeKind::StateChanged)
    } else if b.map(|o| o.service.as_str()) != a.map(|o| o.service.as_str()) {
        // `None` here is "no service observation at all", which differs from
        // every named service -- so an endpoint that went from unidentified
        // to identified lands in this arm rather than falling through to a
        // product or confidence comparison against nothing.
        Some(ChangeKind::ServiceChanged)
    } else if b.and_then(|o| o.product.as_deref()) != a.and_then(|o| o.product.as_deref()) {
        Some(ChangeKind::ProductChanged)
    } else if b.and_then(|o| o.version.as_deref()) != a.and_then(|o| o.version.as_deref()) {
        Some(ChangeKind::VersionChanged)
    } else if b.map(|o| o.confidence.get().to_bits()) != a.map(|o| o.confidence.get().to_bits()) {
        // Compared by bits rather than by `f64` equality so the comparison is
        // reflexive for every value `Confidence` admits: `diff(a, a)` must be
        // empty for *any* `a` (AC-5.6), and a float compared with `==` is not
        // a safe way to promise that.
        Some(ChangeKind::ConfidenceOnly)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use bathy_types::confidence::Confidence;
    use bathy_types::event::{Event, EventBody, Observation, PortState, Target, Transport};
    use bathy_types::nonempty::NonEmpty;

    use crate::fold::fold_events;
    use crate::fold::tests::{completed, denied, digest, ev, ip, port_state, tcp};

    // --- Fixtures. Every fold below is the fold of a *log*, not a
    // hand-assembled `ScanFold`: the diff is only ever handed folds that
    // `fold_events` produced, and building the struct directly would let a
    // fixture assert a shape the fold cannot actually make (a completed scan
    // with no plan hash, say). ---

    fn started_with(sequence: u64, plan: &str) -> Event {
        ev(
            sequence,
            EventBody::ScanStarted {
                plan_hash: digest(plan),
                estimated_targets: 1,
                estimated_probes: 4,
            },
        )
    }

    /// The fold of a scan that announced `plan`, observed `events`, and ran
    /// to completion -- the only shape in which absence means anything.
    /// Sequences are assigned here so callers can write their events in the
    /// order they happened and ignore numbering.
    fn fold_of_plan(plan: &str, events: &[Event]) -> ScanFold {
        let mut log = vec![started_with(0, plan)];
        log.extend(events.iter().cloned());
        log.push(completed(0));
        for (index, event) in log.iter_mut().enumerate() {
            event.sequence = index as u64 + 1;
        }
        fold_events(&log)
    }

    /// [`fold_of_plan`] for the one plan almost every test uses: two scans of
    /// the same work, which is what "what changed since Monday" means.
    fn fold_of(events: &[Event]) -> ScanFold {
        fold_of_plan("weekly-inventory", events)
    }

    /// The fold of a scan that started and was then cancelled or lost --
    /// events, no terminal event.
    fn unfinished_fold(events: &[Event]) -> ScanFold {
        let mut log = vec![started_with(0, "weekly-inventory")];
        log.extend(events.iter().cloned());
        for (index, event) in log.iter_mut().enumerate() {
            event.sequence = index as u64 + 1;
        }
        fold_events(&log)
    }

    /// The fold of a refused scan: one `policy.denied` event and nothing
    /// else, which is exactly what `bathy-engine` leaves behind
    /// (`a_scope_validity_denial_emits_no_scan_started`).
    fn denied_fold() -> ScanFold {
        fold_events(&[denied(1)])
    }

    fn open(addr: &str, port: u16) -> Event {
        port_state(0, addr, port, PortState::Open)
    }

    fn closed(addr: &str, port: u16) -> Event {
        port_state(0, addr, port, PortState::Closed)
    }

    fn open_udp(addr: &str, port: u16) -> Event {
        ev(
            0,
            EventBody::PortStateObserved {
                target: Target { ip: ip(addr) },
                endpoint: udp(port),
                state: PortState::Open,
                evidence_refs: None,
            },
        )
    }

    fn udp(port: u16) -> Endpoint {
        Endpoint {
            transport: Transport::Udp,
            port,
        }
    }

    /// An `Open` port carrying a service identification -- the two events a
    /// real scan emits for one identified endpoint, in the order it emits
    /// them.
    fn svc(
        addr: &str,
        port: u16,
        service: &str,
        product: Option<&str>,
        version: Option<&str>,
        confidence: f64,
    ) -> Vec<Event> {
        vec![
            open(addr, port),
            observed(addr, port, service, product, version, confidence, "bytes"),
        ]
    }

    #[allow(clippy::too_many_arguments)]
    fn observed(
        addr: &str,
        port: u16,
        service: &str,
        product: Option<&str>,
        version: Option<&str>,
        confidence: f64,
        evidence: &str,
    ) -> Event {
        ev(
            0,
            EventBody::ServiceObserved {
                target: Target { ip: ip(addr) },
                endpoint: tcp(port),
                observation: Observation {
                    service: service.into(),
                    product: product.map(str::to_string),
                    version: version.map(str::to_string),
                    confidence: Confidence::new(confidence).unwrap(),
                },
                evidence_refs: NonEmpty::new(digest(evidence)),
                probe_id: format!("{service}-probe-v1"),
            },
        )
    }

    fn kinds(d: &ScanDiff) -> Vec<ChangeKind> {
        d.changes.iter().map(|c| c.kind).collect()
    }

    // --- AC-5.4: every `ChangeKind` is produced under its own condition. ---

    #[test]
    fn a_newly_open_port_is_reported_as_appeared() {
        let d = diff(&fold_of(&[]), &fold_of(&[open("10.0.0.1", 8080)]));
        assert_eq!(kinds(&d), vec![ChangeKind::EndpointAppeared]);
        assert!(d.changes[0].before.is_none());
        assert_eq!(
            d.changes[0].after.as_ref().unwrap().state,
            Some(PortState::Open)
        );
    }

    #[test]
    fn an_endpoint_absent_from_the_second_scan_disappeared() {
        let d = diff(&fold_of(&[open("10.0.0.1", 80)]), &fold_of(&[]));
        assert_eq!(kinds(&d), vec![ChangeKind::EndpointDisappeared]);
        assert!(d.changes[0].after.is_none());
    }

    #[test]
    fn a_port_that_closed_is_reported_as_a_state_change_not_a_disappearance() {
        // The endpoint is in both folds -- both scans looked at it -- so
        // whatever happened to it, it did not disappear.
        let d = diff(
            &fold_of(&[open("10.0.0.1", 80)]),
            &fold_of(&[closed("10.0.0.1", 80)]),
        );
        assert_eq!(kinds(&d), vec![ChangeKind::StateChanged]);
        assert_eq!(
            d.changes[0].after.as_ref().unwrap().state,
            Some(PortState::Closed)
        );
    }

    #[test]
    fn a_service_replaced_by_another_on_the_same_port_is_not_unchanged() {
        // The seventh kind, and the reason it exists: port 8080 answered HTTP
        // on Monday and SSH on Tuesday, neither identification carrying a
        // product or a version. Under the M5 plan's six kinds this compares
        // equal on state, product, version and confidence, and is reported as
        // *unchanged* -- a real change hidden, which is the same defect class
        // as a phantom change pointing the other way.
        let d = diff(
            &fold_of(&svc("10.0.0.1", 8080, "http", None, None, 0.6)),
            &fold_of(&svc("10.0.0.1", 8080, "ssh", None, None, 0.6)),
        );
        assert_eq!(kinds(&d), vec![ChangeKind::ServiceChanged]);
        assert_eq!(d.unchanged, 0);
    }

    #[test]
    fn a_product_swap_is_reported_as_a_product_change() {
        let d = diff(
            &fold_of(&svc(
                "10.0.0.1",
                443,
                "https",
                Some("nginx"),
                Some("1.26.0"),
                0.95,
            )),
            &fold_of(&svc(
                "10.0.0.1",
                443,
                "https",
                Some("apache"),
                Some("1.26.0"),
                0.95,
            )),
        );
        assert_eq!(kinds(&d), vec![ChangeKind::ProductChanged]);
        assert_eq!(
            d.changes[0]
                .after
                .as_ref()
                .unwrap()
                .observation
                .as_ref()
                .unwrap()
                .product
                .as_deref(),
            Some("apache")
        );
    }

    #[test]
    fn a_version_bump_is_reported_as_a_version_change() {
        let d = diff(
            &fold_of(&svc(
                "10.0.0.1",
                443,
                "https",
                Some("nginx"),
                Some("1.26.0"),
                0.95,
            )),
            &fold_of(&svc(
                "10.0.0.1",
                443,
                "https",
                Some("nginx"),
                Some("1.27.1"),
                0.95,
            )),
        );
        assert_eq!(kinds(&d), vec![ChangeKind::VersionChanged]);
        assert_eq!(
            d.changes[0]
                .after
                .as_ref()
                .unwrap()
                .observation
                .as_ref()
                .unwrap()
                .version
                .as_deref(),
            Some("1.27.1")
        );
    }

    #[test]
    fn a_confidence_wobble_alone_is_classified_separately_from_a_real_change() {
        // AC-5.5.
        let d = diff(
            &fold_of(&svc(
                "10.0.0.1",
                443,
                "https",
                Some("nginx"),
                Some("1.26.0"),
                0.95,
            )),
            &fold_of(&svc(
                "10.0.0.1",
                443,
                "https",
                Some("nginx"),
                Some("1.26.0"),
                0.88,
            )),
        );
        assert_eq!(
            kinds(&d),
            vec![ChangeKind::ConfidenceOnly],
            "confidence noise must be separable from substantive change"
        );
        assert!(
            d.substantive_changes().next().is_none(),
            "and must be filterable out without the caller re-deriving what substantive means"
        );
    }

    #[test]
    fn every_change_kind_is_produced_by_some_pair_of_folds() {
        // AC-5.4 as one assertion: a classifier missing an arm cannot pass
        // this even if each individual test above were deleted.
        let base = |c: f64| svc("10.0.0.1", 443, "https", Some("nginx"), Some("1.26.0"), c);
        let cases: Vec<(ChangeKind, ScanDiff)> = vec![
            (
                ChangeKind::EndpointAppeared,
                diff(&fold_of(&[]), &fold_of(&[open("10.0.0.1", 8080)])),
            ),
            (
                ChangeKind::EndpointDisappeared,
                diff(&fold_of(&[open("10.0.0.1", 8080)]), &fold_of(&[])),
            ),
            (
                ChangeKind::StateChanged,
                diff(
                    &fold_of(&[open("10.0.0.1", 80)]),
                    &fold_of(&[closed("10.0.0.1", 80)]),
                ),
            ),
            (
                ChangeKind::ServiceChanged,
                diff(
                    &fold_of(&svc("10.0.0.1", 8080, "http", None, None, 0.6)),
                    &fold_of(&svc("10.0.0.1", 8080, "ssh", None, None, 0.6)),
                ),
            ),
            (
                ChangeKind::ProductChanged,
                diff(
                    &fold_of(&base(0.95)),
                    &fold_of(&svc(
                        "10.0.0.1",
                        443,
                        "https",
                        Some("apache"),
                        Some("1.26.0"),
                        0.95,
                    )),
                ),
            ),
            (
                ChangeKind::VersionChanged,
                diff(
                    &fold_of(&base(0.95)),
                    &fold_of(&svc(
                        "10.0.0.1",
                        443,
                        "https",
                        Some("nginx"),
                        Some("1.27.1"),
                        0.95,
                    )),
                ),
            ),
            (
                ChangeKind::ConfidenceOnly,
                diff(&fold_of(&base(0.95)), &fold_of(&base(0.88))),
            ),
        ];
        for (expected, d) in &cases {
            assert_eq!(kinds(d), vec![*expected], "wrong classification: {d:#?}");
        }
        let produced: BTreeSet<ChangeKind> = cases.iter().map(|(k, _)| *k).collect();
        assert_eq!(
            produced.len(),
            7,
            "every ChangeKind variant must be reachable; got {produced:?}"
        );
    }

    // --- AC-5.6 and AC-5.7. ---

    #[test]
    fn identical_scans_produce_no_changes() {
        let f = fold_of(&[
            open("10.0.0.1", 80),
            open("10.0.0.1", 443),
            observed(
                "10.0.0.1",
                443,
                "https",
                Some("nginx"),
                Some("1.26.0"),
                0.95,
                "bytes",
            ),
        ]);
        let d = diff(&f, &f);
        assert!(d.changes.is_empty(), "{d:#?}");
        assert!(d.undetermined.is_empty());
        assert_eq!(d.unchanged, 2);
    }

    #[test]
    fn changes_are_ordered_deterministically_by_target_then_transport_then_port() {
        // AC-5.7. The key is `(c.target, c.endpoint)`, not
        // `(c.target, c.endpoint.port)`: `Endpoint`'s derived `Ord` is
        // transport-dominant, and keying on the port alone drops the
        // transport dimension entirely -- a decoration for that dimension
        // that cannot fail until UDP exists. The UDP endpoint in the fixture
        // is what stops the assertion being vacuous: on port ordering alone
        // it would sort second, and it must sort last.
        let after = fold_of(&[
            open("10.0.0.2", 80),
            open("10.0.0.1", 443),
            open("10.0.0.1", 80),
            open_udp("10.0.0.1", 53),
        ]);
        let d = diff(&fold_of(&[]), &after);
        let keys: Vec<_> = d.changes.iter().map(|c| (c.target, c.endpoint)).collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted);
        assert_eq!(
            keys,
            vec![
                (ip("10.0.0.1"), tcp(80)),
                (ip("10.0.0.1"), tcp(443)),
                (ip("10.0.0.1"), udp(53)),
                (ip("10.0.0.2"), tcp(80)),
            ],
            "transport dominates port: the UDP endpoint sorts after both TCP ones"
        );
    }

    // --- AC-5.33: presence decides appearance, nothing else. ---

    #[test]
    fn a_first_observed_port_state_is_a_state_change_not_an_appearance() {
        // `EndpointState::state` is `Option<PortState>` (M5 Task 1 shipped it
        // that way deliberately: a `service.observed` with no preceding
        // `port.state` leaves reachability genuinely unknown). So
        // `None -> Some(_)` is a real transition the classifier must decide
        // on purpose. The endpoint was already present in `before`, so it did
        // not appear; what changed is its state.
        let before = fold_of(&[observed(
            "10.0.0.1",
            443,
            "https",
            Some("nginx"),
            Some("1.26.0"),
            0.95,
            "bytes",
        )]);
        let after = fold_of(&[
            open("10.0.0.1", 443),
            observed(
                "10.0.0.1",
                443,
                "https",
                Some("nginx"),
                Some("1.26.0"),
                0.95,
                "bytes",
            ),
        ]);
        assert_eq!(before.endpoints[&(ip("10.0.0.1"), tcp(443))].state, None);

        let d = diff(&before, &after);
        assert_eq!(d.changes.len(), 1);
        assert_eq!(
            d.changes[0].kind,
            ChangeKind::StateChanged,
            "an endpoint already in the fold cannot 'appear'; a first-observed \
             port state is a transition out of unknown"
        );
    }

    #[test]
    fn an_endpoint_in_both_folds_is_never_appeared_or_disappeared() {
        // The other half of AC-5.33, over every pair of states an endpoint
        // can hold on either side, so no single classifier arm can sneak an
        // appearance out of a state transition.
        let states = [
            None,
            Some(PortState::Open),
            Some(PortState::Closed),
            Some(PortState::Filtered),
            Some(PortState::Indeterminate),
        ];
        for b in states {
            for a in states {
                let events = |s: Option<PortState>| match s {
                    None => vec![observed("10.0.0.1", 443, "https", None, None, 0.5, "bytes")],
                    Some(state) => vec![
                        port_state(0, "10.0.0.1", 443, state),
                        observed("10.0.0.1", 443, "https", None, None, 0.5, "bytes"),
                    ],
                };
                let d = diff(&fold_of(&events(b)), &fold_of(&events(a)));
                assert!(
                    !kinds(&d).iter().any(|k| matches!(
                        k,
                        ChangeKind::EndpointAppeared | ChangeKind::EndpointDisappeared
                    )),
                    "{b:?} -> {a:?} was classified as an appearance or disappearance: {d:#?}"
                );
                if b == a {
                    assert_eq!(d.unchanged, 1, "{b:?} -> {a:?}");
                }
            }
        }
    }

    // --- AC-5.34 and the rest of the "nobody looked" class. ---

    #[test]
    fn diffing_a_completed_scan_against_a_denied_one_reports_no_endpoint_disappeared() {
        // AC-5.34, and the defect this whole task is shaped around. Monday's
        // good scan against Tuesday's refused one: two endpoints on one side,
        // zero on the other, because a manifest expired and no packet was
        // sent. Reading that as "every service on the host went away" is a
        // phantom change reachable from a one-line operational state.
        let monday = fold_of(&[open("10.0.0.1", 80), open("10.0.0.1", 443)]);
        let tuesday = denied_fold();

        let d = diff(&monday, &tuesday);

        assert!(
            !d.changes
                .iter()
                .any(|c| c.kind == ChangeKind::EndpointDisappeared),
            "a policy-denied scan must not be diffed as a disappearance: {d:#?}"
        );
        assert!(d.changes.is_empty(), "and not as any other change: {d:#?}");
        assert_eq!(
            d.undetermined.len(),
            2,
            "the endpoints are not forgotten -- they are unanswered"
        );
        assert_eq!(d.undecidable, Some(Undecidable::ScanIncomplete));
        assert!(!d.absence_was_evidence());
        assert!(
            matches!(d.after_terminal, Some(Terminal::Denied { ref reason_code, .. })
                     if reason_code.code() == "scope_expired"),
            "and the reason survives to the diff, or an agent cannot act on it"
        );
    }

    #[test]
    fn a_cancelled_scan_is_not_a_scan_that_found_less() {
        // `terminal: None` is "still running or cancelled mid-flight". An
        // endpoint missing from a log that simply stops is not evidence.
        let monday = fold_of(&[open("10.0.0.1", 80), open("10.0.0.1", 443)]);
        let tuesday = unfinished_fold(&[open("10.0.0.1", 80)]);

        let d = diff(&monday, &tuesday);
        assert!(d.changes.is_empty(), "{d:#?}");
        assert_eq!(d.undetermined.len(), 1);
        assert_eq!(d.undetermined[0].endpoint, tcp(443));
        assert_eq!(d.undecidable, Some(Undecidable::ScanIncomplete));
        assert_eq!(d.unchanged, 1, "port 80 was seen by both and is decided");
    }

    #[test]
    fn a_budget_exhausted_scan_is_not_a_scan_that_found_less() {
        // `bathy-engine` reports budget and time exhaustion as
        // `scan.failed`, so `Terminal::Failed` covers both -- verified
        // against `scheduler.rs`'s terminal block, not assumed.
        let mut log = vec![started_with(1, "weekly-inventory"), open("10.0.0.1", 80)];
        log[1].sequence = 2;
        log.push(ev(
            3,
            EventBody::ScanFailed {
                reason_code: "budget_exhausted".into(),
                detail: "packet budget spent after 1 units".into(),
            },
        ));
        let truncated = fold_events(&log);

        let d = diff(
            &fold_of(&[open("10.0.0.1", 80), open("10.0.0.1", 443)]),
            &truncated,
        );
        assert!(d.changes.is_empty(), "{d:#?}");
        assert_eq!(d.undetermined.len(), 1);
        assert_eq!(d.undecidable, Some(Undecidable::ScanIncomplete));
    }

    #[test]
    fn two_completed_scans_of_different_plans_cannot_report_a_disappearance() {
        // The same failure mode reached without any scan failing at all:
        // Monday scanned ports 80 and 443, Tuesday scanned only 80. Both
        // completed. Nothing disappeared -- Tuesday never looked at 443.
        let monday = fold_of_plan(
            "ports-80-443",
            &[open("10.0.0.1", 80), open("10.0.0.1", 443)],
        );
        let tuesday = fold_of_plan("ports-80", &[open("10.0.0.1", 80)]);

        let d = diff(&monday, &tuesday);
        assert!(d.changes.is_empty(), "{d:#?}");
        assert_eq!(d.undetermined.len(), 1);
        assert_eq!(d.undecidable, Some(Undecidable::CoverageDiffers));
        assert_eq!(
            d.unchanged, 1,
            "port 80 is in both folds, so it is decidable whatever the plans were"
        );
    }

    #[test]
    fn a_completed_scan_with_no_plan_hash_is_not_assumed_to_match() {
        // A truncated log can lose `scan.started` while keeping
        // `scan.completed`. Two unknown plan hashes are not an agreement.
        let mut log = vec![open("10.0.0.1", 80), completed(2)];
        log[0].sequence = 1;
        let headless = fold_events(&log);
        assert_eq!(headless.plan_hash, None);
        assert!(matches!(
            headless.terminal,
            Some(Terminal::Completed { .. })
        ));

        let d = diff(&headless, &fold_events(&[completed(1)]));
        assert!(d.changes.is_empty(), "{d:#?}");
        assert_eq!(d.undecidable, Some(Undecidable::CoverageDiffers));
    }

    #[test]
    fn two_completed_scans_of_the_same_plan_do_report_appearance_and_disappearance() {
        // The other direction, and the one that keeps the rule above from
        // being a way to never say anything: when both scans ran the same
        // plan to the end, absence *is* evidence and the diff says so.
        let monday = fold_of(&[open("10.0.0.1", 80)]);
        let tuesday = fold_of(&[open("10.0.0.1", 443)]);

        let d = diff(&monday, &tuesday);
        assert_eq!(
            kinds(&d),
            vec![
                ChangeKind::EndpointDisappeared,
                ChangeKind::EndpointAppeared
            ]
        );
        assert!(d.undetermined.is_empty());
        assert_eq!(d.undecidable, None);
        assert!(d.absence_was_evidence());
    }

    // --- What must never count as a change. ---

    #[test]
    fn different_evidence_bytes_for_the_same_conclusion_are_not_a_change() {
        // Every HTTP response carries a `Date` header, so the digest of the
        // captured bytes differs on every re-scan of an unchanged server.
        // Comparing evidence refs would make a diff of two identical
        // inventories a wall of changes.
        let monday = fold_of(&[
            open("10.0.0.1", 443),
            observed(
                "10.0.0.1",
                443,
                "https",
                Some("nginx"),
                Some("1.26.0"),
                0.95,
                "monday-bytes",
            ),
        ]);
        let tuesday = fold_of(&[
            open("10.0.0.1", 443),
            observed(
                "10.0.0.1",
                443,
                "https",
                Some("nginx"),
                Some("1.26.0"),
                0.95,
                "tuesday-bytes",
            ),
        ]);
        assert_ne!(
            monday.endpoints[&(ip("10.0.0.1"), tcp(443))].evidence_refs,
            tuesday.endpoints[&(ip("10.0.0.1"), tcp(443))].evidence_refs,
            "fixture sanity: the two folds really do cite different bytes"
        );

        let d = diff(&monday, &tuesday);
        assert!(d.changes.is_empty(), "{d:#?}");
        assert_eq!(d.unchanged, 1);
    }

    #[test]
    fn the_same_conclusion_from_a_different_probe_is_not_a_change() {
        let mut tuesday_event = observed(
            "10.0.0.1",
            443,
            "https",
            Some("nginx"),
            Some("1.26.0"),
            0.95,
            "bytes",
        );
        if let EventBody::ServiceObserved { probe_id, .. } = &mut tuesday_event.body {
            *probe_id = "http-head-v2".into();
        }
        let monday = fold_of(&svc(
            "10.0.0.1",
            443,
            "https",
            Some("nginx"),
            Some("1.26.0"),
            0.95,
        ));
        let tuesday = fold_of(&[open("10.0.0.1", 443), tuesday_event]);

        let d = diff(&monday, &tuesday);
        assert!(d.changes.is_empty(), "{d:#?}");
        assert_eq!(d.unchanged, 1);
    }

    #[test]
    fn a_scan_terminal_difference_alone_is_not_a_change() {
        // Two folds of the same endpoints that ended differently: the
        // terminals are reported on the diff, but they are not changes to any
        // endpoint.
        let monday = fold_of(&[open("10.0.0.1", 80)]);
        let tuesday = unfinished_fold(&[open("10.0.0.1", 80)]);
        let d = diff(&monday, &tuesday);
        assert!(d.changes.is_empty());
        assert_eq!(d.unchanged, 1);
        assert!(d.before_terminal.is_some() && d.after_terminal.is_none());
    }

    #[test]
    fn a_denied_scan_on_the_before_side_is_symmetric() {
        // The rule is about either side's silence, not the later one's:
        // diffing a refused scan against a good one must not report every
        // endpoint as having appeared.
        let d = diff(&denied_fold(), &fold_of(&[open("10.0.0.1", 80)]));
        assert!(d.changes.is_empty(), "{d:#?}");
        assert_eq!(d.undetermined.len(), 1);
        assert!(d.undetermined[0].before.is_none());
        assert!(d.undetermined[0].after.is_some());
    }

    #[test]
    fn undetermined_entries_are_ordered_like_changes_are() {
        let monday = fold_of(&[
            open("10.0.0.2", 80),
            open("10.0.0.1", 443),
            open("10.0.0.1", 80),
            open_udp("10.0.0.1", 53),
        ]);
        let d = diff(&monday, &denied_fold());
        let keys: Vec<_> = d
            .undetermined
            .iter()
            .map(|u| (u.target, u.endpoint))
            .collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted);
        assert_eq!(keys.len(), 4);
    }

    #[test]
    fn diffing_two_empty_folds_says_nothing_at_all() {
        let d = diff(&fold_events(&[]), &fold_events(&[]));
        assert_eq!(
            d,
            ScanDiff {
                undecidable: Some(Undecidable::ScanIncomplete),
                ..ScanDiff::default()
            }
        );
    }
}

/// The diff's algebraic properties are universally quantified -- "for *any*
/// two folds" -- so they are property tests rather than more hand-written
/// pairs. The hand-written tests above pin what each classification *is*;
/// these pin the laws that must hold whatever the classifier decides:
/// self-diffing is empty, the two directions are exact inverses, the output
/// is a total order over distinct keys, nothing is invented or dropped, and
/// an unfinished or differently-planned pair never produces an appearance.
///
/// The strategy is instrumented, and that is not ceremony. M4 shipped a
/// property test whose naive strategy produced 6 non-empty results in 4096
/// cases and never reached the code it was written for. `the_generator_
/// reaches_every_shape_the_diff_properties_claim_to_cover` samples this same
/// strategy 4096 times, counts every shape the properties depend on --
/// including each of the seven `ChangeKind`s -- prints the table, and fails
/// if any bucket is thin.
#[cfg(test)]
mod proptests {
    use super::*;

    use std::collections::BTreeMap as Map;

    use bathy_types::confidence::Confidence;
    use bathy_types::event::{
        DenyReason, Event, EventBody, Observation, PortState, Target, Transport,
    };
    use bathy_types::nonempty::NonEmpty;
    use proptest::prelude::*;
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;

    use crate::fold::fold_events;
    use crate::fold::tests::{digest, ev, ip};

    /// Deliberately tiny domains, for the reason M5 Task 1's generator gives:
    /// these properties are about *collisions* -- the same endpoint appearing
    /// in both folds so that a classification happens at all -- and a wide
    /// address or port space makes collisions vanishingly rare. Two hosts,
    /// three endpoints, two products, two versions.
    const HOSTS: [&str; 2] = ["10.0.0.1", "10.0.0.2"];
    const PLANS: [&str; 2] = ["weekly-inventory", "just-the-web-ports"];

    fn endpoints() -> [Endpoint; 3] {
        [
            Endpoint {
                transport: Transport::Tcp,
                port: 80,
            },
            Endpoint {
                transport: Transport::Tcp,
                port: 443,
            },
            Endpoint {
                transport: Transport::Udp,
                port: 53,
            },
        ]
    }

    /// What one scan saw about one endpoint: nothing at all (the endpoint is
    /// absent from that fold), or a reachability and/or an identification.
    type Record = Option<(Option<PortState>, Option<(usize, usize, usize, u8)>)>;

    /// How a generated scan ended.
    #[derive(Clone, Copy, Debug, PartialEq)]
    enum End {
        Completed,
        Failed,
        Denied,
        Unfinished,
    }

    fn arb_state() -> impl Strategy<Value = Option<PortState>> {
        prop_oneof![
            1 => Just(None),
            3 => Just(Some(PortState::Open)),
            2 => Just(Some(PortState::Closed)),
            1 => Just(Some(PortState::Filtered)),
        ]
    }

    /// `(service, product, version, confidence)`, as indices into small
    /// tables so that two independently generated observations collide often
    /// -- which is what makes `ConfidenceOnly` and `VersionChanged`
    /// reachable at all.
    fn arb_observation() -> impl Strategy<Value = Option<(usize, usize, usize, u8)>> {
        prop::option::weighted(0.75, (0usize..2, 0usize..3, 0usize..3, 0u8..3))
    }

    fn arb_record() -> impl Strategy<Value = Record> {
        prop::option::weighted(0.8, (arb_state(), arb_observation()))
    }

    fn arb_end() -> impl Strategy<Value = End> {
        prop_oneof![
            6 => Just(End::Completed),
            1 => Just(End::Failed),
            1 => Just(End::Denied),
            2 => Just(End::Unfinished),
        ]
    }

    /// One scan: which plan it ran, how it ended, and what it saw about each
    /// of the six (host, endpoint) pairs in the domain.
    fn arb_scan() -> impl Strategy<Value = (usize, End, Vec<Record>)> {
        (
            0usize..PLANS.len(),
            arb_end(),
            prop::collection::vec(arb_record(), 6),
        )
    }

    /// What the later scan did about one endpoint the earlier scan saw.
    ///
    /// Two independently generated scans almost never agree about an
    /// endpoint, so a pair built that way exercises the *unchanged* path --
    /// which is most of a real network most of the time -- in under 8% of
    /// cases, and reaches a bare confidence wobble in 2%. Measured, not
    /// assumed: the coverage test below failed on exactly those two buckets
    /// before this existed. So the later scan is generated as a
    /// *perturbation* of the earlier one, which is also what "what changed
    /// since Monday" actually looks like.
    #[derive(Clone, Debug)]
    enum Mutation {
        Keep,
        Wobble,
        Upgrade,
        Replace(Record),
    }

    fn arb_mutation() -> impl Strategy<Value = Mutation> {
        prop_oneof![
            5 => Just(Mutation::Keep),
            2 => Just(Mutation::Wobble),
            2 => Just(Mutation::Upgrade),
            3 => arb_record().prop_map(Mutation::Replace),
        ]
    }

    fn apply(record: &Record, mutation: &Mutation) -> Record {
        match mutation {
            Mutation::Keep => *record,
            Mutation::Replace(new) => *new,
            // A different confidence and nothing else, which is the one
            // classification a diff must be able to set aside.
            Mutation::Wobble => match record {
                Some((state, Some((service, product, version, confidence)))) => Some((
                    *state,
                    Some((*service, *product, *version, (confidence + 1) % 3)),
                )),
                other => *other,
            },
            // The same product at a new version -- the flagship case a
            // differential scanner exists for, and one that a `Replace` of a
            // random record reaches only by coincidence.
            Mutation::Upgrade => match record {
                Some((state, Some((service, product, version, confidence)))) => Some((
                    *state,
                    Some((*service, *product, (version + 1) % 3, *confidence)),
                )),
                other => *other,
            },
        }
    }

    fn arb_scan_pair() -> impl Strategy<Value = (ScanFold, ScanFold)> {
        (
            arb_scan(),
            0usize..PLANS.len(),
            arb_end(),
            prop::collection::vec(arb_mutation(), 6),
        )
            .prop_map(|(before, plan, end, mutations)| {
                let after: Vec<Record> = before
                    .2
                    .iter()
                    .zip(mutations.iter())
                    .map(|(record, mutation)| apply(record, mutation))
                    .collect();
                (build(&before), build(&(plan, end, after)))
            })
    }

    /// Turn a generated scan into a real fold -- by building the log the
    /// engine would have written and folding *that*, so no property can
    /// assert something about a `ScanFold` no log could produce.
    fn build(scan: &(usize, End, Vec<Record>)) -> ScanFold {
        const SERVICES: [&str; 2] = ["http", "ssh"];
        const PRODUCTS: [Option<&str>; 3] = [None, Some("nginx"), Some("openssh")];
        const VERSIONS: [Option<&str>; 3] = [None, Some("1.26.0"), Some("1.27.1")];
        const CONFIDENCES: [f64; 3] = [0.5, 0.88, 0.95];

        let (plan, end, records) = scan;
        let mut log: Vec<Event> = Vec::new();
        if *end != End::Denied {
            log.push(ev(
                0,
                EventBody::ScanStarted {
                    plan_hash: digest(PLANS[*plan]),
                    estimated_targets: 2,
                    estimated_probes: 6,
                },
            ));
        }

        for (index, record) in records.iter().enumerate() {
            let Some((state, observation)) = record else {
                continue;
            };
            let target = Target {
                ip: ip(HOSTS[index / 3]),
            };
            let endpoint = endpoints()[index % 3];
            if let Some(state) = state {
                log.push(ev(
                    0,
                    EventBody::PortStateObserved {
                        target: Target { ip: target.ip },
                        endpoint,
                        state: *state,
                        evidence_refs: None,
                    },
                ));
            }
            if let Some((service, product, version, confidence)) = observation {
                log.push(ev(
                    0,
                    EventBody::ServiceObserved {
                        target,
                        endpoint,
                        observation: Observation {
                            service: SERVICES[*service].into(),
                            product: PRODUCTS[*product].map(str::to_string),
                            version: VERSIONS[*version].map(str::to_string),
                            confidence: Confidence::new(CONFIDENCES[*confidence as usize]).unwrap(),
                        },
                        evidence_refs: NonEmpty::new(digest("evidence")),
                        probe_id: format!("{}-probe-v1", SERVICES[*service]),
                    },
                ));
            }
        }

        match end {
            End::Completed => log.push(ev(
                0,
                EventBody::ScanCompleted {
                    probes_sent: 6,
                    packets_spent: 12,
                    findings: 1,
                },
            )),
            End::Failed => log.push(ev(
                0,
                EventBody::ScanFailed {
                    reason_code: "budget_exhausted".into(),
                    detail: "packet budget spent".into(),
                },
            )),
            End::Denied => log.push(ev(
                0,
                EventBody::PolicyDenied {
                    reason_code: DenyReason::ScopeExpired,
                    detail: "manifest expired".into(),
                },
            )),
            End::Unfinished => {}
        }

        for (index, event) in log.iter_mut().enumerate() {
            event.sequence = index as u64 + 1;
        }
        fold_events(&log)
    }

    fn keys(d: &ScanDiff) -> Vec<(std::net::IpAddr, Endpoint)> {
        d.changes
            .iter()
            .map(|c| (c.target, c.endpoint))
            .chain(d.undetermined.iter().map(|u| (u.target, u.endpoint)))
            .collect()
    }

    proptest! {
        /// AC-5.6, universally quantified: nothing is a change from itself.
        #[test]
        fn diffing_any_fold_against_itself_is_empty((fold, _) in arb_scan_pair()) {
            let d = diff(&fold, &fold);
            prop_assert!(d.changes.is_empty(), "{d:#?}");
            prop_assert!(d.undetermined.is_empty(), "{d:#?}");
            prop_assert_eq!(d.unchanged, fold.endpoints.len() as u64);
        }

        /// Appearance and disappearance are exact inverses: whatever the
        /// classifier says about `(a, b)`, it must say the mirror image about
        /// `(b, a)`. A rule that fires in one direction only is how a diff
        /// starts inventing endpoints.
        #[test]
        fn the_two_directions_are_exact_inverses((a, b) in arb_scan_pair()) {
            let forward = diff(&a, &b);
            let backward = diff(&b, &a);

            let mirror = |k: ChangeKind| match k {
                ChangeKind::EndpointAppeared => ChangeKind::EndpointDisappeared,
                ChangeKind::EndpointDisappeared => ChangeKind::EndpointAppeared,
                other => other,
            };
            let forward_kinds: Map<_, _> = forward
                .changes
                .iter()
                .map(|c| ((c.target, c.endpoint), mirror(c.kind)))
                .collect();
            let backward_kinds: Map<_, _> = backward
                .changes
                .iter()
                .map(|c| ((c.target, c.endpoint), c.kind))
                .collect();
            prop_assert_eq!(forward_kinds, backward_kinds);
            prop_assert_eq!(forward.unchanged, backward.unchanged);
            prop_assert_eq!(forward.undecidable, backward.undecidable);

            let forward_undetermined: BTreeSet<_> = forward
                .undetermined
                .iter()
                .map(|u| (u.target, u.endpoint))
                .collect();
            let backward_undetermined: BTreeSet<_> = backward
                .undetermined
                .iter()
                .map(|u| (u.target, u.endpoint))
                .collect();
            prop_assert_eq!(forward_undetermined, backward_undetermined);

            // And the records themselves are swapped, not merely the keys.
            for (f, b) in forward.changes.iter().zip(backward.changes.iter()) {
                prop_assert_eq!(&f.before, &b.after);
                prop_assert_eq!(&f.after, &b.before);
            }
        }

        /// AC-5.7, universally quantified: the output is a total order over
        /// distinct endpoints, and an endpoint is never reported twice --
        /// not as two changes, and not as a change *and* an unanswered
        /// question.
        #[test]
        fn the_output_is_totally_ordered_and_free_of_duplicate_keys((a, b) in arb_scan_pair()) {
            let d = diff(&a, &b);
            for list in [
                d.changes.iter().map(|c| (c.target, c.endpoint)).collect::<Vec<_>>(),
                d.undetermined.iter().map(|u| (u.target, u.endpoint)).collect::<Vec<_>>(),
            ] {
                let mut sorted = list.clone();
                sorted.sort();
                sorted.dedup();
                prop_assert_eq!(&list, &sorted);
            }
            let all = keys(&d);
            let distinct: BTreeSet<_> = all.iter().copied().collect();
            prop_assert_eq!(all.len(), distinct.len());
        }

        /// Nothing is invented and nothing is dropped: every endpoint either
        /// side mentions is accounted for exactly once, as a change, as an
        /// unanswered question, or in the `unchanged` count.
        #[test]
        fn every_endpoint_is_accounted_for_exactly_once((a, b) in arb_scan_pair()) {
            let d = diff(&a, &b);
            let union: BTreeSet<_> = a.endpoints.keys().chain(b.endpoints.keys()).collect();
            prop_assert_eq!(
                union.len() as u64,
                d.changes.len() as u64 + d.undetermined.len() as u64 + d.unchanged
            );
            let reported: BTreeSet<_> = keys(&d).into_iter().collect();
            for key in reported {
                prop_assert!(union.contains(&key), "{key:?} is in neither fold");
            }
        }

        /// The anti-phantom invariant, over every generated pair: if the two
        /// scans cannot be compared -- either did not complete, or they ran
        /// different plans -- then no endpoint may be reported as having
        /// appeared or disappeared. This is AC-5.34 generalized past the
        /// denied case to every way a scan can fail to look.
        #[test]
        fn an_incomparable_pair_never_reports_an_appearance((a, b) in arb_scan_pair()) {
            let d = diff(&a, &b);
            if d.undecidable.is_some() {
                prop_assert!(
                    !d.changes.iter().any(|c| matches!(
                        c.kind,
                        ChangeKind::EndpointAppeared | ChangeKind::EndpointDisappeared
                    )),
                    "{d:#?}"
                );
            } else {
                prop_assert!(d.undetermined.is_empty(), "{d:#?}");
            }
        }

        /// A confidence wobble is never reported as a product or version
        /// change, whatever else is going on in the pair (AC-5.5).
        #[test]
        fn a_confidence_only_change_never_reports_a_product_or_version((a, b) in arb_scan_pair()) {
            for change in diff(&a, &b).changes {
                let (Some(before), Some(after)) = (&change.before, &change.after) else {
                    continue;
                };
                let same = |f: fn(&Observation) -> Option<String>| {
                    before.observation.as_ref().and_then(f) == after.observation.as_ref().and_then(f)
                };
                if same(|o| Some(o.service.clone()))
                    && same(|o| o.product.clone())
                    && same(|o| o.version.clone())
                    && before.state == after.state
                {
                    prop_assert_eq!(change.kind, ChangeKind::ConfidenceOnly, "{:#?}", change);
                }
            }
        }
    }

    /// Coverage instrumentation for the strategy above. Every threshold is a
    /// shape one of the properties would silently stop testing if the
    /// generator drifted.
    #[test]
    fn the_generator_reaches_every_shape_the_diff_properties_claim_to_cover() {
        const CASES: usize = 4096;

        let strategy = arb_scan_pair();
        let mut runner = TestRunner::deterministic();
        let mut counts: Map<String, usize> = Map::new();
        let mut bump = |name: &str, hit: bool| {
            let slot = counts.entry(name.to_string()).or_insert(0);
            if hit {
                *slot += 1;
            }
        };

        for _ in 0..CASES {
            let (a, b) = strategy.new_tree(&mut runner).unwrap().current();
            let d = diff(&a, &b);

            bump(
                "both folds have >= 1 endpoint",
                !a.endpoints.is_empty() && !b.endpoints.is_empty(),
            );
            bump(
                "the two folds disagree about at least one endpoint's presence",
                a.endpoints.keys().collect::<BTreeSet<_>>()
                    != b.endpoints.keys().collect::<BTreeSet<_>>(),
            );
            bump(
                "absence counted as evidence (comparable pair)",
                d.undecidable.is_none(),
            );
            bump(
                "undecidable: ScanIncomplete",
                d.undecidable == Some(Undecidable::ScanIncomplete),
            );
            bump(
                "undecidable: CoverageDiffers",
                d.undecidable == Some(Undecidable::CoverageDiffers),
            );
            bump(
                "at least one undetermined endpoint",
                !d.undetermined.is_empty(),
            );
            bump("at least one unchanged endpoint", d.unchanged > 0);
            bump("at least one change", !d.changes.is_empty());
            bump("at least two changes", d.changes.len() >= 2);
            for kind in [
                ChangeKind::EndpointAppeared,
                ChangeKind::EndpointDisappeared,
                ChangeKind::StateChanged,
                ChangeKind::ServiceChanged,
                ChangeKind::ProductChanged,
                ChangeKind::VersionChanged,
                ChangeKind::ConfidenceOnly,
            ] {
                bump(
                    &format!("produced {kind:?}"),
                    d.changes.iter().any(|c| c.kind == kind),
                );
            }
            bump(
                "a denied fold on one side",
                matches!(a.terminal, Some(Terminal::Denied { .. }))
                    || matches!(b.terminal, Some(Terminal::Denied { .. })),
            );
        }

        for (name, hit) in &counts {
            println!("{hit:5} / {CASES}  {name}");
        }

        // Floors on a 4096-case sample with a fixed seed
        // (`TestRunner::deterministic()`), each set at roughly half the count
        // actually observed -- room for a strategy tweak, no room for a
        // bucket to collapse unnoticed.
        //
        // Observed on the run these were calibrated against: both folds
        // non-empty 4095, presence disagreement 1761, comparable pair 748,
        // ScanIncomplete 2586, CoverageDiffers 762, >=1 undetermined 1439,
        // >=1 unchanged 3894, >=1 change 3811, >=2 changes 2836, appeared
        // 191, disappeared 167, StateChanged 1970, ServiceChanged 696,
        // ProductChanged 228, VersionChanged 1972, ConfidenceOnly 1843,
        // denied on one side 719.
        let floor = |name: &str, minimum: usize| {
            let hit = counts.get(name).copied().unwrap_or(0);
            assert!(
                hit >= minimum,
                "strategy coverage too thin: {hit}/{CASES} cases reached {name:?}, \
                 wanted at least {minimum}. A property test over inputs that never \
                 reach the branch is a decoration."
            );
        };
        floor("both folds have >= 1 endpoint", CASES * 80 / 100);
        floor(
            "the two folds disagree about at least one endpoint's presence",
            CASES * 20 / 100,
        );
        floor(
            "absence counted as evidence (comparable pair)",
            CASES * 8 / 100,
        );
        floor("undecidable: ScanIncomplete", CASES * 30 / 100);
        floor("undecidable: CoverageDiffers", CASES * 8 / 100);
        floor("at least one undetermined endpoint", CASES * 15 / 100);
        floor("at least one unchanged endpoint", CASES * 40 / 100);
        floor("at least one change", CASES * 40 / 100);
        floor("at least two changes", CASES * 30 / 100);
        // Each of the seven kinds, so no classifier arm can be deleted and
        // leave a property passing over inputs that never reach it. The two
        // presence kinds are the rarest -- they need the pair to be
        // comparable *and* to disagree about an endpoint -- at ~4%, against
        // the 0.15% defect this whole mechanism responds to.
        floor("produced EndpointAppeared", CASES * 2 / 100);
        floor("produced EndpointDisappeared", CASES * 2 / 100);
        floor("produced StateChanged", CASES * 20 / 100);
        floor("produced ServiceChanged", CASES * 8 / 100);
        floor("produced ProductChanged", CASES * 2 / 100);
        floor("produced VersionChanged", CASES * 20 / 100);
        floor("produced ConfidenceOnly", CASES * 20 / 100);
        floor("a denied fold on one side", CASES * 8 / 100);
    }
}
