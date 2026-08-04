//! The fold: an immutable event log in, a queryable endpoint state out.

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use bathy_types::event::{DenyReason, Endpoint, Event, EventBody, Observation, PortState};
use bathy_types::ids::Digest;

/// How one endpoint is addressed in a fold: the host it lives on, plus the
/// transport/port pair. A tuple rather than a struct because it is exactly a
/// composite `BTreeMap` key and nothing else, and because the derived tuple
/// `Ord` gives the sort order the whole query layer is specified in terms of
/// -- by target, then transport, then port.
pub type EndpointKey = (IpAddr, Endpoint);

/// Everything one scan's event log says, arranged for lookup.
///
/// `BTreeMap`/`BTreeSet`, never `HashMap`/`HashSet`: iteration order must be
/// total and stable, because M5 Task 2 diffs two of these and a reordering
/// would surface to an operator as a change that did not happen.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct ScanFold {
    /// Every endpoint the log says anything about, including the ones found
    /// `Closed` or `Filtered`. See [`ScanFold::open_endpoints`] for why the
    /// two are deliberately not collapsed.
    pub endpoints: BTreeMap<EndpointKey, EndpointState>,
    /// Hosts a `host.discovered` event named.
    ///
    /// **Unpopulated as of M5, and empty is not evidence that no host is
    /// up.** No code in `bathy-engine` constructs `EventBody::HostDiscovered`
    /// -- `discovery.rs` ships unprivileged TCP host discovery as a library
    /// building block that the scheduler does not yet call, so no real scan
    /// emits the event and this set is empty for every log the engine
    /// produces today. It is wired up in M6, when discovery joins the
    /// scheduler. A consumer must read this as "the log said nothing about
    /// host liveness", never as "these are all the hosts that were up".
    pub hosts_up: BTreeSet<IpAddr>,
    /// The scan's terminal event, if it reached one.
    ///
    /// `None` is a real and meaningful value: a scan that was cancelled
    /// mid-flight, or is still running, has no terminal state and must not
    /// fold to something that looks completed. It does **not** mean "refused"
    /// -- a scan denied by policy is terminal and folds to
    /// [`Terminal::Denied`].
    pub terminal: Option<Terminal>,
}

/// What the log knows about one endpoint.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct EndpointState {
    /// The last observed reachability of this endpoint, or `None` if the log
    /// contains no `port.state` event for it.
    ///
    /// `Option` rather than a bare `PortState`, and this is a deliberate
    /// departure from the M5 plan's sketched interface. A `service.observed`
    /// event carries no port state of its own, so a log containing one with
    /// no preceding `port.state` for the same endpoint leaves this field
    /// with nothing to hold. The alternatives were all worse: defaulting to
    /// `Open` invents an observation the log never recorded (and M5 Task 2
    /// would then report a state change between a real `None` and an
    /// invented `Open`), and defaulting to `Indeterminate` overloads a
    /// variant whose documented meaning is "probed, but the response was
    /// contradictory across retries" -- a *finding*, not an absence.
    ///
    /// This is the same distinction `open_endpoints` exists to preserve, one
    /// level down: "we probed it and it was shut" and "we never probed it"
    /// are different answers and neither may impersonate the other.
    ///
    /// A gap-free log from `bathy-engine` never produces `None` here --
    /// `Scheduler::detect_service` only runs on an endpoint already found
    /// `Open`, so `port.state` always precedes `service.observed`. It is
    /// reachable only from a truncated or hand-edited log, which is exactly
    /// the input a pure function that will one day be handed a file from
    /// disk has to have a defined answer for.
    pub state: Option<PortState>,
    /// The last service observation for this endpoint, by sequence.
    pub observation: Option<Observation>,
    /// Every distinct evidence digest any event cited for this endpoint, in
    /// first-cited order.
    ///
    /// Accumulated across events rather than replaced by the latest one: a
    /// digest is a pointer into the content-addressed evidence store, and
    /// dropping one destroys the ability to answer "what did we actually see
    /// on this port" for anything but the final observation. Deduplicated
    /// because the same bytes cited twice are one piece of evidence, and
    /// order is first-citation order, which is total because the events were
    /// put in a total order before folding.
    pub evidence_refs: Vec<Digest>,
    /// The probe behind [`EndpointState::observation`], if there is one.
    pub probe_id: Option<String>,
}

/// The three ways a scan's log can end.
///
/// One variant per terminal `EventBody`, and "terminal" is `bathy-engine`'s
/// own definition, not this crate's: `durable_log.rs`'s `is_terminal` and
/// `scheduler.rs`'s `already_terminated()` both match exactly
/// `ScanCompleted | ScanFailed | PolicyDenied`, and a denial is the *only*
/// event a refused scan's log contains (`scheduler.rs`'s
/// `a_scope_validity_denial_emits_no_scan_started`). This enum must mirror
/// that set: an earlier revision omitted [`Terminal::Denied`], and a refused
/// scan then folded byte-identically to a scan that had never run -- so a
/// diff against it reported every endpoint on the host as having disappeared
/// when no packet had been sent. See
/// `a_policy_denied_scan_is_terminal_and_is_not_a_scan_that_never_ran`.
///
/// "Still running" and "cancelled mid-flight" are the cases represented by
/// `ScanFold::terminal` being `None` rather than by a value here. Adding a
/// terminal `EventBody` to `bathy-types` without adding it here is the defect
/// this doc comment exists to prevent; `fold_events`'s `match` is exhaustive
/// over `EventBody`, so a new variant there will not compile until it is
/// decided here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Terminal {
    Completed {
        probes_sent: u64,
        packets_spent: u64,
        findings: u64,
    },
    Failed {
        reason_code: String,
        detail: String,
    },
    /// The scan was refused by policy and no packet was emitted under it.
    ///
    /// `reason_code` is the typed [`DenyReason`], not a `String`, because
    /// that is what `EventBody::PolicyDenied` carries and an agent branches
    /// on `DenyReason::code`'s stable wire strings. Distinct from
    /// [`Terminal::Failed`], whose `reason_code` is an untyped engine/IO
    /// string: "we were not allowed to look" and "we tried and it broke" are
    /// different answers to "what happened to this scan", and M5 Task 2's
    /// diff must be able to tell them apart before it classifies an empty
    /// result.
    Denied {
        reason_code: DenyReason,
        detail: String,
    },
}

impl EndpointState {
    /// Whether this endpoint was observed `Open`.
    ///
    /// Note what this is *not*: `!is_open()` covers `Closed`, `Filtered`,
    /// `Indeterminate` and "never observed" alike, which is why callers that
    /// need to tell those apart must read [`EndpointState::state`] directly.
    pub fn is_open(&self) -> bool {
        self.state == Some(PortState::Open)
    }

    fn cite(&mut self, digest: Digest) {
        // Linear scan, not a set: the vector holds a handful of digests for a
        // single endpoint, and preserving first-citation order is the point.
        if !self.evidence_refs.contains(&digest) {
            self.evidence_refs.push(digest);
        }
    }
}

impl ScanFold {
    /// The endpoints observed `Open`, in key order.
    ///
    /// Deliberately an iterator over a subset rather than a separate stored
    /// collection: `open_endpoints().count()` and `endpoints.len()` answer
    /// different questions and both are needed. An endpoint we probed and
    /// found closed is a *finding* -- it is the evidence a later diff needs
    /// to say "this port closed" -- while an endpoint we never probed is not
    /// a finding at all. Storing only the open ones would erase that
    /// difference permanently.
    pub fn open_endpoints(&self) -> impl Iterator<Item = (&EndpointKey, &EndpointState)> {
        self.endpoints.iter().filter(|(_, state)| state.is_open())
    }
}

/// Fold an event log into the state it describes.
///
/// Pure: same events in, byte-identical `ScanFold` out, for any permutation
/// of the input. Nothing here reads a clock, a socket, a database or a file.
///
/// One caveat, attached where it belongs rather than to the claim as a whole:
/// on a **malformed** log -- one with two events sharing a `sequence`, which
/// `bathy-evidence` cannot produce -- the tiebreak is keyed on `Debug`
/// rendering, which is stable within a build but carries no cross-release
/// guarantee from Rust. See the "Ordering" section.
///
/// # Ordering
///
/// The events are put into a total order *before* folding, and the caller's
/// order is never trusted. `read_from` streams a resumable log, a resumed
/// scan appends after a gap-free replay, and nothing in the type system says
/// a caller hands these over in order -- so "sorted by `sequence`" is
/// established here rather than assumed.
///
/// `sequence` alone is a total order on a well-formed log, where it is
/// gap-free and monotonic by construction. It is *not* total on a malformed
/// one: two events sharing a sequence number would be left in whatever
/// relative order the caller supplied, and the fold's determinism guarantee
/// would quietly become a guarantee about the caller. Ties are therefore
/// broken by the events' own `Debug` rendering, which is a pure function of
/// their contents -- so two events that tie on both are indistinguishable to
/// the fold and applying either first gives the same result. Rendering is
/// computed only inside a run of equal sequence numbers, so a well-formed log
/// never pays for it.
///
/// **The scope of that tiebreak's guarantee, stated exactly.** `Debug` is
/// total, pure and deterministic *within a build*, which is the whole of what
/// the fold's callers can observe: two folds compared in one process agree
/// unconditionally. Rust promises nothing about `Debug` output across
/// releases, so on the tie path -- and only there -- "byte-identical" is
/// build-relative. Three things bound this. It is unreachable from a real
/// log: `bathy-evidence`'s log is append-only, gap-free and monotonic in
/// `sequence` by construction, so no two events can collide. Nothing today
/// compares a `ScanFold` across builds, because `ScanFold` is not
/// serializable (deliberately -- see the crate docs). And the alternative
/// keys were each worse: a canonical-JSON (RFC 8785) rendering *is* stable
/// across releases and is this project's hashing input, but reaching it means
/// adding `serde_json` to a crate whose single-dependency graph is what
/// makes its purity checkable rather than merely asserted; a derived `Ord` on
/// `Event` is impossible (`Confidence` wraps an `f64`) and would in any case
/// be silently defined by source order, the exact drift `bathy-types`'
/// `transport_orders_by_declaration_order` exists to catch. The moment
/// `ScanFold` gains a wire encoding (M5 Task 2), the tie path becomes
/// cross-release visible and this trade must be re-decided -- which is why
/// it is a named obligation on Task 2 in the M5 plan and not a note here.
///
/// # Malformed and contradictory logs
///
/// A `bathy-evidence` log is append-only and gap-free by construction, so the
/// cases below are unreachable from a real scan. This is nonetheless a pure
/// function over a slice that will one day come from a file on disk, so each
/// has a decided answer rather than an accidental one. None of them panics
/// and none of them is silently dropped:
///
/// - **Two `service.observed` for one endpoint disagreeing about the
///   product.** The later one by sequence wins, for exactly the reason a
///   later `port.state` wins (AC-5.2): the log is an ordered record of what
///   was learned, so the last thing learned is the current belief. Both
///   events' evidence digests are retained, so the superseded observation's
///   bytes remain reachable.
/// - **A `port.state` after a terminal event.** Folded normally. Discarding
///   post-terminal events would make the fold a validator that silently
///   deletes data, and a truncated-then-appended log is far likelier than a
///   log whose tail is meaningless. `terminal` holds the last terminal event
///   by sequence, so a `scan.failed` after a `scan.completed` wins.
/// - **A sequence gap.** Folded normally, with no error. A gap means the log
///   is missing events, and the events that *are* present still say true
///   things; refusing to answer at all would be a worse failure mode than
///   answering from what survives. Detecting the gap is `bathy-evidence`'s
///   job, at the point where the missing data is still recoverable, and
///   duplicating that check here would put a second, weaker source of truth
///   in the query layer.
pub fn fold_events(events: &[Event]) -> ScanFold {
    let mut fold = ScanFold::default();

    for event in total_order(events) {
        match &event.body {
            EventBody::ScanStarted { .. } | EventBody::Progress { .. } => {}

            EventBody::PolicyDenied {
                reason_code,
                detail,
            } => {
                fold.terminal = Some(Terminal::Denied {
                    reason_code: *reason_code,
                    detail: detail.clone(),
                });
            }

            EventBody::HostDiscovered { target, .. } => {
                fold.hosts_up.insert(target.ip);
            }

            EventBody::PortStateObserved {
                target,
                endpoint,
                state,
                evidence_refs,
            } => {
                let entry = fold.endpoints.entry((target.ip, *endpoint)).or_default();
                entry.state = Some(*state);
                for digest in evidence_refs.iter().flat_map(|refs| refs.iter()) {
                    entry.cite(*digest);
                }
            }

            EventBody::ServiceObserved {
                target,
                endpoint,
                observation,
                evidence_refs,
                probe_id,
            } => {
                let entry = fold.endpoints.entry((target.ip, *endpoint)).or_default();
                entry.observation = Some(observation.clone());
                entry.probe_id = Some(probe_id.clone());
                for digest in evidence_refs.iter() {
                    entry.cite(*digest);
                }
            }

            EventBody::ScanCompleted {
                probes_sent,
                packets_spent,
                findings,
            } => {
                fold.terminal = Some(Terminal::Completed {
                    probes_sent: *probes_sent,
                    packets_spent: *packets_spent,
                    findings: *findings,
                });
            }

            EventBody::ScanFailed {
                reason_code,
                detail,
            } => {
                fold.terminal = Some(Terminal::Failed {
                    reason_code: reason_code.clone(),
                    detail: detail.clone(),
                });
            }
        }
    }

    fold
}

/// Put `events` into the total order the fold applies them in: by `sequence`,
/// then -- only where sequence numbers collide, which a well-formed log never
/// does -- by the events' own `Debug` rendering.
///
/// See [`fold_events`]'s "Ordering" section for why the tiebreak exists at
/// all. Borrowing rather than cloning: the fold reads each event once and
/// clones only the two owned fields it keeps.
fn total_order(events: &[Event]) -> Vec<&Event> {
    let mut ordered: Vec<&Event> = events.iter().collect();
    ordered.sort_by_key(|event| event.sequence);

    // Second pass over runs of equal `sequence` only. `sort_by_key` above is
    // stable, so without this a duplicated sequence number would resolve to
    // whatever order the caller supplied.
    let mut start = 0;
    while start < ordered.len() {
        let mut end = start + 1;
        while end < ordered.len() && ordered[end].sequence == ordered[start].sequence {
            end += 1;
        }
        if end - start > 1 {
            ordered[start..end].sort_by_cached_key(|event| format!("{event:?}"));
        }
        start = end;
    }

    ordered
}

#[cfg(test)]
mod tests {
    use super::*;

    use bathy_types::confidence::Confidence;
    use bathy_types::event::{Target, Transport};
    use bathy_types::ids::ScanId;
    use bathy_types::nonempty::NonEmpty;

    fn scan_id() -> ScanId {
        "scan_01ARZ3NDEKTSV4RRFFQ69G5FAV".parse().unwrap()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    pub(super) fn tcp(port: u16) -> Endpoint {
        Endpoint {
            transport: Transport::Tcp,
            port,
        }
    }

    pub(super) fn ev(sequence: u64, body: EventBody) -> Event {
        Event {
            scan_id: scan_id(),
            sequence,
            timestamp: "2026-08-01T15:04:31.182Z".into(),
            engine_version: "0.1.0".into(),
            body,
        }
    }

    pub(super) fn digest(tag: &str) -> Digest {
        Digest::of_bytes(tag.as_bytes())
    }

    fn started(sequence: u64) -> Event {
        ev(
            sequence,
            EventBody::ScanStarted {
                plan_hash: digest("plan"),
                estimated_targets: 1,
                estimated_probes: 2,
            },
        )
    }

    fn completed(sequence: u64) -> Event {
        ev(
            sequence,
            EventBody::ScanCompleted {
                probes_sent: 2,
                packets_spent: 4,
                findings: 1,
            },
        )
    }

    fn failed(sequence: u64) -> Event {
        ev(
            sequence,
            EventBody::ScanFailed {
                reason_code: "io".into(),
                detail: "socket closed".into(),
            },
        )
    }

    pub(super) fn denied(sequence: u64) -> Event {
        ev(
            sequence,
            EventBody::PolicyDenied {
                reason_code: DenyReason::ScopeExpired,
                detail: "scope manifest expired at 2026-07-30T00:00:00.000Z".into(),
            },
        )
    }

    fn discovered(sequence: u64, addr: &str) -> Event {
        ev(
            sequence,
            EventBody::HostDiscovered {
                target: Target { ip: ip(addr) },
                method: "tcp-connect".into(),
                evidence_refs: NonEmpty::new(digest(addr)),
            },
        )
    }

    fn port_state(sequence: u64, addr: &str, port: u16, state: PortState) -> Event {
        ev(
            sequence,
            EventBody::PortStateObserved {
                target: Target { ip: ip(addr) },
                endpoint: tcp(port),
                state,
                evidence_refs: None,
            },
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn service(
        sequence: u64,
        addr: &str,
        port: u16,
        name: &str,
        product: Option<&str>,
        version: Option<&str>,
        confidence: f64,
    ) -> Event {
        ev(
            sequence,
            EventBody::ServiceObserved {
                target: Target { ip: ip(addr) },
                endpoint: tcp(port),
                observation: Observation {
                    service: name.into(),
                    product: product.map(str::to_string),
                    version: version.map(str::to_string),
                    confidence: Confidence::new(confidence).unwrap(),
                },
                evidence_refs: NonEmpty::new(digest(&format!("{addr}:{port}:{sequence}"))),
                probe_id: format!("{name}-probe-v1"),
            },
        )
    }

    // --- The five tests the M5 plan specifies for this task. ---

    #[test]
    fn folds_port_state_and_service_into_one_endpoint_record() {
        let f = fold_events(&[
            started(1),
            port_state(2, "10.0.0.1", 443, PortState::Open),
            service(
                3,
                "10.0.0.1",
                443,
                "https",
                Some("nginx"),
                Some("1.26.0"),
                0.95,
            ),
            completed(4),
        ]);
        let e = f.endpoints.get(&(ip("10.0.0.1"), tcp(443))).unwrap();
        assert_eq!(e.state, Some(PortState::Open));
        assert_eq!(
            e.observation.as_ref().unwrap().product.as_deref(),
            Some("nginx")
        );
        assert_eq!(e.evidence_refs.len(), 1);
        assert_eq!(e.probe_id.as_deref(), Some("https-probe-v1"));
    }

    #[test]
    fn a_later_event_supersedes_an_earlier_one_for_the_same_endpoint() {
        // AC-5.2.
        let f = fold_events(&[
            port_state(1, "10.0.0.1", 80, PortState::Filtered),
            port_state(2, "10.0.0.1", 80, PortState::Open),
        ]);
        assert_eq!(
            f.endpoints[&(ip("10.0.0.1"), tcp(80))].state,
            Some(PortState::Open)
        );
    }

    #[test]
    fn folding_is_order_independent_given_sequence_numbers() {
        // AC-5.1. Constructed so that folding in caller order gives the
        // *wrong* answer rather than merely a differently-ordered one: the
        // input is already reversed relative to sequence, so a fold that
        // skipped the sort would leave port 80 `Filtered`.
        let events = vec![
            port_state(2, "10.0.0.1", 80, PortState::Open),
            port_state(1, "10.0.0.1", 80, PortState::Filtered),
        ];
        let mut shuffled = events.clone();
        shuffled.reverse();
        assert_eq!(fold_events(&events), fold_events(&shuffled));
        assert_eq!(
            fold_events(&events).endpoints[&(ip("10.0.0.1"), tcp(80))].state,
            Some(PortState::Open),
            "sequence 2 is the later event and must win regardless of input order"
        );
    }

    #[test]
    fn the_terminal_event_is_captured() {
        let f = fold_events(&[started(1), completed(2)]);
        assert!(matches!(f.terminal, Some(Terminal::Completed { .. })));
        let g = fold_events(&[started(1)]);
        assert!(
            g.terminal.is_none(),
            "an unfinished scan has no terminal state"
        );
    }

    #[test]
    fn closed_ports_are_folded_but_distinguishable_from_open() {
        // AC-5.3.
        let f = fold_events(&[
            port_state(1, "10.0.0.1", 80, PortState::Open),
            port_state(2, "10.0.0.1", 81, PortState::Closed),
        ]);
        assert_eq!(f.open_endpoints().count(), 1);
        assert_eq!(f.endpoints.len(), 2);
        assert_eq!(
            f.endpoints[&(ip("10.0.0.1"), tcp(81))].state,
            Some(PortState::Closed)
        );
    }

    // --- Tests the plan's five do not pin. Each is here because a plausible
    // implementation passes all five above and still gets this wrong. ---

    #[test]
    fn filtered_endpoints_are_retained_too_not_just_closed_ones() {
        // AC-5.3 names `Closed` *and* `Filtered`, and the plan's own test
        // exercises only `Closed`. `Filtered` is the more likely one to be
        // dropped by an implementation that treats "not open" as "not worth
        // keeping", and it is the evidence a later diff needs to distinguish
        // a firewall appearing from a service vanishing.
        let f = fold_events(&[
            port_state(1, "10.0.0.1", 80, PortState::Filtered),
            port_state(2, "10.0.0.1", 81, PortState::Indeterminate),
        ]);
        assert_eq!(f.endpoints.len(), 2);
        assert_eq!(f.open_endpoints().count(), 0);
        assert_eq!(
            f.endpoints[&(ip("10.0.0.1"), tcp(80))].state,
            Some(PortState::Filtered)
        );
        assert_eq!(
            f.endpoints[&(ip("10.0.0.1"), tcp(81))].state,
            Some(PortState::Indeterminate)
        );
    }

    #[test]
    fn an_endpoint_never_probed_is_absent_not_closed() {
        // The other half of AC-5.3's distinction, and the half no plan test
        // covers: `endpoints` must not gain entries the log never mentioned.
        let f = fold_events(&[port_state(1, "10.0.0.1", 80, PortState::Open)]);
        assert!(!f.endpoints.contains_key(&(ip("10.0.0.1"), tcp(81))));
        assert_eq!(f.endpoints.len(), 1);
    }

    #[test]
    fn hosts_up_are_recorded_from_host_discovered_and_nothing_else() {
        let f = fold_events(&[
            discovered(1, "10.0.0.1"),
            discovered(2, "10.0.0.2"),
            discovered(3, "10.0.0.1"),
            // A port observation is not a host discovery. Folding it into
            // `hosts_up` would make the set answer a question nobody asked.
            port_state(4, "10.0.0.9", 80, PortState::Open),
        ]);
        assert_eq!(f.hosts_up, BTreeSet::from([ip("10.0.0.1"), ip("10.0.0.2")]));
    }

    #[test]
    fn a_service_observation_without_a_port_state_leaves_the_state_unknown() {
        // The malformed-log ruling for `EndpointState::state`: the endpoint
        // exists (we learned something about it) but its reachability is
        // `None`, not an invented `Open`.
        let f = fold_events(&[service(
            1,
            "10.0.0.1",
            443,
            "https",
            Some("nginx"),
            None,
            0.5,
        )]);
        let e = &f.endpoints[&(ip("10.0.0.1"), tcp(443))];
        assert_eq!(e.state, None);
        assert!(e.observation.is_some());
        assert_eq!(
            f.open_endpoints().count(),
            0,
            "an endpoint with no observed port state is not an open endpoint"
        );
    }

    #[test]
    fn contradictory_service_observations_resolve_to_the_later_sequence() {
        let f = fold_events(&[
            service(2, "10.0.0.1", 443, "https", Some("apache"), None, 0.4),
            service(1, "10.0.0.1", 443, "https", Some("nginx"), None, 0.9),
        ]);
        let e = &f.endpoints[&(ip("10.0.0.1"), tcp(443))];
        assert_eq!(
            e.observation.as_ref().unwrap().product.as_deref(),
            Some("apache")
        );
        assert_eq!(
            e.evidence_refs.len(),
            2,
            "the superseded observation's evidence must stay reachable"
        );
    }

    #[test]
    fn evidence_refs_accumulate_in_first_citation_order_and_deduplicate() {
        let a = digest("a");
        let b = digest("b");
        let refs = |sequence: u64, ds: &[Digest]| {
            ev(
                sequence,
                EventBody::PortStateObserved {
                    target: Target { ip: ip("10.0.0.1") },
                    endpoint: tcp(80),
                    state: PortState::Open,
                    evidence_refs: Some(NonEmpty::try_from(ds.to_vec()).unwrap()),
                },
            )
        };
        let f = fold_events(&[refs(2, &[b, a]), refs(1, &[a])]);
        assert_eq!(
            f.endpoints[&(ip("10.0.0.1"), tcp(80))].evidence_refs,
            vec![a, b],
            "sequence 1 cites `a` first, so `a` leads; `a` is not repeated"
        );
    }

    #[test]
    fn events_after_a_terminal_event_are_still_folded() {
        let f = fold_events(&[
            started(1),
            completed(2),
            port_state(3, "10.0.0.1", 80, PortState::Open),
        ]);
        assert_eq!(
            f.endpoints.len(),
            1,
            "a post-terminal event carries real data and must not be dropped"
        );
        assert!(matches!(f.terminal, Some(Terminal::Completed { .. })));
    }

    #[test]
    fn the_last_terminal_event_by_sequence_wins() {
        let f = fold_events(&[failed(3), completed(2), started(1)]);
        assert_eq!(
            f.terminal,
            Some(Terminal::Failed {
                reason_code: "io".into(),
                detail: "socket closed".into(),
            })
        );
    }

    #[test]
    fn a_policy_denied_scan_is_terminal_and_is_not_a_scan_that_never_ran() {
        // CRITICAL-1. `policy.denied` is one of `bathy-engine`'s three
        // terminal event kinds (`durable_log.rs`'s `is_terminal`,
        // `scheduler.rs`'s `already_terminated()`), and a refused scan's log
        // is exactly one event: this one. An earlier revision discarded it,
        // so a refused scan folded to `terminal: None` with no endpoints --
        // byte-identical to a scan that had never run, and contradicting
        // `bathy-store`, which had already recorded `TaskStatus::Denied` for
        // the same scan.
        let refused = fold_events(&[denied(1)]);
        let never_ran = fold_events(&[]);

        assert_eq!(
            refused.terminal,
            Some(Terminal::Denied {
                reason_code: DenyReason::ScopeExpired,
                detail: "scope manifest expired at 2026-07-30T00:00:00.000Z".into(),
            }),
            "a denial is a terminal outcome and must be readable as one"
        );
        assert_ne!(
            refused, never_ran,
            "a refused scan must not be confusable with one that never ran"
        );
        assert_ne!(
            format!("{refused:?}"),
            format!("{never_ran:?}"),
            "and must not be confusable byte for byte either"
        );
    }

    #[test]
    fn a_denied_scan_does_not_diff_as_every_endpoint_disappearing() {
        // Why CRITICAL-1 is critical rather than an interface question. M5
        // Task 2's diff is a pure function of two folds. Monday's good scan
        // against Tuesday's expired-manifest scan gives `2 endpoints,
        // Completed` against `0 endpoints, <terminal>`. If Tuesday's
        // terminal were `None`, the only classification the diff could reach
        // is `EndpointDisappeared` for every endpoint -- an agent told every
        // service on the host went away when no packet was sent. The fold
        // owes the diff enough to refuse that classification, and this is it.
        let monday = fold_events(&[
            port_state(1, "10.0.0.1", 80, PortState::Open),
            port_state(2, "10.0.0.1", 443, PortState::Open),
            completed(3),
        ]);
        let tuesday = fold_events(&[denied(1)]);

        assert_eq!(monday.endpoints.len(), 2);
        assert!(tuesday.endpoints.is_empty());
        assert!(
            matches!(tuesday.terminal, Some(Terminal::Denied { .. })),
            "the empty side must carry why it is empty, or the diff cannot \
             tell a refusal from a disappearance"
        );
        assert!(
            !matches!(tuesday.terminal, None | Some(Terminal::Completed { .. })),
            "a refused scan is neither unfinished nor completed"
        );
    }

    #[test]
    fn a_denied_terminal_is_superseded_and_supersedes_by_sequence_like_any_other() {
        // `Denied` is not a special case of the last-terminal-wins rule
        // (AC-5.2 applied to `terminal`); it participates in it. Both
        // directions, so an implementation that appends `Denied` outside the
        // ordinary terminal path fails here.
        let denial_last = fold_events(&[completed(1), denied(2)]);
        assert!(matches!(
            denial_last.terminal,
            Some(Terminal::Denied { .. })
        ));

        let denial_first = fold_events(&[denied(1), failed(2)]);
        assert!(matches!(
            denial_first.terminal,
            Some(Terminal::Failed { .. })
        ));
    }

    #[test]
    fn a_denial_is_not_folded_into_a_failure() {
        // `Terminal::Failed` would also make a denied scan distinguishable
        // from an empty one, and would still be wrong: `DenyReason` is a
        // closed set of four wire codes an agent branches on, while
        // `Failed::reason_code` is an unconstrained engine/IO string. A diff
        // that reads "refused" as "errored" retries a scan that policy
        // refused.
        let f = fold_events(&[denied(1)]);
        assert!(
            !matches!(f.terminal, Some(Terminal::Failed { .. })),
            "a policy denial is not an engine failure"
        );
        let Some(Terminal::Denied { reason_code, .. }) = f.terminal else {
            panic!("expected Terminal::Denied, got {:?}", f.terminal);
        };
        assert_eq!(
            reason_code.code(),
            "scope_expired",
            "the typed DenyReason must survive the fold, not be stringified"
        );
    }

    #[test]
    fn a_sequence_gap_does_not_stop_the_fold() {
        let f = fold_events(&[
            started(1),
            port_state(900, "10.0.0.1", 80, PortState::Open),
            completed(901),
        ]);
        assert_eq!(f.open_endpoints().count(), 1);
        assert!(matches!(f.terminal, Some(Terminal::Completed { .. })));
    }

    #[test]
    fn duplicate_sequence_numbers_fold_independently_of_caller_order() {
        // Two contradictory events sharing a sequence number: `sequence`
        // alone cannot order them, so a fold that sorts on it and nothing
        // else would let the caller's order decide the answer.
        let a = port_state(1, "10.0.0.1", 80, PortState::Open);
        let b = port_state(1, "10.0.0.1", 80, PortState::Closed);
        assert_eq!(
            fold_events(&[a.clone(), b.clone()]),
            fold_events(&[b, a]),
            "a duplicated sequence number must still fold deterministically"
        );
    }

    #[test]
    fn an_empty_log_folds_to_an_empty_result() {
        let f = fold_events(&[]);
        assert!(f.endpoints.is_empty());
        assert!(f.hosts_up.is_empty());
        assert!(f.terminal.is_none());
    }

    #[test]
    fn endpoints_iterate_in_target_then_transport_then_port_order() {
        // The stable iteration order the whole determinism claim rests on.
        let udp = |port| Endpoint {
            transport: Transport::Udp,
            port,
        };
        let f = fold_events(&[
            port_state(1, "10.0.0.2", 80, PortState::Open),
            port_state(2, "10.0.0.1", 443, PortState::Open),
            port_state(3, "10.0.0.1", 80, PortState::Open),
            ev(
                4,
                EventBody::PortStateObserved {
                    target: Target { ip: ip("10.0.0.1") },
                    endpoint: udp(53),
                    state: PortState::Open,
                    evidence_refs: None,
                },
            ),
        ]);
        let keys: Vec<_> = f.endpoints.keys().copied().collect();
        assert_eq!(
            keys,
            vec![
                (ip("10.0.0.1"), tcp(80)),
                (ip("10.0.0.1"), tcp(443)),
                (ip("10.0.0.1"), udp(53)),
                (ip("10.0.0.2"), tcp(80)),
            ]
        );
    }
}

/// Order-independence and determinism (AC-5.1) are universally quantified --
/// "for any permutation of any log" -- so they are property tests here rather
/// than the two hand-written cases above, which between them cover exactly one
/// permutation of one two-event log.
///
/// The strategy is instrumented, and that is not ceremony. M4 shipped a
/// property test whose naive `any::<u8>()` strategy produced 6 non-empty
/// results in 4096 cases and never once reached the code it was written to
/// cover, which is what AC-4.25 exists to prevent. A property test over
/// inputs that never reach the interesting branch is a decoration that
/// reports a number. `the_generator_reaches_every_shape_these_properties_
/// claim_to_cover` samples the same strategy 4096 times, counts how often each
/// shape appears, prints the table and fails if any bucket is thin.
#[cfg(test)]
mod proptests {
    use super::tests::*;
    use super::*;

    use std::collections::BTreeMap as Map;

    use bathy_types::confidence::Confidence;
    use bathy_types::event::{DenyReason, Target};
    use bathy_types::nonempty::NonEmpty;
    use proptest::prelude::*;
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;

    /// Deliberately tiny domains. Two hosts and three ports, not `any::<u16>()`:
    /// the properties under test are about *collisions* -- two events landing on
    /// one endpoint so that one supersedes the other -- and a wide port space
    /// makes collisions vanishingly rare, producing thousands of cases that
    /// exercise nothing. The coverage test below is what proves this reasoning
    /// held rather than merely sounding right.
    const HOSTS: [&str; 2] = ["10.0.0.1", "10.0.0.2"];
    const PORTS: [u16; 3] = [80, 443, 8080];
    /// Small enough that duplicates and out-of-order arrivals are common, which
    /// is the point: `sequence` is the fold's whole ordering story.
    const SEQUENCES: std::ops::Range<u64> = 1..6;

    fn arb_state() -> impl Strategy<Value = PortState> {
        prop_oneof![
            Just(PortState::Open),
            Just(PortState::Closed),
            Just(PortState::Filtered),
            Just(PortState::Indeterminate),
        ]
    }

    fn arb_target() -> impl Strategy<Value = Target> {
        prop::sample::select(HOSTS.as_slice()).prop_map(|h| Target {
            ip: h.parse().unwrap(),
        })
    }

    fn arb_endpoint() -> impl Strategy<Value = Endpoint> {
        prop::sample::select(PORTS.as_slice()).prop_map(tcp)
    }

    fn arb_body() -> impl Strategy<Value = EventBody> {
        prop_oneof![
            1 => Just(EventBody::ScanStarted {
                plan_hash: digest("plan"),
                estimated_targets: 2,
                estimated_probes: 6,
            }),
            2 => arb_target().prop_map(|target| EventBody::HostDiscovered {
                evidence_refs: NonEmpty::new(digest(&target.ip.to_string())),
                target,
                method: "tcp-connect".into(),
            }),
            6 => (arb_target(), arb_endpoint(), arb_state(), prop::option::of(0u8..3))
                .prop_map(|(target, endpoint, state, refs)| EventBody::PortStateObserved {
                    target,
                    endpoint,
                    state,
                    evidence_refs: refs
                        .map(|n| NonEmpty::new(digest(&format!("port-evidence-{n}")))),
                }),
            4 => (
                arb_target(),
                arb_endpoint(),
                prop::sample::select(vec!["http", "https", "ssh"]),
                prop::option::of(prop::sample::select(vec!["nginx", "apache", "openssh"])),
                prop::option::of(prop::sample::select(vec!["1.26.0", "1.27.1"])),
                0.0f64..=1.0,
                0u8..3,
            )
                .prop_map(|(target, endpoint, name, product, version, confidence, refs)| {
                    EventBody::ServiceObserved {
                        target,
                        endpoint,
                        observation: Observation {
                            service: name.into(),
                            product: product.map(str::to_string),
                            version: version.map(str::to_string),
                            confidence: Confidence::new(confidence).unwrap(),
                        },
                        evidence_refs: NonEmpty::new(digest(&format!("svc-evidence-{refs}"))),
                        probe_id: format!("{name}-probe-v1"),
                    }
                }),
            1 => Just(EventBody::Progress {
                probes_sent: 1,
                probes_total: 6,
                packets_spent: 2,
            }),
            1 => Just(EventBody::PolicyDenied {
                reason_code: DenyReason::TargetOutOfScope,
                detail: "not in the allow set".into(),
            }),
            2 => (0u64..4).prop_map(|findings| EventBody::ScanCompleted {
                probes_sent: 6,
                packets_spent: 12,
                findings,
            }),
            1 => Just(EventBody::ScanFailed {
                reason_code: "io".into(),
                detail: "socket closed".into(),
            }),
        ]
    }

    fn arb_event() -> impl Strategy<Value = Event> {
        (SEQUENCES, arb_body()).prop_map(|(sequence, body)| ev(sequence, body))
    }

    fn arb_log() -> impl Strategy<Value = Vec<Event>> {
        prop::collection::vec(arb_event(), 0..10)
    }

    /// A log paired with a shuffle of itself. The pair is generated rather than
    /// hand-reversed so that the permutation space is actually explored; the
    /// coverage test records how often the shuffle genuinely reorders, because
    /// a "permutation" that is always the identity would make the whole
    /// property vacuous.
    fn arb_log_and_permutation() -> impl Strategy<Value = (Vec<Event>, Vec<Event>)> {
        arb_log().prop_flat_map(|log| (Just(log.clone()), Just(log).prop_shuffle()))
    }

    proptest! {
        /// AC-5.1, universally quantified.
        #[test]
        fn folding_any_permutation_of_a_log_gives_the_same_result(
            (log, permuted) in arb_log_and_permutation()
        ) {
            prop_assert_eq!(fold_events(&log), fold_events(&permuted));
        }

        /// AC-5.1's stronger form, and the one the M5 design intent states:
        /// not merely `PartialEq`-equal but byte-identical, so that a
        /// `BTreeMap` iteration order or a `Vec<Digest>` ordering cannot
        /// differ underneath an equality that happens not to look at it.
        /// `Digest`'s `Debug` renders the full `blake3:<hex>`, so evidence
        /// ordering is inside this comparison.
        #[test]
        fn folding_any_permutation_renders_byte_identically(
            (log, permuted) in arb_log_and_permutation()
        ) {
            prop_assert_eq!(
                format!("{:?}", fold_events(&log)),
                format!("{:?}", fold_events(&permuted))
            );
        }

        /// AC-5.3, universally quantified: every endpoint the log mentions is
        /// in the fold exactly once, whatever state it was found in, and no
        /// endpoint it does not mention is invented.
        #[test]
        fn the_fold_keys_are_exactly_the_endpoints_the_log_mentions(log in arb_log()) {
            let mut mentioned = BTreeSet::new();
            for event in &log {
                match &event.body {
                    EventBody::PortStateObserved { target, endpoint, .. }
                    | EventBody::ServiceObserved { target, endpoint, .. } => {
                        mentioned.insert((target.ip, *endpoint));
                    }
                    _ => {}
                }
            }
            let folded: BTreeSet<_> = fold_events(&log).endpoints.keys().copied().collect();
            prop_assert_eq!(folded, mentioned);
        }

        /// The fold never invents a terminal state, and never drops one.
        /// Paired with the AC-5.1 properties above this pins "an unfinished
        /// scan has no terminal state" over generated logs, not just the one
        /// hand-written case.
        ///
        /// The `matches!` arm below is the enumeration of terminal event
        /// kinds *this property depends on*, and it must stay equal to
        /// `bathy-engine`'s (`durable_log.rs`'s `is_terminal`). It omitted
        /// `PolicyDenied` while the fold did, which is why this property
        /// passed over a log whose only event was a denial -- both sides of
        /// the equality were wrong in the same direction. It is now the test
        /// that dies if the `PolicyDenied` arm is removed from `fold_events`.
        #[test]
        fn a_log_with_no_terminal_event_folds_to_no_terminal(log in arb_log()) {
            let has_terminal = log.iter().any(|e| matches!(
                e.body,
                EventBody::ScanCompleted { .. }
                    | EventBody::ScanFailed { .. }
                    | EventBody::PolicyDenied { .. }
            ));
            prop_assert_eq!(fold_events(&log).terminal.is_some(), has_terminal);
        }
    }

    /// Coverage instrumentation for the strategy above (AC-4.25's rule, applied
    /// to a new crate). Samples `CASES` logs from the *same* strategy the
    /// properties use and reports how many reached each shape. Every threshold
    /// below is a shape one of the properties above would silently stop testing
    /// if the generator drifted.
    #[test]
    fn the_generator_reaches_every_shape_these_properties_claim_to_cover() {
        const CASES: usize = 4096;

        let strategy = arb_log_and_permutation();
        let mut runner = TestRunner::deterministic();
        let mut counts: Map<&str, usize> = Map::new();
        let mut bump = |name: &'static str, hit: bool| {
            let slot = counts.entry(name).or_insert(0);
            if hit {
                *slot += 1;
            }
        };

        for _ in 0..CASES {
            let (log, permuted) = strategy.new_tree(&mut runner).unwrap().current();
            let fold = fold_events(&log);

            // How many `port.state` events land on each endpoint: >= 2 is the
            // supersession case AC-5.2 is about.
            let mut per_endpoint: Map<EndpointKey, usize> = Map::new();
            for event in &log {
                if let EventBody::PortStateObserved {
                    target, endpoint, ..
                } = &event.body
                {
                    *per_endpoint.entry((target.ip, *endpoint)).or_insert(0) += 1;
                }
            }
            let mut sequences: Vec<u64> = log.iter().map(|e| e.sequence).collect();
            sequences.sort_unstable();
            let duplicate_sequence = sequences.windows(2).any(|w| w[0] == w[1]);

            bump("log is non-empty", !log.is_empty());
            bump(
                "permutation actually reorders the log",
                log.len() > 1 && log != permuted,
            );
            bump("fold has >= 1 endpoint", !fold.endpoints.is_empty());
            bump("fold has >= 2 endpoints", fold.endpoints.len() >= 2);
            bump(
                "fold has >= 1 OPEN endpoint",
                fold.open_endpoints().count() > 0,
            );
            bump(
                "fold retains a Closed/Filtered/Indeterminate endpoint (AC-5.3)",
                fold.endpoints.values().any(|s| {
                    matches!(
                        s.state,
                        Some(PortState::Closed | PortState::Filtered | PortState::Indeterminate)
                    )
                }),
            );
            bump(
                "an endpoint got >= 2 port.state events (supersession, AC-5.2)",
                per_endpoint.values().any(|n| *n >= 2),
            );
            bump(
                "fold carries a service observation",
                fold.endpoints.values().any(|s| s.observation.is_some()),
            );
            bump(
                "an endpoint has an observation but no port state",
                fold.endpoints
                    .values()
                    .any(|s| s.observation.is_some() && s.state.is_none()),
            );
            bump(
                "an endpoint cites >= 2 evidence digests",
                fold.endpoints.values().any(|s| s.evidence_refs.len() >= 2),
            );
            bump("fold reached a terminal state", fold.terminal.is_some());
            bump(
                "fold reached Terminal::Failed specifically",
                matches!(fold.terminal, Some(Terminal::Failed { .. })),
            );
            bump(
                "fold reached Terminal::Denied specifically",
                matches!(fold.terminal, Some(Terminal::Denied { .. })),
            );
            bump("fold recorded a host as up", !fold.hosts_up.is_empty());
            bump(
                "log has a duplicated sequence number (tiebreak path)",
                duplicate_sequence,
            );
        }

        for (name, hit) in &counts {
            println!("{hit:5} / {CASES}  {name}");
        }

        // Floors on a 4096-case sample. `TestRunner::deterministic()` fixes the
        // seed, so the counts above are reproducible run to run and these
        // numbers are not a coin toss -- each floor is set at roughly half the
        // count actually observed, which leaves room for a future strategy
        // tweak without leaving room for a bucket to collapse unnoticed.
        //
        // Observed on the run these were calibrated against (see this task's
        // report for the full printed table): non-empty 3694, permutation
        // reorders 2980, >=1 endpoint 3334, >=2 endpoints 2481, >=1 open 1196,
        // non-open retained 2498, supersession 691, service observation 2391,
        // observation-without-state 1971, >=2 digests 758, terminal 2348,
        // Terminal::Failed 641, Terminal::Denied 523, host up 1530, duplicate
        // sequence 2625.
        //
        // The terminal counts moved when `Terminal::Denied` was added (M5
        // Task 1 fix round, CRITICAL-1): "reached a terminal state" rose
        // 1998 -> 2348 because a denial is now one, and "Terminal::Failed
        // specifically" fell 705 -> 641 because a denial now sometimes wins
        // the last-terminal-by-sequence position a failure used to. Nothing
        // about the strategy changed; the fold's answer did.
        //
        // The two 10% floors (supersession, >=2 digests) are the rarest shapes
        // and were calibrated *downward* after this test failed at 20% on 691
        // real hits -- the instrumentation catching a threshold set by guess
        // rather than by measurement, which is the same class of error it
        // exists to catch in the generator. 691/4096 is 17%; M4's defect,
        // which this whole mechanism is a response to, was 6/4096 = 0.15%.
        let floor = |name: &str, minimum: usize| {
            let hit = counts.get(name).copied().unwrap_or(0);
            assert!(
                hit >= minimum,
                "strategy coverage too thin: {hit}/{CASES} cases reached {name:?}, \
                 wanted at least {minimum}. A property test over inputs that never \
                 reach the branch is a decoration."
            );
        };
        floor("log is non-empty", CASES * 80 / 100);
        floor("permutation actually reorders the log", CASES * 50 / 100);
        floor("fold has >= 1 endpoint", CASES * 60 / 100);
        floor("fold has >= 2 endpoints", CASES * 30 / 100);
        floor("fold has >= 1 OPEN endpoint", CASES * 20 / 100);
        floor(
            "fold retains a Closed/Filtered/Indeterminate endpoint (AC-5.3)",
            CASES * 30 / 100,
        );
        floor(
            "an endpoint got >= 2 port.state events (supersession, AC-5.2)",
            CASES * 10 / 100,
        );
        floor("fold carries a service observation", CASES * 30 / 100);
        floor(
            "an endpoint has an observation but no port state",
            CASES * 15 / 100,
        );
        floor("an endpoint cites >= 2 evidence digests", CASES * 10 / 100);
        floor("fold reached a terminal state", CASES * 30 / 100);
        floor(
            "fold reached Terminal::Failed specifically",
            CASES * 5 / 100,
        );
        // Same generator weight as `ScanFailed` (1 of 18), so the same floor.
        // Without this bucket the `PolicyDenied` arm could be deleted and
        // `a_log_with_no_terminal_event_folds_to_no_terminal` would still be
        // the only thing catching it -- a single property with no evidence
        // that its generator ever reaches the shape.
        floor(
            "fold reached Terminal::Denied specifically",
            CASES * 5 / 100,
        );
        floor("fold recorded a host as up", CASES * 20 / 100);
        floor(
            "log has a duplicated sequence number (tiebreak path)",
            CASES * 30 / 100,
        );
    }
}
