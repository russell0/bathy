//! The scan plan: a fully enumerated, deterministically ordered list of scan
//! units, plus the content hash that identifies the *work* a request
//! describes.
//!
//! # The unit list is never persisted -- `unit(i)` is a compatibility surface
//!
//! M2's `unit_progress` table (`bathy-store`) stores only `(scan_id,
//! unit_index)` -- see `crates/bathy-store/src/schema.sql` and the
//! `unit_progress_persists_only_the_index_never_an_expanded_target` test
//! next to it, which proves that structurally rather than by comment. A
//! resumed scan rebuilds its plan from the stored `request_json` and skips
//! whatever indices are already recorded complete. That is sound only if
//! `unit(i)` returns the same [`ScanUnit`] for a given index, for a given
//! engine version, forever: the ordering implemented below is therefore a
//! compatibility surface in the same sense a wire format is, not an
//! implementation detail free to shift between releases. Changing it
//! without a version bump would silently point every resumed scan at the
//! wrong host and port -- not an error, just a *wrong* probe, which is the
//! worse failure mode.
//!
//! # Port-major ordering
//!
//! Units are ordered so that every host is probed on port *p* before any
//! host is probed on port *p+1*: consecutive indices therefore address
//! different hosts whenever there is more than one target. This spreads
//! load across the target network instead of hammering one address
//! repeatedly -- better for the target (no single host is hit twice in a
//! row) and better for result quality (a host that starts rate-limiting
//! partway through would distort a host-major ordering's results far more
//! severely, since its degraded responses would cluster together instead of
//! being spread across the whole scan).
//!
//! # `plan_hash`: what's in, what's out
//!
//! `plan_hash` excludes `idempotency_key` (the key names one *attempt* at
//! the work; the hash names the work itself) and includes `budgets`
//! (reusing a key with a larger budget must be a conflict, not a silent
//! widening -- `bathy-store`'s idempotency check depends on exactly this).
//!
//! It also excludes the request's *raw* `targets` and `ports` fields, and
//! that is deliberate, not an oversight. Those two fields are exactly the
//! ones [`expand_targets`]/[`resolve_ports`] exist to make order-independent
//! (see their own module docs). If the raw, caller-phrased arrays were
//! embedded in the hashed document, two requests describing the identical
//! scan -- `targets: ["10.0.0.1", "10.0.0.2"]` vs
//! `["10.0.0.2", "10.0.0.1"]` -- would hash *differently*, because
//! `canonical_json` treats array element order as significant (deliberately
//! so -- see `bathy_types::canonical`'s own doc comment, and
//! `expanded_targets`/`resolved_ports` below, which *are* order-sensitive
//! arrays and must stay that way). The fix is to hash the canonical,
//! order-independent forms of those two fields instead of the raw ones.
//!
//! (This is a defect in the task brief, not a hypothetical: an earlier draft
//! of `build` below -- copied verbatim from the brief's Step 3 -- hashed the
//! serialized request wholesale, stripping only `idempotency_key`. That
//! version fails the `plan_hash_ignores_target_and_port_ordering` test this
//! module exists to satisfy. See the task report for the mutation that
//! reproduces it.)

use std::net::IpAddr;

use serde_json::json;

use bathy_types::canonical::{CanonicalError, plan_digest};
use bathy_types::event::{Endpoint, Transport};
use bathy_types::ids::Digest;
use bathy_types::request::ScanRequest;

use crate::ports::{PortError, resolve_ports};
use crate::targets::{TargetError, expand_targets};

/// One addressable unit of work: probe `target` on `endpoint` as the
/// `index`-th step of the plan it came from.
///
/// `endpoint.transport` is always [`Transport::Tcp`]: v0.1 plans TCP probes
/// only, mirroring `ports::resolve_ports`'s own scope (its dataset and
/// range-parsing logic carry no transport information of their own -- see
/// that module's doc comment).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScanUnit {
    pub index: u64,
    pub target: IpAddr,
    pub endpoint: Endpoint,
}

#[derive(Debug, thiserror::Error)]
pub enum PlanError {
    #[error(transparent)]
    Target(#[from] TargetError),
    #[error(transparent)]
    Port(#[from] PortError),
    #[error(transparent)]
    Canonical(#[from] CanonicalError),
}

/// A fully enumerated, deterministically ordered scan.
///
/// The unit list itself (`targets`, `ports`) is never serialized or
/// persisted anywhere in this crate -- it is recomputed from a
/// [`ScanRequest`] every time a [`ScanPlan`] is built, which is what
/// resumption depends on (see the module doc). `targets` and `ports` are
/// both already sorted and deduplicated by [`expand_targets`] and
/// [`resolve_ports`] respectively, so this struct does not need to
/// re-establish that invariant.
#[derive(Clone, Debug)]
pub struct ScanPlan {
    targets: Vec<IpAddr>,
    ports: Vec<u16>,
    hash: Digest,
}

impl ScanPlan {
    /// Expand `request` into a plan, refusing target sets larger than
    /// `max_targets` (see [`expand_targets`]'s pre-count pass for why this
    /// is checked before any address is allocated for).
    pub fn build(request: &ScanRequest, max_targets: usize) -> Result<Self, PlanError> {
        let targets = expand_targets(request.targets.as_slice(), max_targets)?;
        let ports = resolve_ports(&request.ports)?;

        let mut normalized =
            serde_json::to_value(request).expect("ScanRequest always serializes to JSON");
        {
            let obj = normalized
                .as_object_mut()
                .expect("ScanRequest serializes to a JSON object");
            // `idempotency_key` names an attempt, not the work: excluded so
            // two attempts at the same plan hash identically (AC-3.10).
            obj.remove("idempotency_key");
            // `targets` and `ports` are the *raw*, caller-ordered fields.
            // Their canonical, order-independent equivalents
            // (`expanded_targets`, `resolved_ports`) are inserted below in
            // their place -- see the module doc for why leaving the raw
            // fields in would break AC-3.10.
            obj.remove("targets");
            obj.remove("ports");
        }

        let canonical = json!({
            "engine_plan_version": 1,
            "request": normalized,
            "expanded_targets": targets.iter().map(|t| t.to_string()).collect::<Vec<_>>(),
            "resolved_ports": ports,
        });
        let hash = plan_digest(&canonical)?;

        Ok(Self {
            targets,
            ports,
            hash,
        })
    }

    /// The content hash identifying the work this plan describes. See the
    /// module doc for exactly what is and isn't included.
    pub fn hash(&self) -> Digest {
        self.hash
    }

    /// The expanded, sorted, deduplicated target list. Exposed for callers
    /// that need the whole set at once; per-unit access should go through
    /// [`unit`](Self::unit)/[`units_from`](Self::units_from) instead, which
    /// don't require materializing every unit.
    pub fn targets(&self) -> &[IpAddr] {
        &self.targets
    }

    /// Total number of scan units in this plan.
    ///
    /// This is `targets.len() * ports.len()`, computed with a plain `*`
    /// rather than `checked_mul`, deliberately: it cannot overflow `u64` for
    /// any plan this crate's own types can produce. `targets.len()` is
    /// bounded by the entire IPv4 address space (2^32 -- `expand_targets`
    /// refuses IPv6 outright, see `targets.rs`'s module doc), and
    /// `ports.len()` is bounded by `u16::MAX as u64 + 1` (2^16 -- ports are
    /// `u16`). The product is therefore bounded by 2^48, far below `u64`'s
    /// own ceiling of 2^64. See `len_cannot_overflow_u64_for_any_plan_this_crate_can_build`
    /// and `len_and_unit_are_correct_near_the_top_of_a_large_realistic_range`
    /// below for this reasoning pinned as executable tests.
    pub fn len(&self) -> u64 {
        self.targets.len() as u64 * self.ports.len() as u64
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The unit at `index`, or `None` if `index >= len()`.
    ///
    /// Port-major: `index / hosts` selects the port, `index % hosts`
    /// selects the host, so every host is visited once per port before the
    /// port advances. See the module doc for why this ordering, once
    /// shipped, cannot change.
    pub fn unit(&self, index: u64) -> Option<ScanUnit> {
        if index >= self.len() {
            return None;
        }
        let hosts = self.targets.len() as u64;
        let port_index = (index / hosts) as usize;
        let host_index = (index % hosts) as usize;
        Some(ScanUnit {
            index,
            target: self.targets[host_index],
            endpoint: Endpoint {
                transport: Transport::Tcp,
                port: self.ports[port_index],
            },
        })
    }

    /// Every unit from `index` (inclusive) to the end of the plan --
    /// exactly what a resumed scan needs: the stored cursor plus this
    /// iterator reproduces the remaining work without ever materializing
    /// the units already completed.
    pub fn units_from(&self, index: u64) -> impl Iterator<Item = ScanUnit> + '_ {
        (index..self.len()).filter_map(|i| self.unit(i))
    }
}

/// A lower bound on how long a plan takes: the probe count divided by the
/// packets-per-second ceiling, rounded up. Probe latency and connection
/// limits can only make a real run slower.
///
/// It lives here, beside the plan whose length is one of its two inputs,
/// because it is a fact about a plan and a budget and about nothing else.
/// It was first written in `bathy-mcp`, which made the command-line surface
/// reach up into the MCP adapter for it -- legal under the layer table and
/// still the wrong shape: an estimator that lives in the server is one that
/// disappears if the server is ever feature-gated out, taking `scan preview`
/// with it.
pub fn estimated_runtime_seconds(probes: u64, packets_per_second: u32) -> u64 {
    let pps = u64::from(packets_per_second).max(1);
    probes.div_ceil(pps)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bathy_types::ids::ScopeId;

    // --- estimated_runtime_seconds, moved from `bathy-mcp` with its tests ---

    #[test]
    fn a_runtime_estimate_rounds_up_rather_than_reporting_zero_seconds() {
        assert_eq!(estimated_runtime_seconds(1, 100), 1);
        assert_eq!(estimated_runtime_seconds(0, 100), 0);
        assert_eq!(estimated_runtime_seconds(201, 100), 3);
    }

    #[test]
    fn a_zero_rate_does_not_divide_by_zero() {
        // Budgets refuse zero at parse time, so this is unreachable from a
        // request; it is here because the arithmetic must not be the thing
        // that turns a future validation gap into a panic on either surface.
        assert_eq!(estimated_runtime_seconds(5, 0), 5);
    }
    use bathy_types::nonempty::NonEmpty;
    use bathy_types::request::{
        Budgets, EvidenceLevel, Objective, PortPreset, PortSelection, ServiceDetection,
    };

    fn scope_id() -> ScopeId {
        "scope_01ARZ3NDEKTSV4RRFFQ69G5FAV".parse().unwrap()
    }

    fn budgets() -> Budgets {
        Budgets {
            maximum_packets: 1_000_000,
            maximum_runtime_seconds: 3_600,
            maximum_packets_per_second: 10_000,
        }
    }

    fn request_over_specs(targets: &[&str], ports: &[&str]) -> ScanRequest {
        ScanRequest {
            targets: NonEmpty::try_from(targets.iter().map(|s| s.to_string()).collect::<Vec<_>>())
                .expect("test fixture target lists are never empty"),
            authorization_scope_id: scope_id(),
            objective: Objective::InventoryExposedServices,
            ports: PortSelection::Explicit {
                explicit: NonEmpty::try_from(
                    ports.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
                )
                .expect("test fixture port lists are never empty"),
            },
            service_detection: ServiceDetection::default(),
            budgets: budgets(),
            evidence_level: EvidenceLevel::Headers,
            idempotency_key: "test-key".into(),
        }
    }

    fn request_over(target_spec: &str, ports: &[&str]) -> ScanRequest {
        request_over_specs(&[target_spec], ports)
    }

    // ---- Brief's Step 1 tests, verbatim ------------------------------

    #[test]
    fn unit_count_is_targets_times_ports() {
        let plan = ScanPlan::build(&request_over("10.0.0.0/30", &["22", "80"]), 100_000).unwrap();
        assert_eq!(plan.len(), 2 * 2); // /30 -> .1 and .2
    }

    #[test]
    fn units_are_port_major_so_consecutive_probes_hit_different_hosts() {
        let plan = ScanPlan::build(&request_over("10.0.0.0/29", &["22", "80"]), 100_000).unwrap();
        let first_six: Vec<_> = (0..6).map(|i| plan.unit(i).unwrap()).collect();
        // Port 22 across all six hosts before port 80 begins.
        assert!(first_six.iter().all(|u| u.endpoint.port == 22));
        let hosts: Vec<_> = first_six.iter().map(|u| u.target).collect();
        let unique: std::collections::BTreeSet<_> = hosts.iter().collect();
        assert_eq!(unique.len(), 6, "no host is probed twice in a row");
    }

    #[test]
    fn unit_index_is_stable_and_addressable() {
        let plan = ScanPlan::build(&request_over("10.0.0.0/29", &["22", "80"]), 100_000).unwrap();
        for i in 0..plan.len() {
            assert_eq!(plan.unit(i).unwrap().index, i);
        }
        assert!(plan.unit(plan.len()).is_none());
    }

    #[test]
    fn plan_hash_ignores_target_and_port_ordering() {
        let a = ScanPlan::build(
            &request_over_specs(&["10.0.0.1", "10.0.0.2"], &["80", "22"]),
            100,
        )
        .unwrap();
        let b = ScanPlan::build(
            &request_over_specs(&["10.0.0.2", "10.0.0.1"], &["22", "80"]),
            100,
        )
        .unwrap();
        assert_eq!(a.hash(), b.hash());
    }

    #[test]
    fn plan_hash_ignores_the_idempotency_key() {
        let mut r1 = request_over("10.0.0.0/30", &["22"]);
        let mut r2 = r1.clone();
        r1.idempotency_key = "run-one".into();
        r2.idempotency_key = "run-two".into();
        assert_eq!(
            ScanPlan::build(&r1, 100).unwrap().hash(),
            ScanPlan::build(&r2, 100).unwrap().hash()
        );
    }

    #[test]
    fn plan_hash_changes_when_budgets_change() {
        let r1 = request_over("10.0.0.0/30", &["22"]);
        let mut r2 = r1.clone();
        r2.budgets.maximum_packets = r1.budgets.maximum_packets + 1;
        assert_ne!(
            ScanPlan::build(&r1, 100).unwrap().hash(),
            ScanPlan::build(&r2, 100).unwrap().hash(),
            "a different budget is a different plan and must not reuse an idempotency key"
        );
    }

    #[test]
    fn resuming_from_an_index_yields_exactly_the_remaining_units() {
        let plan = ScanPlan::build(&request_over("10.0.0.0/29", &["22", "80"]), 100).unwrap();
        let remaining: Vec<_> = plan.units_from(9).collect();
        assert_eq!(remaining.len() as u64, plan.len() - 9);
        assert_eq!(remaining[0].index, 9);
    }

    // ---- Step 5: plan determinism, stated directly -------------------

    proptest::proptest! {
        /// Building the same request twice must produce the same hash and
        /// the same unit at every index. This proves determinism *within
        /// one process*; cross-process stability (a hasher seeded per
        /// process, or map-iteration-order dependence, would pass this test
        /// every time while still breaking idempotency in production) is
        /// verified separately -- see `examples/plan_hash_probe.rs` and the
        /// task report for both hashes from two real process invocations.
        #[test]
        fn identical_requests_produce_identical_plans(seed in 0u8..64) {
            let r = request_over(&format!("10.0.{seed}.0/30"), &["22", "80", "443"]);
            let a = ScanPlan::build(&r, 10_000).unwrap();
            let b = ScanPlan::build(&r, 10_000).unwrap();
            proptest::prop_assert_eq!(a.hash(), b.hash());
            proptest::prop_assert_eq!(a.len(), b.len());
            for i in 0..a.len() {
                proptest::prop_assert_eq!(a.unit(i), b.unit(i));
            }
        }
    }

    // ---- Verification beyond the brief (task dispatch) -----------------

    // Dispatch: "property-test the ordering invariants ... for arbitrary
    // target and port counts, (a) `unit(i).index == i` for all `i <
    // len()`, (b) `unit(len())` is `None`, (c) every `(target, port)` pair
    // appears exactly once, and (d) consecutive indices differ in target
    // whenever there is more than one target." Follows the permutation
    // property tests' shape in `targets.rs`/`ports.rs`: a proptest over
    // generated counts rather than a couple of fixed examples.
    //
    // `//` rather than `///` deliberately: this comment sits directly above
    // the `proptest::proptest! { ... }` macro invocation itself, not above
    // an item the macro expands to, and rustdoc warns ("unused doc
    // comment") on a doc comment attached to a macro call.
    proptest::proptest! {
        #[test]
        fn ordering_invariants_hold_for_arbitrary_target_and_port_counts(
            target_count in 1usize..15,
            port_count in 1usize..15,
        ) {
            let target_specs: Vec<String> = (1..=target_count).map(|i| format!("10.0.0.{i}")).collect();
            let port_specs: Vec<String> = (1..=port_count).map(|i| i.to_string()).collect();
            let target_refs: Vec<&str> = target_specs.iter().map(String::as_str).collect();
            let port_refs: Vec<&str> = port_specs.iter().map(String::as_str).collect();
            let plan = ScanPlan::build(&request_over_specs(&target_refs, &port_refs), 1_000).unwrap();

            // (a) unit(i).index == i for every valid index.
            for i in 0..plan.len() {
                proptest::prop_assert_eq!(plan.unit(i).unwrap().index, i);
            }

            // (b) unit(len()) is None.
            proptest::prop_assert!(plan.unit(plan.len()).is_none());

            // (c) every (target, port) pair appears exactly once. Combined
            // with `all.len() == plan.len() == target_count * port_count`,
            // a set of that same cardinality with no duplicates can only be
            // the full cross product -- there is no smaller set of
            // distinct pairs drawn from `target_count` targets and
            // `port_count` ports that has that many members.
            let all: Vec<ScanUnit> = plan.units_from(0).collect();
            proptest::prop_assert_eq!(all.len() as u64, plan.len());
            let pairs: std::collections::BTreeSet<(IpAddr, u16)> =
                all.iter().map(|u| (u.target, u.endpoint.port)).collect();
            proptest::prop_assert_eq!(pairs.len(), all.len());

            // (d) consecutive indices differ in target whenever there is
            // more than one target -- port-major, not host-major.
            if target_count > 1 {
                for w in all.windows(2) {
                    proptest::prop_assert_ne!(w[0].target, w[1].target);
                }
            }
        }
    }

    /// Dispatch: "`units_from(n)` must equal `(n..len()).map(unit)`
    /// exactly. Test at n=0, n=len()-1, n=len(), n>len()."
    #[test]
    fn units_from_matches_mapping_unit_over_the_remaining_range() {
        let plan = ScanPlan::build(&request_over("10.0.0.0/29", &["22", "80"]), 100).unwrap();
        let len = plan.len();
        for n in [0, len - 1, len, len + 1, len + 100] {
            let expected: Vec<ScanUnit> = (n..len).filter_map(|i| plan.unit(i)).collect();
            let actual: Vec<ScanUnit> = plan.units_from(n).collect();
            assert_eq!(actual, expected, "units_from({n}) mismatch");
        }
    }

    /// Dispatch: "A request whose expansion yields zero targets cannot
    /// happen (`NonEmpty` plus expansion errors), but confirm `len() == 0`
    /// behaves sanely if it ever arises -- `unit(0)` must be `None`,
    /// `units_from(0)` empty." `ScanPlan::build` genuinely cannot produce
    /// this (every valid target/port spec resolves to at least one
    /// address/port), so this constructs the struct directly via its
    /// private fields -- this test module is a child of `plan`, so it can.
    #[test]
    fn empty_plan_behaves_sanely_even_though_the_public_api_cannot_construct_one() {
        let no_targets = ScanPlan {
            targets: Vec::new(),
            ports: vec![80],
            hash: Digest::of_bytes(b"empty-targets"),
        };
        assert_eq!(no_targets.len(), 0);
        assert!(no_targets.is_empty());
        assert!(no_targets.unit(0).is_none());
        assert_eq!(no_targets.units_from(0).count(), 0);

        let no_ports = ScanPlan {
            targets: vec!["10.0.0.1".parse().unwrap()],
            ports: Vec::new(),
            hash: Digest::of_bytes(b"empty-ports"),
        };
        assert_eq!(no_ports.len(), 0);
        assert!(no_ports.is_empty());
        assert!(no_ports.unit(0).is_none());
        assert_eq!(no_ports.units_from(0).count(), 0);
    }

    // ---- Overflow analysis (dispatch) -----------------------------------

    /// `len()`'s doc comment argues the `targets.len() * ports.len()`
    /// product is bounded by 2^48 (2^32 possible IPv4 targets times 2^16
    /// possible ports), far below `u64::MAX` (2^64). Pinned here as an
    /// executable check of that bound, independent of whether this crate
    /// could ever actually allocate a plan that large.
    #[test]
    fn len_cannot_overflow_u64_for_any_plan_this_crate_can_build() {
        let max_possible_targets = 1u64 << 32; // all of IPv4 -- expand_targets refuses IPv6.
        let max_possible_ports = 1u64 << 16; // u16::MAX + 1.
        let product = max_possible_targets.checked_mul(max_possible_ports);
        assert_eq!(product, Some(1u64 << 48));
        assert!(product.unwrap() < u64::MAX);
    }

    /// A concrete, tractable-to-actually-build plan whose `len()` exceeds
    /// `u32::MAX` -- the boundary a bug that accidentally narrowed any of
    /// this arithmetic to `u32` would trip over -- and whose `unit()` is
    /// checked at both ends of the range, not just index 0.
    #[test]
    fn len_and_unit_are_correct_near_the_top_of_a_large_realistic_range() {
        // 10.0.0.0/15 -> 131,070 usable hosts (network/broadcast trimmed).
        let mut request = request_over("10.0.0.0/15", &["1"]);
        request.ports = PortSelection::Preset {
            preset: PortPreset::All,
        }; // 65,535 ports.

        let plan = ScanPlan::build(&request, 200_000).unwrap();

        let hosts = 131_070u64;
        let ports = 65_535u64;
        assert_eq!(plan.len(), hosts * ports);
        assert!(
            plan.len() > u32::MAX as u64,
            "test is only meaningful once len() exceeds u32::MAX"
        );

        let first = plan.unit(0).unwrap();
        assert_eq!(first.index, 0);
        assert_eq!(first.endpoint.port, 1);
        assert_eq!(first.target, plan.targets()[0]);

        let last = plan.unit(plan.len() - 1).unwrap();
        assert_eq!(last.index, plan.len() - 1);
        assert_eq!(
            last.endpoint.port, 65_535,
            "last unit is the last port (port-major)"
        );
        assert_eq!(last.target, *plan.targets().last().unwrap());

        assert!(plan.unit(plan.len()).is_none());
    }
}
