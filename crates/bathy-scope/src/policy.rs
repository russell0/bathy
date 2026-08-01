use std::net::IpAddr;

use bathy_types::request::ScanRequest;

use crate::manifest::ScopeManifest;

/// C5: `DenyReason` moved to `bathy-types` (see that type's own doc comment
/// for why) -- re-exported here rather than redefined, so existing call
/// sites that write `bathy_scope::policy::DenyReason` or
/// `bathy_scope::DenyReason` (via `crate::lib`'s own re-export) keep
/// working unchanged. `code()` moves with the type: inherent methods on a
/// foreign type may only be defined in the crate that defines the type.
pub use bathy_types::DenyReason;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyDecision {
    Approved,
    Denied { reason: DenyReason, detail: String },
}

/// Evaluated once, before any packet exists, over the *fully expanded* target
/// list. Partial approval is not offered: if any target is out of scope the
/// whole scan is refused, so an agent cannot widen a scan by burying one
/// unauthorized address in a large CIDR.
pub fn evaluate(
    manifest: &ScopeManifest,
    request: &ScanRequest,
    expanded_targets: &[IpAddr],
    now_rfc3339: &str,
) -> PolicyDecision {
    let deny = |reason, detail: String| PolicyDecision::Denied { reason, detail };

    if request.authorization_scope_id != manifest.id() {
        return deny(
            DenyReason::ScopeMismatch,
            format!(
                "request cites {} but manifest is {}",
                request.authorization_scope_id,
                manifest.id()
            ),
        );
    }
    if manifest.is_expired(now_rfc3339) {
        return deny(
            DenyReason::ScopeExpired,
            format!("manifest {} expired before {now_rfc3339}", manifest.id()),
        );
    }
    if let Some(bad) = expanded_targets.iter().find(|ip| !manifest.allows(**ip)) {
        return deny(
            DenyReason::TargetOutOfScope,
            format!("{bad} is not authorized by manifest {}", manifest.id()),
        );
    }
    let c = manifest.ceiling();
    let b = request.budgets;
    if b.maximum_packets > c.maximum_packets
        || b.maximum_runtime_seconds > c.maximum_runtime_seconds
        || b.maximum_packets_per_second > c.maximum_packets_per_second
    {
        return deny(
            DenyReason::BudgetExceedsCeiling,
            format!(
                "requested {}pkt/{}s/{}pps exceeds ceiling {}pkt/{}s/{}pps",
                b.maximum_packets,
                b.maximum_runtime_seconds,
                b.maximum_packets_per_second,
                c.maximum_packets,
                c.maximum_runtime_seconds,
                c.maximum_packets_per_second
            ),
        );
    }
    PolicyDecision::Approved
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: &str = "2026-08-15T00:00:00.000Z";

    /// Deliberately the same fixture text as `manifest.rs`'s own `MANIFEST`
    /// const (allows `10.30.0.0/24`, denies `10.30.0.1/32`, ceiling
    /// 1,000,000pkt/3600s/20,000pps) -- Task 7's `allows()` behavior is the
    /// ground truth this whole module is built on, so evaluating against a
    /// manifest shaped any other way would not actually exercise it.
    const MANIFEST_JSON: &str = r#"{
      "id": "scope_01ARZ3NDEKTSV4RRFFQ69G5FAV",
      "description": "Lab subnet, August 2026 inventory",
      "not_after": "2026-09-01T00:00:00.000Z",
      "allowed_cidrs": ["10.30.0.0/24"],
      "denied_cidrs": ["10.30.0.1/32"],
      "budget_ceiling": {
        "maximum_packets": 1000000,
        "maximum_runtime_seconds": 3600,
        "maximum_packets_per_second": 20000
      }
    }"#;

    /// Matches `MANIFEST_JSON`'s `id` and comfortably fits under its
    /// ceiling on every budget axis.
    const REQUEST_JSON: &str = r#"{
      "targets": ["10.30.0.0/24"],
      "authorization_scope_id": "scope_01ARZ3NDEKTSV4RRFFQ69G5FAV",
      "objective": "inventory_exposed_services",
      "ports": { "preset": "common-1000" },
      "service_detection": { "enabled": true, "intensity": 4 },
      "budgets": {
        "maximum_packets": 200000,
        "maximum_runtime_seconds": 900,
        "maximum_packets_per_second": 5000
      },
      "evidence_level": "headers",
      "idempotency_key": "asset-inventory-2026-08-01"
    }"#;

    fn manifest() -> ScopeManifest {
        ScopeManifest::load(MANIFEST_JSON).unwrap()
    }

    fn request() -> ScanRequest {
        serde_json::from_str(REQUEST_JSON).unwrap()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn approves_a_request_wholly_inside_scope_and_under_ceiling() {
        let m = manifest();
        let d = evaluate(&m, &request(), &[ip("10.30.0.42")], NOW);
        assert_eq!(d, PolicyDecision::Approved);
    }

    #[test]
    fn denies_when_any_single_target_is_out_of_scope() {
        let m = manifest();
        let d = evaluate(&m, &request(), &[ip("10.30.0.42"), ip("10.31.0.9")], NOW);
        assert!(
            matches!(&d, PolicyDecision::Denied { reason, .. } if *reason == DenyReason::TargetOutOfScope),
            "one out-of-scope target must deny the whole scan, got {d:?}"
        );
    }

    #[test]
    fn denies_an_expired_manifest() {
        let m = manifest();
        let d = evaluate(
            &m,
            &request(),
            &[ip("10.30.0.42")],
            "2026-10-01T00:00:00.000Z",
        );
        assert!(
            matches!(&d, PolicyDecision::Denied { reason, .. } if *reason == DenyReason::ScopeExpired)
        );
    }

    #[test]
    fn denies_a_request_whose_budget_exceeds_the_manifest_ceiling() {
        let m = manifest();
        let mut r = request();
        r.budgets.maximum_packets_per_second = 999_999;
        let d = evaluate(&m, &r, &[ip("10.30.0.42")], NOW);
        assert!(
            matches!(&d, PolicyDecision::Denied { reason, .. } if *reason == DenyReason::BudgetExceedsCeiling)
        );
    }

    #[test]
    fn denies_when_the_request_names_a_different_scope() {
        let m = manifest();
        let mut r = request();
        r.authorization_scope_id = "scope_01ARZ3NDEKTSV4RRFFQ69G5FAW".parse().unwrap();
        let d = evaluate(&m, &r, &[ip("10.30.0.42")], NOW);
        assert!(
            matches!(&d, PolicyDecision::Denied { reason, .. } if *reason == DenyReason::ScopeMismatch)
        );
    }

    #[test]
    fn every_denial_carries_a_stable_machine_readable_code() {
        let m = manifest();
        let d = evaluate(&m, &request(), &[ip("8.8.8.8")], NOW);
        let PolicyDecision::Denied { reason, detail } = d else {
            panic!("expected denial")
        };
        assert_eq!(reason.code(), "target_out_of_scope");
        assert!(
            detail.contains("8.8.8.8"),
            "detail must name the offending target"
        );
    }

    // --- AC-1.30, extended beyond the brief's single example: every deny
    // reason -- not just `target_out_of_scope` -- must name its own
    // offending value in `detail`, and every `code()` string is checked
    // verbatim since agents branch on the literal text. ---

    #[test]
    fn stable_codes_are_exactly_the_documented_strings() {
        assert_eq!(DenyReason::ScopeMismatch.code(), "scope_mismatch");
        assert_eq!(DenyReason::ScopeExpired.code(), "scope_expired");
        assert_eq!(DenyReason::TargetOutOfScope.code(), "target_out_of_scope");
        assert_eq!(
            DenyReason::BudgetExceedsCeiling.code(),
            "budget_exceeds_ceiling"
        );
    }

    #[test]
    fn scope_mismatch_detail_names_the_offending_scope_id() {
        let m = manifest();
        let mut r = request();
        r.authorization_scope_id = "scope_01ARZ3NDEKTSV4RRFFQ69G5FAW".parse().unwrap();
        let d = evaluate(&m, &r, &[ip("10.30.0.42")], NOW);
        let PolicyDecision::Denied { reason, detail } = d else {
            panic!("expected denial")
        };
        assert_eq!(reason.code(), "scope_mismatch");
        assert!(
            detail.contains("scope_01ARZ3NDEKTSV4RRFFQ69G5FAW"),
            "detail must name the offending (mismatched) scope id, got: {detail}"
        );
    }

    #[test]
    fn scope_expired_detail_names_the_evaluated_instant() {
        let m = manifest();
        let d = evaluate(
            &m,
            &request(),
            &[ip("10.30.0.42")],
            "2026-10-01T00:00:00.000Z",
        );
        let PolicyDecision::Denied { reason, detail } = d else {
            panic!("expected denial")
        };
        assert_eq!(reason.code(), "scope_expired");
        assert!(
            detail.contains("2026-10-01T00:00:00.000Z"),
            "detail must name the specific instant the manifest was evaluated \
             against, got: {detail}"
        );
    }

    #[test]
    fn budget_exceeds_ceiling_detail_names_the_offending_numbers() {
        let m = manifest();
        let mut r = request();
        r.budgets.maximum_packets_per_second = 999_999;
        let d = evaluate(&m, &r, &[ip("10.30.0.42")], NOW);
        let PolicyDecision::Denied { reason, detail } = d else {
            panic!("expected denial")
        };
        assert_eq!(reason.code(), "budget_exceeds_ceiling");
        assert!(
            detail.contains("999999"),
            "detail must name the offending requested value, got: {detail}"
        );
        assert!(
            detail.contains("20000"),
            "detail must name the ceiling it was compared against, got: {detail}"
        );
    }

    // --- AC-1.31: budgets exceeding the ceiling on ANY axis are denied,
    // not just packets-per-second (the brief's own test only exercises
    // that one axis). ---

    #[test]
    fn denies_when_maximum_packets_exceeds_the_ceiling() {
        let m = manifest();
        let mut r = request();
        r.budgets.maximum_packets = 1_000_001; // ceiling is 1_000_000
        let d = evaluate(&m, &r, &[ip("10.30.0.42")], NOW);
        assert!(
            matches!(&d, PolicyDecision::Denied { reason, .. } if *reason == DenyReason::BudgetExceedsCeiling)
        );
    }

    #[test]
    fn denies_when_maximum_runtime_seconds_exceeds_the_ceiling() {
        let m = manifest();
        let mut r = request();
        r.budgets.maximum_runtime_seconds = 3_601; // ceiling is 3600
        let d = evaluate(&m, &r, &[ip("10.30.0.42")], NOW);
        assert!(
            matches!(&d, PolicyDecision::Denied { reason, .. } if *reason == DenyReason::BudgetExceedsCeiling)
        );
    }

    // Boundary: a request whose budgets sit exactly AT the ceiling on every
    // axis must still be approved -- exercises the same "refuse strictly
    // past, not at" shape as `BudgetLedger::try_spend_packets` (see
    // budget.rs), just on the policy side. `evaluate` uses `>`, not `>=`;
    // this is the test that would fail if that were ever flipped.
    #[test]
    fn request_budgets_exactly_at_the_manifest_ceiling_are_approved() {
        let m = manifest();
        let mut r = request();
        r.budgets.maximum_packets = 1_000_000;
        r.budgets.maximum_runtime_seconds = 3600;
        r.budgets.maximum_packets_per_second = 20_000;
        let d = evaluate(&m, &r, &[ip("10.30.0.42")], NOW);
        assert_eq!(d, PolicyDecision::Approved);
    }

    // --- Ordering: `evaluate` checks scope-mismatch, then expiry, then
    // targets, then budget, in that fixed order. Confirms a request that
    // triggers two problems at once reports the earlier check, so the
    // ordering is itself pinned down rather than left to whichever branch
    // happens to run first. ---

    #[test]
    fn scope_mismatch_is_reported_even_when_the_manifest_is_also_expired() {
        let m = manifest();
        let mut r = request();
        r.authorization_scope_id = "scope_01ARZ3NDEKTSV4RRFFQ69G5FAW".parse().unwrap();
        // "2026-10-01" is also past the manifest's 2026-09-01 expiry, but
        // scope mismatch is checked first.
        let d = evaluate(&m, &r, &[ip("10.30.0.42")], "2026-10-01T00:00:00.000Z");
        assert!(
            matches!(&d, PolicyDecision::Denied { reason, .. } if *reason == DenyReason::ScopeMismatch)
        );
    }

    proptest::proptest! {
        /// The single most important invariant in the project: nothing
        /// outside the allow set is ever approved, for any target address.
        ///
        /// This is written as a bidirectional check (approved iff inside
        /// the allow set) against `should_allow`, a value computed purely
        /// from the literal CIDR text in `MANIFEST_JSON` above -- NOT by
        /// calling `manifest.allows()` or `evaluate()` itself. That
        /// independence is the whole point: Task 7's reviewer found a
        /// property test in `manifest.rs` that compared `allows()` against
        /// itself, so any mutation to `allows()` moved both sides of the
        /// assertion together and the test could never fail no matter how
        /// broken the implementation became. This test's `should_allow`
        /// would not move if `evaluate`/`allows` were mutated, because it
        /// never calls either.
        ///
        /// `octets_strategy` is weighted rather than a bare
        /// `any::<[u8; 4]>()`: a uniformly random 4-byte address lands
        /// inside a single /24 with probability ~1/16.7M, so an unweighted
        /// strategy would burn its whole case budget re-proving the trivial
        /// half of the invariant (far-away addresses are denied) and
        /// essentially never reach the interesting boundary.
        ///
        /// What is actually guaranteed, and by which arm: the single denied
        /// host `10.30.0.1` and the subnet's `.0`/`.255` boundary addresses
        /// each have their own `Just(..)` arm below, so each is sampled on
        /// roughly 1 in 5 test cases. That is a real guarantee. The
        /// swept-fourth-octet arm (second below) makes all 256 addresses in
        /// `10.30.0.0/24` merely *reachable* -- possible, not reliably
        /// sampled -- which is not the same thing and previously was not
        /// enough: mutation testing caught deleting the deny-set check in
        /// `manifest.rs` only 5 times out of 8 runs before the `Just` arms
        /// existed, because that arm alone gives the denied host roughly a
        /// (1/2) * (1/256) chance per case, i.e. per-run miss probability
        /// (255/256)^128 ≈ 61% at proptest's default case count. An earlier
        /// version of this comment claimed the swept arm alone guaranteed
        /// coverage of "every one of those 256 boundary cases" -- that was
        /// the reachable-vs-sampled conflation this paragraph now corrects.
        #[test]
        fn no_target_outside_the_allow_set_is_ever_approved(octets in octets_strategy()) {
            let ip = IpAddr::from(octets);
            let m = manifest();
            let d = evaluate(&m, &request(), &[ip], NOW);
            // Independent ground truth: 10.30.0.0/24 minus the single
            // denied host 10.30.0.1. `ipnet`'s CIDR containment is plain
            // bitmask arithmetic -- it does not special-case a subnet's
            // network (`.0`) or broadcast (`.255`) address the way some
            // "usable host" iterators do -- so both remain inside the
            // allow set.
            let should_allow =
                octets[0] == 10 && octets[1] == 30 && octets[2] == 0 && octets[3] != 1;
            if should_allow {
                proptest::prop_assert!(
                    matches!(&d, PolicyDecision::Approved),
                    "{ip} is inside the allow set but was denied: {d:?}"
                );
            } else {
                proptest::prop_assert!(
                    matches!(&d, PolicyDecision::Denied { .. }),
                    "{ip} was approved but is outside the allow set: {d:?}"
                );
            }
        }
    }

    fn octets_strategy() -> impl proptest::strategy::Strategy<Value = [u8; 4]> {
        use proptest::prelude::*;
        prop_oneof![
            // Any address anywhere in IPv4 space.
            any::<[u8; 4]>(),
            // Any address inside 10.30.0.0/24 -- sweeps every value of the
            // fourth octet, so both CIDR boundaries and the denied host are
            // *possible* outcomes of this arm, though not reliably sampled
            // by it alone (see the three `Just` arms below for the actual
            // per-case guarantee -- C4).
            (0u8..=255).prop_map(|d| [10u8, 30, 0, d]),
            // The single denied host, and the subnet's network/broadcast
            // boundary addresses, each as their own arm: `prop_oneof!`
            // gives every arm equal weight, so each of these three is
            // sampled on roughly 1 in 5 test cases -- not merely reachable
            // via the swept arm above, but reliably exercised by every run.
            // This is what makes this test's headline claim ("nothing
            // outside the allow set is ever approved") actually hold with
            // overwhelming per-run probability, rather than the ~39% catch
            // rate the swept arm alone provided (see the doc comment on
            // the test above for the mutation-testing evidence).
            Just([10u8, 30, 0, 1]),
            Just([10u8, 30, 0, 0]),
            Just([10u8, 30, 0, 255]),
        ]
    }
}
