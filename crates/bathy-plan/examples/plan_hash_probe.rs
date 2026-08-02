//! Cross-process `plan_hash` stability probe.
//!
//! `plan::tests::identical_requests_produce_identical_plans` proves hash
//! determinism *within one process*. That is not the same guarantee as
//! stability *across* process invocations: a hasher seeded per-process at
//! startup, or reliance on a `HashMap`'s (randomized) iteration order,
//! would pass the in-process property test every single time -- the two
//! calls to `ScanPlan::build` in that test run in the same process, so both
//! would pick up the same per-process seed/order -- while still silently
//! breaking idempotency the moment a scan is resumed by a second `bathy`
//! invocation. This binary exists to make that distinction checkable: build
//! the identical, hardcoded `ScanRequest` and print its `plan_hash`. Run it
//! twice as two separate OS processes and diff the two lines of output; see
//! the task report for the actual invocation and both hashes.
use bathy_plan::ScanPlan;
use bathy_types::ids::ScopeId;
use bathy_types::nonempty::NonEmpty;
use bathy_types::request::{
    Budgets, EvidenceLevel, Objective, PortPreset, PortSelection, ScanRequest, ServiceDetection,
};

fn main() {
    let request = ScanRequest {
        targets: NonEmpty::try_from(vec!["10.30.0.0/24".to_string()])
            .expect("non-empty target list"),
        authorization_scope_id: "scope_01ARZ3NDEKTSV4RRFFQ69G5FAV"
            .parse::<ScopeId>()
            .expect("valid scope id"),
        objective: Objective::InventoryExposedServices,
        ports: PortSelection::Preset {
            preset: PortPreset::Common1000,
        },
        service_detection: ServiceDetection::default(),
        budgets: Budgets {
            maximum_packets: 200_000,
            maximum_runtime_seconds: 900,
            maximum_packets_per_second: 5_000,
        },
        evidence_level: EvidenceLevel::Headers,
        // Deliberately different from any other invocation's key would be,
        // to make the point concrete: plan_hash must not depend on this,
        // and this probe hardcodes the same value every run anyway so it
        // isn't even exercising that axis, only cross-process stability.
        idempotency_key: "cross-process-probe".to_string(),
    };

    let plan = ScanPlan::build(&request, 100_000).expect("plan builds from a valid request");
    println!("{}", plan.hash());
}
