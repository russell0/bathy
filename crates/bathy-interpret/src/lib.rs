#![forbid(unsafe_code)]
//! `bathy-interpret`: the pure interpretation layer.
//!
//! This crate turns the raw bytes a [`bathy_types::ProbeCapture`] recorded
//! into zero or more [`Interpretation`]s -- structured claims about what
//! service, product, and version a peer's response is evidence for. It is
//! the reason findings in this project are explainable and replayable:
//!
//! - **Explainable.** Every [`Interpretation`] names the exact `rule_id`
//!   that produced it and the exact byte range of the response that
//!   justified it (`matched_span`). [`explain`] resolves any rule id this
//!   crate can produce back to human-readable documentation and its
//!   provenance. M5's `fingerprint.explain` tool is built directly on this.
//! - **Replayable.** [`interpret`] is a pure function: no I/O, no clock, no
//!   randomness, no async runtime. Feed it the same bytes years later and
//!   it makes the same claim, because nothing except those bytes and this
//!   crate's own source code ever fed the decision. M4 Task 4's replay
//!   corpus depends on this holding exactly, with the network interface
//!   down; M7's fuzz target depends on it never panicking regardless.
//!
//! # Purity is enforced structurally, not just by convention
//!
//! `bathy-interpret` depends on exactly two crates: `bathy-types` (for
//! [`bathy_types::ProbeCapture`], [`bathy_types::event::Observation`], and
//! [`bathy_types::confidence::Confidence`] -- the shapes this crate
//! consumes and produces) and `regex` (for matching text-shaped protocol
//! banners). This crate's own code never touches tokio, the filesystem, a
//! clock, or a random-number generator -- `cargo tree -p bathy-interpret
//! --edges normal` is asserted in CI to show only `bathy-types`, `regex`,
//! and their own transitive dependencies (AC-4.10), and no matcher in
//! `rules.rs` calls anything from either crate except `regex::Regex`
//! itself and plain byte/string operations.
//!
//! (Narrowed claim, M4 Task 3 review round 1: an earlier version of this
//! paragraph said "no randomness anywhere in ... its dependency graph,"
//! which overstates what AC-4.10 actually checks. `bathy-types` itself
//! depends on `ulid`, which depends on `rand`/`getrandom` -- `getrandom`
//! *is* present in this crate's dependency tree; `bathy_types::clock` is
//! the sanctioned, sole call site for it in this workspace, and this
//! crate's own code never calls it. That inheritance is unavoidable and
//! judged acceptable: it is linkable, not callable, from here, and
//! removing it would not actually shrink the built artifact -- Cargo's
//! feature unification means every other crate in the workspace that
//! depends on `bathy-types` already pulls the same dependency in, so it is
//! compiled into any binary that links this crate either way.)
//!
//! This crate also sits *below* `bathy-probe` in this workspace's layer
//! order (`xtask`'s `LAYERS`), specifically so `ProbeCapture` fixtures can
//! be built by hand in a test or fuzz target with no socket anywhere in
//! the dependency graph at all.
//!
//! # Never guess (AC-4.13)
//!
//! [`interpret`] returns an empty vector when nothing in its rule set
//! recognizes the input. A scanner that invents a service from bytes that
//! do not structurally support the claim is worse than one that reports
//! nothing -- see `interpret::tests::unrecognized_bytes_yield_no_observation_rather_than_a_guess`.

mod interpret;
mod rules;

pub use interpret::{Interpretation, interpret};
pub use rules::{RuleDoc, Specificity, all_rules, explain};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_rule_documents_its_non_nmap_source() {
        for rule in all_rules() {
            assert!(!rule.source.is_empty(), "rule {} has no source", rule.id);
            let lower = rule.source.to_lowercase();
            assert!(!lower.contains("nmap"), "rule {} cites Nmap", rule.id);
        }
    }

    #[test]
    fn every_rule_documents_a_non_empty_rationale() {
        for rule in all_rules() {
            assert!(
                !rule.rationale.is_empty(),
                "rule {} has no rationale",
                rule.id
            );
        }
    }

    #[test]
    fn every_rule_id_is_unique() {
        let mut ids: Vec<&str> = all_rules().map(|r| r.id).collect();
        let before = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), before, "duplicate rule id in the registry");
    }

    #[test]
    fn explain_resolves_every_rule_all_rules_can_produce() {
        for rule in all_rules() {
            assert!(
                explain(rule.id).is_some(),
                "explain() cannot resolve {}, which all_rules() lists",
                rule.id
            );
        }
    }

    #[test]
    fn explain_returns_none_for_an_unknown_rule_id() {
        assert!(explain("no-such-rule-id").is_none());
    }

    #[test]
    fn the_rule_set_is_non_empty() {
        // A crate with zero rules would make every other guarantee here
        // vacuous. Not a brief requirement, but the whole point of this
        // crate existing.
        assert!(all_rules().next().is_some());
    }
}
