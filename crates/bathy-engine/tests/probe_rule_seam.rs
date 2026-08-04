//! The probe-id ↔ rule-id seam, guarded.
//!
//! # Why this file exists at all, and why it lives *here*
//!
//! `bathy-interpret` dispatches rules by matching a `ProbeCapture`'s
//! `probe_id` against a `&'static str` duplicated in each rule
//! (`rules::rules_for`). The authoritative ids live one layer up, in
//! `bathy-probe` (`Probe::id`, one per probe). Those are two independent
//! lists of the same strings, and until this file existed nothing connected
//! them: renaming `redis-ping-v1` to `redis-ping-v2` in `bathy-probe` --
//! **exactly what the mandatory `-vN` suffix scheme
//! (`ProbeRegistry::new`'s own assertion) exists to make possible** -- left
//! all 253 tests in `bathy-probe`, `bathy-interpret` and `bathy-engine`
//! green while permanently and silently disabling Redis identification: a
//! real Redis returns `+PONG\r\n`, `rules_for("redis-ping-v2")` yields an
//! empty iterator, `interpret` returns an empty vector, and
//! `Scheduler::detect_service` returns `Ok(None)`. No error, no warning, no
//! event. A silent false negative that no amount of production traffic
//! would ever surface.
//!
//! `bathy-interpret` cannot check this itself, and the design note on
//! `bathy_interpret::known_probe_ids` is right about why: this crate's
//! `xtask check-deps` layer order puts `bathy-interpret` *below*
//! `bathy-probe`, and `check-deps` inspects a package's dev-dependencies
//! too (`find_violations` does not filter `cargo metadata`'s dependency
//! list by kind), so even a dev-only `bathy-probe` edge from
//! `bathy-interpret` is a layering violation that fails the build. That
//! reasoning was never wrong. What was wrong is that it stopped there --
//! "I cannot check this from here" was treated as "it need not be checked."
//!
//! The invariant does not need to move layers; it needs to move **files**.
//! `bathy-engine` is the first crate in the layer order that depends on
//! both (`Cargo.toml`: `bathy-probe` and `bathy-interpret`, both normal
//! dependencies, both downhill), so it is the first place the two lists can
//! be compared at all. This test does that comparison, using nothing but
//! the two crates' public APIs.
//!
//! # What is asserted, and in which direction
//!
//! **Both directions, as an exact set equality**, via two separately named
//! assertions so a failure says which kind of drift happened and what to do
//! about it:
//!
//! 1. Every id in `bathy_interpret::known_probe_ids()` is the id of a probe
//!    in `ProbeRegistry::standard()` -- an *orphaned rule*: a rule that can
//!    never fire, because no probe produces captures bearing its id. This
//!    is the direction that catches the version bump above.
//! 2. Every id in `ProbeRegistry::standard()` has at least one rule -- a
//!    *mute probe*: a probe whose captures nothing can interpret, so it
//!    burns a packet, a socket and a rate-limiter token on every candidate
//!    endpoint and can only ever contribute `Ok(None)`.
//!
//! Direction 1 alone (the "superset" the review proposed) is sufficient to
//! catch the reported defect, and direction 2 is the one with a plausible
//! benign trigger: someone lands a probe in one commit and its rules in the
//! next. It is asserted anyway, deliberately. A mute probe is not a
//! harmless intermediate state -- `select_probes` will hand it real
//! endpoints the moment it is in `standard()`, and it will spend real
//! budget against them for a result it structurally cannot produce. If that
//! state is ever genuinely wanted, the right response is not to weaken this
//! test but to keep the probe out of `standard()` until its rules exist,
//! which is also what stops it emitting traffic. Making that decision
//! explicit is the point; a test that quietly tolerated it would be back to
//! "unchecked".
//!
//! Neither assertion pins the *contents* of the id set -- adding a ninth
//! protocol (probe + rules together) passes untouched. Only disagreement
//! between the two lists fails.

use std::collections::BTreeSet;

use bathy_interpret::known_probe_ids;
use bathy_probe::ProbeRegistry;

fn registry_ids() -> BTreeSet<&'static str> {
    ProbeRegistry::standard()
        .all()
        .iter()
        .map(|p| p.id())
        .collect()
}

fn rule_ids() -> BTreeSet<&'static str> {
    known_probe_ids().collect()
}

/// Direction 1: no rule names a probe id that no probe produces.
///
/// The failure message names the specific orphaned id and states the two
/// legitimate repairs, because the situation that produces this failure is
/// almost always a deliberate, correct probe-id version bump that simply
/// has not been finished yet -- the person reading this message needs to be
/// told what the other half of their change is, not merely that something
/// is inconsistent.
#[test]
fn every_interpret_rule_names_a_probe_id_some_real_probe_actually_emits() {
    let orphaned: Vec<&str> = rule_ids().difference(&registry_ids()).copied().collect();
    assert!(
        orphaned.is_empty(),
        "bathy-interpret has rule(s) for probe id(s) {orphaned:?}, which no probe in \
         ProbeRegistry::standard() emits ({:?}).\n\
         Those rules are unreachable: nothing will ever produce a ProbeCapture with \
         that probe_id, so rules_for() returns an empty iterator, interpret() returns \
         an empty vector, and Scheduler::detect_service returns Ok(None) -- silently, \
         with no error and no event.\n\
         If a probe id was version-bumped in bathy-probe, bump the matching \
         `probe_id` on its rule(s) in crates/bathy-interpret/src/rules.rs to the same \
         new value, and add a corpus fixture under testdata/captures/ naming it. If a \
         probe was removed, remove its rules too.",
        registry_ids()
    );
}

/// Direction 2: no probe exists whose captures nothing can interpret.
#[test]
fn every_registered_probe_has_at_least_one_interpret_rule_that_can_fire_on_it() {
    let mute: Vec<&str> = registry_ids().difference(&rule_ids()).copied().collect();
    assert!(
        mute.is_empty(),
        "ProbeRegistry::standard() contains probe(s) {mute:?} that bathy-interpret has \
         no rule for (it knows {:?}).\n\
         select_probes() will still offer them as candidates, so each one spends a \
         rate-limiter token, a budget packet and a real TCP connection against every \
         matching endpoint to produce a capture that interpret() can only ever return \
         an empty vector for.\n\
         Either add at least one rule for it in crates/bathy-interpret/src/rules.rs, \
         or keep the probe out of ProbeRegistry::standard() until its rules exist \
         (which is also what stops it emitting traffic).",
        rule_ids()
    );
}

/// Fixture sanity for the two tests above: they compare two sets, and two
/// *empty* sets are equal. If `known_probe_ids()` or `ProbeRegistry::all()`
/// ever started returning nothing, both assertions above would pass while
/// checking nothing at all -- the exact "vacuously green" shape this whole
/// file exists to eliminate.
#[test]
fn the_seam_assertions_are_comparing_non_empty_sets() {
    assert_eq!(
        registry_ids().len(),
        8,
        "M4 ships eight probes; update this count deliberately when that changes"
    );
    assert_eq!(rule_ids().len(), 8, "one probe id per probe, all covered");
}
