#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic,
        clippy::arithmetic_side_effects
    )
)]

//! The probe framework: the bounded I/O layer that turns a live socket into
//! raw, uninterpreted bytes.
//!
//! `bathy-probe` **does I/O and produces bytes**. It never interprets what
//! it reads -- no protocol parsing, no pattern matching, no confidence
//! scoring. `bathy-interpret` (M4 Task 3) is the crate that consumes those
//! bytes and does no I/O at all. Keeping that line clean is the design
//! point this whole milestone is built on: it is what makes interpretation
//! replayable years later against a newer rule set, from stored evidence
//! alone, without a network.
//!
//! The peer on the other end of every socket this crate touches is hostile
//! by assumption: a scan reaches thousands of endpoints, and one of them
//! will misbehave, deliberately or not. [`framework::ProbeIo::read_bounded`]
//! is the load-bearing guarantee that a hostile peer cannot turn a probe
//! into unbounded memory growth or an indefinite hang -- see its own doc
//! comment for exactly how.
//!
//! # No panics on the byte path (Global Constraint), and how it is scoped
//!
//! The `#![cfg_attr(not(test), deny(...))]` above is the executable form of
//! the overview's "No panics in parsing paths" constraint. That constraint
//! said `unwrap()`/`expect()`/indexing-slice panics were "denied by lint" in
//! this crate and in `bathy-interpret` **from M1**, and no such lint existed
//! anywhere in the tree until the M7 verification round -- not in either
//! `lib.rs`, not in `ci.yml`, not in any `Cargo.toml` lint table. It was an
//! aspiration written in the indicative mood for six milestones. Enabling it
//! found real hits in both crates, in exactly the code that reads a socket.
//!
//! **What is denied**, and why each: `unwrap_used` and `expect_used` (a
//! panic is a denial of service triggerable by the thing being scanned),
//! `indexing_slicing` (indexing is the operation that goes wrong in offset
//! arithmetic over a hostile response -- this project has the scars),
//! `panic`, and `arithmetic_side_effects` (an overflowing offset panics in
//! debug and silently wraps in release, which is worse).
//!
//! **How test code is exempt.** `cfg_attr(not(test), ...)`, not a bare
//! `deny`. Under `cargo clippy --all-targets` the library is compiled twice:
//! once as the lib, where `cfg(test)` is off and the deny is live over every
//! line of production code, and once as the unit-test harness, where
//! `cfg(test)` is on and the deny is absent -- so `#[cfg(test)] mod tests`
//! keeps `unwrap()`, which is idiomatic there and not a hostile-input path.
//! Integration tests and benches are separate crates that never see this
//! attribute at all. The exemption is therefore by compilation unit, not by
//! a path list a checker has to keep in sync.
//!
//! **A crate-level `#![allow]` of any of these would reproduce the exact
//! defect being closed**, so every exception is site-level, carries a
//! `reason`, and states why its panic is unreachable. `cargo run -p xtask --
//! check-panics` enforces all of that, and additionally holds the overview's
//! constraint text to the set of crates that actually carry the attribute.

pub mod framework;
pub mod probes;

pub use framework::{Probe, ProbeError, ProbeIo, ProbeKind, ProbeRegistry, select_probes};
// `ProbeCapture` is defined in `bathy-types` (see that type's own doc
// comment for why), not here -- re-exported so a `bathy-probe` consumer
// never has to know that fact to use it.
pub use bathy_types::ProbeCapture;
