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

//! The scope manifest: the authorization boundary that decides whether a
//! packet may ever be sent to a given address. Nothing downstream of
//! [`manifest::ScopeManifest::allows`] should be trusted to make that call
//! itself -- every other crate that ends up putting a packet on the wire
//! goes through this gate first.
//!
//! # No panics on the byte path (Global Constraint)
//!
//! The `#![cfg_attr(not(test), deny(...))]` above is the same lint
//! `bathy-probe` and `bathy-interpret` carry, and this crate is here because
//! the constraint's original wording was too narrow, not because anything
//! here reads a socket. `ScopeManifest::load` parses a document this project
//! did not write -- `gates::FUZZ_SURFACES` has registered it as an
//! untrusted-input surface since M7 Task 1, calling it "the authorization
//! boundary" -- and `allows` then decides whether a packet may be emitted at
//! all. A panic in a *deny-by-default* check is not a crash in a leaf
//! parser: it is the gate failing, which is the most consequential failure
//! in this repository.
//!
//! It cost nothing to add. The lint was enabled here in the M7 panic-lint
//! round and found **zero** hits: every bound in `manifest.rs`, `policy.rs`
//! and `budget.rs` was already checked. That measurement is the reason this
//! crate was widened into the constraint and the event-log crates were not;
//! see the `panic-lint-widening` entry in `xtask`'s `DEFERRALS` for the
//! three that were measured and left outstanding, with their counts.
//!
//! Test code is exempt by compilation unit (`cfg_attr(not(test), ...)`) --
//! see `bathy-probe`'s crate doc for the full reasoning.

pub mod budget;
pub mod manifest;
pub mod policy;

pub use budget::{BudgetExhausted, BudgetLedger};
pub use manifest::{ManifestError, ScopeManifest};
pub use policy::{DenyReason, PolicyDecision, evaluate};
