#![forbid(unsafe_code)]
//! Queryable views over a scan's event log.
//!
//! The event log is the source of truth (`bathy-evidence/src/log.rs`: state
//! is derived from the log, never the other way around). This crate derives
//! the *answerable* view from it -- "which ports are open", "what is running
//! on them" -- and holds no state of its own.
//!
//! Everything here is a pure function of its arguments. No crate in this
//! layer touches the store, the network, the clock or the filesystem, and
//! `[dependencies]` is `bathy-types` plus the pure data crates `bathy-types`
//! itself already pulls in -- `serde`, `serde_json`, `schemars`, `thiserror`
//! -- so staying pure remains a property of the dependency graph rather than
//! of anybody's discipline. M5 Task 2 added those four to publish `ScanFold`
//! and `ScanDiff` as committed JSON Schemas (AC-5.35) and to give `WireError`
//! a `Display`; `cargo tree -p bathy-query` is unchanged by the addition,
//! because every one of them was already there transitively.
//!
//! That list is the claim, so it is pinned rather than described: `xtask`'s
//! `PINNED_DEPENDENCIES` holds it and `check-deps` fails on a direct
//! dependency this module does not name, in either direction.
//!
//! Purity is not a stylistic preference here. M5 Task 2's diff is a function
//! of two folds, so any nondeterminism in a fold shows up downstream as a
//! *phantom change* -- a diff telling an operator that a service appeared
//! when nothing did, which is worse than shipping no diff at all. That is
//! why the output is built from `BTreeMap`/`BTreeSet` (total, stable
//! iteration order) and why the fold sorts by `sequence` before folding
//! rather than trusting the order a caller happened to hand it.

pub mod diff;
pub mod fold;
pub mod schema;
pub mod wire;

pub use diff::{Change, ChangeKind, ScanDiff, Undecidable, Undetermined, diff};
pub use fold::{EndpointKey, EndpointState, ScanFold, Terminal, fold_events};
pub use wire::{FoldEntry, ScanFoldWire, WireError};
