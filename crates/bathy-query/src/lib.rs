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
//! `[dependencies]` is `bathy-types` alone so that staying pure is a
//! property of the dependency graph rather than of anybody's discipline.
//!
//! Purity is not a stylistic preference here. M5 Task 2's diff is a function
//! of two folds, so any nondeterminism in a fold shows up downstream as a
//! *phantom change* -- a diff telling an operator that a service appeared
//! when nothing did, which is worse than shipping no diff at all. That is
//! why the output is built from `BTreeMap`/`BTreeSet` (total, stable
//! iteration order) and why the fold sorts by `sequence` before folding
//! rather than trusting the order a caller happened to hand it.

pub mod fold;

pub use fold::{EndpointKey, EndpointState, ScanFold, Terminal, fold_events};
