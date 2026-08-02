#![forbid(unsafe_code)]

//! `bathy-plan`: turning a scan request into the concrete units a plan is
//! made of. This first slice covers target expansion only -- see
//! [`targets::expand_targets`].
//!
//! Target expansion is a different question from scope authorization
//! (`bathy_scope::ScopeManifest::allows`, in the crate one layer below this
//! one in `xtask`'s `LAYERS`). Expansion decides which addresses are *worth
//! probing*; scope decides which addresses are *authorized*. The two
//! questions do not have the same answer in general -- see the `targets`
//! module doc for the specific case (network/broadcast addresses) where
//! they diverge -- and nothing in this crate consults scope, or should be
//! read as assuming scope agrees with it.

pub mod targets;

pub use targets::{TargetError, expand_targets};
