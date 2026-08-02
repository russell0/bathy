#![forbid(unsafe_code)]

//! `bathy-plan`: turning a scan request into the concrete units a plan is
//! made of. So far that covers target expansion (see
//! [`targets::expand_targets`]) and port selection (see
//! [`ports::resolve_ports`]).
//!
//! Target expansion is a different question from scope authorization
//! (`bathy_scope::ScopeManifest::allows`, in the crate one layer below this
//! one in `xtask`'s `LAYERS`). Expansion decides which addresses are *worth
//! probing*; scope decides which addresses are *authorized*. The two
//! questions do not have the same answer in general -- see the `targets`
//! module doc for the specific case (network/broadcast addresses) where
//! they diverge -- and nothing in this crate consults scope, or should be
//! read as assuming scope agrees with it.

pub mod ports;
pub mod targets;

pub use ports::{PortError, resolve_ports};
pub use targets::{TargetError, expand_targets};
