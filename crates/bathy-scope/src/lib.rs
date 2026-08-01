#![forbid(unsafe_code)]

//! The scope manifest: the authorization boundary that decides whether a
//! packet may ever be sent to a given address. Nothing downstream of
//! [`manifest::ScopeManifest::allows`] should be trusted to make that call
//! itself -- every other crate that ends up putting a packet on the wire
//! goes through this gate first.

pub mod budget;
pub mod manifest;
pub mod policy;

pub use budget::{BudgetExhausted, BudgetLedger};
pub use manifest::{ManifestError, ScopeManifest};
pub use policy::{DenyReason, PolicyDecision, evaluate};
