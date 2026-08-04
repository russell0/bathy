//! The gate every packet in this crate passes through.
//!
//! # Why this is a type and not a function call
//!
//! `bathy_scope::evaluate` returning `Approved` is a *fact about a moment*.
//! Nothing about a `ScanRequest` records that the fact was ever established,
//! so a code path that forgets to ask, or asks and ignores the answer, looks
//! exactly like one that asked and was told yes. That is how M3's review
//! found a `Scheduler` that had been built with no scope awareness at all
//! since the crate's first task -- and the fix there was not another check,
//! it was making the unauthorized state unconstructible.
//!
//! [`AuthorizedScan`] is that fix at the CLI layer. Its fields are private
//! and its only constructor is [`AuthorizedScan::authorize`], which takes a
//! real loaded [`ScopeManifest`] and returns `Err` unless
//! `bathy_scope::evaluate` approves the request over the plan's **fully
//! expanded** target list. Every function in this crate that can emit a
//! packet takes an `&AuthorizedScan`, so there is no spelling of "scan
//! without a manifest" for a caller to reach.
//!
//! The engine still re-checks scope identity, expiry and each individual
//! target immediately before dispatch. That is the backstop and it stays.
//! What this type adds is that the CLI can no longer *reach* the backstop
//! with an unevaluated request and be refused there -- which would satisfy
//! "no packet is emitted" while failing AC-5.8's actual requirement that the
//! refusal happen before any network activity at all.

use std::sync::Arc;

use bathy_plan::ScanPlan;
use bathy_scope::{PolicyDecision, ScopeManifest, evaluate};
use bathy_types::request::ScanRequest;

use crate::exit::CliError;

/// The CLI's own ceiling on target expansion, applied before any address is
/// allocated for (`bathy_plan::expand_targets` pre-counts). 65,536 is one
/// `/16`; a wider inventory is a decision an operator should make one range
/// at a time rather than discover by memory pressure.
pub const MAX_TARGETS: usize = 65_536;

/// A scan request that has been evaluated against a real manifest and
/// approved, together with the plan that evaluation was performed over.
///
/// There is no other way to build one. See this module's doc comment.
pub struct AuthorizedScan {
    manifest: Arc<ScopeManifest>,
    request: ScanRequest,
    plan: ScanPlan,
}

impl AuthorizedScan {
    /// Expand `request` into a plan and evaluate it against `manifest` at
    /// `now_rfc3339`.
    ///
    /// The evaluation is over `plan.targets()` -- the fully expanded list --
    /// not over the raw CIDR strings the caller typed, so a single
    /// unauthorized address buried in a large range refuses the whole scan
    /// (`bathy_scope::evaluate` offers no partial approval, deliberately).
    pub fn authorize(
        manifest: Arc<ScopeManifest>,
        request: ScanRequest,
        now_rfc3339: &str,
    ) -> Result<Self, CliError> {
        let plan = ScanPlan::build(&request, MAX_TARGETS)
            .map_err(|e| CliError::operational("invalid_plan", e))?;
        match evaluate(&manifest, &request, plan.targets(), now_rfc3339) {
            PolicyDecision::Approved => Ok(Self {
                manifest,
                request,
                plan,
            }),
            PolicyDecision::Denied { reason, detail } => Err(CliError::Denied {
                reason_code: reason.code(),
                detail,
            }),
        }
    }

    pub fn manifest(&self) -> &Arc<ScopeManifest> {
        &self.manifest
    }

    pub fn request(&self) -> &ScanRequest {
        &self.request
    }

    pub fn plan(&self) -> &ScanPlan {
        &self.plan
    }

    /// What `scan preview` reports, and the same fields `scan start` echoes
    /// back in its `TaskHandle`.
    pub fn estimated_targets(&self) -> u64 {
        self.plan.targets().len() as u64
    }

    pub fn estimated_probes(&self) -> u64 {
        self.plan.len()
    }
}
