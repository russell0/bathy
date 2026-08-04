//! The engine handles this server holds, and the gate every packet passes.
//!
//! This mirrors the command-line surface deliberately. Both are thin
//! translators over the same engine, and where the two could diverge they are
//! written to the same shape so a reviewer can see that they have not.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use bathy_engine::{GroupCommitConfig, GroupCommitLog, RunSummary, Scheduler, SchedulerConfig};
use bathy_evidence::EvidenceStore;
use bathy_plan::ScanPlan;
use bathy_probe::ProbeRegistry;
use bathy_scope::{BudgetLedger, PolicyDecision, ScopeManifest, evaluate};
use bathy_store::TaskStore;
use bathy_types::clock::{Clock, SystemClock};
use bathy_types::ids::ScanId;
use bathy_types::request::ScanRequest;
use tokio_util::sync::CancellationToken;

use crate::error::{ToolFailure, ToolResult, manifest_error, unreadable_manifest};

/// The ceiling on target expansion, applied before any address is allocated
/// for. It is the same number the command-line surface applies: one `/16`.
/// A wider inventory is a decision an operator should make one range at a
/// time rather than discover by memory pressure.
pub const MAX_TARGETS: usize = 65_536;

/// Everything the engine needs, opened once against one state directory.
///
/// Held for the life of the server rather than reopened per call: the task
/// store and the evidence store are the state directory's own concurrency
/// control, and two of either would be two answers to one question.
pub struct Runtime {
    pub state_dir: PathBuf,
    pub store: Arc<TaskStore>,
    pub evidence: Arc<EvidenceStore>,
    pub probes: Arc<ProbeRegistry>,
    pub clock: Arc<dyn Clock>,
}

impl Runtime {
    pub fn open(state_dir: &Path) -> Result<Self, String> {
        // One clock, shared: the task store and every scheduler must be
        // handed the same one, because two clocks means two identifier
        // generators and identifiers that can collide.
        let clock: Arc<dyn Clock> = Arc::new(SystemClock::default());
        std::fs::create_dir_all(state_dir).map_err(|e| format!("state directory: {e}"))?;
        Ok(Self {
            state_dir: state_dir.to_path_buf(),
            store: Arc::new(
                TaskStore::open(state_dir, Arc::clone(&clock))
                    .map_err(|e| format!("task store: {e}"))?,
            ),
            evidence: Arc::new(
                EvidenceStore::open(state_dir).map_err(|e| format!("evidence store: {e}"))?,
            ),
            probes: Arc::new(ProbeRegistry::standard()),
            clock,
        })
    }

    pub fn now(&self) -> String {
        self.clock.now_rfc3339()
    }
}

/// Load a scope manifest document from disk.
///
/// A **path**, never a document: an inline manifest would let a caller author
/// its own authorization. This is the same function the command-line surface
/// performs for `--scope <PATH>`, and it is the only way a manifest enters
/// this process.
pub fn load_manifest(path: &str) -> ToolResult<Arc<ScopeManifest>> {
    let text = std::fs::read_to_string(path).map_err(|e| unreadable_manifest(path, e))?;
    let manifest = ScopeManifest::load(&text).map_err(|e| manifest_error(path, e))?;
    Ok(Arc::new(manifest))
}

/// Why a request was refused, in the shape the tool surface reports it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Denial {
    pub reason_code: &'static str,
    pub detail: String,
}

/// A scan request that has been evaluated against a real manifest and
/// approved, together with the plan the evaluation was performed over.
///
/// There is no other way to build one, and every function here that can emit
/// a packet takes one. That is the same fix the command-line surface applies
/// one layer up and the engine applies one layer down: make the unauthorized
/// state unconstructible rather than checked, because a path that forgets to
/// ask looks exactly like one that asked and was told yes.
pub struct AuthorizedScan {
    manifest: Arc<ScopeManifest>,
    request: ScanRequest,
    plan: ScanPlan,
}

/// What authorizing a request produced: an approval, a refusal, or a request
/// that could not be turned into a plan at all.
pub enum Authorization {
    Approved(Box<AuthorizedScan>),
    Denied {
        denial: Denial,
        /// The plan is still reported: it is a fact about the request, not
        /// about the decision, and an agent that was refused needs to know
        /// which plan was refused.
        plan: Box<ScanPlan>,
    },
}

impl AuthorizedScan {
    /// Expand `request` into a plan and evaluate it against `manifest`.
    ///
    /// The evaluation is over the fully expanded target list, not over the
    /// ranges the caller wrote, so a single unauthorized address buried in a
    /// large range refuses the whole scan.
    pub fn authorize(
        manifest: Arc<ScopeManifest>,
        request: ScanRequest,
        now_rfc3339: &str,
    ) -> ToolResult<Authorization> {
        let plan = ScanPlan::build(&request, MAX_TARGETS)
            .map_err(|e| ToolFailure::new("invalid_plan", e))?;
        match evaluate(&manifest, &request, plan.targets(), now_rfc3339) {
            PolicyDecision::Approved => Ok(Authorization::Approved(Box::new(Self {
                manifest,
                request,
                plan,
            }))),
            PolicyDecision::Denied { reason, detail } => Ok(Authorization::Denied {
                denial: Denial {
                    reason_code: reason.code(),
                    detail,
                },
                plan: Box::new(plan),
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

    pub fn estimated_targets(&self) -> u64 {
        self.plan.targets().len() as u64
    }

    pub fn estimated_probes(&self) -> u64 {
        self.plan.len()
    }
}

/// A lower bound on how long a plan takes: the probe count divided by the
/// packets-per-second ceiling, rounded up. Probe latency and connection
/// limits can only make a real run slower.
pub fn estimated_runtime_seconds(probes: u64, packets_per_second: u32) -> u64 {
    let pps = u64::from(packets_per_second).max(1);
    probes.div_ceil(pps)
}

/// The only place in this crate that builds a scheduler, and therefore the
/// only place a packet can originate.
///
/// Detached deliberately: the caller has already written the handle, and this
/// server stays alive to answer further calls while the scan runs. That is
/// what makes a start return in well under a second regardless of scan size.
pub fn spawn_scan(
    runtime: &Runtime,
    authorized: AuthorizedScan,
    scan_id: ScanId,
    from_index: u64,
    ledger: BudgetLedger,
) -> ToolResult<()> {
    let log = Arc::new(Mutex::new(
        GroupCommitLog::open(&runtime.state_dir, scan_id, GroupCommitConfig::default())
            .map_err(|e| ToolFailure::new("log_unavailable", e))?,
    ));

    let scheduler = Scheduler::new(
        ledger,
        Arc::clone(authorized.manifest()),
        SchedulerConfig::default(),
        log,
        Arc::clone(&runtime.store),
        Arc::clone(&runtime.clock),
        scan_id,
        env!("CARGO_PKG_VERSION"),
        authorized.request().service_detection,
        authorized.request().evidence_level,
        Arc::clone(&runtime.evidence),
        Arc::clone(&runtime.probes),
    );

    // A cancel may arrive through this server or through the command line, so
    // the marker protocol is what actually stops the run. Both surfaces read
    // and write it from the same place.
    let token = CancellationToken::new();
    let watcher = bathy_engine::cancel::spawn_watcher(&runtime.state_dir, scan_id, token.clone());

    tokio::spawn(async move {
        let summary = scheduler.run(authorized.plan(), from_index, token).await;
        watcher.abort();
        report(scan_id, summary);
    });
    Ok(())
}

/// A detached scan has nobody to return to, so its outcome goes to the
/// diagnostic channel. Standard error, not the logging capability: that
/// capability is deprecated in this protocol version, and standard output is
/// the transport.
fn report(scan_id: ScanId, summary: Result<RunSummary, bathy_engine::EngineError>) {
    match summary {
        Ok(s) => eprintln!(
            "bathy-mcp: {scan_id} finished: {} unit(s), {} open, {} packet(s){}",
            s.units_completed,
            s.open_ports,
            s.packets_spent,
            if s.cancelled {
                " (cancelled)"
            } else if s.budget_exhausted {
                " (packet budget exhausted)"
            } else if s.time_exhausted {
                " (runtime exhausted)"
            } else {
                ""
            }
        ),
        Err(e) => eprintln!("bathy-mcp: {scan_id} failed: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_runtime_estimate_rounds_up_rather_than_reporting_zero_seconds() {
        assert_eq!(estimated_runtime_seconds(1, 100), 1);
        assert_eq!(estimated_runtime_seconds(0, 100), 0);
        assert_eq!(estimated_runtime_seconds(201, 100), 3);
    }

    #[test]
    fn a_zero_rate_does_not_divide_by_zero() {
        // Budgets refuse zero at parse time, so this is unreachable from a
        // request; it is here because the arithmetic must not be the thing
        // that turns a future validation gap into a panic on the tool path.
        assert_eq!(estimated_runtime_seconds(5, 0), 5);
    }

    #[test]
    fn a_manifest_that_is_not_there_is_a_distinct_answer_from_one_that_is_malformed() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("nope.json");
        assert_eq!(
            load_manifest(missing.to_str().unwrap()).unwrap_err().error,
            "scope_unreadable"
        );

        let bad = dir.path().join("bad.json");
        std::fs::write(&bad, b"{ not json").unwrap();
        assert_eq!(
            load_manifest(bad.to_str().unwrap()).unwrap_err().error,
            "scope_invalid"
        );
    }
}
