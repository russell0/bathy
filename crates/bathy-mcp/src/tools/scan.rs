//! `scan.preview`, `scan.start`, `scan.status`, `scan.events`, `scan.cancel`
//! and `scan.resume`.

use bathy_evidence::EventLogReader;
use bathy_scope::BudgetLedger;
use bathy_store::{StartOutcome, StartRequest, TaskStore};
use bathy_types::ids::ScanId;
use bathy_types::request::ScanRequest;
use bathy_types::task::{PolicyDecisionTag, TaskHandle, TaskStatus};
use bathy_types::tools::{
    ScanCancelInput, ScanCancelOutput, ScanEventsInput, ScanEventsOutput, ScanPreviewInput,
    ScanPreviewOutput, ScanResumeInput, ScanResumeOutput, ScanStartInput, ScanStartOutput,
    ScanStatusInput, ScanStatusOutput,
};

use bathy_plan::estimated_runtime_seconds;

use crate::engine::{Authorization, AuthorizedScan, Denial, Runtime, load_manifest, spawn_scan};
use crate::error::{ToolFailure, ToolResult, log_error, no_such_log, no_such_scan, store_error};

// ---------------------------------------------------------------------------
// scan.preview
// ---------------------------------------------------------------------------

/// Nothing on this path opens a socket: it loads a document, expands a plan
/// and evaluates a policy. The emission path is not reachable from here.
///
/// It takes the time rather than a [`Runtime`] because it needs nothing else
/// from one, and opening a `Runtime` creates the state directory -- which a
/// preview, whose whole promise is that it changes nothing, must not do.
pub fn preview(input: ScanPreviewInput, now_rfc3339: &str) -> ToolResult<ScanPreviewOutput> {
    let manifest = load_manifest(&input.manifest_path)?;
    let scope_id = manifest.id();
    let request = input
        .request
        .into_request(scope_id, manifest.ceiling())
        .map_err(|e| ToolFailure::new(e.code, e.detail))?;
    let packets_per_second = request.budgets.maximum_packets_per_second;

    match AuthorizedScan::authorize(manifest, request, now_rfc3339)? {
        Authorization::Approved(scan) => Ok(ScanPreviewOutput {
            policy_decision: PolicyDecisionTag::Approved,
            plan_hash: Some(scan.plan().hash()),
            estimated_targets: Some(scan.estimated_targets()),
            estimated_probes: Some(scan.estimated_probes()),
            estimated_runtime_seconds: Some(estimated_runtime_seconds(
                scan.estimated_probes(),
                packets_per_second,
            )),
            scope_id: Some(scope_id),
            reason_code: None,
            detail: None,
        }),
        // Deliberately shaped like the command-line surface's refusal: the
        // decision and the reason, and none of the plan detail. An operator
        // reproducing an agent's refusal from a shell must get the same
        // document, and the two would otherwise differ on exactly the path
        // nobody re-checks.
        Authorization::Denied { denial, .. } => Ok(denied_preview(denial)),
    }
}

fn denied_preview(denial: Denial) -> ScanPreviewOutput {
    ScanPreviewOutput {
        policy_decision: PolicyDecisionTag::Denied,
        plan_hash: None,
        estimated_targets: None,
        estimated_probes: None,
        estimated_runtime_seconds: None,
        scope_id: None,
        reason_code: Some(denial.reason_code.to_string()),
        detail: Some(denial.detail),
    }
}

// ---------------------------------------------------------------------------
// scan.start
// ---------------------------------------------------------------------------

/// What authorizing a start produced, before the approval gate is consulted.
///
/// Separated from [`start`] so the gate can be applied between "this scan is
/// authorized by the manifest" and "this scan has begun" without either step
/// being able to skip the other.
pub enum StartAdmission {
    /// The manifest refused. No scan record exists and no packet was sent.
    Denied(Box<ScanStartOutput>),
    /// The manifest approved. Nothing has been started yet.
    Authorized(Box<AuthorizedScan>),
}

/// Decide whether a manifest authorizes this request. Opens nothing and
/// creates nothing -- it takes the time rather than a [`Runtime`] so that a
/// caller can refuse a scan before the state directory exists, which is what
/// makes "a denied scan leaves no trace" true rather than tidy.
pub fn admit(input: &ScanStartInput, now_rfc3339: &str) -> ToolResult<StartAdmission> {
    let manifest = load_manifest(&input.manifest_path)?;
    let request = input
        .request
        .clone()
        .into_request(manifest.id(), manifest.ceiling())
        .map_err(|e| ToolFailure::new(e.code, e.detail))?;

    match AuthorizedScan::authorize(manifest, request, now_rfc3339)? {
        Authorization::Approved(scan) => Ok(StartAdmission::Authorized(scan)),
        Authorization::Denied { denial, .. } => {
            Ok(StartAdmission::Denied(Box::new(ScanStartOutput {
                policy_decision: PolicyDecisionTag::Denied,
                handle: None,
                reason_code: Some(denial.reason_code.to_string()),
                detail: Some(denial.detail),
                reused: false,
            })))
        }
    }
}

/// Work an admission left for the caller to run.
///
/// Present exactly when this call created the scan. A reused key produces
/// `None`, which is the whole of the idempotency guarantee: the second caller
/// gets the first scan's handle and starts nothing.
pub struct Work {
    pub scan_id: ScanId,
    /// The plan index to start from. Zero for a start; the stored cursor for
    /// a resume.
    pub from_index: u64,
    pub ledger: BudgetLedger,
}

/// What admitting a scan into the store produced.
pub struct Admission {
    /// The document both surfaces publish for this outcome.
    pub output: ScanStartOutput,
    pub work: Option<Work>,
}

/// Admit the scan into the store, and say what work that left.
///
/// Split out of [`begin`] because the two interfaces run the work
/// differently and must not answer differently: the tool surface detaches a
/// scheduler and returns, and the command surface runs to completion in the
/// caller's own process (AC-5.12). Everything up to that point -- the
/// idempotency decision, the status write, the stale-marker clear, and the
/// document that reports all three -- is one implementation, so the two
/// surfaces cannot drift on it.
///
/// Called only with an [`AuthorizedScan`], so the manifest check cannot be
/// skipped by reaching this function directly; the approval gate is applied
/// by `scan.start`'s caller, between authorization and here.
pub fn admit_into_store(authorized: &AuthorizedScan, runtime: &Runtime) -> ToolResult<Admission> {
    let request_json = serde_json::to_string(authorized.request())
        .map_err(|e| ToolFailure::new("request_unserializable", e))?;

    let outcome = runtime
        .store
        .start_or_reuse(&StartRequest {
            idempotency_key: authorized.request().idempotency_key.clone(),
            plan_hash: authorized.plan().hash(),
            scope_id: authorized.request().authorization_scope_id,
            request_json,
            estimated_targets: authorized.estimated_targets(),
            estimated_probes: authorized.estimated_probes(),
        })
        .map_err(store_error)?;

    let (scan_id, status, fresh) = match outcome {
        StartOutcome::Started { scan_id } => (scan_id, TaskStatus::Running, true),
        StartOutcome::Reused { scan_id, status } => (scan_id, status, false),
    };

    if fresh {
        runtime
            .store
            .set_status(scan_id, TaskStatus::Running)
            .map_err(store_error)?;
    }

    let handle = TaskHandle {
        task_id: scan_id,
        plan_hash: authorized.plan().hash(),
        policy_decision: PolicyDecisionTag::Approved,
        estimated_targets: authorized.estimated_targets(),
        status,
    };

    let work = fresh.then(|| {
        // Before any work begins, so a marker written for an earlier run of
        // this scan cannot cancel this one on the watcher's first look.
        bathy_engine::cancel::clear(&runtime.state_dir, scan_id);
        Work {
            scan_id,
            from_index: 0,
            ledger: BudgetLedger::new(authorized.request().budgets),
        }
    });

    Ok(Admission {
        output: ScanStartOutput {
            policy_decision: PolicyDecisionTag::Approved,
            handle: Some(handle),
            reason_code: None,
            detail: None,
            reused: !fresh,
        },
        work,
    })
}

/// Admit the scan into the store and begin it, detached.
pub fn begin(authorized: AuthorizedScan, runtime: &Runtime) -> ToolResult<ScanStartOutput> {
    let admission = admit_into_store(&authorized, runtime)?;
    if let Some(work) = admission.work {
        spawn_scan(
            runtime,
            authorized,
            work.scan_id,
            work.from_index,
            work.ledger,
        )?;
    }
    Ok(admission.output)
}

// ---------------------------------------------------------------------------
// scan.status
// ---------------------------------------------------------------------------

pub fn status(input: ScanStatusInput, runtime: &Runtime) -> ToolResult<ScanStatusOutput> {
    let record = record_for(&runtime.store, input.scan_id)?;
    let units_completed = runtime
        .store
        .completed_units(input.scan_id)
        .map_err(store_error)?
        .len() as u64;

    Ok(ScanStatusOutput {
        scan_id: record.scan_id,
        status: record.status,
        estimated_targets: record.estimated_targets,
        units_completed,
        units_total: record.estimated_probes,
        packets_spent: record.packets_spent,
        elapsed_seconds: record.elapsed_seconds,
        last_sequence: record.last_sequence,
        plan_hash: record.plan_hash,
        scope_id: record.scope_id,
        idempotency_key: record.idempotency_key,
        created_at: record.created_at,
        updated_at: record.updated_at,
    })
}

fn record_for(store: &TaskStore, scan_id: ScanId) -> ToolResult<bathy_store::TaskRecord> {
    store
        .get(scan_id)
        .map_err(store_error)?
        .ok_or_else(|| no_such_scan(scan_id))
}

// ---------------------------------------------------------------------------
// scan.events
// ---------------------------------------------------------------------------

pub fn events(input: ScanEventsInput, runtime: &Runtime) -> ToolResult<ScanEventsOutput> {
    if input.limit == 0 || input.limit > 1000 {
        return Err(ToolFailure::new(
            "bad_limit",
            format!("limit must be 1-1000, got {}", input.limit),
        ));
    }
    // The reader takes no writer lock, so a scan that is still running can be
    // followed while it writes.
    let reader = EventLogReader::open(&runtime.state_dir, input.scan_id).map_err(no_such_log)?;
    let available = reader.read_from(input.after_sequence).map_err(log_error)?;

    let limit = input.limit as usize;
    let has_more = available.len() > limit;
    let events: Vec<_> = available.into_iter().take(limit).collect();
    // An empty page leaves the cursor where the caller put it, so polling a
    // scan that has written nothing new does not rewind it.
    let next_cursor = events
        .last()
        .map(|e| e.sequence)
        .unwrap_or(input.after_sequence);

    Ok(ScanEventsOutput {
        events,
        next_cursor,
        has_more,
    })
}

// ---------------------------------------------------------------------------
// scan.cancel
// ---------------------------------------------------------------------------

pub fn cancel(input: ScanCancelInput, runtime: &Runtime) -> ToolResult<ScanCancelOutput> {
    // The scan must exist. A marker written for an identifier that was never
    // started would sit in the state directory forever, waiting to cancel
    // something that has not happened yet.
    let record = record_for(&runtime.store, input.scan_id)?;
    let units_completed = runtime
        .store
        .completed_units(input.scan_id)
        .map_err(store_error)?
        .len() as u64;
    let resumable = runtime
        .store
        .next_pending_unit(input.scan_id, record.estimated_probes)
        .map_err(store_error)?
        .is_some();

    bathy_engine::cancel::request(&runtime.state_dir, input.scan_id)
        .map_err(|e| ToolFailure::new("state_dir_unwritable", e))?;

    Ok(ScanCancelOutput {
        scan_id: input.scan_id,
        status: record.status,
        units_completed,
        resumable,
        cancellation_requested: true,
    })
}

// ---------------------------------------------------------------------------
// scan.resume
// ---------------------------------------------------------------------------

/// What preparing a resume produced: the document, and the work it left.
pub struct Resumption {
    pub output: ScanResumeOutput,
    /// `None` when the scan had no unfinished units, which is the "already
    /// complete" answer both surfaces return.
    pub work: Option<(Box<AuthorizedScan>, Work)>,
}

/// Re-authorize a stopped scan and work out where it restarts.
///
/// Split from [`resume`] for the reason [`admit_into_store`] is split from
/// [`begin`]: the re-authorization, the plan check, the cursor, the
/// stale-marker clear and the document are one implementation, and only the
/// running of the work differs between the two surfaces.
pub fn prepare_resume(input: &ScanResumeInput, runtime: &Runtime) -> ToolResult<Resumption> {
    let manifest = load_manifest(&input.manifest_path)?;
    let record = record_for(&runtime.store, input.scan_id)?;
    let request: ScanRequest = serde_json::from_str(&record.request_json)
        .map_err(|e| ToolFailure::new("stored_request_unreadable", e))?;

    // Re-authorized, not trusted: the manifest may have expired, been
    // narrowed, or been swapped since this scan was admitted. A resume is new
    // network activity and gets a new decision.
    let authorized = match AuthorizedScan::authorize(manifest, request, &runtime.now())? {
        Authorization::Approved(scan) => scan,
        Authorization::Denied { denial, .. } => {
            return Err(ToolFailure::new(denial.reason_code, denial.detail));
        }
    };

    if authorized.plan().hash() != record.plan_hash {
        return Err(ToolFailure::new(
            "plan_mismatch",
            format!(
                "scan {} was started against plan {} but this scope and request produce {}",
                input.scan_id,
                record.plan_hash,
                authorized.plan().hash()
            ),
        ));
    }

    let total = authorized.plan().len();
    let Some(from_index) = runtime
        .store
        .next_pending_unit(input.scan_id, total)
        .map_err(store_error)?
    else {
        return Ok(Resumption {
            output: ScanResumeOutput {
                scan_id: input.scan_id,
                status: record.status,
                resumed_from_unit: total,
                units_total: total,
                resumed: false,
            },
            work: None,
        });
    };

    // Before any work begins; see `admit_into_store`.
    bathy_engine::cancel::clear(&runtime.state_dir, input.scan_id);
    runtime
        .store
        .set_status(input.scan_id, TaskStatus::Running)
        .map_err(store_error)?;

    // Seeded from the prior run's counters rather than reset: a resumed scan
    // that got a fresh, unspent budget could exceed the ceiling an operator
    // wrote down by cancelling and resuming.
    let ledger = BudgetLedger::resumed(
        authorized.request().budgets,
        record.packets_spent,
        record.elapsed_seconds,
    );

    Ok(Resumption {
        output: ScanResumeOutput {
            scan_id: input.scan_id,
            status: TaskStatus::Running,
            resumed_from_unit: from_index,
            units_total: total,
            resumed: true,
        },
        work: Some((
            authorized,
            Work {
                scan_id: input.scan_id,
                from_index,
                ledger,
            },
        )),
    })
}

/// Re-authorize a stopped scan and continue it, detached.
pub fn resume(input: ScanResumeInput, runtime: &Runtime) -> ToolResult<ScanResumeOutput> {
    let resumption = prepare_resume(&input, runtime)?;
    if let Some((authorized, work)) = resumption.work {
        spawn_scan(
            runtime,
            *authorized,
            work.scan_id,
            work.from_index,
            work.ledger,
        )?;
    }
    Ok(resumption.output)
}
