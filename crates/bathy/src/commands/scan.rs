//! `bathy scan preview|start|status|events|cancel|resume`.
//!
//! The emission path in this crate is [`run_to_completion`], and it takes an
//! [`AuthorizedScan`] -- see `crate::authorize` for why that is a type and
//! not a check.

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bathy_engine::{GroupCommitConfig, GroupCommitLog, RunSummary, Scheduler, SchedulerConfig};
use bathy_evidence::{EventLogReader, EvidenceStore};
use bathy_probe::ProbeRegistry;
use bathy_scope::{BudgetLedger, ScopeManifest};
use bathy_store::{StartOutcome, StartRequest, StoreError, TaskStore};
use bathy_types::clock::Clock;
use bathy_types::event::{Event, EventBody};
use bathy_types::ids::ScanId;
use bathy_types::nonempty::NonEmpty;
use bathy_types::request::{Budgets, PortSelection, ScanRequest, ServiceDetection};
use bathy_types::task::{PolicyDecisionTag, TaskHandle, TaskStatus};
use tokio_util::sync::CancellationToken;

use crate::authorize::AuthorizedScan;
use crate::cli::{EventsArgs, PreviewArgs, RequestArgs, ResumeArgs, StartArgs};
use crate::commands::scope::load_manifest;
use crate::emit::Emitter;
use crate::exit::{CliError, ExitCode};
use crate::state;

/// `idempotency_key` is excluded from `plan_hash` by `ScanPlan::build`, so
/// the constant a preview uses cannot change the hash it reports. It is
/// spelled out rather than left as `""` so that a stray preview request
/// serialized into a log is identifiable.
const PREVIEW_KEY: &str = "preview-not-an-attempt";

/// Turn the request-shaping flags into a real [`ScanRequest`].
///
/// Budgets left unspecified default to the manifest's own ceiling. That is
/// not "unbounded": the ceiling is a hard limit an operator already wrote
/// down, `bathy_scope::evaluate` refuses anything above it, and the
/// alternative -- a built-in default -- would be a number this program
/// invented for someone else's network.
fn build_request(
    args: &RequestArgs,
    manifest: &ScopeManifest,
    idempotency_key: String,
) -> Result<ScanRequest, CliError> {
    let ceiling = manifest.ceiling();
    let targets = NonEmpty::try_from(args.targets.clone())
        .map_err(|e| CliError::operational("no_targets", e))?;
    let ports = match (&args.port_preset, args.ports.is_empty()) {
        (Some(preset), _) => PortSelection::Preset {
            preset: (*preset).into(),
        },
        (None, false) => PortSelection::Explicit {
            explicit: NonEmpty::try_from(args.ports.clone())
                .map_err(|e| CliError::operational("no_ports", e))?,
        },
        (None, true) => {
            return Err(CliError::operational(
                "no_ports",
                "one of --ports or --port-preset is required",
            ));
        }
    };
    if args.intensity > 9 {
        return Err(CliError::operational(
            "bad_intensity",
            format!("--intensity must be 0-9, got {}", args.intensity),
        ));
    }
    let budgets = Budgets {
        maximum_packets: args.max_packets.unwrap_or(ceiling.maximum_packets),
        maximum_runtime_seconds: args
            .max_runtime_seconds
            .unwrap_or(ceiling.maximum_runtime_seconds),
        maximum_packets_per_second: args
            .max_packets_per_second
            .unwrap_or(ceiling.maximum_packets_per_second),
    };
    if budgets.maximum_packets == 0
        || budgets.maximum_runtime_seconds == 0
        || budgets.maximum_packets_per_second == 0
    {
        return Err(CliError::operational(
            "bad_budget",
            "every budget must be greater than zero",
        ));
    }
    Ok(ScanRequest {
        targets,
        authorization_scope_id: manifest.id(),
        objective: args.objective.into(),
        ports,
        service_detection: ServiceDetection {
            enabled: !args.no_service_detection,
            intensity: args.intensity,
        },
        budgets,
        evidence_level: args.evidence_level.into(),
        idempotency_key,
    })
}

fn preview_document(authorized: &AuthorizedScan) -> serde_json::Value {
    serde_json::json!({
        "plan_hash": authorized.plan().hash().to_string(),
        "estimated_targets": authorized.estimated_targets(),
        "estimated_probes": authorized.estimated_probes(),
        "policy_decision": "approved",
        "scope_id": authorized.request().authorization_scope_id.to_string(),
    })
}

/// AC-5.9. Nothing on this path opens a socket: it loads a document,
/// expands a plan and evaluates a policy, and the emission path is not
/// reachable from here at all.
pub fn preview(
    args: &PreviewArgs,
    clock: &dyn Clock,
    emitter: &Emitter,
) -> Result<ExitCode, CliError> {
    let manifest = load_manifest(&args.scope)?;
    let request = build_request(&args.request, &manifest, PREVIEW_KEY.to_string())?;
    let authorized = AuthorizedScan::authorize(manifest, request, &clock.now_rfc3339())?;
    let doc = preview_document(&authorized);
    let human = format!(
        "approved  plan {}\n  {} target(s), {} probe(s)",
        authorized.plan().hash(),
        authorized.estimated_targets(),
        authorized.estimated_probes()
    );
    emitter.result(doc, human);
    Ok(ExitCode::Success)
}

fn handle_document(handle: &TaskHandle) -> serde_json::Value {
    serde_json::to_value(handle).expect("TaskHandle always serializes")
}

fn summary_document(summary: &RunSummary) -> serde_json::Value {
    serde_json::json!({
        "units_completed": summary.units_completed,
        "packets_spent": summary.packets_spent,
        "open_ports": summary.open_ports,
        "cancelled": summary.cancelled,
        "budget_exhausted": summary.budget_exhausted,
        "time_exhausted": summary.time_exhausted,
        "policy_denied": summary.policy_denied,
        "local_resource_failures": summary.local_resource_failures,
    })
}

fn exit_for(summary: &RunSummary) -> ExitCode {
    if summary.policy_denied {
        ExitCode::PolicyDenied
    } else if summary.budget_exhausted || summary.time_exhausted {
        ExitCode::Exhausted
    } else {
        ExitCode::Success
    }
}

/// Everything the engine needs, opened once against one state directory.
struct Runtime {
    store: Arc<TaskStore>,
    evidence: Arc<EvidenceStore>,
    probes: Arc<ProbeRegistry>,
    clock: Arc<dyn Clock>,
}

impl Runtime {
    fn open(state_dir: &Path, clock: Arc<dyn Clock>) -> Result<Self, CliError> {
        std::fs::create_dir_all(state_dir)
            .map_err(|e| CliError::operational("state_dir_unwritable", e))?;
        let store = Arc::new(
            TaskStore::open(state_dir, Arc::clone(&clock))
                .map_err(|e| CliError::operational("store_unavailable", e))?,
        );
        let evidence = Arc::new(
            EvidenceStore::open(state_dir)
                .map_err(|e| CliError::operational("evidence_unavailable", e))?,
        );
        Ok(Self {
            store,
            evidence,
            probes: Arc::new(ProbeRegistry::standard()),
            clock,
        })
    }
}

/// The only place in this crate that builds a [`Scheduler`], and therefore
/// the only place a packet can originate. It takes an [`AuthorizedScan`]
/// because that is the only type in this crate that can prove a manifest
/// approved this request.
#[allow(clippy::too_many_arguments)]
async fn run_to_completion(
    authorized: &AuthorizedScan,
    runtime: &Runtime,
    state_dir: &Path,
    scan_id: ScanId,
    from_index: u64,
    ledger: BudgetLedger,
    emitter: &Emitter,
) -> Result<ExitCode, CliError> {
    let log = Arc::new(Mutex::new(
        GroupCommitLog::open(state_dir, scan_id, GroupCommitConfig::default())
            .map_err(|e| CliError::operational("log_unavailable", e))?,
    ));

    let scheduler = Scheduler::new(
        ledger,
        Arc::clone(authorized.manifest()),
        SchedulerConfig::default(),
        Arc::clone(&log),
        Arc::clone(&runtime.store),
        Arc::clone(&runtime.clock),
        scan_id,
        env!("CARGO_PKG_VERSION"),
        authorized.request().service_detection,
        authorized.request().evidence_level,
        Arc::clone(&runtime.evidence),
        Arc::clone(&runtime.probes),
    );

    // `scan cancel` runs in a different process and cannot reach this
    // token, so it leaves a marker in the state directory and this task
    // turns the marker into a real cancellation. Aborted below so the
    // poller cannot outlive the scan it was watching.
    let token = CancellationToken::new();
    let watcher = {
        let token = token.clone();
        let dir = state_dir.to_path_buf();
        tokio::spawn(async move {
            loop {
                if state::cancel_requested(&dir, scan_id) {
                    token.cancel();
                    return;
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        })
    };

    let summary = scheduler.run(authorized.plan(), from_index, token).await;
    watcher.abort();
    let summary = summary.map_err(|e| CliError::operational("scan_failed", e))?;

    let exit = exit_for(&summary);
    let human = format!(
        "{} unit(s) probed, {} open, {} packet(s) spent{}",
        summary.units_completed,
        summary.open_ports,
        summary.packets_spent,
        if summary.cancelled {
            " (cancelled)"
        } else if summary.budget_exhausted {
            " (packet budget exhausted)"
        } else if summary.time_exhausted {
            " (runtime exhausted)"
        } else {
            ""
        }
    );
    emitter.result(summary_document(&summary), human);
    Ok(exit)
}

pub async fn start(
    args: &StartArgs,
    state_dir: &Path,
    emitter: &Emitter,
) -> Result<ExitCode, CliError> {
    let clock = state::clock();
    let manifest = load_manifest(&args.scope)?;
    let request = build_request(&args.request, &manifest, args.idempotency_key.clone())?;
    // Authorization happens before the state directory is even opened: a
    // denied scan must leave no trace, not a `pending` row someone later
    // mistakes for work that was attempted.
    let authorized = AuthorizedScan::authorize(manifest, request, &clock.now_rfc3339())?;

    let runtime = Runtime::open(state_dir, Arc::clone(&clock))?;
    let request_json = serde_json::to_string(authorized.request())
        .map_err(|e| CliError::operational("request_unserializable", e))?;

    let outcome = runtime
        .store
        .start_or_reuse(&StartRequest {
            idempotency_key: args.idempotency_key.clone(),
            plan_hash: authorized.plan().hash(),
            scope_id: authorized.request().authorization_scope_id,
            request_json,
            estimated_targets: authorized.estimated_targets(),
            estimated_probes: authorized.estimated_probes(),
        })
        .map_err(map_store_error)?;

    let (scan_id, status, fresh) = match outcome {
        StartOutcome::Started { scan_id } => (scan_id, TaskStatus::Running, true),
        StartOutcome::Reused { scan_id, status } => (scan_id, status, false),
    };

    // `running` is a real state, not a label on the handle. Before this
    // task nothing in the workspace ever wrote it, and a `TaskHandle` that
    // said `running` while `scan status` said `pending` would be two
    // answers to one question. Written before the handle is printed, so a
    // second process that reads the handle and immediately asks for status
    // cannot see the earlier value.
    if fresh {
        runtime
            .store
            .set_status(scan_id, TaskStatus::Running)
            .map_err(|e| CliError::operational("store_unavailable", e))?;
    }

    let handle = TaskHandle {
        task_id: scan_id,
        plan_hash: authorized.plan().hash(),
        policy_decision: PolicyDecisionTag::Approved,
        estimated_targets: authorized.estimated_targets(),
        status,
    };
    // AC-5.12: printed and flushed *before* the scheduler is built, so the
    // handle is on the pipe regardless of how long the scan then takes.
    emitter.result(
        handle_document(&handle),
        format!(
            "{scan_id}  {}  plan {}",
            status_word(status),
            handle.plan_hash
        ),
    );

    if !fresh {
        emitter.note(format!(
            "idempotency key `{}` already names scan {scan_id} ({}); \
             nothing was started. Use `bathy scan resume` to continue it.",
            args.idempotency_key,
            status_word(status)
        ));
        return Ok(ExitCode::Success);
    }

    state::clear_cancel(state_dir, scan_id);
    let ledger = BudgetLedger::new(authorized.request().budgets);
    run_to_completion(
        &authorized,
        &runtime,
        state_dir,
        scan_id,
        0,
        ledger,
        emitter,
    )
    .await
}

pub async fn resume(
    args: &ResumeArgs,
    state_dir: &Path,
    emitter: &Emitter,
) -> Result<ExitCode, CliError> {
    let clock = state::clock();
    let scan_id = state::parse_scan_id(&args.scan)?;
    let manifest = load_manifest(&args.scope)?;
    let runtime = Runtime::open(state_dir, Arc::clone(&clock))?;

    let record = runtime
        .store
        .get(scan_id)
        .map_err(|e| CliError::operational("store_unavailable", e))?
        .ok_or_else(|| CliError::operational("no_such_scan", format!("no scan {scan_id}")))?;

    let request: ScanRequest = serde_json::from_str(&record.request_json)
        .map_err(|e| CliError::operational("stored_request_unreadable", e))?;

    // Re-authorized, not trusted: the manifest may have expired, been
    // narrowed, or been swapped for a different one since this scan was
    // admitted. A resume is new network activity and gets a new decision.
    let authorized = AuthorizedScan::authorize(manifest, request, &clock.now_rfc3339())?;

    if authorized.plan().hash() != record.plan_hash {
        return Err(CliError::operational(
            "plan_mismatch",
            format!(
                "scan {scan_id} was started against plan {} but this scope and request \
                 produce {}",
                record.plan_hash,
                authorized.plan().hash()
            ),
        ));
    }

    let total = authorized.plan().len();
    let from_index = runtime
        .store
        .next_pending_unit(scan_id, total)
        .map_err(|e| CliError::operational("store_unavailable", e))?;
    let Some(from_index) = from_index else {
        emitter.note(format!("scan {scan_id} has no unfinished units"));
        emitter.result(
            serde_json::json!({ "scan_id": scan_id.to_string(), "resumed": false }),
            format!("{scan_id} is already complete"),
        );
        return Ok(ExitCode::Success);
    };

    state::clear_cancel(state_dir, scan_id);
    runtime
        .store
        .set_status(scan_id, TaskStatus::Running)
        .map_err(|e| CliError::operational("store_unavailable", e))?;
    let ledger = BudgetLedger::resumed(
        authorized.request().budgets,
        record.packets_spent,
        record.elapsed_seconds,
    );
    emitter.note(format!(
        "resuming {scan_id} at unit {from_index} of {total}"
    ));
    run_to_completion(
        &authorized,
        &runtime,
        state_dir,
        scan_id,
        from_index,
        ledger,
        emitter,
    )
    .await
}

pub fn status(scan: &str, state_dir: &Path, emitter: &Emitter) -> Result<ExitCode, CliError> {
    let scan_id = state::parse_scan_id(scan)?;
    let runtime = Runtime::open(state_dir, state::clock())?;
    let record = runtime
        .store
        .get(scan_id)
        .map_err(|e| CliError::operational("store_unavailable", e))?
        .ok_or_else(|| CliError::operational("no_such_scan", format!("no scan {scan_id}")))?;

    let doc = serde_json::json!({
        "scan_id": record.scan_id.to_string(),
        "status": status_word(record.status),
        "plan_hash": record.plan_hash.to_string(),
        "scope_id": record.scope_id.to_string(),
        "idempotency_key": record.idempotency_key,
        "estimated_targets": record.estimated_targets,
        "estimated_probes": record.estimated_probes,
        "packets_spent": record.packets_spent,
        "elapsed_seconds": record.elapsed_seconds,
        "last_sequence": record.last_sequence,
        "created_at": record.created_at,
        "updated_at": record.updated_at,
    });
    let human = format!(
        "{}  {}  {}/{} probe(s), {} packet(s), {}s",
        record.scan_id,
        status_word(record.status),
        record.last_sequence,
        record.estimated_probes,
        record.packets_spent,
        record.elapsed_seconds
    );
    emitter.result(doc, human);
    Ok(ExitCode::Success)
}

pub fn cancel(scan: &str, state_dir: &Path, emitter: &Emitter) -> Result<ExitCode, CliError> {
    let scan_id = state::parse_scan_id(scan)?;
    // The scan must exist. Writing a marker for a scan id that was never
    // started would sit in the state directory forever waiting to cancel
    // something that has not happened yet.
    let runtime = Runtime::open(state_dir, state::clock())?;
    runtime
        .store
        .get(scan_id)
        .map_err(|e| CliError::operational("store_unavailable", e))?
        .ok_or_else(|| CliError::operational("no_such_scan", format!("no scan {scan_id}")))?;

    state::request_cancel(state_dir, scan_id)?;
    emitter.result(
        serde_json::json!({ "scan_id": scan_id.to_string(), "cancellation_requested": true }),
        format!("{scan_id}: cancellation requested; in-flight probes will be drained"),
    );
    Ok(ExitCode::Success)
}

fn is_terminal(event: &Event) -> bool {
    matches!(
        &event.body,
        EventBody::ScanCompleted { .. }
            | EventBody::ScanFailed { .. }
            | EventBody::PolicyDenied { .. }
    )
}

pub fn events(
    args: &EventsArgs,
    state_dir: &Path,
    emitter: &Emitter,
) -> Result<ExitCode, CliError> {
    let scan_id = state::parse_scan_id(&args.scan)?;
    let mut cursor = args.after;
    // A follower's only stopping condition used to be a terminal event, and
    // a scan whose process was killed never writes one -- so `--follow`
    // polled forever against a log nothing would ever append to. An agent
    // that shelled out has no interrupt to send, so it hangs. `0` restores
    // the old behaviour, but only when a caller asks for it in writing.
    let idle_limit = if args.idle_timeout_seconds == 0 {
        None
    } else {
        Some(Duration::from_secs(args.idle_timeout_seconds))
    };
    let mut last_event = Instant::now();
    loop {
        // Reopened on each poll rather than held: `EventLogReader`'s
        // `last_sequence` is a snapshot, and reopening is how a follower
        // advances past it (see that type's doc comment).
        let reader = EventLogReader::open(state_dir, scan_id)
            .map_err(|e| CliError::operational("no_such_scan_log", e))?;
        let batch = reader
            .read_from(cursor)
            .map_err(|e| CliError::operational("log_unreadable", e))?;
        let mut saw_terminal = false;
        if !batch.is_empty() {
            last_event = Instant::now();
        }
        for event in &batch {
            cursor = event.sequence;
            saw_terminal |= is_terminal(event);
            let doc = serde_json::to_value(event).expect("Event always serializes");
            let human = format!(
                "{:>6}  {}  {}",
                event.sequence,
                event.timestamp,
                serde_json::to_string(&event.body).expect("EventBody always serializes")
            );
            emitter.result(doc, human);
        }
        if !args.follow || saw_terminal {
            return Ok(ExitCode::Success);
        }
        if let Some(limit) = idle_limit
            && last_event.elapsed() >= limit
        {
            // Operational, not success: the caller asked to be followed to
            // a terminal event and is not getting one, and the events
            // already on stdout are a prefix, not an answer.
            return Err(CliError::operational(
                "follow_idle_timeout",
                format!(
                    "no event for {}s while following {scan_id} (last sequence {cursor}); \
                     the writing process may have exited without a terminal event",
                    args.idle_timeout_seconds
                ),
            ));
        }
        std::thread::sleep(Duration::from_millis(200));
    }
}

fn map_store_error(e: StoreError) -> CliError {
    match e {
        StoreError::IdempotencyConflict { .. } => CliError::Conflict {
            detail: e.to_string(),
        },
        other => CliError::operational("store_unavailable", other),
    }
}

fn status_word(status: TaskStatus) -> &'static str {
    match status {
        TaskStatus::Pending => "pending",
        TaskStatus::Running => "running",
        TaskStatus::Paused => "paused",
        TaskStatus::Completed => "completed",
        TaskStatus::Cancelled => "cancelled",
        TaskStatus::Failed => "failed",
        TaskStatus::Denied => "denied",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn summary() -> RunSummary {
        RunSummary::default()
    }

    #[test]
    fn a_clean_run_exits_zero() {
        assert_eq!(exit_for(&summary()), ExitCode::Success);
    }

    #[test]
    fn each_exhaustion_axis_maps_to_three_and_a_denial_to_two() {
        let mut budget = summary();
        budget.budget_exhausted = true;
        assert_eq!(exit_for(&budget), ExitCode::Exhausted);

        let mut time = summary();
        time.time_exhausted = true;
        assert_eq!(exit_for(&time), ExitCode::Exhausted);

        let mut denied = summary();
        denied.policy_denied = true;
        assert_eq!(exit_for(&denied), ExitCode::PolicyDenied);
    }

    #[test]
    fn a_cancelled_run_is_not_a_failure() {
        // Cancellation is a request that was honoured, not an error. It has
        // its own reporting (`cancelled: true` in the summary) and must not
        // be conflated with the ceilings, which mean something different to
        // an agent deciding whether to retry.
        let mut cancelled = summary();
        cancelled.cancelled = true;
        assert_eq!(exit_for(&cancelled), ExitCode::Success);
    }

    #[test]
    fn a_denial_outranks_an_exhaustion_when_both_are_set() {
        let mut both = summary();
        both.policy_denied = true;
        both.budget_exhausted = true;
        assert_eq!(
            exit_for(&both),
            ExitCode::PolicyDenied,
            "an authorization refusal is the more important answer"
        );
    }

    #[test]
    fn an_idempotency_conflict_is_the_only_store_error_that_is_not_operational() {
        let conflict = StoreError::IdempotencyConflict {
            key: "k".into(),
            existing: format!("blake3:{}", "0".repeat(64)).parse().unwrap(),
            incoming: format!("blake3:{}", "1".repeat(64)).parse().unwrap(),
        };
        assert_eq!(
            map_store_error(conflict).exit_code(),
            ExitCode::IdempotencyConflict
        );
        assert_eq!(
            map_store_error(StoreError::NotFound(
                "scan_01ARZ3NDEKTSV4RRFFQ69G5FAV".parse().unwrap()
            ))
            .exit_code(),
            ExitCode::Operational
        );
    }
}
