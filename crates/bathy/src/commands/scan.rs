//! `bathy scan preview|start|status|events|cancel|resume`.
//!
//! # One implementation of each answer
//!
//! Every subcommand here calls the same function the corresponding tool
//! calls and renders the same typed document. That is not tidiness: M5 Task
//! 4's review drove all eleven tools and all their subcommands against one
//! state directory and found **six** documents that differed and four
//! questions the tool surface could ask that this one could not. Two of the
//! six had already been found and fixed one at a time, which is the tell --
//! the divergences were not a bug, they were a *shape*: two implementations
//! of one answer, corrected wherever somebody happened to look.
//!
//! So the shape is gone. `scan.status`, `scan.cancel`, `scan.events`,
//! `scan.preview` and the two halves of `scan.start`/`scan.resume` that
//! decide anything all live once, in `bathy_mcp::tools::scan`, and
//! `crates/bathy/tests/mcp.rs` compares the two surfaces as whole documents
//! for every tool the server advertises.
//!
//! # What genuinely differs, and why
//!
//! The tool surface **detaches** a scheduler and returns a handle; this one
//! **runs to completion** in the caller's own process, because a command that
//! returned while its scan kept running in a process the shell is about to
//! reap would scan nothing (AC-5.12 requires the handle be printed first, not
//! that the process exit). So `scan start` and `scan resume` print the tool's
//! document *and then* a run summary the tool has no equivalent of. That is
//! the only intended difference, and the parity test asserts it rather than
//! skipping the fields it touches.
//!
//! # The emission path
//!
//! [`run_to_completion`] is the only function in this crate that builds a
//! `Scheduler`, and it takes a `bathy_mcp::engine::AuthorizedScan` -- a type
//! whose only constructor evaluates a real manifest over the plan's fully
//! expanded target list. This crate used to carry a second type of the same
//! name and the same discipline; two spellings of "authorized" is the defect
//! class above wearing its most expensive hat, so there is now one. The
//! engine still re-checks scope identity, expiry and each target immediately
//! before dispatch: that is the backstop and it stays.

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bathy_engine::{GroupCommitLog, RunSummary, Scheduler, SchedulerConfig};
use bathy_mcp::engine::{AuthorizedScan, Runtime};
use bathy_mcp::tools;
use bathy_types::clock::Clock;
use bathy_types::event::Event;
use bathy_types::ids::ScanId;
use bathy_types::nonempty::NonEmpty;
use bathy_types::request::{EvidenceLevel, PortSelection, ServiceDetection};
use bathy_types::task::TaskStatus;
use bathy_types::tools::{
    ScanCancelInput, ScanEventsInput, ScanPreviewInput, ScanRequestSpec, ScanResumeInput,
    ScanStartInput, ScanStatusInput,
};
use tokio_util::sync::CancellationToken;

use crate::cli::{EventsArgs, PreviewArgs, RequestArgs, ResumeArgs, StartArgs};
use crate::emit::Emitter;
use crate::exit::{CliError, ExitCode};
use crate::state;

/// `idempotency_key` is excluded from `plan_hash` by `ScanPlan::build`, so
/// the constant a preview uses cannot change the hash it reports. It is
/// spelled out rather than left as `""` so that a stray preview request
/// serialized into a log is identifiable.
const PREVIEW_KEY: &str = "preview-not-an-attempt";

/// Turn the request-shaping flags into the request *spec* the tool surface
/// declares.
///
/// A spec, not a `ScanRequest`: the scope identity and the budget defaults
/// are filled in from the manifest by `ScanRequestSpec::into_request`, which
/// is also where the intensity and budget bounds are checked. Doing it here
/// as well would be a second copy of the validation the published schema
/// promises, and the two would eventually say different things.
fn build_spec(args: &RequestArgs, idempotency_key: String) -> Result<ScanRequestSpec, CliError> {
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
    Ok(ScanRequestSpec {
        targets,
        objective: args.objective.into(),
        ports,
        service_detection: ServiceDetection {
            enabled: !args.no_service_detection,
            intensity: args.intensity,
        },
        evidence_level: EvidenceLevel::from(args.evidence_level),
        max_packets: args.max_packets,
        max_runtime_seconds: args.max_runtime_seconds,
        max_packets_per_second: args.max_packets_per_second,
        idempotency_key,
    })
}

fn runtime(state_dir: &Path) -> Result<Runtime, CliError> {
    Runtime::open(state_dir).map_err(|e| CliError::operational("state_unavailable", e))
}

fn document<T: serde::Serialize>(value: &T) -> Result<serde_json::Value, CliError> {
    serde_json::to_value(value).map_err(|e| CliError::operational("encode_failed", e))
}

/// AC-5.9. Nothing on this path opens a socket, and nothing on it opens the
/// state directory either: it loads a document, expands a plan and evaluates
/// a policy.
pub fn preview(
    args: &PreviewArgs,
    clock: &dyn bathy_types::clock::Clock,
    emitter: &Emitter,
) -> Result<ExitCode, CliError> {
    let out = tools::scan::preview(
        ScanPreviewInput {
            manifest_path: args.scope.display().to_string(),
            request: build_spec(&args.request, PREVIEW_KEY.to_string())?,
        },
        &clock.now_rfc3339(),
    )
    .map_err(CliError::from_tool)?;

    // A denial is exit 2 and carries the engine's own reason code, the same
    // way the tool marks the result as an error rather than a success with a
    // discouraging field in it.
    if out.policy_decision == bathy_types::task::PolicyDecisionTag::Denied {
        return Err(CliError::from_tool(bathy_mcp::error::ToolFailure::new(
            out.reason_code.unwrap_or_default(),
            out.detail.unwrap_or_default(),
        )));
    }

    let human = format!(
        "approved  plan {}\n  {} target(s), {} probe(s), ~{}s",
        out.plan_hash.map(|h| h.to_string()).unwrap_or_default(),
        out.estimated_targets.unwrap_or_default(),
        out.estimated_probes.unwrap_or_default(),
        out.estimated_runtime_seconds.unwrap_or_default(),
    );
    emitter.result(document(&out)?, human);
    Ok(ExitCode::Success)
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

/// The only place in this crate that builds a [`Scheduler`], and therefore
/// the only place a packet can originate. See the module doc for why it
/// takes an [`AuthorizedScan`].
async fn run_to_completion(
    authorized: &AuthorizedScan,
    runtime: &Runtime,
    scan_id: ScanId,
    from_index: u64,
    ledger: bathy_scope::BudgetLedger,
    log: Arc<Mutex<GroupCommitLog>>,
    emitter: &Emitter,
) -> Result<ExitCode, CliError> {
    let scheduler = Scheduler::new(
        ledger,
        Arc::clone(authorized.manifest()),
        SchedulerConfig::default(),
        Arc::clone(&log),
        Arc::clone(&runtime.store),
        Arc::clone(&runtime.clock),
        scan_id,
        // Not this crate's `CARGO_PKG_VERSION`, which is `0.1.0-alpha.1` --
        // a publication version for the CLI wrapper. `bathy-mcp` writes the
        // same records from the same engine, and when each surface stamped
        // its own crate version one build wrote two different provenance
        // strings; the reader in `bathy-evidence` matched only one of them
        // and accused every CLI-written record of a version skew. See the
        // doc comment on `ENGINE_VERSION`.
        bathy_evidence::ENGINE_VERSION,
        authorized.request().service_detection,
        authorized.request().evidence_level,
        // AC-6.20. `--objective host-inventory` and the MCP schemas' own
        // `host_inventory` have been offering this since M1 with nothing
        // branching on it; this is the parameter that makes the option a
        // user can already type do what it says.
        authorized.request().objective,
        Arc::clone(&runtime.evidence),
        Arc::clone(&runtime.probes),
    );

    // `scan cancel` runs in a different process and cannot reach this token,
    // so it leaves a marker in the state directory and this task turns the
    // marker into a real cancellation. Aborted below so the poller cannot
    // outlive the scan it was watching. The MCP server speaks the same
    // protocol, from the same place -- see `bathy_engine::cancel`.
    let token = CancellationToken::new();
    let watcher = bathy_engine::cancel::spawn_watcher(&runtime.state_dir, scan_id, token.clone());

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
    let input = ScanStartInput {
        manifest_path: args.scope.display().to_string(),
        request: build_spec(&args.request, args.idempotency_key.clone())?,
    };

    // Authorization happens before the state directory is opened: a denied
    // scan must leave no trace, not a `pending` row someone later mistakes
    // for work that was attempted. `admit` opens nothing.
    let clock = state::clock();
    let authorized =
        match tools::scan::admit(&input, &clock.now_rfc3339()).map_err(CliError::from_tool)? {
            tools::scan::StartAdmission::Denied(out) => {
                return Err(CliError::from_tool(bathy_mcp::error::ToolFailure::new(
                    out.reason_code.clone().unwrap_or_default(),
                    out.detail.clone().unwrap_or_default(),
                )));
            }
            tools::scan::StartAdmission::Authorized(scan) => *scan,
        };

    let runtime = runtime(state_dir)?;
    let admission =
        tools::scan::admit_into_store(&authorized, &runtime).map_err(CliError::from_tool)?;
    let handle = admission
        .output
        .handle
        .as_ref()
        .expect("an approved admission always carries a handle");
    let (scan_id, status) = (handle.task_id, handle.status);

    // AC-5.12: printed and flushed *before* the scheduler is built, so the
    // handle is on the pipe regardless of how long the scan then takes.
    emitter.result(
        document(&admission.output)?,
        format!(
            "{scan_id}  {}  plan {}",
            status_word(status),
            handle.plan_hash
        ),
    );

    let Some(work) = admission.work else {
        emitter.note(format!(
            "idempotency key `{}` already names scan {scan_id} ({}); \
             nothing was started. Use `bathy scan resume` to continue it.",
            args.idempotency_key,
            status_word(status)
        ));
        return Ok(ExitCode::Success);
    };

    run_to_completion(
        &authorized,
        &runtime,
        work.scan_id,
        work.from_index,
        work.ledger,
        work.log,
        emitter,
    )
    .await
}

pub async fn resume(
    args: &ResumeArgs,
    state_dir: &Path,
    emitter: &Emitter,
) -> Result<ExitCode, CliError> {
    let input = ScanResumeInput {
        manifest_path: args.scope.display().to_string(),
        scan_id: state::parse_scan_id(&args.scan)?,
    };
    let runtime = runtime(state_dir)?;
    let resumption = tools::scan::prepare_resume(&input, &runtime).map_err(CliError::from_tool)?;

    let human = if resumption.output.resumed {
        format!(
            "{} resuming at unit {} of {}",
            resumption.output.scan_id,
            resumption.output.resumed_from_unit,
            resumption.output.units_total
        )
    } else {
        format!("{} is already complete", resumption.output.scan_id)
    };
    emitter.result(document(&resumption.output)?, human);

    let Some((authorized, work)) = resumption.work else {
        return Ok(ExitCode::Success);
    };
    run_to_completion(
        &authorized,
        &runtime,
        work.scan_id,
        work.from_index,
        work.ledger,
        work.log,
        emitter,
    )
    .await
}

pub fn status(scan: &str, state_dir: &Path, emitter: &Emitter) -> Result<ExitCode, CliError> {
    let out = tools::scan::status(
        ScanStatusInput {
            scan_id: state::parse_scan_id(scan)?,
        },
        &runtime(state_dir)?,
    )
    .map_err(CliError::from_tool)?;

    let human = format!(
        "{}  {}  {}/{} probe(s), {} packet(s), {}s",
        out.scan_id,
        status_word(out.status),
        out.units_completed,
        out.units_total,
        out.packets_spent,
        out.elapsed_seconds
    );
    emitter.result(document(&out)?, human);
    Ok(ExitCode::Success)
}

pub fn cancel(scan: &str, state_dir: &Path, emitter: &Emitter) -> Result<ExitCode, CliError> {
    let out = tools::scan::cancel(
        ScanCancelInput {
            scan_id: state::parse_scan_id(scan)?,
        },
        &runtime(state_dir)?,
    )
    .map_err(CliError::from_tool)?;

    let human = format!(
        "{}: cancellation requested; in-flight probes will be drained ({})",
        out.scan_id,
        if out.resumable {
            "resumable"
        } else {
            "nothing left to resume"
        }
    );
    emitter.result(document(&out)?, human);
    Ok(ExitCode::Success)
}

fn is_terminal(event: &Event) -> bool {
    use bathy_types::event::EventBody;
    matches!(
        &event.body,
        EventBody::ScanCompleted { .. }
            | EventBody::ScanFailed { .. }
            | EventBody::PolicyDenied { .. }
    )
}

/// `bathy scan events`, which is the one place the two surfaces render the
/// same answer in different *shapes*, on purpose.
///
/// The tool returns one paging document -- `{events, next_cursor, has_more}`
/// -- because a JSON-RPC result is one value and a client needs the cursor to
/// ask for the next page. This command emits one event per line, because
/// AC-5.10's contract is line-delimited JSON on stdout and because `--follow`
/// has no last page to attach a cursor to. The events themselves are the same
/// documents in the same order, which is what the parity test asserts; the
/// envelope is the declared difference.
///
/// `--limit` exists so the *question* is expressible from a shell even though
/// the answer is shaped differently. Without it the tool could ask for a
/// bounded page and an operator could not.
pub fn events(
    args: &EventsArgs,
    state_dir: &Path,
    emitter: &Emitter,
) -> Result<ExitCode, CliError> {
    let scan_id = state::parse_scan_id(&args.scan)?;
    let runtime = runtime(state_dir)?;
    let mut cursor = args.after;
    // The tool's own ceiling on one page. Used as the page size when the
    // caller named no bound: an unbounded read is still paged, it just does
    // not stop after the first page.
    const MAX_PAGE: u32 = 1_000;
    let page_size = args.limit.unwrap_or(MAX_PAGE);
    // A follower's only stopping condition used to be a terminal event, and
    // a scan whose process was killed never writes one -- so `--follow`
    // polled forever against a log nothing would ever append to. An agent
    // that shelled out has no interrupt to send. `0` restores the old
    // behaviour, but only when a caller asks for it in writing.
    let idle_limit =
        (args.idle_timeout_seconds != 0).then(|| Duration::from_secs(args.idle_timeout_seconds));
    let mut last_event = Instant::now();
    loop {
        let page = tools::scan::events(
            ScanEventsInput {
                scan_id,
                after_sequence: cursor,
                limit: page_size,
            },
            &runtime,
        )
        .map_err(CliError::from_tool)?;

        let mut saw_terminal = false;
        if !page.events.is_empty() {
            last_event = Instant::now();
        }
        for event in &page.events {
            saw_terminal |= is_terminal(event);
            let human = format!(
                "{:>6}  {}  {}",
                event.sequence,
                event.timestamp,
                serde_json::to_string(&event.body).expect("EventBody always serializes")
            );
            emitter.result(document(event)?, human);
        }
        cursor = page.next_cursor;

        // `--limit` bounds a read, exactly as the tool's `limit` bounds a
        // page: one read, one page, the same events. A caller that wants the
        // rest asks for it, and is told on stderr that there is a rest --
        // stdout stays line-delimited JSON and nothing else (AC-5.10).
        //
        // With no `--limit`, a non-following read keeps going until the log
        // is exhausted. That is the whole of the fix for the truncation the
        // M5 Task 4 fix review found: stdout was silently a *prefix* of the
        // answer, with exit 0 and the only warning on a stream scripts
        // discard, and a consumer had no in-band way to tell. The bound is
        // still here and still the same bound the tool takes; it is now
        // something a caller asks for rather than something they get.
        if !args.follow {
            if !page.has_more {
                return Ok(ExitCode::Success);
            }
            if args.limit.is_some() {
                emitter.note(format!(
                    "more events remain; re-run with --after {cursor}, or raise \
                     --limit (currently {page_size})"
                ));
                return Ok(ExitCode::Success);
            }
            // Unbounded, and there is more log: read the next page. `cursor`
            // strictly advances whenever `has_more` is set (a page that had
            // more to give was not empty), so this terminates.
            continue;
        }
        if saw_terminal {
            return Ok(ExitCode::Success);
        }
        // Following, and the log is already ahead of us: read the next page
        // immediately rather than sleeping through work that is already
        // written.
        if page.has_more {
            continue;
        }
        if let Some(limit) = idle_limit
            && last_event.elapsed() >= limit
        {
            // Operational, not success: the caller asked to be followed to a
            // terminal event and is not getting one, and the events already
            // on stdout are a prefix, not an answer.
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

    /// The exit codes a tool refusal maps to, which is the only part of a
    /// refusal this surface decides for itself.
    #[test]
    fn a_tool_refusal_keeps_its_code_and_gets_this_surfaces_exit_status() {
        use bathy_mcp::error::ToolFailure;

        let conflict = CliError::from_tool(ToolFailure::new("idempotency_conflict", "x"));
        assert_eq!(conflict.exit_code(), ExitCode::IdempotencyConflict);

        for code in [
            "scope_mismatch",
            "scope_expired",
            "target_out_of_scope",
            "budget_exceeds_ceiling",
        ] {
            let denied = CliError::from_tool(ToolFailure::new(code, "x"));
            assert_eq!(denied.exit_code(), ExitCode::PolicyDenied, "{code}");
            assert_eq!(denied.to_json()["reason_code"], serde_json::json!(code));
        }

        let other = CliError::from_tool(ToolFailure::new("no_such_scan", "x"));
        assert_eq!(other.exit_code(), ExitCode::Operational);
        assert_eq!(other.to_json()["error"], serde_json::json!("no_such_scan"));
    }
}
