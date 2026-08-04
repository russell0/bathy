//! `result.query` and `result.diff`.
//!
//! Both are the fold and the diff verbatim. There is no second fold here: a
//! fold that disagreed with the one the command line publishes would make the
//! two surfaces answer the same question differently, which is the thing this
//! architecture exists to prevent.

use bathy_evidence::EventLogReader;
use bathy_query::{
    ResultQueryInput, ResultQueryOutput, ScanDiff, ScanFold, ScanFoldWire, diff, fold_events,
};
use bathy_types::ids::ScanId;
use bathy_types::tools::ResultDiffInput;

use crate::engine::Runtime;
use crate::error::{ToolResult, log_error, no_such_log};

fn fold_of(runtime: &Runtime, scan_id: ScanId) -> ToolResult<ScanFold> {
    let reader = EventLogReader::open(&runtime.state_dir, scan_id).map_err(no_such_log)?;
    let events = reader.read_from(0).map_err(log_error)?;
    Ok(fold_events(&events))
}

pub fn query(input: ResultQueryInput, runtime: &Runtime) -> ToolResult<ResultQueryOutput> {
    let fold = fold_of(runtime, input.scan_id)?;
    let wire = ScanFoldWire::from(&fold);
    let total_before_filter = wire.endpoints.len() as u64;
    let endpoints: Vec<_> = wire
        .endpoints
        .into_iter()
        .filter(|entry| input.filter.matches(entry))
        .collect();

    Ok(ResultQueryOutput {
        total: endpoints.len() as u64,
        total_before_filter,
        endpoints,
        hosts_up: wire.hosts_up,
        plan_hash: wire.plan_hash,
        terminal: wire.terminal,
    })
}

pub fn diff_scans(input: ResultDiffInput, runtime: &Runtime) -> ToolResult<ScanDiff> {
    let before = fold_of(runtime, input.before_scan_id)?;
    let after = fold_of(runtime, input.after_scan_id)?;
    let mut d = diff(&before, &after);
    if !input.include_confidence_only {
        // Dropped from the list, and deliberately *not* moved into
        // `unchanged`: a confidence wobble is a difference the scan really
        // saw, and counting it as no difference would be a second claim
        // rather than a narrower view of the same one.
        d.changes
            .retain(|c| c.kind != bathy_query::ChangeKind::ConfidenceOnly);
    }
    Ok(d)
}
