//! `bathy result query|diff`.
//!
//! Both are `bathy-query`'s fold and diff, verbatim. There is no second fold
//! here: a fold that disagreed with the one the MCP server publishes would
//! make the two interfaces answer the same question differently, which is
//! the thing this project's architecture exists to prevent.

use std::path::Path;

use bathy_evidence::EventLogReader;
use bathy_query::{ScanFoldWire, diff, fold_events};
use bathy_types::ids::ScanId;

use crate::emit::Emitter;
use crate::exit::{CliError, ExitCode};
use crate::state;

fn fold_of(state_dir: &Path, scan_id: ScanId) -> Result<bathy_query::ScanFold, CliError> {
    let reader = EventLogReader::open(state_dir, scan_id)
        .map_err(|e| CliError::operational("no_such_scan_log", e))?;
    let events = reader
        .read_from(0)
        .map_err(|e| CliError::operational("log_unreadable", e))?;
    Ok(fold_events(&events))
}

pub fn query(scan: &str, state_dir: &Path, emitter: &Emitter) -> Result<ExitCode, CliError> {
    let scan_id = state::parse_scan_id(scan)?;
    let fold = fold_of(state_dir, scan_id)?;
    let wire = ScanFoldWire::from(&fold);
    let doc = serde_json::to_value(&wire).map_err(|e| CliError::operational("encode_failed", e))?;

    let mut human = String::new();
    for entry in &wire.endpoints {
        let state_word = entry
            .state
            .map(|s| serde_json::to_string(&s).unwrap_or_default())
            .unwrap_or_else(|| "null".into());
        human.push_str(&format!(
            "{}:{} {} {}\n",
            entry.target,
            entry.endpoint.port,
            state_word.trim_matches('"'),
            entry
                .observation
                .as_ref()
                .map(|o| o.service.clone())
                .unwrap_or_default()
        ));
    }
    human.push_str(&format!("{} endpoint(s)", wire.endpoints.len()));
    emitter.result(doc, human);
    Ok(ExitCode::Success)
}

pub fn diff_scans(
    before: &str,
    after: &str,
    state_dir: &Path,
    emitter: &Emitter,
) -> Result<ExitCode, CliError> {
    let before_fold = fold_of(state_dir, state::parse_scan_id(before)?)?;
    let after_fold = fold_of(state_dir, state::parse_scan_id(after)?)?;
    let d = diff(&before_fold, &after_fold);
    let doc = serde_json::to_value(&d).map_err(|e| CliError::operational("encode_failed", e))?;
    let human = format!(
        "{} change(s), {} unchanged, {} undetermined",
        d.changes.len(),
        d.unchanged,
        d.undetermined.len()
    );
    emitter.result(doc, human);
    Ok(ExitCode::Success)
}
