//! `bathy result query|diff`.
//!
//! Both are the `result.query` and `result.diff` tool functions, rendered.
//! There is no second fold or diff here, and -- since M5 Task 4's fix round
//! -- no second *document* either: this command used to publish
//! `ScanFoldWire` where the tool publishes `ResultQueryOutput`, so the two
//! surfaces answered one question with two shapes, and the command could not
//! express the filter at all.
//!
//! The filter is the larger half of that. An agent could ask "endpoints
//! identified with confidence at least 0.8 on ports 1-1024"; an operator
//! could not reproduce the question from a shell, which is the premise that
//! makes this tool surface auditable.

use std::path::Path;

use bathy_mcp::engine::Runtime;
use bathy_mcp::tools;
use bathy_query::{EndpointFilter, PortRange, ResultQueryInput};
use bathy_types::confidence::Confidence;
use bathy_types::tools::ResultDiffInput;

use crate::cli::{DiffArgs, QueryArgs};
use crate::emit::Emitter;
use crate::exit::{CliError, ExitCode};
use crate::state;

fn runtime(state_dir: &Path) -> Result<Runtime, CliError> {
    Runtime::open(state_dir).map_err(|e| CliError::operational("state_unavailable", e))
}

fn document<T: serde::Serialize>(value: &T) -> Result<serde_json::Value, CliError> {
    serde_json::to_value(value).map_err(|e| CliError::operational("encode_failed", e))
}

/// `LOW-HIGH`, or a single port meaning a range of one.
///
/// Parsed here rather than by `clap` because the tool takes a `{low, high}`
/// object and a shell caller should not have to write JSON; the answer is the
/// same `PortRange` either way, so the two surfaces filter identically.
fn parse_port_range(text: &str) -> Result<PortRange, CliError> {
    let bad = |detail: String| CliError::operational("bad_port_range", detail);
    let port = |s: &str| {
        s.trim()
            .parse::<u16>()
            .map_err(|e| bad(format!("`{s}` is not a port: {e}")))
    };
    match text.split_once('-') {
        Some((low, high)) => Ok(PortRange {
            low: port(low)?,
            high: port(high)?,
        }),
        None => {
            let only = port(text)?;
            Ok(PortRange {
                low: only,
                high: only,
            })
        }
    }
}

fn filter_of(args: &QueryArgs) -> Result<EndpointFilter, CliError> {
    let min_confidence = match args.min_confidence {
        Some(v) => Some(Confidence::new(v).map_err(|e| {
            CliError::operational(
                "bad_confidence",
                format!("--min-confidence must be 0.0-1.0, got {v}: {e}"),
            )
        })?),
        None => None,
    };
    Ok(EndpointFilter {
        state: args.state.map(Into::into),
        service: args.service.clone(),
        min_confidence,
        port_range: args
            .port_range
            .as_deref()
            .map(parse_port_range)
            .transpose()?,
    })
}

pub fn query(args: &QueryArgs, state_dir: &Path, emitter: &Emitter) -> Result<ExitCode, CliError> {
    let out = tools::result::query(
        ResultQueryInput {
            scan_id: state::parse_scan_id(&args.scan)?,
            filter: filter_of(args)?,
        },
        &runtime(state_dir)?,
    )
    .map_err(CliError::from_tool)?;

    let mut human = String::new();
    for entry in &out.endpoints {
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
    human.push_str(&format!(
        "{} of {} endpoint(s)",
        out.total, out.total_before_filter
    ));
    emitter.result(document(&out)?, human);
    Ok(ExitCode::Success)
}

pub fn diff_scans(
    args: &DiffArgs,
    state_dir: &Path,
    emitter: &Emitter,
) -> Result<ExitCode, CliError> {
    let out = tools::result::diff_scans(
        ResultDiffInput {
            before_scan_id: state::parse_scan_id(&args.before)?,
            after_scan_id: state::parse_scan_id(&args.after)?,
            include_confidence_only: args.include_confidence_only,
        },
        &runtime(state_dir)?,
    )
    .map_err(CliError::from_tool)?;

    let human = format!(
        "{} change(s), {} unchanged, {} undetermined",
        out.changes.len(),
        out.unchanged,
        out.undetermined.len()
    );
    emitter.result(document(&out)?, human);
    Ok(ExitCode::Success)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_port_range_takes_both_spellings_and_refuses_anything_else() {
        assert_eq!(
            parse_port_range("80-90").unwrap(),
            PortRange { low: 80, high: 90 }
        );
        assert_eq!(
            parse_port_range("443").unwrap(),
            PortRange {
                low: 443,
                high: 443
            },
            "a single port is the range containing it, not an error"
        );
        for bad in ["", "http", "80-", "-90", "70000", "80-70000"] {
            assert!(parse_port_range(bad).is_err(), "{bad} parsed");
        }
    }
}
