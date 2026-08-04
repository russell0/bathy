//! `bathy serve mcp`.
//!
//! The command that turns this binary into the agent-facing product. It adds
//! no capability: it exposes the same engine, through the same scope
//! enforcement, to a caller that speaks a machine protocol instead of a shell.

use std::path::Path;
use std::time::Duration;

use bathy_mcp::ServerConfig;

use crate::cli::ServeMcpArgs;
use crate::emit::Emitter;
use crate::exit::{CliError, ExitCode};

pub fn mcp(args: &ServeMcpArgs, state_dir: &Path, emitter: &Emitter) -> Result<ExitCode, CliError> {
    if args.approval_ttl_seconds == 0 {
        return Err(CliError::operational(
            "bad_approval_ttl",
            "--approval-ttl-seconds must be greater than zero; an approval that never \
             expires is a standing grant",
        ));
    }

    // Stdout is the transport from here on, so the one line a human might
    // want goes to stderr. `Emitter::note` is already the stderr channel.
    emitter.note(format!(
        "serving 11 MCP tools on stdio; state {}, human approval above {} target(s)",
        state_dir.display(),
        args.approval_threshold_targets
    ));

    let config = ServerConfig::new(state_dir.to_path_buf())
        .with_approval_threshold(args.approval_threshold_targets)
        .with_approval_ttl(Duration::from_secs(args.approval_ttl_seconds));

    // A runtime built here rather than by an attribute on `main`: this is one
    // of three subcommands that needs one, and the rest of the program should
    // not start a thread pool to print a rule's rationale.
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| CliError::operational("runtime_unavailable", e))?
        .block_on(bathy_mcp::serve_stdio(config))
        .map_err(|e| CliError::operational("mcp_server_failed", e))?;

    Ok(ExitCode::Success)
}
