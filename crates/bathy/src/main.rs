#![forbid(unsafe_code)]

//! The `bathy` command.
//!
//! This binary contains **no scanning logic**. It parses arguments, loads a
//! scope manifest, calls the engine API and renders the answer. Task 4's MCP
//! server is the same translator over the same API; anything one can do the
//! other can do, which is what makes the tool surface testable without an
//! MCP client.
//!
//! Deliberately a binary-only module tree rather than a library: the crate's
//! `lib.rs` stays the name reservation it has always been, so nothing in
//! this file is reachable except by running the program. That is also what
//! forces this crate's own tests to spawn the binary, which is where a CLI
//! is actually used.

mod authorize;
mod cli;
mod commands;
mod emit;
mod exit;
mod state;

use clap::Parser;

use cli::{Cli, Command, EvidenceCommand, ResultCommand, ScanCommand, ScopeCommand};
use emit::Emitter;
use exit::{CliError, ExitCode};

fn main() -> std::process::ExitCode {
    // `try_parse`, not `parse`. `clap`'s own `exit()` uses status **2** for
    // a usage error, and 2 is this program's "policy denial" -- an agent
    // branching on the exit code would read a typo as an authorization
    // refusal. Usage errors are operational errors and exit 1; `--help` and
    // `--version` are successful requests and exit 0 on stdout.
    let raw: Vec<String> = std::env::args().collect();
    let wants_json = raw.iter().any(|a| a == "--json");
    let cli = match Cli::try_parse_from(&raw) {
        Ok(cli) => cli,
        Err(e) => return usage_exit(e, wants_json),
    };

    let emitter = Emitter::new(cli.json);
    match dispatch(&cli, &emitter) {
        Ok(code) => std::process::ExitCode::from(code.code() as u8),
        Err(e) => {
            emitter.failure(&e);
            std::process::ExitCode::from(e.exit_code().code() as u8)
        }
    }
}

/// `clap` reports `--help`/`--version` through the same `Err` channel as a
/// genuine usage error, and the two must not exit the same way.
fn usage_exit(e: clap::Error, wants_json: bool) -> std::process::ExitCode {
    use clap::error::ErrorKind;
    if matches!(
        e.kind(),
        ErrorKind::DisplayHelp
            | ErrorKind::DisplayVersion
            | ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand
    ) {
        let _ = e.print();
        return std::process::ExitCode::from(ExitCode::Success.code() as u8);
    }
    // `render().to_string()`, not `render().ansi()`: `bathy` is run by
    // agents through a pipe far more often than by a human at a terminal,
    // and escape sequences inside a JSON `detail` string are noise a caller
    // has to strip before it can read the message.
    let message = e.render().to_string();
    let err = CliError::operational("usage", message.trim_end());
    // AC-5.10 has to hold on this path too: an agent that asked for JSON
    // gets JSON even when its own arguments were wrong. `wants_json` is
    // scanned out of the raw argv because the parse that would have told us
    // properly is the thing that just failed.
    if wants_json {
        let emitter = Emitter::new(true);
        emitter.result(err.to_json(), "");
    }
    eprint!("{message}");
    std::process::ExitCode::from(err.exit_code().code() as u8)
}

fn dispatch(cli: &Cli, emitter: &Emitter) -> Result<ExitCode, CliError> {
    let state_dir = state::resolve_state_dir(cli.state_dir.clone())?;
    match &cli.command {
        Command::Scope(ScopeCommand::Validate(args)) => {
            commands::scope::validate(&args.scope, state::clock().as_ref(), emitter)
        }
        Command::Scan(ScanCommand::Preview(args)) => {
            commands::scan::preview(args, state::clock().as_ref(), emitter)
        }
        Command::Scan(ScanCommand::Start(args)) => {
            block_on(commands::scan::start(args, &state_dir, emitter))
        }
        Command::Scan(ScanCommand::Resume(args)) => {
            block_on(commands::scan::resume(args, &state_dir, emitter))
        }
        Command::Scan(ScanCommand::Status(args)) => {
            commands::scan::status(&args.scan, &state_dir, emitter)
        }
        Command::Scan(ScanCommand::Cancel(args)) => {
            commands::scan::cancel(&args.scan, &state_dir, emitter)
        }
        Command::Scan(ScanCommand::Events(args)) => {
            commands::scan::events(args, &state_dir, emitter)
        }
        Command::Result(ResultCommand::Query(args)) => {
            commands::result::query(&args.scan, &state_dir, emitter)
        }
        Command::Result(ResultCommand::Diff(args)) => {
            commands::result::diff_scans(&args.before, &args.after, &state_dir, emitter)
        }
        Command::Evidence(EvidenceCommand::Get(args)) => {
            commands::evidence::get(&args.digest, &state_dir, emitter)
        }
        Command::Explain(args) => {
            commands::explain::run(args.rule_id.as_deref(), args.list, emitter)
        }
    }
}

/// A runtime is built only for the two subcommands that actually need one.
///
/// `#[tokio::main]` on `main` would start a thread pool for `bathy explain`
/// and for every failed argument parse, which is both wasteful and a wider
/// blast radius than the emission path deserves.
fn block_on<F: std::future::Future<Output = Result<ExitCode, CliError>>>(
    fut: F,
) -> Result<ExitCode, CliError> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| CliError::operational("runtime_unavailable", e))?
        .block_on(fut)
}
