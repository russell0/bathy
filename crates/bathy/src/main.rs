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

use cli::{Cli, Command, EvidenceCommand, ResultCommand, ScanCommand, ScopeCommand, ServeCommand};
use emit::Emitter;
use exit::{CliError, ExitCode};

fn main() -> std::process::ExitCode {
    // `try_parse`, not `parse`. `clap`'s own `exit()` uses status **2** for
    // a usage error, and 2 is this program's "policy denial" -- an agent
    // branching on the exit code would read a typo as an authorization
    // refusal. Usage errors are operational errors and exit 1; `--help` and
    // `--version` are successful requests and exit 0 on stdout. Which is
    // which is decided kind by kind in `outcome_for`, not by `clap`'s own
    // grouping.
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

/// What `clap` actually reported, once its single `Err` channel is
/// disentangled. `clap` returns `Err` for `--help` and `--version` as well
/// as for genuine mistakes, and the two must not exit the same way.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ParseOutcome {
    /// The caller asked for help. Exit 0; the answer is the help text.
    HelpRequested,
    /// The caller asked for the version. Exit 0.
    VersionRequested,
    /// The caller's arguments were wrong, or `clap` could not deliver its
    /// output. Exit 1 (operational), with a usage document on stdout under
    /// `--json`.
    UsageError,
}

/// The mapping, decided one `ErrorKind` at a time.
///
/// This is written as an exhaustive-shaped match rather than a `matches!`
/// over the interesting few because the defect it replaces was a
/// three-variant `matches!` that swept
/// `DisplayHelpOnMissingArgumentOrSubcommand` in with `--help`: `bathy
/// --json scan` then exited **0 having written nothing to stdout**, which
/// an agent branching on the status can only read as "the scan found
/// nothing". A malformed invocation must never be indistinguishable from
/// an empty result.
///
/// The trap is that `clap` groups its kinds by *its* notion of severity —
/// [`ErrorKind::as_str`] returns `None` for exactly `DisplayHelp`,
/// `DisplayHelpOnMissingArgumentOrSubcommand`, `DisplayVersion`, `Io` and
/// `Format`, and the two doc comments that say "not a true error" sit
/// beside a third that describes a missing argument. That grouping is not
/// ours. Three of those five are failures here, and
/// `clap_kinds_that_are_not_true_errors_to_clap_are_still_failures_to_us`
/// pins it.
///
/// `ErrorKind` is `#[non_exhaustive]`, so a wildcard is mandatory. It
/// resolves to [`ParseOutcome::UsageError`]: a kind this program has never
/// seen is a mistake it does not understand, and the safe direction is
/// nonzero with an explanation, never 0 with silence.
fn outcome_for(kind: clap::error::ErrorKind) -> ParseOutcome {
    use clap::error::ErrorKind as K;
    match kind {
        // Genuine requests, both answered on stdout.
        K::DisplayHelp => ParseOutcome::HelpRequested,
        K::DisplayVersion => ParseOutcome::VersionRequested,

        // A command invoked with nothing after it. `clap` renders help for
        // it, which is why it was mistaken for `--help`, but the caller did
        // not ask for help -- it named a command group and stopped. Same
        // mistake as `MissingSubcommand`, so it gets the same answer;
        // before this fix, `bathy` and `bathy --json` disagreed about it.
        K::DisplayHelpOnMissingArgumentOrSubcommand => ParseOutcome::UsageError,
        K::MissingSubcommand => ParseOutcome::UsageError,

        // Bad or missing values.
        K::InvalidValue => ParseOutcome::UsageError,
        K::UnknownArgument => ParseOutcome::UsageError,
        K::InvalidSubcommand => ParseOutcome::UsageError,
        K::NoEquals => ParseOutcome::UsageError,
        K::ValueValidation => ParseOutcome::UsageError,
        K::TooManyValues => ParseOutcome::UsageError,
        K::TooFewValues => ParseOutcome::UsageError,
        K::WrongNumberOfValues => ParseOutcome::UsageError,
        K::ArgumentConflict => ParseOutcome::UsageError,
        K::MissingRequiredArgument => ParseOutcome::UsageError,
        K::InvalidUtf8 => ParseOutcome::UsageError,

        // `clap` could not write, or could not format, its own output.
        // Nothing was delivered, so nothing succeeded -- and these are the
        // other two kinds whose `as_str()` is `None`.
        K::Io => ParseOutcome::UsageError,
        K::Format => ParseOutcome::UsageError,

        // `#[non_exhaustive]`: a kind added by a future `clap`.
        _ => ParseOutcome::UsageError,
    }
}

/// Render the `Err` half of the parse and exit.
fn usage_exit(e: clap::Error, wants_json: bool) -> std::process::ExitCode {
    match outcome_for(e.kind()) {
        ParseOutcome::HelpRequested => requested_exit(help_document(&e), &e, wants_json),
        ParseOutcome::VersionRequested => requested_exit(version_document(&e), &e, wants_json),
        ParseOutcome::UsageError => usage_error_exit(e, wants_json),
    }
}

/// `--help` and `--version`: exit 0, and the answer goes on stdout in
/// whichever form was asked for.
///
/// Under `--json` that is **one JSON document**, not the prose. AC-5.10
/// says stdout carries line-delimited JSON and nothing else, and `emit.rs`
/// states the same rule in its own words; 1,273 bytes of help text on
/// stdout was an exception neither document made. Emitting a document
/// instead of exempting `--help` also keeps the invariant an agent can
/// actually rely on -- under `--json`, an exit-0 run always leaves at least
/// one parseable line on stdout.
fn requested_exit(
    document: serde_json::Value,
    e: &clap::Error,
    wants_json: bool,
) -> std::process::ExitCode {
    if wants_json {
        Emitter::new(true).result(document, "");
    } else {
        let _ = e.print();
    }
    std::process::ExitCode::from(ExitCode::Success.code() as u8)
}

fn help_document(e: &clap::Error) -> serde_json::Value {
    serde_json::json!({
        "help": rendered(e),
        // The exit-code contract, structured, from the same `ExitCode::TABLE`
        // the prose section is rendered from (AC-5.11).
        "exit_codes": ExitCode::table_json(),
        "exit_code": ExitCode::Success.code(),
    })
}

fn version_document(e: &clap::Error) -> serde_json::Value {
    serde_json::json!({
        "version": rendered(e),
        "exit_code": ExitCode::Success.code(),
    })
}

fn usage_error_exit(e: clap::Error, wants_json: bool) -> std::process::ExitCode {
    // `DisplayHelpOnMissingArgumentOrSubcommand` renders as bare help text
    // with no sentence saying what was wrong, so the sentence is supplied.
    // It is deliberately the wording `clap` itself uses for
    // `MissingSubcommand` (`ErrorKind::as_str`), because the two kinds are
    // the same mistake and a caller must not have to learn two spellings.
    let message = if e.kind() == clap::error::ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand {
        format!(
            "error: a subcommand is required but one was not provided\n\n{}",
            rendered(&e)
        )
    } else {
        rendered(&e)
    };
    let err = CliError::operational("usage", &message);
    // AC-5.10 has to hold on this path too: an agent that asked for JSON
    // gets JSON even when its own arguments were wrong. `wants_json` is
    // scanned out of the raw argv because the parse that would have told us
    // properly is the thing that just failed.
    if wants_json {
        let emitter = Emitter::new(true);
        emitter.result(err.to_json(), "");
    }
    eprintln!("{message}");
    std::process::ExitCode::from(err.exit_code().code() as u8)
}

/// `render().to_string()`, not `render().ansi()`: `bathy` is run by agents
/// through a pipe far more often than by a human at a terminal, and escape
/// sequences inside a JSON string are noise a caller has to strip before it
/// can read the message.
fn rendered(e: &clap::Error) -> String {
    e.render().to_string().trim_end().to_string()
}

fn dispatch(cli: &Cli, emitter: &Emitter) -> Result<ExitCode, CliError> {
    let state_dir = state::resolve_state_dir(cli.state_dir.clone())?;
    match &cli.command {
        Command::Scope(ScopeCommand::Validate(args)) => commands::scope::validate(
            &args.scope,
            &args.targets,
            state::clock().as_ref(),
            emitter,
        ),
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
        Command::Serve(ServeCommand::Mcp(args)) => {
            commands::serve::mcp(args, &state_dir, emitter)
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

#[cfg(test)]
mod tests {
    use super::*;
    use clap::error::ErrorKind as K;

    /// Every `ErrorKind` `clap` 4.6 defines, in declaration order, paired
    /// with the outcome this program deliberately assigns it.
    ///
    /// Written out rather than derived because there is nothing to derive
    /// from: `ErrorKind` is `#[non_exhaustive]` and has no `VARIANTS`. The
    /// list is the decision record -- an operator reading it sees the whole
    /// mapping without re-deriving it from a `match`.
    const MAPPING: &[(K, ParseOutcome)] = &[
        (K::InvalidValue, ParseOutcome::UsageError),
        (K::UnknownArgument, ParseOutcome::UsageError),
        (K::InvalidSubcommand, ParseOutcome::UsageError),
        (K::NoEquals, ParseOutcome::UsageError),
        (K::ValueValidation, ParseOutcome::UsageError),
        (K::TooManyValues, ParseOutcome::UsageError),
        (K::TooFewValues, ParseOutcome::UsageError),
        (K::WrongNumberOfValues, ParseOutcome::UsageError),
        (K::ArgumentConflict, ParseOutcome::UsageError),
        (K::MissingRequiredArgument, ParseOutcome::UsageError),
        (K::MissingSubcommand, ParseOutcome::UsageError),
        (K::InvalidUtf8, ParseOutcome::UsageError),
        (K::DisplayHelp, ParseOutcome::HelpRequested),
        (
            K::DisplayHelpOnMissingArgumentOrSubcommand,
            ParseOutcome::UsageError,
        ),
        (K::DisplayVersion, ParseOutcome::VersionRequested),
        (K::Io, ParseOutcome::UsageError),
        (K::Format, ParseOutcome::UsageError),
    ];

    #[test]
    fn every_clap_error_kind_has_a_deliberate_outcome_and_only_two_of_them_succeed() {
        // 17 is `clap` 4.6's count. If a bump makes this fail, the new kind
        // must be added to `MAPPING` *and* to `outcome_for` with a stated
        // reason -- which is the point: a kind nobody decided about would
        // otherwise fall through the wildcard silently.
        assert_eq!(MAPPING.len(), 17, "clap's ErrorKind set changed");
        for (kind, expected) in MAPPING {
            assert_eq!(outcome_for(*kind), *expected, "{kind:?}");
        }
        let succeeding: Vec<K> = MAPPING
            .iter()
            .filter(|(_, o)| *o != ParseOutcome::UsageError)
            .map(|(k, _)| *k)
            .collect();
        assert_eq!(
            succeeding,
            vec![K::DisplayHelp, K::DisplayVersion],
            "exactly two kinds are successful requests; everything else exits nonzero"
        );
    }

    #[test]
    fn clap_kinds_that_are_not_true_errors_to_clap_are_still_failures_to_us() {
        // `ErrorKind::as_str()` is `None` for exactly five kinds, and the
        // original defect was taking that grouping for ours. Three of the
        // five are failures here. This is the assertion that dies if the
        // `matches!` over "the ones clap does not call errors" ever comes
        // back.
        for kind in [
            K::DisplayHelpOnMissingArgumentOrSubcommand,
            K::Io,
            K::Format,
        ] {
            assert!(kind.as_str().is_none(), "{kind:?}");
            assert_eq!(
                outcome_for(kind),
                ParseOutcome::UsageError,
                "{kind:?} is not an error to clap, but it is one to us"
            );
        }
    }

    // There is deliberately no test for the `_` arm. `ErrorKind` is
    // `#[non_exhaustive]`, so a variant outside `MAPPING` cannot be
    // constructed here, and a test that walked `MAPPING` and asserted "not
    // help" would only restate the assertion above while appearing to cover
    // the wildcard. The count assertion is what actually guards it: a
    // `clap` bump that adds a kind fails the suite instead of routing it
    // silently.

    #[test]
    fn the_json_help_document_carries_the_whole_exit_code_table() {
        let table = ExitCode::table_json();
        let rows = table.as_array().expect("array");
        assert_eq!(rows.len(), ExitCode::TABLE.len());
        for (row, (code, meaning)) in rows.iter().zip(ExitCode::TABLE) {
            assert_eq!(row["code"], code.code());
            assert_eq!(row["meaning"], *meaning);
        }
    }
}
