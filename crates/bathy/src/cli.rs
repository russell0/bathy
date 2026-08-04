//! The command tree.
//!
//! # `--scope` is a field, not a check (AC-5.8)
//!
//! Every subcommand that can put a packet on someone else's network carries
//! `scope: PathBuf` -- **not** `Option<PathBuf>`, and with no default and no
//! skip flag. The argument struct for such a command cannot be constructed
//! without a manifest path, so "we forgot to check for `--scope`" is not a
//! mistake that can be made here: there is no value of the type that
//! represents it. Omitting the flag fails inside `clap`, before `main` has
//! dispatched anything, before a state directory is opened and before a
//! `ScanRequest` exists.
//!
//! That is the same fix M3 applied to the scheduler when it found a
//! `Scheduler` could be built with no scope awareness at all: make the
//! unauthorized state unconstructible rather than checked. The engine's
//! deny-by-default is still there and still enforcing; it is the backstop,
//! not the mechanism. `crate::authorize::AuthorizedScan` is the second half
//! of the same idea one layer up -- nothing in this crate can reach the
//! emission path without one, and it has no constructor that does not
//! evaluate a real manifest.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

use crate::exit::ExitCode;

/// Long help for the root command. `--help` is where an agent reads the
/// exit-code contract, so the table is rendered from `ExitCode::TABLE`
/// rather than restated.
fn after_help() -> String {
    format!(
        "{}\nEvery subcommand that can emit a packet requires --scope. There is no default \
         and no flag to skip it.",
        ExitCode::help_section()
    )
}

#[derive(Debug, Parser)]
#[command(
    name = "bathy",
    version,
    about = "Agent-native network discovery with deny-by-default scope enforcement.",
    after_long_help = after_help(),
    after_help = after_help(),
)]
pub struct Cli {
    /// Emit line-delimited JSON on stdout; all diagnostics go to stderr.
    #[arg(long, global = true)]
    pub json: bool,

    /// Where scan state, event logs and evidence live.
    /// Defaults to $BATHY_STATE_DIR, else $HOME/.local/share/bathy.
    #[arg(long, global = true, value_name = "DIR")]
    pub state_dir: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Scope manifests: load one and report what it authorizes.
    #[command(subcommand)]
    Scope(ScopeCommand),
    /// Plan, start, observe and stop scans.
    #[command(subcommand)]
    Scan(ScanCommand),
    /// Query and compare finished scans.
    #[command(subcommand)]
    Result(ResultCommand),
    /// Fetch the exact bytes a finding cited.
    #[command(subcommand)]
    Evidence(EvidenceCommand),
    /// Explain an interpretation rule: what it looks for and where it comes from.
    Explain(ExplainArgs),
    /// Expose the same engine to an agent over a machine protocol.
    #[command(subcommand)]
    Serve(ServeCommand),
}

#[derive(Debug, Subcommand)]
pub enum ServeCommand {
    /// Serve eleven typed tools over the Model Context Protocol, on stdio.
    ///
    /// Stdout is the transport, so this command writes nothing else to it;
    /// diagnostics go to stderr. It runs until the client disconnects.
    Mcp(ServeMcpArgs),
}

#[derive(Debug, Args)]
pub struct ServeMcpArgs {
    /// A scan wider than this many addresses asks a human before it starts.
    ///
    /// Server-side configuration on purpose: a threshold a caller could set
    /// is not a threshold. There is no tool argument for it.
    #[arg(long, value_name = "TARGETS", default_value_t = bathy_mcp::config::DEFAULT_APPROVAL_THRESHOLD_TARGETS)]
    pub approval_threshold_targets: u64,

    /// How many seconds an approval stays redeemable.
    #[arg(long, value_name = "SECONDS", default_value_t = 600)]
    pub approval_ttl_seconds: u64,
}

#[derive(Debug, Subcommand)]
pub enum ScopeCommand {
    /// Load a manifest and report what it authorizes, or why it is unusable.
    Validate(ScopeValidateArgs),
}

#[derive(Debug, Args)]
pub struct ScopeValidateArgs {
    /// Path to the scope manifest JSON document.
    #[arg(long, value_name = "PATH")]
    pub scope: PathBuf,

    /// Addresses, CIDRs or inclusive ranges to check against the manifest.
    ///
    /// Present so this command can answer the same question the
    /// `scope.validate` tool answers. Without it the tool surface could do
    /// something the command surface could not, and the premise that makes
    /// the tool surface auditable from a shell would not hold.
    #[arg(long, value_name = "TARGET", value_delimiter = ',')]
    pub targets: Vec<String>,
}

#[derive(Debug, Subcommand)]
pub enum ScanCommand {
    /// Compute a plan hash, target and probe estimates, and a policy
    /// decision. Emits no packet.
    Preview(PreviewArgs),
    /// Admit a scan and run it. Prints the task handle immediately; the
    /// scan continues in this process until it finishes.
    Start(StartArgs),
    /// Report a scan's stored lifecycle record.
    Status(ScanRefArgs),
    /// Read a scan's event log.
    Events(EventsArgs),
    /// Ask a running scan to stop. In-flight probes are drained, not dropped.
    Cancel(ScanRefArgs),
    /// Continue a scan that stopped before its plan was exhausted.
    Resume(ResumeArgs),
}

/// The request-shaping flags shared by `preview`, `start` and (via the
/// stored request) `resume`.
///
/// `scope` is **not** here: it lives on each packet-emitting subcommand's
/// own struct as a required field. See this module's doc comment.
#[derive(Debug, Args, Clone)]
pub struct RequestArgs {
    /// Targets: CIDRs, single addresses, or inclusive a.b.c.d-e.f.g.h ranges.
    #[arg(long, value_name = "TARGET", value_delimiter = ',', required = true)]
    pub targets: Vec<String>,

    /// Explicit ports and inclusive ranges, e.g. 22,80,8000-8100.
    #[arg(
        long,
        value_name = "PORTS",
        value_delimiter = ',',
        conflicts_with = "port_preset",
        required_unless_present = "port_preset"
    )]
    pub ports: Vec<String>,

    /// A named port set instead of an explicit list.
    #[arg(long, value_name = "PRESET")]
    pub port_preset: Option<PortPresetArg>,

    /// What this scan is for.
    #[arg(long, value_enum, default_value_t = ObjectiveArg::InventoryExposedServices)]
    pub objective: ObjectiveArg,

    /// Hard packet ceiling. Defaults to the manifest's own ceiling.
    #[arg(long, value_name = "N")]
    pub max_packets: Option<u64>,

    /// Hard runtime ceiling in seconds. Defaults to the manifest's own ceiling.
    #[arg(long, value_name = "SECONDS")]
    pub max_runtime_seconds: Option<u64>,

    /// Hard packets-per-second ceiling. Defaults to the manifest's own ceiling.
    #[arg(long, value_name = "PPS")]
    pub max_packets_per_second: Option<u32>,

    /// Do not attempt service identification on open ports.
    #[arg(long)]
    pub no_service_detection: bool,

    /// How many probes an open port may be shown, 0-9.
    #[arg(long, value_name = "N", default_value_t = 4)]
    pub intensity: u8,

    /// How much of a matched probe's response to keep as evidence.
    #[arg(long, value_enum, default_value_t = EvidenceLevelArg::Headers)]
    pub evidence_level: EvidenceLevelArg,
}

#[derive(Debug, Args)]
pub struct PreviewArgs {
    /// Path to the scope manifest authorizing this scan. Required.
    #[arg(long, value_name = "PATH")]
    pub scope: PathBuf,
    #[command(flatten)]
    pub request: RequestArgs,
}

#[derive(Debug, Args)]
pub struct StartArgs {
    /// Path to the scope manifest authorizing this scan. Required: there is
    /// no default and no flag to skip it.
    #[arg(long, value_name = "PATH")]
    pub scope: PathBuf,
    /// Names this attempt. Repeating it with an identical plan returns the
    /// original scan; repeating it with a different plan is refused (exit 4).
    #[arg(long, value_name = "KEY")]
    pub idempotency_key: String,
    #[command(flatten)]
    pub request: RequestArgs,
}

#[derive(Debug, Args)]
pub struct ResumeArgs {
    /// Path to the scope manifest authorizing this scan. Required, and
    /// re-evaluated: a manifest that has expired since the scan started
    /// refuses the resume.
    #[arg(long, value_name = "PATH")]
    pub scope: PathBuf,
    /// The scan to continue.
    #[arg(long, value_name = "SCAN_ID")]
    pub scan: String,
}

#[derive(Debug, Args)]
pub struct ScanRefArgs {
    #[arg(long, value_name = "SCAN_ID")]
    pub scan: String,
}

#[derive(Debug, Args)]
pub struct EventsArgs {
    #[arg(long, value_name = "SCAN_ID")]
    pub scan: String,
    /// Return only events after this sequence number.
    #[arg(long, value_name = "SEQUENCE", default_value_t = 0)]
    pub after: u64,
    /// How many events to read at most, 1-1000. Unset reads the whole log.
    ///
    /// The same bound the `scan.events` tool takes, and here for the same
    /// reason `--targets` is on `scope validate`: a question the tool
    /// surface can ask and this one cannot is a question an operator cannot
    /// reproduce from a shell. Under `--follow` it bounds each poll.
    ///
    /// **There is no default bound**, and that is deliberate. It used to
    /// default to 200: a 402-event log then produced 200 lines on stdout,
    /// exit 0, and the "there is more" notice on stderr alone -- so
    /// `bathy --json scan events --scan X > events.jsonl`, which discards
    /// stderr as scripts do, silently became a prefix of the answer with a
    /// success code, and nothing on stdout said so. An agent reading that
    /// file has no way to tell a complete log from a truncated one. A read
    /// that is not following now returns the whole log unless a caller
    /// writes down a bound, so truncation only ever happens because someone
    /// asked for it.
    #[arg(long, value_name = "N")]
    pub limit: Option<u32>,
    /// Keep reading as the scan writes, until it reaches a terminal event.
    #[arg(long)]
    pub follow: bool,

    /// Give up after this many seconds with no new event, and say so.
    /// 0 waits forever. Ignored without --follow.
    ///
    /// A scan whose process was killed never writes its terminal event, so
    /// an unbounded follower waits for something that will never arrive --
    /// and an agent that shelled out to `scan events --follow` has no
    /// interrupt to send. The default is far longer than any gap a live
    /// scan produces (probe timeouts are seconds, not minutes), so reaching
    /// it means the writer is gone, not slow.
    #[arg(long, value_name = "SECONDS", default_value_t = 300)]
    pub idle_timeout_seconds: u64,
}

#[derive(Debug, Subcommand)]
pub enum ResultCommand {
    /// Fold a scan's event log into per-endpoint state.
    Query(QueryArgs),
    /// Compare two scans' folds.
    Diff(DiffArgs),
}

/// `bathy result query`, including the whole of the `result.query` filter.
///
/// The filter is the largest of the four things the tool surface could
/// express and this one could not: an agent could ask "endpoints identified
/// with confidence at least 0.8 on ports 1-1024" and an operator had no way
/// to reproduce the question. Every field of `bathy_query::EndpointFilter`
/// has a flag here, and the parity test compares the two answers as whole
/// documents so a field added to the filter cannot be reachable from only
/// one surface.
#[derive(Debug, Args)]
pub struct QueryArgs {
    #[arg(long, value_name = "SCAN_ID")]
    pub scan: String,
    /// Keep only endpoints in this reachability state.
    #[arg(long, value_enum, value_name = "STATE")]
    pub state: Option<PortStateArg>,
    /// Keep only endpoints whose identified service matches this exactly.
    #[arg(long, value_name = "NAME")]
    pub service: Option<String>,
    /// Keep only endpoints identified with at least this confidence, 0.0-1.0.
    /// An endpoint carrying no identification at all is dropped by this.
    #[arg(long, value_name = "FLOAT")]
    pub min_confidence: Option<f64>,
    /// Keep only endpoints whose port is inside this inclusive range,
    /// written `LOW-HIGH` or as a single port.
    #[arg(long, value_name = "LOW-HIGH")]
    pub port_range: Option<String>,
}

#[derive(Debug, Args)]
pub struct DiffArgs {
    /// The earlier scan.
    #[arg(long, value_name = "SCAN_ID")]
    pub before: String,
    /// The later scan.
    #[arg(long, value_name = "SCAN_ID")]
    pub after: String,
    /// Keep changes where only the confidence moved. Confidence wobbles
    /// between runs, so these are separated from substantive change and
    /// dropped by default.
    #[arg(long)]
    pub include_confidence_only: bool,
}

#[derive(Debug, Subcommand)]
pub enum EvidenceCommand {
    /// Write the bytes stored under a digest to stdout.
    Get(EvidenceGetArgs),
}

#[derive(Debug, Args)]
pub struct EvidenceGetArgs {
    /// A `blake3:<64 hex>` digest, as cited by an event's evidence_refs.
    #[arg(long, value_name = "DIGEST")]
    pub digest: String,
    /// Return at most this many bytes, and say so. Absent returns all of
    /// them. Under `--json` the document reports `truncated`; in human mode
    /// the bytes are simply cut short, so the flag is how you know.
    #[arg(long, value_name = "N")]
    pub max_bytes: Option<u64>,
}

#[derive(Debug, Args)]
pub struct ExplainArgs {
    /// The rule id, e.g. http-server-header-v1.
    #[arg(value_name = "RULE_ID", required_unless_present = "list")]
    pub rule_id: Option<String>,
    /// List every rule this build can explain.
    #[arg(long)]
    pub list: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum PortPresetArg {
    #[value(name = "top-100")]
    Top100,
    #[value(name = "common-1000")]
    Common1000,
    All,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ObjectiveArg {
    HostInventory,
    InventoryExposedServices,
    ChangeDetection,
    ConfidenceRefinement,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum EvidenceLevelArg {
    None,
    Headers,
    Full,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum PortStateArg {
    Open,
    Closed,
    Filtered,
    Indeterminate,
}

impl From<PortStateArg> for bathy_types::event::PortState {
    fn from(s: PortStateArg) -> Self {
        match s {
            PortStateArg::Open => Self::Open,
            PortStateArg::Closed => Self::Closed,
            PortStateArg::Filtered => Self::Filtered,
            PortStateArg::Indeterminate => Self::Indeterminate,
        }
    }
}

impl From<PortPresetArg> for bathy_types::PortPreset {
    fn from(p: PortPresetArg) -> Self {
        match p {
            PortPresetArg::Top100 => Self::Top100,
            PortPresetArg::Common1000 => Self::Common1000,
            PortPresetArg::All => Self::All,
        }
    }
}

impl From<ObjectiveArg> for bathy_types::Objective {
    fn from(o: ObjectiveArg) -> Self {
        match o {
            ObjectiveArg::HostInventory => Self::HostInventory,
            ObjectiveArg::InventoryExposedServices => Self::InventoryExposedServices,
            ObjectiveArg::ChangeDetection => Self::ChangeDetection,
            ObjectiveArg::ConfidenceRefinement => Self::ConfidenceRefinement,
        }
    }
}

impl From<EvidenceLevelArg> for bathy_types::EvidenceLevel {
    fn from(e: EvidenceLevelArg) -> Self {
        match e {
            EvidenceLevelArg::None => Self::None,
            EvidenceLevelArg::Headers => Self::Headers,
            EvidenceLevelArg::Full => Self::Full,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn the_command_tree_is_internally_consistent() {
        Cli::command().debug_assert();
    }

    /// AC-5.8, stated against the parser rather than against a runtime
    /// check: for each packet-emitting subcommand, a complete invocation
    /// minus `--scope` must fail to parse.
    #[test]
    fn no_packet_emitting_subcommand_parses_without_a_scope() {
        let complete: &[&[&str]] = &[
            &[
                "bathy",
                "scan",
                "start",
                "--idempotency-key",
                "k",
                "--targets",
                "10.30.0.1",
                "--ports",
                "80",
            ],
            &["bathy", "scan", "resume", "--scan", "scan_x"],
            // `preview` emits no packet, but it decides authorization and
            // must not be usable without a manifest either.
            &[
                "bathy",
                "scan",
                "preview",
                "--targets",
                "10.30.0.1",
                "--ports",
                "80",
            ],
        ];
        for argv in complete {
            let mut with_scope: Vec<&str> = argv.to_vec();
            with_scope.extend(["--scope", "/dev/null"]);
            assert!(
                Cli::try_parse_from(&with_scope).is_ok(),
                "fixture must otherwise be a complete invocation: {with_scope:?}"
            );
            assert!(
                Cli::try_parse_from(*argv).is_err(),
                "{argv:?} parsed without --scope"
            );
        }
    }

    #[test]
    fn the_help_text_carries_the_exit_code_table() {
        let help = Cli::command().render_help().to_string();
        for (code, meaning) in ExitCode::TABLE {
            assert!(
                help.contains(&format!("{}  {meaning}", code.code())),
                "{help}"
            );
        }
    }
}
