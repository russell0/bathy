#![forbid(unsafe_code)]

//! `bathy-engine`: the emission path that actually puts packets on the
//! wire, and the budget/rate machinery that governs how fast it may do so.
//!
//! The first component is [`rate::RateLimiter`]: rate control here is an
//! *accuracy* feature as much as a politeness one. Scanning faster than a
//! target's ICMP or SYN rate limit produces false `filtered` results, so
//! the budget that keeps a scan polite is the same budget that keeps its
//! results honest -- which is why the limiter lives on the emission path
//! and is not optional.
//!
//! The second component is [`connect::probe_connect`]: unprivileged TCP
//! connect scanning, the first code in this workspace that actually
//! touches a socket. See the `connect` module doc for why its `Closed` and
//! `Filtered` outcomes are kept distinct rather than collapsed.
//!
//! The third component is [`discovery::discover_host`]: unprivileged host
//! discovery built directly on the first two -- a refusal
//! (`ConnectOutcome::Closed`) is treated as proof of life exactly like an
//! accepted connection, every probe passes through the `RateLimiter`, and
//! discovery stops at the first conclusive answer rather than working
//! through the whole configured probe list. See the `discovery` module doc
//! for why `Filtered`/`Unreachable` are never promoted into evidence about
//! the target -- and (M3 whole-branch review, IMPORTANT-4) for why this
//! component ships in v0.1 as a correct, independently tested library
//! building block with no caller in [`scheduler::Scheduler`] yet: M6
//! (`bathy-packetd`) is the plan's actual integration point for
//! `host.discovered`, via `discover_host_combined`, which tries privileged
//! ICMP first and falls back to exactly this module's TCP method.
//!
//! The fourth component is [`durable_log::GroupCommitLog`]: the M2-decided
//! group-commit batching that makes it safe for the fifth component to
//! drive `EventLog::append` in a hot loop at all -- see that module's doc
//! comment for the crash contract and the measured throughput this buys.
//!
//! The fifth component, and the one that turns the first four (plus every
//! other M1-M3 component) into an actual scanner, is
//! [`scheduler::Scheduler`]: budget-governed, cancellable, resumable
//! execution of a [`bathy_plan::ScanPlan`]. See that module's doc comment
//! for the invariants it holds: budget reserved strictly before emission,
//! in-flight work drained (never dropped) on cancellation, resumption that
//! neither re-probes nor skips a unit, and four distinct terminal outcomes.

pub mod cancel;
pub mod connect;
pub mod discovery;
pub mod durable_log;
pub mod rate;
pub mod scheduler;

pub use connect::{ConnectOutcome, classify_io_error, probe_connect};
pub use discovery::{DiscoveryConfig, DiscoveryConfigError, DiscoveryResult, discover_host};
pub use durable_log::{GroupCommitConfig, GroupCommitLog};
pub use rate::RateLimiter;
pub use scheduler::{EngineError, RunSummary, Scheduler, SchedulerConfig};
