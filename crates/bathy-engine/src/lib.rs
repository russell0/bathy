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
//! the target.

pub mod connect;
pub mod discovery;
pub mod rate;

pub use connect::{ConnectOutcome, classify_io_error, probe_connect};
pub use discovery::{DiscoveryConfig, DiscoveryResult, discover_host};
pub use rate::RateLimiter;
