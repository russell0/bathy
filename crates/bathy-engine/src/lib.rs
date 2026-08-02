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

pub mod rate;

pub use rate::RateLimiter;
