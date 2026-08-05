#![forbid(unsafe_code)]

//! The `bathy` crate's library target: a name reservation and the one
//! constant the binary and the probes both need.
//!
//! The attribute above is not decoration. The Global Constraint is
//! `#![forbid(unsafe_code)]` in **every** crate except `bathy-packetd`, and
//! this file was the one target in the workspace without it -- `main.rs`
//! carries it, and an inner attribute in a binary root does not reach the
//! library target beside it. Found in M7 Task 4 while re-verifying the design
//! paper's claim that the constraint holds everywhere, which it now does.

pub const REPOSITORY: &str = "https://github.com/russell0/bathy";
