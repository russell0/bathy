#![forbid(unsafe_code)]

//! The probe framework: the bounded I/O layer that turns a live socket into
//! raw, uninterpreted bytes.
//!
//! `bathy-probe` **does I/O and produces bytes**. It never interprets what
//! it reads -- no protocol parsing, no pattern matching, no confidence
//! scoring. `bathy-interpret` (M4 Task 3) is the crate that consumes those
//! bytes and does no I/O at all. Keeping that line clean is the design
//! point this whole milestone is built on: it is what makes interpretation
//! replayable years later against a newer rule set, from stored evidence
//! alone, without a network.
//!
//! The peer on the other end of every socket this crate touches is hostile
//! by assumption: a scan reaches thousands of endpoints, and one of them
//! will misbehave, deliberately or not. [`framework::ProbeIo::read_bounded`]
//! is the load-bearing guarantee that a hostile peer cannot turn a probe
//! into unbounded memory growth or an indefinite hang -- see its own doc
//! comment for exactly how.

pub mod framework;
pub mod probes;

pub use framework::{Probe, ProbeError, ProbeIo, ProbeKind, ProbeRegistry, select_probes};
// `ProbeCapture` is defined in `bathy-types` (see that type's own doc
// comment for why), not here -- re-exported so a `bathy-probe` consumer
// never has to know that fact to use it.
pub use bathy_types::ProbeCapture;
