#![forbid(unsafe_code)]

//! Evidence: the content-addressed blob store, and the append-only event log
//! that is this project's actual source of truth.
//!
//! [`store`] holds the substrate under this project's entire provenance
//! claim. Every finding the scanner emits cites the exact response bytes
//! that justified it, and those bytes live here, keyed by their own BLAKE3
//! digest.
//!
//! Three properties carry that claim (see [`store`] for the code that makes
//! each one true):
//!
//! 1. **Verify on read.** [`EvidenceStore::get`] recomputes the digest of the
//!    bytes it read and refuses to return them if they disagree. Without
//!    that check, "content addressed" is a naming convention rather than a
//!    guarantee.
//! 2. **Atomic writes.** Temp file then rename, so a crash never leaves a
//!    partial blob visible under a digest that does not describe it.
//! 3. **Bounded.** [`EvidenceStore::put_capped`] truncates at a byte cap and
//!    reports truncation, so a hostile endpoint flooding bytes cannot turn
//!    `evidence_level: full` into unbounded disk use.
//!
//! Evidence is always written *before* the event that references it, so an
//! `evidence_refs` entry can never dangle (enforced by the caller, in M4).
//!
//! [`log`] holds [`EventLog`], the per-scan append-only JSONL record of
//! everything a scan observed. It is the source of truth for a scan; SQLite
//! state (`bathy-store`, a later M2 task) is a derived index rebuildable
//! from it, never the other way around. See [`log`]'s module doc comment for
//! the two properties that carry that claim.

pub mod log;
pub mod store;

pub use log::{EventLog, LogError};
pub use store::{EvidenceError, EvidenceStore, blob_path};
