#![forbid(unsafe_code)]

//! The SQLite-backed task store: scan state, database-enforced idempotency,
//! and the resumption cursor.
//!
//! [`tasks::TaskStore`] is the sole authority on three things:
//!
//! 1. **Idempotency.** Repeating `scan.start` with the same `idempotency_key`
//!    and the same plan must not start a second scan, and repeating it with
//!    the same key but a *different* plan must be refused outright rather
//!    than silently doing either the old or the new thing. This is enforced
//!    by a `UNIQUE` index in `schema.sql`, not only by the read-then-write
//!    logic in [`tasks::TaskStore::start_or_reuse`] -- a read-then-write in
//!    Rust is a race between two connections, and only the database itself
//!    can arbitrate it.
//! 2. **State.** `scans.status` and the other scan-level fields survive
//!    closing and reopening the store.
//! 3. **The resumption cursor.** `unit_progress` records which indices of
//!    the deterministic plan are already done, so `scan.resume` can skip
//!    them. Only the index is ever persisted -- the expanded target list is
//!    always regenerated from `scans.request_json` on resume, never stored.
//!
//! This is a derived index, not the source of truth: `bathy-evidence`'s
//! append-only event log is, and can always rebuild what belongs here. That
//! ordering is also why this crate sits strictly above `bathy-evidence` in
//! `xtask`'s `LAYERS` while never being depended on by it.

pub mod tasks;

pub use tasks::{ListFilter, StartOutcome, StartRequest, StoreError, TaskRecord, TaskStore};
