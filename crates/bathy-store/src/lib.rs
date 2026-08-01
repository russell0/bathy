#![forbid(unsafe_code)]

//! Scaffold only. `bathy-store` will hold the SQLite-backed task store (idempotent
//! task handles, retries, and state transitions) added in a later M2 task. It
//! exists as an empty crate now purely so the layer order in
//! `xtask/src/main.rs`'s `LAYERS` -- `bathy-evidence` strictly below
//! `bathy-store` -- has something to point at, and so `Clock` (which
//! `bathy-evidence::EventLog::append` needs) has a documented reason to live
//! in `bathy-types` instead: `bathy-store` cannot be `Clock`'s home without
//! `bathy-evidence` depending upward on it, which `check-deps` forbids.
