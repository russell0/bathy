PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS scans (
    scan_id           TEXT PRIMARY KEY,
    plan_hash         TEXT NOT NULL,
    idempotency_key   TEXT NOT NULL,
    scope_id          TEXT NOT NULL,
    status            TEXT NOT NULL,
    request_json      TEXT NOT NULL,
    estimated_targets INTEGER NOT NULL,
    estimated_probes  INTEGER NOT NULL,
    packets_spent     INTEGER NOT NULL DEFAULT 0,
    -- Wall-clock runtime, in whole seconds, spent across every run of this
    -- scan so far. Read back on resume (M3 Task 7 fix round 1, CRITICAL-2)
    -- to seed `BudgetLedger::resumed`'s runtime baseline -- without it, a
    -- cancelled scan resumed by a fresh Scheduler/BudgetLedger gets a full
    -- new runtime budget every time, the same hole `packets_spent` closes
    -- for the packet ceiling.
    elapsed_seconds   INTEGER NOT NULL DEFAULT 0,
    last_sequence     INTEGER NOT NULL DEFAULT 0,
    created_at        TEXT NOT NULL,
    updated_at        TEXT NOT NULL
);

-- The idempotency guarantee, enforced by the database rather than by a
-- read-then-write race in application code.
CREATE UNIQUE INDEX IF NOT EXISTS scans_idempotency
    ON scans (idempotency_key);

CREATE INDEX IF NOT EXISTS scans_status ON scans (status);

-- Resumption cursor: which units of the deterministic plan are finished.
-- The plan is regenerated from request_json on resume, so only the index is
-- stored, never the expanded target list.
CREATE TABLE IF NOT EXISTS unit_progress (
    scan_id     TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    unit_index  INTEGER NOT NULL,
    PRIMARY KEY (scan_id, unit_index)
) WITHOUT ROWID;

-- Schema version, stamped last so this statement only ever runs once this
-- file's own tables/columns are genuinely in place (M3 Task 7 fix round 2).
-- `TaskStore::open` checks `PRAGMA user_version` BEFORE running this file
-- against an existing database, and migrates an older database (one that
-- pre-dates this pragma entirely, and so always reads back as 0) up to this
-- shape first -- see `open`'s own doc comment. Keep this in sync with
-- `tasks::CURRENT_SCHEMA_VERSION`.
PRAGMA user_version = 1;
