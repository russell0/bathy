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
