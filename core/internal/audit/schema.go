package audit

import (
	"database/sql"
	"fmt"
)

// schema defines all tables and indexes for the Tollgate audit database.
// Every statement uses CREATE IF NOT EXISTS — safe to run on every startup.
//
// SECURITY CONTRACT:
//   - The decisions table is append-only. No UPDATE or DELETE is ever issued
//     against it by application code. This is enforced at the application layer.
//   - WAL mode is enabled before migrations run to ensure safe concurrent reads.
//   - Foreign keys are enforced at the SQLite level.
const schema = `
CREATE TABLE IF NOT EXISTS decisions (
    id               TEXT     PRIMARY KEY,
    request_id       TEXT     NOT NULL,
    agent_id         TEXT     NOT NULL,
    decision         TEXT     NOT NULL CHECK(decision IN ('approved','denied','pending_human')),
    denial_code      TEXT,                   -- NULL if approved
    denial_reason    TEXT,                   -- NULL if approved
    action           TEXT     NOT NULL,
    destination      TEXT     NOT NULL,
    amount_usd       REAL     NOT NULL,
    amount_raw       TEXT     NOT NULL,      -- exact on-chain amount — no float precision loss
    purpose          TEXT     NOT NULL,
    chain_id         INTEGER  NOT NULL,
    nonce            TEXT     NOT NULL,
    policy_version   TEXT     NOT NULL,
    policy_hash      TEXT     NOT NULL,
    risk_score       REAL     NOT NULL,
    token_id         TEXT,                   -- NULL if denied
    token_expires_at DATETIME,              -- NULL if denied
    created_at       DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

-- Nonces table — replay attack prevention.
-- A nonce in this table was used. Period. Cleanup is for storage hygiene only.
CREATE TABLE IF NOT EXISTS used_nonces (
    nonce      TEXT     PRIMARY KEY,
    agent_id   TEXT     NOT NULL,
    used_at    DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    expires_at DATETIME NOT NULL
);

-- Revoked tokens — loaded entirely into memory on startup for sub-millisecond checks.
-- Persisted here so revocations survive server restarts.
CREATE TABLE IF NOT EXISTS revoked_tokens (
    token_id   TEXT     PRIMARY KEY,
    agent_id   TEXT     NOT NULL,
    revoked_at DATETIME NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    reason     TEXT
);

-- Behavioral baseline snapshots — one row per agent per hour window.
-- Used by the baseline engine to compute deviation scores over time.
CREATE TABLE IF NOT EXISTS baseline_snapshots (
    id           TEXT     PRIMARY KEY,
    agent_id     TEXT     NOT NULL,
    window_start DATETIME NOT NULL,
    window_end   DATETIME NOT NULL,
    tx_count     INTEGER  NOT NULL,
    total_usd    REAL     NOT NULL,
    avg_usd      REAL     NOT NULL,
    destinations TEXT     NOT NULL  -- JSON array of unique destination addresses
);

-- Indexes — keep queries fast as the audit log grows.
CREATE INDEX IF NOT EXISTS idx_decisions_agent   ON decisions(agent_id);
CREATE INDEX IF NOT EXISTS idx_decisions_created ON decisions(created_at);
CREATE INDEX IF NOT EXISTS idx_nonces_expires    ON used_nonces(expires_at);
CREATE INDEX IF NOT EXISTS idx_baseline_agent    ON baseline_snapshots(agent_id, window_start);
`

// runMigrations applies the schema to db.
// Idempotent — safe to call on every startup.
// Called before any other database operation in New().
func runMigrations(db *sql.DB) error {
	if _, err := db.Exec(schema); err != nil {
		return fmt.Errorf("audit: schema migration failed: %w", err)
	}
	return nil
}
