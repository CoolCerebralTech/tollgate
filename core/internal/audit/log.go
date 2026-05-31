package audit

import (
	"database/sql"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	_ "modernc.org/sqlite"
)

// DB is the Tollgate audit database.
// All public methods are safe for concurrent use.
// SECURITY CONTRACT:
//   - No UPDATE or DELETE is ever issued against the decisions table.
//   - Every query uses parameterized statements — zero string-formatted SQL.
//   - A failed audit write causes the request to be DENIED. No approval
//     exists without a corresponding audit record.
type DB struct {
	db *sql.DB
	mu sync.Mutex // serializes writes to prevent WAL contention
}

// DecisionRecord is the complete audit entry written for every policy evaluation.
// Approved and denied decisions both produce a full record.
type DecisionRecord struct {
	ID             string
	RequestID      string
	AgentID        string
	Decision       string // "approved" | "denied" | "pending_human"
	DenialCode     string // empty if approved
	DenialReason   string // empty if approved
	Action         string
	Destination    string
	AmountUSD      float64
	AmountRaw      string
	Purpose        string
	ChainID        int64
	Nonce          string
	PolicyVersion  string
	PolicyHash     string
	RiskScore      float64
	TokenID        string    // empty if denied
	TokenExpiresAt time.Time // zero if denied
}

// New opens the SQLite database at path, configures it for production use,
// and runs schema migrations. Returns a ready-to-use DB or a fatal error.
//
// Configuration applied:
//   - WAL mode      : allows concurrent reads while a write is in progress
//   - Foreign keys  : enforced at the SQLite engine level
//   - Busy timeout  : 5 seconds before returning SQLITE_BUSY
//   - Cache size    : 8 MB in-memory page cache for read performance
func New(path string) (*DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("audit: failed to open database at %q: %w", path, err)
	}

	// Limit to one writer connection — SQLite handles concurrency best this way.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	// Apply critical PRAGMA settings before any other operation.
	pragmas := []string{
		`PRAGMA journal_mode=WAL`,   // non-blocking concurrent reads
		`PRAGMA foreign_keys=ON`,    // enforce referential integrity
		`PRAGMA busy_timeout=5000`,  // wait up to 5s on a locked database
		`PRAGMA synchronous=NORMAL`, // safe under WAL, faster than FULL
		`PRAGMA cache_size=-8192`,   // 8 MB page cache
		`PRAGMA temp_store=MEMORY`,  // temp tables in RAM
	}
	for _, p := range pragmas {
		if _, err := db.Exec(p); err != nil {
			return nil, fmt.Errorf("audit: failed to set pragma %q: %w", p, err)
		}
	}

	// Verify the database is reachable before claiming success.
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("audit: database ping failed: %w", err)
	}

	// Run schema migrations — idempotent, safe on every startup.
	if err := runMigrations(db); err != nil {
		return nil, err
	}

	adb := &DB{db: db}

	// Load expired-nonce cleanup goroutine. Runs every 10 minutes.
	// This is purely for storage hygiene — security is enforced at write time.
	go adb.nonceCleanupLoop()

	return adb, nil
}

// Close shuts down the database cleanly. Called during graceful server shutdown.
func (a *DB) Close() error {
	return a.db.Close()
}

// Ping verifies the database connection is alive. Used by the health endpoint.
func (a *DB) Ping() error {
	return a.db.Ping()
}

// ── Decision writes ───────────────────────────────────────────────────────────

// WriteDecision appends a complete policy evaluation record to the decisions table.
//
// SECURITY: This must complete successfully before a response is sent to the agent.
// If this write fails, the caller MUST return a denial — an unrecorded approval
// does not exist as far as Tollgate is concerned.
//
// This function never updates or deletes existing rows.
func (a *DB) WriteDecision(rec DecisionRecord) error {
	if rec.ID == "" {
		rec.ID = uuid.New().String()
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	// Normalize optional fields so SQLite receives NULL where appropriate.
	var denialCode, denialReason, tokenID sql.NullString
	var tokenExpiresAt sql.NullTime

	if rec.DenialCode != "" {
		denialCode = sql.NullString{String: rec.DenialCode, Valid: true}
	}
	if rec.DenialReason != "" {
		denialReason = sql.NullString{String: rec.DenialReason, Valid: true}
	}
	if rec.TokenID != "" {
		tokenID = sql.NullString{String: rec.TokenID, Valid: true}
	}
	if !rec.TokenExpiresAt.IsZero() {
		tokenExpiresAt = sql.NullTime{Time: rec.TokenExpiresAt, Valid: true}
	}

	const q = `
		INSERT INTO decisions
			(id, request_id, agent_id, decision, denial_code, denial_reason,
			 action, destination, amount_usd, amount_raw, purpose, chain_id,
			 nonce, policy_version, policy_hash, risk_score, token_id, token_expires_at)
		VALUES
			(?,  ?,          ?,        ?,        ?,           ?,
			 ?,      ?,           ?,          ?,          ?,       ?,
			 ?,     ?,             ?,           ?,          ?,        ?)`

	_, err := a.db.Exec(q,
		rec.ID, rec.RequestID, rec.AgentID, rec.Decision,
		denialCode, denialReason,
		rec.Action, rec.Destination, rec.AmountUSD, rec.AmountRaw,
		rec.Purpose, rec.ChainID,
		rec.Nonce, rec.PolicyVersion, rec.PolicyHash,
		rec.RiskScore, tokenID, tokenExpiresAt,
	)
	if err != nil {
		return fmt.Errorf("audit: WriteDecision failed: %w", err)
	}
	return nil
}

// ── Nonce management ─────────────────────────────────────────────────────────

// IsNonceUsed reports whether nonce has been seen before within its validity window.
// Returns true (block the request) on any database error — fail closed.
func (a *DB) IsNonceUsed(nonce string) (bool, error) {
	const q = `SELECT 1 FROM used_nonces WHERE nonce = ? AND expires_at > ? LIMIT 1`
	row := a.db.QueryRow(q, nonce, time.Now().UTC())

	var dummy int
	err := row.Scan(&dummy)
	switch err {
	case nil:
		return true, nil // nonce exists and is still valid — replay attempt
	case sql.ErrNoRows:
		return false, nil // nonce is fresh
	default:
		// Database error — fail closed (treat as used to prevent bypass).
		return true, fmt.Errorf("audit: IsNonceUsed query failed: %w", err)
	}
}

// RecordNonce stores nonce so future requests with the same nonce are rejected.
// expiresAt should be now + nonce_window_seconds from the policy config.
func (a *DB) RecordNonce(nonce, agentID string, expiresAt time.Time) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	const q = `
		INSERT INTO used_nonces (nonce, agent_id, expires_at)
		VALUES (?, ?, ?)
		ON CONFLICT(nonce) DO NOTHING`

	_, err := a.db.Exec(q, nonce, agentID, expiresAt.UTC())
	if err != nil {
		return fmt.Errorf("audit: RecordNonce failed: %w", err)
	}
	return nil
}

// nonceCleanupLoop deletes expired nonces every 10 minutes.
// This is storage hygiene only — expired nonces are already excluded by
// IsNonceUsed's WHERE clause.
func (a *DB) nonceCleanupLoop() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		a.mu.Lock()
		_, _ = a.db.Exec(`DELETE FROM used_nonces WHERE expires_at <= ?`, time.Now().UTC())
		a.mu.Unlock()
	}
}

// ── Token revocation ──────────────────────────────────────────────────────────

// WriteRevocation persists a token revocation to SQLite so it survives restarts.
// The in-memory revocation list in the agent registry is updated separately
// and is the primary check path (sub-millisecond). This write is the backup.
func (a *DB) WriteRevocation(tokenID, agentID, reason string) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	const q = `
		INSERT INTO revoked_tokens (token_id, agent_id, reason)
		VALUES (?, ?, ?)
		ON CONFLICT(token_id) DO NOTHING`

	_, err := a.db.Exec(q, tokenID, agentID, reason)
	if err != nil {
		return fmt.Errorf("audit: WriteRevocation failed: %w", err)
	}
	return nil
}

// LoadAllRevocations returns all revoked token IDs from SQLite.
// Called once on startup to populate the in-memory revocation map.
func (a *DB) LoadAllRevocations() (map[string]bool, error) {
	const q = `SELECT token_id FROM revoked_tokens`
	rows, err := a.db.Query(q)
	if err != nil {
		return nil, fmt.Errorf("audit: LoadAllRevocations query failed: %w", err)
	}
	defer rows.Close()

	revoked := make(map[string]bool)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("audit: LoadAllRevocations scan failed: %w", err)
		}
		revoked[id] = true
	}
	return revoked, rows.Err()
}

// ── Spend limit queries ───────────────────────────────────────────────────────

// SumApprovedUSD returns the total USD approved for agentID since the given time.
// Used by the policy engine to enforce hourly and daily spend limits.
//
// SECURITY: Returns (0, err) on database failure. The policy engine treats any
// error from this function as an automatic DENY — fail closed.
func (a *DB) SumApprovedUSD(agentID string, since time.Time) (float64, error) {
	const q = `
		SELECT COALESCE(SUM(amount_usd), 0)
		FROM   decisions
		WHERE  agent_id = ?
		AND    decision  = 'approved'
		AND    created_at >= ?`

	// Truncate to millisecond and format with exactly 3 fractional digits.
	// This MUST match the precision of created_at (strftime('%f') = 3 digits).
	// If the string lengths differ, SQLite's lexicographic text comparison
	// will produce incorrect results for times with non-zero sub-second values.
	formattedSince := since.UTC().Truncate(time.Millisecond).Format("2006-01-02T15:04:05.000Z")

	row := a.db.QueryRow(q, agentID, formattedSince)
	var total float64
	if err := row.Scan(&total); err != nil {
		return 0, fmt.Errorf("audit: SumApprovedUSD failed: %w", err)
	}
	return total, nil
}

// ── Baseline snapshots ────────────────────────────────────────────────────────

// WriteBaselineSnapshot persists a behavioral baseline snapshot for an agent.
// Called asynchronously — does not block the request response path.
func (a *DB) WriteBaselineSnapshot(
	agentID string,
	windowStart, windowEnd time.Time,
	txCount int,
	totalUSD, avgUSD float64,
	destinationsJSON string,
) error {
	a.mu.Lock()
	defer a.mu.Unlock()

	const q = `
		INSERT INTO baseline_snapshots
			(id, agent_id, window_start, window_end, tx_count, total_usd, avg_usd, destinations)
		VALUES
			(?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := a.db.Exec(q,
		uuid.New().String(),
		agentID,
		windowStart.UTC(),
		windowEnd.UTC(),
		txCount,
		totalUSD,
		avgUSD,
		destinationsJSON,
	)
	if err != nil {
		return fmt.Errorf("audit: WriteBaselineSnapshot failed: %w", err)
	}
	return nil
}

// LoadBaselineSnapshots returns all snapshots for agentID within the given window.
// Used by the baseline engine on startup or when rebuilding an agent's history.
func (a *DB) LoadBaselineSnapshots(agentID string, since time.Time) ([]BaselineSnapshot, error) {
	const q = `
		SELECT id, agent_id, window_start, window_end, tx_count, total_usd, avg_usd, destinations
		FROM   baseline_snapshots
		WHERE  agent_id = ?
		AND    window_start >= ?
		ORDER  BY window_start ASC`

	rows, err := a.db.Query(q, agentID, since.UTC())
	if err != nil {
		return nil, fmt.Errorf("audit: LoadBaselineSnapshots query failed: %w", err)
	}
	defer rows.Close()

	var snaps []BaselineSnapshot
	for rows.Next() {
		var s BaselineSnapshot
		if err := rows.Scan(
			&s.ID, &s.AgentID,
			&s.WindowStart, &s.WindowEnd,
			&s.TxCount, &s.TotalUSD, &s.AvgUSD,
			&s.DestinationsJSON,
		); err != nil {
			return nil, fmt.Errorf("audit: LoadBaselineSnapshots scan failed: %w", err)
		}
		snaps = append(snaps, s)
	}
	return snaps, rows.Err()
}

// BaselineSnapshot is a single persisted behavioral snapshot for one agent.
type BaselineSnapshot struct {
	ID               string
	AgentID          string
	WindowStart      time.Time
	WindowEnd        time.Time
	TxCount          int
	TotalUSD         float64
	AvgUSD           float64
	DestinationsJSON string
}
