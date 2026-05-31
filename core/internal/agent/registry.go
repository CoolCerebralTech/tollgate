package agent

import (
	"fmt"
	"sync"

	"go.uber.org/zap"
)

// RevocationStore is implemented by the audit DB.
// The registry uses it to persist revocations across restarts.
type RevocationStore interface {
	WriteRevocation(tokenID, agentID, reason string) error
	LoadAllRevocations() (map[string]bool, error)
}

// Registry manages agent token revocations and provides agent validation helpers.
//
// SECURITY CONTRACT:
//   - Revocation list is in-memory for sub-millisecond checks on every request.
//   - Revocations are also persisted to SQLite so they survive server restarts.
//   - On startup, all existing revocations are loaded from SQLite into memory.
//   - IsRevoked() is checked before any other validation on every request.
type Registry struct {
	mu        sync.RWMutex
	revoked   map[string]bool // tokenID → revoked
	store     RevocationStore
	secretHex string // AGENT_TOKEN_SECRET — used for token issuance only
	log       *zap.Logger
}

// NewRegistry creates a Registry, loads existing revocations from the store,
// and returns a ready-to-use Registry.
func NewRegistry(store RevocationStore, secretHex string, log *zap.Logger) (*Registry, error) {
	r := &Registry{
		revoked:   make(map[string]bool),
		store:     store,
		secretHex: secretHex,
		log:       log,
	}

	// Load all existing revocations from SQLite into memory.
	existing, err := store.LoadAllRevocations()
	if err != nil {
		return nil, fmt.Errorf("agent: failed to load revocations from store: %w", err)
	}
	r.revoked = existing

	log.Info("agent registry initialized",
		zap.Int("revoked_tokens_loaded", len(existing)),
	)

	return r, nil
}

// IsRevoked reports whether tokenID has been revoked.
// This is checked on every single request — it must be fast.
// Returns true (block the request) if tokenID is in the revocation list.
func (r *Registry) IsRevoked(tokenID string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.revoked[tokenID]
}

// RevokeToken adds tokenID to the in-memory revocation list and persists it
// to SQLite. Effect is immediate — under 1ms.
func (r *Registry) RevokeToken(tokenID, agentID, reason string) error {
	// Persist to SQLite first — if this fails, do not update in-memory state.
	// A failed persist means the revocation would be lost on restart.
	if err := r.store.WriteRevocation(tokenID, agentID, reason); err != nil {
		return fmt.Errorf("agent: failed to persist revocation for token %s: %w", tokenID, err)
	}

	r.mu.Lock()
	r.revoked[tokenID] = true
	r.mu.Unlock()

	r.log.Warn("agent token revoked",
		zap.String("token_id", tokenID),
		zap.String("agent_id", agentID),
		zap.String("reason", reason),
	)

	return nil
}

// Verify parses and validates a raw token string.
// Checks signature, expiry, and revocation list — in that order.
// Returns claims on success, error on any failure.
//
// SECURITY: Error messages are intentionally generic — never reveal which
// check failed. The 401 response to the client must be equally generic.
func (r *Registry) Verify(tokenStr string) (*AgentTokenClaims, error) {
	claims, err := VerifyToken(tokenStr, r.secretHex)
	if err != nil {
		// Do not wrap — the error message from VerifyToken is already generic.
		return nil, err
	}

	// Check revocation AFTER signature verification.
	// This order prevents timing-based enumeration of revoked token IDs.
	if r.IsRevoked(claims.TokenID) {
		return nil, fmt.Errorf("agent: unauthorized")
	}

	return claims, nil
}

// IssueToken creates a new signed agent token for agentID valid for 30 days.
// Used by the admin tooling and tests — not called in the hot request path.
func (r *Registry) IssueToken(agentID string) (string, error) {
	const thirtyDays = 30 * 24 * 60 * 60 * 1e9 // nanoseconds
	token, err := IssueToken(agentID, r.secretHex, thirtyDays)
	if err != nil {
		return "", fmt.Errorf("agent: IssueToken failed: %w", err)
	}
	return token, nil
}
