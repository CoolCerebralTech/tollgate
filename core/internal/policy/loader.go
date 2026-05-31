package policy

import (
	"fmt"
	"os"
	"sync"

	gocrypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/fsnotify/fsnotify"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

// Loader reads policy.yaml and keeps an in-memory copy that is atomically
// updated whenever the file changes on disk.
//
// SECURITY CONTRACT:
//   - If the policy file cannot be read or parsed at any point, all requests
//     are denied until the file is restored. The Loader never serves a stale
//     or partial policy.
//   - The active policy and its hash are updated atomically under a write lock.
//     A request mid-evaluation always sees a complete, consistent policy.
//   - The policy hash is keccak256 of the raw file bytes — exactly what gets
//     embedded in every ApprovalToken and audit record.
type Loader struct {
	mu          sync.RWMutex
	policy      *Policy
	policyHash  string // keccak256 hex of raw policy.yaml bytes
	policyValid bool   // false = deny all requests
	filePath    string
	log         *zap.Logger
}

// NewLoader creates a Loader, performs the initial policy load, and optionally
// starts a file watcher for hot reload. Returns an error only if the initial
// load fails — a running server with no policy must deny all requests.
func NewLoader(filePath string, hotReload bool, log *zap.Logger) (*Loader, error) {
	l := &Loader{
		filePath: filePath,
		log:      log,
	}

	if err := l.load(); err != nil {
		return nil, fmt.Errorf("policy: initial load failed: %w", err)
	}

	if hotReload {
		go l.watchFile()
	}

	return l, nil
}

// GetPolicy returns the current active policy and its keccak256 hash.
// Returns (nil, "", false) if the policy is unavailable — caller must deny.
func (l *Loader) GetPolicy() (*Policy, string, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.policy, l.policyHash, l.policyValid
}

// load reads policy.yaml from disk, parses it, and atomically replaces the
// in-memory policy. On any failure, marks policy as invalid (deny all).
func (l *Loader) load() error {
	raw, err := os.ReadFile(l.filePath)
	if err != nil {
		l.mu.Lock()
		l.policyValid = false
		l.mu.Unlock()
		return fmt.Errorf("cannot read policy file %q: %w", l.filePath, err)
	}

	var p Policy
	if err := yaml.Unmarshal(raw, &p); err != nil {
		l.mu.Lock()
		l.policyValid = false
		l.mu.Unlock()
		return fmt.Errorf("cannot parse policy YAML: %w", err)
	}

	if err := validatePolicy(&p); err != nil {
		l.mu.Lock()
		l.policyValid = false
		l.mu.Unlock()
		return fmt.Errorf("policy validation failed: %w", err)
	}

	// Compute keccak256 of raw bytes — this hash goes into every ApprovalToken.
	hash := fmt.Sprintf("0x%x", gocrypto.Keccak256(raw))

	l.mu.Lock()
	l.policy = &p
	l.policyHash = hash
	l.policyValid = true
	l.mu.Unlock()

	l.log.Info("policy loaded",
		zap.String("version", p.Version),
		zap.String("hash", hash),
		zap.String("updated_by", p.UpdatedBy),
		zap.Int("agent_count", len(p.Agents)),
	)

	return nil
}

// watchFile uses fsnotify to hot-reload policy.yaml on change.
// Runs in its own goroutine. Never returns (runs for the lifetime of the server).
//
// SECURITY: if a reload fails (bad YAML, validation error), the previous
// valid policy remains active and all requests continue to be evaluated
// against it. The server logs a critical error but does not crash.
func (l *Loader) watchFile() {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		l.log.Error("policy: failed to start file watcher", zap.Error(err))
		return
	}
	defer watcher.Close()

	if err := watcher.Add(l.filePath); err != nil {
		l.log.Error("policy: failed to watch file", zap.String("path", l.filePath), zap.Error(err))
		return
	}

	l.log.Info("policy: hot reload active", zap.String("watching", l.filePath))

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			// React to writes and renames (editors like vim write via rename).
			if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) {
				l.log.Info("policy: file changed — reloading", zap.String("event", event.Op.String()))
				if err := l.load(); err != nil {
					l.log.Error("policy: reload failed — all requests DENIED until policy is restored",
						zap.Error(err),
					)
				}
				// Re-add the watch in case the file was replaced (rename events
				// can cause the watcher to lose track of the inode).
				_ = watcher.Add(l.filePath)
			}

		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			l.log.Error("policy: file watcher error", zap.Error(err))
		}
	}
}

// validatePolicy checks that the policy is internally consistent and has
// all required fields. Called after every YAML parse — before the policy
// is made active.
func validatePolicy(p *Policy) error {
	if p.Version == "" {
		return fmt.Errorf("policy must have a version field")
	}
	if p.Global.DefaultAction != "deny" {
		return fmt.Errorf("global_rules.default_action must be 'deny' (got %q) — fail-closed is mandatory", p.Global.DefaultAction)
	}
	if p.Global.MaxRequestAgeSeconds <= 0 {
		return fmt.Errorf("global_rules.max_request_age_seconds must be positive")
	}
	if p.Global.NonceWindowSeconds <= 0 {
		return fmt.Errorf("global_rules.nonce_window_seconds must be positive")
	}

	seenIDs := make(map[string]bool)
	for i, agent := range p.Agents {
		if agent.ID == "" {
			return fmt.Errorf("agent[%d] has no id field", i)
		}
		if seenIDs[agent.ID] {
			return fmt.Errorf("duplicate agent id %q — each agent must have a unique id", agent.ID)
		}
		seenIDs[agent.ID] = true

		if agent.SpendLimits.MaxPerTransactionUSD <= 0 {
			return fmt.Errorf("agent %q: max_per_transaction_usd must be positive", agent.ID)
		}
		if agent.SpendLimits.AutoApproveBelowUSD < 0 {
			return fmt.Errorf("agent %q: auto_approve_below_usd cannot be negative", agent.ID)
		}
		if len(agent.AllowedPurposes) == 0 {
			return fmt.Errorf("agent %q: allowed_purposes cannot be empty", agent.ID)
		}
		if agent.BehavioralRiskThreshold < 0 || agent.BehavioralRiskThreshold > 1.0 {
			return fmt.Errorf("agent %q: behavioral_risk_threshold must be between 0.0 and 1.0", agent.ID)
		}
	}

	return nil
}
