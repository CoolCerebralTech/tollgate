package baseline

import (
	"math"
	"sync"
	"time"
)

// txRecord is a single observed transaction stored in the agent's history.
type txRecord struct {
	timestamp   time.Time
	amountUSD   float64
	destination string
	hourOfDay   int
}

// agentStats holds the rolling behavioral history for one agent.
type agentStats struct {
	mu      sync.RWMutex
	history []txRecord // ordered oldest → newest
}

// Tracker maintains in-memory behavioral history for every registered agent.
// It is the data store that the Scorer reads from.
//
// SECURITY CONTRACT:
//   - A new agent with fewer than minDataPoints observations always returns
//     a risk score of 0.0. This prevents false positives on new agents.
//   - Record() is called AFTER a successful approval — not before.
//     The baseline reflects real approved behavior, not attempted behavior.
//   - All operations are safe for concurrent use.
type Tracker struct {
	mu     sync.RWMutex
	agents map[string]*agentStats

	// maxHistory is the maximum number of records kept per agent in memory.
	// Older records beyond this window are dropped.
	maxHistory int
}

// minDataPoints is the minimum number of approved transactions required before
// the baseline engine starts issuing non-zero risk scores.
// Below this threshold the engine returns 0.0 — not enough history to judge.
const minDataPoints = 20

// NewTracker creates a Tracker with a rolling window of maxHistory records per agent.
func NewTracker(maxHistory int) *Tracker {
	if maxHistory <= 0 {
		maxHistory = 500
	}
	return &Tracker{
		agents:     make(map[string]*agentStats),
		maxHistory: maxHistory,
	}
}

// Record appends a transaction to the agent's history.
// Called asynchronously after every approved transaction.
func (t *Tracker) Record(agentID, destination string, amountUSD float64) {
	t.mu.Lock()
	stats, ok := t.agents[agentID]
	if !ok {
		stats = &agentStats{}
		t.agents[agentID] = stats
	}
	t.mu.Unlock()

	rec := txRecord{
		timestamp:   time.Now().UTC(),
		amountUSD:   amountUSD,
		destination: destination,
		hourOfDay:   time.Now().UTC().Hour(),
	}

	stats.mu.Lock()
	defer stats.mu.Unlock()

	stats.history = append(stats.history, rec)

	// Trim to maxHistory — drop oldest records first.
	if len(stats.history) > t.maxHistory {
		stats.history = stats.history[len(stats.history)-t.maxHistory:]
	}
}

// Snapshot returns a copy of the agent's history for scoring.
// Returns nil if the agent has no history.
func (t *Tracker) Snapshot(agentID string) []txRecord {
	t.mu.RLock()
	stats, ok := t.agents[agentID]
	t.mu.RUnlock()

	if !ok {
		return nil
	}

	stats.mu.RLock()
	defer stats.mu.RUnlock()

	if len(stats.history) == 0 {
		return nil
	}

	cp := make([]txRecord, len(stats.history))
	copy(cp, stats.history)
	return cp
}

// ── Derived metrics — read from a snapshot ───────────────────────────────────

// requestsPerHour returns the number of approved transactions in the last hour.
func requestsPerHour(history []txRecord) float64 {
	cutoff := time.Now().UTC().Add(-1 * time.Hour)
	count := 0
	for _, r := range history {
		if r.timestamp.After(cutoff) {
			count++
		}
	}
	return float64(count)
}

// amountStats returns the mean and standard deviation of transaction amounts.
func amountStats(history []txRecord) (mean, std float64) {
	if len(history) == 0 {
		return 0, 0
	}
	sum := 0.0
	for _, r := range history {
		sum += r.amountUSD
	}
	mean = sum / float64(len(history))

	variance := 0.0
	for _, r := range history {
		d := r.amountUSD - mean
		variance += d * d
	}
	variance /= float64(len(history))
	std = math.Sqrt(variance)
	return mean, std
}

// knownDestinations returns a set of all destinations the agent has used before.
func knownDestinations(history []txRecord) map[string]bool {
	seen := make(map[string]bool, len(history))
	for _, r := range history {
		seen[r.destination] = true
	}
	return seen
}

// normalHours returns the set of hours-of-day (UTC) the agent normally transacts in.
func normalHours(history []txRecord) map[int]bool {
	seen := make(map[int]bool)
	for _, r := range history {
		seen[r.hourOfDay] = true
	}
	return seen
}

// avgRequestsPerHour computes the agent's historical average hourly transaction rate
// by looking at full 1-hour windows in the history.
func avgRequestsPerHour(history []txRecord) float64 {
	if len(history) < 2 {
		return 1.0 // safe default — avoids division-by-zero
	}
	// Simple approach: total records / total hours spanned
	oldest := history[0].timestamp
	newest := history[len(history)-1].timestamp
	hours := newest.Sub(oldest).Hours()
	if hours < 1 {
		hours = 1
	}
	return float64(len(history)) / hours
}
