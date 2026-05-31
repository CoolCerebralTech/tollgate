package ratelimit

import (
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/time/rate"
)

// Limiter manages two layers of rate limiting:
//  1. A global limiter — caps total server throughput.
//  2. Per-agent limiters — caps throughput per individual agent.
//
// Both use the token bucket algorithm via golang.org/x/time/rate.
// All operations are safe for concurrent use.
//
// SECURITY CONTRACT:
//   - Global limit is checked first. If it fails, per-agent check is skipped.
//   - Per-agent limiters are created lazily on first request from that agent.
//   - Stale per-agent limiters (no requests in 1 hour) are cleaned up
//     by a background goroutine to prevent unbounded memory growth.
type Limiter struct {
	global *rate.Limiter

	mu     sync.RWMutex
	agents map[string]*agentLimiter

	agentRPS   rate.Limit
	agentBurst int
}

type agentLimiter struct {
	limiter  *rate.Limiter
	lastSeen atomic.Int64 // UnixNano — set atomically from multiple goroutines
}

// New creates a Limiter with the given global and per-agent rate limits.
// globalRPS: maximum total requests per second across all agents.
// agentRPS:  maximum requests per second for a single agent.
// agentBurst: burst allowance for a single agent.
func New(globalRPS, agentRPS, agentBurst int) *Limiter {
	l := &Limiter{
		global:     rate.NewLimiter(rate.Limit(globalRPS), globalRPS*2),
		agents:     make(map[string]*agentLimiter),
		agentRPS:   rate.Limit(agentRPS),
		agentBurst: agentBurst,
	}
	go l.cleanupLoop()
	return l
}

// AllowGlobal checks whether the global rate limit allows this request.
// Returns false if the global limit is exceeded — request must be rejected with 429.
func (l *Limiter) AllowGlobal() bool {
	return l.global.Allow()
}

// AllowAgent checks whether the per-agent rate limit allows this request.
// Creates a new limiter for the agent if one does not exist.
// Returns false if the agent's limit is exceeded — request must be rejected with 429.
func (l *Limiter) AllowAgent(agentID string) bool {
	l.mu.RLock()
	al, ok := l.agents[agentID]
	l.mu.RUnlock()

	if ok {
		// Update lastSeen atomically — no race with other readers/writers.
		al.lastSeen.Store(time.Now().UnixNano())
		return al.limiter.Allow()
	}

	// First request from this agent — create a new limiter.
	l.mu.Lock()
	// Double-check after acquiring write lock to avoid duplicate creation.
	if al, ok = l.agents[agentID]; ok {
		l.mu.Unlock()
		al.lastSeen.Store(time.Now().UnixNano())
		return al.limiter.Allow()
	}
	newAL := &agentLimiter{
		limiter: rate.NewLimiter(l.agentRPS, l.agentBurst),
	}
	newAL.lastSeen.Store(time.Now().UnixNano())
	l.agents[agentID] = newAL
	l.mu.Unlock()

	return newAL.limiter.Allow()
}

// cleanupLoop removes per-agent limiters that have not been used in 1 hour.
// Runs as a background goroutine for the lifetime of the server.
func (l *Limiter) cleanupLoop() {
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		cutoff := time.Now().Add(-1 * time.Hour).UnixNano()
		l.mu.Lock()
		for id, al := range l.agents {
			if al.lastSeen.Load() < cutoff {
				delete(l.agents, id)
			}
		}
		l.mu.Unlock()
	}
}
