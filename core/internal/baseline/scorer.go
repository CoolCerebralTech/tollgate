package baseline

import (
	"math"
	"time"
)

// Scorer computes behavioral risk scores for agent requests.
// It implements the policy.BaselineScorer interface.
//
// Risk score formula (weights must sum to 1.0):
//
//	frequency_score  * 0.35
//	amount_score     * 0.40
//	destination_score* 0.15
//	timing_score     * 0.10
//
// All component scores are clamped to [0.0, 1.0].
// Final score is in [0.0, 1.0] — higher means more anomalous.
//
// If the agent has fewer than minDataPoints history records, Score() returns
// 0.0 unconditionally. Not enough history to establish a baseline.
type Scorer struct {
	tracker *Tracker
}

// NewScorer creates a Scorer backed by the given Tracker.
func NewScorer(tracker *Tracker) *Scorer {
	return &Scorer{tracker: tracker}
}

// Score computes the risk score for a proposed transaction.
// Returns 0.0 if there is insufficient history (< minDataPoints).
// Never returns a value outside [0.0, 1.0].
func (s *Scorer) Score(agentID, destination string, amountUSD float64) float64 {
	history := s.tracker.Snapshot(agentID)

	// Not enough history — no false positives for new agents.
	if len(history) < minDataPoints {
		return 0.0
	}

	// ── Component 1: Frequency Score (weight 0.35) ────────────────────────────
	// A spike to 3x the historical average request rate scores 1.0.
	avgRPH := avgRequestsPerHour(history)
	currentRPH := requestsPerHour(history)
	frequencyScore := 0.0
	if avgRPH > 0 {
		frequencyScore = math.Min(1.0, currentRPH/(avgRPH*3.0))
	}

	// ── Component 2: Amount Score (weight 0.40) ───────────────────────────────
	// Uses Z-score normalization. More than 2 standard deviations from the mean
	// starts producing a non-zero score. Beyond 4 std devs scores 1.0.
	mean, std := amountStats(history)
	amountScore := 0.0
	if std > 0 {
		zScore := math.Abs(amountUSD-mean) / std
		// Map Z-score to [0, 1]: below 2 std devs = 0, above 4 std devs = 1
		amountScore = math.Min(1.0, math.Max(0.0, (zScore-2.0)/2.0))
	} else if amountUSD != mean {
		// All historical amounts identical and current amount differs -> max anomaly
		amountScore = 1.0
	}

	// ── Component 3: Destination Score (weight 0.15) ──────────────────────────
	// New destination = 1.0. Known destination = 0.0.
	destinations := knownDestinations(history)
	destinationScore := 0.0
	if !destinations[destination] {
		destinationScore = 1.0
	}

	// ── Component 4: Timing Score (weight 0.10) ───────────────────────────────
	// Request at an unusual hour for this agent = 1.0.
	// Use the current UTC hour, NOT the hour of the most recent transaction.
	currentHour := time.Now().UTC().Hour()
	hours := normalHours(history)
	timingScore := 0.0
	if !hours[currentHour] {
		timingScore = 1.0
	}

	// ── Weighted combination ──────────────────────────────────────────────────
	final := (frequencyScore * 0.35) +
		(amountScore * 0.40) +
		(destinationScore * 0.15) +
		(timingScore * 0.10)

	// Clamp to [0.0, 1.0] — floating-point arithmetic can drift slightly.
	return math.Min(1.0, math.Max(0.0, final))
}

// Record appends a transaction to the agent's history.
// Must be called AFTER an approval — baseline reflects approved behavior only.
func (s *Scorer) Record(agentID, destination string, amountUSD float64) {
	s.tracker.Record(agentID, destination, amountUSD)
}
