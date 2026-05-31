package policy

import (
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"
)

// SpendChecker is implemented by the audit DB layer.
// The engine calls it to enforce hourly and daily spend limits without
// importing the audit package directly (avoids circular imports).
type SpendChecker interface {
	SumApprovedUSD(agentID string, since time.Time) (float64, error)
	IsNonceUsed(nonce string) (bool, error)
	RecordNonce(nonce, agentID string, expiresAt time.Time) error
}

// BaselineScorer is implemented by the baseline package.
// Returns a risk score 0.0–1.0 for the given agent and request amount.
type BaselineScorer interface {
	Score(agentID, destination string, amountUSD float64) float64
	Record(agentID, destination string, amountUSD float64)
}

// Engine is the policy evaluation judge.
// It is stateless — all state lives in the Loader, audit DB, and baseline scorer.
// The same input always produces the same output (deterministic).
//
// SECURITY CONTRACT:
//   - Checks run in strict order. First failure stops evaluation immediately.
//   - Any internal error (DB failure, unexpected panic) returns DENIED.
//   - If the policy is unavailable, ALL requests are denied.
//   - Zero-amount requests are always denied — hardcoded, not configurable.
type Engine struct {
	loader   *Loader
	spend    SpendChecker
	baseline BaselineScorer
	log      *zap.Logger
}

// NewEngine constructs a policy Engine with all required dependencies.
func NewEngine(loader *Loader, spend SpendChecker, baseline BaselineScorer, log *zap.Logger) *Engine {
	return &Engine{
		loader:   loader,
		spend:    spend,
		baseline: baseline,
		log:      log,
	}
}

// Evaluate runs the 11-check evaluation pipeline against req.
// Returns a complete EvaluationResult — never returns an error directly.
// All errors are translated into a DENIED result with CodeInternalError.
//
// CHECK ORDER (do not reorder — order is security-critical):
//  1. Request age
//  2. Nonce uniqueness
//  3. Agent existence
//  4. Agent enabled
//  5. Purpose binding
//  6. Blocked destination
//  7. Allowed destination
//  8. Per-transaction spend limit
//  9. Hourly + daily spend limit
//
// 10. Behavioral baseline score
// 11. Route decision (approve / pending human)
func (e *Engine) Evaluate(req ActionRequest) EvaluationResult {
	// ── Load active policy ────────────────────────────────────────────────────
	p, policyHash, valid := e.loader.GetPolicy()
	if !valid || p == nil {
		e.log.Error("policy unavailable — denying all requests")
		return deny(CodePolicyUnavailable, "Policy file is unavailable. All requests denied until restored.", 0, policyHash, "")
	}

	// ── Hardcoded law: zero amount is always denied ───────────────────────────
	// No YAML rule can override this. There is no legitimate reason for an AI
	// agent to request approval for a zero-value transaction.
	if req.AmountUSD <= 0 {
		return deny(CodeZeroAmount, "Zero or negative amount transactions are never permitted.", 0, policyHash, p.Version)
	}

	// ── CHECK 1: Request Age ──────────────────────────────────────────────────
	// Rejects replayed requests captured from the network.
	maxAge := time.Duration(p.Global.MaxRequestAgeSeconds) * time.Second
	if time.Since(req.Timestamp) > maxAge {
		return deny(CodeRequestExpired,
			fmt.Sprintf("Request timestamp is too old (max age: %ds). Possible replay attack.", p.Global.MaxRequestAgeSeconds),
			0, policyHash, p.Version,
		)
	}

	// ── CHECK 2: Nonce Uniqueness ─────────────────────────────────────────────
	// Prevents an attacker from replaying a captured approved request.
	if p.Global.RequireNonce {
		if req.Nonce == "" {
			return deny(CodeNonceReplay, "Nonce is required but missing.", 0, policyHash, p.Version)
		}
		used, err := e.spend.IsNonceUsed(req.Nonce)
		if err != nil {
			e.log.Error("nonce check DB error — failing closed", zap.Error(err))
			return deny(CodeInternalError, "Internal error during nonce validation.", 0, policyHash, p.Version)
		}
		if used {
			return deny(CodeNonceReplay, "Nonce has already been used. Possible replay attack.", 0, policyHash, p.Version)
		}
	}

	// ── CHECK 3: Agent Existence ──────────────────────────────────────────────
	// Unknown agents are ALWAYS denied. There is no default policy.
	agent := findAgent(p, req.AgentID)
	if agent == nil {
		return deny(CodeAgentUnknown,
			fmt.Sprintf("Agent %q is not registered in this policy.", req.AgentID),
			0, policyHash, p.Version,
		)
	}

	// ── CHECK 4: Agent Enabled ────────────────────────────────────────────────
	// Setting enabled: false is how a compromised agent is instantly killed.
	if !agent.Enabled {
		return deny(CodeAgentDisabled,
			fmt.Sprintf("Agent %q is disabled.", req.AgentID),
			0, policyHash, p.Version,
		)
	}

	// ── CHECK 5: Purpose Binding ──────────────────────────────────────────────
	// The request purpose must EXACTLY match one of the agent's allowed purposes.
	// Case-sensitive. This is what stops the Grok NFT-style permission expansion.
	if !purposeAllowed(agent, req.Purpose) {
		return deny(CodePurposeMismatch,
			fmt.Sprintf("Purpose %q is not in the agent's allowed_purposes list.", req.Purpose),
			0, policyHash, p.Version,
		)
	}

	// ── CHECK 6: Blocked Destination ─────────────────────────────────────────
	// Explicit deny list is checked BEFORE the allow list. Always.
	if destinationBlocked(agent, req.Destination) {
		return deny(CodeDestinationBlocked,
			fmt.Sprintf("Destination %q is on the blocked_destinations list.", req.Destination),
			0, policyHash, p.Version,
		)
	}

	// ── CHECK 7: Allowed Destination ─────────────────────────────────────────
	// Destination must be explicitly whitelisted.
	if !destinationAllowed(agent, req.Destination) {
		return deny(CodeDestinationNotAllowed,
			fmt.Sprintf("Destination %q is not in the agent's allowed_destinations list.", req.Destination),
			0, policyHash, p.Version,
		)
	}

	// ── CHECK 8: Per-Transaction Spend Limit ──────────────────────────────────
	if req.AmountUSD > agent.SpendLimits.MaxPerTransactionUSD {
		return deny(CodeExceedsTransactionLimit,
			fmt.Sprintf("Amount $%.2f exceeds per-transaction limit of $%.2f.",
				req.AmountUSD, agent.SpendLimits.MaxPerTransactionUSD),
			0, policyHash, p.Version,
		)
	}

	// ── CHECK 9: Hourly + Daily Spend Limits ──────────────────────────────────
	// Query the audit log for approved totals within each window.
	// DB errors fail closed — treat as limit exceeded.
	hourlyTotal, err := e.spend.SumApprovedUSD(req.AgentID, time.Now().Add(-1*time.Hour))
	if err != nil {
		e.log.Error("hourly spend check failed — failing closed", zap.Error(err))
		return deny(CodeInternalError, "Internal error during spend limit check.", 0, policyHash, p.Version)
	}
	if hourlyTotal+req.AmountUSD > agent.SpendLimits.MaxPerHourUSD {
		return deny(CodeExceedsHourlyLimit,
			fmt.Sprintf("This transaction would bring hourly total to $%.2f, exceeding limit of $%.2f.",
				hourlyTotal+req.AmountUSD, agent.SpendLimits.MaxPerHourUSD),
			0, policyHash, p.Version,
		)
	}

	dailyTotal, err := e.spend.SumApprovedUSD(req.AgentID, time.Now().Add(-24*time.Hour))
	if err != nil {
		e.log.Error("daily spend check failed — failing closed", zap.Error(err))
		return deny(CodeInternalError, "Internal error during spend limit check.", 0, policyHash, p.Version)
	}
	if dailyTotal+req.AmountUSD > agent.SpendLimits.MaxPerDayUSD {
		return deny(CodeExceedsDailyLimit,
			fmt.Sprintf("This transaction would bring daily total to $%.2f, exceeding limit of $%.2f.",
				dailyTotal+req.AmountUSD, agent.SpendLimits.MaxPerDayUSD),
			0, policyHash, p.Version,
		)
	}

	// ── CHECK 10: Behavioral Baseline Score ───────────────────────────────────
	// Runs after all rule checks. Catches pattern gaming that rules cannot detect.
	// A new agent with fewer than 20 data points returns 0.0 (no false positives).
	riskScore := e.baseline.Score(req.AgentID, req.Destination, req.AmountUSD)
	flaggedReview := false

	if riskScore > agent.BehavioralRiskThreshold {
		return deny(CodeBehavioralAnomaly,
			fmt.Sprintf("Behavioral risk score %.2f exceeds threshold %.2f. Request flagged as anomalous.",
				riskScore, agent.BehavioralRiskThreshold),
			riskScore, policyHash, p.Version,
		)
	}
	if riskScore > agent.BehavioralReviewThreshold {
		flaggedReview = true
		e.log.Warn("request flagged for review — risk score above review threshold",
			zap.String("agent_id", req.AgentID),
			zap.Float64("risk_score", riskScore),
			zap.Float64("review_threshold", agent.BehavioralReviewThreshold),
		)
	}

	// ── CHECK 11: Route Decision ──────────────────────────────────────────────
	// All checks passed. Now determine approval path based on amount thresholds.

	// Record the nonce now — only after all checks pass.
	// This prevents a failed request from consuming a nonce.
	if p.Global.RequireNonce {
		nonceExpiry := time.Now().Add(time.Duration(p.Global.NonceWindowSeconds) * time.Second)
		if err := e.spend.RecordNonce(req.Nonce, req.AgentID, nonceExpiry); err != nil {
			e.log.Error("failed to record nonce — failing closed", zap.Error(err))
			return deny(CodeInternalError, "Internal error recording nonce.", riskScore, policyHash, p.Version)
		}
	}

	autoApproved := req.AmountUSD <= agent.SpendLimits.AutoApproveBelowUSD

	// Above require_human_above_usd → pending human approval (Phase 2 handles routing).
	if req.AmountUSD > agent.SpendLimits.RequireHumanAboveUSD {
		return EvaluationResult{
			Decision:      DecisionPendingHuman,
			RiskScore:     riskScore,
			AutoApproved:  false,
			PolicyVersion: p.Version,
			PolicyHash:    policyHash,
			FlaggedReview: flaggedReview,
		}
	}

	// Approved — either auto-approved or recommended for review.
	return EvaluationResult{
		Decision:      DecisionApproved,
		RiskScore:     riskScore,
		AutoApproved:  autoApproved,
		PolicyVersion: p.Version,
		PolicyHash:    policyHash,
		FlaggedReview: flaggedReview,
	}
}

// RunCanary executes startup self-tests against the policy engine.
// Crashes the server if any canary produces the wrong result.
// This confirms the policy engine is wired correctly before serving real traffic.
//
// Three canaries:
//  1. Valid request below auto-approve → must return APPROVED
//  2. Amount above per-transaction limit → must return DENIED / EXCEEDS_TRANSACTION_LIMIT
//  3. Wrong purpose → must return DENIED / PURPOSE_MISMATCH
func (e *Engine) RunCanary(agentID, validDestination, validPurpose string) error {
	now := time.Now().UTC()

	// Canary 1 — valid request, should approve
	c1 := ActionRequest{
		AgentID:     agentID,
		Action:      "canary_transfer",
		Destination: validDestination,
		AmountUSD:   1.00,
		AmountRaw:   "1000000",
		Purpose:     validPurpose,
		ChainID:     84532,
		Nonce:       fmt.Sprintf("canary-nonce-1-%d", now.UnixNano()),
		Timestamp:   now,
	}
	r1 := e.Evaluate(c1)
	if r1.Decision != DecisionApproved {
		return fmt.Errorf("canary 1 FAILED: expected APPROVED, got %s (code: %s, reason: %s)",
			r1.Decision, r1.DenialCode, r1.DenialReason)
	}

	// Canary 2 — amount way above limit, should deny with EXCEEDS_TRANSACTION_LIMIT
	c2 := ActionRequest{
		AgentID:     agentID,
		Action:      "canary_transfer",
		Destination: validDestination,
		AmountUSD:   999_999_999.00, // always exceeds any sane limit
		AmountRaw:   "999999999000000",
		Purpose:     validPurpose,
		ChainID:     84532,
		Nonce:       fmt.Sprintf("canary-nonce-2-%d", now.UnixNano()),
		Timestamp:   now,
	}
	r2 := e.Evaluate(c2)
	if r2.Decision != DecisionDenied || r2.DenialCode != CodeExceedsTransactionLimit {
		return fmt.Errorf("canary 2 FAILED: expected DENIED/%s, got %s/%s",
			CodeExceedsTransactionLimit, r2.Decision, r2.DenialCode)
	}

	// Canary 3 — wrong purpose, should deny with PURPOSE_MISMATCH
	c3 := ActionRequest{
		AgentID:     agentID,
		Action:      "canary_transfer",
		Destination: validDestination,
		AmountUSD:   1.00,
		AmountRaw:   "1000000",
		Purpose:     "__canary_invalid_purpose__",
		ChainID:     84532,
		Nonce:       fmt.Sprintf("canary-nonce-3-%d", now.UnixNano()),
		Timestamp:   now,
	}
	r3 := e.Evaluate(c3)
	if r3.Decision != DecisionDenied || r3.DenialCode != CodePurposeMismatch {
		return fmt.Errorf("canary 3 FAILED: expected DENIED/%s, got %s/%s",
			CodePurposeMismatch, r3.Decision, r3.DenialCode)
	}

	return nil
}

// ── Private helpers ───────────────────────────────────────────────────────────

// deny constructs a denial EvaluationResult. All denial paths go through here
// to ensure consistent structure.
func deny(code, reason string, riskScore float64, policyHash, policyVersion string) EvaluationResult {
	return EvaluationResult{
		Decision:      DecisionDenied,
		DenialCode:    code,
		DenialReason:  reason,
		RiskScore:     riskScore,
		PolicyHash:    policyHash,
		PolicyVersion: policyVersion,
	}
}

// findAgent returns the AgentPolicy for agentID, or nil if not found.
func findAgent(p *Policy, agentID string) *AgentPolicy {
	for i := range p.Agents {
		if p.Agents[i].ID == agentID {
			return &p.Agents[i]
		}
	}
	return nil
}

// purposeAllowed returns true if purpose exactly matches one of the agent's
// allowed_purposes. Case-sensitive — "DeFi" != "defi".
func purposeAllowed(agent *AgentPolicy, purpose string) bool {
	for _, allowed := range agent.AllowedPurposes {
		if allowed == purpose {
			return true
		}
	}
	return false
}

// destinationBlocked returns true if destination is on the blocked list.
// Case-insensitive for addresses (0xABC == 0xabc).
func destinationBlocked(agent *AgentPolicy, destination string) bool {
	dest := strings.ToLower(destination)
	for _, blocked := range agent.BlockedDestinations {
		if strings.ToLower(blocked) == dest {
			return true
		}
	}
	return false
}

// destinationAllowed returns true if destination is on the allowed list.
// Case-insensitive for addresses (0xABC == 0xabc).
func destinationAllowed(agent *AgentPolicy, destination string) bool {
	dest := strings.ToLower(destination)
	for _, allowed := range agent.AllowedDestinations {
		if strings.ToLower(allowed) == dest {
			return true
		}
	}
	return false
}
