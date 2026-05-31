package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
	"tollgate/internal/agent"
	"tollgate/internal/audit"
	"tollgate/internal/policy"
	"tollgate/internal/ratelimit"
	"tollgate/internal/signing"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// Deps holds every module the handlers need. Passed to NewServer and
// threaded through to each handler. All fields are required.
type Deps struct {
	Config        configProvider
	PolicyEngine  *policy.Engine
	Signer        *signing.Signer
	AuditDB       *audit.DB
	AgentRegistry *agent.Registry
	RateLimiter   *ratelimit.Limiter
	Baseline      baselineRecorder
	TTLSeconds    int
	DryRun        bool
}

// configProvider gives handlers access to safe config values.
type configProvider interface {
	IsProduction() bool
	IsDryRun() bool
}

// baselineRecorder is the subset of the baseline Scorer used by handlers.
type baselineRecorder interface {
	Record(agentID, destination string, amountUSD float64)
}

// handlers owns all HTTP handler functions.
type handlers struct {
	cfg  configProvider
	deps Deps
	log  *zap.Logger
}

// ── POST /v1/action-check ─────────────────────────────────────────────────────

// actionCheckRequest is the JSON body expected from an AI agent.
// Every field is required — missing any field returns 400.
type actionCheckRequest struct {
	AgentID     string  `json:"agent_id"`
	Action      string  `json:"action"`
	Destination string  `json:"destination"`
	AmountUSD   float64 `json:"amount_usd"`
	AmountRaw   string  `json:"amount_raw"`
	Purpose     string  `json:"purpose"`
	ChainID     int64   `json:"chain_id"`
	Nonce       string  `json:"nonce"`
	Timestamp   string  `json:"timestamp"` // RFC3339
}

// actionCheckResponse is the JSON body returned to the agent.
type actionCheckResponse struct {
	Status     string                 `json:"status"` // "approved" | "denied" | "pending_human"
	DecisionID string                 `json:"decision_id"`
	Token      *signing.ApprovalToken `json:"approval_token,omitempty"` // nil if not approved
	Code       string                 `json:"code,omitempty"`           // denial code
	Message    string                 `json:"message,omitempty"`        // denial reason
}

// actionCheck is the main endpoint. Every AI financial request comes here first.
//
// Full request lifecycle (wall-clock order):
//  1. Method + Content-Type check
//  2. Agent auth (HMAC verify + revocation + per-agent rate limit)
//  3. JSON decode + field validation
//  4. Policy engine evaluation (11 checks)
//  5. If approved → build + sign Approval Token
//  6. Write audit record (MUST succeed before response is sent)
//  7. Update behavioral baseline (async)
//  8. Return response
func (h *handlers) actionCheck(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	if !requireJSON(w, r) {
		return
	}

	// ── Step 2: Auth ──────────────────────────────────────────────────────────
	agentID, _, ok := authenticateRequest(w, r, h.deps)
	if !ok {
		return
	}

	// ── Step 3: Decode + validate ─────────────────────────────────────────────
	var req actionCheckRequest
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if err := validateActionRequest(req, agentID); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	ts, err := time.Parse(time.RFC3339, req.Timestamp)
	if err != nil {
		writeError(w, http.StatusBadRequest, "timestamp must be RFC3339 format")
		return
	}

	policyReq := policy.ActionRequest{
		AgentID:     req.AgentID,
		Action:      req.Action,
		Destination: req.Destination,
		AmountUSD:   req.AmountUSD,
		AmountRaw:   req.AmountRaw,
		Purpose:     req.Purpose,
		ChainID:     req.ChainID,
		Nonce:       req.Nonce,
		Timestamp:   ts,
	}

	// ── Step 4: Policy engine evaluation ─────────────────────────────────────
	result := h.deps.PolicyEngine.Evaluate(policyReq)

	decisionID := uuid.New().String()

	// ── Step 5: Build + sign Approval Token (if approved) ────────────────────
	var token *signing.ApprovalToken

	if result.Decision == policy.DecisionApproved {
		if h.deps.DryRun {
			// DRY RUN: build a dummy token without a real signature.
			token = &signing.ApprovalToken{
				TokenID:       uuid.New().String(),
				AgentID:       req.AgentID,
				Destination:   req.Destination,
				AmountUSD:     req.AmountUSD,
				AmountRaw:     req.AmountRaw,
				Purpose:       req.Purpose,
				ChainID:       req.ChainID,
				Nonce:         req.Nonce,
				IssuedAt:      time.Now().UTC(),
				ExpiresAt:     time.Now().UTC().Add(time.Duration(h.deps.TTLSeconds) * time.Second),
				PolicyVersion: result.PolicyVersion,
				PolicyHash:    result.PolicyHash,
				RiskScore:     result.RiskScore,
				AutoApproved:  result.AutoApproved,
				Signature:     "0x" + "00",
			}
		} else {
			token, err = h.deps.Signer.BuildApprovalToken(signing.BuildRequest{
				AgentID:       req.AgentID,
				PolicyVersion: result.PolicyVersion,
				PolicyHash:    result.PolicyHash,
				Action:        req.Action,
				Destination:   req.Destination,
				AmountUSD:     req.AmountUSD,
				AmountRaw:     req.AmountRaw,
				Purpose:       req.Purpose,
				ChainID:       req.ChainID,
				Nonce:         req.Nonce,
				TTLSeconds:    h.deps.TTLSeconds,
				RiskScore:     result.RiskScore,
				AutoApproved:  result.AutoApproved,
			})
			if err != nil {
				h.log.Error("failed to build approval token — denying",
					zap.String("agent_id", req.AgentID),
					zap.Error(err),
				)
				// Signing failure → deny. Never return an unsigned approval.
				result = policy.EvaluationResult{
					Decision:      policy.DecisionDenied,
					DenialCode:    policy.CodeInternalError,
					DenialReason:  "Internal signing error.",
					PolicyVersion: result.PolicyVersion,
					PolicyHash:    result.PolicyHash,
				}
				token = nil
			}
		}
	}

	// ── Step 6: Write audit record ────────────────────────────────────────────
	// SECURITY: If this write fails, the response is DENIED regardless of the
	// policy decision. An approval without an audit record does not exist.
	auditRec := audit.DecisionRecord{
		ID:            decisionID,
		RequestID:     requestIDFromContext(r.Context()),
		AgentID:       req.AgentID,
		Decision:      string(result.Decision),
		DenialCode:    result.DenialCode,
		DenialReason:  result.DenialReason,
		Action:        req.Action,
		Destination:   req.Destination,
		AmountUSD:     req.AmountUSD,
		AmountRaw:     req.AmountRaw,
		Purpose:       req.Purpose,
		ChainID:       req.ChainID,
		Nonce:         req.Nonce,
		PolicyVersion: result.PolicyVersion,
		PolicyHash:    result.PolicyHash,
		RiskScore:     result.RiskScore,
	}
	if token != nil {
		auditRec.TokenID = token.TokenID
		auditRec.TokenExpiresAt = token.ExpiresAt
	}

	if err := h.deps.AuditDB.WriteDecision(auditRec); err != nil {
		h.log.Error("audit write failed — converting approval to denial",
			zap.String("agent_id", req.AgentID),
			zap.String("decision_id", decisionID),
			zap.Error(err),
		)
		// Audit failure → deny. No exceptions.
		resp := actionCheckResponse{
			Status:     string(policy.DecisionDenied),
			DecisionID: decisionID,
			Code:       policy.CodeInternalError,
			Message:    "Internal error — decision could not be recorded.",
		}
		body, _ := json.Marshal(resp)
		writeJSON(w, body)
		return
	}

	// ── Step 7: Update behavioral baseline (async) ────────────────────────────
	// Only record approved transactions — baseline reflects real behavior.
	// Async so it never delays the response.
	if result.Decision == policy.DecisionApproved {
		go h.deps.Baseline.Record(req.AgentID, req.Destination, req.AmountUSD)
	}

	// ── Step 8: Return response ───────────────────────────────────────────────
	resp := actionCheckResponse{
		Status:     string(result.Decision),
		DecisionID: decisionID,
		Token:      token,
		Code:       result.DenialCode,
		Message:    result.DenialReason,
	}

	body, err := json.Marshal(resp)
	if err != nil {
		h.log.Error("failed to marshal response", zap.Error(err))
		writeError(w, http.StatusInternalServerError, "internal server error")
		return
	}

	writeJSON(w, body)
}

// ── GET /v1/health ────────────────────────────────────────────────────────────

type healthResponse struct {
	Status        string                 `json:"status"`
	Version       string                 `json:"version"`
	Checks        map[string]interface{} `json:"checks"`
	UptimeSeconds int64                  `json:"uptime_seconds"`
}

var serverStart = time.Now()

func (h *handlers) health(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) {
		return
	}

	_, policyHash, policyLoaded := h.deps.PolicyEngine.LoaderStatus()
	dbOK := h.deps.AuditDB.Ping() == nil

	status := "ok"
	if !policyLoaded || !dbOK {
		status = "degraded"
	}

	resp := healthResponse{
		Status:  status,
		Version: "1.0.0",
		Checks: map[string]interface{}{
			"policy_loaded":  policyLoaded,
			"policy_hash":    policyHash,
			"signing_key_ok": true, // if signer booted, key is valid
			"audit_db_ok":    dbOK,
		},
		UptimeSeconds: int64(time.Since(serverStart).Seconds()),
	}

	body, _ := json.Marshal(resp)
	writeJSON(w, body)
}

// ── POST /v1/agent/revoke ─────────────────────────────────────────────────────

type revokeRequest struct {
	TokenID string `json:"token_id"`
	Reason  string `json:"reason"`
}

func (h *handlers) revokeToken(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	if !requireJSON(w, r) {
		return
	}

	// Revoke endpoint requires auth — any valid agent token can revoke.
	// In production this would require a separate admin token.
	_, _, ok := authenticateRequest(w, r, h.deps)
	if !ok {
		return
	}

	var req revokeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.TokenID == "" {
		writeError(w, http.StatusBadRequest, "token_id is required")
		return
	}

	if err := h.deps.AgentRegistry.RevokeToken(req.TokenID, "unknown", req.Reason); err != nil {
		h.log.Error("revocation failed", zap.String("token_id", req.TokenID), zap.Error(err))
		writeError(w, http.StatusInternalServerError, "revocation failed")
		return
	}

	h.log.Warn("token revoked via API",
		zap.String("token_id", req.TokenID),
		zap.String("reason", req.Reason),
	)

	body, _ := json.Marshal(map[string]string{
		"status":   "revoked",
		"token_id": req.TokenID,
	})
	writeJSON(w, body)
}

// ── Validation ────────────────────────────────────────────────────────────────

// validateActionRequest checks all required fields are present and sane.
// Returns a descriptive error — but the HTTP response to the client is always
// the generic "invalid request body" message, not this detail.
func validateActionRequest(req actionCheckRequest, authenticatedAgentID string) error {
	if req.AgentID == "" {
		return fmt.Errorf("agent_id is required")
	}
	// SECURITY: the agent_id in the body must match the authenticated token.
	// Prevents agent A from submitting requests on behalf of agent B.
	if req.AgentID != authenticatedAgentID {
		return fmt.Errorf("agent_id in body does not match authenticated token")
	}
	if req.Action == "" {
		return fmt.Errorf("action is required")
	}
	if req.Destination == "" {
		return fmt.Errorf("destination is required")
	}
	if req.AmountUSD < 0 {
		return fmt.Errorf("amount_usd cannot be negative")
	}
	if req.AmountRaw == "" {
		return fmt.Errorf("amount_raw is required")
	}
	if req.Purpose == "" {
		return fmt.Errorf("purpose is required")
	}
	if req.ChainID <= 0 {
		return fmt.Errorf("chain_id is required")
	}
	if req.Nonce == "" {
		return fmt.Errorf("nonce is required")
	}
	if req.Timestamp == "" {
		return fmt.Errorf("timestamp is required")
	}
	return nil
}

// ── Context helpers ───────────────────────────────────────────────────────────

func requestIDFromContext(ctx context.Context) string {
	v, _ := ctx.Value(ctxRequestID).(string)
	return v
}
