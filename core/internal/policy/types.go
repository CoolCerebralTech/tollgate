package policy

import "time"

// Policy is the top-level structure of policy.yaml.
// Every field maps directly to a YAML key — no magic, no inference.
type Policy struct {
	Version   string        `yaml:"version"`
	UpdatedAt string        `yaml:"updated_at"`
	UpdatedBy string        `yaml:"updated_by"`
	Agents    []AgentPolicy `yaml:"agents"`
	Global    GlobalRules   `yaml:"global_rules"`
}

// AgentPolicy defines all rules for a single registered AI agent.
// An agent not listed here is ALWAYS denied — there is no default policy.
type AgentPolicy struct {
	ID             string `yaml:"id"`
	Name           string `yaml:"name"`
	Enabled        bool   `yaml:"enabled"`
	Purpose        string `yaml:"purpose"`
	ClearanceLevel int    `yaml:"clearance_level"` // 1=lowest, 5=highest

	SpendLimits         SpendLimits `yaml:"spend_limits"`
	AllowedDestinations []string    `yaml:"allowed_destinations"`
	BlockedDestinations []string    `yaml:"blocked_destinations"`
	AllowedPurposes     []string    `yaml:"allowed_purposes"`

	RejectUnsolicitedPermissions bool    `yaml:"reject_unsolicited_permissions"`
	BehavioralRiskThreshold      float64 `yaml:"behavioral_risk_threshold"`   // block above this
	BehavioralReviewThreshold    float64 `yaml:"behavioral_review_threshold"` // flag above this
}

// SpendLimits defines all monetary boundaries for an agent.
type SpendLimits struct {
	MaxPerTransactionUSD float64 `yaml:"max_per_transaction_usd"`
	MaxPerHourUSD        float64 `yaml:"max_per_hour_usd"`
	MaxPerDayUSD         float64 `yaml:"max_per_day_usd"`
	AutoApproveBelowUSD  float64 `yaml:"auto_approve_below_usd"`
	RequireHumanAboveUSD float64 `yaml:"require_human_above_usd"`
}

// GlobalRules apply to every request regardless of which agent sends it.
// These are the floor — no per-agent policy can override them.
type GlobalRules struct {
	DefaultAction        string `yaml:"default_action"`          // must be "deny"
	MaxRequestAgeSeconds int    `yaml:"max_request_age_seconds"` // reject stale requests
	RequireNonce         bool   `yaml:"require_nonce"`
	NonceWindowSeconds   int    `yaml:"nonce_window_seconds"`
}

// ActionRequest is the validated, parsed financial action request from an AI agent.
// Every field is required. The gateway layer rejects requests with any missing field
// before this struct is constructed.
type ActionRequest struct {
	AgentID     string    `json:"agent_id"`
	Action      string    `json:"action"`
	Destination string    `json:"destination"`
	AmountUSD   float64   `json:"amount_usd"`
	AmountRaw   string    `json:"amount_raw"`
	Purpose     string    `json:"purpose"`
	ChainID     int64     `json:"chain_id"`
	Nonce       string    `json:"nonce"`
	Timestamp   time.Time `json:"timestamp"`
}

// EvaluationResult is the complete output of the policy engine for one request.
// The gateway layer uses this to build the response and write the audit record.
type EvaluationResult struct {
	Decision      Decision // Approved, Denied, or PendingHuman
	DenialCode    string   // set when Decision == Denied
	DenialReason  string   // human-readable explanation for the audit log
	RiskScore     float64  // behavioral baseline score at decision time
	AutoApproved  bool     // true if amount was below auto-approve threshold
	PolicyVersion string   // exact version active at evaluation time
	PolicyHash    string   // keccak256 of policy.yaml at evaluation time
	FlaggedReview bool     // true if risk score exceeded review threshold
}

// Decision is the three possible outcomes of a policy evaluation.
type Decision string

const (
	DecisionApproved     Decision = "approved"
	DecisionDenied       Decision = "denied"
	DecisionPendingHuman Decision = "pending_human"
)

// Denial codes — used in API responses and audit log.
// These are stable identifiers. Do not rename them — the audit log
// and any downstream tooling depends on these exact strings.
const (
	CodeRequestExpired          = "REQUEST_EXPIRED"
	CodeNonceReplay             = "NONCE_REPLAY"
	CodeAgentUnknown            = "AGENT_UNKNOWN"
	CodeAgentDisabled           = "AGENT_DISABLED"
	CodePurposeMismatch         = "PURPOSE_MISMATCH"
	CodeDestinationBlocked      = "DESTINATION_BLOCKED"
	CodeDestinationNotAllowed   = "DESTINATION_NOT_ALLOWED"
	CodeExceedsTransactionLimit = "EXCEEDS_TRANSACTION_LIMIT"
	CodeExceedsHourlyLimit      = "EXCEEDS_HOURLY_LIMIT"
	CodeExceedsDailyLimit       = "EXCEEDS_DAILY_LIMIT"
	CodeBehavioralAnomaly       = "BEHAVIORAL_ANOMALY"
	CodeZeroAmount              = "ZERO_AMOUNT"
	CodeInternalError           = "INTERNAL_ERROR"
	CodePolicyUnavailable       = "POLICY_UNAVAILABLE"
)
