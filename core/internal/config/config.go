package config

import (
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/joho/godotenv"
)

// Config holds all validated runtime configuration for the Tollgate Notary.
// Populated once at startup. Never mutated after Load() returns.
// SECURITY: The signing key and agent secret fields are stored in memory only.
// They are never written to disk again, never logged, never serialized.
type Config struct {
	// Server
	ServerPort                int
	ServerReadTimeoutSeconds  int
	ServerWriteTimeoutSeconds int
	ServerMaxRequestBodyBytes int64

	// Signing — SECURITY: never log these values, not even partially
	SigningKeyHex    string
	AgentTokenSecret string

	// Policy
	PolicyFilePath  string
	PolicyHotReload bool

	// Audit
	AuditDBPath string

	// Rate limiting
	RateLimitPerAgentRPS int
	RateLimitBurst       int
	GlobalRateLimitRPS   int

	// Approval token
	ApprovalTokenTTLSeconds int

	// Runtime
	Environment string // "development" | "production"
	DryRunMode  bool
}

// Load reads environment variables (and optionally a .env file), validates
// every required value, and returns a fully verified Config.
//
// SECURITY CONTRACT:
//   - Crashes with a descriptive error if any required variable is missing or invalid.
//   - The signing key and agent secret are NEVER logged under any circumstances.
//   - DRY_RUN_MODE=true + ENVIRONMENT=production is a fatal misconfiguration.
//   - All validation errors are collected and reported together so the operator
//     sees every problem in one crash, not one problem at a time.
func Load() (*Config, error) {
	// Attempt to load .env — not fatal if absent (env vars may be injected directly
	// by the OS or a secrets manager in production).
	if err := godotenv.Load(); err != nil {
		fmt.Fprintln(os.Stderr, "[config] no .env file found — reading from environment")
	}

	cfg := &Config{}
	var errs []string

	// ── SERVER ────────────────────────────────────────────────────────────────

	if v, err := requireInt("SERVER_PORT", 1, 65535); err != nil {
		errs = append(errs, err.Error())
	} else {
		cfg.ServerPort = v
	}

	if v, err := requireInt("SERVER_READ_TIMEOUT_SECONDS", 1, 300); err != nil {
		errs = append(errs, err.Error())
	} else {
		cfg.ServerReadTimeoutSeconds = v
	}

	if v, err := requireInt("SERVER_WRITE_TIMEOUT_SECONDS", 1, 300); err != nil {
		errs = append(errs, err.Error())
	} else {
		cfg.ServerWriteTimeoutSeconds = v
	}

	if v, err := requireInt64("SERVER_MAX_REQUEST_BODY_BYTES", 1024, 10*1024*1024); err != nil {
		errs = append(errs, err.Error())
	} else {
		cfg.ServerMaxRequestBodyBytes = v
	}

	// ── SIGNING KEY ───────────────────────────────────────────────────────────
	// SECURITY: validate format only — never log the value, not even on error.

	signingKey := os.Getenv("TOLLGATE_SIGNING_KEY_HEX")
	switch {
	case signingKey == "":
		errs = append(errs, "TOLLGATE_SIGNING_KEY_HEX is required but not set")
	case len(signingKey) != 64:
		// Report length only — never echo the actual value back
		errs = append(errs, fmt.Sprintf(
			"TOLLGATE_SIGNING_KEY_HEX must be exactly 64 hex characters (got %d)", len(signingKey),
		))
	default:
		if _, err := hex.DecodeString(signingKey); err != nil {
			errs = append(errs, "TOLLGATE_SIGNING_KEY_HEX contains invalid non-hex characters")
		} else {
			cfg.SigningKeyHex = signingKey
		}
	}

	// ── AGENT TOKEN SECRET ────────────────────────────────────────────────────
	// SECURITY: validate format only — never log the value, not even on error.

	agentSecret := os.Getenv("AGENT_TOKEN_SECRET")
	switch {
	case agentSecret == "":
		errs = append(errs, "AGENT_TOKEN_SECRET is required but not set")
	case len(agentSecret) < 64:
		errs = append(errs, fmt.Sprintf(
			"AGENT_TOKEN_SECRET must be at least 64 hex characters (got %d)", len(agentSecret),
		))
	default:
		if _, err := hex.DecodeString(agentSecret); err != nil {
			errs = append(errs, "AGENT_TOKEN_SECRET contains invalid non-hex characters")
		} else {
			cfg.AgentTokenSecret = agentSecret
		}
	}

	// ── POLICY ───────────────────────────────────────────────────────────────

	policyPath := os.Getenv("POLICY_FILE_PATH")
	if policyPath == "" {
		errs = append(errs, "POLICY_FILE_PATH is required but not set")
	} else {
		cfg.PolicyFilePath = policyPath
	}

	cfg.PolicyHotReload = parseBool("POLICY_HOT_RELOAD", true)

	// ── AUDIT LOG ─────────────────────────────────────────────────────────────

	auditPath := os.Getenv("AUDIT_DB_PATH")
	if auditPath == "" {
		errs = append(errs, "AUDIT_DB_PATH is required but not set")
	} else {
		cfg.AuditDBPath = auditPath
	}

	// ── RATE LIMITING ─────────────────────────────────────────────────────────

	if v, err := requireInt("RATE_LIMIT_PER_AGENT_RPS", 1, 10_000); err != nil {
		errs = append(errs, err.Error())
	} else {
		cfg.RateLimitPerAgentRPS = v
	}

	if v, err := requireInt("RATE_LIMIT_BURST", 1, 10_000); err != nil {
		errs = append(errs, err.Error())
	} else {
		cfg.RateLimitBurst = v
	}

	if v, err := requireInt("GLOBAL_RATE_LIMIT_RPS", 1, 100_000); err != nil {
		errs = append(errs, err.Error())
	} else {
		cfg.GlobalRateLimitRPS = v
	}

	// ── APPROVAL TOKEN ────────────────────────────────────────────────────────

	if v, err := requireInt("APPROVAL_TOKEN_TTL_SECONDS", 10, 3600); err != nil {
		errs = append(errs, err.Error())
	} else {
		cfg.ApprovalTokenTTLSeconds = v
	}

	// ── ENVIRONMENT ───────────────────────────────────────────────────────────

	env := strings.ToLower(strings.TrimSpace(os.Getenv("ENVIRONMENT")))
	if env == "" {
		env = "development"
	}
	if env != "development" && env != "production" {
		errs = append(errs, fmt.Sprintf(
			"ENVIRONMENT must be 'development' or 'production' (got %q)", env,
		))
	} else {
		cfg.Environment = env
	}

	// ── DRY RUN MODE ──────────────────────────────────────────────────────────
	// SECURITY: DRY_RUN_MODE bypasses real signing. It is NEVER permitted in production.

	dryRun := parseBool("DRY_RUN_MODE", false)
	if dryRun && env == "production" {
		// Hard crash — this combination is a critical misconfiguration.
		errs = append(errs, "FATAL: DRY_RUN_MODE=true is strictly forbidden when ENVIRONMENT=production")
	}
	cfg.DryRunMode = dryRun

	// ── COLLECT ALL ERRORS ────────────────────────────────────────────────────
	// Report every problem at once. Operators should not have to restart the
	// server multiple times to discover all configuration mistakes.

	if len(errs) > 0 {
		return nil, fmt.Errorf(
			"Tollgate cannot start — %d configuration error(s):\n  ✗ %s",
			len(errs),
			strings.Join(errs, "\n  ✗ "),
		)
	}

	return cfg, nil
}

// PrintStartupSummary logs safe (non-secret) configuration values on startup.
// SECURITY: signing key and agent secret are intentionally excluded.
func (c *Config) PrintStartupSummary() {
	sep := "  ──────────────────────────────────────"

	fmt.Println()
	fmt.Println("  ╷ TOLLGATE NOTARY")
	fmt.Println("  ╵ runtime config")
	fmt.Println(sep)
	fmt.Printf("  %-16s %s\n", "environment", c.Environment)
	fmt.Printf("  %-16s %d\n", "port", c.ServerPort)
	fmt.Printf("  %-16s %s\n", "policy file", truncate(c.PolicyFilePath, 30))
	fmt.Printf("  %-16s %v\n", "hot reload", c.PolicyHotReload)
	fmt.Printf("  %-16s %s\n", "audit db", truncate(c.AuditDBPath, 30))
	fmt.Printf("  %-16s %ds\n", "token ttl", c.ApprovalTokenTTLSeconds)
	fmt.Printf("  %-16s %d req/s\n", "global rps cap", c.GlobalRateLimitRPS)
	fmt.Println(sep)
	fmt.Printf("  %-16s %s\n", "signing key", "[ sealed — never logged ]")
	fmt.Printf("  %-16s %s\n", "agent secret", "[ sealed — never logged ]")
	fmt.Println(sep)

	if c.DryRunMode {
		fmt.Println()
		fmt.Println("  ⚠  DRY RUN MODE")
		fmt.Println("     All requests return APPROVED.")
		fmt.Println("     No real signatures are issued.")
		fmt.Println("     Do not run this in production.")
		fmt.Println()
	}
}

// IsProduction returns true when running in production mode.
func (c *Config) IsProduction() bool { return c.Environment == "production" }

// IsDryRun returns true when DRY_RUN_MODE is active.
func (c *Config) IsDryRun() bool { return c.DryRunMode }

// ── Private helpers ───────────────────────────────────────────────────────────

// requireInt reads key from the environment, asserts it is an integer,
// and validates it falls within [min, max] inclusive.
// Returns a descriptive error — never the raw value — on failure.
func requireInt(key string, min, max int) (int, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return 0, fmt.Errorf("%s is required but not set", key)
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%s must be a whole number (could not parse value)", key)
	}
	if n < min || n > max {
		return 0, fmt.Errorf("%s must be between %d and %d (got %d)", key, min, max, n)
	}
	return n, nil
}

// requireInt64 is requireInt for larger values (e.g. byte limits).
func requireInt64(key string, min, max int64) (int64, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return 0, fmt.Errorf("%s is required but not set", key)
	}
	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%s must be a whole number (could not parse value)", key)
	}
	if n < min || n > max {
		return 0, fmt.Errorf("%s must be between %d and %d (got %d)", key, min, max, n)
	}
	return n, nil
}

// parseBool reads key from the environment as a boolean.
// Returns defaultVal if the variable is absent or empty.
// Accepts: "true","1","yes" → true | "false","0","no" → false
// Unrecognised values fall back to defaultVal.
func parseBool(key string, defaultVal bool) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(key))) {
	case "true", "1", "yes":
		return true
	case "false", "0", "no":
		return false
	default:
		return defaultVal
	}
}

// truncate shortens a string for display purposes only.
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
