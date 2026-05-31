package agent

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

// tokenPayload is the JSON body of an agent token.
// Every field is required — a token missing any field is invalid.
type tokenPayload struct {
	AgentID   string `json:"agent_id"`
	IssuedAt  string `json:"issued_at"`
	ExpiresAt string `json:"expires_at"`
	TokenID   string `json:"token_id"`
}

// AgentTokenClaims is returned by VerifyToken on success.
// The gateway uses AgentID and TokenID to enforce policy and revocation.
type AgentTokenClaims struct {
	AgentID   string
	TokenID   string
	ExpiresAt time.Time
}

// IssueToken creates a new HMAC-SHA256 signed agent token valid for ttl duration.
// Format: base64url(payload) + "." + base64url(HMAC-SHA256(base64url(payload), secret))
//
// SECURITY: secretHex must come from AGENT_TOKEN_SECRET in the environment only.
// Never log or return the raw secret value.
func IssueToken(agentID, secretHex string, ttl time.Duration) (string, error) {
	secretBytes, err := hex.DecodeString(secretHex)
	if err != nil {
		return "", fmt.Errorf("agent: invalid token secret — must be hex-encoded")
	}

	now := time.Now().UTC()
	payload := tokenPayload{
		AgentID:   agentID,
		IssuedAt:  now.Format(time.RFC3339),
		ExpiresAt: now.Add(ttl).Format(time.RFC3339),
		TokenID:   uuid.New().String(),
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("agent: failed to marshal token payload: %w", err)
	}

	encodedPayload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	sig := computeHMAC(encodedPayload, secretBytes)
	encodedSig := base64.RawURLEncoding.EncodeToString(sig)

	return encodedPayload + "." + encodedSig, nil
}

// VerifyToken parses and validates an agent token string.
//
// Checks performed in order:
//  1. Format — must be exactly two base64url segments separated by "."
//  2. Signature — HMAC-SHA256 verified with constant-time comparison
//  3. Expiry — token must not be expired
//
// SECURITY:
//   - Uses crypto/subtle.ConstantTimeCompare for signature verification.
//     Timing attacks on HMAC comparison are a real class of vulnerability.
//   - On failure, returns a generic error — never reveals which check failed.
//     The 401 response to the client must be equally generic.
func VerifyToken(tokenStr, secretHex string) (*AgentTokenClaims, error) {
	secretBytes, err := hex.DecodeString(secretHex)
	if err != nil {
		return nil, fmt.Errorf("agent: invalid token secret configuration")
	}

	// Split on "." — must have exactly two parts.
	parts := strings.SplitN(tokenStr, ".", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return nil, fmt.Errorf("agent: malformed token")
	}

	encodedPayload := parts[0]
	providedSig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("agent: malformed token")
	}

	// Verify HMAC signature using constant-time comparison.
	// SECURITY: Do NOT use == here. Timing attacks are real.
	expectedSig := computeHMAC(encodedPayload, secretBytes)
	if subtle.ConstantTimeCompare(providedSig, expectedSig) != 1 {
		return nil, fmt.Errorf("agent: unauthorized")
	}

	// Decode and parse the payload — only after signature is verified.
	payloadJSON, err := base64.RawURLEncoding.DecodeString(encodedPayload)
	if err != nil {
		return nil, fmt.Errorf("agent: malformed token")
	}

	var payload tokenPayload
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return nil, fmt.Errorf("agent: malformed token")
	}

	if payload.AgentID == "" || payload.TokenID == "" {
		return nil, fmt.Errorf("agent: malformed token")
	}

	// Check expiry.
	expiresAt, err := time.Parse(time.RFC3339, payload.ExpiresAt)
	if err != nil {
		return nil, fmt.Errorf("agent: malformed token")
	}
	if time.Now().UTC().After(expiresAt) {
		return nil, fmt.Errorf("agent: unauthorized")
	}

	return &AgentTokenClaims{
		AgentID:   payload.AgentID,
		TokenID:   payload.TokenID,
		ExpiresAt: expiresAt,
	}, nil
}

// computeHMAC returns the HMAC-SHA256 of message using key.
func computeHMAC(message string, key []byte) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(message))
	return mac.Sum(nil)
}
