package gateway

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"tollgate/internal/config"

	"github.com/google/uuid"
	"go.uber.org/zap"
)

// ── Context keys ──────────────────────────────────────────────────────────────

type contextKey string

const (
	ctxRequestID contextKey = "request_id"
	ctxAgentID   contextKey = "agent_id"
)

// ── Middleware 1: Panic Recovery ──────────────────────────────────────────────

// recoverMiddleware catches any panic in downstream handlers, logs it,
// returns 500 to the client, and keeps the server alive for other requests.
func recoverMiddleware(log *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					reqID, _ := r.Context().Value(ctxRequestID).(string)
					log.Error("panic recovered — request aborted",
						zap.String("request_id", reqID),
						zap.String("path", r.URL.Path),
						zap.Any("panic", rec),
					)
					writeError(w, http.StatusInternalServerError, "internal server error")
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// ── Middleware 2: Request Size Limit ─────────────────────────────────────────

// requestSizeMiddleware rejects bodies exceeding the configured limit.
// Uses http.MaxBytesReader — the body is never fully read for oversized requests.
// Returns 413 before any handler logic runs.
func requestSizeMiddleware(cfg *config.Config) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Body != nil {
				r.Body = http.MaxBytesReader(w, r.Body, cfg.ServerMaxRequestBodyBytes)
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ── Middleware 3: Request ID ──────────────────────────────────────────────────

// requestIDMiddleware assigns a UUID to every request.
// Added to the response header and request context for end-to-end tracing.
func requestIDMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reqID := uuid.New().String()
			w.Header().Set("X-Request-ID", reqID)
			ctx := context.WithValue(r.Context(), ctxRequestID, reqID)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ── Middleware 4: Global Rate Limit ──────────────────────────────────────────

// globalRateLimitMiddleware enforces the total server RPS ceiling.
// Returns 429 with Retry-After if exceeded.
func globalRateLimitMiddleware(deps Deps) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !deps.RateLimiter.AllowGlobal() {
				w.Header().Set("Retry-After", "1")
				writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// ── Middleware 5: Structured Request Logging ──────────────────────────────────

// loggingMiddleware logs every request with request ID, method, path,
// status code, and duration.
// SECURITY: token values and secrets are never logged.
func loggingMiddleware(log *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rw := &responseWriter{ResponseWriter: w, status: http.StatusOK}

			next.ServeHTTP(rw, r)

			reqID, _ := r.Context().Value(ctxRequestID).(string)
			agentID, _ := r.Context().Value(ctxAgentID).(string)

			log.Info("request",
				zap.String("request_id", reqID),
				zap.String("agent_id", agentID),
				zap.String("method", r.Method),
				zap.String("path", r.URL.Path),
				zap.Int("status", rw.status),
				zap.Duration("duration", time.Since(start)),
			)
		})
	}
}

// ── Auth helper — called inside handlers ──────────────────────────────────────

// authenticateRequest extracts the Bearer token, verifies it via the agent
// registry, enforces the per-agent rate limit, and returns agent identity.
//
// Returns (agentID, tokenID, true) on success.
// Writes 401 and returns ("", "", false) on any failure.
//
// SECURITY:
//   - All failure paths return exactly the same 401 body.
//     Never hint at which check failed.
//   - The raw token string is never logged.
func authenticateRequest(w http.ResponseWriter, r *http.Request, deps Deps) (agentID, tokenID string, ok bool) {
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return "", "", false
	}

	tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenStr == "" {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return "", "", false
	}

	claims, err := deps.AgentRegistry.Verify(tokenStr)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "unauthorized")
		return "", "", false
	}

	// Per-agent rate limit — after auth so we know which agent it is.
	if !deps.RateLimiter.AllowAgent(claims.AgentID) {
		w.Header().Set("Retry-After", "1")
		writeError(w, http.StatusTooManyRequests, "rate limit exceeded")
		return "", "", false
	}

	return claims.AgentID, claims.TokenID, true
}

// ── Content-Type + Method enforcement ────────────────────────────────────────

// requireJSON returns false and writes 415 if Content-Type is not application/json.
func requireJSON(w http.ResponseWriter, r *http.Request) bool {
	ct := r.Header.Get("Content-Type")
	if !strings.HasPrefix(ct, "application/json") {
		writeError(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")
		return false
	}
	return true
}

// requireMethod returns false and writes 405 if the HTTP method does not match.
func requireMethod(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method != method {
		w.Header().Set("Allow", method)
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return false
	}
	return true
}

// ── Response helpers ──────────────────────────────────────────────────────────

// writeError writes a JSON error body with the given HTTP status.
func writeError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	fmt.Fprintf(w, `{"error":%q}`, message)
}

// writeJSON writes a 200 OK JSON response.
func writeJSON(w http.ResponseWriter, body []byte) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

// ── responseWriter wraps http.ResponseWriter to capture the status code ──────

type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(status int) {
	rw.status = status
	rw.ResponseWriter.WriteHeader(status)
}
