package gateway

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
	"tollgate/internal/config"

	"go.uber.org/zap"
)

// Server is the Tollgate HTTP gateway.
// It owns the HTTP server lifecycle — start, route, and graceful shutdown.
type Server struct {
	cfg     *config.Config
	handler http.Handler
	log     *zap.Logger
}

// NewServer constructs the HTTP server, wires all routes, and applies all middleware.
// deps carries every module the handlers need — see Deps in handlers.go.
func NewServer(cfg *config.Config, deps Deps, log *zap.Logger) *Server {
	mux := http.NewServeMux()

	h := &handlers{cfg: cfg, deps: deps, log: log}

	// Register all routes.
	mux.HandleFunc("/v1/action-check", h.actionCheck) // POST only — enforced in handler
	mux.HandleFunc("/v1/health", h.health)            // GET only — no auth
	mux.HandleFunc("/v1/agent/revoke", h.revokeToken) // POST only — admin auth

	// Apply middleware stack (outermost = first to run).
	// Order is security-critical — do not reorder.
	wrapped := chain(mux,
		recoverMiddleware(log),          // 1 — catch panics before anything else
		requestSizeMiddleware(cfg),      // 2 — reject oversized bodies early
		requestIDMiddleware(),           // 3 — assign request ID for tracing
		globalRateLimitMiddleware(deps), // 4 — global RPS cap
		loggingMiddleware(log),          // 5 — log every request with timing
	)

	return &Server{
		cfg:     cfg,
		handler: wrapped,
		log:     log,
	}
}

// Start begins serving HTTP requests and blocks until the server shuts down.
// Shutdown is triggered by SIGTERM or SIGINT (Ctrl+C).
// All in-flight requests are given 15 seconds to complete before force-close.
func (s *Server) Start() error {
	srv := &http.Server{
		Addr:           fmt.Sprintf(":%d", s.cfg.ServerPort),
		Handler:        s.handler,
		ReadTimeout:    time.Duration(s.cfg.ServerReadTimeoutSeconds) * time.Second,
		WriteTimeout:   time.Duration(s.cfg.ServerWriteTimeoutSeconds) * time.Second,
		IdleTimeout:    60 * time.Second,
		MaxHeaderBytes: 1 << 20, // 1 MB
	}

	// Channel that receives OS signals for graceful shutdown.
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGTERM, syscall.SIGINT)

	// Start listening first so we can report the actual bound address.
	listener, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		return fmt.Errorf("gateway: failed to bind port %d: %w", s.cfg.ServerPort, err)
	}

	// Serve in a goroutine so we can block on the signal channel below.
	serveErr := make(chan error, 1)
	go func() {
		s.log.Info("tollgate notary listening",
			zap.String("address", listener.Addr().String()),
			zap.String("environment", s.cfg.Environment),
		)
		if err := srv.Serve(listener); err != nil && err != http.ErrServerClosed {
			serveErr <- err
		}
	}()

	// Block until a shutdown signal or a fatal serve error.
	select {
	case sig := <-quit:
		s.log.Info("shutdown signal received — draining in-flight requests",
			zap.String("signal", sig.String()),
		)
	case err := <-serveErr:
		return fmt.Errorf("gateway: serve error: %w", err)
	}

	// Graceful shutdown — give in-flight requests 15 seconds to complete.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		s.log.Error("graceful shutdown incomplete — forcing close", zap.Error(err))
		return srv.Close()
	}

	s.log.Info("tollgate notary shut down cleanly")
	return nil
}

// chain applies middleware in order: chain(mux, a, b, c) → a(b(c(mux)))
// The first middleware in the list is the outermost (runs first on ingress,
// last on egress).
func chain(h http.Handler, middlewares ...func(http.Handler) http.Handler) http.Handler {
	// Apply in reverse so the first middleware in the list is outermost.
	for i := len(middlewares) - 1; i >= 0; i-- {
		h = middlewares[i](h)
	}
	return h
}
