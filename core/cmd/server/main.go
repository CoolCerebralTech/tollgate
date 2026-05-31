package main

import (
	"fmt"
	"os"
	"time"
	"tollgate/internal/agent"
	"tollgate/internal/audit"
	"tollgate/internal/baseline"
	"tollgate/internal/config"
	"tollgate/internal/gateway"
	"tollgate/internal/policy"
	"tollgate/internal/ratelimit"
	"tollgate/internal/signing"

	"go.uber.org/zap"
)

func main() {
	// ── Step 1: Config ────────────────────────────────────────────────────────
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	cfg.PrintStartupSummary()

	// ── Step 2: Logger ────────────────────────────────────────────────────────
	var log *zap.Logger
	if cfg.IsProduction() {
		log, err = zap.NewProduction()
	} else {
		log, err = zap.NewDevelopment()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "FATAL: failed to init logger:", err)
		os.Exit(1)
	}
	defer log.Sync()

	// ── Step 3: Audit Database ────────────────────────────────────────────────
	adb, err := audit.New(cfg.AuditDBPath)
	if err != nil {
		log.Fatal("FATAL: audit database failed to open", zap.Error(err))
	}
	defer adb.Close()
	log.Info("audit database ready", zap.String("path", cfg.AuditDBPath))

	// ── Step 4: Signing Service ───────────────────────────────────────────────
	// SECURITY: signing key is loaded once here. Never passed around as a string
	// after this point — only the *signing.Signer is passed to other modules.
	signer, err := signing.New(cfg.SigningKeyHex)
	if err != nil {
		log.Fatal("FATAL: signing service failed to load key", zap.Error(err))
	}
	log.Info("signing service ready", zap.String("public_address", signer.PublicAddress()))

	// ── Step 5: Policy Loader ─────────────────────────────────────────────────
	loader, err := policy.NewLoader(cfg.PolicyFilePath, cfg.PolicyHotReload, log)
	if err != nil {
		log.Fatal("FATAL: policy loader failed", zap.Error(err))
	}

	// ── Step 6: Behavioral Baseline ───────────────────────────────────────────
	tracker := baseline.NewTracker(500)
	scorer := baseline.NewScorer(tracker)

	// ── Step 7: Policy Engine ─────────────────────────────────────────────────
	engine := policy.NewEngine(loader, adb, scorer, log)

	// ── Step 8: Startup Canary Tests ──────────────────────────────────────────
	// Confirms the policy engine is wired correctly before serving real traffic.
	// Crashes the server if any canary produces the wrong result.
	log.Info("running startup canary checks...")
	if err := engine.RunCanary(
		"trading-bot-01",
		"0xdef4560000000000000000000000000000000000",
		"defi_yield_optimization",
	); err != nil {
		log.Fatal("FATAL: startup canary failed — policy engine misconfigured", zap.Error(err))
	}
	log.Info("startup canaries passed")

	// ── Step 9: Agent Registry ────────────────────────────────────────────────
	registry, err := agent.NewRegistry(adb, cfg.AgentTokenSecret, log)
	if err != nil {
		log.Fatal("FATAL: agent registry failed to initialize", zap.Error(err))
	}

	// ── Step 10: Rate Limiter ─────────────────────────────────────────────────
	limiter := ratelimit.New(cfg.GlobalRateLimitRPS, cfg.RateLimitPerAgentRPS, cfg.RateLimitBurst)

	// ── Step 11: Dry Run Warning ──────────────────────────────────────────────
	// PrintStartupSummary already printed the banner. Log it again for the
	// structured log pipeline so monitoring systems can alert on it.
	if cfg.IsDryRun() {
		log.Warn("DRY RUN MODE ACTIVE — all requests will be approved regardless of policy")
	}

	// ── Step 12: Issue a dev token if in development ──────────────────────────
	// Prints a ready-to-use agent token so you can test immediately.
	// Never done in production.
	if !cfg.IsProduction() {
		tok, err := registry.IssueToken("trading-bot-01")
		if err != nil {
			log.Warn("could not issue dev token", zap.Error(err))
		} else {
			log.Info("─────────────────────────────────────────────────────")
			log.Info("DEV TOKEN (trading-bot-01) — use in Authorization header")
			log.Info("Bearer " + tok)
			log.Info("Token expires in 30 days")
			log.Info("─────────────────────────────────────────────────────")
		}
	}

	// ── Step 13: Start HTTP Server ────────────────────────────────────────────
	deps := gateway.Deps{
		PolicyEngine:  engine,
		Signer:        signer,
		AuditDB:       adb,
		AgentRegistry: registry,
		RateLimiter:   limiter,
		Baseline:      scorer,
		TTLSeconds:    cfg.ApprovalTokenTTLSeconds,
		DryRun:        cfg.IsDryRun(),
	}

	srv := gateway.NewServer(cfg, deps, log)

	log.Info("tollgate notary starting",
		zap.Int("port", cfg.ServerPort),
		zap.String("public_address", signer.PublicAddress()),
		zap.String("policy_version", func() string {
			v, _, _ := engine.LoaderStatus()
			return v
		}()),
		zap.Time("started_at", time.Now().UTC()),
	)

	if err := srv.Start(); err != nil {
		log.Fatal("server stopped with error", zap.Error(err))
	}
}
