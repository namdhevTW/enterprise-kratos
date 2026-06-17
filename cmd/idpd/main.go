package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/enterprise-idp/idpd/internal/authenticator/adapters/password"
	authnregistry "github.com/enterprise-idp/idpd/internal/authenticator/registry"
	"github.com/enterprise-idp/idpd/internal/flow"
	"github.com/enterprise-idp/idpd/internal/flow/login"
	"github.com/enterprise-idp/idpd/internal/hydra"
	"github.com/enterprise-idp/idpd/internal/identity"
	"github.com/enterprise-idp/idpd/internal/policy"
	"github.com/enterprise-idp/idpd/internal/session"
	internaltenant "github.com/enterprise-idp/idpd/internal/tenant"
)

func main() {
	// -------------------------------------------------------------------------
	// Configuration from environment
	// -------------------------------------------------------------------------
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		slog.Error("DATABASE_URL environment variable is required")
		os.Exit(1)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// -------------------------------------------------------------------------
	// Database connection pool
	// -------------------------------------------------------------------------
	ctx := context.Background()

	poolCfg, err := pgxpool.ParseConfig(dbURL)
	if err != nil {
		slog.Error("failed to parse DATABASE_URL", "err", err)
		os.Exit(1)
	}

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		slog.Error("failed to create connection pool", "err", err)
		os.Exit(1)
	}
	defer pool.Close()

	// Verify connectivity before accepting traffic.
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		slog.Error("database ping failed", "err", err)
		os.Exit(1)
	}
	slog.Info("database connection established")

	// -------------------------------------------------------------------------
	// Authenticator registry
	// -------------------------------------------------------------------------
	authnReg := authnregistry.New()
	authnReg.MustRegister(password.New())
	// REST adapters (TOTP, PassKey, OTP) are registered here when their
	// base URLs are available from config. Example:
	//   authnReg.MustRegister(rest.New("totp", authenticator.SecondFactor, os.Getenv("TOTP_SERVICE_URL"), nil))
	slog.Info("authenticator registry ready", "count", len(authnReg.All()))

	// -------------------------------------------------------------------------
	// Stores
	// -------------------------------------------------------------------------
	tenantStore := internaltenant.NewStore(pool)
	tenantResolver := internaltenant.NewResolver(tenantStore)
	flowStore := flow.NewStore(pool)
	policyStore := policy.NewStore(pool)
	identityStore := identity.NewStore(pool)
	sessionStore := session.NewStore(pool)

	// -------------------------------------------------------------------------
	// Hydra client (optional — only wired when HYDRA_ADMIN_URL is set)
	// -------------------------------------------------------------------------
	var hydraClient *hydra.Client
	if hydraAdminURL := os.Getenv("HYDRA_ADMIN_URL"); hydraAdminURL != "" {
		hydraClient = hydra.NewClient(hydraAdminURL, nil)
		slog.Info("hydra integration enabled", "admin_url", hydraAdminURL)
	} else {
		slog.Info("hydra integration disabled (HYDRA_ADMIN_URL not set)")
	}

	// -------------------------------------------------------------------------
	// Flow engines + session handler
	// -------------------------------------------------------------------------
	loginEngine := login.New(flowStore, policyStore, identityStore, authnReg)
	loginHandler := login.NewHandler(loginEngine, sessionStore, hydraClient)
	sessionHandler := session.NewHandler(sessionStore)

	// -------------------------------------------------------------------------
	// Router
	// -------------------------------------------------------------------------
	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(30 * time.Second))

	// Health check — no tenant context needed.
	r.Get("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	})

	// Tenant-scoped routes. All handlers mounted here can call
	// internaltenant.TenantFromContext(r.Context()) to obtain the resolved tenant.
	r.Route("/t/{tenant-slug}", func(r chi.Router) {
		r.Use(tenantResolver.Handler)
		loginHandler.Mount(r)
		sessionHandler.Mount(r)
	})

	// -------------------------------------------------------------------------
	// HTTP server
	// -------------------------------------------------------------------------
	addr := fmt.Sprintf(":%s", port)
	srv := &http.Server{
		Addr:         addr,
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	slog.Info("idpd starting", "addr", addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		slog.Error("server exited with error", "err", err)
		os.Exit(1)
	}
}
