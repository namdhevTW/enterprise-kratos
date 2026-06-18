package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/enterprise-idp/idpd/internal/migration"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

const usage = `idpctl — Enterprise IDP management CLI

Usage:
  idpctl <command> [flags]

Commands:
  migrate   Migrate a Kratos instance into a tenant

Run "idpctl <command> -help" for command-specific flags.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(1)
	}

	switch os.Args[1] {
	case "migrate":
		runMigrate(os.Args[2:])
	case "-h", "--help", "help":
		fmt.Fprint(os.Stderr, usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(1)
	}
}

func runMigrate(args []string) {
	fs := flag.NewFlagSet("migrate", flag.ExitOnError)

	kratosConfig  := fs.String("kratos-config", "", "Path to the Kratos kratos.yml config file (required)")
	kratosDB      := fs.String("kratos-db", "", "Kratos source PostgreSQL DSN (overrides dsn in kratos.yml)")
	kratosNID     := fs.String("kratos-nid", "", "Kratos network ID UUID (auto-detected when omitted)")
	targetDB      := fs.String("target-db", "", "IDP target CockroachDB DSN (required)")
	targetTenant  := fs.String("target-tenant", "", "Target tenant slug (required)")
	targetName    := fs.String("target-name", "", "Target tenant display name (defaults to --target-tenant)")
	includeSessions := fs.Bool("include-sessions", false, "Also migrate active sessions")
	dryRun        := fs.Bool("dry-run", false, "Print what would be done without writing to the IDP DB")

	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, `Usage: idpctl migrate [flags]

Migrate a single Kratos instance into a tenant in the Enterprise IDP.

What is migrated:
  kratos.yml   → tenant_flow_policies, tenant_sso_providers
  identity schema → identity_schemas
  identities + traits → identities
  credentials (password hashes, OIDC subjects) → identity_credentials
  active sessions (optional, --include-sessions) → sessions

What is NOT migrated:
  TOTP secrets  — owned by external enterprise services

Flags:`)
		fs.PrintDefaults()
	}

	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	if *kratosConfig == "" {
		slog.Error("--kratos-config is required")
		os.Exit(1)
	}
	if *targetTenant == "" {
		slog.Error("--target-tenant is required")
		os.Exit(1)
	}
	if *targetDB == "" {
		slog.Error("--target-db is required")
		os.Exit(1)
	}

	cfg, err := migration.ParseConfig(*kratosConfig)
	if err != nil {
		slog.Error("failed to parse Kratos config", "err", err)
		os.Exit(1)
	}

	// Resolve Kratos DB DSN: --kratos-db overrides dsn in config YAML.
	kratosDSN := *kratosDB
	if kratosDSN == "" {
		kratosDSN = cfg.DSN
	}
	if kratosDSN == "" {
		slog.Error("Kratos DB DSN is required: set --kratos-db or dsn in kratos.yml")
		os.Exit(1)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()

	// Resolve optional Kratos network ID.
	var nidPtr *uuid.UUID
	if *kratosNID != "" {
		parsed, err := uuid.Parse(*kratosNID)
		if err != nil {
			slog.Error("invalid --kratos-nid", "err", err)
			os.Exit(1)
		}
		nidPtr = &parsed
	}

	slog.Info("connecting to Kratos DB", "dsn", maskDSN(kratosDSN))
	src, err := migration.NewKratosReader(ctx, kratosDSN, nidPtr)
	if err != nil {
		slog.Error("failed to connect to Kratos DB", "err", err)
		os.Exit(1)
	}
	defer src.Close()
	slog.Info("Kratos DB connected", "nid", src.NID())

	if *dryRun {
		slog.Info("dry-run mode: no writes will be performed")
		dryRunReport(ctx, cfg, src)
		return
	}

	slog.Info("connecting to IDP DB", "dsn", maskDSN(*targetDB))
	poolCfg, err := pgxpool.ParseConfig(*targetDB)
	if err != nil {
		slog.Error("failed to parse --target-db", "err", err)
		os.Exit(1)
	}
	dst, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		slog.Error("failed to connect to IDP DB", "err", err)
		os.Exit(1)
	}
	defer dst.Close()
	slog.Info("IDP DB connected")

	migrator := migration.New(cfg, src, dst, migration.Options{
		TargetTenantSlug: *targetTenant,
		TargetTenantName: *targetName,
		IncludeSessions:  *includeSessions,
	})

	if err := migrator.Run(ctx); err != nil {
		slog.Error("migration failed", "err", err)
		os.Exit(1)
	}
}

// dryRunReport prints a summary of what would be migrated without touching the IDP DB.
func dryRunReport(ctx context.Context, cfg *migration.KratosConfig, src *migration.KratosReader) {
	identities, err := src.Identities(ctx)
	if err != nil {
		slog.Error("failed to read identities", "err", err)
		return
	}
	creds, err := src.Credentials(ctx)
	if err != nil {
		slog.Error("failed to read credentials", "err", err)
		return
	}

	credCounts := make(map[string]int)
	for _, c := range creds {
		credCounts[c.Type]++
	}

	fmt.Println("=== DRY RUN REPORT ===")
	fmt.Printf("Identities:      %d\n", len(identities))
	fmt.Printf("Credentials:\n")
	for typ, n := range credCounts {
		fmt.Printf("  %-16s %d\n", typ, n)
	}
	fmt.Printf("OIDC providers:  %d\n", len(cfg.SelfService.Methods.OIDC.Config.Providers))
	fmt.Printf("Policy:\n")
	fmt.Printf("  first factors: %v\n", cfg.AllowedFirstFactors())
	fmt.Printf("  verification:  %v\n", cfg.RequireVerification())
	fmt.Printf("  session TTL:   %s\n", cfg.Session.Lifespan)
}

// maskDSN redacts the password from a DSN string for safe logging.
func maskDSN(dsn string) string {
	// Simple heuristic: replace password= or :<password>@ patterns.
	// Not exhaustive but sufficient for slog output.
	if len(dsn) > 40 {
		return dsn[:20] + "...[redacted]"
	}
	return dsn
}
