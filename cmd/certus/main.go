package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"certus/internal/access"
	"certus/internal/administration"
	"certus/internal/audit"
	"certus/internal/cas"
	"certus/internal/client"
	"certus/internal/config"
	"certus/internal/identity"
	"certus/internal/maintenance"
	"certus/internal/mfa"
	"certus/internal/oauth"
	"certus/internal/oidc"
	httpserver "certus/internal/platform/http"
	"certus/internal/session"
	"certus/internal/storage/postgres"
)

var (
	version   = "dev"
	commit    = "unknown"
	buildTime = "unknown"
)

func main() {
	if len(os.Args) > 1 && (os.Args[1] == "version" || os.Args[1] == "--version") {
		fmt.Printf("certus %s (commit %s, built %s)\n", version, commit, buildTime)
		return
	}

	cfg, err := config.Load()
	if err != nil {
		slog.Error("invalid configuration", "error", err)
		os.Exit(1)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var clients client.Repository = defaultClients()
	var users identity.UserRepository = identity.NewMemoryUserRepository()
	var passwords identity.PasswordRepository = users.(identity.PasswordRepository)
	var sessions session.Repository = session.NewMemoryRepository()
	var oauthRepository oauth.Repository = oauth.NewMemoryRepository()
	var casRepository cas.Repository = cas.NewMemoryRepository()
	var accessRepository access.Repository = access.NewMemoryRepository()
	var administrationRepository administration.Repository = administration.NewMemoryRepository()
	var auditRepository audit.Repository = audit.NewMemoryRepository()
	var mfaRepository mfa.Repository = mfa.NewMemoryRepository()
	var maintenanceRepository maintenance.Repository
	var keys oidc.KeyRepository = &oidc.MemoryKeyRepository{}
	maintenanceRepository = maintenance.NewMemoryRepository(keys)
	if cfg.DatabaseURL != "" {
		pool, err := postgres.Open(ctx, cfg.DatabaseURL)
		if err != nil {
			logger.Error("connect to postgres", "error", err)
			os.Exit(1)
		}
		defer pool.Close()
		if err := postgres.Migrate(ctx, pool); err != nil {
			logger.Error("migrate postgres", "error", err)
			os.Exit(1)
		}
		clients = postgres.NewClientRepository(pool)
		userRepository := postgres.NewUserRepository(pool)
		users = userRepository
		passwords = userRepository
		sessions = postgres.NewSessionRepository(pool)
		oauthRepository = postgres.NewOAuthRepository(pool)
		casRepository = postgres.NewCASRepository(pool)
		accessRepository = postgres.NewAccessRepository(pool)
		administrationRepository = postgres.NewAdministrationRepository(pool)
		auditRepository = postgres.NewAuditRepository(pool)
		mfaRepository = postgres.NewMFARepository(pool)
		keys = postgres.NewOIDCKeyRepository(pool)
		maintenanceRepository = postgres.NewMaintenanceRepository(pool)
		logger.Info("postgres storage enabled")
	} else {
		logger.Warn("in-memory storage enabled; data will not persist")
	}

	maintenanceService := maintenance.NewService(
		maintenanceRepository,
		cfg.AuditRetention,
		cfg.SigningKeyRetention,
	)
	go maintenanceService.Run(ctx, cfg.CleanupInterval, logger)

	handler, err := httpserver.NewWithDependencies(ctx, cfg, logger, httpserver.Dependencies{
		Clients:        clients,
		Users:          users,
		Passwords:      passwords,
		Sessions:       sessions,
		OAuth:          oauthRepository,
		CAS:            casRepository,
		Access:         accessRepository,
		Administration: administrationRepository,
		Audit:          auditRepository,
		MFA:            mfaRepository,
		Maintenance:    maintenanceService,
		Keys:           keys,
	})
	if err != nil {
		logger.Error("initialize protocol execution", "error", err)
		os.Exit(1)
	}
	server := &http.Server{
		Addr:              cfg.Address,
		Handler:           handler,
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		IdleTimeout:       cfg.IdleTimeout,
	}

	go func() {
		logger.Info("certus started", "version", version, "commit", commit, "address", cfg.Address, "issuer", cfg.Issuer)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("server stopped unexpectedly", "error", err)
			os.Exit(1)
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("graceful shutdown failed", "error", err)
		os.Exit(1)
	}
	logger.Info("certus stopped")
}

func defaultClients() client.Repository {
	return client.NewMemoryRepository(client.Client{
		ID:              "specus",
		Name:            "Specus",
		Description:     "示例接入系统",
		ApplicationType: client.ApplicationPublic,
		Protocols:       []client.Protocol{client.ProtocolOAuth21},
		GrantTypes:      []client.GrantType{client.GrantAuthorizationCode, client.GrantRefreshToken},
		RedirectURIs:    []string{"http://localhost:3000/callback"},
		LoginMethods:    []client.LoginMethod{client.LoginPassword, client.LoginLDAP},
		AllowedScopes:   []string{"openid", "profile", "email"},
		Enabled:         true,
	})
}
