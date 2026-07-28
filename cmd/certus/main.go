package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"certus/internal/client"
	"certus/internal/config"
	httpserver "certus/internal/platform/http"
	"certus/internal/storage/postgres"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		slog.Error("invalid configuration", "error", err)
		os.Exit(1)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var clients client.Repository = defaultClients()
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
		logger.Info("postgres storage enabled")
	} else {
		logger.Warn("in-memory storage enabled; data will not persist")
	}

	server := &http.Server{
		Addr:              cfg.Address,
		Handler:           httpserver.NewWithClients(cfg, logger, clients),
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		IdleTimeout:       cfg.IdleTimeout,
	}

	go func() {
		logger.Info("certus started", "address", cfg.Address, "issuer", cfg.Issuer)
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
		ID:           "specus",
		Name:         "Specus",
		Description:  "示例接入系统",
		RedirectURIs: []string{"http://localhost:3000/callback"},
		LoginMethods: []client.LoginMethod{client.LoginPassword, client.LoginLDAP},
		Enabled:      true,
	})
}
