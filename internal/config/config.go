package config

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"
)

type Config struct {
	Address           string
	Issuer            string
	Environment       string
	DatabaseURL       string
	ReadHeaderTimeout time.Duration
	IdleTimeout       time.Duration
	ShutdownTimeout   time.Duration
}

func Load() (Config, error) {
	cfg := Config{
		Address:           env("CERTUS_ADDR", ":8080"),
		Issuer:            strings.TrimRight(env("CERTUS_ISSUER", "http://localhost:8080"), "/"),
		Environment:       env("CERTUS_ENV", "development"),
		DatabaseURL:       strings.TrimSpace(os.Getenv("CERTUS_DATABASE_URL")),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	var err error
	cfg.ShutdownTimeout, err = duration("CERTUS_SHUTDOWN_TIMEOUT", 10*time.Second)
	if err != nil {
		return Config{}, err
	}
	issuer, err := url.Parse(cfg.Issuer)
	if err != nil || issuer.Scheme == "" || issuer.Host == "" {
		return Config{}, fmt.Errorf("CERTUS_ISSUER must be an absolute URL")
	}
	return cfg, nil
}

func env(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func duration(name string, fallback time.Duration) (time.Duration, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback, nil
	}
	parsed, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}
	return parsed, nil
}
