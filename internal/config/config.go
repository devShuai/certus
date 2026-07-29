package config

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"certus/internal/mfa"
)

type Config struct {
	Address             string
	Issuer              string
	Environment         string
	DatabaseURL         string
	AdminToken          string
	MFAEncryptionKey    []byte
	LDAP                LDAPConfig
	ExternalOIDC        ExternalOIDCConfig
	ReadHeaderTimeout   time.Duration
	IdleTimeout         time.Duration
	ShutdownTimeout     time.Duration
	CleanupInterval     time.Duration
	AuditRetention      time.Duration
	SigningKeyRetention time.Duration
}

type LDAPConfig struct {
	URL                  string
	StartTLS             bool
	BaseDN               string
	BindDN               string
	BindPassword         string
	UserFilter           string
	UsernameAttribute    string
	DisplayNameAttribute string
	EmailAttribute       string
}

func (c LDAPConfig) Enabled() bool {
	return c.URL != ""
}

type ExternalOIDCConfig struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	Label        string
}

func (c ExternalOIDCConfig) Enabled() bool {
	return c.Issuer != ""
}

func Load() (Config, error) {
	cfg := Config{
		Address:     env("CERTUS_ADDR", ":8080"),
		Issuer:      strings.TrimRight(env("CERTUS_ISSUER", "http://localhost:8080"), "/"),
		Environment: env("CERTUS_ENV", "development"),
		DatabaseURL: strings.TrimSpace(os.Getenv("CERTUS_DATABASE_URL")),
		AdminToken:  strings.TrimSpace(os.Getenv("CERTUS_ADMIN_TOKEN")),
		LDAP: LDAPConfig{
			URL:                  strings.TrimSpace(os.Getenv("CERTUS_LDAP_URL")),
			BaseDN:               strings.TrimSpace(os.Getenv("CERTUS_LDAP_BASE_DN")),
			BindDN:               strings.TrimSpace(os.Getenv("CERTUS_LDAP_BIND_DN")),
			BindPassword:         os.Getenv("CERTUS_LDAP_BIND_PASSWORD"),
			UserFilter:           env("CERTUS_LDAP_USER_FILTER", "(uid={username})"),
			UsernameAttribute:    env("CERTUS_LDAP_USERNAME_ATTRIBUTE", "uid"),
			DisplayNameAttribute: env("CERTUS_LDAP_DISPLAY_NAME_ATTRIBUTE", "displayName"),
			EmailAttribute:       env("CERTUS_LDAP_EMAIL_ATTRIBUTE", "mail"),
		},
		ExternalOIDC: ExternalOIDCConfig{
			Issuer:       strings.TrimRight(strings.TrimSpace(os.Getenv("CERTUS_EXTERNAL_OIDC_ISSUER")), "/"),
			ClientID:     strings.TrimSpace(os.Getenv("CERTUS_EXTERNAL_OIDC_CLIENT_ID")),
			ClientSecret: os.Getenv("CERTUS_EXTERNAL_OIDC_CLIENT_SECRET"),
			Label:        env("CERTUS_EXTERNAL_OIDC_LABEL", "外部身份提供商"),
		},
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	var err error
	cfg.LDAP.StartTLS, err = boolean("CERTUS_LDAP_START_TLS", false)
	if err != nil {
		return Config{}, err
	}
	cfg.ShutdownTimeout, err = duration("CERTUS_SHUTDOWN_TIMEOUT", 10*time.Second)
	if err != nil {
		return Config{}, err
	}
	cfg.CleanupInterval, err = duration("CERTUS_CLEANUP_INTERVAL", 15*time.Minute)
	if err != nil || cfg.CleanupInterval < 0 {
		return Config{}, fmt.Errorf("CERTUS_CLEANUP_INTERVAL must be a non-negative duration")
	}
	cfg.AuditRetention, err = duration("CERTUS_AUDIT_RETENTION", 90*24*time.Hour)
	if err != nil || cfg.AuditRetention <= 0 {
		return Config{}, fmt.Errorf("CERTUS_AUDIT_RETENTION must be a positive duration")
	}
	cfg.SigningKeyRetention, err = duration("CERTUS_SIGNING_KEY_RETENTION", 24*time.Hour)
	if err != nil || cfg.SigningKeyRetention < time.Hour {
		return Config{}, fmt.Errorf("CERTUS_SIGNING_KEY_RETENTION must be at least 1h")
	}
	if cfg.AdminToken != "" && len(cfg.AdminToken) < 32 {
		return Config{}, fmt.Errorf("CERTUS_ADMIN_TOKEN must contain at least 32 characters")
	}
	cfg.MFAEncryptionKey, err = mfa.DecodeEncryptionKey(os.Getenv("CERTUS_MFA_ENCRYPTION_KEY"))
	if err != nil {
		return Config{}, fmt.Errorf("CERTUS_MFA_ENCRYPTION_KEY: %w", err)
	}
	issuer, err := url.Parse(cfg.Issuer)
	if err != nil || issuer.Scheme == "" || issuer.Host == "" {
		return Config{}, fmt.Errorf("CERTUS_ISSUER must be an absolute URL")
	}
	if err := validateLDAP(cfg.LDAP); err != nil {
		return Config{}, err
	}
	if err := validateExternalOIDC(cfg.ExternalOIDC); err != nil {
		return Config{}, err
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

func boolean(name string, fallback bool) (bool, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback, nil
	}
	switch strings.ToLower(value) {
	case "true", "1", "yes":
		return true, nil
	case "false", "0", "no":
		return false, nil
	default:
		return false, fmt.Errorf("%s must be a boolean", name)
	}
}

func validateLDAP(cfg LDAPConfig) error {
	if !cfg.Enabled() {
		if cfg.BaseDN != "" || cfg.BindDN != "" || cfg.BindPassword != "" {
			return fmt.Errorf("CERTUS_LDAP_URL is required when LDAP settings are configured")
		}
		return nil
	}
	endpoint, err := url.Parse(cfg.URL)
	if err != nil || endpoint.Host == "" || (endpoint.Scheme != "ldap" && endpoint.Scheme != "ldaps") {
		return fmt.Errorf("CERTUS_LDAP_URL must use ldap:// or ldaps://")
	}
	if cfg.StartTLS && endpoint.Scheme != "ldap" {
		return fmt.Errorf("CERTUS_LDAP_START_TLS is only valid with ldap://")
	}
	if cfg.BaseDN == "" {
		return fmt.Errorf("CERTUS_LDAP_BASE_DN is required")
	}
	if !strings.Contains(cfg.UserFilter, "{username}") {
		return fmt.Errorf("CERTUS_LDAP_USER_FILTER must contain {username}")
	}
	if (cfg.BindDN == "") != (cfg.BindPassword == "") {
		return fmt.Errorf("CERTUS_LDAP_BIND_DN and CERTUS_LDAP_BIND_PASSWORD must be configured together")
	}
	return nil
}

func validateExternalOIDC(cfg ExternalOIDCConfig) error {
	configured := 0
	for _, value := range []string{cfg.Issuer, cfg.ClientID, cfg.ClientSecret} {
		if value != "" {
			configured++
		}
	}
	if configured == 0 {
		return nil
	}
	if configured != 3 {
		return fmt.Errorf("CERTUS_EXTERNAL_OIDC_ISSUER, CERTUS_EXTERNAL_OIDC_CLIENT_ID and CERTUS_EXTERNAL_OIDC_CLIENT_SECRET must be configured together")
	}
	issuer, err := url.Parse(cfg.Issuer)
	if err != nil || issuer.Scheme == "" || issuer.Host == "" || issuer.RawQuery != "" || issuer.Fragment != "" {
		return fmt.Errorf("CERTUS_EXTERNAL_OIDC_ISSUER must be an absolute issuer URL")
	}
	if issuer.Scheme != "https" && !(issuer.Scheme == "http" && strings.EqualFold(issuer.Hostname(), "localhost")) {
		return fmt.Errorf("CERTUS_EXTERNAL_OIDC_ISSUER must use HTTPS (HTTP is allowed only for localhost)")
	}
	return nil
}
