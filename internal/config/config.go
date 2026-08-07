package config

import (
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"certus/internal/federation"
	"certus/internal/mailer"
	"certus/internal/mfa"
	"certus/internal/ratelimit"
	"certus/internal/secrets"
)

type Config struct {
	Address              string
	Issuer               string
	Environment          string
	DatabaseURL          string
	AdminToken           string
	MetricsToken         string
	MFAEncryptionKey     []byte
	SecretEncryptionKeys secrets.KeyRing
	TrustedProxies       []netip.Prefix
	Registration         RegistrationConfig
	SMTP                 mailer.Config
	RateLimits           RateLimitConfig
	LDAP                 LDAPConfig
	ExternalOIDC         ExternalOIDCConfig
	ReadHeaderTimeout    time.Duration
	IdleTimeout          time.Duration
	ShutdownTimeout      time.Duration
	CleanupInterval      time.Duration
	AuditRetention       time.Duration
	SigningKeyRetention  time.Duration
	SigningKeyRotation   time.Duration
	EmailVerificationTTL time.Duration
}

type RateLimitConfig struct {
	LoginSource       ratelimit.Policy
	LoginIdentity     ratelimit.Policy
	Registration      ratelimit.Policy
	MFA               ratelimit.Policy
	OAuth             ratelimit.Policy
	Device            ratelimit.Policy
	EmailVerification ratelimit.Policy
}

type RegistrationConfig struct {
	Enabled      bool
	RequireEmail bool
}

type LDAPConfig = federation.LDAPConfig
type ExternalOIDCConfig = federation.ExternalOIDCConfig

func Load() (Config, error) {
	cfg := Config{
		Address:     env("CERTUS_ADDR", ":8080"),
		Issuer:      strings.TrimRight(env("CERTUS_ISSUER", "http://localhost:8080"), "/"),
		Environment: env("CERTUS_ENV", "development"),
		DatabaseURL: strings.TrimSpace(os.Getenv("CERTUS_DATABASE_URL")),
		AdminToken:  strings.TrimSpace(os.Getenv("CERTUS_ADMIN_TOKEN")),
		MetricsToken: strings.TrimSpace(
			os.Getenv("CERTUS_METRICS_TOKEN"),
		),
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
	cfg.Registration.Enabled, err = boolean("CERTUS_REGISTRATION_ENABLED", false)
	if err != nil {
		return Config{}, err
	}
	cfg.Registration.RequireEmail, err = boolean("CERTUS_REGISTRATION_REQUIRE_EMAIL", true)
	if err != nil {
		return Config{}, err
	}
	cfg.SMTP = mailer.Config{
		Host:        strings.TrimSpace(os.Getenv("CERTUS_SMTP_HOST")),
		Username:    strings.TrimSpace(os.Getenv("CERTUS_SMTP_USERNAME")),
		Password:    os.Getenv("CERTUS_SMTP_PASSWORD"),
		TLSMode:     mailer.TLSMode(strings.ToLower(env("CERTUS_SMTP_TLS_MODE", string(mailer.TLSImplicit)))),
		FromAddress: strings.TrimSpace(os.Getenv("CERTUS_EMAIL_FROM_ADDRESS")),
		FromName:    env("CERTUS_EMAIL_FROM_NAME", "Certus"),
	}
	defaultSMTPPort := 465
	if cfg.SMTP.TLSMode == mailer.TLSStartTLS {
		defaultSMTPPort = 587
	}
	cfg.SMTP.Port, err = integer("CERTUS_SMTP_PORT", defaultSMTPPort)
	if err != nil {
		return Config{}, fmt.Errorf("CERTUS_SMTP_PORT must be an integer")
	}
	if !cfg.SMTP.Enabled() && strings.TrimSpace(os.Getenv("CERTUS_SMTP_PORT")) == "" {
		cfg.SMTP.Port = 0
	}
	if err := cfg.SMTP.Validate(); err != nil {
		return Config{}, fmt.Errorf("SMTP configuration: %w", err)
	}
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
	cfg.SigningKeyRotation, err = duration("CERTUS_SIGNING_KEY_ROTATION_INTERVAL", 24*time.Hour)
	if err != nil || cfg.SigningKeyRotation < 0 ||
		cfg.SigningKeyRotation > 0 && cfg.SigningKeyRotation < time.Hour {
		return Config{}, fmt.Errorf("CERTUS_SIGNING_KEY_ROTATION_INTERVAL must be zero or at least 1h")
	}
	if cfg.AdminToken != "" && len(cfg.AdminToken) < 32 {
		return Config{}, fmt.Errorf("CERTUS_ADMIN_TOKEN must contain at least 32 characters")
	}
	if cfg.MetricsToken != "" && len(cfg.MetricsToken) < 32 {
		return Config{}, fmt.Errorf("CERTUS_METRICS_TOKEN must contain at least 32 characters")
	}
	cfg.MFAEncryptionKey, err = mfa.DecodeEncryptionKey(os.Getenv("CERTUS_MFA_ENCRYPTION_KEY"))
	if err != nil {
		return Config{}, fmt.Errorf("CERTUS_MFA_ENCRYPTION_KEY: %w", err)
	}
	cfg.SecretEncryptionKeys, err = secrets.ParseKeyRing(os.Getenv("CERTUS_SECRET_ENCRYPTION_KEYS"))
	if err != nil {
		return Config{}, fmt.Errorf("CERTUS_SECRET_ENCRYPTION_KEYS: %w", err)
	}
	cfg.TrustedProxies, err = trustedProxies(os.Getenv("CERTUS_TRUSTED_PROXIES"))
	if err != nil {
		return Config{}, fmt.Errorf("CERTUS_TRUSTED_PROXIES: %w", err)
	}
	cfg.RateLimits.LoginSource, err = rateLimitPolicy(
		"CERTUS_LOGIN_SOURCE_RATE_LIMIT", "CERTUS_LOGIN_SOURCE_RATE_WINDOW",
		30, time.Minute,
	)
	if err != nil {
		return Config{}, err
	}
	cfg.RateLimits.LoginIdentity, err = rateLimitPolicy(
		"CERTUS_LOGIN_IDENTITY_RATE_LIMIT", "CERTUS_LOGIN_IDENTITY_RATE_WINDOW",
		10, 5*time.Minute,
	)
	if err != nil {
		return Config{}, err
	}
	cfg.RateLimits.Registration, err = rateLimitPolicy(
		"CERTUS_REGISTRATION_RATE_LIMIT", "CERTUS_REGISTRATION_RATE_WINDOW",
		5, time.Hour,
	)
	if err != nil {
		return Config{}, err
	}
	cfg.RateLimits.MFA, err = rateLimitPolicy(
		"CERTUS_MFA_RATE_LIMIT", "CERTUS_MFA_RATE_WINDOW",
		10, 5*time.Minute,
	)
	if err != nil {
		return Config{}, err
	}
	cfg.RateLimits.OAuth, err = rateLimitPolicy(
		"CERTUS_OAUTH_RATE_LIMIT", "CERTUS_OAUTH_RATE_WINDOW",
		600, time.Minute,
	)
	if err != nil {
		return Config{}, err
	}
	cfg.RateLimits.Device, err = rateLimitPolicy(
		"CERTUS_DEVICE_RATE_LIMIT", "CERTUS_DEVICE_RATE_WINDOW",
		20, time.Minute,
	)
	if err != nil {
		return Config{}, err
	}
	cfg.RateLimits.EmailVerification, err = rateLimitPolicy(
		"CERTUS_EMAIL_VERIFICATION_RATE_LIMIT", "CERTUS_EMAIL_VERIFICATION_RATE_WINDOW",
		5, 10*time.Minute,
	)
	if err != nil {
		return Config{}, err
	}
	cfg.EmailVerificationTTL, err = duration("CERTUS_EMAIL_VERIFICATION_TTL", 30*time.Minute)
	if err != nil || cfg.EmailVerificationTTL <= 0 {
		return Config{}, fmt.Errorf("CERTUS_EMAIL_VERIFICATION_TTL must be a positive duration")
	}
	if strings.EqualFold(cfg.Environment, "production") &&
		cfg.DatabaseURL != "" &&
		!cfg.SecretEncryptionKeys.Available() {
		return Config{}, fmt.Errorf("CERTUS_SECRET_ENCRYPTION_KEYS is required with PostgreSQL in production")
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
	if cfg.Registration.Enabled &&
		strings.EqualFold(cfg.Environment, "production") &&
		issuer.Scheme != "https" {
		return Config{}, fmt.Errorf("CERTUS_ISSUER must use HTTPS when registration is enabled in production")
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

func rateLimitPolicy(
	limitName, windowName string,
	defaultLimit int,
	defaultWindow time.Duration,
) (ratelimit.Policy, error) {
	limit, err := integer(limitName, defaultLimit)
	if err != nil || limit < 0 {
		return ratelimit.Policy{}, fmt.Errorf("%s must be a non-negative integer", limitName)
	}
	if limit == 0 {
		return ratelimit.Policy{}, nil
	}
	window, err := duration(windowName, defaultWindow)
	if err != nil {
		return ratelimit.Policy{}, err
	}
	policy := ratelimit.Policy{Limit: limit, Window: window}
	if err := policy.Validate(); err != nil {
		return ratelimit.Policy{}, fmt.Errorf(
			"%s and %s must define 1-1000000 attempts over 1s-24h",
			limitName, windowName,
		)
	}
	return policy, nil
}

func integer(name string, fallback int) (int, error) {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return 0, err
	}
	return parsed, nil
}

func trustedProxies(raw string) ([]netip.Prefix, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	result := make([]netip.Prefix, 0)
	seen := make(map[netip.Prefix]struct{})
	for _, entry := range strings.Split(raw, ",") {
		value := strings.TrimSpace(entry)
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			address, addressErr := netip.ParseAddr(value)
			if addressErr != nil {
				return nil, fmt.Errorf("%q is not an IP address or CIDR", value)
			}
			bits := 128
			if address.Is4() {
				bits = 32
			}
			prefix = netip.PrefixFrom(address.Unmap(), bits)
		}
		prefix = prefix.Masked()
		if _, duplicate := seen[prefix]; duplicate {
			continue
		}
		seen[prefix] = struct{}{}
		result = append(result, prefix)
	}
	return result, nil
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
