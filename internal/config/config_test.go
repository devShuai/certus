package config

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"
)

func TestLoadRejectsShortAdminToken(t *testing.T) {
	t.Setenv("CERTUS_ADMIN_TOKEN", "too-short")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "at least 32") {
		t.Fatalf("expected short token error, got %v", err)
	}
}

func TestLoadMFAEncryptionKey(t *testing.T) {
	t.Setenv("CERTUS_MFA_ENCRYPTION_KEY", base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef")))
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.MFAEncryptionKey) != 32 {
		t.Fatalf("unexpected MFA key length: %d", len(cfg.MFAEncryptionKey))
	}
	t.Setenv("CERTUS_MFA_ENCRYPTION_KEY", "not-a-key")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "32 bytes") {
		t.Fatalf("expected invalid MFA key error, got %v", err)
	}
}

func TestLoadMaintenanceRetention(t *testing.T) {
	t.Setenv("CERTUS_CLEANUP_INTERVAL", "30m")
	t.Setenv("CERTUS_AUDIT_RETENTION", "720h")
	t.Setenv("CERTUS_SIGNING_KEY_RETENTION", "2h")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.CleanupInterval.String() != "30m0s" || cfg.SigningKeyRetention.String() != "2h0m0s" {
		t.Fatalf("unexpected maintenance configuration: %#v", cfg)
	}
	t.Setenv("CERTUS_SIGNING_KEY_RETENTION", "30m")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "at least 1h") {
		t.Fatalf("expected signing key retention error, got %v", err)
	}
}

func TestLoadSecretEncryptionKeyRingAndSigningRotation(t *testing.T) {
	key := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	t.Setenv("CERTUS_SECRET_ENCRYPTION_KEYS", "primary="+key)
	t.Setenv("CERTUS_SIGNING_KEY_ROTATION_INTERVAL", "12h")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.SecretEncryptionKeys.Available() ||
		cfg.SecretEncryptionKeys.PrimaryID() != "primary" ||
		cfg.SigningKeyRotation != 12*time.Hour {
		t.Fatalf("unexpected secret key configuration: %#v", cfg)
	}
	t.Setenv("CERTUS_ENV", "production")
	t.Setenv("CERTUS_DATABASE_URL", "postgres://certus@example/certus")
	t.Setenv("CERTUS_SECRET_ENCRYPTION_KEYS", "")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "required") {
		t.Fatalf("expected production secret encryption key error, got %v", err)
	}
}

func TestLoadRateLimitsAndTrustedProxies(t *testing.T) {
	t.Setenv("CERTUS_TRUSTED_PROXIES", "10.0.0.0/8, 192.0.2.10")
	t.Setenv("CERTUS_LOGIN_SOURCE_RATE_LIMIT", "12")
	t.Setenv("CERTUS_LOGIN_SOURCE_RATE_WINDOW", "2m")
	t.Setenv("CERTUS_OAUTH_RATE_LIMIT", "0")
	t.Setenv("CERTUS_REGISTRATION_RATE_LIMIT", "7")
	t.Setenv("CERTUS_REGISTRATION_RATE_WINDOW", "2h")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.TrustedProxies) != 2 ||
		cfg.RateLimits.LoginSource.Limit != 12 ||
		cfg.RateLimits.LoginSource.Window != 2*time.Minute ||
		cfg.RateLimits.Registration.Limit != 7 ||
		cfg.RateLimits.Registration.Window != 2*time.Hour ||
		cfg.RateLimits.OAuth.Enabled() {
		t.Fatalf("unexpected proxy or rate-limit configuration: %#v", cfg)
	}
}

func TestLoadRegistrationConfiguration(t *testing.T) {
	t.Setenv("CERTUS_REGISTRATION_ENABLED", "true")
	t.Setenv("CERTUS_REGISTRATION_REQUIRE_EMAIL", "false")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Registration.Enabled || cfg.Registration.RequireEmail {
		t.Fatalf("unexpected registration configuration: %#v", cfg.Registration)
	}
}

func TestLoadSMTPConfigurationAndSenderName(t *testing.T) {
	t.Setenv("CERTUS_SMTP_HOST", "smtp.exmail.qq.com")
	t.Setenv("CERTUS_SMTP_PORT", "465")
	t.Setenv("CERTUS_SMTP_USERNAME", "support@example.com")
	t.Setenv("CERTUS_SMTP_PASSWORD", "smtp-secret")
	t.Setenv("CERTUS_SMTP_TLS_MODE", "implicit")
	t.Setenv("CERTUS_EMAIL_FROM_ADDRESS", "support@example.com")
	t.Setenv("CERTUS_EMAIL_FROM_NAME", "Certus Support")
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.SMTP.Enabled() ||
		cfg.SMTP.Port != 465 ||
		cfg.SMTP.FromName != "Certus Support" ||
		cfg.SMTP.FromAddress != "support@example.com" {
		t.Fatalf("unexpected SMTP configuration: %#v", cfg.SMTP)
	}
}

func TestLoadRejectsIncompleteSMTPConfiguration(t *testing.T) {
	t.Setenv("CERTUS_SMTP_HOST", "smtp.example.com")
	t.Setenv("CERTUS_SMTP_USERNAME", "support@example.com")
	t.Setenv("CERTUS_EMAIL_FROM_ADDRESS", "support@example.com")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "configured together") {
		t.Fatalf("expected incomplete SMTP error, got %v", err)
	}
}

func TestLoadRejectsUnsafeEmailSenderName(t *testing.T) {
	t.Setenv("CERTUS_SMTP_HOST", "smtp.example.com")
	t.Setenv("CERTUS_SMTP_USERNAME", "support@example.com")
	t.Setenv("CERTUS_SMTP_PASSWORD", "smtp-secret")
	t.Setenv("CERTUS_EMAIL_FROM_ADDRESS", "support@example.com")
	t.Setenv("CERTUS_EMAIL_FROM_NAME", "Certus\r\nBcc: attacker@example.com")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "safe characters") {
		t.Fatalf("expected unsafe sender name error, got %v", err)
	}
}

func TestLoadRequiresHTTPSForProductionRegistration(t *testing.T) {
	t.Setenv("CERTUS_ENV", "production")
	t.Setenv("CERTUS_REGISTRATION_ENABLED", "true")
	t.Setenv("CERTUS_ISSUER", "http://auth.example.com")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("expected production registration HTTPS error, got %v", err)
	}
}

func TestLoadRejectsInvalidRateLimitAndTrustedProxy(t *testing.T) {
	t.Setenv("CERTUS_LOGIN_SOURCE_RATE_WINDOW", "500ms")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "1s-24h") {
		t.Fatalf("expected invalid rate-limit error, got %v", err)
	}
	t.Setenv("CERTUS_LOGIN_SOURCE_RATE_WINDOW", "1m")
	t.Setenv("CERTUS_TRUSTED_PROXIES", "not-an-address")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "IP address or CIDR") {
		t.Fatalf("expected invalid trusted proxy error, got %v", err)
	}
}

func TestLoadAcceptsStrongAdminToken(t *testing.T) {
	t.Setenv("CERTUS_ADMIN_TOKEN", strings.Repeat("a", 32))
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.AdminToken) != 32 {
		t.Fatalf("unexpected token length: %d", len(cfg.AdminToken))
	}
}

func TestLoadValidatesMetricsToken(t *testing.T) {
	t.Setenv("CERTUS_METRICS_TOKEN", "short")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "CERTUS_METRICS_TOKEN") {
		t.Fatalf("expected short metrics token error, got %v", err)
	}
	t.Setenv("CERTUS_METRICS_TOKEN", strings.Repeat("m", 32))
	cfg, err := Load()
	if err != nil || len(cfg.MetricsToken) != 32 {
		t.Fatalf("valid metrics token was rejected: %#v %v", cfg, err)
	}
}

func TestLoadLDAPConfiguration(t *testing.T) {
	t.Setenv("CERTUS_LDAP_URL", "ldaps://directory.example.com")
	t.Setenv("CERTUS_LDAP_BASE_DN", "ou=people,dc=example,dc=com")
	t.Setenv("CERTUS_LDAP_BIND_DN", "cn=reader,dc=example,dc=com")
	t.Setenv("CERTUS_LDAP_BIND_PASSWORD", "reader-secret")
	t.Setenv("CERTUS_LDAP_USER_FILTER", "(&(objectClass=person)(uid={username}))")

	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.LDAP.Enabled() || cfg.LDAP.UsernameAttribute != "uid" {
		t.Fatalf("unexpected LDAP configuration: %#v", cfg.LDAP)
	}
}

func TestLoadRejectsIncompleteLDAPConfiguration(t *testing.T) {
	t.Setenv("CERTUS_LDAP_URL", "ldap://directory.example.com")
	t.Setenv("CERTUS_LDAP_BASE_DN", "dc=example,dc=com")
	t.Setenv("CERTUS_LDAP_USER_FILTER", "(uid=missing-placeholder)")

	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "{username}") {
		t.Fatalf("expected LDAP filter error, got %v", err)
	}
}

func TestLoadRejectsIncompleteExternalOIDCConfiguration(t *testing.T) {
	t.Setenv("CERTUS_EXTERNAL_OIDC_ISSUER", "https://idp.example.com")
	t.Setenv("CERTUS_EXTERNAL_OIDC_CLIENT_ID", "certus")

	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "must be configured together") {
		t.Fatalf("expected external OIDC configuration error, got %v", err)
	}
}
