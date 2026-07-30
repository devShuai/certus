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
