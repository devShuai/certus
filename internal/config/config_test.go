package config

import (
	"strings"
	"testing"
)

func TestLoadRejectsShortAdminToken(t *testing.T) {
	t.Setenv("CERTUS_ADMIN_TOKEN", "too-short")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "at least 32") {
		t.Fatalf("expected short token error, got %v", err)
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
