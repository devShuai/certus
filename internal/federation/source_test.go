package federation

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"certus/internal/secrets"
)

func TestSourceServiceEncryptsAndPreservesOIDCSecret(t *testing.T) {
	repository := NewMemorySourceRepository()
	service := NewSourceService(repository, testSourceKeyRing(t, "current", 7))
	service.now = func() time.Time {
		return time.Date(2026, time.July, 30, 12, 0, 0, 0, time.UTC)
	}
	source, err := service.Create(context.Background(), CreateSource{
		ID:   "workforce",
		Name: "Workforce SSO",
		Type: SourceOIDC,
		OIDC: &OIDCSourceInput{
			Issuer:       "https://id.example.com/",
			ClientID:     "certus",
			ClientSecret: "top-secret",
			Scopes:       []string{"openid", "profile", "openid"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !source.SecretConfigured || source.SecretKeyID != "current" ||
		strings.Contains(string(source.SecretCiphertext), "top-secret") {
		t.Fatalf("source secret was not encrypted: %#v", source)
	}
	encoded, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "top-secret") ||
		strings.Contains(string(encoded), "SecretCiphertext") {
		t.Fatalf("source response leaked secret material: %s", encoded)
	}
	enabled := false
	replaced, err := service.Replace(context.Background(), source.ID, ReplaceSource{
		Name:    "Workforce",
		Enabled: &enabled,
		OIDC: &OIDCSourceInput{
			Issuer:   "https://id.example.com",
			ClientID: "certus-updated",
			Scopes:   []string{"openid", "email"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if replaced.Enabled || !replaced.SecretConfigured {
		t.Fatalf("replacement did not preserve source state: %#v", replaced)
	}
	enabled = true
	if _, err := service.Replace(context.Background(), source.ID, ReplaceSource{
		Name:    "Workforce",
		Enabled: &enabled,
		OIDC: &OIDCSourceInput{
			Issuer:   "https://id.example.com",
			ClientID: "certus-updated",
			Scopes:   []string{"openid", "email"},
		},
	}); err != nil {
		t.Fatal(err)
	}
	authenticator, err := service.OIDCAuthenticator(
		context.Background(),
		source.ID,
		"https://auth.example.com/login/oidc/callback",
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if authenticator.config.ClientSecret != "top-secret" ||
		authenticator.config.ProviderID != "identity-source:workforce" {
		t.Fatalf("unexpected dynamic authenticator: %#v", authenticator.config)
	}
}

func TestSourceServiceValidatesLDAPAndSupportsAnonymousBind(t *testing.T) {
	service := NewSourceService(NewMemorySourceRepository(), secrets.KeyRing{})
	source, err := service.Create(context.Background(), CreateSource{
		ID:   "directory",
		Name: "Directory",
		Type: SourceLDAP,
		LDAP: &LDAPSourceInput{
			URL:        "ldap://directory.example.com",
			BaseDN:     "ou=people,dc=example,dc=com",
			UserFilter: "(&(objectClass=person)(uid={username}))",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if source.SecretConfigured || source.LDAP.UsernameAttribute != "uid" {
		t.Fatalf("unexpected anonymous LDAP source: %#v", source)
	}
	_, err = service.Create(context.Background(), CreateSource{
		ID:   "broken",
		Name: "Broken",
		Type: SourceLDAP,
		LDAP: &LDAPSourceInput{
			URL:        "ldaps://directory.example.com",
			StartTLS:   true,
			BaseDN:     "dc=example,dc=com",
			UserFilter: "(uid={username})",
		},
	})
	if !errors.Is(err, ErrInvalidSource) {
		t.Fatalf("invalid StartTLS configuration was accepted: %v", err)
	}
}

func TestSourceServiceRequiresEncryptionAndRewrapsSecrets(t *testing.T) {
	repository := NewMemorySourceRepository()
	unavailable := NewSourceService(repository, secrets.KeyRing{})
	_, err := unavailable.Create(context.Background(), CreateSource{
		ID:   "upstream",
		Name: "Upstream",
		Type: SourceOIDC,
		OIDC: &OIDCSourceInput{
			Issuer:       "https://id.example.com",
			ClientID:     "certus",
			ClientSecret: "secret",
		},
	})
	if !errors.Is(err, ErrSourceEncryptionUnavailable) {
		t.Fatalf("OIDC secret was stored without encryption: %v", err)
	}

	oldRing := testSourceKeyRing(t, "old", 3)
	oldService := NewSourceService(repository, oldRing)
	if _, err := oldService.Create(context.Background(), CreateSource{
		ID:   "upstream",
		Name: "Upstream",
		Type: SourceOIDC,
		OIDC: &OIDCSourceInput{
			Issuer:       "https://id.example.com",
			ClientID:     "certus",
			ClientSecret: "secret",
		},
	}); err != nil {
		t.Fatal(err)
	}
	newKey := base64.StdEncoding.EncodeToString(bytesOf(9))
	oldKey := base64.StdEncoding.EncodeToString(bytesOf(3))
	rotatedRing, err := secrets.ParseKeyRing("new=" + newKey + ",old=" + oldKey)
	if err != nil {
		t.Fatal(err)
	}
	count, err := RewrapSourceSecrets(context.Background(), repository, rotatedRing)
	if err != nil || count != 1 {
		t.Fatalf("rewrap identity source secret: count=%d err=%v", count, err)
	}
	source, err := repository.Find(context.Background(), "upstream")
	if err != nil || source.SecretKeyID != "new" {
		t.Fatalf("source was not rewrapped: %#v %v", source, err)
	}
	authenticator, err := NewSourceService(repository, rotatedRing).OIDCAuthenticator(
		context.Background(),
		"upstream",
		"https://auth.example.com/login/oidc/callback",
		nil,
	)
	if err != nil || authenticator.config.ClientSecret != "secret" {
		t.Fatalf("rewrapped secret could not be decrypted: %#v %v", authenticator, err)
	}
}

func testSourceKeyRing(t *testing.T, id string, fill byte) secrets.KeyRing {
	t.Helper()
	ring, err := secrets.ParseKeyRing(id + "=" + base64.StdEncoding.EncodeToString(bytesOf(fill)))
	if err != nil {
		t.Fatal(err)
	}
	return ring
}

func bytesOf(fill byte) []byte {
	value := make([]byte, 32)
	for index := range value {
		value[index] = fill
	}
	return value
}
