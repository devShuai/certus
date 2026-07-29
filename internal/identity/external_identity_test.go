package identity

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestResolveExternalIdentityProvisionsAndReusesUser(t *testing.T) {
	repository := NewMemoryUserRepository()
	profile := ExternalProfile{
		ProviderID:  "oidc:https://idp.example.com",
		Subject:     "subject-123",
		Username:    "Alice Smith",
		DisplayName: "Alice",
	}
	first, err := repository.ResolveExternalIdentity(context.Background(), profile, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	second, err := repository.ResolveExternalIdentity(context.Background(), profile, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != second.ID || first.Username != "alice-smith" {
		t.Fatalf("external identity was not reused: first=%#v second=%#v", first, second)
	}
}

func TestResolveExternalIdentityLinksOnlyTrustedEmail(t *testing.T) {
	email := "alice@example.com"
	existing, err := NewUser(CreateUser{
		Username:    "alice",
		DisplayName: "Alice",
		Email:       &email,
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	repository := NewMemoryUserRepository(existing)
	profile := ExternalProfile{
		ProviderID:   "oidc:https://idp.example.com",
		Subject:      "trusted-subject",
		Username:     "external-alice",
		DisplayName:  "External Alice",
		Email:        &email,
		EmailTrusted: true,
	}
	linked, err := repository.ResolveExternalIdentity(context.Background(), profile, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if linked.ID != existing.ID {
		t.Fatalf("trusted email did not link existing user: %#v", linked)
	}

	untrusted := profile
	untrusted.Subject = "untrusted-subject"
	untrusted.Username = "other-alice"
	untrusted.EmailTrusted = false
	untrusted.Email = nil
	separate, err := repository.ResolveExternalIdentity(context.Background(), untrusted, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if separate.ID == existing.ID || !strings.HasPrefix(separate.Username, "other-alice") {
		t.Fatalf("untrusted identity was incorrectly linked: %#v", separate)
	}
}
