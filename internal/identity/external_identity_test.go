package identity

import (
	"context"
	"errors"
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

func TestExternalIdentityManagementProtectsLastAuthenticationMethod(t *testing.T) {
	repository := NewMemoryUserRepository()
	now := time.Now().UTC()
	profile := ExternalProfile{
		ProviderID:  "identity-source:workforce",
		Subject:     "subject-123",
		Username:    "alice",
		DisplayName: "Alice",
	}
	user, err := repository.ResolveExternalIdentity(context.Background(), profile, now)
	if err != nil {
		t.Fatal(err)
	}
	updated := profile
	updated.Username = "alice.updated"
	updated.DisplayName = "Alice Updated"
	if _, err := repository.ResolveExternalIdentity(context.Background(), updated, now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	items, err := repository.ListExternalIdentities(context.Background(), user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 ||
		items[0].ProviderID != profile.ProviderID ||
		items[0].Username != updated.Username ||
		items[0].DisplayName != updated.DisplayName ||
		!items[0].LastAuthenticatedAt.Equal(now.Add(time.Minute)) {
		t.Fatalf("unexpected external identities: %#v", items)
	}
	if err := repository.DeleteExternalIdentity(
		context.Background(),
		user.ID,
		items[0].ID,
	); !errors.Is(err, ErrLastAuthentication) {
		t.Fatalf("last authentication method was removable: %v", err)
	}
	if err := repository.SetPassword(context.Background(), user.ID, "stored-hash", now); err != nil {
		t.Fatal(err)
	}
	if err := repository.DeleteExternalIdentity(context.Background(), user.ID, items[0].ID); err != nil {
		t.Fatal(err)
	}
	items, err = repository.ListExternalIdentities(context.Background(), user.ID)
	if err != nil || len(items) != 0 {
		t.Fatalf("external identity was not removed: %#v %v", items, err)
	}
}

func TestExternalIdentityCanBeRemovedWhenAnotherProviderRemains(t *testing.T) {
	email := "alice@example.com"
	repository := NewMemoryUserRepository()
	first, err := repository.ResolveExternalIdentity(context.Background(), ExternalProfile{
		ProviderID:   "identity-source:workforce",
		Subject:      "alice-workforce",
		Username:     "alice",
		DisplayName:  "Alice",
		Email:        &email,
		EmailTrusted: true,
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	second, err := repository.ResolveExternalIdentity(context.Background(), ExternalProfile{
		ProviderID:   "identity-source:partners",
		Subject:      "alice-partners",
		Username:     "alice.external",
		DisplayName:  "Alice",
		Email:        &email,
		EmailTrusted: true,
	}, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if second.ID != first.ID {
		t.Fatalf("trusted identities did not link to one user: first=%s second=%s", first.ID, second.ID)
	}
	items, err := repository.ListExternalIdentities(context.Background(), first.ID)
	if err != nil || len(items) != 2 {
		t.Fatalf("unexpected external identities: %#v %v", items, err)
	}
	if err := repository.DeleteExternalIdentity(context.Background(), first.ID, items[0].ID); err != nil {
		t.Fatal(err)
	}
	items, err = repository.ListExternalIdentities(context.Background(), first.ID)
	if err != nil || len(items) != 1 {
		t.Fatalf("unexpected remaining external identities: %#v %v", items, err)
	}
}
