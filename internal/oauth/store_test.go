package oauth

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestAuthorizationCodePKCEMismatchDoesNotConsumeCode(t *testing.T) {
	repository := NewMemoryRepository()
	now := time.Now().UTC()
	code := AuthorizationCode{
		Hash:          []byte("code-hash"),
		ClientID:      "client",
		RedirectURI:   "https://app.example/callback",
		CodeChallenge: "expected-challenge",
		ExpiresAt:     now.Add(time.Minute),
	}
	if err := repository.SaveAuthorizationCode(context.Background(), code); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.ConsumeAuthorizationCode(context.Background(), code.Hash, code.ClientID, code.RedirectURI, "wrong-challenge", now); !errors.Is(err, ErrGrantNotFound) {
		t.Fatalf("unexpected mismatch result: %v", err)
	}
	if _, err := repository.ConsumeAuthorizationCode(context.Background(), code.Hash, code.ClientID, code.RedirectURI, code.CodeChallenge, now); err != nil {
		t.Fatalf("correct PKCE could not consume code: %v", err)
	}
	if _, err := repository.ConsumeAuthorizationCode(context.Background(), code.Hash, code.ClientID, code.RedirectURI, code.CodeChallenge, now); !errors.Is(err, ErrGrantConsumed) {
		t.Fatalf("authorization code was reusable: %v", err)
	}
}

func TestOIDCClientSessionLifecycle(t *testing.T) {
	repository := NewMemoryRepository()
	ctx := context.Background()
	now := time.Now().UTC()
	for _, value := range []OIDCClientSession{
		{SessionID: "session", ClientID: "alpha", UserID: "user", CreatedAt: now},
		{SessionID: "session", ClientID: "beta", UserID: "user", CreatedAt: now},
		{SessionID: "other", ClientID: "alpha", UserID: "user", CreatedAt: now},
	} {
		if err := repository.SaveOIDCClientSession(ctx, value); err != nil {
			t.Fatal(err)
		}
	}
	items, err := repository.ListOIDCClientSessions(ctx, "session")
	if err != nil || len(items) != 2 {
		t.Fatalf("unexpected OIDC client sessions: %#v %v", items, err)
	}
	if err := repository.DeleteOIDCClientSessions(ctx, "session"); err != nil {
		t.Fatal(err)
	}
	items, err = repository.ListOIDCClientSessions(ctx, "session")
	if err != nil || len(items) != 0 {
		t.Fatalf("OIDC client sessions were not deleted: %#v %v", items, err)
	}
	items, err = repository.ListOIDCClientSessions(ctx, "other")
	if err != nil || len(items) != 1 {
		t.Fatalf("unrelated OIDC client session was deleted: %#v %v", items, err)
	}
}

func TestConsentLifecycleAndScopeExpansion(t *testing.T) {
	repository := NewMemoryRepository()
	ctx := context.Background()
	grantedAt := time.Now().UTC().Add(-time.Minute)
	consent, err := repository.GrantConsent(ctx, "user", "client", []string{"openid"}, grantedAt)
	if err != nil || !consent.Covers([]string{"openid"}) || consent.Covers([]string{"openid", "email"}) {
		t.Fatalf("unexpected initial consent: %#v %v", consent, err)
	}
	updatedAt := time.Now().UTC()
	consent, err = repository.GrantConsent(ctx, "user", "client", []string{"email", "openid"}, updatedAt)
	if err != nil || !consent.Covers([]string{"openid", "email"}) ||
		!consent.GrantedAt.Equal(grantedAt) || !consent.UpdatedAt.Equal(updatedAt) {
		t.Fatalf("scope expansion did not preserve consent history: %#v %v", consent, err)
	}
	items, err := repository.ListConsentsByUser(ctx, "user")
	if err != nil || len(items) != 1 {
		t.Fatalf("unexpected consent list: %#v %v", items, err)
	}
	if err := repository.DeleteConsent(ctx, "user", "client", time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.FindConsent(ctx, "user", "client"); !errors.Is(err, ErrConsentNotFound) {
		t.Fatalf("deleted consent remained available: %v", err)
	}
}

func TestRefreshReuseRevokesReplacementFamily(t *testing.T) {
	repository := NewMemoryRepository()
	now := time.Now().UTC()
	current := RefreshToken{
		Hash:      []byte("current"),
		FamilyID:  "family",
		ClientID:  "client",
		UserID:    "user",
		Scope:     []string{"openid"},
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
	}
	if err := repository.SaveRefreshToken(context.Background(), current); err != nil {
		t.Fatal(err)
	}
	familyAccess := AccessToken{
		Hash:      []byte("family-access"),
		ClientID:  current.ClientID,
		UserID:    current.UserID,
		FamilyID:  current.FamilyID,
		Scope:     current.Scope,
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
	}
	if err := repository.SaveAccessToken(context.Background(), familyAccess); err != nil {
		t.Fatal(err)
	}
	replacement := RefreshToken{
		Hash:      []byte("replacement"),
		ClientID:  "client",
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
	}
	if _, err := repository.RotateRefreshToken(context.Background(), current.Hash, replacement, now); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.RotateRefreshToken(context.Background(), current.Hash, RefreshToken{Hash: []byte("attacker"), ClientID: "client"}, now); !errors.Is(err, ErrRefreshReuse) {
		t.Fatalf("reuse was not detected: %v", err)
	}
	if _, err := repository.RotateRefreshToken(context.Background(), replacement.Hash, RefreshToken{Hash: []byte("next"), ClientID: "client"}, now); !errors.Is(err, ErrRefreshReuse) {
		t.Fatalf("replacement family was not revoked: %v", err)
	}
	if _, err := repository.FindAccessToken(context.Background(), familyAccess.Hash, now); !errors.Is(err, ErrGrantNotFound) {
		t.Fatalf("refresh reuse did not revoke family access tokens: %v", err)
	}
}

func TestSessionAndConsentRevocation(t *testing.T) {
	repository := NewMemoryRepository()
	ctx := context.Background()
	now := time.Now().UTC()
	if _, err := repository.GrantConsent(ctx, "user", "client", []string{"openid", "profile"}, now); err != nil {
		t.Fatal(err)
	}
	code := AuthorizationCode{
		Hash:          []byte("session-code"),
		ClientID:      "client",
		UserID:        "user",
		SessionID:     "session-a",
		RedirectURI:   "https://app.example/callback",
		CodeChallenge: "challenge",
		Scope:         []string{"openid"},
		ExpiresAt:     now.Add(time.Minute),
	}
	accessA := AccessToken{
		Hash: []byte("access-a"), ClientID: "client", UserID: "user", SessionID: "session-a",
		Scope: []string{"openid"}, IssuedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	accessB := AccessToken{
		Hash: []byte("access-b"), ClientID: "client", UserID: "user", SessionID: "session-b",
		Scope: []string{"openid"}, IssuedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	refreshB := RefreshToken{
		Hash: []byte("refresh-b"), FamilyID: "family-b", ClientID: "client", UserID: "user",
		SessionID: "session-b", Scope: []string{"openid"}, IssuedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	if err := repository.SaveAuthorizationCode(ctx, code); err != nil {
		t.Fatal(err)
	}
	for _, token := range []AccessToken{accessA, accessB} {
		if err := repository.SaveAccessToken(ctx, token); err != nil {
			t.Fatal(err)
		}
	}
	if err := repository.SaveRefreshToken(ctx, refreshB); err != nil {
		t.Fatal(err)
	}
	if err := repository.RevokeSessionTokens(ctx, "user", "session-a", now); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.FindAccessToken(ctx, accessA.Hash, now); !errors.Is(err, ErrGrantNotFound) {
		t.Fatalf("session access token remained active: %v", err)
	}
	if _, err := repository.ConsumeAuthorizationCode(
		ctx, code.Hash, code.ClientID, code.RedirectURI, code.CodeChallenge, now,
	); !errors.Is(err, ErrGrantNotFound) {
		t.Fatalf("session authorization code remained active: %v", err)
	}
	if _, err := repository.FindAccessToken(ctx, accessB.Hash, now); err != nil {
		t.Fatalf("unrelated session token was revoked: %v", err)
	}
	if err := repository.DeleteConsent(ctx, "user", "client", now); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.FindAccessToken(ctx, accessB.Hash, now); !errors.Is(err, ErrGrantNotFound) {
		t.Fatalf("consent access token remained active: %v", err)
	}
	if _, err := repository.FindRefreshToken(ctx, refreshB.Hash, now); !errors.Is(err, ErrGrantNotFound) {
		t.Fatalf("consent refresh token remained active: %v", err)
	}
}

func TestDeviceApprovalGrantsConsent(t *testing.T) {
	repository := NewMemoryRepository()
	ctx := context.Background()
	now := time.Now().UTC()
	device := DeviceAuthorization{
		DeviceHash: []byte("device"), UserHash: []byte("user-code"), ClientID: "client",
		Scope: []string{"openid", "profile"}, Status: DevicePending,
		CreatedAt: now, ExpiresAt: now.Add(time.Minute), Interval: time.Second,
	}
	if err := repository.SaveDeviceAuthorization(ctx, device); err != nil {
		t.Fatal(err)
	}
	if err := repository.DecideDeviceAuthorization(
		ctx, device.UserHash, "user", now, []string{"pwd"}, "urn:certus:aal:1", true, now,
	); err != nil {
		t.Fatal(err)
	}
	consent, err := repository.FindConsent(ctx, "user", "client")
	if err != nil || !consent.Covers(device.Scope) {
		t.Fatalf("device approval did not grant consent: %#v %v", consent, err)
	}
}

func TestClientRevocationIncludesMachineTokensAndPendingDevices(t *testing.T) {
	repository := NewMemoryRepository()
	ctx := context.Background()
	now := time.Now().UTC()
	access := AccessToken{
		Hash: []byte("machine-access"), ClientID: "client", Scope: []string{"api.read"},
		IssuedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	other := AccessToken{
		Hash: []byte("other-access"), ClientID: "other", Scope: []string{"api.read"},
		IssuedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	for _, token := range []AccessToken{access, other} {
		if err := repository.SaveAccessToken(ctx, token); err != nil {
			t.Fatal(err)
		}
	}
	device := DeviceAuthorization{
		DeviceHash: []byte("pending-device"), UserHash: []byte("pending-code"), ClientID: "client",
		Scope: []string{"openid"}, Status: DevicePending,
		CreatedAt: now, ExpiresAt: now.Add(time.Minute), Interval: time.Second,
	}
	if err := repository.SaveDeviceAuthorization(ctx, device); err != nil {
		t.Fatal(err)
	}
	if err := repository.RevokeClientTokens(ctx, "client", now); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.FindAccessToken(ctx, access.Hash, now); !errors.Is(err, ErrGrantNotFound) {
		t.Fatalf("disabled client access token remained active: %v", err)
	}
	if _, err := repository.FindAccessToken(ctx, other.Hash, now); err != nil {
		t.Fatalf("unrelated client access token was revoked: %v", err)
	}
	if _, err := repository.PollDeviceAuthorization(ctx, device.DeviceHash, device.ClientID, now); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("pending device authorization was not denied: %v", err)
	}
}

func TestAccessAndRefreshTokenRevocation(t *testing.T) {
	repository := NewMemoryRepository()
	now := time.Now().UTC()
	access := AccessToken{
		Hash:      []byte("access"),
		ClientID:  "client",
		Scope:     []string{"api.read"},
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
	}
	if err := repository.SaveAccessToken(context.Background(), access); err != nil {
		t.Fatal(err)
	}
	if err := repository.RevokeAccessToken(context.Background(), access.Hash, "other-client", now); !errors.Is(err, ErrGrantNotFound) {
		t.Fatalf("another client revoked access token: %v", err)
	}
	if err := repository.RevokeAccessToken(context.Background(), access.Hash, access.ClientID, now); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.FindAccessToken(context.Background(), access.Hash, now); !errors.Is(err, ErrGrantNotFound) {
		t.Fatalf("revoked access token remained active: %v", err)
	}

	refresh := RefreshToken{
		Hash:      []byte("refresh"),
		FamilyID:  "family",
		ClientID:  "client",
		UserID:    "user",
		Scope:     []string{"openid"},
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
	}
	replacement := refresh
	replacement.Hash = []byte("refresh-replacement")
	familyAccess := AccessToken{
		Hash:      []byte("family-access"),
		ClientID:  refresh.ClientID,
		UserID:    refresh.UserID,
		FamilyID:  refresh.FamilyID,
		Scope:     refresh.Scope,
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
	}
	if err := repository.SaveRefreshToken(context.Background(), refresh); err != nil {
		t.Fatal(err)
	}
	if err := repository.SaveRefreshToken(context.Background(), replacement); err != nil {
		t.Fatal(err)
	}
	if err := repository.SaveAccessToken(context.Background(), familyAccess); err != nil {
		t.Fatal(err)
	}
	if err := repository.RevokeRefreshToken(context.Background(), refresh.Hash, refresh.ClientID, now); err != nil {
		t.Fatal(err)
	}
	for _, hash := range [][]byte{refresh.Hash, replacement.Hash} {
		if _, err := repository.FindRefreshToken(context.Background(), hash, now); !errors.Is(err, ErrGrantNotFound) {
			t.Fatalf("revoked refresh family member remained active: %q %v", hash, err)
		}
	}
	if _, err := repository.FindAccessToken(context.Background(), familyAccess.Hash, now); !errors.Is(err, ErrGrantNotFound) {
		t.Fatalf("access token from revoked refresh family remained active: %v", err)
	}
}
