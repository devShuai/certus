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
