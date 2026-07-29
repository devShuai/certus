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
