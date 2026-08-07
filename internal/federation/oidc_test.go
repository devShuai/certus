package federation

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestOIDCAuthenticatorUsesPKCEAndValidatesNonce(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var issuer string
	var tokenNonce string
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			writeTestJSON(t, w, map[string]any{
				"issuer":                 issuer,
				"authorization_endpoint": issuer + "/authorize",
				"token_endpoint":         issuer + "/token",
				"jwks_uri":               issuer + "/jwks",
				"response_types_supported": []string{
					"code",
				},
				"subject_types_supported":               []string{"public"},
				"id_token_signing_alg_values_supported": []string{"RS256"},
			})
		case "/token":
			if err := r.ParseForm(); err != nil {
				t.Errorf("parse token form: %v", err)
			}
			if r.Form.Get("code_verifier") != strings.Repeat("v", 64) {
				t.Errorf("PKCE verifier missing: %#v", r.Form)
			}
			idToken := signTestIDToken(t, key, map[string]any{
				"iss":                issuer,
				"sub":                "subject-123",
				"aud":                "certus",
				"exp":                time.Now().Add(time.Minute).Unix(),
				"iat":                time.Now().Add(-time.Second).Unix(),
				"nonce":              tokenNonce,
				"preferred_username": "alice",
				"name":               "Alice",
				"email":              "alice@example.com",
				"email_verified":     true,
			})
			writeTestJSON(t, w, map[string]any{
				"access_token": "upstream-access-token",
				"token_type":   "Bearer",
				"expires_in":   60,
				"id_token":     idToken,
			})
		case "/jwks":
			writeTestJSON(t, w, map[string]any{"keys": []map[string]string{{
				"kty": "RSA",
				"kid": "test-key",
				"use": "sig",
				"alg": "RS256",
				"n":   base64.RawURLEncoding.EncodeToString(key.PublicKey.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.PublicKey.E)).Bytes()),
			}}})
		default:
			http.NotFound(w, r)
		}
	}))
	defer provider.Close()
	issuer = provider.URL

	authenticator := NewOIDCAuthenticator(ExternalOIDCConfig{
		Issuer:       issuer,
		ClientID:     "certus",
		ClientSecret: "secret",
		Label:        "Test IdP",
	}, "https://auth.example.com/login/oidc/callback", provider.Client())
	authorizationURL, err := authenticator.AuthorizationURL(
		context.Background(),
		"state-value",
		"nonce-value",
		strings.Repeat("v", 64),
	)
	if err != nil {
		t.Fatal(err)
	}
	target, err := url.Parse(authorizationURL)
	if err != nil {
		t.Fatal(err)
	}
	if target.Query().Get("state") != "state-value" ||
		target.Query().Get("nonce") != "nonce-value" ||
		target.Query().Get("code_challenge_method") != "S256" ||
		target.Query().Get("code_challenge") == "" {
		t.Fatalf("unexpected authorization URL: %s", authorizationURL)
	}
	tokenNonce = "nonce-value"
	profile, err := authenticator.Exchange(
		context.Background(),
		"authorization-code",
		"nonce-value",
		strings.Repeat("v", 64),
	)
	if err != nil {
		t.Fatal(err)
	}
	if profile.Subject != "subject-123" || profile.Email == nil ||
		!profile.EmailTrusted || !profile.EmailVerified {
		t.Fatalf("unexpected external profile: %#v", profile)
	}

	tokenNonce = "different-nonce"
	if _, err := authenticator.Exchange(
		context.Background(),
		"authorization-code",
		"nonce-value",
		strings.Repeat("v", 64),
	); err == nil || !strings.Contains(err.Error(), "nonce mismatch") {
		t.Fatalf("expected nonce mismatch, got %v", err)
	}
}

func signTestIDToken(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	header, err := json.Marshal(map[string]string{"alg": "RS256", "kid": "test-key", "typ": "JWT"})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func writeTestJSON(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Errorf("encode test response: %v", err)
	}
}
