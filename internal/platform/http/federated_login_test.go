package httpserver

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"certus/internal/cas"
	"certus/internal/client"
	"certus/internal/config"
	"certus/internal/federation"
	"certus/internal/identity"
	"certus/internal/oauth"
	"certus/internal/oidc"
	"certus/internal/secrets"
	"certus/internal/session"
)

func TestClientBoundDynamicOIDCLoginRoundTrip(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	var issuer string
	var tokenNonce string
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			writeJSON(w, http.StatusOK, map[string]any{
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
				t.Errorf("parse upstream token request: %v", err)
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"access_token": "upstream-access-token",
				"token_type":   "Bearer",
				"expires_in":   60,
				"id_token": dynamicIDToken(t, key, map[string]any{
					"iss":                issuer,
					"sub":                "employee-42",
					"aud":                "certus",
					"exp":                time.Now().Add(time.Minute).Unix(),
					"iat":                time.Now().Add(-time.Second).Unix(),
					"nonce":              tokenNonce,
					"preferred_username": "alice",
					"name":               "Alice",
					"email":              "alice@example.com",
					"email_verified":     true,
				}),
			})
		case "/jwks":
			writeJSON(w, http.StatusOK, map[string]any{"keys": []map[string]string{{
				"kty": "RSA",
				"kid": "dynamic-key",
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

	ring := dynamicSourceKeyRing(t)
	sourceRepository := federation.NewMemorySourceRepository()
	sourceService := federation.NewSourceService(sourceRepository, ring)
	for _, source := range []federation.CreateSource{
		{
			ID:   "workforce",
			Name: "Workforce SSO",
			Type: federation.SourceOIDC,
			OIDC: &federation.OIDCSourceInput{
				Issuer:       issuer,
				ClientID:     "certus",
				ClientSecret: "upstream-secret",
			},
		},
		{
			ID:   "contractors",
			Name: "Contractor SSO",
			Type: federation.SourceOIDC,
			OIDC: &federation.OIDCSourceInput{
				Issuer:       issuer,
				ClientID:     "certus",
				ClientSecret: "upstream-secret",
			},
		},
	} {
		if _, err := sourceService.Create(context.Background(), source); err != nil {
			t.Fatal(err)
		}
	}
	clients := client.NewMemoryRepository(client.Client{
		ID:                      "finance",
		Name:                    "Finance",
		ApplicationType:         client.ApplicationPublic,
		TokenEndpointAuthMethod: client.TokenEndpointAuthNone,
		Protocols:               []client.Protocol{client.ProtocolOAuth21},
		GrantTypes:              []client.GrantType{client.GrantAuthorizationCode},
		RedirectURIs:            []string{"https://finance.example.com/callback"},
		LoginMethods:            []client.LoginMethod{client.LoginOIDC},
		IdentitySourceIDs:       []string{"workforce"},
		AllowedScopes:           []string{"openid"},
		Enabled:                 true,
	})
	users := identity.NewMemoryUserRepository()
	handler, err := NewWithDependencies(
		context.Background(),
		config.Config{
			Issuer:               "https://auth.example.com",
			SecretEncryptionKeys: ring,
		},
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		Dependencies{
			Clients:            clients,
			Users:              users,
			Passwords:          users,
			Sessions:           session.NewMemoryRepository(),
			OAuth:              oauth.NewMemoryRepository(),
			CAS:                cas.NewMemoryRepository(),
			Keys:               &oidc.MemoryKeyRepository{},
			IdentitySources:    sourceRepository,
			OutboundHTTPClient: provider.Client(),
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	returnTo := "/oauth2/authorize?client_id=finance"
	pageRequest := httptest.NewRequest(
		http.MethodGet,
		"/login?continue="+url.QueryEscape(returnTo),
		nil,
	)
	page := httptest.NewRecorder()
	handler.ServeHTTP(page, pageRequest)
	if page.Code != http.StatusOK ||
		!strings.Contains(page.Body.String(), "Workforce SSO") ||
		strings.Contains(page.Body.String(), "Contractor SSO") ||
		!strings.Contains(page.Body.String(), "source_id=workforce") {
		t.Fatalf("bound source login page is incorrect: %d %s", page.Code, page.Body.String())
	}

	startRequest := httptest.NewRequest(
		http.MethodGet,
		"/login/oidc?source_id=workforce&continue="+url.QueryEscape(returnTo),
		nil,
	)
	start := httptest.NewRecorder()
	handler.ServeHTTP(start, startRequest)
	if start.Code != http.StatusFound {
		t.Fatalf("start dynamic OIDC login: %d %s", start.Code, start.Body.String())
	}
	authorizationURL, err := url.Parse(start.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	state := authorizationURL.Query().Get("state")
	tokenNonce = authorizationURL.Query().Get("nonce")
	if authorizationURL.Host != strings.TrimPrefix(issuer, "http://") ||
		state == "" ||
		tokenNonce == "" {
		t.Fatalf("unexpected upstream authorization URL: %s", authorizationURL)
	}
	var transaction *http.Cookie
	for _, cookie := range start.Result().Cookies() {
		if cookie.Name == externalOIDCCookieName {
			transaction = cookie
			break
		}
	}
	if transaction == nil {
		t.Fatal("dynamic OIDC transaction cookie was not issued")
	}
	callbackRequest := httptest.NewRequest(
		http.MethodGet,
		"/login/oidc/callback?code=authorization-code&state="+url.QueryEscape(state),
		nil,
	)
	callbackRequest.AddCookie(transaction)
	callback := httptest.NewRecorder()
	handler.ServeHTTP(callback, callbackRequest)
	if callback.Code != http.StatusSeeOther ||
		callback.Header().Get("Location") != returnTo {
		t.Fatalf("complete dynamic OIDC login: %d %s %s", callback.Code, callback.Header().Get("Location"), callback.Body.String())
	}
	foundSession := false
	for _, cookie := range callback.Result().Cookies() {
		if cookie.Name == sessionCookieName && cookie.Value != "" {
			foundSession = true
			break
		}
	}
	if !foundSession {
		t.Fatal("dynamic OIDC login did not establish a Certus session")
	}

	unboundRequest := httptest.NewRequest(
		http.MethodGet,
		"/login/oidc?source_id=contractors&continue="+url.QueryEscape(returnTo),
		nil,
	)
	unbound := httptest.NewRecorder()
	handler.ServeHTTP(unbound, unboundRequest)
	if unbound.Code != http.StatusBadRequest ||
		!strings.Contains(unbound.Body.String(), `"login_method_not_allowed"`) {
		t.Fatalf("unbound identity source was accepted: %d %s", unbound.Code, unbound.Body.String())
	}
}

func dynamicSourceKeyRing(t *testing.T) secrets.KeyRing {
	t.Helper()
	key := make([]byte, 32)
	for index := range key {
		key[index] = 17
	}
	ring, err := secrets.ParseKeyRing(
		"dynamic-test=" + base64.StdEncoding.EncodeToString(key),
	)
	if err != nil {
		t.Fatal(err)
	}
	return ring
}

func dynamicIDToken(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	t.Helper()
	header, err := json.Marshal(map[string]string{
		"alg": "RS256",
		"kid": "dynamic-key",
		"typ": "JWT",
	})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." +
		base64.RawURLEncoding.EncodeToString(payload)
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}
