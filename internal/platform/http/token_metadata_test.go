package httpserver

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"certus/internal/cas"
	"certus/internal/client"
	"certus/internal/config"
	"certus/internal/identity"
	"certus/internal/oauth"
	"certus/internal/oidc"
	"certus/internal/session"
)

func TestTokenIntrospectionAndRevocation(t *testing.T) {
	registered, secret, err := client.New(client.CreateClient{
		ID:              "resource-api",
		Name:            "Resource API",
		ApplicationType: client.ApplicationConfidential,
		Protocols:       []client.Protocol{client.ProtocolOAuth21},
		GrantTypes:      []client.GrantType{client.GrantClientCredentials},
		AllowedScopes:   []string{"api.read"},
	})
	if err != nil {
		t.Fatal(err)
	}
	users := identity.NewMemoryUserRepository()
	handler, err := NewWithDependencies(
		context.Background(),
		config.Config{Issuer: "https://auth.example.com"},
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		Dependencies{
			Clients:   client.NewMemoryRepository(registered),
			Users:     users,
			Passwords: users,
			Sessions:  session.NewMemoryRepository(),
			OAuth:     oauth.NewMemoryRepository(),
			CAS:       cas.NewMemoryRepository(),
			Keys:      &oidc.MemoryKeyRepository{},
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	tokenForm := url.Values{
		"grant_type": {string(client.GrantClientCredentials)},
		"scope":      {"api.read"},
	}
	tokenResponse := oauthFormRequest(t, handler, "/oauth2/token", tokenForm, registered.ID, secret)
	if tokenResponse.Code != http.StatusOK {
		t.Fatalf("client credentials token: %d %s", tokenResponse.Code, tokenResponse.Body.String())
	}
	var tokens map[string]any
	if err := json.Unmarshal(tokenResponse.Body.Bytes(), &tokens); err != nil {
		t.Fatal(err)
	}
	accessToken, _ := tokens["access_token"].(string)
	if accessToken == "" {
		t.Fatalf("missing access token: %#v", tokens)
	}

	introspectionForm := url.Values{
		"token":           {accessToken},
		"token_type_hint": {"access_token"},
	}
	introspection := oauthFormRequest(t, handler, "/oauth2/introspect", introspectionForm, registered.ID, secret)
	if introspection.Code != http.StatusOK ||
		!strings.Contains(introspection.Body.String(), `"active":true`) ||
		!strings.Contains(introspection.Body.String(), `"client_id":"resource-api"`) ||
		!strings.Contains(introspection.Body.String(), `"scope":"api.read"`) {
		t.Fatalf("active introspection: %d %s", introspection.Code, introspection.Body.String())
	}

	unauthorized := oauthFormRequest(t, handler, "/oauth2/introspect", introspectionForm, registered.ID, "wrong-secret")
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("introspection accepted invalid client: %d %s", unauthorized.Code, unauthorized.Body.String())
	}

	revocation := oauthFormRequest(t, handler, "/oauth2/revoke", introspectionForm, registered.ID, secret)
	if revocation.Code != http.StatusOK || revocation.Body.Len() != 0 {
		t.Fatalf("token revocation: %d %s", revocation.Code, revocation.Body.String())
	}
	inactive := oauthFormRequest(t, handler, "/oauth2/introspect", introspectionForm, registered.ID, secret)
	if inactive.Code != http.StatusOK || strings.TrimSpace(inactive.Body.String()) != `{"active":false}` {
		t.Fatalf("revoked token remained active: %d %s", inactive.Code, inactive.Body.String())
	}

	unknown := oauthFormRequest(t, handler, "/oauth2/revoke", url.Values{"token": {"unknown-token"}}, registered.ID, secret)
	if unknown.Code != http.StatusOK {
		t.Fatalf("unknown token revocation was not idempotent: %d %s", unknown.Code, unknown.Body.String())
	}

	discovery := httptest.NewRecorder()
	handler.ServeHTTP(discovery, httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil))
	for _, endpoint := range []string{
		`"introspection_endpoint":"https://auth.example.com/oauth2/introspect"`,
		`"revocation_endpoint":"https://auth.example.com/oauth2/revoke"`,
		`"end_session_endpoint":"https://auth.example.com/oauth2/logout"`,
		`"backchannel_logout_supported":true`,
		`"backchannel_logout_session_supported":true`,
	} {
		if !strings.Contains(discovery.Body.String(), endpoint) {
			t.Fatalf("discovery missing %s: %s", endpoint, discovery.Body.String())
		}
	}
}

func oauthFormRequest(t *testing.T, handler http.Handler, target string, form url.Values, clientID, secret string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth(clientID, secret)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}
