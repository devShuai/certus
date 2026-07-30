package httpserver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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

func TestIdentitySourceAdminLifecycleAndOIDCProbe(t *testing.T) {
	var issuer string
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/openid-configuration" {
			http.NotFound(w, r)
			return
		}
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
	}))
	defer provider.Close()
	issuer = provider.URL

	key := make([]byte, 32)
	for index := range key {
		key[index] = 11
	}
	ring, err := secrets.ParseKeyRing(
		"test=" + base64.StdEncoding.EncodeToString(key),
	)
	if err != nil {
		t.Fatal(err)
	}
	users := identity.NewMemoryUserRepository()
	sources := federation.NewMemorySourceRepository()
	handler, err := NewWithDependencies(
		context.Background(),
		config.Config{
			Issuer:               "https://auth.example.com",
			AdminToken:           "test-admin-token",
			SecretEncryptionKeys: ring,
		},
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		Dependencies{
			Clients:            client.NewMemoryRepository(),
			Users:              users,
			Passwords:          users,
			Sessions:           session.NewMemoryRepository(),
			OAuth:              oauth.NewMemoryRepository(),
			CAS:                cas.NewMemoryRepository(),
			Keys:               &oidc.MemoryKeyRepository{},
			IdentitySources:    sources,
			OutboundHTTPClient: provider.Client(),
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	created := adminJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/api/v1/admin/identity-sources",
		`{
			"id":"workforce",
			"name":"Workforce SSO",
			"type":"oidc",
			"oidc":{
				"issuer":`+mustJSON(t, issuer)+`,
				"client_id":"certus",
				"client_secret":"upstream-secret",
				"scopes":["openid","profile","email"]
			}
		}`,
	)
	if created.Code != http.StatusCreated ||
		strings.Contains(created.Body.String(), "upstream-secret") ||
		!strings.Contains(created.Body.String(), `"secret_configured":true`) {
		t.Fatalf("create identity source: %d %s", created.Code, created.Body.String())
	}
	probed := adminJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/api/v1/admin/identity-sources/workforce/probe",
		"",
	)
	if probed.Code != http.StatusOK ||
		!strings.Contains(probed.Body.String(), `"status":"available"`) {
		t.Fatalf("probe identity source: %d %s", probed.Code, probed.Body.String())
	}
	replaced := adminJSONRequest(
		t,
		handler,
		http.MethodPut,
		"/api/v1/admin/identity-sources/workforce",
		`{
			"name":"Workforce Identity",
			"enabled":false,
			"oidc":{
				"issuer":`+mustJSON(t, issuer)+`,
				"client_id":"certus-v2",
				"scopes":["openid","email"]
			}
		}`,
	)
	if replaced.Code != http.StatusOK ||
		!strings.Contains(replaced.Body.String(), `"secret_configured":true`) ||
		!strings.Contains(replaced.Body.String(), `"enabled":false`) {
		t.Fatalf("replace identity source: %d %s", replaced.Code, replaced.Body.String())
	}
	listed := adminJSONRequest(
		t,
		handler,
		http.MethodGet,
		"/api/v1/admin/identity-sources",
		"",
	)
	if listed.Code != http.StatusOK ||
		!strings.Contains(listed.Body.String(), `"id":"workforce"`) ||
		strings.Contains(listed.Body.String(), "upstream-secret") {
		t.Fatalf("list identity sources: %d %s", listed.Code, listed.Body.String())
	}
	archived := adminJSONRequest(
		t,
		handler,
		http.MethodDelete,
		"/api/v1/admin/identity-sources/workforce",
		"",
	)
	if archived.Code != http.StatusNoContent {
		t.Fatalf("archive identity source: %d %s", archived.Code, archived.Body.String())
	}
}

func mustJSON(t *testing.T, value string) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}
