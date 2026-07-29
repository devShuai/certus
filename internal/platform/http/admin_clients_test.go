package httpserver

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"certus/internal/config"
)

func TestCreateClientReturnsIntegrationParameters(t *testing.T) {
	handler := New(config.Config{
		Issuer:     "https://auth.example.com",
		AdminToken: "test-admin-token",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	request := httptest.NewRequest(http.MethodPost, "/api/v1/admin/clients", bytes.NewBufferString(`{
		"id":"finance",
		"name":"Finance",
		"description":"财务系统",
		"application_type":"confidential",
		"protocols":["oauth2.0","oauth2.1","cas"],
		"grant_types":["authorization_code","refresh_token","client_credentials"],
		"redirect_uris":["https://finance.example.com/oidc/callback"],
		"login_methods":["password"],
		"allowed_scopes":["openid","profile"],
		"cas_version":"3.0",
		"cas_service_urls":["https://finance.example.com/login/cas"],
		"cas_proxy":true,
		"cas_single_logout":true
	}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer test-admin-token")
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	body := response.Body.String()
	if response.Code != http.StatusCreated {
		t.Fatalf("unexpected response: %d %s", response.Code, body)
	}
	for _, expected := range []string{
		`"client_id":"finance"`,
		`"client_secret":"`,
		`"issuer":"https://auth.example.com"`,
		`"authorization_endpoint":"https://auth.example.com/oauth2/authorize"`,
		`"challenge_method":"S256"`,
		`"supported_protocols":["oauth2.0","oauth2.1","cas"]`,
		`"validate_url":"https://auth.example.com/cas/p3/serviceValidate"`,
		`"proxy_url":"https://auth.example.com/cas/proxy"`,
	} {
		if !strings.Contains(body, expected) {
			t.Errorf("response does not contain %s: %s", expected, body)
		}
	}

	integration := httptest.NewRequest(http.MethodGet, "/api/v1/admin/clients/finance/integration", nil)
	integration.Header.Set("Authorization", "Bearer test-admin-token")
	integrationResponse := httptest.NewRecorder()
	handler.ServeHTTP(integrationResponse, integration)
	if integrationResponse.Code != http.StatusOK {
		t.Fatalf("unexpected integration response: %d %s", integrationResponse.Code, integrationResponse.Body.String())
	}
	if strings.Contains(integrationResponse.Body.String(), `"client_secret"`) {
		t.Fatal("client secret was exposed after initial creation")
	}
}

func TestAdminClientsPage(t *testing.T) {
	handler := New(config.Config{Issuer: "https://auth.example.com"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	request := httptest.NewRequest(http.MethodGet, "/admin/clients", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK ||
		!strings.Contains(response.Body.String(), "保存并生成接入参数") ||
		!strings.Contains(response.Body.String(), "/static/admin-clients.js") {
		t.Fatalf("unexpected response: %d %s", response.Code, response.Body.String())
	}
	if !strings.Contains(response.Header().Get("Content-Security-Policy"), "script-src 'self'") {
		t.Fatal("admin page scripts are not restricted by CSP")
	}
}
