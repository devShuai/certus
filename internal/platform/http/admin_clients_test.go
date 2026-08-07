package httpserver

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"certus/internal/client"
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
		"favicon_url":"https://finance.example.com/favicon.svg",
		"launch_uri":"https://finance.example.com/?login=oidc",
		"application_type":"confidential",
		"token_endpoint_auth_method":"client_secret_post",
		"protocols":["oauth2.0","oauth2.1","cas"],
		"grant_types":["authorization_code","refresh_token","client_credentials"],
		"redirect_uris":["https://finance.example.com/oidc/callback"],
		"post_logout_redirect_uris":["https://finance.example.com/logout/callback"],
		"backchannel_logout_uri":"https://finance.example.com/oidc/backchannel-logout",
		"backchannel_logout_session_required":true,
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
		`"favicon_url":"https://finance.example.com/favicon.svg"`,
		`"launch_uri":"https://finance.example.com/?login=oidc"`,
		`"client_secret":"`,
		`"client_authentication_method":"client_secret_post"`,
		`"issuer":"https://auth.example.com"`,
		`"authorization_endpoint":"https://auth.example.com/oauth2/authorize"`,
		`"end_session_endpoint":"https://auth.example.com/oauth2/logout"`,
		`"post_logout_redirect_uris":["https://finance.example.com/logout/callback"]`,
		`"backchannel_logout_uri":"https://finance.example.com/oidc/backchannel-logout"`,
		`"backchannel_logout_session_required":true`,
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

func TestAdminClientIntrospectionPermissions(t *testing.T) {
	handler := New(config.Config{
		Issuer:     "https://auth.example.com",
		AdminToken: "test-admin-token",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	resource := adminJSONRequest(t, handler, http.MethodPost, "/api/v1/admin/clients", `{
		"id":"resource-api",
		"name":"Resource API",
		"application_type":"confidential",
		"protocols":["oauth2.1"],
		"grant_types":["client_credentials"],
		"allowed_scopes":["api.read"]
	}`)
	if resource.Code != http.StatusCreated {
		t.Fatalf("create introspection resource client: %d %s", resource.Code, resource.Body.String())
	}
	disabled := adminJSONRequest(t, handler, http.MethodPost, "/api/v1/admin/clients", `{
		"id":"disabled-api",
		"name":"Disabled API",
		"application_type":"confidential",
		"protocols":["oauth2.1"],
		"grant_types":["client_credentials"],
		"allowed_scopes":["api.read"],
		"enabled":false
	}`)
	if disabled.Code != http.StatusCreated {
		t.Fatalf("create disabled introspection client: %d %s", disabled.Code, disabled.Body.String())
	}

	issuer := adminJSONRequest(t, handler, http.MethodPost, "/api/v1/admin/clients", `{
		"id":"collector-cli",
		"name":"Collector CLI",
		"application_type":"public",
		"protocols":["oauth2.1"],
		"grant_types":["urn:ietf:params:oauth:grant-type:device_code"],
		"login_methods":["password"],
		"allowed_scopes":["openid","api.write"],
		"introspectable_by":["resource-api"]
	}`)
	if issuer.Code != http.StatusCreated ||
		!strings.Contains(issuer.Body.String(), `"introspectable_by":["resource-api"]`) {
		t.Fatalf("create client introspection permission: %d %s", issuer.Code, issuer.Body.String())
	}
	publicIssuer := httptest.NewRecorder()
	handler.ServeHTTP(
		publicIssuer,
		httptest.NewRequest(http.MethodGet, "/api/v1/clients/collector-cli", nil),
	)
	if publicIssuer.Code != http.StatusOK || strings.Contains(publicIssuer.Body.String(), "introspectable_by") {
		t.Fatalf("public client metadata exposed introspection permissions: %d %s", publicIssuer.Code, publicIssuer.Body.String())
	}

	for _, test := range []struct {
		name   string
		target string
	}{
		{name: "missing", target: "missing-api"},
		{name: "public", target: "specus"},
		{name: "disabled", target: "disabled-api"},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := adminJSONRequest(t, handler, http.MethodPost, "/api/v1/admin/clients", `{
				"id":"invalid-`+test.name+`",
				"name":"Invalid Introspection Client",
				"application_type":"public",
				"protocols":["oauth2.1"],
				"grant_types":["urn:ietf:params:oauth:grant-type:device_code"],
				"login_methods":["password"],
				"introspectable_by":["`+test.target+`"]
			}`)
			if response.Code != http.StatusBadRequest ||
				!strings.Contains(response.Body.String(), `"invalid_introspection_client"`) {
				t.Fatalf("invalid introspection client was accepted: %d %s", response.Code, response.Body.String())
			}
		})
	}
}

func TestAdminClientsPage(t *testing.T) {
	handler := New(config.Config{Issuer: "https://auth.example.com"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	for _, path := range []string{"/admin", "/admin/clients"} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		response := httptest.NewRecorder()

		handler.ServeHTTP(response, request)

		if response.Code != http.StatusSeeOther ||
			!strings.HasPrefix(response.Header().Get("Location"), "/login?continue=") {
			t.Fatalf("unexpected response for %s: %d %s", path, response.Code, response.Body.String())
		}
		if !strings.Contains(response.Header().Get("Content-Security-Policy"), "script-src 'self'") {
			t.Fatal("admin page scripts are not restricted by CSP")
		}
	}
}

func TestClientLifecycleAPIs(t *testing.T) {
	handler := New(config.Config{
		Issuer:     "https://auth.example.com",
		AdminToken: "test-admin-token",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	createBody := `{
		"id":"resource-api",
		"name":"Resource API",
		"application_type":"confidential",
		"token_endpoint_auth_method":"client_secret_post",
		"protocols":["oauth2.1"],
		"grant_types":["client_credentials","urn:ietf:params:oauth:grant-type:device_code"],
		"login_methods":["password"],
		"allowed_scopes":["openid","api.read"]
	}`
	created := adminJSONRequest(t, handler, http.MethodPost, "/api/v1/admin/clients", createBody)
	if created.Code != http.StatusCreated {
		t.Fatalf("create client: %d %s", created.Code, created.Body.String())
	}
	var creation clientRegistrationResponse
	if err := json.Unmarshal(created.Body.Bytes(), &creation); err != nil {
		t.Fatal(err)
	}
	originalSecret := creation.Integration.ClientSecret

	rotated := adminJSONRequest(t, handler, http.MethodPost, "/api/v1/admin/clients/resource-api/secret", "")
	if rotated.Code != http.StatusOK {
		t.Fatalf("rotate secret: %d %s", rotated.Code, rotated.Body.String())
	}
	var rotation clientRegistrationResponse
	if err := json.Unmarshal(rotated.Body.Bytes(), &rotation); err != nil {
		t.Fatal(err)
	}
	newSecret := rotation.Integration.ClientSecret
	if newSecret == "" || newSecret == originalSecret {
		t.Fatal("secret rotation did not return a new one-time secret")
	}
	tokenForm := url.Values{
		"grant_type":    {string(client.GrantClientCredentials)},
		"scope":         {"api.read"},
		"client_id":     {"resource-api"},
		"client_secret": {originalSecret},
	}
	if oldToken := oauthPostFormRequest(t, handler, "/oauth2/token", tokenForm); oldToken.Code != http.StatusUnauthorized {
		t.Fatalf("old secret remained valid: %d %s", oldToken.Code, oldToken.Body.String())
	}
	tokenForm.Set("client_secret", newSecret)
	newToken := oauthPostFormRequest(t, handler, "/oauth2/token", tokenForm)
	if newToken.Code != http.StatusOK {
		t.Fatalf("new secret was not valid: %d %s", newToken.Code, newToken.Body.String())
	}
	var issued map[string]any
	if err := json.Unmarshal(newToken.Body.Bytes(), &issued); err != nil {
		t.Fatal(err)
	}
	accessToken, _ := issued["access_token"].(string)
	metadataForm := url.Values{
		"client_id":     {"resource-api"},
		"client_secret": {newSecret},
		"token":         {accessToken},
	}
	introspection := oauthPostFormRequest(t, handler, "/oauth2/introspect", metadataForm)
	if introspection.Code != http.StatusOK || !strings.Contains(introspection.Body.String(), `"active":true`) {
		t.Fatalf("client_secret_post introspection failed: %d %s", introspection.Code, introspection.Body.String())
	}
	revocation := oauthPostFormRequest(t, handler, "/oauth2/revoke", metadataForm)
	if revocation.Code != http.StatusOK {
		t.Fatalf("client_secret_post revocation failed: %d %s", revocation.Code, revocation.Body.String())
	}
	introspection = oauthPostFormRequest(t, handler, "/oauth2/introspect", metadataForm)
	if introspection.Code != http.StatusOK || !strings.Contains(introspection.Body.String(), `"active":false`) {
		t.Fatalf("revoked post-authenticated token remained active: %d %s", introspection.Code, introspection.Body.String())
	}
	dualAuthentication := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(tokenForm.Encode()))
	dualAuthentication.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	dualAuthentication.SetBasicAuth("resource-api", newSecret)
	dualResponse := httptest.NewRecorder()
	handler.ServeHTTP(dualResponse, dualAuthentication)
	if dualResponse.Code != http.StatusBadRequest ||
		!strings.Contains(dualResponse.Body.String(), `"invalid_request"`) {
		t.Fatalf("multiple client authentication methods were accepted: %d %s", dualResponse.Code, dualResponse.Body.String())
	}
	deviceForm := url.Values{
		"client_id":     {"resource-api"},
		"client_secret": {newSecret},
		"scope":         {"openid"},
	}
	deviceAuthorization := oauthPostFormRequest(t, handler, "/oauth2/device_authorization", deviceForm)
	if deviceAuthorization.Code != http.StatusOK ||
		!strings.Contains(deviceAuthorization.Body.String(), `"device_code"`) {
		t.Fatalf("client_secret_post device authorization failed: %d %s", deviceAuthorization.Code, deviceAuthorization.Body.String())
	}

	disabled := adminJSONRequest(t, handler, http.MethodPut, "/api/v1/admin/clients/resource-api", `{
		"name":"Resource API v2",
		"description":"updated",
		"token_endpoint_auth_method":"client_secret_post",
		"protocols":["oauth2.1"],
		"grant_types":["client_credentials","urn:ietf:params:oauth:grant-type:device_code"],
		"login_methods":["password"],
		"allowed_scopes":["openid","api.read"],
		"enabled":false
	}`)
	if disabled.Code != http.StatusOK ||
		!strings.Contains(disabled.Body.String(), `"name":"Resource API v2"`) ||
		!strings.Contains(disabled.Body.String(), `"enabled":false`) {
		t.Fatalf("disable client: %d %s", disabled.Code, disabled.Body.String())
	}
	public := httptest.NewRecorder()
	handler.ServeHTTP(public, httptest.NewRequest(http.MethodGet, "/api/v1/clients/resource-api", nil))
	if public.Code != http.StatusNotFound {
		t.Fatalf("disabled client remained publicly visible: %d %s", public.Code, public.Body.String())
	}

	archived := adminJSONRequest(t, handler, http.MethodDelete, "/api/v1/admin/clients/resource-api", "")
	if archived.Code != http.StatusNoContent {
		t.Fatalf("archive client: %d %s", archived.Code, archived.Body.String())
	}
	updateArchived := adminJSONRequest(t, handler, http.MethodPut, "/api/v1/admin/clients/resource-api", `{
		"name":"Archived",
		"token_endpoint_auth_method":"client_secret_post",
		"protocols":["oauth2.1"],
		"grant_types":["client_credentials"],
		"allowed_scopes":["openid","api.read"]
	}`)
	if updateArchived.Code != http.StatusConflict || !strings.Contains(updateArchived.Body.String(), `"client_archived"`) {
		t.Fatalf("archived client was mutable: %d %s", updateArchived.Code, updateArchived.Body.String())
	}
}

func oauthPostFormRequest(
	t *testing.T,
	handler http.Handler,
	target string,
	form url.Values,
) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func adminJSONRequest(t *testing.T, handler http.Handler, method, target, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, target, strings.NewReader(body))
	request.Header.Set("Authorization", "Bearer test-admin-token")
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}
