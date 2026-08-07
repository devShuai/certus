package httpserver

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"

	"certus/internal/cas"
	"certus/internal/client"
	"certus/internal/config"
	"certus/internal/identity"
	"certus/internal/oauth"
	"certus/internal/oidc"
	"certus/internal/security"
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
	postAuthentication := url.Values{
		"client_id":     {registered.ID},
		"client_secret": {secret},
		"token":         {accessToken},
	}
	wrongMethod := oauthPostFormRequest(t, handler, "/oauth2/introspect", postAuthentication)
	if wrongMethod.Code != http.StatusUnauthorized {
		t.Fatalf("client_secret_basic client used client_secret_post: %d %s", wrongMethod.Code, wrongMethod.Body.String())
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
		`"email_verified"`,
		`"prompt_values_supported":["none","login","consent"]`,
		`"token_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post","none"]`,
		`"introspection_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post"]`,
		`"revocation_endpoint_auth_methods_supported":["client_secret_basic","client_secret_post","none"]`,
	} {
		if !strings.Contains(discovery.Body.String(), endpoint) {
			t.Fatalf("discovery missing %s: %s", endpoint, discovery.Body.String())
		}
	}
}

func TestCrossClientAccessTokenIntrospection(t *testing.T) {
	ctx := context.Background()
	resource, resourceSecret, err := client.New(client.CreateClient{
		ID:              "conspectus",
		Name:            "Conspectus",
		ApplicationType: client.ApplicationConfidential,
		Protocols:       []client.Protocol{client.ProtocolOAuth21},
		GrantTypes:      []client.GrantType{client.GrantClientCredentials},
		AllowedScopes:   []string{"api.write"},
	})
	if err != nil {
		t.Fatal(err)
	}
	otherResource, otherSecret, err := client.New(client.CreateClient{
		ID:              "other-resource",
		Name:            "Other Resource",
		ApplicationType: client.ApplicationConfidential,
		Protocols:       []client.Protocol{client.ProtocolOAuth21},
		GrantTypes:      []client.GrantType{client.GrantClientCredentials},
		AllowedScopes:   []string{"api.write"},
	})
	if err != nil {
		t.Fatal(err)
	}
	issuer, _, err := client.New(client.CreateClient{
		ID:               "conspectus-cli",
		Name:             "Conspectus CLI",
		ApplicationType:  client.ApplicationPublic,
		Protocols:        []client.Protocol{client.ProtocolOAuth21},
		GrantTypes:       []client.GrantType{client.GrantDeviceCode},
		LoginMethods:     []client.LoginMethod{client.LoginPassword},
		AllowedScopes:    []string{"openid", "api.write"},
		IntrospectableBy: []string{resource.ID},
	})
	if err != nil {
		t.Fatal(err)
	}
	user, err := identity.NewUser(identity.CreateUser{
		Username: "collector", DisplayName: "Collector", Status: identity.UserActive,
	}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	users := identity.NewMemoryUserRepository(user)
	oauthRepository := oauth.NewMemoryRepository()
	if _, err := oauthRepository.GrantConsent(
		ctx, user.ID, issuer.ID, []string{"openid", "api.write"}, time.Now().UTC(),
	); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	accessToken := "collector-access-token"
	if err := oauthRepository.SaveAccessToken(ctx, oauth.AccessToken{
		Hash:      security.HashToken(accessToken),
		ClientID:  issuer.ID,
		UserID:    user.ID,
		Scope:     []string{"openid", "api.write"},
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	refreshToken := "collector-refresh-token"
	if err := oauthRepository.SaveRefreshToken(ctx, oauth.RefreshToken{
		Hash:      security.HashToken(refreshToken),
		FamilyID:  "collector-family",
		ClientID:  issuer.ID,
		UserID:    user.ID,
		Scope:     []string{"openid", "api.write"},
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	handler, err := NewWithDependencies(
		ctx,
		config.Config{Issuer: "https://auth.example.com"},
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		Dependencies{
			Clients:   client.NewMemoryRepository(resource, otherResource, issuer),
			Users:     users,
			Passwords: users,
			Sessions:  session.NewMemoryRepository(),
			OAuth:     oauthRepository,
			CAS:       cas.NewMemoryRepository(),
			Keys:      &oidc.MemoryKeyRepository{},
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	introspectionForm := url.Values{
		"token":           {accessToken},
		"token_type_hint": {"access_token"},
	}
	allowed := oauthFormRequest(
		t, handler, "/oauth2/introspect", introspectionForm, resource.ID, resourceSecret,
	)
	for _, expected := range []string{
		`"active":true`,
		`"client_id":"conspectus-cli"`,
		`"scope":"openid api.write"`,
		`"sub":"` + user.ID + `"`,
	} {
		if allowed.Code != http.StatusOK || !strings.Contains(allowed.Body.String(), expected) {
			t.Fatalf("allowed cross-client introspection missing %s: %d %s", expected, allowed.Code, allowed.Body.String())
		}
	}

	denied := oauthFormRequest(
		t, handler, "/oauth2/introspect", introspectionForm, otherResource.ID, otherSecret,
	)
	if denied.Code != http.StatusOK || strings.TrimSpace(denied.Body.String()) != `{"active":false}` {
		t.Fatalf("unlisted client learned token state: %d %s", denied.Code, denied.Body.String())
	}

	refreshForm := url.Values{
		"token":           {refreshToken},
		"token_type_hint": {"refresh_token"},
	}
	refreshDenied := oauthFormRequest(
		t, handler, "/oauth2/introspect", refreshForm, resource.ID, resourceSecret,
	)
	if refreshDenied.Code != http.StatusOK || strings.TrimSpace(refreshDenied.Body.String()) != `{"active":false}` {
		t.Fatalf("cross-client refresh token introspection was allowed: %d %s", refreshDenied.Code, refreshDenied.Body.String())
	}

	introspectionForm.Set("token_type_hint", "refresh_token")
	fallback := oauthFormRequest(
		t, handler, "/oauth2/introspect", introspectionForm, resource.ID, resourceSecret,
	)
	if fallback.Code != http.StatusOK || !strings.Contains(fallback.Body.String(), `"active":true`) {
		t.Fatalf("access token lookup did not recover from an incorrect hint: %d %s", fallback.Code, fallback.Body.String())
	}
}

func TestEmailClaimsReflectStoredVerificationState(t *testing.T) {
	email := "alice@example.com"
	for _, test := range []struct {
		name     string
		user     identity.User
		expected map[string]any
	}{
		{
			name:     "unverified",
			user:     identity.User{Email: &email},
			expected: map[string]any{"email": email, "email_verified": false},
		},
		{
			name:     "verified",
			user:     identity.User{Email: &email, EmailVerified: true},
			expected: map[string]any{"email": email, "email_verified": true},
		},
		{
			name:     "missing email",
			user:     identity.User{EmailVerified: true},
			expected: map[string]any{},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			claims := map[string]any{}
			addEmailClaims(claims, test.user)
			if !reflect.DeepEqual(claims, test.expected) {
				t.Fatalf("unexpected email claims: %#v", claims)
			}
		})
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
