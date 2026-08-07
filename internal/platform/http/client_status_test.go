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
	"time"

	"certus/internal/audit"
	"certus/internal/cas"
	"certus/internal/client"
	"certus/internal/config"
	"certus/internal/identity"
	"certus/internal/oauth"
	"certus/internal/oidc"
	"certus/internal/ratelimit"
	"certus/internal/session"
)

func newClientStatusHandler(
	t *testing.T,
	registered client.Client,
	user identity.User,
	consented bool,
	configure func(*config.Config),
) (http.Handler, string, *oauth.MemoryRepository, *audit.MemoryRepository) {
	t.Helper()
	ctx := context.Background()
	users := identity.NewMemoryUserRepository(user)
	oauthRepository := oauth.NewMemoryRepository()
	if consented {
		if _, err := oauthRepository.GrantConsent(
			ctx, user.ID, registered.ID, []string{"openid", "profile", "email"}, time.Now().UTC(),
		); err != nil {
			t.Fatal(err)
		}
	}
	cfg := config.Config{Issuer: "https://auth.example.com"}
	if configure != nil {
		configure(&cfg)
	}
	audits := audit.NewMemoryRepository()
	handler, err := NewWithDependencies(ctx, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), Dependencies{
		Clients:   client.NewMemoryRepository(registered),
		Users:     users,
		Passwords: users,
		Sessions:  session.NewMemoryRepository(),
		OAuth:     oauthRepository,
		CAS:       cas.NewMemoryRepository(),
		Audit:     audits,
		Keys:      &oidc.MemoryKeyRepository{},
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler, registered.ID, oauthRepository, audits
}

func statusRequest(handler http.Handler, clientID, secret, userID string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(
		http.MethodGet,
		"/api/v1/clients/me/users/"+userID+"/status",
		nil,
	)
	if clientID != "" {
		request.Header.Set(
			"Authorization",
			"Basic "+base64.StdEncoding.EncodeToString([]byte(clientID+":"+secret)),
		)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func TestClientQueriesUserStatusWithConsent(t *testing.T) {
	registered, secret, err := client.New(client.CreateClient{
		ID:              "finance",
		Name:            "Finance",
		ApplicationType: client.ApplicationConfidential,
		Protocols:       []client.Protocol{client.ProtocolOAuth21},
		GrantTypes:      []client.GrantType{client.GrantAuthorizationCode, client.GrantRefreshToken},
		LoginMethods:    []client.LoginMethod{client.LoginPassword},
		RedirectURIs:    []string{"https://finance.example.com/callback"},
		AllowedScopes:   []string{"openid", "profile", "email"},
	})
	if err != nil {
		t.Fatal(err)
	}
	user, err := identity.NewUser(identity.CreateUser{
		Username: "alice", DisplayName: "Alice", Status: identity.UserActive,
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	handler, _, _, audits := newClientStatusHandler(t, registered, user, true, nil)

	response := statusRequest(handler, registered.ID, secret, user.ID)
	if response.Code != http.StatusOK {
		t.Fatalf("status query: %d %s", response.Code, response.Body.String())
	}
	var body struct {
		Sub           string              `json:"sub"`
		Status        identity.UserStatus `json:"status"`
		EmailVerified bool                `json:"email_verified"`
		UpdatedAt     time.Time           `json:"updated_at"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body.Sub != user.ID ||
		body.Status != identity.UserActive ||
		body.EmailVerified ||
		body.UpdatedAt.IsZero() {
		t.Fatalf("unexpected status response: %#v", body)
	}
	if strings.Contains(response.Body.String(), `"username"`) ||
		strings.Contains(response.Body.String(), `"email"`) {
		t.Fatalf("status response leaks profile fields: %s", response.Body.String())
	}
	found := false
	if events, err := audits.List(context.Background(), audit.Filter{Limit: 100}); err != nil {
		t.Fatal(err)
	} else {
		for _, event := range events.Items {
			if event.EventType == "user.status_queried" && event.Outcome == audit.OutcomeSuccess {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("missing user.status_queried audit event")
	}
}

func TestClientStatusReflectsDisabledUser(t *testing.T) {
	registered, secret, err := client.New(client.CreateClient{
		ID:              "finance",
		Name:            "Finance",
		ApplicationType: client.ApplicationConfidential,
		Protocols:       []client.Protocol{client.ProtocolOAuth21},
		GrantTypes:      []client.GrantType{client.GrantAuthorizationCode, client.GrantRefreshToken},
		LoginMethods:    []client.LoginMethod{client.LoginPassword},
		RedirectURIs:    []string{"https://finance.example.com/callback"},
	})
	if err != nil {
		t.Fatal(err)
	}
	user, err := identity.NewUser(identity.CreateUser{
		Username: "alice", DisplayName: "Alice", Status: identity.UserDisabled,
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	handler, _, _, _ := newClientStatusHandler(t, registered, user, true, nil)

	response := statusRequest(handler, registered.ID, secret, user.ID)
	if response.Code != http.StatusOK ||
		!strings.Contains(response.Body.String(), `"status":"disabled"`) {
		t.Fatalf("disabled user status: %d %s", response.Code, response.Body.String())
	}
}

func TestClientStatusRequiresConsent(t *testing.T) {
	registered, secret, err := client.New(client.CreateClient{
		ID:              "finance",
		Name:            "Finance",
		ApplicationType: client.ApplicationConfidential,
		Protocols:       []client.Protocol{client.ProtocolOAuth21},
		GrantTypes:      []client.GrantType{client.GrantAuthorizationCode, client.GrantRefreshToken},
		LoginMethods:    []client.LoginMethod{client.LoginPassword},
		RedirectURIs:    []string{"https://finance.example.com/callback"},
	})
	if err != nil {
		t.Fatal(err)
	}
	user, err := identity.NewUser(identity.CreateUser{
		Username: "alice", DisplayName: "Alice", Status: identity.UserActive,
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	handler, _, _, audits := newClientStatusHandler(t, registered, user, false, nil)

	response := statusRequest(handler, registered.ID, secret, user.ID)
	if response.Code != http.StatusNotFound {
		t.Fatalf("query without consent: %d %s", response.Code, response.Body.String())
	}
	if response.Body.Len() != 0 {
		t.Fatalf("not-found response must not leak details: %s", response.Body.String())
	}
	found := false
	if events, err := audits.List(context.Background(), audit.Filter{Limit: 100}); err != nil {
		t.Fatal(err)
	} else {
		for _, event := range events.Items {
			if event.EventType == "user.status_queried" && event.Outcome == audit.OutcomeFailure {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("missing failed user.status_queried audit event")
	}
}

func TestClientStatusRevokedConsentIsNotFound(t *testing.T) {
	registered, secret, err := client.New(client.CreateClient{
		ID:              "finance",
		Name:            "Finance",
		ApplicationType: client.ApplicationConfidential,
		Protocols:       []client.Protocol{client.ProtocolOAuth21},
		GrantTypes:      []client.GrantType{client.GrantAuthorizationCode, client.GrantRefreshToken},
		LoginMethods:    []client.LoginMethod{client.LoginPassword},
		RedirectURIs:    []string{"https://finance.example.com/callback"},
	})
	if err != nil {
		t.Fatal(err)
	}
	user, err := identity.NewUser(identity.CreateUser{
		Username: "alice", DisplayName: "Alice", Status: identity.UserActive,
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	handler, clientID, oauthRepository, _ := newClientStatusHandler(t, registered, user, true, nil)
	response := statusRequest(handler, clientID, secret, user.ID)
	if response.Code != http.StatusOK {
		t.Fatalf("expected consent first: %d", response.Code)
	}
	if err := oauthRepository.DeleteConsent(
		context.Background(), user.ID, registered.ID, time.Now().UTC(),
	); err != nil {
		t.Fatal(err)
	}
	response = statusRequest(handler, clientID, secret, user.ID)
	if response.Code != http.StatusNotFound {
		t.Fatalf("revoked consent query: %d %s", response.Code, response.Body.String())
	}
}

func TestClientStatusUnknownUserIsNotFound(t *testing.T) {
	registered, secret, err := client.New(client.CreateClient{
		ID:              "finance",
		Name:            "Finance",
		ApplicationType: client.ApplicationConfidential,
		Protocols:       []client.Protocol{client.ProtocolOAuth21},
		GrantTypes:      []client.GrantType{client.GrantAuthorizationCode, client.GrantRefreshToken},
		LoginMethods:    []client.LoginMethod{client.LoginPassword},
		RedirectURIs:    []string{"https://finance.example.com/callback"},
	})
	if err != nil {
		t.Fatal(err)
	}
	user, err := identity.NewUser(identity.CreateUser{
		Username: "alice", DisplayName: "Alice", Status: identity.UserActive,
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	handler, _, _, _ := newClientStatusHandler(t, registered, user, true, nil)

	response := statusRequest(handler, registered.ID, secret, "00000000-0000-4000-8000-000000000000")
	if response.Code != http.StatusNotFound || response.Body.Len() != 0 {
		t.Fatalf("unknown user: %d %s", response.Code, response.Body.String())
	}
	response = statusRequest(handler, registered.ID, secret, "not-a-uuid")
	if response.Code != http.StatusNotFound {
		t.Fatalf("malformed user id: %d %s", response.Code, response.Body.String())
	}
}

func TestClientStatusRequiresConfidentialClientAuthentication(t *testing.T) {
	registered, _, err := client.New(client.CreateClient{
		ID:              "finance",
		Name:            "Finance",
		ApplicationType: client.ApplicationConfidential,
		Protocols:       []client.Protocol{client.ProtocolOAuth21},
		GrantTypes:      []client.GrantType{client.GrantAuthorizationCode, client.GrantRefreshToken},
		LoginMethods:    []client.LoginMethod{client.LoginPassword},
		RedirectURIs:    []string{"https://finance.example.com/callback"},
	})
	if err != nil {
		t.Fatal(err)
	}
	user, err := identity.NewUser(identity.CreateUser{
		Username: "alice", DisplayName: "Alice", Status: identity.UserActive,
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	handler, _, _, _ := newClientStatusHandler(t, registered, user, true, nil)

	response := statusRequest(handler, "", "", user.ID)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated query: %d %s", response.Code, response.Body.String())
	}
	response = statusRequest(handler, registered.ID, "wrong-secret", user.ID)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("wrong secret: %d %s", response.Code, response.Body.String())
	}

	public, _, err := client.New(client.CreateClient{
		ID:              "web",
		Name:            "Web",
		ApplicationType: client.ApplicationPublic,
		Protocols:       []client.Protocol{client.ProtocolOAuth21},
		GrantTypes:      []client.GrantType{client.GrantAuthorizationCode, client.GrantRefreshToken},
		LoginMethods:    []client.LoginMethod{client.LoginPassword},
		RedirectURIs:    []string{"https://web.example.com/callback"},
	})
	if err != nil {
		t.Fatal(err)
	}
	handler, _, _, _ = newClientStatusHandler(t, public, user, true, nil)
	response = statusRequest(handler, public.ID, "", user.ID)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("public client query: %d %s", response.Code, response.Body.String())
	}
}

func TestClientStatusRateLimitedPerClient(t *testing.T) {
	registered, secret, err := client.New(client.CreateClient{
		ID:              "finance",
		Name:            "Finance",
		ApplicationType: client.ApplicationConfidential,
		Protocols:       []client.Protocol{client.ProtocolOAuth21},
		GrantTypes:      []client.GrantType{client.GrantAuthorizationCode, client.GrantRefreshToken},
		LoginMethods:    []client.LoginMethod{client.LoginPassword},
		RedirectURIs:    []string{"https://finance.example.com/callback"},
	})
	if err != nil {
		t.Fatal(err)
	}
	user, err := identity.NewUser(identity.CreateUser{
		Username: "alice", DisplayName: "Alice", Status: identity.UserActive,
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	handler, _, _, _ := newClientStatusHandler(t, registered, user, true, func(cfg *config.Config) {
		cfg.RateLimits.ClientStatus = ratelimit.Policy{Limit: 1, Window: time.Minute}
	})

	if response := statusRequest(handler, registered.ID, secret, user.ID); response.Code != http.StatusOK {
		t.Fatalf("first query: %d %s", response.Code, response.Body.String())
	}
	response := statusRequest(handler, registered.ID, secret, user.ID)
	if response.Code != http.StatusTooManyRequests {
		t.Fatalf("rate-limited query: %d %s", response.Code, response.Body.String())
	}
}
