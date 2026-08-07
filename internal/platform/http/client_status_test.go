package httpserver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
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
	users := identity.NewMemoryUserRepository(user)
	oauthRepository := oauth.NewMemoryRepository()
	if consented {
		if _, err := oauthRepository.GrantConsent(
			context.Background(), user.ID, registered.ID, []string{"openid", "profile", "email"}, time.Now().UTC(),
		); err != nil {
			t.Fatal(err)
		}
	}
	handler, clientID, audits := newClientStatusHandlerFull(
		t, registered, configure, users, oauthRepository,
	)
	return handler, clientID, oauthRepository, audits
}

func newClientStatusHandlerFull(
	t *testing.T,
	registered client.Client,
	configure func(*config.Config),
	users identity.UserRepository,
	oauthRepository oauth.Repository,
) (http.Handler, string, *audit.MemoryRepository) {
	t.Helper()
	cfg := config.Config{Issuer: "https://auth.example.com"}
	if configure != nil {
		configure(&cfg)
	}
	passwords, ok := users.(identity.PasswordRepository)
	if !ok {
		t.Fatal("user repository does not implement password repository")
	}
	audits := audit.NewMemoryRepository()
	handler, err := NewWithDependencies(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), Dependencies{
		Clients:   client.NewMemoryRepository(registered),
		Users:     users,
		Passwords: passwords,
		Sessions:  session.NewMemoryRepository(),
		OAuth:     oauthRepository,
		CAS:       cas.NewMemoryRepository(),
		Audit:     audits,
		Keys:      &oidc.MemoryKeyRepository{},
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler, registered.ID, audits
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

type failingUserRepository struct {
	*identity.MemoryUserRepository
	err error
}

func (r *failingUserRepository) Find(_ context.Context, _ string) (identity.User, error) {
	return identity.User{}, r.err
}

type failingOAuthRepository struct {
	*oauth.MemoryRepository
	err error
}

func (r *failingOAuthRepository) FindConsent(_ context.Context, _, _ string) (oauth.Consent, error) {
	return oauth.Consent{}, r.err
}

func confidentialTestClient(t *testing.T) (client.Client, string) {
	t.Helper()
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
	return registered, secret
}

func statusAuditReasons(t *testing.T, audits *audit.MemoryRepository, clientID string) map[string]bool {
	t.Helper()
	reasons := map[string]bool{}
	events, err := audits.List(context.Background(), audit.Filter{ClientID: clientID, Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events.Items {
		if event.EventType != "user.status_queried" {
			continue
		}
		if reason, ok := event.Details["reason"].(string); ok {
			reasons[reason] = true
		}
	}
	return reasons
}

func TestClientStatusAuditsRateLimit(t *testing.T) {
	registered, secret := confidentialTestClient(t)
	user, err := identity.NewUser(identity.CreateUser{
		Username: "alice", DisplayName: "Alice", Status: identity.UserActive,
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	handler, _, _, audits := newClientStatusHandler(t, registered, user, true, func(cfg *config.Config) {
		cfg.RateLimits.ClientStatus = ratelimit.Policy{Limit: 1, Window: time.Minute}
	})
	if response := statusRequest(handler, registered.ID, secret, user.ID); response.Code != http.StatusOK {
		t.Fatalf("first query: %d %s", response.Code, response.Body.String())
	}
	response := statusRequest(handler, registered.ID, secret, user.ID)
	if response.Code != http.StatusTooManyRequests {
		t.Fatalf("rate-limited query: %d %s", response.Code, response.Body.String())
	}
	if !statusAuditReasons(t, audits, registered.ID)["rate_limited"] {
		t.Fatal("missing rate_limited audit event")
	}
}

func TestClientStatusAuditsStorageFailure(t *testing.T) {
	registered, secret := confidentialTestClient(t)
	user, err := identity.NewUser(identity.CreateUser{
		Username: "alice", DisplayName: "Alice", Status: identity.UserActive,
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	users := &failingUserRepository{MemoryUserRepository: identity.NewMemoryUserRepository(user), err: errors.New("database unavailable")}
	oauthRepository := oauth.NewMemoryRepository()
	if _, err := oauthRepository.GrantConsent(
		context.Background(), user.ID, registered.ID, []string{"openid"}, time.Now().UTC(),
	); err != nil {
		t.Fatal(err)
	}
	handler, _, audits := newClientStatusHandlerFull(t, registered, nil, users, oauthRepository)
	response := statusRequest(handler, registered.ID, secret, user.ID)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("storage failure: %d %s", response.Code, response.Body.String())
	}
	if !statusAuditReasons(t, audits, registered.ID)["storage_error"] {
		t.Fatal("missing storage_error audit event")
	}
}

func TestClientStatusAuditsConsentStorageFailure(t *testing.T) {
	registered, secret := confidentialTestClient(t)
	user, err := identity.NewUser(identity.CreateUser{
		Username: "alice", DisplayName: "Alice", Status: identity.UserActive,
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	oauthRepository := &failingOAuthRepository{MemoryRepository: oauth.NewMemoryRepository(), err: errors.New("database unavailable")}
	handler, _, audits := newClientStatusHandlerFull(t, registered, nil, identity.NewMemoryUserRepository(user), oauthRepository)
	response := statusRequest(handler, registered.ID, secret, user.ID)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("consent storage failure: %d %s", response.Code, response.Body.String())
	}
	if !statusAuditReasons(t, audits, registered.ID)["consent_unavailable"] {
		t.Fatal("missing consent_unavailable audit event")
	}
}

func TestClientStatusAuditsAuthenticationFailure(t *testing.T) {
	registered, _ := confidentialTestClient(t)
	user, err := identity.NewUser(identity.CreateUser{
		Username: "alice", DisplayName: "Alice", Status: identity.UserActive,
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	handler, _, _, audits := newClientStatusHandler(t, registered, user, true, nil)

	response := statusRequest(handler, "", "", user.ID)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("missing credentials: %d %s", response.Code, response.Body.String())
	}
	response = statusRequest(handler, registered.ID, "wrong-secret", user.ID)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("wrong secret: %d %s", response.Code, response.Body.String())
	}
	events, err := audits.List(context.Background(), audit.Filter{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, event := range events.Items {
		if event.EventType == "client.authentication_failed" && event.Outcome == audit.OutcomeFailure {
			found++
		}
	}
	if found != 2 {
		t.Fatalf("expected two authentication failure events, got %d: %#v", found, events.Items)
	}
	for _, event := range events.Items {
		if event.EventType == "client.authentication_failed" && event.ClientID != nil {
			t.Fatalf("unverified client attributed as authenticated subject: %#v", event)
		}
	}
	for _, event := range events.Items {
		if event.EventType == "user.status_queried" {
			t.Fatalf("failed authentication was attributed to user.status_queried: %#v", event)
		}
	}
}
