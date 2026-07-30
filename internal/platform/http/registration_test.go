package httpserver

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"certus/internal/client"
	"certus/internal/config"
	"certus/internal/identity"
	"certus/internal/ratelimit"
)

func TestRegistrationIsDisabledByDefault(t *testing.T) {
	users := identity.NewMemoryUserRepository()
	handler := NewWithRepositories(
		config.Config{Issuer: "https://auth.example.com"},
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		client.NewMemoryRepository(),
		users,
	)
	response := newTestBrowser(handler).request(t, http.MethodGet, "/register", "", "")
	if response.Code != http.StatusNotFound {
		t.Fatalf("disabled registration returned %d", response.Code)
	}
}

func TestRegistrationCreatesSessionAndPreservesOAuthFlow(t *testing.T) {
	registered := client.Client{
		ID:              "specus",
		Name:            "Specus",
		LoginMethods:    []client.LoginMethod{client.LoginPassword},
		AllowedScopes:   []string{"openid"},
		RedirectURIs:    []string{"https://specus.example.com/"},
		Protocols:       []client.Protocol{client.ProtocolOAuth21},
		GrantTypes:      []client.GrantType{client.GrantAuthorizationCode},
		ApplicationType: client.ApplicationPublic,
		Enabled:         true,
	}
	users := identity.NewMemoryUserRepository()
	handler := NewWithRepositories(
		config.Config{
			Issuer: "https://auth.example.com",
			Registration: config.RegistrationConfig{
				Enabled:      true,
				RequireEmail: true,
			},
		},
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		client.NewMemoryRepository(registered),
		users,
	)
	browser := newTestBrowser(handler)
	returnTo := "/oauth2/authorize?client_id=specus&redirect_uri=https%3A%2F%2Fspecus.example.com%2F&response_type=code"
	page := browser.request(
		t,
		http.MethodGet,
		"/register?continue="+url.QueryEscape(returnTo)+"&client_id=specus",
		"",
		"",
	)
	if page.Code != http.StatusOK ||
		!strings.Contains(page.Body.String(), "注册并登录 Specus") ||
		browser.cookies[csrfCookieName] == nil {
		t.Fatalf("unexpected registration page: %d %s", page.Code, page.Body.String())
	}
	form := url.Values{
		"csrf_token":            {browser.cookies[csrfCookieName].Value},
		"continue":              {returnTo},
		"client_id":             {"specus"},
		"username":              {"alice"},
		"display_name":          {"Alice Chen"},
		"email":                 {"Alice@Example.COM"},
		"password":              {"correct horse battery staple"},
		"password_confirmation": {"correct horse battery staple"},
	}
	response := browser.request(
		t,
		http.MethodPost,
		"/register",
		form.Encode(),
		"application/x-www-form-urlencoded",
	)
	if response.Code != http.StatusSeeOther ||
		response.Header().Get("Location") != returnTo ||
		browser.cookies[sessionCookieName] == nil {
		t.Fatalf("unexpected registration response: %d %s %s", response.Code, response.Header().Get("Location"), response.Body.String())
	}
	user, err := users.FindByUsername(context.Background(), "alice")
	if err != nil || user.Email == nil || *user.Email != "alice@example.com" {
		t.Fatalf("registered user was not persisted: %#v %v", user, err)
	}
	if _, err := identity.NewPasswordService(users).Authenticate(
		context.Background(),
		"alice",
		"correct horse battery staple",
	); err != nil {
		t.Fatalf("registered password cannot authenticate: %v", err)
	}
}

func TestRegistrationRendersValidationErrorsWithoutPartialUser(t *testing.T) {
	users := identity.NewMemoryUserRepository()
	handler := NewWithRepositories(
		config.Config{
			Issuer: "https://auth.example.com",
			Registration: config.RegistrationConfig{
				Enabled:      true,
				RequireEmail: true,
			},
		},
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		client.NewMemoryRepository(),
		users,
	)
	browser := newTestBrowser(handler)
	page := browser.request(t, http.MethodGet, "/register", "", "")
	if page.Code != http.StatusOK {
		t.Fatalf("registration page returned %d", page.Code)
	}
	form := url.Values{
		"csrf_token":            {browser.cookies[csrfCookieName].Value},
		"continue":              {"/portal"},
		"username":              {"alice"},
		"display_name":          {"Alice"},
		"email":                 {"alice@example.com"},
		"password":              {"correct horse battery staple"},
		"password_confirmation": {"different password value"},
	}
	response := browser.request(
		t,
		http.MethodPost,
		"/register",
		form.Encode(),
		"application/x-www-form-urlencoded",
	)
	if response.Code != http.StatusOK ||
		!strings.Contains(response.Body.String(), "两次输入的密码不一致") ||
		!strings.Contains(response.Body.String(), `value="alice"`) {
		t.Fatalf("unexpected validation response: %d %s", response.Code, response.Body.String())
	}
	if _, err := users.FindByUsername(context.Background(), "alice"); err == nil {
		t.Fatal("password mismatch left a partial user")
	}
}

func TestRegistrationRejectsClientWithoutPasswordLogin(t *testing.T) {
	registered := client.Client{
		ID:           "federated-only",
		Name:         "Federated only",
		LoginMethods: []client.LoginMethod{client.LoginOIDC},
		Enabled:      true,
	}
	handler := NewWithRepositories(
		config.Config{
			Issuer:       "https://auth.example.com",
			Registration: config.RegistrationConfig{Enabled: true},
		},
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		client.NewMemoryRepository(registered),
		identity.NewMemoryUserRepository(),
	)
	returnTo := "/oauth2/authorize?client_id=federated-only"
	response := newTestBrowser(handler).request(
		t,
		http.MethodGet,
		"/register?continue="+url.QueryEscape(returnTo),
		"",
		"",
	)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("federated-only client registration returned %d", response.Code)
	}
}

func TestRegistrationLinkAndRateLimit(t *testing.T) {
	users := identity.NewMemoryUserRepository()
	handler := NewWithRepositories(
		config.Config{
			Issuer:       "https://auth.example.com",
			Registration: config.RegistrationConfig{Enabled: true},
			RateLimits: config.RateLimitConfig{
				Registration: ratelimit.Policy{Limit: 1, Window: time.Hour},
			},
		},
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		client.NewMemoryRepository(),
		users,
	)
	browser := newTestBrowser(handler)
	login := browser.request(t, http.MethodGet, "/login", "", "")
	if login.Code != http.StatusOK || !strings.Contains(login.Body.String(), "创建 Certus 账号") {
		t.Fatalf("registration link is missing: %d %s", login.Code, login.Body.String())
	}
	page := browser.request(t, http.MethodGet, "/register", "", "")
	if page.Code != http.StatusOK {
		t.Fatalf("registration page returned %d", page.Code)
	}
	form := url.Values{
		"csrf_token":            {browser.cookies[csrfCookieName].Value},
		"continue":              {"/portal"},
		"username":              {"alice"},
		"display_name":          {"Alice"},
		"password":              {"correct horse battery staple"},
		"password_confirmation": {"different password value"},
	}
	first := browser.request(
		t,
		http.MethodPost,
		"/register",
		form.Encode(),
		"application/x-www-form-urlencoded",
	)
	if first.Code != http.StatusOK {
		t.Fatalf("first registration attempt returned %d", first.Code)
	}
	second := browser.request(
		t,
		http.MethodPost,
		"/register",
		form.Encode(),
		"application/x-www-form-urlencoded",
	)
	if second.Code != http.StatusTooManyRequests || second.Header().Get("Retry-After") == "" {
		t.Fatalf("registration rate limit returned %d with Retry-After %q", second.Code, second.Header().Get("Retry-After"))
	}
}
