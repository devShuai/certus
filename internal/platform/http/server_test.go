package httpserver

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"certus/internal/config"
)

func TestHealth(t *testing.T) {
	handler := New(config.Config{Issuer: "https://auth.example.com"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	request := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"status":"ok"`) {
		t.Fatalf("unexpected response: %d %s", response.Code, response.Body.String())
	}
	if response.Header().Get("X-Request-ID") == "" {
		t.Fatal("missing request ID")
	}
}

func TestReadinessReflectsDependencyState(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	readyServer := &server{
		logger:    logger,
		readiness: func(context.Context) error { return nil },
	}
	response := httptest.NewRecorder()
	readyServer.ready(response, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"status":"ready"`) {
		t.Fatalf("unexpected ready response: %d %s", response.Code, response.Body.String())
	}

	unavailableServer := &server{
		logger: logger,
		readiness: func(context.Context) error {
			return errors.New("dependency unavailable")
		},
	}
	response = httptest.NewRecorder()
	unavailableServer.ready(response, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if response.Code != http.StatusServiceUnavailable ||
		!strings.Contains(response.Body.String(), `"status":"unavailable"`) {
		t.Fatalf("unexpected unavailable response: %d %s", response.Code, response.Body.String())
	}
}

func TestPortal(t *testing.T) {
	handler := New(config.Config{Issuer: "https://auth.example.com"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	request := httptest.NewRequest(http.MethodGet, "/portal", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	body := response.Body.String()
	if response.Code != http.StatusOK ||
		!strings.Contains(body, "中间落地页") ||
		!strings.Contains(body, `href="http://localhost:3000/?login=oidc"`) ||
		strings.Contains(body, `/login?client_id=specus`) {
		t.Fatalf("unexpected response: %d %s", response.Code, response.Body.String())
	}
}

func TestAuthorizeRedirectsValidRequestToLogin(t *testing.T) {
	handler := New(config.Config{Issuer: "https://auth.example.com"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	target := "/oauth2/authorize?client_id=specus&redirect_uri=http%3A%2F%2Flocalhost%3A3000%2Fcallback&response_type=code&scope=openid&state=opaque-state&code_challenge=abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG&code_challenge_method=S256"
	request := httptest.NewRequest(http.MethodGet, target, nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusFound {
		t.Fatalf("unexpected response: %d %s", response.Code, response.Body.String())
	}
	location := response.Header().Get("Location")
	if !strings.HasPrefix(location, "/login?") || !strings.Contains(location, "client_id=specus") {
		t.Fatalf("unexpected redirect: %s", location)
	}
}

func TestLoginPageHighlightsTargetSystem(t *testing.T) {
	handler := New(config.Config{Issuer: "https://auth.example.com"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	returnTo := "/oauth2/authorize?client_id=specus"
	request := httptest.NewRequest(
		http.MethodGet,
		"/login?continue="+url.QueryEscape(returnTo)+"&client_id=specus",
		nil,
	)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	body := response.Body.String()
	if response.Code != http.StatusOK ||
		!strings.Contains(body, `class="login-target"`) ||
		!strings.Contains(body, "即将登录") ||
		!strings.Contains(body, "登录 Specus") ||
		!strings.Contains(body, "<small>specus</small>") {
		t.Fatalf("login page did not emphasize target system: %d %s", response.Code, body)
	}
}

func TestLoginSuccessPageRequiresSession(t *testing.T) {
	handler := New(config.Config{Issuer: "https://auth.example.com"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	request := httptest.NewRequest(
		http.MethodGet,
		loginSuccessURL("/portal"),
		nil,
	)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusFound ||
		response.Header().Get("Location") != "/login?continue=%2Fportal" {
		t.Fatalf("anonymous success page was not rejected: %d %s", response.Code, response.Header().Get("Location"))
	}
}

func TestAuthorizeRejectsUnknownClient(t *testing.T) {
	handler := New(config.Config{Issuer: "https://auth.example.com"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	request := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?client_id=unknown", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `"code":"invalid_request"`) {
		t.Fatalf("unexpected response: %d %s", response.Code, response.Body.String())
	}
}
