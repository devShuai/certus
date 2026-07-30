package httpserver

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
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

	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "中间落地页") {
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

func TestAuthorizeRejectsUnknownClient(t *testing.T) {
	handler := New(config.Config{Issuer: "https://auth.example.com"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	request := httptest.NewRequest(http.MethodGet, "/oauth2/authorize?client_id=unknown", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `"code":"invalid_request"`) {
		t.Fatalf("unexpected response: %d %s", response.Code, response.Body.String())
	}
}
