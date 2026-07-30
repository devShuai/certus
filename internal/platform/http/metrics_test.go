package httpserver

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"certus/internal/config"
)

func TestMetricsEndpointIsDisabledWithoutDedicatedToken(t *testing.T) {
	handler := New(
		config.Config{Issuer: "https://auth.example.com"},
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if response.Code != http.StatusNotFound {
		t.Fatalf("disabled metrics endpoint: %d %s", response.Code, response.Body.String())
	}
}

func TestMetricsEndpointRequiresTokenAndExportsLowCardinalityRoutes(t *testing.T) {
	token := strings.Repeat("m", 32)
	handler := New(
		config.Config{Issuer: "https://auth.example.com", MetricsToken: token},
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	health := httptest.NewRecorder()
	handler.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/healthz", nil))

	unauthorized := httptest.NewRecorder()
	handler.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized metrics request: %d %s", unauthorized.Code, unauthorized.Body.String())
	}

	request := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK ||
		!strings.HasPrefix(response.Header().Get("Content-Type"), "text/plain") ||
		!strings.Contains(
			response.Body.String(),
			`certus_http_requests_total{method="GET",route="GET /healthz",status="200"} 1`,
		) {
		t.Fatalf("authorized metrics request: %d %#v %s", response.Code, response.Header(), response.Body.String())
	}
	if strings.Contains(response.Body.String(), token) {
		t.Fatal("metrics token leaked into output")
	}
}
