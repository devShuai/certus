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
	"time"

	"certus/internal/config"
	"certus/internal/ratelimit"
)

type failingRateLimitRepository struct{}

func (failingRateLimitRepository) Take(
	context.Context,
	ratelimit.Attempt,
) (ratelimit.Decision, error) {
	return ratelimit.Decision{}, errors.New("repository unavailable")
}

func TestRateLimitIsSharedAndReturnsRetryMetadata(t *testing.T) {
	repository := ratelimit.NewMemoryRepository()
	now := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	newServer := func() *server {
		return &server{
			logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
			rateLimits: ratelimit.NewService(repository),
			now:        func() time.Time { return now },
		}
	}
	policy := ratelimit.Policy{Limit: 1, Window: time.Minute}
	request := func() *http.Request {
		value := httptest.NewRequest(http.MethodPost, "/login", nil)
		value.RemoteAddr = "192.0.2.10:4321"
		return value
	}
	if allowed := newServer().allowRateLimitedRequest(
		httptest.NewRecorder(), request(),
		"login.source", "192.0.2.10", policy, false,
	); !allowed {
		t.Fatal("first request was blocked")
	}
	response := httptest.NewRecorder()
	if allowed := newServer().allowRateLimitedRequest(
		response, request(),
		"login.source", "192.0.2.10", policy, false,
	); allowed {
		t.Fatal("request over the shared limit was allowed")
	}
	if response.Code != http.StatusTooManyRequests ||
		response.Header().Get("Retry-After") != "60" ||
		response.Header().Get("X-RateLimit-Remaining") != "0" {
		t.Fatalf("unexpected limited response: %d %#v %s", response.Code, response.Header(), response.Body.String())
	}
}

func TestRateLimitFailsClosedWhenRepositoryIsUnavailable(t *testing.T) {
	s := &server{
		logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		rateLimits: ratelimit.NewService(failingRateLimitRepository{}),
		now:        time.Now,
	}
	response := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/oauth2/token", nil)
	if allowed := s.allowRateLimitedRequest(
		response, request,
		"oauth.source", "192.0.2.10",
		ratelimit.Policy{Limit: 10, Window: time.Minute}, true,
	); allowed {
		t.Fatal("request was allowed without rate-limit storage")
	}
	if response.Code != http.StatusServiceUnavailable ||
		!strings.Contains(response.Body.String(), `"error":"temporarily_unavailable"`) {
		t.Fatalf("unexpected unavailable response: %d %s", response.Code, response.Body.String())
	}
}

func TestOAuthEndpointAppliesConfiguredRateLimit(t *testing.T) {
	handler := New(config.Config{
		Issuer: "https://auth.example.com",
		RateLimits: config.RateLimitConfig{
			OAuth: ratelimit.Policy{Limit: 1, Window: time.Minute},
		},
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	send := func() *httptest.ResponseRecorder {
		body := url.Values{
			"client_id":  {"unknown"},
			"grant_type": {"client_credentials"},
		}.Encode()
		request := httptest.NewRequest(http.MethodPost, "/oauth2/token", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	if first := send(); first.Code != http.StatusUnauthorized {
		t.Fatalf("first invalid client request: %d %s", first.Code, first.Body.String())
	}
	if second := send(); second.Code != http.StatusTooManyRequests {
		t.Fatalf("rate limit was not enforced: %d %s", second.Code, second.Body.String())
	}
}
