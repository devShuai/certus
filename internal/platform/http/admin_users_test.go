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

func TestAdminUsersRequireToken(t *testing.T) {
	handler := New(config.Config{Issuer: "https://auth.example.com", AdminToken: "test-admin-token"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	request := httptest.NewRequest(http.MethodGet, "/api/v1/admin/users", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unexpected response: %d %s", response.Code, response.Body.String())
	}
}

func TestAdminUsersRequireIdentityOrEmergencyToken(t *testing.T) {
	handler := New(config.Config{Issuer: "https://auth.example.com"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	request := httptest.NewRequest(http.MethodGet, "/api/v1/admin/users", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusUnauthorized || !strings.Contains(response.Body.String(), `"code":"unauthorized"`) {
		t.Fatalf("unexpected response: %d %s", response.Code, response.Body.String())
	}
}

func TestAdminUserLifecycle(t *testing.T) {
	handler := New(config.Config{Issuer: "https://auth.example.com", AdminToken: "test-admin-token"}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	create := httptest.NewRequest(http.MethodPost, "/api/v1/admin/users", bytes.NewBufferString(
		`{"username":"alice","display_name":"Alice","email":"alice@example.com"}`,
	))
	create.Header.Set("Content-Type", "application/json")
	create.Header.Set("Authorization", "Bearer test-admin-token")
	created := httptest.NewRecorder()

	handler.ServeHTTP(created, create)

	if created.Code != http.StatusCreated || !strings.Contains(created.Body.String(), `"username":"alice"`) {
		t.Fatalf("unexpected create response: %d %s", created.Code, created.Body.String())
	}

	list := httptest.NewRequest(http.MethodGet, "/api/v1/admin/users?q=ali&limit=10", nil)
	list.Header.Set("Authorization", "Bearer test-admin-token")
	listed := httptest.NewRecorder()
	handler.ServeHTTP(listed, list)
	if listed.Code != http.StatusOK || !strings.Contains(listed.Body.String(), `"total":1`) {
		t.Fatalf("unexpected list response: %d %s", listed.Code, listed.Body.String())
	}

	location := created.Header().Get("Location")
	userID := location[strings.LastIndex(location, "/")+1:]
	setPassword := httptest.NewRequest(http.MethodPut, location+"/password", bytes.NewBufferString(
		`{"password":"correct horse battery staple"}`,
	))
	setPassword.Header.Set("Content-Type", "application/json")
	setPassword.Header.Set("Authorization", "Bearer test-admin-token")
	passwordSet := httptest.NewRecorder()
	handler.ServeHTTP(passwordSet, setPassword)
	if passwordSet.Code != http.StatusNoContent {
		t.Fatalf("unexpected password response: %d %s", passwordSet.Code, passwordSet.Body.String())
	}

	replace := httptest.NewRequest(http.MethodPut, location, bytes.NewBufferString(
		`{"display_name":"Alice Chen","email":null,"status":"disabled"}`,
	))
	replace.Header.Set("Content-Type", "application/json")
	replace.Header.Set("Authorization", "Bearer test-admin-token")
	replaced := httptest.NewRecorder()
	handler.ServeHTTP(replaced, replace)
	if replaced.Code != http.StatusOK ||
		!strings.Contains(replaced.Body.String(), `"status":"disabled"`) ||
		!strings.Contains(replaced.Body.String(), `"email":null`) {
		t.Fatalf("unexpected replace response for %s: %d %s", userID, replaced.Code, replaced.Body.String())
	}
}
