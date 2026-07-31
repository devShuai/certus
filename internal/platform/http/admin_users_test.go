package httpserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"certus/internal/client"
	"certus/internal/config"
	"certus/internal/identity"
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

func TestAdminImportsSpecusPasswordsAndLoginUpgradesHash(t *testing.T) {
	users := identity.NewMemoryUserRepository()
	handler := NewWithRepositories(
		config.Config{
			Issuer:     "https://auth.example.com",
			AdminToken: "test-admin-token",
		},
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		client.NewMemoryRepository(),
		users,
	)
	password := "existing specus password"
	passwordHash := fmt.Sprintf("%x", sha256.Sum256([]byte(password)))
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/admin/users/import",
		bytes.NewBufferString(fmt.Sprintf(`{
			"password_algorithm":"specus_sha256",
			"users":[{
				"username":"alice",
				"display_name":"Alice",
				"email":"alice@example.com",
				"password_hash":"%s"
			}]
		}`, passwordHash)),
	)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer test-admin-token")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated ||
		!strings.Contains(response.Body.String(), `"count":1`) ||
		strings.Contains(response.Body.String(), passwordHash) {
		t.Fatalf("unexpected import response: %d %s", response.Code, response.Body.String())
	}

	browser := newTestBrowser(handler)
	page := browser.request(t, http.MethodGet, "/login", "", "")
	if page.Code != http.StatusOK {
		t.Fatalf("login page returned %d", page.Code)
	}
	form := "csrf_token=" + url.QueryEscape(browser.cookies[csrfCookieName].Value) +
		"&continue=%2Fportal&username=alice&password=" + url.QueryEscape(password)
	login := browser.request(
		t,
		http.MethodPost,
		"/login",
		form,
		"application/x-www-form-urlencoded",
	)
	if login.Code != http.StatusSeeOther ||
		login.Header().Get("Location") != loginSuccessURL("/portal") {
		t.Fatalf("migrated login returned %d %s", login.Code, login.Body.String())
	}
	_, credential, err := users.FindPasswordByUsername(context.Background(), "alice")
	if err != nil || !strings.HasPrefix(credential.Hash, "$argon2id$") {
		t.Fatalf("migrated password was not upgraded: %#v %v", credential, err)
	}
}

func TestAdminPasswordImportIsAtomicOnConflict(t *testing.T) {
	users := identity.NewMemoryUserRepository()
	handler := NewWithRepositories(
		config.Config{
			Issuer:     "https://auth.example.com",
			AdminToken: "test-admin-token",
		},
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		client.NewMemoryRepository(),
		users,
	)
	passwordHash := fmt.Sprintf("%x", sha256.Sum256([]byte("existing password")))
	importUsers := func(body string) *httptest.ResponseRecorder {
		t.Helper()
		request := httptest.NewRequest(
			http.MethodPost,
			"/api/v1/admin/users/import",
			bytes.NewBufferString(body),
		)
		request.Header.Set("Content-Type", "application/json")
		request.Header.Set("Authorization", "Bearer test-admin-token")
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	first := importUsers(fmt.Sprintf(`{
		"password_algorithm":"specus_sha256",
		"users":[{"username":"existing","display_name":"Existing","password_hash":"%s"}]
	}`, passwordHash))
	if first.Code != http.StatusCreated {
		t.Fatalf("initial import returned %d %s", first.Code, first.Body.String())
	}
	conflict := importUsers(fmt.Sprintf(`{
		"password_algorithm":"specus_sha256",
		"users":[
			{"username":"new-user","display_name":"New User","password_hash":"%s"},
			{"username":"existing","display_name":"Existing","password_hash":"%s"}
		]
	}`, passwordHash, passwordHash))
	if conflict.Code != http.StatusConflict {
		t.Fatalf("conflicting import returned %d %s", conflict.Code, conflict.Body.String())
	}
	if _, err := users.FindByUsername(context.Background(), "new-user"); err == nil {
		t.Fatal("conflicting import left a partial user")
	}
}
