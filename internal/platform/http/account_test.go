package httpserver

import (
	"context"
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
	"certus/internal/session"
)

func TestAccountSessionPasswordChangeAndReset(t *testing.T) {
	ctx := context.Background()
	user, err := identity.NewUser(identity.CreateUser{
		Username: "alice", DisplayName: "Alice", Status: identity.UserActive,
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	users := identity.NewMemoryUserRepository(user)
	passwords := identity.NewPasswordService(users)
	if err := passwords.Set(ctx, user.ID, "initial-password-123"); err != nil {
		t.Fatal(err)
	}
	sessionRepository := session.NewMemoryRepository()
	sessionService := session.NewService(sessionRepository, time.Hour)
	current, currentToken, err := sessionService.Create(ctx, user.ID, "192.0.2.10", "current-agent")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := sessionService.Create(ctx, user.ID, "192.0.2.11", "other-agent"); err != nil {
		t.Fatal(err)
	}
	audits := audit.NewMemoryRepository()
	handler, err := NewWithDependencies(ctx, config.Config{
		Issuer: "https://auth.example.com", AdminToken: strings.Repeat("a", 32),
	}, slog.New(slog.NewTextHandler(io.Discard, nil)), Dependencies{
		Clients:   client.NewMemoryRepository(),
		Users:     users,
		Passwords: users,
		Sessions:  sessionRepository,
		OAuth:     oauth.NewMemoryRepository(),
		CAS:       cas.NewMemoryRepository(),
		Audit:     audits,
		Keys:      &oidc.MemoryKeyRepository{},
	})
	if err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodGet, "/account", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusFound || response.Header().Get("Location") != "/login?continue=%2Faccount" {
		t.Fatalf("unauthenticated account page: %d %s", response.Code, response.Header().Get("Location"))
	}

	request = httptest.NewRequest(http.MethodGet, "/account", nil)
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: currentToken})
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK ||
		!strings.Contains(response.Body.String(), "账户安全") ||
		!strings.Contains(response.Body.String(), "/static/account.js") {
		t.Fatalf("account page: %d %s", response.Code, response.Body.String())
	}

	request = httptest.NewRequest(http.MethodGet, "/api/v1/account/profile", nil)
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: currentToken})
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK ||
		!strings.Contains(response.Body.String(), `"username":"alice"`) ||
		!strings.Contains(response.Body.String(), `"current_session"`) ||
		!strings.Contains(response.Body.String(), `"csrf_token"`) {
		t.Fatalf("account profile: %d %s", response.Code, response.Body.String())
	}

	request = httptest.NewRequest(http.MethodGet, "/api/v1/account/sessions", nil)
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: currentToken})
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK ||
		!strings.Contains(response.Body.String(), `"current":true`) ||
		!strings.Contains(response.Body.String(), `"other-agent"`) {
		t.Fatalf("list sessions: %d %s", response.Code, response.Body.String())
	}

	request = httptest.NewRequest(http.MethodPut, "/api/v1/account/password", strings.NewReader(
		`{"current_password":"initial-password-123","new_password":"changed-password-456"}`,
	))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-CSRF-Token", strings.Repeat("c", 32))
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: currentToken})
	request.AddCookie(&http.Cookie{Name: csrfCookieName, Value: strings.Repeat("c", 32)})
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("change password: %d %s", response.Code, response.Body.String())
	}
	active, err := sessionService.ListByUser(ctx, user.ID)
	if err != nil || len(active) != 1 || active[0].ID != current.ID {
		t.Fatalf("other sessions were not revoked: %#v %v", active, err)
	}

	request = httptest.NewRequest(http.MethodPost, "/api/v1/admin/users/"+user.ID+"/password-reset", nil)
	request.Header.Set("Authorization", "Bearer "+strings.Repeat("a", 32))
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("issue reset: %d %s", response.Code, response.Body.String())
	}
	var issued map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &issued); err != nil {
		t.Fatal(err)
	}
	resetToken, _ := issued["reset_token"].(string)
	if resetToken == "" {
		t.Fatal("missing one-time reset token")
	}

	request = httptest.NewRequest(http.MethodPost, "/api/v1/account/password/reset", strings.NewReader(
		`{"reset_token":"`+resetToken+`","new_password":"reset-password-789"}`,
	))
	request.Header.Set("Content-Type", "application/json")
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("redeem reset: %d %s", response.Code, response.Body.String())
	}
	if active, _ := sessionService.ListByUser(ctx, user.ID); len(active) != 0 {
		t.Fatalf("reset did not revoke sessions: %#v", active)
	}
	if _, err := passwords.Authenticate(ctx, user.Username, "reset-password-789"); err != nil {
		t.Fatalf("reset password does not authenticate: %v", err)
	}
	if page, err := audits.List(ctx, audit.Filter{EventType: "password.reset", Limit: 20}); err != nil ||
		page.Total != 1 || page.Items[0].Outcome != audit.OutcomeSuccess {
		t.Fatalf("missing reset audit: %#v %v", page, err)
	}

	_, logoutToken, err := sessionService.Create(ctx, user.ID, "192.0.2.12", "logout-agent")
	if err != nil {
		t.Fatal(err)
	}
	request = httptest.NewRequest(http.MethodPost, "/logout", strings.NewReader(""))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: logoutToken})
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), `"invalid_csrf"`) {
		t.Fatalf("logout without CSRF: %d %s", response.Code, response.Body.String())
	}
	if active, _ := sessionService.ListByUser(ctx, user.ID); len(active) != 1 {
		t.Fatalf("invalid logout revoked session: %#v", active)
	}

	csrf := strings.Repeat("d", 32)
	request = httptest.NewRequest(http.MethodPost, "/logout", strings.NewReader("csrf_token="+csrf))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: logoutToken})
	request.AddCookie(&http.Cookie{Name: csrfCookieName, Value: csrf})
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/login" {
		t.Fatalf("logout: %d %s", response.Code, response.Body.String())
	}
	if active, _ := sessionService.ListByUser(ctx, user.ID); len(active) != 0 {
		t.Fatalf("logout did not revoke current session: %#v", active)
	}
}
