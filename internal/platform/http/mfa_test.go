package httpserver

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
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
	"certus/internal/mfa"
	"certus/internal/oauth"
	"certus/internal/oidc"
	"certus/internal/session"
)

func TestTOTPEnrollmentAndLoginChallenge(t *testing.T) {
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
	_, accountToken, err := sessionService.Create(ctx, user.ID, "192.0.2.10", "account-agent")
	if err != nil {
		t.Fatal(err)
	}
	audits := audit.NewMemoryRepository()
	handler, err := NewWithDependencies(ctx, config.Config{
		Issuer:           "https://auth.example.com",
		MFAEncryptionKey: []byte("0123456789abcdef0123456789abcdef"),
	}, slog.New(slog.NewTextHandler(io.Discard, nil)), Dependencies{
		Clients:   client.NewMemoryRepository(),
		Users:     users,
		Passwords: users,
		Sessions:  sessionRepository,
		OAuth:     oauth.NewMemoryRepository(),
		CAS:       cas.NewMemoryRepository(),
		Audit:     audits,
		MFA:       mfa.NewMemoryRepository(),
		Keys:      &oidc.MemoryKeyRepository{},
	})
	if err != nil {
		t.Fatal(err)
	}
	csrf := strings.Repeat("c", 32)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/account/mfa/totp/setup", strings.NewReader(
		`{"current_password":"initial-password-123"}`,
	))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-CSRF-Token", csrf)
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: accountToken})
	request.AddCookie(&http.Cookie{Name: csrfCookieName, Value: csrf})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusCreated {
		t.Fatalf("setup MFA: %d %s", response.Code, response.Body.String())
	}
	var setup mfa.Setup
	if err := json.Unmarshal(response.Body.Bytes(), &setup); err != nil {
		t.Fatal(err)
	}
	if len(setup.RecoveryCodes) != 10 || setup.Secret == "" || setup.OTPAuthURI == "" {
		t.Fatalf("incomplete MFA setup: %#v", setup)
	}
	code := testTOTP(t, setup.Secret, time.Now())
	request = httptest.NewRequest(http.MethodPost, "/api/v1/account/mfa/totp/enable", strings.NewReader(
		`{"code":"`+code+`"}`,
	))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-CSRF-Token", csrf)
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: accountToken})
	request.AddCookie(&http.Cookie{Name: csrfCookieName, Value: csrf})
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("enable MFA: %d %s", response.Code, response.Body.String())
	}

	request = httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(
		"csrf_token="+csrf+"&continue=%2Fportal&username=alice&password=initial-password-123",
	))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(&http.Cookie{Name: csrfCookieName, Value: csrf})
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/login/mfa" {
		t.Fatalf("primary login did not require MFA: %d %s %s", response.Code, response.Header().Get("Location"), response.Body.String())
	}
	var transaction *http.Cookie
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == mfaCookieName {
			transaction = cookie
		}
	}
	if transaction == nil {
		t.Fatal("missing signed MFA transaction cookie")
	}

	request = httptest.NewRequest(http.MethodPost, "/login/mfa", strings.NewReader(
		"csrf_token="+csrf+"&code="+setup.RecoveryCodes[0],
	))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.AddCookie(&http.Cookie{Name: csrfCookieName, Value: csrf})
	request.AddCookie(transaction)
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/portal" {
		t.Fatalf("MFA login failed: %d %s %s", response.Code, response.Header().Get("Location"), response.Body.String())
	}
	foundSession := false
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == sessionCookieName && cookie.Value != "" {
			foundSession = true
		}
	}
	if !foundSession {
		t.Fatal("MFA completion did not create a session")
	}
	if page, err := audits.List(ctx, audit.Filter{EventType: "login.mfa", Limit: 20}); err != nil ||
		page.Total != 1 || page.Items[0].Outcome != audit.OutcomeSuccess {
		t.Fatalf("missing MFA login audit: %#v %v", page, err)
	}
}

func testTOTP(t *testing.T, encodedSecret string, now time.Time) string {
	t.Helper()
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(encodedSecret)
	if err != nil {
		t.Fatal(err)
	}
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(now.Unix()/30))
	mac := hmac.New(sha1.New, secret)
	_, _ = mac.Write(counter[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := (uint32(sum[offset])&0x7f)<<24 |
		uint32(sum[offset+1])<<16 |
		uint32(sum[offset+2])<<8 |
		uint32(sum[offset+3])
	return fmt.Sprintf("%06d", value%1_000_000)
}
