package httpserver

import (
	"bytes"
	"context"
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
	"certus/internal/mailer"
	"certus/internal/oauth"
	"certus/internal/oidc"
	"certus/internal/ratelimit"
	"certus/internal/session"
)

func newEmailVerificationHandler(
	t *testing.T,
	user identity.User,
	sender mailer.Sender,
	configure func(*config.Config),
) (http.Handler, string, *identity.MemoryUserRepository, *audit.MemoryRepository) {
	t.Helper()
	users := identity.NewMemoryUserRepository(user)
	return newEmailVerificationHandlerWithUsers(t, users, user, sender, configure)
}

func newEmailVerificationHandlerWithUsers(
	t *testing.T,
	users *identity.MemoryUserRepository,
	sessionUser identity.User,
	sender mailer.Sender,
	configure func(*config.Config),
) (http.Handler, string, *identity.MemoryUserRepository, *audit.MemoryRepository) {
	t.Helper()
	ctx := context.Background()
	sessionRepository := session.NewMemoryRepository()
	sessionService := session.NewService(sessionRepository, time.Hour)
	_, currentToken, err := sessionService.Create(ctx, sessionUser.ID, "192.0.2.10", "test-agent")
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{
		Issuer:               "https://auth.example.com",
		AdminToken:           "test-admin-token",
		EmailVerificationTTL: 30 * time.Minute,
	}
	if configure != nil {
		configure(&cfg)
	}
	audits := audit.NewMemoryRepository()
	handler, err := NewWithDependencies(ctx, cfg, slog.New(slog.NewTextHandler(io.Discard, nil)), Dependencies{
		Clients:   client.NewMemoryRepository(),
		Users:     users,
		Passwords: users,
		Sessions:  sessionRepository,
		OAuth:     oauth.NewMemoryRepository(),
		CAS:       cas.NewMemoryRepository(),
		Audit:     audits,
		Keys:      &oidc.MemoryKeyRepository{},
		Mailer:    sender,
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler, currentToken, users, audits
}

func accountCSRF(t *testing.T, handler http.Handler, sessionToken string) accountCredentials {
	t.Helper()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/account/profile", nil)
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionToken})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("account profile: %d %s", response.Code, response.Body.String())
	}
	var body struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	var csrfCookie *http.Cookie
	for _, cookie := range response.Result().Cookies() {
		if cookie.Name == csrfCookieName {
			csrfCookie = cookie
			break
		}
	}
	if csrfCookie == nil {
		t.Fatal("profile response did not set a CSRF cookie")
	}
	return accountCredentials{
		sessionToken: sessionToken,
		csrfToken:    body.CSRFToken,
		csrfCookie:   csrfCookie,
	}
}

type accountCredentials struct {
	sessionToken string
	csrfToken    string
	csrfCookie   *http.Cookie
}

func (c accountCredentials) attach(request *http.Request) {
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: c.sessionToken})
	if c.csrfCookie != nil {
		request.AddCookie(c.csrfCookie)
	}
}

func issueVerificationRequest(handler http.Handler, credentials accountCredentials) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "/api/v1/account/email/verification", nil)
	if credentials.sessionToken != "" {
		credentials.attach(request)
	}
	if credentials.csrfToken != "" {
		request.Header.Set("X-CSRF-Token", credentials.csrfToken)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func verificationTokenFromMessage(t *testing.T, messages []mailer.Message) string {
	t.Helper()
	if len(messages) != 1 {
		t.Fatalf("expected one verification email, got %#v", messages)
	}
	const marker = "/account/verify-email?token="
	index := strings.Index(messages[0].Text, marker)
	if index < 0 {
		t.Fatalf("verification email has no link: %s", messages[0].Text)
	}
	rest := messages[0].Text[index+len(marker):]
	token, _, _ := strings.Cut(rest, "\n")
	return strings.TrimSpace(token)
}

func verifyRequest(handler http.Handler, credentials accountCredentials, token string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/account/email/verify",
		bytes.NewBufferString(`{"token":"`+token+`"}`),
	)
	request.Header.Set("Content-Type", "application/json")
	if credentials.sessionToken != "" {
		credentials.attach(request)
	}
	if credentials.csrfToken != "" {
		request.Header.Set("X-CSRF-Token", credentials.csrfToken)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func TestAccountIssuesAndVerifiesEmail(t *testing.T) {
	email := "alice@example.com"
	user, err := identity.NewUser(identity.CreateUser{
		Username: "alice", DisplayName: "Alice", Email: &email, Status: identity.UserActive,
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	recording := &recordingMailer{}
	handler, sessionToken, users, audits := newEmailVerificationHandler(t, user, recording, nil)
	credentials := accountCSRF(t, handler, sessionToken)

	response := issueVerificationRequest(handler, credentials)
	if response.Code != http.StatusNoContent {
		t.Fatalf("issue verification: %d %s", response.Code, response.Body.String())
	}
	if len(recording.messages) != 1 ||
		recording.messages[0].To != email ||
		recording.messages[0].Subject != "验证你的 Certus 邮箱" {
		t.Fatalf("unexpected verification message: %#v", recording.messages)
	}
	token := verificationTokenFromMessage(t, recording.messages)

	response = verifyRequest(handler, credentials, token)
	if response.Code != http.StatusNoContent {
		t.Fatalf("verify email: %d %s", response.Code, response.Body.String())
	}
	verified, err := users.Find(context.Background(), user.ID)
	if err != nil || !verified.EmailVerified {
		t.Fatalf("email was not verified: %#v %v", verified, err)
	}
	if events, err := audits.List(context.Background(), audit.Filter{Limit: 100}); err != nil ||
		len(events.Items) != 2 {
		t.Fatalf("unexpected audit events: %#v %v", events, err)
	} else {
		eventTypes := map[string]bool{}
		for _, event := range events.Items {
			eventTypes[event.EventType] = true
		}
		if !eventTypes["email.verification_sent"] || !eventTypes["email.verified"] {
			t.Fatalf("missing audit events: %#v", events.Items)
		}
	}

	response = verifyRequest(handler, credentials, token)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("reused verification token: %d %s", response.Code, response.Body.String())
	}
}

func TestAccountEmailVerificationRequiresAuthenticationAndCSRF(t *testing.T) {
	email := "alice@example.com"
	user, err := identity.NewUser(identity.CreateUser{
		Username: "alice", DisplayName: "Alice", Email: &email, Status: identity.UserActive,
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	handler, sessionToken, _, _ := newEmailVerificationHandler(t, user, &recordingMailer{}, nil)

	response := issueVerificationRequest(handler, accountCredentials{})
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated issue: %d %s", response.Code, response.Body.String())
	}
	response = issueVerificationRequest(handler, accountCredentials{sessionToken: sessionToken})
	if response.Code != http.StatusBadRequest {
		t.Fatalf("missing CSRF issue: %d %s", response.Code, response.Body.String())
	}
	response = verifyRequest(handler, accountCredentials{sessionToken: sessionToken}, "some-token")
	if response.Code != http.StatusBadRequest {
		t.Fatalf("missing CSRF verify: %d %s", response.Code, response.Body.String())
	}
}

func TestAccountEmailVerificationConflicts(t *testing.T) {
	email := "alice@example.com"
	user, err := identity.NewUser(identity.CreateUser{
		Username: "alice", DisplayName: "Alice", Email: &email, Status: identity.UserActive,
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	recording := &recordingMailer{}
	handler, sessionToken, users, _ := newEmailVerificationHandler(t, user, recording, nil)
	credentials := accountCSRF(t, handler, sessionToken)
	if _, err := users.SetEmailVerified(context.Background(), user.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	response := issueVerificationRequest(handler, credentials)
	if response.Code != http.StatusConflict || len(recording.messages) != 0 {
		t.Fatalf("verified user issue: %d %s", response.Code, response.Body.String())
	}
}

func changeEmailRequest(handler http.Handler, credentials accountCredentials, email string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(
		http.MethodPut,
		"/api/v1/account/email",
		bytes.NewBufferString(`{"email":"`+email+`"}`),
	)
	request.Header.Set("Content-Type", "application/json")
	credentials.attach(request)
	request.Header.Set("X-CSRF-Token", credentials.csrfToken)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func TestAccountChangesEmailAndReVerifies(t *testing.T) {
	email := "alice@example.com"
	user, err := identity.NewUser(identity.CreateUser{
		Username: "alice", DisplayName: "Alice", Email: &email, Status: identity.UserActive,
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	recording := &recordingMailer{}
	handler, sessionToken, users, audits := newEmailVerificationHandler(t, user, recording, nil)
	credentials := accountCSRF(t, handler, sessionToken)

	if response := issueVerificationRequest(handler, credentials); response.Code != http.StatusNoContent {
		t.Fatalf("issue before change: %d %s", response.Code, response.Body.String())
	}
	oldToken := verificationTokenFromMessage(t, recording.messages)

	replacement := "alice+new@example.com"
	response := changeEmailRequest(handler, credentials, replacement)
	if response.Code != http.StatusNoContent {
		t.Fatalf("change email: %d %s", response.Code, response.Body.String())
	}
	changed, err := users.Find(context.Background(), user.ID)
	if err != nil || changed.Email == nil || *changed.Email != replacement {
		t.Fatalf("email was not updated: %#v %v", changed, err)
	}
	if changed.EmailVerified {
		t.Fatalf("email change did not reset verification: %#v", changed)
	}
	if len(recording.messages) != 2 || recording.messages[1].To != replacement {
		t.Fatalf("verification email was not sent to the new address: %#v", recording.messages)
	}
	newToken := verificationTokenFromMessage(t, recording.messages[1:])

	response = verifyRequest(handler, credentials, oldToken)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("old token still valid after email change: %d %s", response.Code, response.Body.String())
	}
	response = verifyRequest(handler, credentials, newToken)
	if response.Code != http.StatusNoContent {
		t.Fatalf("verify new address: %d %s", response.Code, response.Body.String())
	}
	final, err := users.Find(context.Background(), user.ID)
	if err != nil || !final.EmailVerified {
		t.Fatalf("new address was not verified: %#v %v", final, err)
	}
	eventTypes := map[string]bool{}
	if events, err := audits.List(context.Background(), audit.Filter{Limit: 100}); err != nil {
		t.Fatal(err)
	} else {
		for _, event := range events.Items {
			eventTypes[event.EventType] = true
		}
	}
	if !eventTypes["email.changed"] || !eventTypes["email.verification_sent"] || !eventTypes["email.verified"] {
		t.Fatalf("missing audit events: %#v", eventTypes)
	}
}

func TestAccountEmailChangeRejectsConflict(t *testing.T) {
	emailA := "alice@example.com"
	userA, err := identity.NewUser(identity.CreateUser{
		Username: "alice", DisplayName: "Alice", Email: &emailA, Status: identity.UserActive,
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	emailB := "bob@example.com"
	userB, err := identity.NewUser(identity.CreateUser{
		Username: "bob", DisplayName: "Bob", Email: &emailB, Status: identity.UserActive,
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	users := identity.NewMemoryUserRepository(userA, userB)
	handler, sessionToken, _, _ := newEmailVerificationHandlerWithUsers(t, users, userB, &recordingMailer{}, nil)
	credentials := accountCSRF(t, handler, sessionToken)
	response := changeEmailRequest(handler, credentials, emailA)
	if response.Code != http.StatusConflict {
		t.Fatalf("conflicting email change: %d %s", response.Code, response.Body.String())
	}
}

func TestAccountEmailChangeRejectsInvalidEmail(t *testing.T) {
	email := "alice@example.com"
	user, err := identity.NewUser(identity.CreateUser{
		Username: "alice", DisplayName: "Alice", Email: &email, Status: identity.UserActive,
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	handler, sessionToken, _, _ := newEmailVerificationHandler(t, user, &recordingMailer{}, nil)
	credentials := accountCSRF(t, handler, sessionToken)
	for _, invalid := range []string{"", "not-an-email"} {
		response := changeEmailRequest(handler, credentials, invalid)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("invalid email %q: %d %s", invalid, response.Code, response.Body.String())
		}
	}
}

func TestAccountEmailChangeSameVerifiedEmailIsNoOp(t *testing.T) {
	email := "alice@example.com"
	user, err := identity.NewUser(identity.CreateUser{
		Username: "alice", DisplayName: "Alice", Email: &email, Status: identity.UserActive,
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	recording := &recordingMailer{}
	handler, sessionToken, users, _ := newEmailVerificationHandler(t, user, recording, nil)
	credentials := accountCSRF(t, handler, sessionToken)
	if _, err := users.SetEmailVerified(context.Background(), user.ID, time.Now()); err != nil {
		t.Fatal(err)
	}
	response := changeEmailRequest(handler, credentials, email)
	if response.Code != http.StatusNoContent || len(recording.messages) != 0 {
		t.Fatalf("same verified email: %d %s", response.Code, response.Body.String())
	}
}

func TestAccountEmailChangeRateLimited(t *testing.T) {
	email := "alice@example.com"
	user, err := identity.NewUser(identity.CreateUser{
		Username: "alice", DisplayName: "Alice", Email: &email, Status: identity.UserActive,
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	recording := &recordingMailer{}
	handler, sessionToken, _, _ := newEmailVerificationHandler(t, user, recording, func(cfg *config.Config) {
		cfg.RateLimits.EmailVerification = ratelimit.Policy{Limit: 1, Window: time.Minute}
	})
	credentials := accountCSRF(t, handler, sessionToken)
	if response := changeEmailRequest(handler, credentials, "alice+new@example.com"); response.Code != http.StatusNoContent {
		t.Fatalf("first change: %d %s", response.Code, response.Body.String())
	}
	response := changeEmailRequest(handler, credentials, "alice+other@example.com")
	if response.Code != http.StatusTooManyRequests {
		t.Fatalf("rate-limited change: %d %s", response.Code, response.Body.String())
	}
}

func TestAccountEmailVerificationRequiresConfiguredEmail(t *testing.T) {
	user, err := identity.NewUser(identity.CreateUser{
		Username: "alice", DisplayName: "Alice", Status: identity.UserActive,
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	recording := &recordingMailer{}
	handler, sessionToken, _, _ := newEmailVerificationHandler(t, user, recording, nil)
	credentials := accountCSRF(t, handler, sessionToken)
	response := issueVerificationRequest(handler, credentials)
	if response.Code != http.StatusBadRequest || len(recording.messages) != 0 {
		t.Fatalf("user without email: %d %s", response.Code, response.Body.String())
	}
}

func TestAccountEmailVerificationRequiresSMTP(t *testing.T) {
	email := "alice@example.com"
	user, err := identity.NewUser(identity.CreateUser{
		Username: "alice", DisplayName: "Alice", Email: &email, Status: identity.UserActive,
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	handler, sessionToken, _, _ := newEmailVerificationHandler(t, user, nil, nil)
	credentials := accountCSRF(t, handler, sessionToken)
	response := issueVerificationRequest(handler, credentials)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("unconfigured SMTP: %d %s", response.Code, response.Body.String())
	}
}

func TestAccountEmailVerificationReportsSendFailure(t *testing.T) {
	email := "alice@example.com"
	user, err := identity.NewUser(identity.CreateUser{
		Username: "alice", DisplayName: "Alice", Email: &email, Status: identity.UserActive,
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	recording := &recordingMailer{err: errors.New("SMTP unavailable")}
	handler, sessionToken, _, _ := newEmailVerificationHandler(t, user, recording, nil)
	credentials := accountCSRF(t, handler, sessionToken)
	response := issueVerificationRequest(handler, credentials)
	if response.Code != http.StatusBadGateway {
		t.Fatalf("SMTP failure: %d %s", response.Code, response.Body.String())
	}
}

func TestAccountEmailVerificationRateLimited(t *testing.T) {
	email := "alice@example.com"
	user, err := identity.NewUser(identity.CreateUser{
		Username: "alice", DisplayName: "Alice", Email: &email, Status: identity.UserActive,
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	recording := &recordingMailer{}
	handler, sessionToken, _, _ := newEmailVerificationHandler(t, user, recording, func(cfg *config.Config) {
		cfg.RateLimits.EmailVerification = ratelimit.Policy{Limit: 1, Window: time.Minute}
	})
	credentials := accountCSRF(t, handler, sessionToken)
	if response := issueVerificationRequest(handler, credentials); response.Code != http.StatusNoContent {
		t.Fatalf("first issue: %d %s", response.Code, response.Body.String())
	}
	response := issueVerificationRequest(handler, credentials)
	if response.Code != http.StatusTooManyRequests {
		t.Fatalf("rate-limited issue: %d %s", response.Code, response.Body.String())
	}
}

func TestAccountEmailVerifyRejectsCrossAccountToken(t *testing.T) {
	emailA := "alice@example.com"
	userA, err := identity.NewUser(identity.CreateUser{
		Username: "alice", DisplayName: "Alice", Email: &emailA, Status: identity.UserActive,
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	emailB := "bob@example.com"
	userB, err := identity.NewUser(identity.CreateUser{
		Username: "bob", DisplayName: "Bob", Email: &emailB, Status: identity.UserActive,
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	recording := &recordingMailer{}
	handler, sessionTokenA, users, _ := newEmailVerificationHandler(t, userA, recording, nil)
	handlerB, sessionTokenB, _, _ := newEmailVerificationHandler(t, userB, recording, nil)
	csrfA := accountCSRF(t, handler, sessionTokenA)
	csrfB := accountCSRF(t, handlerB, sessionTokenB)

	if response := issueVerificationRequest(handler, csrfA); response.Code != http.StatusNoContent {
		t.Fatalf("issue for alice: %d %s", response.Code, response.Body.String())
	}
	token := verificationTokenFromMessage(t, recording.messages)

	response := verifyRequest(handlerB, csrfB, token)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("cross-account verify: %d %s", response.Code, response.Body.String())
	}
	alice, err := users.Find(context.Background(), userA.ID)
	if err != nil || alice.EmailVerified {
		t.Fatalf("cross-account verify changed alice: %#v %v", alice, err)
	}

	response = verifyRequest(handler, csrfA, token)
	if response.Code != http.StatusNoContent {
		t.Fatalf("token was consumed by the wrong session: %d %s", response.Code, response.Body.String())
	}
}

func TestAccountEmailVerificationRejectsInvalidToken(t *testing.T) {
	email := "alice@example.com"
	user, err := identity.NewUser(identity.CreateUser{
		Username: "alice", DisplayName: "Alice", Email: &email, Status: identity.UserActive,
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	handler, sessionToken, _, _ := newEmailVerificationHandler(t, user, &recordingMailer{}, nil)
	credentials := accountCSRF(t, handler, sessionToken)
	response := verifyRequest(handler, credentials, "not-a-real-token")
	if response.Code != http.StatusBadRequest {
		t.Fatalf("invalid token: %d %s", response.Code, response.Body.String())
	}
}

func TestVerifyEmailPageRequiresSession(t *testing.T) {
	email := "alice@example.com"
	user, err := identity.NewUser(identity.CreateUser{
		Username: "alice", DisplayName: "Alice", Email: &email, Status: identity.UserActive,
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	handler, sessionToken, _, _ := newEmailVerificationHandler(t, user, &recordingMailer{}, nil)

	request := httptest.NewRequest(http.MethodGet, "/account/verify-email?token=abc", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusFound ||
		!strings.Contains(response.Header().Get("Location"), "/login?continue=") {
		t.Fatalf("unauthenticated verify page: %d %s", response.Code, response.Header().Get("Location"))
	}

	request = httptest.NewRequest(http.MethodGet, "/account/verify-email?token=abc", nil)
	request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sessionToken})
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK ||
		!strings.Contains(response.Body.String(), "邮箱验证") ||
		!strings.Contains(response.Body.String(), "/static/verify-email.js") {
		t.Fatalf("verify page: %d %s", response.Code, response.Body.String())
	}
}

func TestAdminMarksUserEmailVerified(t *testing.T) {
	email := "alice@example.com"
	user, err := identity.NewUser(identity.CreateUser{
		Username: "alice", DisplayName: "Alice", Email: &email, Status: identity.UserActive,
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	handler, _, users, audits := newEmailVerificationHandler(t, user, &recordingMailer{}, nil)
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/admin/users/"+user.ID+"/email-verification",
		nil,
	)
	request.Header.Set("Authorization", "Bearer test-admin-token")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("admin mark verified: %d %s", response.Code, response.Body.String())
	}
	verified, err := users.Find(context.Background(), user.ID)
	if err != nil || !verified.EmailVerified {
		t.Fatalf("admin mark did not verify email: %#v %v", verified, err)
	}
	found := false
	if events, err := audits.List(context.Background(), audit.Filter{Limit: 100}); err != nil {
		t.Fatalf("list audit events: %v", err)
	} else {
		for _, event := range events.Items {
			if event.EventType == "email.verified_by_admin" {
				found = true
			}
		}
	}
	if !found {
		t.Fatal("missing email.verified_by_admin audit event")
	}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusConflict {
		t.Fatalf("double admin mark: %d %s", response.Code, response.Body.String())
	}
}

func TestAdminMarkVerifiedRejectsUserWithoutEmail(t *testing.T) {
	user, err := identity.NewUser(identity.CreateUser{
		Username: "alice", DisplayName: "Alice", Status: identity.UserActive,
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	handler, _, _, _ := newEmailVerificationHandler(t, user, &recordingMailer{}, nil)
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/admin/users/"+user.ID+"/email-verification",
		nil,
	)
	request.Header.Set("Authorization", "Bearer test-admin-token")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("admin mark without email: %d %s", response.Code, response.Body.String())
	}
}
