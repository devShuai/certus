package httpserver

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"certus/internal/cas"
	"certus/internal/client"
	"certus/internal/config"
	"certus/internal/identity"
	"certus/internal/mailer"
	"certus/internal/oauth"
	"certus/internal/oidc"
	"certus/internal/session"
)

func TestAdminSendsSMTPTestEmail(t *testing.T) {
	recording := &recordingMailer{}
	handler := newEmailTestHandler(t, recording)
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/admin/email/test",
		bytes.NewBufferString(`{"to":"alice@example.com"}`),
	)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer test-admin-token")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("unexpected SMTP test response: %d %s", response.Code, response.Body.String())
	}
	if len(recording.messages) != 1 ||
		recording.messages[0].To != "alice@example.com" ||
		recording.messages[0].Subject != "Certus SMTP 配置测试" {
		t.Fatalf("unexpected SMTP test message: %#v", recording.messages)
	}
}

func TestAdminSMTPTestRejectsInvalidRecipient(t *testing.T) {
	recording := &recordingMailer{}
	handler := newEmailTestHandler(t, recording)
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/admin/email/test",
		bytes.NewBufferString(`{"to":"alice@example.com\r\nBcc:attacker@example.com"}`),
	)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer test-admin-token")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest || len(recording.messages) != 0 {
		t.Fatalf("invalid recipient returned %d with messages %#v", response.Code, recording.messages)
	}
}

func TestAdminSMTPTestReportsTransportFailure(t *testing.T) {
	recording := &recordingMailer{err: errors.New("SMTP unavailable")}
	handler := newEmailTestHandler(t, recording)
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/admin/email/test",
		bytes.NewBufferString(`{"to":"alice@example.com"}`),
	)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer test-admin-token")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusBadGateway {
		t.Fatalf("SMTP failure returned %d %s", response.Code, response.Body.String())
	}
}

func TestAdminSMTPTestRequiresConfiguration(t *testing.T) {
	handler := New(
		config.Config{
			Issuer:     "https://auth.example.com",
			AdminToken: "test-admin-token",
		},
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	request := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/admin/email/test",
		bytes.NewBufferString(`{"to":"alice@example.com"}`),
	)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer test-admin-token")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("unconfigured SMTP returned %d %s", response.Code, response.Body.String())
	}
}

type recordingMailer struct {
	messages []mailer.Message
	err      error
}

func (m *recordingMailer) Send(_ context.Context, message mailer.Message) error {
	if m.err != nil {
		return m.err
	}
	m.messages = append(m.messages, message)
	return nil
}

func newEmailTestHandler(t *testing.T, sender mailer.Sender) http.Handler {
	t.Helper()
	users := identity.NewMemoryUserRepository()
	handler, err := NewWithDependencies(
		context.Background(),
		config.Config{
			Issuer:     "https://auth.example.com",
			AdminToken: "test-admin-token",
		},
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		Dependencies{
			Clients:   client.NewMemoryRepository(),
			Users:     users,
			Passwords: users,
			Sessions:  session.NewMemoryRepository(),
			OAuth:     oauth.NewMemoryRepository(),
			CAS:       cas.NewMemoryRepository(),
			Keys:      &oidc.MemoryKeyRepository{},
			Mailer:    sender,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return handler
}
