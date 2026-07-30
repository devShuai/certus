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

type staleKeyRepository struct {
	*oidc.MemoryKeyRepository
}

func (r *staleKeyRepository) ListSigningKeys(ctx context.Context) ([]oidc.SigningKey, error) {
	keys, err := r.MemoryKeyRepository.ListSigningKeys(ctx)
	for index := range keys {
		if keys[index].Active {
			keys[index].CreatedAt = time.Time{}
		}
	}
	return keys, err
}

func (r *staleKeyRepository) RotateSigningKeyIfOlderThan(
	ctx context.Context,
	kid string,
	value []byte,
	now time.Time,
	_ time.Time,
) (bool, error) {
	return true, r.MemoryKeyRepository.RotateSigningKey(ctx, kid, value, now)
}

func TestAutomaticSigningKeyRotation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	users := identity.NewMemoryUserRepository()
	keys := &staleKeyRepository{MemoryKeyRepository: &oidc.MemoryKeyRepository{}}
	audits := audit.NewMemoryRepository()
	if _, err := NewWithDependencies(ctx, config.Config{
		Issuer: "https://auth.example.com", SigningKeyRotation: time.Hour,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)), Dependencies{
		Clients:   client.NewMemoryRepository(),
		Users:     users,
		Passwords: users,
		Sessions:  session.NewMemoryRepository(),
		OAuth:     oauth.NewMemoryRepository(),
		CAS:       cas.NewMemoryRepository(),
		Audit:     audits,
		Keys:      keys,
	}); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		stored, err := keys.ListSigningKeys(ctx)
		if err != nil {
			t.Fatal(err)
		}
		page, auditErr := audits.List(ctx, audit.Filter{
			EventType: "oidc.signing_key_rotated",
			Limit:     10,
		})
		if auditErr != nil {
			t.Fatal(auditErr)
		}
		if len(stored) == 2 && page.Total == 1 {
			if page.Items[0].Details["automatic"] != true {
				t.Fatalf("automatic rotation audit was not recorded: %#v", page)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("automatic rotation did not complete: %#v", stored)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestSigningKeyRotationAndManualMaintenance(t *testing.T) {
	ctx := context.Background()
	users := identity.NewMemoryUserRepository()
	keys := &oidc.MemoryKeyRepository{}
	adminToken := strings.Repeat("a", 32)
	handler, err := NewWithDependencies(ctx, config.Config{
		Issuer: "https://auth.example.com", AdminToken: adminToken,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)), Dependencies{
		Clients:   client.NewMemoryRepository(),
		Users:     users,
		Passwords: users,
		Sessions:  session.NewMemoryRepository(),
		OAuth:     oauth.NewMemoryRepository(),
		CAS:       cas.NewMemoryRepository(),
		Keys:      keys,
	})
	if err != nil {
		t.Fatal(err)
	}

	before := httptest.NewRecorder()
	handler.ServeHTTP(before, httptest.NewRequest(http.MethodGet, "/oauth2/jwks", nil))
	oldKID := firstJWKID(t, before)

	request := httptest.NewRequest(http.MethodPost, "/api/v1/admin/signing-keys/rotate", nil)
	request.Header.Set("Authorization", "Bearer "+adminToken)
	rotated := httptest.NewRecorder()
	handler.ServeHTTP(rotated, request)
	if rotated.Code != http.StatusCreated || !strings.Contains(rotated.Body.String(), `"active":true`) {
		t.Fatalf("rotate signing key: %d %s", rotated.Code, rotated.Body.String())
	}

	after := httptest.NewRecorder()
	handler.ServeHTTP(after, httptest.NewRequest(http.MethodGet, "/oauth2/jwks", nil))
	var jwks struct {
		Keys []map[string]string `json:"keys"`
	}
	if err := json.Unmarshal(after.Body.Bytes(), &jwks); err != nil {
		t.Fatal(err)
	}
	if len(jwks.Keys) != 2 || jwks.Keys[0]["kid"] == oldKID {
		t.Fatalf("JWKS did not retain old key and activate new key: %#v", jwks.Keys)
	}

	request = httptest.NewRequest(http.MethodPost, "/api/v1/admin/maintenance/cleanup", nil)
	request.Header.Set("Authorization", "Bearer "+adminToken)
	cleanup := httptest.NewRecorder()
	handler.ServeHTTP(cleanup, request)
	if cleanup.Code != http.StatusOK || !strings.Contains(cleanup.Body.String(), `"oidc_signing_keys":0`) {
		t.Fatalf("manual maintenance: %d %s", cleanup.Code, cleanup.Body.String())
	}
}

func firstJWKID(t *testing.T, response *httptest.ResponseRecorder) string {
	t.Helper()
	var jwks struct {
		Keys []map[string]string `json:"keys"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &jwks); err != nil {
		t.Fatal(err)
	}
	if len(jwks.Keys) != 1 || jwks.Keys[0]["kid"] == "" {
		t.Fatalf("unexpected JWKS: %#v", jwks.Keys)
	}
	return jwks.Keys[0]["kid"]
}
