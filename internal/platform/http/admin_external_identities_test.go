package httpserver

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
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

func TestAdminManagesUserExternalIdentitiesAndRevokesSessions(t *testing.T) {
	ctx := context.Background()
	users := identity.NewMemoryUserRepository()
	user, err := users.ResolveExternalIdentity(ctx, identity.ExternalProfile{
		ProviderID:  "identity-source:workforce",
		Subject:     "external-alice",
		Username:    "alice",
		DisplayName: "Alice",
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	externalIdentities, err := users.ListExternalIdentities(ctx, user.ID)
	if err != nil || len(externalIdentities) != 1 {
		t.Fatalf("prepare external identity: %#v %v", externalIdentities, err)
	}

	sessionRepository := session.NewMemoryRepository()
	sessionService := session.NewService(sessionRepository, time.Hour)
	_, sessionToken, err := sessionService.Create(ctx, user.ID, "192.0.2.10", "test")
	if err != nil {
		t.Fatal(err)
	}
	audits := audit.NewMemoryRepository()
	handler, err := NewWithDependencies(
		ctx,
		config.Config{
			Issuer:     "https://auth.example.com",
			AdminToken: "test-admin-token",
		},
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		Dependencies{
			Clients:   client.NewMemoryRepository(),
			Users:     users,
			Passwords: users,
			Sessions:  sessionRepository,
			OAuth:     oauth.NewMemoryRepository(),
			CAS:       cas.NewMemoryRepository(),
			Keys:      &oidc.MemoryKeyRepository{},
			Audit:     audits,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	listed := adminJSONRequest(
		t,
		handler,
		http.MethodGet,
		"/api/v1/admin/users/"+user.ID+"/external-identities",
		"",
	)
	if listed.Code != http.StatusOK ||
		!strings.Contains(listed.Body.String(), `"provider_id":"identity-source:workforce"`) ||
		!strings.Contains(listed.Body.String(), `"subject":"external-alice"`) {
		t.Fatalf("list external identities: %d %s", listed.Code, listed.Body.String())
	}

	target := "/api/v1/admin/users/" + user.ID + "/external-identities/" + externalIdentities[0].ID
	protected := adminJSONRequest(t, handler, http.MethodDelete, target, "")
	if protected.Code != http.StatusConflict ||
		!strings.Contains(protected.Body.String(), `"code":"last_authentication_method"`) {
		t.Fatalf("delete last authentication method: %d %s", protected.Code, protected.Body.String())
	}
	if _, err := sessionService.Find(ctx, sessionToken); err != nil {
		t.Fatalf("protected deletion revoked session: %v", err)
	}

	if err := users.SetPassword(ctx, user.ID, "stored-hash", time.Now()); err != nil {
		t.Fatal(err)
	}
	deleted := adminJSONRequest(t, handler, http.MethodDelete, target, "")
	if deleted.Code != http.StatusNoContent {
		t.Fatalf("delete external identity: %d %s", deleted.Code, deleted.Body.String())
	}
	if _, err := sessionService.Find(ctx, sessionToken); !errors.Is(err, session.ErrNotFound) {
		t.Fatalf("external identity deletion did not revoke session: %v", err)
	}
	remaining, err := users.ListExternalIdentities(ctx, user.ID)
	if err != nil || len(remaining) != 0 {
		t.Fatalf("external identity was not deleted: %#v %v", remaining, err)
	}
	page, err := audits.List(ctx, audit.Filter{
		EventType: "external_identity.deleted_by_admin",
		Limit:     20,
	})
	if err != nil || page.Total != 1 {
		t.Fatalf("external identity deletion was not audited: %#v %v", page, err)
	}
}
