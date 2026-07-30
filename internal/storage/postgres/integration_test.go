package postgres

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"certus/internal/access"
	"certus/internal/audit"
	"certus/internal/client"
	"certus/internal/identity"
	"certus/internal/mfa"
	"certus/internal/oauth"
	"certus/internal/oidc"
	"certus/internal/session"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestPostgresMigrationsAndRepositories(t *testing.T) {
	databaseURL := strings.TrimSpace(os.Getenv("CERTUS_TEST_DATABASE_URL"))
	if databaseURL == "" {
		t.Skip("CERTUS_TEST_DATABASE_URL is not configured")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	adminPool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer adminPool.Close()
	schema := fmt.Sprintf("certus_test_%d", time.Now().UnixNano())
	if !strings.HasPrefix(schema, "certus_test_") {
		t.Fatal("unsafe integration schema name")
	}
	identifier := pgx.Identifier{schema}.Sanitize()
	if _, err := adminPool.Exec(ctx, "CREATE SCHEMA "+identifier); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		_, _ = adminPool.Exec(cleanupCtx, "DROP SCHEMA "+identifier+" CASCADE")
	})

	poolConfig, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	poolConfig.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := Migrate(ctx, pool); err != nil {
		t.Fatal(err)
	}
	if err := Migrate(ctx, pool); err != nil {
		t.Fatalf("idempotent migration failed: %v", err)
	}

	registered, _, err := client.New(client.CreateClient{
		ID:                               "integration",
		Name:                             "Integration",
		ApplicationType:                  client.ApplicationPublic,
		Protocols:                        []client.Protocol{client.ProtocolOAuth21},
		GrantTypes:                       []client.GrantType{client.GrantAuthorizationCode},
		RedirectURIs:                     []string{"https://app.example.com/callback"},
		PostLogoutRedirectURIs:           []string{"https://app.example.com/logout/callback"},
		BackchannelLogoutURI:             "https://app.example.com/oidc/backchannel-logout",
		BackchannelLogoutSessionRequired: true,
		LoginMethods:                     []client.LoginMethod{client.LoginPassword},
		AllowedScopes:                    []string{"openid", "roles"},
	})
	if err != nil {
		t.Fatal(err)
	}
	clientRepository := NewClientRepository(pool)
	if _, err := clientRepository.Create(ctx, registered); err != nil {
		t.Fatal(err)
	}
	storedClient, err := clientRepository.Find(ctx, registered.ID)
	if err != nil || len(storedClient.PostLogoutRedirectURIs) != 1 ||
		storedClient.PostLogoutRedirectURIs[0] != "https://app.example.com/logout/callback" ||
		storedClient.BackchannelLogoutURI != "https://app.example.com/oidc/backchannel-logout" ||
		!storedClient.BackchannelLogoutSessionRequired {
		t.Fatalf("client logout redirect round trip failed: %#v %v", storedClient, err)
	}

	user, err := identity.NewUser(identity.CreateUser{
		Username: "alice", DisplayName: "Alice", Status: identity.UserActive,
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	users := NewUserRepository(pool)
	if _, err := users.Create(ctx, user); err != nil {
		t.Fatal(err)
	}
	passwords := identity.NewPasswordService(users)
	if err := passwords.Set(ctx, user.ID, "integration-password-123"); err != nil {
		t.Fatal(err)
	}
	if authenticated, err := passwords.Authenticate(ctx, user.Username, "integration-password-123"); err != nil || authenticated.ID != user.ID {
		t.Fatalf("password repository round trip failed: %#v %v", authenticated, err)
	}

	sessions := session.NewService(NewSessionRepository(pool), time.Hour)
	current, rawSession, err := sessions.CreateWithMethods(
		ctx, user.ID, "192.0.2.10", "integration-test", []string{"pwd", "otp"}, "urn:certus:aal:2",
	)
	if err != nil {
		t.Fatal(err)
	}
	found, err := sessions.Find(ctx, rawSession)
	if err != nil || found.ID != current.ID || found.AssuranceLevel != "urn:certus:aal:2" {
		t.Fatalf("session repository round trip failed: %#v %v", found, err)
	}
	oauthRepository := NewOAuthRepository(pool)
	if err := oauthRepository.SaveOIDCClientSession(ctx, oauth.OIDCClientSession{
		SessionID: current.ID,
		ClientID:  registered.ID,
		UserID:    user.ID,
		CreatedAt: time.Now(),
	}); err != nil {
		t.Fatal(err)
	}
	oidcSessions, err := oauthRepository.ListOIDCClientSessions(ctx, current.ID)
	if err != nil || len(oidcSessions) != 1 || oidcSessions[0].ClientID != registered.ID {
		t.Fatalf("OIDC client session round trip failed: %#v %v", oidcSessions, err)
	}
	if err := oauthRepository.DeleteOIDCClientSessions(ctx, current.ID); err != nil {
		t.Fatal(err)
	}

	accessRepository := NewAccessRepository(pool)
	role, err := access.NewRole(registered.ID, access.CreateRole{Code: "approver", Name: "Approver"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := accessRepository.CreateRole(ctx, role); err != nil {
		t.Fatal(err)
	}
	if err := accessRepository.ReplaceUserRoles(ctx, user.ID, []access.RoleGrant{{RoleID: role.ID}}, "integration-test", time.Now()); err != nil {
		t.Fatal(err)
	}
	entitlements, err := accessRepository.Effective(ctx, user.ID, registered.ID, time.Now())
	if err != nil || len(entitlements.Roles) != 1 || entitlements.Roles[0] != "approver" {
		t.Fatalf("access repository round trip failed: %#v %v", entitlements, err)
	}

	mfaRepository := NewMFARepository(pool)
	if err := mfaRepository.ReplacePending(ctx, mfa.Credential{
		UserID: user.ID, Secret: []byte("encrypted-secret"), CreatedAt: time.Now(),
	}, [][]byte{[]byte("recovery-hash")}); err != nil {
		t.Fatal(err)
	}
	if credential, err := mfaRepository.Find(ctx, user.ID); err != nil || credential.RecoveryCodes != 1 {
		t.Fatalf("MFA repository round trip failed: %#v %v", credential, err)
	}

	keys := NewOIDCKeyRepository(pool)
	signer, err := oidc.NewSigner(ctx, keys)
	if err != nil {
		t.Fatal(err)
	}
	oldToken, err := signer.Sign(map[string]any{"sub": user.ID})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signer.Rotate(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := signer.Verify(oldToken); err != nil {
		t.Fatalf("retired PostgreSQL key did not verify old token: %v", err)
	}

	audits := NewAuditRepository(pool)
	oldEvent, err := audit.Normalize(audit.Event{
		EventType: "integration.expired", Outcome: audit.OutcomeSuccess,
	}, time.Now().Add(-100*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := audits.Append(ctx, oldEvent); err != nil {
		t.Fatal(err)
	}
	deleted, err := NewMaintenanceRepository(pool).Cleanup(
		ctx, time.Now(), time.Now().Add(-90*24*time.Hour), time.Now().Add(-time.Hour),
	)
	if err != nil {
		t.Fatal(err)
	}
	if deleted["audit_events"] != 1 {
		t.Fatalf("maintenance did not remove expired audit event: %#v", deleted)
	}
}
