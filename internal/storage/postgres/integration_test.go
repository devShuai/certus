package postgres

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"certus/internal/access"
	"certus/internal/administration"
	"certus/internal/audit"
	"certus/internal/client"
	"certus/internal/federation"
	"certus/internal/identity"
	"certus/internal/mfa"
	"certus/internal/oauth"
	"certus/internal/oidc"
	"certus/internal/ratelimit"
	"certus/internal/secrets"
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
		ApplicationType:                  client.ApplicationConfidential,
		TokenEndpointAuthMethod:          client.TokenEndpointAuthSecretPost,
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
		!storedClient.BackchannelLogoutSessionRequired ||
		storedClient.TokenEndpointAuthMethod != client.TokenEndpointAuthSecretPost {
		t.Fatalf("client logout redirect round trip failed: %#v %v", storedClient, err)
	}

	sourceKeyRing, err := secrets.ParseKeyRing(
		"source-test=" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{13}, 32)),
	)
	if err != nil {
		t.Fatal(err)
	}
	sourceRepository := NewSourceRepository(pool)
	sourceService := federation.NewSourceService(sourceRepository, sourceKeyRing)
	createdSource, err := sourceService.Create(ctx, federation.CreateSource{
		ID:   "workforce",
		Name: "Workforce SSO",
		Type: federation.SourceOIDC,
		OIDC: &federation.OIDCSourceInput{
			Issuer:       "https://id.example.com",
			ClientID:     "certus",
			ClientSecret: "upstream-secret",
			Scopes:       []string{"openid", "profile", "email"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	storedSource, err := sourceRepository.Find(ctx, createdSource.ID)
	if err != nil || !storedSource.SecretConfigured ||
		storedSource.SecretKeyID != "source-test" ||
		storedSource.OIDC == nil ||
		storedSource.OIDC.ClientID != "certus" {
		t.Fatalf("identity source round trip failed: %#v %v", storedSource, err)
	}
	sourceAuthenticator, err := sourceService.OIDCAuthenticator(
		ctx,
		storedSource.ID,
		"https://auth.example.com/login/oidc/callback",
		nil,
	)
	if err != nil {
		t.Fatalf("build stored OIDC source authenticator: %v", err)
	}
	if sourceAuthenticator.Label() != "Workforce SSO" {
		t.Fatalf("unexpected stored OIDC source label: %q", sourceAuthenticator.Label())
	}
	registered.LoginMethods = []client.LoginMethod{client.LoginOIDC}
	registered.IdentitySourceIDs = []string{createdSource.ID}
	if _, err := clientRepository.Replace(ctx, registered); err != nil {
		t.Fatalf("bind client identity source: %v", err)
	}
	storedClient, err = clientRepository.Find(ctx, registered.ID)
	if err != nil || len(storedClient.IdentitySourceIDs) != 1 ||
		storedClient.IdentitySourceIDs[0] != createdSource.ID {
		t.Fatalf("client identity source round trip failed: %#v %v", storedClient, err)
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
	if active, err := sessions.IsActive(ctx, user.ID, current.ID); err != nil || !active {
		t.Fatalf("PostgreSQL session active check failed: %v %v", active, err)
	}
	administrators := NewAdministrationRepository(pool)
	if err := administrators.ReplaceUserRoles(
		ctx,
		user.ID,
		[]administration.Role{administration.RoleSuperAdmin},
		"emergency_token",
		time.Now(),
	); err != nil {
		t.Fatal(err)
	}
	administratorAccess, err := administrators.Effective(ctx, user.ID)
	if err != nil || !administratorAccess.Has(administration.PermissionAdminRolesWrite) {
		t.Fatalf("PostgreSQL administrator role was not effective: %#v %v", administratorAccess, err)
	}
	superAdministrators, err := administrators.ListRoleUsers(ctx, administration.RoleSuperAdmin)
	if err != nil || len(superAdministrators) != 1 || superAdministrators[0] != user.ID {
		t.Fatalf("PostgreSQL super administrator listing failed: %#v %v", superAdministrators, err)
	}
	if err := administrators.ReplaceUserRoles(
		ctx,
		user.ID,
		nil,
		user.ID,
		time.Now(),
	); !errors.Is(err, administration.ErrLastSuperAdmin) {
		t.Fatalf("PostgreSQL last super administrator was removable: %v", err)
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
	granted, err := oauthRepository.GrantConsent(
		ctx, user.ID, registered.ID, []string{"openid"}, time.Now().UTC(),
	)
	if err != nil || !granted.Covers([]string{"openid"}) {
		t.Fatalf("grant OAuth consent failed: %#v %v", granted, err)
	}
	granted, err = oauthRepository.GrantConsent(
		ctx, user.ID, registered.ID, []string{"roles"}, time.Now().UTC(),
	)
	if err != nil || !granted.Covers([]string{"openid", "roles"}) {
		t.Fatalf("expand OAuth consent failed: %#v %v", granted, err)
	}
	consents, err := oauthRepository.ListConsentsByUser(ctx, user.ID)
	if err != nil || len(consents) != 1 {
		t.Fatalf("list OAuth consents failed: %#v %v", consents, err)
	}
	tokenTime := time.Now().UTC()
	sessionAccess := oauth.AccessToken{
		Hash: []byte("postgres-session-access"), ClientID: registered.ID, UserID: user.ID,
		SessionID: current.ID, Scope: []string{"openid"}, IssuedAt: tokenTime, ExpiresAt: tokenTime.Add(time.Hour),
	}
	otherAccess := oauth.AccessToken{
		Hash: []byte("postgres-other-access"), ClientID: registered.ID, UserID: user.ID,
		Scope: []string{"openid"}, IssuedAt: tokenTime, ExpiresAt: tokenTime.Add(time.Hour),
	}
	sessionRefresh := oauth.RefreshToken{
		Hash: []byte("postgres-session-refresh"), FamilyID: "f5597c29-e356-4ce9-9ebd-bd7fdd424bc4",
		ClientID: registered.ID, UserID: user.ID, SessionID: current.ID,
		Scope: []string{"openid"}, IssuedAt: tokenTime, ExpiresAt: tokenTime.Add(time.Hour),
	}
	for _, token := range []oauth.AccessToken{sessionAccess, otherAccess} {
		if err := oauthRepository.SaveAccessToken(ctx, token); err != nil {
			t.Fatal(err)
		}
	}
	if err := oauthRepository.SaveRefreshToken(ctx, sessionRefresh); err != nil {
		t.Fatal(err)
	}
	if err := oauthRepository.RevokeSessionTokens(ctx, user.ID, current.ID, tokenTime); err != nil {
		t.Fatal(err)
	}
	if _, err := oauthRepository.FindAccessToken(ctx, sessionAccess.Hash, tokenTime); !errors.Is(err, oauth.ErrGrantNotFound) {
		t.Fatalf("PostgreSQL session access token remained active: %v", err)
	}
	if _, err := oauthRepository.FindRefreshToken(ctx, sessionRefresh.Hash, tokenTime); !errors.Is(err, oauth.ErrGrantNotFound) {
		t.Fatalf("PostgreSQL session refresh token remained active: %v", err)
	}
	if _, err := oauthRepository.FindAccessToken(ctx, otherAccess.Hash, tokenTime); err != nil {
		t.Fatalf("PostgreSQL session revocation affected unrelated token: %v", err)
	}
	if err := oauthRepository.DeleteConsent(ctx, user.ID, registered.ID, tokenTime); err != nil {
		t.Fatal(err)
	}
	if _, err := oauthRepository.FindAccessToken(ctx, otherAccess.Hash, tokenTime); !errors.Is(err, oauth.ErrGrantNotFound) {
		t.Fatalf("PostgreSQL consent access token remained active: %v", err)
	}
	machineAccess := oauth.AccessToken{
		Hash: []byte("postgres-machine-access"), ClientID: registered.ID, Scope: []string{"api.read"},
		IssuedAt: tokenTime, ExpiresAt: tokenTime.Add(time.Hour),
	}
	if err := oauthRepository.SaveAccessToken(ctx, machineAccess); err != nil {
		t.Fatal(err)
	}
	if err := oauthRepository.RevokeClientTokens(ctx, registered.ID, tokenTime); err != nil {
		t.Fatal(err)
	}
	if _, err := oauthRepository.FindAccessToken(ctx, machineAccess.Hash, tokenTime); !errors.Is(err, oauth.ErrGrantNotFound) {
		t.Fatalf("PostgreSQL client access token remained active: %v", err)
	}

	accessRepository := NewAccessRepository(pool)
	role, err := access.NewRole(registered.ID, access.CreateRole{Code: "approver", Name: "Approver"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := accessRepository.CreateRole(ctx, role); err != nil {
		t.Fatal(err)
	}
	permission, err := access.NewPermission(registered.ID, access.CreatePermission{Code: "invoice.approve", Name: "Approve invoice"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := accessRepository.CreatePermission(ctx, permission); err != nil {
		t.Fatal(err)
	}
	updatedRole, err := role.Updated(access.UpdateRole{Code: "senior-approver", Name: "Senior approver"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if updatedRole, err = accessRepository.ReplaceRole(ctx, updatedRole); err != nil {
		t.Fatal(err)
	}
	if found, err := accessRepository.FindRole(ctx, registered.ID, role.ID); err != nil || found.Code != "senior-approver" {
		t.Fatalf("find updated PostgreSQL role: %#v %v", found, err)
	}
	updatedPermission, err := permission.Updated(access.UpdatePermission{Code: "invoice.approve.high-value", Name: "Approve high-value invoice"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if updatedPermission, err = accessRepository.ReplacePermission(ctx, updatedPermission); err != nil {
		t.Fatal(err)
	}
	if found, err := accessRepository.FindPermission(ctx, registered.ID, permission.ID); err != nil || found.Code != "invoice.approve.high-value" {
		t.Fatalf("find updated PostgreSQL permission: %#v %v", found, err)
	}
	if err := accessRepository.SetRolePermissions(ctx, registered.ID, role.ID, []string{permission.ID}); err != nil {
		t.Fatal(err)
	}
	if err := accessRepository.DeletePermission(ctx, registered.ID, permission.ID); !errors.Is(err, access.ErrInUse) {
		t.Fatalf("delete referenced PostgreSQL permission: %v", err)
	}
	if err := accessRepository.ReplaceUserRoles(ctx, user.ID, []access.RoleGrant{{RoleID: role.ID}}, "integration-test", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := accessRepository.DeleteRole(ctx, registered.ID, role.ID); !errors.Is(err, access.ErrInUse) {
		t.Fatalf("delete assigned PostgreSQL role: %v", err)
	}
	entitlements, err := accessRepository.Effective(ctx, user.ID, registered.ID, time.Now())
	if err != nil ||
		len(entitlements.Roles) != 1 || entitlements.Roles[0] != "senior-approver" ||
		len(entitlements.Permissions) != 1 || entitlements.Permissions[0] != "invoice.approve.high-value" {
		t.Fatalf("access repository round trip failed: %#v %v", entitlements, err)
	}
	if err := accessRepository.ReplaceUserRoles(ctx, user.ID, nil, "integration-test", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := accessRepository.SetRolePermissions(ctx, registered.ID, role.ID, nil); err != nil {
		t.Fatal(err)
	}
	if err := accessRepository.DeletePermission(ctx, registered.ID, permission.ID); err != nil {
		t.Fatal(err)
	}
	if err := accessRepository.DeleteRole(ctx, registered.ID, role.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := accessRepository.FindRole(ctx, registered.ID, role.ID); !errors.Is(err, access.ErrNotFound) {
		t.Fatalf("find deleted PostgreSQL role: %v", err)
	}

	mfaRepository := NewMFARepository(pool)
	legacyMFAKey := []byte("legacy-mfa-key-material-32-bytes")
	legacyMFAService := mfa.NewService(mfaRepository, legacyMFAKey, "Certus")
	if _, err := legacyMFAService.Setup(ctx, user.ID, user.Username); err != nil {
		t.Fatal(err)
	}
	if credential, err := mfaRepository.Find(ctx, user.ID); err != nil || credential.RecoveryCodes != 10 {
		t.Fatalf("MFA repository round trip failed: %#v %v", credential, err)
	}
	mfaPrimaryKey := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	mfaKeyRing, err := secrets.ParseKeyRing("primary=" + mfaPrimaryKey)
	if err != nil {
		t.Fatal(err)
	}
	if count, err := mfa.RewrapSecrets(ctx, mfaRepository, mfaKeyRing, legacyMFAKey); err != nil || count != 1 {
		t.Fatalf("PostgreSQL MFA secret rewrap failed: %d %v", count, err)
	}
	rewrappedMFA, err := mfaRepository.Find(ctx, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if keyID, ok := secrets.EnvelopeKeyID(rewrappedMFA.Secret); !ok || keyID != "primary" {
		t.Fatalf("unexpected PostgreSQL MFA envelope key: %q %v", keyID, ok)
	}
	if count, err := mfa.RewrapSecrets(ctx, mfaRepository, mfaKeyRing, nil); err != nil || count != 0 {
		t.Fatalf("PostgreSQL MFA rewrap was not idempotent: %d %v", count, err)
	}
	if err := mfaRepository.Enable(ctx, user.ID, 0, time.Now()); err != nil {
		t.Fatal(err)
	}
	regeneratedHashes := [][]byte{[]byte("regenerated-code-1"), []byte("regenerated-code-2")}
	if err := mfaRepository.ReplaceRecoveryCodes(ctx, user.ID, regeneratedHashes, time.Now()); err != nil {
		t.Fatal(err)
	}
	if credential, err := mfaRepository.Find(ctx, user.ID); err != nil || credential.RecoveryCodes != 2 {
		t.Fatalf("PostgreSQL recovery code replacement failed: %#v %v", credential, err)
	}
	if err := mfaRepository.UseRecoveryCode(ctx, user.ID, regeneratedHashes[0], time.Now()); err != nil {
		t.Fatal(err)
	}
	if credential, err := mfaRepository.Find(ctx, user.ID); err != nil || credential.RecoveryCodes != 1 {
		t.Fatalf("PostgreSQL regenerated recovery code consumption failed: %#v %v", credential, err)
	}
	limiter := ratelimit.NewService(NewRateLimitRepository(pool))
	rateNow := time.Now().UTC().Add(-2 * time.Minute)
	for index, expected := range []bool{true, true, false} {
		decision, err := limiter.Allow(
			ctx,
			"login.source",
			"192.0.2.10",
			ratelimit.Policy{Limit: 2, Window: time.Minute},
			rateNow,
		)
		if err != nil || decision.Allowed != expected {
			t.Fatalf("PostgreSQL rate-limit attempt %d: %#v %v", index+1, decision, err)
		}
	}
	var allowed atomic.Int64
	var attempts sync.WaitGroup
	for range 20 {
		attempts.Add(1)
		go func() {
			defer attempts.Done()
			decision, err := limiter.Allow(
				ctx,
				"oauth.source",
				"192.0.2.11",
				ratelimit.Policy{Limit: 10, Window: time.Minute},
				rateNow,
			)
			if err != nil {
				t.Errorf("concurrent PostgreSQL rate limit: %v", err)
				return
			}
			if decision.Allowed {
				allowed.Add(1)
			}
		}()
	}
	attempts.Wait()
	if allowed.Load() != 10 {
		t.Fatalf("unexpected concurrent PostgreSQL allowance count: %d", allowed.Load())
	}

	legacyKeys := NewOIDCKeyRepository(pool)
	legacySigner, err := oidc.NewSigner(ctx, legacyKeys)
	if err != nil {
		t.Fatal(err)
	}
	oldToken, err := legacySigner.Sign(map[string]any{"sub": user.ID})
	if err != nil {
		t.Fatal(err)
	}
	primaryKey := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	keyRing, err := secrets.ParseKeyRing("primary=" + primaryKey)
	if err != nil {
		t.Fatal(err)
	}
	keys := NewEncryptedOIDCKeyRepository(pool, keyRing)
	if rewrapped, err := keys.RewrapSigningKeys(ctx); err != nil || rewrapped != 1 {
		t.Fatalf("legacy signing key was not encrypted: %d %v", rewrapped, err)
	}
	signer, err := oidc.NewSigner(ctx, keys)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signer.Verify(oldToken); err != nil {
		t.Fatalf("encrypted PostgreSQL key did not verify existing token: %v", err)
	}
	if _, err := signer.Rotate(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := signer.Verify(oldToken); err != nil {
		t.Fatalf("retired PostgreSQL key did not verify old token: %v", err)
	}
	rows, err := pool.Query(ctx, `
		SELECT private_key_pem, encryption_key_id
		FROM oidc_signing_keys
		ORDER BY kid`)
	if err != nil {
		t.Fatal(err)
	}
	var encryptedCount int
	for rows.Next() {
		var material []byte
		var keyID string
		if err := rows.Scan(&material, &keyID); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		if bytes.Contains(material, []byte("PRIVATE KEY")) || keyID != "primary" {
			rows.Close()
			t.Fatalf("OIDC signing key was stored in plaintext or with wrong key: %q %s", material, keyID)
		}
		encryptedCount++
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		t.Fatal(err)
	}
	rows.Close()
	if encryptedCount != 2 {
		t.Fatalf("unexpected encrypted signing key count: %d", encryptedCount)
	}
	nextKey := base64.StdEncoding.EncodeToString([]byte("abcdef0123456789abcdef0123456789"))
	rotatedRing, err := secrets.ParseKeyRing("next=" + nextKey + ",primary=" + primaryKey)
	if err != nil {
		t.Fatal(err)
	}
	rotatedKeys := NewEncryptedOIDCKeyRepository(pool, rotatedRing)
	if rewrapped, err := rotatedKeys.RewrapSigningKeys(ctx); err != nil || rewrapped != 2 {
		t.Fatalf("signing keys were not rewrapped with the new primary: %d %v", rewrapped, err)
	}
	var oldEncryptionKeys int
	if err := pool.QueryRow(ctx, `
		SELECT count(*)
		FROM oidc_signing_keys
		WHERE encryption_key_id <> 'next'`,
	).Scan(&oldEncryptionKeys); err != nil || oldEncryptionKeys != 0 {
		t.Fatalf("old signing-key encryption identifiers remain: %d %v", oldEncryptionKeys, err)
	}
	if rotatedSigner, err := oidc.NewSigner(ctx, rotatedKeys); err != nil {
		t.Fatal(err)
	} else if _, err := rotatedSigner.Verify(oldToken); err != nil {
		t.Fatalf("rewrapped PostgreSQL key did not verify old token: %v", err)
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
	if deleted["rate_limit_buckets"] != 2 {
		t.Fatalf("maintenance did not remove expired rate-limit bucket: %#v", deleted)
	}
}
