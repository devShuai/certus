package postgres

import (
	"io/fs"
	"strings"
	"testing"
)

func TestEmbeddedMigrations(t *testing.T) {
	entries, err := fs.Glob(migrationFiles, "migrations/*.sql")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("no embedded migrations")
	}
	content, err := migrationFiles.ReadFile(entries[0])
	if err != nil {
		t.Fatal(err)
	}
	requiredTables := []string{
		"oauth_clients",
		"users",
		"sessions",
		"oauth_authorization_codes",
		"oauth_refresh_tokens",
		"audit_events",
	}
	for _, table := range requiredTables {
		if !strings.Contains(string(content), "CREATE TABLE "+table) {
			t.Errorf("migration does not create %s", table)
		}
	}
	if strings.Contains(string(content), "CREATE EXTENSION") {
		t.Fatal("base migration must not require database extension installation privileges")
	}
}

func TestProtocolExecutionMigration(t *testing.T) {
	content, err := migrationFiles.ReadFile("migrations/005_protocol_execution.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{
		"oauth_access_tokens",
		"oauth_device_authorizations",
		"cas_service_tickets",
		"cas_service_sessions",
		"oidc_signing_keys",
	} {
		if !strings.Contains(string(content), "CREATE TABLE "+table) {
			t.Errorf("protocol migration does not create %s", table)
		}
	}
	if strings.Contains(string(content), "CREATE EXTENSION") {
		t.Fatal("protocol migration must not require extension installation privileges")
	}
}

func TestCASProxyMigration(t *testing.T) {
	content, err := migrationFiles.ReadFile("migrations/006_cas_proxy.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{
		"cas_proxy_granting_tickets",
		"cas_proxy_tickets",
	} {
		if !strings.Contains(string(content), "CREATE TABLE "+table) {
			t.Errorf("CAS proxy migration does not create %s", table)
		}
	}
}

func TestTokenRevocationMigration(t *testing.T) {
	content, err := migrationFiles.ReadFile("migrations/007_token_revocation.sql")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "ADD COLUMN refresh_family_id") {
		t.Fatal("token revocation migration does not link access tokens to refresh families")
	}
}

func TestClientLifecycleMigration(t *testing.T) {
	content, err := migrationFiles.ReadFile("migrations/008_client_lifecycle.sql")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "ADD COLUMN archived_at") {
		t.Fatal("client lifecycle migration does not add soft archive state")
	}
}

func TestAccessControlMigration(t *testing.T) {
	content, err := migrationFiles.ReadFile("migrations/009_access_control.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{
		"access_roles",
		"access_permissions",
		"access_role_permissions",
		"access_user_roles",
	} {
		if !strings.Contains(string(content), "CREATE TABLE "+table) {
			t.Errorf("access control migration does not create %s", table)
		}
	}
}

func TestPasswordResetMigration(t *testing.T) {
	content, err := migrationFiles.ReadFile("migrations/010_password_resets.sql")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "CREATE TABLE password_reset_tokens") ||
		!strings.Contains(string(content), "consumed_at") {
		t.Fatal("password reset migration does not create one-time reset tokens")
	}
}

func TestTOTPMFAMigration(t *testing.T) {
	content, err := migrationFiles.ReadFile("migrations/011_totp_mfa.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"mfa_totp_credentials", "mfa_recovery_codes"} {
		if !strings.Contains(string(content), "CREATE TABLE "+table) {
			t.Errorf("TOTP MFA migration does not create %s", table)
		}
	}
	if !strings.Contains(string(content), "last_used_step") {
		t.Fatal("TOTP MFA migration does not store replay protection state")
	}
}

func TestAuthenticationContextMigration(t *testing.T) {
	content, err := migrationFiles.ReadFile("migrations/012_authentication_context.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, column := range []string{"authentication_methods", "assurance_level"} {
		if !strings.Contains(string(content), column) {
			t.Errorf("authentication context migration does not add %s", column)
		}
	}
}

func TestOIDCLogoutMigration(t *testing.T) {
	content, err := migrationFiles.ReadFile("migrations/013_oidc_logout.sql")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "CREATE TABLE oauth_client_post_logout_redirect_uris") {
		t.Fatal("OIDC logout migration does not create the post-logout redirect registry")
	}
}

func TestOIDCBackchannelLogoutMigration(t *testing.T) {
	content, err := migrationFiles.ReadFile("migrations/014_oidc_backchannel_logout.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{
		"ADD COLUMN backchannel_logout_uri",
		"CREATE TABLE oidc_client_sessions",
	} {
		if !strings.Contains(string(content), expected) {
			t.Fatalf("OIDC back-channel logout migration does not contain %s", expected)
		}
	}
}

func TestOAuthConsentMigration(t *testing.T) {
	content, err := migrationFiles.ReadFile("migrations/015_oauth_consents.sql")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "CREATE TABLE oauth_consents") {
		t.Fatal("OAuth consent migration does not create the consent registry")
	}
}
