package postgres

import (
	"strings"
	"testing"
)

func TestOptionalCASVersionMigration(t *testing.T) {
	content, err := migrationFiles.ReadFile("migrations/016_optional_cas_version.sql")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(content), "cas_version IN ('', '1.0', '2.0', '3.0')") {
		t.Fatal("optional CAS version migration does not allow OAuth-only clients")
	}
}

func TestOAuthClientAuthenticationMethodMigration(t *testing.T) {
	content, err := migrationFiles.ReadFile("migrations/021_oauth_client_auth_method.sql")
	if err != nil {
		t.Fatal(err)
	}
	statement := string(content)
	for _, expected := range []string{
		"token_endpoint_auth_method",
		"client_secret_basic",
		"client_secret_post",
		"application_type = 'public'",
		"application_type = 'confidential'",
	} {
		if !strings.Contains(statement, expected) {
			t.Fatalf("OAuth client authentication migration missing %q", expected)
		}
	}
}
