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
