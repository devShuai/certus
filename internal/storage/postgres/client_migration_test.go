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
