package config

import (
	"strings"
	"testing"
)

func TestLoadRejectsShortAdminToken(t *testing.T) {
	t.Setenv("CERTUS_ADMIN_TOKEN", "too-short")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "at least 32") {
		t.Fatalf("expected short token error, got %v", err)
	}
}

func TestLoadAcceptsStrongAdminToken(t *testing.T) {
	t.Setenv("CERTUS_ADMIN_TOKEN", strings.Repeat("a", 32))
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.AdminToken) != 32 {
		t.Fatalf("unexpected token length: %d", len(cfg.AdminToken))
	}
}
