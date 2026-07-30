package identity

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestPasswordMigrationUpgradesSpecusHashAfterSuccessfulLogin(t *testing.T) {
	now := time.Date(2026, 7, 31, 8, 0, 0, 0, time.UTC)
	password := "existing specus password"
	repository := NewMemoryUserRepository()
	migrations := NewPasswordMigrationService(repository)
	migrations.now = func() time.Time { return now }

	result, err := migrations.Import(context.Background(), ImportPasswordUsers{
		Algorithm: PasswordMigrationSpecusSHA256,
		Users: []PasswordMigrationUser{{
			Username:     "alice",
			DisplayName:  "Alice",
			PasswordHash: specusPasswordHash(password),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Count != 1 || !result.ExpiresAt.Equal(now.Add(defaultPasswordMigrationLifetime)) {
		t.Fatalf("unexpected migration result: %#v", result)
	}
	_, credential, err := repository.FindPasswordByUsername(context.Background(), "alice")
	if err != nil || !strings.HasPrefix(credential.Hash, "$legacy$specus_sha256$") {
		t.Fatalf("legacy credential was not stored: %#v %v", credential, err)
	}

	passwords := NewPasswordService(repository)
	passwords.now = func() time.Time { return now.Add(time.Minute) }
	if _, err := passwords.Authenticate(context.Background(), "alice", "wrong password"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong migrated password was accepted: %v", err)
	}
	user, err := passwords.Authenticate(context.Background(), "alice", password)
	if err != nil || user.Username != "alice" {
		t.Fatalf("migrated password did not authenticate: %#v %v", user, err)
	}
	_, credential, err = repository.FindPasswordByUsername(context.Background(), "alice")
	if err != nil || !strings.HasPrefix(credential.Hash, "$argon2id$") {
		t.Fatalf("migrated password was not upgraded: %#v %v", credential, err)
	}
}

func TestExpiredMigratedPasswordCannotAuthenticate(t *testing.T) {
	now := time.Date(2026, 7, 31, 8, 0, 0, 0, time.UTC)
	expiresAt := now.Add(time.Hour)
	repository := NewMemoryUserRepository()
	migrations := NewPasswordMigrationService(repository)
	migrations.now = func() time.Time { return now }
	_, err := migrations.Import(context.Background(), ImportPasswordUsers{
		Algorithm: PasswordMigrationSpecusSHA256,
		ExpiresAt: &expiresAt,
		Users: []PasswordMigrationUser{{
			Username:     "alice",
			DisplayName:  "Alice",
			PasswordHash: specusPasswordHash("existing specus password"),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	passwords := NewPasswordService(repository)
	passwords.now = func() time.Time { return expiresAt }
	if _, err := passwords.Authenticate(
		context.Background(),
		"alice",
		"existing specus password",
	); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("expired migrated password was accepted: %v", err)
	}
}

func TestPasswordMigrationRejectsInvalidInputWithoutPartialUsers(t *testing.T) {
	repository := NewMemoryUserRepository()
	migrations := NewPasswordMigrationService(repository)
	_, err := migrations.Import(context.Background(), ImportPasswordUsers{
		Algorithm: PasswordMigrationSpecusSHA256,
		Users: []PasswordMigrationUser{
			{
				Username:     "alice",
				DisplayName:  "Alice",
				PasswordHash: specusPasswordHash("alice password"),
			},
			{
				Username:     "bob",
				DisplayName:  "Bob",
				PasswordHash: "not-a-sha256-hash",
			},
		},
	})
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid migrated hash returned %v", err)
	}
	if _, findErr := repository.FindByUsername(context.Background(), "alice"); !errors.Is(findErr, ErrNotFound) {
		t.Fatalf("invalid batch left a partial user: %v", findErr)
	}
}

func TestPasswordMigrationConflictRollsBackEntireBatch(t *testing.T) {
	existing, err := NewUser(CreateUser{
		Username:    "existing",
		DisplayName: "Existing",
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	repository := NewMemoryUserRepository(existing)
	migrations := NewPasswordMigrationService(repository)
	_, err = migrations.Import(context.Background(), ImportPasswordUsers{
		Algorithm: PasswordMigrationSpecusSHA256,
		Users: []PasswordMigrationUser{
			{
				Username:     "new-user",
				DisplayName:  "New User",
				PasswordHash: specusPasswordHash("new password"),
			},
			{
				Username:     "existing",
				DisplayName:  "Existing Again",
				PasswordHash: specusPasswordHash("existing password"),
			},
		},
	})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("expected migration conflict, got %v", err)
	}
	if _, findErr := repository.FindByUsername(context.Background(), "new-user"); !errors.Is(findErr, ErrNotFound) {
		t.Fatalf("conflicting batch left a partial user: %v", findErr)
	}
}

func specusPasswordHash(password string) string {
	return fmt.Sprintf("%x", sha256.Sum256([]byte(password)))
}
