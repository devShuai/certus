package identity

import (
	"context"
	"errors"
	"regexp"
	"testing"
	"time"
)

func TestNewUserNormalizesIdentity(t *testing.T) {
	email := " User@Example.COM "
	now := time.Date(2026, 7, 28, 10, 0, 0, 0, time.FixedZone("CST", 8*60*60))
	user, err := NewUser(CreateUser{
		Username:    " Alice.Smith ",
		DisplayName: " Alice Smith ",
		Email:       &email,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if user.Username != "alice.smith" || user.DisplayName != "Alice Smith" {
		t.Fatalf("user was not normalized: %#v", user)
	}
	if user.Email == nil || *user.Email != "user@example.com" {
		t.Fatalf("email was not normalized: %#v", user.Email)
	}
	if user.EmailVerified {
		t.Fatal("new local user email was implicitly verified")
	}
	if user.Status != UserActive || !user.CreatedAt.Equal(now.UTC()) {
		t.Fatalf("unexpected defaults: %#v", user)
	}
	if !regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`).MatchString(user.ID) {
		t.Fatalf("invalid UUID: %s", user.ID)
	}
}

func TestMemoryUserRepositoryPreventsDuplicates(t *testing.T) {
	repository := NewMemoryUserRepository()
	now := time.Now()
	email := "alice@example.com"
	first, err := NewUser(CreateUser{Username: "alice", DisplayName: "Alice", Email: &email}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.Create(context.Background(), first); err != nil {
		t.Fatal(err)
	}
	second, err := NewUser(CreateUser{Username: "alice", DisplayName: "Another Alice"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.Create(context.Background(), second); !errors.Is(err, ErrConflict) {
		t.Fatalf("expected conflict, got %v", err)
	}
}

func TestReplaceRequiresExplicitValidStatus(t *testing.T) {
	current := User{ID: "id", Username: "alice", DisplayName: "Alice", Status: UserActive}
	if _, err := Replace(current, ReplaceUser{DisplayName: "Alice"}, time.Now()); !errors.Is(err, ErrInvalid) {
		t.Fatalf("expected invalid status, got %v", err)
	}
}

func TestReplacePreservesVerificationOnlyForSameEmail(t *testing.T) {
	now := time.Now().UTC()
	email := "alice@example.com"
	current, err := NewUser(CreateUser{
		Username: "alice", DisplayName: "Alice", Email: &email,
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	current.EmailVerified = true

	sameEmail := " Alice@Example.COM "
	unchanged, err := Replace(current, ReplaceUser{
		DisplayName: "Alice", Email: &sameEmail, Status: UserActive,
	}, now.Add(time.Minute))
	if err != nil || !unchanged.EmailVerified {
		t.Fatalf("same email lost verification: %#v %v", unchanged, err)
	}

	changedEmail := "new@example.com"
	changed, err := Replace(current, ReplaceUser{
		DisplayName: "Alice", Email: &changedEmail, Status: UserActive,
	}, now.Add(2*time.Minute))
	if err != nil || changed.EmailVerified {
		t.Fatalf("changed email retained verification: %#v %v", changed, err)
	}
}
