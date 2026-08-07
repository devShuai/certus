package identity

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestEmailVerificationIssuesAndVerifies(t *testing.T) {
	email := "alice@example.com"
	user, err := NewUser(CreateUser{Username: "alice", DisplayName: "Alice", Email: &email}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	repository := NewMemoryUserRepository(user)
	service := NewEmailVerificationService(repository)

	token, err := service.Issue(context.Background(), user.ID, 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if token == "" {
		t.Fatal("expected a raw verification token")
	}
	userID, err := service.Verify(context.Background(), token)
	if err != nil {
		t.Fatal(err)
	}
	if userID != user.ID {
		t.Fatalf("unexpected verified user: %s", userID)
	}
	verified, err := repository.Find(context.Background(), user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !verified.EmailVerified {
		t.Fatal("email was not marked as verified")
	}
}

func TestEmailVerificationTokenIsSingleUse(t *testing.T) {
	email := "alice@example.com"
	user, err := NewUser(CreateUser{Username: "alice", DisplayName: "Alice", Email: &email}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	repository := NewMemoryUserRepository(user)
	service := NewEmailVerificationService(repository)

	token, err := service.Issue(context.Background(), user.ID, 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Verify(context.Background(), token); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Verify(context.Background(), token); !errors.Is(err, ErrInvalidVerificationToken) {
		t.Fatalf("reused token returned %v", err)
	}
}

func TestEmailVerificationRejectsExpiredToken(t *testing.T) {
	email := "alice@example.com"
	user, err := NewUser(CreateUser{Username: "alice", DisplayName: "Alice", Email: &email}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	repository := NewMemoryUserRepository(user)
	service := NewEmailVerificationService(repository)

	token, err := service.Issue(context.Background(), user.ID, 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	repository.mu.Lock()
	for key, stored := range repository.emailVerifies {
		if stored.UserID == user.ID {
			stored.ExpiresAt = time.Now().Add(-time.Minute)
			repository.emailVerifies[key] = stored
		}
	}
	repository.mu.Unlock()
	if _, err := service.Verify(context.Background(), token); !errors.Is(err, ErrInvalidVerificationToken) {
		t.Fatalf("expired token returned %v", err)
	}
}

func TestEmailVerificationRejectsTokenAfterEmailChange(t *testing.T) {
	email := "alice@example.com"
	user, err := NewUser(CreateUser{Username: "alice", DisplayName: "Alice", Email: &email}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	repository := NewMemoryUserRepository(user)
	service := NewEmailVerificationService(repository)

	token, err := service.Issue(context.Background(), user.ID, 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	replacement := "alice+new@example.com"
	updated, err := Replace(user, ReplaceUser{DisplayName: "Alice", Email: &replacement, Status: UserActive}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.Replace(context.Background(), updated); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Verify(context.Background(), token); !errors.Is(err, ErrInvalidVerificationToken) {
		t.Fatalf("token for previous email returned %v", err)
	}
}

func TestEmailVerificationRejectsAlreadyVerifiedUser(t *testing.T) {
	email := "alice@example.com"
	user, err := NewUser(CreateUser{Username: "alice", DisplayName: "Alice", Email: &email}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	repository := NewMemoryUserRepository(user)
	service := NewEmailVerificationService(repository)

	token, err := service.Issue(context.Background(), user.ID, 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Verify(context.Background(), token); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Issue(context.Background(), user.ID, 30*time.Minute); !errors.Is(err, ErrEmailAlreadyVerified) {
		t.Fatalf("issue for verified user returned %v", err)
	}
}

func TestEmailVerificationRejectsUserWithoutEmail(t *testing.T) {
	user, err := NewUser(CreateUser{Username: "alice", DisplayName: "Alice"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	repository := NewMemoryUserRepository(user)
	service := NewEmailVerificationService(repository)

	if _, err := service.Issue(context.Background(), user.ID, 30*time.Minute); !errors.Is(err, ErrEmailNotConfigured) {
		t.Fatalf("issue without email returned %v", err)
	}
}

func TestEmailVerificationReplacesActiveToken(t *testing.T) {
	email := "alice@example.com"
	user, err := NewUser(CreateUser{Username: "alice", DisplayName: "Alice", Email: &email}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	repository := NewMemoryUserRepository(user)
	service := NewEmailVerificationService(repository)

	first, err := service.Issue(context.Background(), user.ID, 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.Issue(context.Background(), user.ID, 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("expected distinct tokens")
	}
	if _, err := service.Verify(context.Background(), first); !errors.Is(err, ErrInvalidVerificationToken) {
		t.Fatalf("superseded token returned %v", err)
	}
	if _, err := service.Verify(context.Background(), second); err != nil {
		t.Fatalf("latest token failed: %v", err)
	}
}

func TestEmailVerificationRejectsEmptyToken(t *testing.T) {
	email := "alice@example.com"
	user, err := NewUser(CreateUser{Username: "alice", DisplayName: "Alice", Email: &email}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	service := NewEmailVerificationService(NewMemoryUserRepository(user))
	for _, token := range []string{"", "   ", "not-a-real-token"} {
		if _, err := service.Verify(context.Background(), token); !errors.Is(err, ErrInvalidVerificationToken) {
			t.Fatalf("token %q returned %v", token, err)
		}
	}
	if !strings.Contains(ErrInvalidVerificationToken.Error(), "expired") {
		t.Fatal("unexpected verification token error text")
	}
}
