package identity

import (
	"context"
	"errors"
	"strings"
	"sync"
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
	userID, err := service.Verify(context.Background(), token, user.ID)
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
	if _, err := service.Verify(context.Background(), token, user.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Verify(context.Background(), token, user.ID); !errors.Is(err, ErrInvalidVerificationToken) {
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
	if _, err := service.Verify(context.Background(), token, user.ID); !errors.Is(err, ErrInvalidVerificationToken) {
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
	if _, err := service.Verify(context.Background(), token, user.ID); !errors.Is(err, ErrInvalidVerificationToken) {
		t.Fatalf("token for previous email returned %v", err)
	}
	verified, err := repository.Find(context.Background(), user.ID)
	if err != nil || verified.EmailVerified {
		t.Fatalf("changed email was marked verified: %#v %v", verified, err)
	}
}

func TestEmailVerificationEmailMismatchDoesNotConsumeToken(t *testing.T) {
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
	if _, err := service.Verify(context.Background(), token, user.ID); !errors.Is(err, ErrInvalidVerificationToken) {
		t.Fatalf("token for previous email returned %v", err)
	}
	restored, err := Replace(updated, ReplaceUser{DisplayName: "Alice", Email: &email, Status: UserActive}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.Replace(context.Background(), restored); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Verify(context.Background(), token, user.ID); err != nil {
		t.Fatalf("token was consumed by the failed verification: %v", err)
	}
}

func TestEmailVerificationConcurrentWithEmailChange(t *testing.T) {
	for iteration := 0; iteration < 25; iteration++ {
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
		ctx := context.Background()
		var wait sync.WaitGroup
		wait.Add(2)
		go func() {
			defer wait.Done()
			updated, err := Replace(user, ReplaceUser{DisplayName: "Alice", Email: &replacement, Status: UserActive}, time.Now())
			if err != nil {
				t.Error(err)
				return
			}
			if _, err := repository.Replace(ctx, updated); err != nil {
				t.Error(err)
			}
		}()
		go func() {
			defer wait.Done()
			_, _ = service.Verify(ctx, token, user.ID)
		}()
		wait.Wait()
		final, err := repository.Find(ctx, user.ID)
		if err != nil {
			t.Fatal(err)
		}
		// Whatever interleaving happened, ownership of the *current* address
		// must never be claimed: the change resets verification and the old
		// token can never verify the new address.
		if final.EmailVerified {
			t.Fatalf("iteration %d: email ownership invariant broken: %#v", iteration, final)
		}
		if final.Email == nil || !strings.EqualFold(*final.Email, replacement) {
			t.Fatalf("iteration %d: email change was lost: %#v", iteration, final)
		}
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
	if _, err := service.Verify(context.Background(), token, user.ID); err != nil {
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
	if _, err := service.Verify(context.Background(), first, user.ID); !errors.Is(err, ErrInvalidVerificationToken) {
		t.Fatalf("superseded token returned %v", err)
	}
	if _, err := service.Verify(context.Background(), second, user.ID); err != nil {
		t.Fatalf("latest token failed: %v", err)
	}
}

func TestEmailVerificationRejectsOtherUsersToken(t *testing.T) {
	emailA := "alice@example.com"
	userA, err := NewUser(CreateUser{Username: "alice", DisplayName: "Alice", Email: &emailA}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	emailB := "bob@example.com"
	userB, err := NewUser(CreateUser{Username: "bob", DisplayName: "Bob", Email: &emailB}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	repository := NewMemoryUserRepository(userA, userB)
	service := NewEmailVerificationService(repository)

	token, err := service.Issue(context.Background(), userA.ID, 30*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.Verify(context.Background(), token, userB.ID); !errors.Is(err, ErrInvalidVerificationToken) {
		t.Fatalf("cross-account verification returned %v", err)
	}
	userBVerified, err := repository.Find(context.Background(), userB.ID)
	if err != nil || userBVerified.EmailVerified {
		t.Fatalf("cross-account verification changed the session user: %#v", userBVerified)
	}
	userAVerified, err := repository.Find(context.Background(), userA.ID)
	if err != nil || userAVerified.EmailVerified {
		t.Fatalf("cross-account verification changed the token owner: %#v", userAVerified)
	}
	if _, err := service.Verify(context.Background(), token, userA.ID); err != nil {
		t.Fatalf("token was consumed by the wrong account: %v", err)
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
		if _, err := service.Verify(context.Background(), token, user.ID); !errors.Is(err, ErrInvalidVerificationToken) {
			t.Fatalf("token %q returned %v", token, err)
		}
	}
	if !strings.Contains(ErrInvalidVerificationToken.Error(), "expired") {
		t.Fatal("unexpected verification token error text")
	}
}
