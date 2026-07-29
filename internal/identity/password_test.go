package identity

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestPasswordServiceAuthenticatesAndLocksRepeatedFailures(t *testing.T) {
	user, err := NewUser(CreateUser{Username: "alice", DisplayName: "Alice"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	repository := NewMemoryUserRepository(user)
	service := NewPasswordService(repository)
	if err := service.Set(context.Background(), user.ID, "correct horse battery staple"); err != nil {
		t.Fatal(err)
	}
	authenticated, err := service.Authenticate(context.Background(), "ALICE", "correct horse battery staple")
	if err != nil || authenticated.ID != user.ID {
		t.Fatalf("unexpected authentication result: %#v %v", authenticated, err)
	}
	for attempt := 1; attempt <= 5; attempt++ {
		_, err = service.Authenticate(context.Background(), "alice", "incorrect password")
	}
	if !errors.Is(err, ErrCredentialLocked) {
		t.Fatalf("expected credential lock, got %v", err)
	}
	if _, err := service.Authenticate(context.Background(), "alice", "correct horse battery staple"); !errors.Is(err, ErrCredentialLocked) {
		t.Fatalf("locked credential accepted: %v", err)
	}
}
