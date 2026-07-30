package identity

import (
	"context"
	"errors"
	"testing"
)

func TestRegistrationCreatesUserAndPasswordAtomically(t *testing.T) {
	repository := NewMemoryUserRepository()
	service := NewRegistrationService(repository)
	email := " Alice@Example.COM "

	user, err := service.Register(context.Background(), RegisterUser{
		Username:    "Alice",
		DisplayName: "Alice Chen",
		Email:       &email,
		Password:    "correct horse battery staple",
	})
	if err != nil {
		t.Fatal(err)
	}
	if user.Username != "alice" || user.Email == nil || *user.Email != "alice@example.com" {
		t.Fatalf("unexpected registered user: %#v", user)
	}
	authenticated, err := NewPasswordService(repository).Authenticate(
		context.Background(),
		"ALICE",
		"correct horse battery staple",
	)
	if err != nil || authenticated.ID != user.ID {
		t.Fatalf("registered password cannot authenticate: %#v %v", authenticated, err)
	}

	_, err = service.Register(context.Background(), RegisterUser{
		Username:    "another-alice",
		DisplayName: "Another Alice",
		Email:       &email,
		Password:    "another correct password",
	})
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("expected registration conflict, got %v", err)
	}
	if _, findErr := repository.FindByUsername(context.Background(), "another-alice"); !errors.Is(findErr, ErrNotFound) {
		t.Fatalf("conflicting registration left a partial user: %v", findErr)
	}
}

func TestRegistrationRejectsInvalidPasswordBeforePersistence(t *testing.T) {
	repository := NewMemoryUserRepository()
	service := NewRegistrationService(repository)

	_, err := service.Register(context.Background(), RegisterUser{
		Username:    "alice",
		DisplayName: "Alice",
		Password:    "too-short",
	})
	if err == nil {
		t.Fatal("short registration password was accepted")
	}
	if _, findErr := repository.FindByUsername(context.Background(), "alice"); !errors.Is(findErr, ErrNotFound) {
		t.Fatalf("invalid registration left a partial user: %v", findErr)
	}
}
