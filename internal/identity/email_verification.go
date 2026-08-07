package identity

import (
	"context"
	"errors"
	"strings"
	"time"

	"certus/internal/security"
)

var (
	ErrInvalidVerificationToken = errors.New("invalid or expired email verification token")
	ErrEmailAlreadyVerified     = errors.New("email is already verified")
	ErrEmailNotConfigured       = errors.New("user has no email address")
)

type EmailVerificationToken struct {
	UserID    string
	Email     string
	Hash      []byte
	CreatedAt time.Time
	ExpiresAt time.Time
}

type EmailVerificationRepository interface {
	SaveEmailVerification(context.Context, EmailVerificationToken) error
	VerifyEmail(context.Context, []byte, string, time.Time) (string, error)
}

type EmailVerificationService struct {
	repository    UserRepository
	verifications EmailVerificationRepository
	now           func() time.Time
}

func NewEmailVerificationService(repository UserRepository) *EmailVerificationService {
	verifications, _ := repository.(EmailVerificationRepository)
	return &EmailVerificationService{
		repository:    repository,
		verifications: verifications,
		now:           time.Now,
	}
}

func (s *EmailVerificationService) Issue(ctx context.Context, userID string, lifetime time.Duration) (string, error) {
	if s.verifications == nil {
		return "", errors.New("email verification repository is unavailable")
	}
	user, err := s.repository.Find(ctx, userID)
	if err != nil {
		return "", err
	}
	if user.Email == nil {
		return "", ErrEmailNotConfigured
	}
	if user.EmailVerified {
		return "", ErrEmailAlreadyVerified
	}
	if lifetime <= 0 {
		lifetime = 30 * time.Minute
	}
	raw, err := security.RandomToken(32)
	if err != nil {
		return "", err
	}
	now := s.now().UTC()
	if err := s.verifications.SaveEmailVerification(ctx, EmailVerificationToken{
		UserID:    userID,
		Email:     *user.Email,
		Hash:      security.HashToken(raw),
		CreatedAt: now,
		ExpiresAt: now.Add(lifetime),
	}); err != nil {
		return "", err
	}
	return raw, nil
}

// Verify consumes a token on behalf of expectedUserID in a single atomic
// repository operation: the token must belong to that account and still
// match the account's current email. The token is bound to the account it
// was issued for, so consuming it under any other user ID fails without
// consuming the token; if the address changed since issuance, the whole
// operation is rolled back and the token remains unconsumed.
func (s *EmailVerificationService) Verify(ctx context.Context, token, expectedUserID string) (string, error) {
	if s.verifications == nil || strings.TrimSpace(token) == "" {
		return "", ErrInvalidVerificationToken
	}
	userID, err := s.verifications.VerifyEmail(
		ctx, security.HashToken(token), expectedUserID, s.now().UTC(),
	)
	if err != nil {
		return "", ErrInvalidVerificationToken
	}
	return userID, nil
}
