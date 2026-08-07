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
	ConsumeEmailVerification(context.Context, []byte, time.Time) (string, string, error)
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

func (s *EmailVerificationService) Verify(ctx context.Context, token string) (string, error) {
	if s.verifications == nil || strings.TrimSpace(token) == "" {
		return "", ErrInvalidVerificationToken
	}
	userID, email, err := s.verifications.ConsumeEmailVerification(ctx, security.HashToken(token), s.now().UTC())
	if err != nil {
		return "", ErrInvalidVerificationToken
	}
	user, err := s.repository.Find(ctx, userID)
	if err != nil {
		return "", err
	}
	if user.Email == nil || !strings.EqualFold(*user.Email, email) {
		return "", ErrInvalidVerificationToken
	}
	if _, err := s.repository.SetEmailVerified(ctx, userID, s.now().UTC()); err != nil {
		return "", err
	}
	return userID, nil
}
