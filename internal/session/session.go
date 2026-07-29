package session

import (
	"context"
	"errors"
	"fmt"
	"time"

	"certus/internal/security"
)

var ErrNotFound = errors.New("session not found")

type Session struct {
	ID              string
	UserID          string
	AuthenticatedAt time.Time
	ExpiresAt       time.Time
}

type Repository interface {
	Create(context.Context, Session, []byte, string, string) (Session, error)
	Find(context.Context, []byte, time.Time) (Session, error)
	Revoke(context.Context, string, time.Time) error
}

type Service struct {
	repository Repository
	lifetime   time.Duration
	now        func() time.Time
}

func NewService(repository Repository, lifetime time.Duration) *Service {
	if lifetime <= 0 {
		lifetime = 12 * time.Hour
	}
	return &Service{repository: repository, lifetime: lifetime, now: time.Now}
}

func (s *Service) Create(ctx context.Context, userID, ipAddress, userAgent string) (Session, string, error) {
	token, err := security.RandomToken(32)
	if err != nil {
		return Session{}, "", err
	}
	now := s.now().UTC()
	record, err := s.repository.Create(ctx, Session{
		UserID:          userID,
		AuthenticatedAt: now,
		ExpiresAt:       now.Add(s.lifetime),
	}, security.HashToken(token), ipAddress, userAgent)
	if err != nil {
		return Session{}, "", fmt.Errorf("create session: %w", err)
	}
	return record, token, nil
}

func (s *Service) Find(ctx context.Context, token string) (Session, error) {
	if token == "" {
		return Session{}, ErrNotFound
	}
	return s.repository.Find(ctx, security.HashToken(token), s.now().UTC())
}

func (s *Service) Revoke(ctx context.Context, id string) error {
	if id == "" {
		return nil
	}
	return s.repository.Revoke(ctx, id, s.now().UTC())
}
