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
	ID              string     `json:"id"`
	UserID          string     `json:"user_id"`
	AuthenticatedAt time.Time  `json:"authenticated_at"`
	ExpiresAt       time.Time  `json:"expires_at"`
	LastSeenAt      time.Time  `json:"last_seen_at"`
	IPAddress       string     `json:"ip_address,omitempty"`
	UserAgent       string     `json:"user_agent,omitempty"`
	RevokedAt       *time.Time `json:"revoked_at,omitempty"`
	AuthMethods     []string   `json:"authentication_methods"`
	AssuranceLevel  string     `json:"assurance_level"`
}

type Repository interface {
	Create(context.Context, Session, []byte, string, string) (Session, error)
	Find(context.Context, []byte, time.Time) (Session, error)
	IsActive(context.Context, string, string, time.Time) (bool, error)
	ListByUser(context.Context, string, time.Time) ([]Session, error)
	Revoke(context.Context, string, time.Time) error
	RevokeForUser(context.Context, string, string, time.Time) error
	RevokeAll(context.Context, string, string, time.Time) (int64, error)
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
	return s.CreateWithMethods(ctx, userID, ipAddress, userAgent, nil, "urn:certus:aal:1")
}

func (s *Service) CreateWithMethods(
	ctx context.Context,
	userID, ipAddress, userAgent string,
	authMethods []string,
	assuranceLevel string,
) (Session, string, error) {
	token, err := security.RandomToken(32)
	if err != nil {
		return Session{}, "", err
	}
	now := s.now().UTC()
	record, err := s.repository.Create(ctx, Session{
		UserID:          userID,
		AuthenticatedAt: now,
		ExpiresAt:       now.Add(s.lifetime),
		LastSeenAt:      now,
		IPAddress:       ipAddress,
		UserAgent:       userAgent,
		AuthMethods:     append([]string(nil), authMethods...),
		AssuranceLevel:  assuranceLevel,
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

func (s *Service) ListByUser(ctx context.Context, userID string) ([]Session, error) {
	return s.repository.ListByUser(ctx, userID, s.now().UTC())
}

func (s *Service) IsActive(ctx context.Context, userID, id string) (bool, error) {
	if userID == "" || id == "" {
		return false, nil
	}
	return s.repository.IsActive(ctx, userID, id, s.now().UTC())
}

func (s *Service) RevokeForUser(ctx context.Context, userID, id string) error {
	if userID == "" || id == "" {
		return ErrNotFound
	}
	return s.repository.RevokeForUser(ctx, userID, id, s.now().UTC())
}

func (s *Service) RevokeAll(ctx context.Context, userID, exceptID string) (int64, error) {
	if userID == "" {
		return 0, ErrNotFound
	}
	return s.repository.RevokeAll(ctx, userID, exceptID, s.now().UTC())
}
