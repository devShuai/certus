package ratelimit

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
)

var (
	ErrInvalidPolicy = errors.New("invalid rate limit policy")
	ErrInvalidKey    = errors.New("invalid rate limit key")
)

var scopePattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,63}$`)

type Policy struct {
	Limit  int
	Window time.Duration
}

func (p Policy) Enabled() bool {
	return p.Limit > 0 && p.Window > 0
}

func (p Policy) Validate() error {
	if p.Limit == 0 && p.Window == 0 {
		return nil
	}
	if p.Limit < 1 || p.Limit > 1_000_000 ||
		p.Window < time.Second || p.Window > 24*time.Hour {
		return ErrInvalidPolicy
	}
	return nil
}

type Attempt struct {
	Scope       string
	SubjectHash [sha256.Size]byte
	Limit       int
	Window      time.Duration
	Now         time.Time
}

type Decision struct {
	Allowed   bool
	Remaining int
	ResetAt   time.Time
}

type Repository interface {
	Take(context.Context, Attempt) (Decision, error)
}

type Service struct {
	repository Repository
}

func NewService(repository Repository) *Service {
	return &Service{repository: repository}
}

func (s *Service) Allow(
	ctx context.Context,
	scope string,
	subject string,
	policy Policy,
	now time.Time,
) (Decision, error) {
	if !policy.Enabled() {
		return Decision{Allowed: true}, nil
	}
	if err := policy.Validate(); err != nil {
		return Decision{}, err
	}
	scope = strings.TrimSpace(scope)
	subject = strings.TrimSpace(subject)
	if !scopePattern.MatchString(scope) || subject == "" {
		return Decision{}, ErrInvalidKey
	}
	if s == nil || s.repository == nil {
		return Decision{}, errors.New("rate limit repository is unavailable")
	}
	return s.repository.Take(ctx, Attempt{
		Scope:       scope,
		SubjectHash: sha256.Sum256([]byte(scope + "\x00" + subject)),
		Limit:       policy.Limit,
		Window:      policy.Window,
		Now:         now.UTC(),
	})
}

type memoryBucket struct {
	attempts int
	resetAt  time.Time
	touched  time.Time
}

type MemoryRepository struct {
	mu      sync.Mutex
	buckets map[string]memoryBucket
	maxSize int
}

func NewMemoryRepository() *MemoryRepository {
	return &MemoryRepository{
		buckets: make(map[string]memoryBucket),
		maxSize: 10_000,
	}
}

func (r *MemoryRepository) Take(_ context.Context, attempt Attempt) (Decision, error) {
	if err := validateAttempt(attempt); err != nil {
		return Decision{}, err
	}
	key := attempt.Scope + "\x00" + string(attempt.SubjectHash[:])
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.buckets == nil {
		r.buckets = make(map[string]memoryBucket)
	}
	if r.maxSize <= 0 {
		r.maxSize = 10_000
	}
	if len(r.buckets) >= r.maxSize {
		r.prune(attempt.Now)
	}
	if len(r.buckets) >= r.maxSize {
		r.evictOldest()
	}
	bucket := r.buckets[key]
	if bucket.resetAt.IsZero() || !attempt.Now.Before(bucket.resetAt) {
		bucket = memoryBucket{
			attempts: 1,
			resetAt:  attempt.Now.Add(attempt.Window),
			touched:  attempt.Now,
		}
	} else {
		bucket.attempts = min(bucket.attempts+1, attempt.Limit+1)
		bucket.touched = attempt.Now
	}
	r.buckets[key] = bucket
	return decision(bucket.attempts, attempt.Limit, bucket.resetAt), nil
}

func (r *MemoryRepository) prune(now time.Time) {
	for key, bucket := range r.buckets {
		if !now.Before(bucket.resetAt) {
			delete(r.buckets, key)
		}
	}
}

func (r *MemoryRepository) evictOldest() {
	var oldestKey string
	var oldest time.Time
	for key, bucket := range r.buckets {
		if oldestKey == "" || bucket.touched.Before(oldest) {
			oldestKey = key
			oldest = bucket.touched
		}
	}
	if oldestKey != "" {
		delete(r.buckets, oldestKey)
	}
}

func validateAttempt(attempt Attempt) error {
	if !scopePattern.MatchString(attempt.Scope) ||
		attempt.Limit < 1 ||
		attempt.Limit > 1_000_000 ||
		attempt.Window < time.Second ||
		attempt.Window > 24*time.Hour ||
		attempt.Now.IsZero() {
		return fmt.Errorf("%w: scope, limit, window or time", ErrInvalidPolicy)
	}
	return nil
}

func decision(attempts, limit int, resetAt time.Time) Decision {
	remaining := max(limit-attempts, 0)
	return Decision{
		Allowed:   attempts <= limit,
		Remaining: remaining,
		ResetAt:   resetAt,
	}
}
