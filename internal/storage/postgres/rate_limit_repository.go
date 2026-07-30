package postgres

import (
	"context"
	"fmt"
	"time"

	"certus/internal/ratelimit"

	"github.com/jackc/pgx/v5/pgxpool"
)

type RateLimitRepository struct {
	pool *pgxpool.Pool
}

var _ ratelimit.Repository = (*RateLimitRepository)(nil)

func NewRateLimitRepository(pool *pgxpool.Pool) *RateLimitRepository {
	return &RateLimitRepository{pool: pool}
}

func (r *RateLimitRepository) Take(
	ctx context.Context,
	attempt ratelimit.Attempt,
) (ratelimit.Decision, error) {
	var attempts int
	var resetAt time.Time
	err := r.pool.QueryRow(ctx, `
		INSERT INTO rate_limit_buckets (
			scope, subject_hash, attempts, window_ends_at, updated_at
		)
		VALUES ($1, $2, 1, $3, $4)
		ON CONFLICT (scope, subject_hash) DO UPDATE
		SET attempts = CASE
				WHEN rate_limit_buckets.window_ends_at <= EXCLUDED.updated_at THEN 1
				ELSE least(rate_limit_buckets.attempts + 1, $5)
			END,
			window_ends_at = CASE
				WHEN rate_limit_buckets.window_ends_at <= EXCLUDED.updated_at
					THEN EXCLUDED.window_ends_at
				ELSE rate_limit_buckets.window_ends_at
			END,
			updated_at = EXCLUDED.updated_at
		RETURNING attempts, window_ends_at`,
		attempt.Scope,
		attempt.SubjectHash[:],
		attempt.Now.Add(attempt.Window),
		attempt.Now,
		attempt.Limit+1,
	).Scan(&attempts, &resetAt)
	if err != nil {
		return ratelimit.Decision{}, fmt.Errorf("take PostgreSQL rate limit: %w", err)
	}
	return ratelimit.Decision{
		Allowed:   attempts <= attempt.Limit,
		Remaining: max(attempt.Limit-attempts, 0),
		ResetAt:   resetAt,
	}, nil
}
