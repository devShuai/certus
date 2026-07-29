package maintenance

import (
	"context"
	"log/slog"
	"time"

	"certus/internal/oidc"
)

type Result struct {
	CompletedAt time.Time        `json:"completed_at"`
	Deleted     map[string]int64 `json:"deleted"`
}

type Repository interface {
	Cleanup(context.Context, time.Time, time.Time, time.Time) (map[string]int64, error)
}

type MemoryRepository struct {
	keys oidc.KeyRepository
}

func NewMemoryRepository(keys oidc.KeyRepository) *MemoryRepository {
	return &MemoryRepository{keys: keys}
}

func (r *MemoryRepository) Cleanup(
	ctx context.Context,
	_ time.Time,
	_ time.Time,
	signingKeyBefore time.Time,
) (map[string]int64, error) {
	count, err := r.keys.DeleteRetiredSigningKeys(ctx, signingKeyBefore)
	if err != nil {
		return nil, err
	}
	return map[string]int64{"oidc_signing_keys": count}, nil
}

type Service struct {
	repository          Repository
	auditRetention      time.Duration
	signingKeyRetention time.Duration
	now                 func() time.Time
}

func NewService(repository Repository, auditRetention, signingKeyRetention time.Duration) *Service {
	if auditRetention <= 0 {
		auditRetention = 90 * 24 * time.Hour
	}
	if signingKeyRetention < time.Hour {
		signingKeyRetention = 24 * time.Hour
	}
	return &Service{
		repository:          repository,
		auditRetention:      auditRetention,
		signingKeyRetention: signingKeyRetention,
		now:                 time.Now,
	}
}

func (s *Service) RunOnce(ctx context.Context) (Result, error) {
	now := s.now().UTC()
	deleted, err := s.repository.Cleanup(
		ctx,
		now,
		now.Add(-s.auditRetention),
		now.Add(-s.signingKeyRetention),
	)
	if err != nil {
		return Result{}, err
	}
	return Result{CompletedAt: now, Deleted: deleted}, nil
}

func (s *Service) Run(ctx context.Context, interval time.Duration, logger *slog.Logger) {
	if interval <= 0 {
		return
	}
	run := func() {
		result, err := s.RunOnce(ctx)
		if err != nil {
			if ctx.Err() == nil {
				logger.Error("maintenance cleanup failed", "error", err)
			}
			return
		}
		logger.Info("maintenance cleanup completed", "deleted", result.Deleted)
	}
	run()
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			run()
		}
	}
}
