package maintenance

import (
	"context"
	"errors"
	"testing"
	"time"

	"certus/internal/oidc"
)

type failingRepository struct{}

func (failingRepository) Cleanup(
	context.Context,
	time.Time,
	time.Time,
	time.Time,
) (map[string]int64, error) {
	return nil, errors.New("cleanup failed")
}

func TestCleanupPrunesOnlyOldRetiredKeys(t *testing.T) {
	ctx := context.Background()
	keys := &oidc.MemoryKeyRepository{}
	if _, err := oidc.NewSigner(ctx, keys); err != nil {
		t.Fatal(err)
	}
	service := NewService(NewMemoryRepository(keys), 24*time.Hour, time.Hour)
	now := time.Now().UTC()
	service.now = func() time.Time { return now }
	signer, err := oidc.NewSigner(ctx, keys)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := signer.Rotate(ctx); err != nil {
		t.Fatal(err)
	}
	result, err := service.RunOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if result.Deleted["oidc_signing_keys"] != 0 {
		t.Fatalf("fresh retired key was deleted: %#v", result)
	}
	service.now = func() time.Time { return now.Add(2 * time.Hour) }
	result, err = service.RunOnce(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if result.Deleted["oidc_signing_keys"] != 1 {
		t.Fatalf("old retired key was not deleted: %#v", result)
	}
}

func TestCleanupObserverReceivesSuccessAndFailure(t *testing.T) {
	service := NewService(failingRepository{}, time.Hour, time.Hour)
	var observed string
	service.SetObserver(func(result string, duration time.Duration) {
		observed = result
		if duration < 0 {
			t.Errorf("negative observer duration: %v", duration)
		}
	})
	if _, err := service.RunOnce(context.Background()); err == nil {
		t.Fatal("expected cleanup failure")
	}
	if observed != "failure" {
		t.Fatalf("unexpected observer result: %s", observed)
	}
}
