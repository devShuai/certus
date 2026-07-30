package ratelimit

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestMemoryRateLimitIsScopedHashedAndResets(t *testing.T) {
	ctx := context.Background()
	repository := NewMemoryRepository()
	service := NewService(repository)
	policy := Policy{Limit: 2, Window: time.Minute}
	now := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)

	for index, allowed := range []bool{true, true, false} {
		result, err := service.Allow(ctx, "login.source", "192.0.2.10", policy, now)
		if err != nil || result.Allowed != allowed {
			t.Fatalf("attempt %d: %#v %v", index+1, result, err)
		}
	}
	if _, exists := repository.buckets["login.source\x00192.0.2.10"]; exists {
		t.Fatal("raw rate-limit subject was stored")
	}
	other, err := service.Allow(ctx, "login.identity", "alice", policy, now)
	if err != nil || !other.Allowed {
		t.Fatalf("independent scope was blocked: %#v %v", other, err)
	}
	reset, err := service.Allow(ctx, "login.source", "192.0.2.10", policy, now.Add(time.Minute))
	if err != nil || !reset.Allowed || reset.Remaining != 1 {
		t.Fatalf("window did not reset: %#v %v", reset, err)
	}
}

func TestRateLimitRejectsInvalidConfigurationAndKey(t *testing.T) {
	service := NewService(NewMemoryRepository())
	now := time.Now()
	if _, err := service.Allow(
		context.Background(), "bad scope", "subject",
		Policy{Limit: 1, Window: time.Minute}, now,
	); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("invalid scope was accepted: %v", err)
	}
	if _, err := service.Allow(
		context.Background(), "login", "subject",
		Policy{Limit: 1, Window: time.Millisecond}, now,
	); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("invalid policy was accepted: %v", err)
	}
	disabled, err := service.Allow(
		context.Background(), "", "",
		Policy{}, now,
	)
	if err != nil || !disabled.Allowed {
		t.Fatalf("disabled policy did not allow request: %#v %v", disabled, err)
	}
}

func TestMemoryRateLimitIsAtomicAcrossConcurrentAttempts(t *testing.T) {
	service := NewService(NewMemoryRepository())
	policy := Policy{Limit: 50, Window: time.Minute}
	now := time.Now().UTC()
	var allowed atomic.Int64
	var wait sync.WaitGroup
	for range 100 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			result, err := service.Allow(
				context.Background(), "oauth.source", "192.0.2.10", policy, now,
			)
			if err != nil {
				t.Errorf("allow request: %v", err)
				return
			}
			if result.Allowed {
				allowed.Add(1)
			}
		}()
	}
	wait.Wait()
	if allowed.Load() != 50 {
		t.Fatalf("unexpected concurrent allowance count: %d", allowed.Load())
	}
}
