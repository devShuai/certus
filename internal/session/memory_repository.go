package session

import (
	"bytes"
	"context"
	"sync"
	"time"

	"certus/internal/security"
)

type memoryRecord struct {
	Session
	hash      []byte
	revokedAt *time.Time
}

type MemoryRepository struct {
	mu      sync.RWMutex
	records map[string]memoryRecord
}

func NewMemoryRepository() *MemoryRepository {
	return &MemoryRepository{records: make(map[string]memoryRecord)}
}

func (r *MemoryRepository) Create(_ context.Context, value Session, hash []byte, _, _ string) (Session, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id, err := security.RandomToken(16)
	if err != nil {
		return Session{}, err
	}
	value.ID = id
	r.records[id] = memoryRecord{Session: value, hash: append([]byte(nil), hash...)}
	return value, nil
}

func (r *MemoryRepository) Find(_ context.Context, hash []byte, now time.Time) (Session, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, record := range r.records {
		if bytes.Equal(record.hash, hash) && record.revokedAt == nil && record.ExpiresAt.After(now) {
			return record.Session, nil
		}
	}
	return Session{}, ErrNotFound
}

func (r *MemoryRepository) Revoke(_ context.Context, id string, now time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	record, ok := r.records[id]
	if !ok {
		return ErrNotFound
	}
	record.revokedAt = &now
	r.records[id] = record
	return nil
}
