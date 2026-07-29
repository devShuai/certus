package session

import (
	"bytes"
	"context"
	"sort"
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

func (r *MemoryRepository) Create(_ context.Context, value Session, hash []byte, ipAddress, userAgent string) (Session, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	id, err := security.RandomToken(16)
	if err != nil {
		return Session{}, err
	}
	value.ID = id
	value.IPAddress = ipAddress
	value.UserAgent = userAgent
	r.records[id] = memoryRecord{Session: value, hash: append([]byte(nil), hash...)}
	return value, nil
}

func (r *MemoryRepository) Find(_ context.Context, hash []byte, now time.Time) (Session, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, record := range r.records {
		if bytes.Equal(record.hash, hash) && record.revokedAt == nil && record.ExpiresAt.After(now) {
			record.LastSeenAt = now
			r.records[record.ID] = record
			return cloneSession(record.Session), nil
		}
	}
	return Session{}, ErrNotFound
}

func (r *MemoryRepository) ListByUser(_ context.Context, userID string, now time.Time) ([]Session, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]Session, 0)
	for _, record := range r.records {
		if record.UserID == userID && record.revokedAt == nil && record.ExpiresAt.After(now) {
			result = append(result, cloneSession(record.Session))
		}
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].LastSeenAt.After(result[j].LastSeenAt)
	})
	return result, nil
}

func (r *MemoryRepository) Revoke(_ context.Context, id string, now time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	record, ok := r.records[id]
	if !ok {
		return ErrNotFound
	}
	record.revokedAt = &now
	record.RevokedAt = &now
	r.records[id] = record
	return nil
}

func (r *MemoryRepository) RevokeForUser(_ context.Context, userID, id string, now time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	record, ok := r.records[id]
	if !ok || record.UserID != userID {
		return ErrNotFound
	}
	record.revokedAt = &now
	record.RevokedAt = &now
	r.records[id] = record
	return nil
}

func (r *MemoryRepository) RevokeAll(_ context.Context, userID, exceptID string, now time.Time) (int64, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var count int64
	for id, record := range r.records {
		if record.UserID != userID || id == exceptID || record.revokedAt != nil || !record.ExpiresAt.After(now) {
			continue
		}
		value := now
		record.revokedAt = &value
		record.RevokedAt = &value
		r.records[id] = record
		count++
	}
	return count, nil
}

func cloneSession(value Session) Session {
	if value.RevokedAt != nil {
		revokedAt := *value.RevokedAt
		value.RevokedAt = &revokedAt
	}
	return value
}
