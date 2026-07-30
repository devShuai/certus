package mfa

import (
	"bytes"
	"context"
	"sync"
	"time"
)

type memoryCredential struct {
	Credential
	recoveryCodes [][]byte
}

type MemoryRepository struct {
	mu          sync.RWMutex
	credentials map[string]memoryCredential
}

var _ SecretRepository = (*MemoryRepository)(nil)

func NewMemoryRepository() *MemoryRepository {
	return &MemoryRepository{credentials: make(map[string]memoryCredential)}
}

func (r *MemoryRepository) Find(_ context.Context, userID string) (Credential, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	value, ok := r.credentials[userID]
	if !ok {
		return Credential{}, ErrNotFound
	}
	result := cloneCredential(value.Credential)
	result.RecoveryCodes = len(value.recoveryCodes)
	return result, nil
}

func (r *MemoryRepository) ReplacePending(_ context.Context, credential Credential, recoveryCodes [][]byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	value := memoryCredential{Credential: cloneCredential(credential)}
	for _, code := range recoveryCodes {
		value.recoveryCodes = append(value.recoveryCodes, append([]byte(nil), code...))
	}
	r.credentials[credential.UserID] = value
	return nil
}

func (r *MemoryRepository) ReplaceRecoveryCodes(
	_ context.Context,
	userID string,
	recoveryCodes [][]byte,
	_ time.Time,
) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	value, ok := r.credentials[userID]
	if !ok {
		return ErrNotFound
	}
	if !value.Enabled {
		return ErrNotEnabled
	}
	value.recoveryCodes = make([][]byte, 0, len(recoveryCodes))
	for _, code := range recoveryCodes {
		value.recoveryCodes = append(value.recoveryCodes, append([]byte(nil), code...))
	}
	r.credentials[userID] = value
	return nil
}

func (r *MemoryRepository) ListSecretCiphertexts(_ context.Context) ([]SecretRecord, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]SecretRecord, 0, len(r.credentials))
	for _, value := range r.credentials {
		result = append(result, SecretRecord{
			UserID:     value.UserID,
			Ciphertext: append([]byte(nil), value.Secret...),
		})
	}
	return result, nil
}

func (r *MemoryRepository) ReplaceSecretCiphertext(
	_ context.Context,
	userID string,
	current, replacement []byte,
) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	value, ok := r.credentials[userID]
	if !ok || !bytes.Equal(value.Secret, current) {
		return false, nil
	}
	value.Secret = append([]byte(nil), replacement...)
	r.credentials[userID] = value
	return true, nil
}

func (r *MemoryRepository) Enable(_ context.Context, userID string, step int64, now time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	value, ok := r.credentials[userID]
	if !ok {
		return ErrNotFound
	}
	value.Enabled = true
	value.VerifiedAt = &now
	value.LastUsedStep = step
	value.FailedAttempts = 0
	value.LockedUntil = nil
	r.credentials[userID] = value
	return nil
}

func (r *MemoryRepository) UseTOTP(_ context.Context, userID string, step int64, _ time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	value, ok := r.credentials[userID]
	if !ok || !value.Enabled {
		return ErrInvalidCode
	}
	if step <= value.LastUsedStep {
		return ErrReplay
	}
	value.LastUsedStep = step
	value.FailedAttempts = 0
	value.LockedUntil = nil
	r.credentials[userID] = value
	return nil
}

func (r *MemoryRepository) UseRecoveryCode(_ context.Context, userID string, hash []byte, _ time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	value, ok := r.credentials[userID]
	if !ok || !value.Enabled {
		return ErrInvalidCode
	}
	for index, current := range value.recoveryCodes {
		if bytes.Equal(current, hash) {
			value.recoveryCodes = append(value.recoveryCodes[:index], value.recoveryCodes[index+1:]...)
			value.FailedAttempts = 0
			value.LockedUntil = nil
			r.credentials[userID] = value
			return nil
		}
	}
	return ErrInvalidCode
}

func (r *MemoryRepository) RecordFailure(_ context.Context, userID string, attempts int, lockedUntil *time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	value, ok := r.credentials[userID]
	if !ok {
		return ErrNotFound
	}
	value.FailedAttempts = attempts
	if lockedUntil != nil {
		locked := *lockedUntil
		value.LockedUntil = &locked
	} else {
		value.LockedUntil = nil
	}
	r.credentials[userID] = value
	return nil
}

func (r *MemoryRepository) Delete(_ context.Context, userID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.credentials[userID]; !ok {
		return ErrNotFound
	}
	delete(r.credentials, userID)
	return nil
}

func cloneCredential(value Credential) Credential {
	value.Secret = append([]byte(nil), value.Secret...)
	if value.VerifiedAt != nil {
		verifiedAt := *value.VerifiedAt
		value.VerifiedAt = &verifiedAt
	}
	if value.LockedUntil != nil {
		lockedUntil := *value.LockedUntil
		value.LockedUntil = &lockedUntil
	}
	return value
}
