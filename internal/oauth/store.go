package oauth

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"sync"
	"time"
)

var (
	ErrGrantNotFound        = errors.New("grant not found")
	ErrGrantExpired         = errors.New("grant expired")
	ErrGrantConsumed        = errors.New("grant consumed")
	ErrRefreshReuse         = errors.New("refresh token reuse detected")
	ErrAuthorizationPending = errors.New("authorization pending")
	ErrSlowDown             = errors.New("slow down")
	ErrAccessDenied         = errors.New("access denied")
	ErrConsentNotFound      = errors.New("consent not found")
)

type AuthorizationCode struct {
	Hash            []byte
	ClientID        string
	UserID          string
	SessionID       string
	RedirectURI     string
	Scope           []string
	Nonce           string
	CodeChallenge   string
	AuthenticatedAt time.Time
	AuthMethods     []string
	AssuranceLevel  string
	CreatedAt       time.Time
	ExpiresAt       time.Time
}

type AccessToken struct {
	Hash      []byte
	ClientID  string
	UserID    string
	FamilyID  string
	Scope     []string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

type RefreshToken struct {
	Hash      []byte
	FamilyID  string
	ClientID  string
	UserID    string
	Scope     []string
	IssuedAt  time.Time
	ExpiresAt time.Time
}

type DeviceStatus string

const (
	DevicePending  DeviceStatus = "pending"
	DeviceApproved DeviceStatus = "approved"
	DeviceDenied   DeviceStatus = "denied"
	DeviceConsumed DeviceStatus = "consumed"
)

type DeviceAuthorization struct {
	DeviceHash      []byte
	UserHash        []byte
	ClientID        string
	UserID          string
	Scope           []string
	Status          DeviceStatus
	AuthenticatedAt time.Time
	AuthMethods     []string
	AssuranceLevel  string
	CreatedAt       time.Time
	ExpiresAt       time.Time
	Interval        time.Duration
	LastPollAt      *time.Time
}

type OIDCClientSession struct {
	SessionID string
	ClientID  string
	UserID    string
	CreatedAt time.Time
}

type Consent struct {
	UserID    string    `json:"user_id"`
	ClientID  string    `json:"client_id"`
	Scopes    []string  `json:"scopes"`
	GrantedAt time.Time `json:"granted_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

func (c Consent) Covers(scopes []string) bool {
	for _, scope := range scopes {
		if !slices.Contains(c.Scopes, scope) {
			return false
		}
	}
	return true
}

type Repository interface {
	SaveAuthorizationCode(context.Context, AuthorizationCode) error
	ConsumeAuthorizationCode(context.Context, []byte, string, string, string, time.Time) (AuthorizationCode, error)
	SaveAccessToken(context.Context, AccessToken) error
	FindAccessToken(context.Context, []byte, time.Time) (AccessToken, error)
	RevokeAccessToken(context.Context, []byte, string, time.Time) error
	SaveRefreshToken(context.Context, RefreshToken) error
	FindRefreshToken(context.Context, []byte, time.Time) (RefreshToken, error)
	RotateRefreshToken(context.Context, []byte, RefreshToken, time.Time) (RefreshToken, error)
	RevokeRefreshToken(context.Context, []byte, string, time.Time) error
	SaveDeviceAuthorization(context.Context, DeviceAuthorization) error
	FindDeviceByUserCode(context.Context, []byte, time.Time) (DeviceAuthorization, error)
	DecideDeviceAuthorization(context.Context, []byte, string, time.Time, []string, string, bool, time.Time) error
	PollDeviceAuthorization(context.Context, []byte, string, time.Time) (DeviceAuthorization, error)
	SaveOIDCClientSession(context.Context, OIDCClientSession) error
	ListOIDCClientSessions(context.Context, string) ([]OIDCClientSession, error)
	DeleteOIDCClientSessions(context.Context, string) error
	FindConsent(context.Context, string, string) (Consent, error)
	GrantConsent(context.Context, string, string, []string, time.Time) (Consent, error)
	ListConsentsByUser(context.Context, string) ([]Consent, error)
	DeleteConsent(context.Context, string, string) error
}

type memoryAuthorizationCode struct {
	AuthorizationCode
	consumedAt *time.Time
}

type memoryRefreshToken struct {
	RefreshToken
	consumedAt *time.Time
	revokedAt  *time.Time
}

type memoryAccessToken struct {
	AccessToken
	revokedAt *time.Time
}

type MemoryRepository struct {
	mu           sync.Mutex
	codes        []memoryAuthorizationCode
	accessTokens []memoryAccessToken
	refresh      []memoryRefreshToken
	devices      []DeviceAuthorization
	oidcSessions []OIDCClientSession
	consents     []Consent
}

func NewMemoryRepository() *MemoryRepository {
	return &MemoryRepository{}
}

func (r *MemoryRepository) SaveAuthorizationCode(_ context.Context, value AuthorizationCode) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	value.Hash = cloneBytes(value.Hash)
	value.Scope = append([]string(nil), value.Scope...)
	value.AuthMethods = append([]string(nil), value.AuthMethods...)
	r.codes = append(r.codes, memoryAuthorizationCode{AuthorizationCode: value})
	return nil
}

func (r *MemoryRepository) ConsumeAuthorizationCode(_ context.Context, hash []byte, clientID, redirectURI, codeChallenge string, now time.Time) (AuthorizationCode, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for index := range r.codes {
		record := &r.codes[index]
		if !bytes.Equal(record.Hash, hash) {
			continue
		}
		if record.ClientID != clientID || record.RedirectURI != redirectURI || record.CodeChallenge != codeChallenge {
			return AuthorizationCode{}, ErrGrantNotFound
		}
		if record.consumedAt != nil {
			return AuthorizationCode{}, ErrGrantConsumed
		}
		if !record.ExpiresAt.After(now) {
			return AuthorizationCode{}, ErrGrantExpired
		}
		record.consumedAt = &now
		return cloneAuthorizationCode(record.AuthorizationCode), nil
	}
	return AuthorizationCode{}, ErrGrantNotFound
}

func (r *MemoryRepository) SaveAccessToken(_ context.Context, value AccessToken) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	value.Hash = cloneBytes(value.Hash)
	value.Scope = append([]string(nil), value.Scope...)
	r.accessTokens = append(r.accessTokens, memoryAccessToken{AccessToken: value})
	return nil
}

func (r *MemoryRepository) FindAccessToken(_ context.Context, hash []byte, now time.Time) (AccessToken, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, record := range r.accessTokens {
		if bytes.Equal(record.Hash, hash) && record.revokedAt == nil && record.ExpiresAt.After(now) {
			value := record.AccessToken
			value.Hash = cloneBytes(value.Hash)
			value.Scope = append([]string(nil), value.Scope...)
			return value, nil
		}
	}
	return AccessToken{}, ErrGrantNotFound
}

func (r *MemoryRepository) RevokeAccessToken(_ context.Context, hash []byte, clientID string, now time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for index := range r.accessTokens {
		record := &r.accessTokens[index]
		if bytes.Equal(record.Hash, hash) && record.ClientID == clientID {
			if record.revokedAt == nil {
				record.revokedAt = &now
			}
			return nil
		}
	}
	return ErrGrantNotFound
}

func (r *MemoryRepository) SaveRefreshToken(_ context.Context, value RefreshToken) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	value.Hash = cloneBytes(value.Hash)
	value.Scope = append([]string(nil), value.Scope...)
	r.refresh = append(r.refresh, memoryRefreshToken{RefreshToken: value})
	return nil
}

func (r *MemoryRepository) FindRefreshToken(_ context.Context, hash []byte, now time.Time) (RefreshToken, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, record := range r.refresh {
		if bytes.Equal(record.Hash, hash) &&
			record.consumedAt == nil &&
			record.revokedAt == nil &&
			record.ExpiresAt.After(now) {
			value := record.RefreshToken
			value.Hash = cloneBytes(value.Hash)
			value.Scope = append([]string(nil), value.Scope...)
			return value, nil
		}
	}
	return RefreshToken{}, ErrGrantNotFound
}

func (r *MemoryRepository) RotateRefreshToken(_ context.Context, hash []byte, replacement RefreshToken, now time.Time) (RefreshToken, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for index := range r.refresh {
		record := &r.refresh[index]
		if !bytes.Equal(record.Hash, hash) {
			continue
		}
		if record.ClientID != replacement.ClientID {
			return RefreshToken{}, ErrGrantNotFound
		}
		if record.revokedAt != nil || record.consumedAt != nil {
			for familyIndex := range r.refresh {
				if r.refresh[familyIndex].FamilyID == record.FamilyID {
					value := now
					r.refresh[familyIndex].revokedAt = &value
				}
			}
			return RefreshToken{}, ErrRefreshReuse
		}
		if !record.ExpiresAt.After(now) {
			return RefreshToken{}, ErrGrantExpired
		}
		record.consumedAt = &now
		replacement.FamilyID = record.FamilyID
		replacement.UserID = record.UserID
		replacement.Scope = append([]string(nil), record.Scope...)
		replacement.Hash = cloneBytes(replacement.Hash)
		r.refresh = append(r.refresh, memoryRefreshToken{RefreshToken: replacement})
		value := record.RefreshToken
		value.Hash = cloneBytes(value.Hash)
		value.Scope = append([]string(nil), value.Scope...)
		return value, nil
	}
	return RefreshToken{}, ErrGrantNotFound
}

func (r *MemoryRepository) RevokeRefreshToken(_ context.Context, hash []byte, clientID string, now time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, record := range r.refresh {
		if !bytes.Equal(record.Hash, hash) || record.ClientID != clientID {
			continue
		}
		for index := range r.refresh {
			if r.refresh[index].FamilyID == record.FamilyID {
				value := now
				r.refresh[index].revokedAt = &value
			}
		}
		for index := range r.accessTokens {
			if r.accessTokens[index].FamilyID == record.FamilyID {
				value := now
				r.accessTokens[index].revokedAt = &value
			}
		}
		return nil
	}
	return ErrGrantNotFound
}

func (r *MemoryRepository) SaveDeviceAuthorization(_ context.Context, value DeviceAuthorization) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	value.DeviceHash = cloneBytes(value.DeviceHash)
	value.UserHash = cloneBytes(value.UserHash)
	value.Scope = append([]string(nil), value.Scope...)
	r.devices = append(r.devices, value)
	return nil
}

func (r *MemoryRepository) FindDeviceByUserCode(_ context.Context, hash []byte, now time.Time) (DeviceAuthorization, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, value := range r.devices {
		if bytes.Equal(value.UserHash, hash) && value.ExpiresAt.After(now) && value.Status == DevicePending {
			return cloneDevice(value), nil
		}
	}
	return DeviceAuthorization{}, ErrGrantNotFound
}

func (r *MemoryRepository) DecideDeviceAuthorization(
	_ context.Context,
	userHash []byte,
	userID string,
	authenticatedAt time.Time,
	authMethods []string,
	assuranceLevel string,
	approve bool,
	now time.Time,
) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for index := range r.devices {
		value := &r.devices[index]
		if bytes.Equal(value.UserHash, userHash) && value.ExpiresAt.After(now) && value.Status == DevicePending {
			value.UserID = userID
			value.AuthenticatedAt = authenticatedAt
			value.AuthMethods = append([]string(nil), authMethods...)
			value.AssuranceLevel = assuranceLevel
			if approve {
				value.Status = DeviceApproved
			} else {
				value.Status = DeviceDenied
			}
			return nil
		}
	}
	return ErrGrantNotFound
}

func (r *MemoryRepository) PollDeviceAuthorization(_ context.Context, deviceHash []byte, clientID string, now time.Time) (DeviceAuthorization, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for index := range r.devices {
		value := &r.devices[index]
		if !bytes.Equal(value.DeviceHash, deviceHash) || value.ClientID != clientID {
			continue
		}
		if !value.ExpiresAt.After(now) {
			return DeviceAuthorization{}, ErrGrantExpired
		}
		if value.LastPollAt != nil && now.Before(value.LastPollAt.Add(value.Interval)) {
			value.Interval += 5 * time.Second
			value.LastPollAt = &now
			return DeviceAuthorization{}, ErrSlowDown
		}
		value.LastPollAt = &now
		switch value.Status {
		case DevicePending:
			return DeviceAuthorization{}, ErrAuthorizationPending
		case DeviceDenied:
			return DeviceAuthorization{}, ErrAccessDenied
		case DeviceConsumed:
			return DeviceAuthorization{}, ErrGrantConsumed
		case DeviceApproved:
			value.Status = DeviceConsumed
			return cloneDevice(*value), nil
		}
	}
	return DeviceAuthorization{}, ErrGrantNotFound
}

func (r *MemoryRepository) SaveOIDCClientSession(_ context.Context, value OIDCClientSession) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for index := range r.oidcSessions {
		if r.oidcSessions[index].SessionID == value.SessionID &&
			r.oidcSessions[index].ClientID == value.ClientID {
			r.oidcSessions[index] = value
			return nil
		}
	}
	r.oidcSessions = append(r.oidcSessions, value)
	return nil
}

func (r *MemoryRepository) ListOIDCClientSessions(_ context.Context, sessionID string) ([]OIDCClientSession, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	result := make([]OIDCClientSession, 0)
	for _, value := range r.oidcSessions {
		if value.SessionID == sessionID {
			result = append(result, value)
		}
	}
	return result, nil
}

func (r *MemoryRepository) DeleteOIDCClientSessions(_ context.Context, sessionID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	result := r.oidcSessions[:0]
	for _, value := range r.oidcSessions {
		if value.SessionID != sessionID {
			result = append(result, value)
		}
	}
	r.oidcSessions = result
	return nil
}

func (r *MemoryRepository) FindConsent(_ context.Context, userID, clientID string) (Consent, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, value := range r.consents {
		if value.UserID == userID && value.ClientID == clientID {
			return cloneConsent(value), nil
		}
	}
	return Consent{}, ErrConsentNotFound
}

func (r *MemoryRepository) GrantConsent(
	_ context.Context,
	userID, clientID string,
	scopes []string,
	now time.Time,
) (Consent, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for index := range r.consents {
		if r.consents[index].UserID == userID && r.consents[index].ClientID == clientID {
			r.consents[index].Scopes = mergeScopes(r.consents[index].Scopes, scopes)
			r.consents[index].UpdatedAt = now
			return cloneConsent(r.consents[index]), nil
		}
	}
	value := Consent{
		UserID:    userID,
		ClientID:  clientID,
		Scopes:    mergeScopes(nil, scopes),
		GrantedAt: now,
		UpdatedAt: now,
	}
	r.consents = append(r.consents, value)
	return cloneConsent(value), nil
}

func (r *MemoryRepository) ListConsentsByUser(_ context.Context, userID string) ([]Consent, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	result := make([]Consent, 0)
	for _, value := range r.consents {
		if value.UserID == userID {
			result = append(result, cloneConsent(value))
		}
	}
	slices.SortFunc(result, func(a, b Consent) int {
		return b.UpdatedAt.Compare(a.UpdatedAt)
	})
	return result, nil
}

func (r *MemoryRepository) DeleteConsent(_ context.Context, userID, clientID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for index, value := range r.consents {
		if value.UserID == userID && value.ClientID == clientID {
			r.consents = append(r.consents[:index], r.consents[index+1:]...)
			return nil
		}
	}
	return ErrConsentNotFound
}

func cloneBytes(value []byte) []byte {
	return append([]byte(nil), value...)
}

func cloneConsent(value Consent) Consent {
	value.Scopes = append([]string(nil), value.Scopes...)
	return value
}

func mergeScopes(current, requested []string) []string {
	result := append([]string(nil), current...)
	for _, scope := range requested {
		if !slices.Contains(result, scope) {
			result = append(result, scope)
		}
	}
	slices.Sort(result)
	return result
}

func cloneAuthorizationCode(value AuthorizationCode) AuthorizationCode {
	value.Hash = cloneBytes(value.Hash)
	value.Scope = append([]string(nil), value.Scope...)
	value.AuthMethods = append([]string(nil), value.AuthMethods...)
	return value
}

func cloneDevice(value DeviceAuthorization) DeviceAuthorization {
	value.DeviceHash = cloneBytes(value.DeviceHash)
	value.UserHash = cloneBytes(value.UserHash)
	value.Scope = append([]string(nil), value.Scope...)
	value.AuthMethods = append([]string(nil), value.AuthMethods...)
	return value
}
