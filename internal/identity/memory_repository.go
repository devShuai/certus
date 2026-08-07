package identity

import (
	"bytes"
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

type MemoryUserRepository struct {
	mu             sync.RWMutex
	users          map[string]User
	credentials    map[string]PasswordCredential
	external       map[string]ExternalIdentity
	passwordResets map[string]PasswordResetToken
	emailVerifies  map[string]EmailVerificationToken
}

func NewMemoryUserRepository(users ...User) *MemoryUserRepository {
	repository := &MemoryUserRepository{
		users:          make(map[string]User, len(users)),
		credentials:    make(map[string]PasswordCredential),
		external:       make(map[string]ExternalIdentity),
		passwordResets: make(map[string]PasswordResetToken),
		emailVerifies:  make(map[string]EmailVerificationToken),
	}
	for _, user := range users {
		repository.users[user.ID] = cloneUser(user)
	}
	return repository
}

func (r *MemoryUserRepository) SavePasswordReset(_ context.Context, token PasswordResetToken) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.users[token.UserID]; !ok {
		return ErrNotFound
	}
	for key, current := range r.passwordResets {
		if current.UserID == token.UserID {
			delete(r.passwordResets, key)
		}
	}
	token.Hash = append([]byte(nil), token.Hash...)
	r.passwordResets[string(token.Hash)] = token
	return nil
}

func (r *MemoryUserRepository) ConsumePasswordReset(_ context.Context, hash []byte, now time.Time) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for key, token := range r.passwordResets {
		if bytes.Equal(token.Hash, hash) && token.ExpiresAt.After(now) {
			delete(r.passwordResets, key)
			return token.UserID, nil
		}
	}
	return "", ErrInvalidResetToken
}

func (r *MemoryUserRepository) SaveEmailVerification(_ context.Context, token EmailVerificationToken) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.users[token.UserID]; !ok {
		return ErrNotFound
	}
	for key, current := range r.emailVerifies {
		if current.UserID == token.UserID {
			delete(r.emailVerifies, key)
		}
	}
	token.Hash = append([]byte(nil), token.Hash...)
	r.emailVerifies[string(token.Hash)] = token
	return nil
}

func (r *MemoryUserRepository) VerifyEmail(_ context.Context, hash []byte, userID string, now time.Time) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for key, token := range r.emailVerifies {
		if !bytes.Equal(token.Hash, hash) || token.UserID != userID || !token.ExpiresAt.After(now) {
			continue
		}
		user, ok := r.users[userID]
		if !ok || user.Email == nil || !strings.EqualFold(*user.Email, token.Email) {
			return "", ErrInvalidVerificationToken
		}
		delete(r.emailVerifies, key)
		user.EmailVerified = true
		user.UpdatedAt = now.UTC()
		r.users[userID] = cloneUser(user)
		return userID, nil
	}
	return "", ErrInvalidVerificationToken
}

func (r *MemoryUserRepository) ResolveExternalIdentity(_ context.Context, profile ExternalProfile, now time.Time) (User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	key := profile.ProviderID + "\x00" + profile.Subject
	if external, ok := r.external[key]; ok {
		user, exists := r.users[external.UserID]
		if !exists {
			return User{}, ErrNotFound
		}
		external.Username = strings.TrimSpace(profile.Username)
		external.DisplayName = strings.TrimSpace(profile.DisplayName)
		external.Email = cloneEmail(profile.Email)
		external.EmailTrusted = profile.EmailTrusted
		external.EmailVerified = profile.EmailVerified
		external.LastAuthenticatedAt = now.UTC()
		r.external[key] = external
		if profile.EmailVerified && profile.Email != nil && user.Email != nil &&
			strings.EqualFold(*user.Email, *profile.Email) && !user.EmailVerified {
			user.EmailVerified = true
			user.UpdatedAt = now.UTC()
			r.users[user.ID] = cloneUser(user)
		}
		return cloneUser(user), nil
	}
	if profile.EmailTrusted && profile.Email != nil {
		for _, existing := range r.users {
			if existing.Email != nil && strings.EqualFold(*existing.Email, *profile.Email) {
				if profile.EmailVerified && !existing.EmailVerified {
					existing.EmailVerified = true
					existing.UpdatedAt = now.UTC()
					r.users[existing.ID] = cloneUser(existing)
				}
				external, err := newExternalIdentity(existing.ID, profile, now)
				if err != nil {
					return User{}, err
				}
				r.external[key] = external
				return cloneUser(existing), nil
			}
		}
	}

	user, err := NewExternalUser(profile, false, now)
	if err != nil {
		return User{}, err
	}
	for _, existing := range r.users {
		if strings.EqualFold(existing.Username, user.Username) ||
			(existing.Email != nil && user.Email != nil && strings.EqualFold(*existing.Email, *user.Email)) {
			user, err = NewExternalUser(profile, true, now)
			if err != nil {
				return User{}, err
			}
			break
		}
	}
	for _, existing := range r.users {
		if strings.EqualFold(existing.Username, user.Username) ||
			(existing.Email != nil && user.Email != nil && strings.EqualFold(*existing.Email, *user.Email)) {
			return User{}, ErrConflict
		}
	}
	if _, exists := r.users[user.ID]; exists {
		return User{}, ErrConflict
	}
	r.users[user.ID] = cloneUser(user)
	external, err := newExternalIdentity(user.ID, profile, now)
	if err != nil {
		delete(r.users, user.ID)
		return User{}, err
	}
	r.external[key] = external
	return cloneUser(user), nil
}

func (r *MemoryUserRepository) ListExternalIdentities(
	_ context.Context,
	userID string,
) ([]ExternalIdentity, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if _, exists := r.users[userID]; !exists {
		return nil, ErrNotFound
	}
	result := make([]ExternalIdentity, 0)
	for _, external := range r.external {
		if external.UserID == userID {
			result = append(result, cloneExternalIdentity(external))
		}
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].CreatedAt.Equal(result[j].CreatedAt) {
			return result[i].ID < result[j].ID
		}
		return result[i].CreatedAt.Before(result[j].CreatedAt)
	})
	return result, nil
}

func (r *MemoryUserRepository) DeleteExternalIdentity(
	_ context.Context,
	userID, externalIdentityID string,
) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.users[userID]; !exists {
		return ErrNotFound
	}
	targetKey := ""
	for key, external := range r.external {
		if external.ID == externalIdentityID && external.UserID == userID {
			targetKey = key
			break
		}
	}
	if targetKey == "" {
		return ErrExternalIdentityMissing
	}
	alternatives := 0
	if _, exists := r.credentials[userID]; exists {
		alternatives++
	}
	for key, external := range r.external {
		if key != targetKey && external.UserID == userID {
			alternatives++
		}
	}
	if alternatives == 0 {
		return ErrLastAuthentication
	}
	delete(r.external, targetKey)
	return nil
}

func (r *MemoryUserRepository) FindByUsername(_ context.Context, username string) (User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, user := range r.users {
		if strings.EqualFold(user.Username, username) {
			return cloneUser(user), nil
		}
	}
	return User{}, ErrNotFound
}

func (r *MemoryUserRepository) List(_ context.Context, filter UserFilter) (UserPage, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	query := strings.ToLower(strings.TrimSpace(filter.Query))
	matches := make([]User, 0, len(r.users))
	for _, user := range r.users {
		if filter.Status != "" && user.Status != filter.Status {
			continue
		}
		if query != "" &&
			!strings.Contains(strings.ToLower(user.Username), query) &&
			!strings.Contains(strings.ToLower(user.DisplayName), query) &&
			(user.Email == nil || !strings.Contains(strings.ToLower(*user.Email), query)) {
			continue
		}
		matches = append(matches, cloneUser(user))
	}
	sort.Slice(matches, func(i, j int) bool {
		if matches[i].CreatedAt.Equal(matches[j].CreatedAt) {
			return matches[i].ID < matches[j].ID
		}
		return matches[i].CreatedAt.After(matches[j].CreatedAt)
	})
	total := int64(len(matches))
	start := min(filter.Offset, len(matches))
	end := min(start+filter.Limit, len(matches))
	return UserPage{Items: matches[start:end], Total: total, Limit: filter.Limit, Offset: filter.Offset}, nil
}

func (r *MemoryUserRepository) Find(_ context.Context, id string) (User, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	user, ok := r.users[id]
	if !ok {
		return User{}, ErrNotFound
	}
	return cloneUser(user), nil
}

func (r *MemoryUserRepository) Create(_ context.Context, user User) (User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, existing := range r.users {
		if strings.EqualFold(existing.Username, user.Username) ||
			(existing.Email != nil && user.Email != nil && strings.EqualFold(*existing.Email, *user.Email)) {
			return User{}, ErrConflict
		}
	}
	r.users[user.ID] = cloneUser(user)
	return cloneUser(user), nil
}

func (r *MemoryUserRepository) CreateWithPassword(
	_ context.Context,
	user User,
	hash string,
	_ time.Time,
) (User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, existing := range r.users {
		if strings.EqualFold(existing.Username, user.Username) ||
			(existing.Email != nil && user.Email != nil && strings.EqualFold(*existing.Email, *user.Email)) {
			return User{}, ErrConflict
		}
	}
	if _, exists := r.users[user.ID]; exists {
		return User{}, ErrConflict
	}
	r.users[user.ID] = cloneUser(user)
	r.credentials[user.ID] = PasswordCredential{UserID: user.ID, Hash: hash}
	return cloneUser(user), nil
}

func (r *MemoryUserRepository) CreateWithMigratedPasswords(
	_ context.Context,
	records []PasswordMigrationRecord,
	_ time.Time,
) ([]User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	usernames := make(map[string]struct{}, len(r.users)+len(records))
	emails := make(map[string]struct{}, len(r.users)+len(records))
	ids := make(map[string]struct{}, len(r.users)+len(records))
	for _, existing := range r.users {
		usernames[strings.ToLower(existing.Username)] = struct{}{}
		ids[existing.ID] = struct{}{}
		if existing.Email != nil {
			emails[strings.ToLower(*existing.Email)] = struct{}{}
		}
	}
	for _, record := range records {
		username := strings.ToLower(record.User.Username)
		if _, conflict := usernames[username]; conflict {
			return nil, ErrConflict
		}
		usernames[username] = struct{}{}
		if _, conflict := ids[record.User.ID]; conflict {
			return nil, ErrConflict
		}
		ids[record.User.ID] = struct{}{}
		if record.User.Email != nil {
			email := strings.ToLower(*record.User.Email)
			if _, conflict := emails[email]; conflict {
				return nil, ErrConflict
			}
			emails[email] = struct{}{}
		}
	}

	created := make([]User, 0, len(records))
	for _, record := range records {
		r.users[record.User.ID] = cloneUser(record.User)
		r.credentials[record.User.ID] = PasswordCredential{
			UserID: record.User.ID,
			Hash:   record.PasswordHash,
		}
		created = append(created, cloneUser(record.User))
	}
	return created, nil
}

func (r *MemoryUserRepository) Replace(_ context.Context, user User) (User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	current, ok := r.users[user.ID]
	if !ok {
		return User{}, ErrNotFound
	}
	if user.Email == nil || current.Email == nil || !strings.EqualFold(*current.Email, *user.Email) {
		user.EmailVerified = false
	}
	for id, existing := range r.users {
		if id != user.ID && existing.Email != nil && user.Email != nil && strings.EqualFold(*existing.Email, *user.Email) {
			return User{}, ErrConflict
		}
	}
	r.users[user.ID] = cloneUser(user)
	return cloneUser(user), nil
}

func (r *MemoryUserRepository) SetEmailVerified(_ context.Context, userID string, now time.Time) (User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	user, ok := r.users[userID]
	if !ok {
		return User{}, ErrNotFound
	}
	user.EmailVerified = true
	user.UpdatedAt = now.UTC()
	r.users[userID] = cloneUser(user)
	return cloneUser(user), nil
}

func (r *MemoryUserRepository) SetPassword(_ context.Context, userID, hash string, _ time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.users[userID]; !ok {
		return ErrNotFound
	}
	r.credentials[userID] = PasswordCredential{UserID: userID, Hash: hash}
	return nil
}

func (r *MemoryUserRepository) FindPasswordByUsername(_ context.Context, username string) (User, PasswordCredential, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, user := range r.users {
		if !strings.EqualFold(user.Username, username) {
			continue
		}
		credential, ok := r.credentials[user.ID]
		if !ok {
			return User{}, PasswordCredential{}, ErrNotFound
		}
		return cloneUser(user), credential, nil
	}
	return User{}, PasswordCredential{}, ErrNotFound
}

func (r *MemoryUserRepository) RecordPasswordFailure(_ context.Context, userID string, _ time.Time, attempts int, lockedUntil time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	credential, ok := r.credentials[userID]
	if !ok {
		return ErrNotFound
	}
	credential.FailedAttempts = attempts
	if !lockedUntil.IsZero() {
		value := lockedUntil
		credential.LockedUntil = &value
	}
	r.credentials[userID] = credential
	return nil
}

func (r *MemoryUserRepository) RecordPasswordSuccess(_ context.Context, userID string, _ time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	credential, ok := r.credentials[userID]
	if !ok {
		return ErrNotFound
	}
	credential.FailedAttempts = 0
	credential.LockedUntil = nil
	r.credentials[userID] = credential
	return nil
}

func cloneUser(user User) User {
	if user.Email != nil {
		email := *user.Email
		user.Email = &email
	}
	return user
}

func newExternalIdentity(
	userID string,
	profile ExternalProfile,
	now time.Time,
) (ExternalIdentity, error) {
	id, err := newUUID()
	if err != nil {
		return ExternalIdentity{}, fmt.Errorf("generate external identity ID: %w", err)
	}
	now = now.UTC()
	return ExternalIdentity{
		ID:                  id,
		UserID:              userID,
		ProviderID:          strings.TrimSpace(profile.ProviderID),
		Subject:             strings.TrimSpace(profile.Subject),
		Username:            strings.TrimSpace(profile.Username),
		DisplayName:         strings.TrimSpace(profile.DisplayName),
		Email:               cloneEmail(profile.Email),
		EmailTrusted:        profile.EmailTrusted,
		EmailVerified:       profile.EmailVerified,
		CreatedAt:           now,
		LastAuthenticatedAt: now,
	}, nil
}

func cloneExternalIdentity(external ExternalIdentity) ExternalIdentity {
	external.Email = cloneEmail(external.Email)
	return external
}

func cloneEmail(value *string) *string {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}
