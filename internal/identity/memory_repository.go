package identity

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"
)

type MemoryUserRepository struct {
	mu          sync.RWMutex
	users       map[string]User
	credentials map[string]PasswordCredential
	external    map[string]string
}

func NewMemoryUserRepository(users ...User) *MemoryUserRepository {
	repository := &MemoryUserRepository{
		users:       make(map[string]User, len(users)),
		credentials: make(map[string]PasswordCredential),
		external:    make(map[string]string),
	}
	for _, user := range users {
		repository.users[user.ID] = cloneUser(user)
	}
	return repository
}

func (r *MemoryUserRepository) ResolveExternalIdentity(_ context.Context, profile ExternalProfile, now time.Time) (User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	key := profile.ProviderID + "\x00" + profile.Subject
	if userID, ok := r.external[key]; ok {
		user, exists := r.users[userID]
		if !exists {
			return User{}, ErrNotFound
		}
		return cloneUser(user), nil
	}
	if profile.EmailTrusted && profile.Email != nil {
		for _, existing := range r.users {
			if existing.Email != nil && strings.EqualFold(*existing.Email, *profile.Email) {
				r.external[key] = existing.ID
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
	r.external[key] = user.ID
	return cloneUser(user), nil
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

func (r *MemoryUserRepository) Replace(_ context.Context, user User) (User, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.users[user.ID]; !ok {
		return User{}, ErrNotFound
	}
	for id, existing := range r.users {
		if id != user.ID && existing.Email != nil && user.Email != nil && strings.EqualFold(*existing.Email, *user.Email) {
			return User{}, ErrConflict
		}
	}
	r.users[user.ID] = cloneUser(user)
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
