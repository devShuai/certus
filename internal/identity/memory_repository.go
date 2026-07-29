package identity

import (
	"context"
	"sort"
	"strings"
	"sync"
)

type MemoryUserRepository struct {
	mu    sync.RWMutex
	users map[string]User
}

func NewMemoryUserRepository(users ...User) *MemoryUserRepository {
	repository := &MemoryUserRepository{users: make(map[string]User, len(users))}
	for _, user := range users {
		repository.users[user.ID] = cloneUser(user)
	}
	return repository
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

func cloneUser(user User) User {
	if user.Email != nil {
		email := *user.Email
		user.Email = &email
	}
	return user
}
