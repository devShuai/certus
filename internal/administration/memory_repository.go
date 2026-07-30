package administration

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"
)

type MemoryRepository struct {
	mu     sync.RWMutex
	grants map[string][]Grant
}

func NewMemoryRepository() *MemoryRepository {
	return &MemoryRepository{grants: make(map[string][]Grant)}
}

func (r *MemoryRepository) ListUserRoles(_ context.Context, userID string) ([]Grant, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return cloneGrants(r.grants[userID]), nil
}

func (r *MemoryRepository) ListRoleUsers(_ context.Context, role Role) ([]string, error) {
	if !ValidRole(role) {
		return nil, ErrInvalid
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]string, 0)
	for userID, grants := range r.grants {
		if HasRole(grantRoles(grants), role) {
			result = append(result, userID)
		}
	}
	sort.Strings(result)
	return result, nil
}

func (r *MemoryRepository) ReplaceUserRoles(
	_ context.Context,
	userID string,
	roles []Role,
	grantedBy string,
	now time.Time,
) error {
	if err := ValidateRoles(roles); err != nil {
		return err
	}
	if strings.TrimSpace(userID) == "" || strings.TrimSpace(grantedBy) == "" {
		return ErrInvalid
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if HasRole(grantRoles(r.grants[userID]), RoleSuperAdmin) &&
		!HasRole(roles, RoleSuperAdmin) &&
		r.superAdminCountLocked() <= 1 {
		return ErrLastSuperAdmin
	}
	values := make([]Grant, 0, len(roles))
	for _, role := range roles {
		values = append(values, Grant{
			UserID:    userID,
			Role:      role,
			GrantedAt: now.UTC(),
			GrantedBy: grantedBy,
		})
	}
	r.grants[userID] = values
	return nil
}

func (r *MemoryRepository) Effective(_ context.Context, userID string) (Access, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return AccessFor(userID, grantRoles(r.grants[userID])), nil
}

func (r *MemoryRepository) superAdminCountLocked() int {
	count := 0
	for _, values := range r.grants {
		if HasRole(grantRoles(values), RoleSuperAdmin) {
			count++
		}
	}
	return count
}

func grantRoles(values []Grant) []Role {
	result := make([]Role, 0, len(values))
	for _, value := range values {
		result = append(result, value.Role)
	}
	return result
}

func cloneGrants(values []Grant) []Grant {
	result := append([]Grant(nil), values...)
	sort.Slice(result, func(i, j int) bool { return result[i].Role < result[j].Role })
	return result
}
