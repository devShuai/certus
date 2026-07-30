package access

import (
	"context"
	"sort"
	"sync"
	"time"
)

type memoryUserRole struct {
	UserID    string
	RoleID    string
	GrantedAt time.Time
	GrantedBy string
	ExpiresAt *time.Time
}

type MemoryRepository struct {
	mu              sync.RWMutex
	roles           map[string]Role
	permissions     map[string]Permission
	rolePermissions map[string]map[string]struct{}
	userRoles       []memoryUserRole
}

func NewMemoryRepository() *MemoryRepository {
	return &MemoryRepository{
		roles:           make(map[string]Role),
		permissions:     make(map[string]Permission),
		rolePermissions: make(map[string]map[string]struct{}),
	}
}

func (r *MemoryRepository) ListRoles(_ context.Context, clientID string) ([]Role, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]Role, 0)
	for _, role := range r.roles {
		if role.ClientID == clientID {
			result = append(result, role)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Code < result[j].Code
	})
	return result, nil
}

func (r *MemoryRepository) CreateRole(_ context.Context, value Role) (Role, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, existing := range r.roles {
		if existing.ClientID == value.ClientID && existing.Code == value.Code {
			return Role{}, ErrConflict
		}
	}
	r.roles[value.ID] = value
	return value, nil
}

func (r *MemoryRepository) FindRole(_ context.Context, clientID, roleID string) (Role, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	value, exists := r.roles[roleID]
	if !exists || value.ClientID != clientID {
		return Role{}, ErrNotFound
	}
	return value, nil
}

func (r *MemoryRepository) ReplaceRole(_ context.Context, value Role) (Role, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	current, exists := r.roles[value.ID]
	if !exists || current.ClientID != value.ClientID {
		return Role{}, ErrNotFound
	}
	for id, existing := range r.roles {
		if id != value.ID && existing.ClientID == value.ClientID && existing.Code == value.Code {
			return Role{}, ErrConflict
		}
	}
	r.roles[value.ID] = value
	return value, nil
}

func (r *MemoryRepository) DeleteRole(_ context.Context, clientID, roleID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	value, exists := r.roles[roleID]
	if !exists || value.ClientID != clientID {
		return ErrNotFound
	}
	for _, assignment := range r.userRoles {
		if assignment.RoleID == roleID {
			return ErrInUse
		}
	}
	delete(r.roles, roleID)
	delete(r.rolePermissions, roleID)
	return nil
}

func (r *MemoryRepository) ListPermissions(_ context.Context, clientID string) ([]Permission, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]Permission, 0)
	for _, permission := range r.permissions {
		if permission.ClientID == clientID {
			result = append(result, permission)
		}
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Code < result[j].Code
	})
	return result, nil
}

func (r *MemoryRepository) CreatePermission(_ context.Context, value Permission) (Permission, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, existing := range r.permissions {
		if existing.ClientID == value.ClientID && existing.Code == value.Code {
			return Permission{}, ErrConflict
		}
	}
	r.permissions[value.ID] = value
	return value, nil
}

func (r *MemoryRepository) FindPermission(_ context.Context, clientID, permissionID string) (Permission, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	value, exists := r.permissions[permissionID]
	if !exists || value.ClientID != clientID {
		return Permission{}, ErrNotFound
	}
	return value, nil
}

func (r *MemoryRepository) ReplacePermission(_ context.Context, value Permission) (Permission, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	current, exists := r.permissions[value.ID]
	if !exists || current.ClientID != value.ClientID {
		return Permission{}, ErrNotFound
	}
	for id, existing := range r.permissions {
		if id != value.ID && existing.ClientID == value.ClientID && existing.Code == value.Code {
			return Permission{}, ErrConflict
		}
	}
	r.permissions[value.ID] = value
	return value, nil
}

func (r *MemoryRepository) DeletePermission(_ context.Context, clientID, permissionID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	value, exists := r.permissions[permissionID]
	if !exists || value.ClientID != clientID {
		return ErrNotFound
	}
	for _, permissionIDs := range r.rolePermissions {
		if _, assigned := permissionIDs[permissionID]; assigned {
			return ErrInUse
		}
	}
	delete(r.permissions, permissionID)
	return nil
}

func (r *MemoryRepository) SetRolePermissions(_ context.Context, clientID, roleID string, permissionIDs []string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	role, exists := r.roles[roleID]
	if !exists || role.ClientID != clientID {
		return ErrNotFound
	}
	values := make(map[string]struct{}, len(permissionIDs))
	for _, permissionID := range permissionIDs {
		permission, exists := r.permissions[permissionID]
		if !exists || permission.ClientID != clientID {
			return ErrNotFound
		}
		values[permissionID] = struct{}{}
	}
	r.rolePermissions[roleID] = values
	return nil
}

func (r *MemoryRepository) ListRolePermissions(_ context.Context, clientID, roleID string) ([]Permission, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	role, exists := r.roles[roleID]
	if !exists || role.ClientID != clientID {
		return nil, ErrNotFound
	}
	result := make([]Permission, 0)
	for permissionID := range r.rolePermissions[roleID] {
		result = append(result, r.permissions[permissionID])
	}
	sort.Slice(result, func(i, j int) bool {
		return result[i].Code < result[j].Code
	})
	return result, nil
}

func (r *MemoryRepository) ReplaceUserRoles(_ context.Context, userID string, grants []RoleGrant, grantedBy string, now time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, grant := range grants {
		if _, exists := r.roles[grant.RoleID]; !exists {
			return ErrNotFound
		}
	}
	result := r.userRoles[:0]
	for _, value := range r.userRoles {
		if value.UserID != userID {
			result = append(result, value)
		}
	}
	for _, grant := range grants {
		var expiresAt *time.Time
		if grant.ExpiresAt != nil {
			value := grant.ExpiresAt.UTC()
			expiresAt = &value
		}
		result = append(result, memoryUserRole{
			UserID:    userID,
			RoleID:    grant.RoleID,
			GrantedAt: now.UTC(),
			GrantedBy: grantedBy,
			ExpiresAt: expiresAt,
		})
	}
	r.userRoles = result
	return nil
}

func (r *MemoryRepository) ListUserRoles(_ context.Context, userID, clientID string, includeExpired bool, now time.Time) ([]UserRole, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make([]UserRole, 0)
	for _, value := range r.userRoles {
		role, exists := r.roles[value.RoleID]
		if !exists || value.UserID != userID || clientID != "" && role.ClientID != clientID {
			continue
		}
		if !includeExpired && value.ExpiresAt != nil && !value.ExpiresAt.After(now) {
			continue
		}
		result = append(result, UserRole{
			UserID:    userID,
			Role:      role,
			GrantedAt: value.GrantedAt,
			GrantedBy: value.GrantedBy,
			ExpiresAt: cloneTime(value.ExpiresAt),
		})
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Role.ClientID == result[j].Role.ClientID {
			return result[i].Role.Code < result[j].Role.Code
		}
		return result[i].Role.ClientID < result[j].Role.ClientID
	})
	return result, nil
}

func (r *MemoryRepository) Effective(ctx context.Context, userID, clientID string, now time.Time) (Entitlements, error) {
	assignments, err := r.ListUserRoles(ctx, userID, clientID, false, now)
	if err != nil {
		return Entitlements{}, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	roleCodes := make([]string, 0, len(assignments))
	permissionSet := make(map[string]struct{})
	for _, assignment := range assignments {
		roleCodes = append(roleCodes, assignment.Role.Code)
		for permissionID := range r.rolePermissions[assignment.Role.ID] {
			if permission, exists := r.permissions[permissionID]; exists && permission.ClientID == clientID {
				permissionSet[permission.Code] = struct{}{}
			}
		}
	}
	permissionCodes := make([]string, 0, len(permissionSet))
	for code := range permissionSet {
		permissionCodes = append(permissionCodes, code)
	}
	sort.Strings(roleCodes)
	sort.Strings(permissionCodes)
	return Entitlements{
		UserID:      userID,
		ClientID:    clientID,
		Roles:       roleCodes,
		Permissions: permissionCodes,
	}, nil
}

func cloneTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}
