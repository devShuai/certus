package access

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"certus/internal/security"
)

var (
	ErrNotFound = errors.New("access object not found")
	ErrConflict = errors.New("access object already exists")
	ErrInvalid  = errors.New("invalid access object")
)

type Role struct {
	ID          string    `json:"id"`
	ClientID    string    `json:"client_id"`
	Code        string    `json:"code"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type Permission struct {
	ID          string    `json:"id"`
	ClientID    string    `json:"client_id"`
	Code        string    `json:"code"`
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type CreateRole struct {
	Code        string `json:"code"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

type CreatePermission struct {
	Code        string `json:"code"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

type RoleGrant struct {
	RoleID    string     `json:"role_id"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

type UserRole struct {
	UserID    string     `json:"user_id"`
	Role      Role       `json:"role"`
	GrantedAt time.Time  `json:"granted_at"`
	GrantedBy string     `json:"granted_by"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

type Entitlements struct {
	UserID      string   `json:"user_id"`
	ClientID    string   `json:"client_id"`
	Roles       []string `json:"roles"`
	Permissions []string `json:"permissions"`
}

type Repository interface {
	ListRoles(context.Context, string) ([]Role, error)
	CreateRole(context.Context, Role) (Role, error)
	ListPermissions(context.Context, string) ([]Permission, error)
	CreatePermission(context.Context, Permission) (Permission, error)
	SetRolePermissions(context.Context, string, string, []string) error
	ListRolePermissions(context.Context, string, string) ([]Permission, error)
	ReplaceUserRoles(context.Context, string, []RoleGrant, string, time.Time) error
	ListUserRoles(context.Context, string, string, bool, time.Time) ([]UserRole, error)
	Effective(context.Context, string, string, time.Time) (Entitlements, error)
}

var codePattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{1,63}$`)

func NewRole(clientID string, input CreateRole, now time.Time) (Role, error) {
	id, err := security.RandomUUID()
	if err != nil {
		return Role{}, err
	}
	code, name, description, err := validateDefinition(clientID, input.Code, input.Name, input.Description)
	if err != nil {
		return Role{}, err
	}
	now = now.UTC()
	return Role{
		ID:          id,
		ClientID:    strings.TrimSpace(clientID),
		Code:        code,
		Name:        name,
		Description: description,
		CreatedAt:   now,
		UpdatedAt:   now,
	}, nil
}

func NewPermission(clientID string, input CreatePermission, now time.Time) (Permission, error) {
	id, err := security.RandomUUID()
	if err != nil {
		return Permission{}, err
	}
	code, name, description, err := validateDefinition(clientID, input.Code, input.Name, input.Description)
	if err != nil {
		return Permission{}, err
	}
	now = now.UTC()
	return Permission{
		ID:          id,
		ClientID:    strings.TrimSpace(clientID),
		Code:        code,
		Name:        name,
		Description: description,
		CreatedAt:   now,
		UpdatedAt:   now,
	}, nil
}

func ValidateRoleGrants(values []RoleGrant, now time.Time) error {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if strings.TrimSpace(value.RoleID) == "" {
			return fmt.Errorf("%w: role_id is required", ErrInvalid)
		}
		if _, exists := seen[value.RoleID]; exists {
			return fmt.Errorf("%w: duplicate role_id", ErrInvalid)
		}
		seen[value.RoleID] = struct{}{}
		if value.ExpiresAt != nil && !value.ExpiresAt.After(now) {
			return fmt.Errorf("%w: expires_at must be in the future", ErrInvalid)
		}
	}
	return nil
}

func validateDefinition(clientID, rawCode, rawName, rawDescription string) (string, string, string, error) {
	if strings.TrimSpace(clientID) == "" {
		return "", "", "", fmt.Errorf("%w: client_id is required", ErrInvalid)
	}
	code := strings.ToLower(strings.TrimSpace(rawCode))
	name := strings.TrimSpace(rawName)
	description := strings.TrimSpace(rawDescription)
	if !codePattern.MatchString(code) {
		return "", "", "", fmt.Errorf("%w: code must be 2-64 lowercase letters, digits, dots, underscores or hyphens", ErrInvalid)
	}
	if name == "" || len([]rune(name)) > 128 {
		return "", "", "", fmt.Errorf("%w: name must be 1-128 characters", ErrInvalid)
	}
	if len([]rune(description)) > 512 {
		return "", "", "", fmt.Errorf("%w: description supports at most 512 characters", ErrInvalid)
	}
	return code, name, description, nil
}
