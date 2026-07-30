package administration

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"
)

var (
	ErrNotFound       = errors.New("administrator grant not found")
	ErrInvalid        = errors.New("invalid administrator role")
	ErrLastSuperAdmin = errors.New("cannot remove the last super administrator")
)

type Role string

const (
	RoleSuperAdmin       Role = "super_admin"
	RoleIdentityAdmin    Role = "identity_admin"
	RoleApplicationAdmin Role = "application_admin"
	RoleSecurityAdmin    Role = "security_admin"
	RoleAuditor          Role = "auditor"
)

type Permission string

const (
	PermissionAll                Permission = "*"
	PermissionUsersRead          Permission = "admin.users.read"
	PermissionUsersWrite         Permission = "admin.users.write"
	PermissionClientsRead        Permission = "admin.clients.read"
	PermissionClientsWrite       Permission = "admin.clients.write"
	PermissionAccessRead         Permission = "admin.access.read"
	PermissionAccessWrite        Permission = "admin.access.write"
	PermissionAuditRead          Permission = "admin.audit.read"
	PermissionSecurityRead       Permission = "admin.security.read"
	PermissionSecurityWrite      Permission = "admin.security.write"
	PermissionMaintenanceExecute Permission = "admin.maintenance.execute"
	PermissionAdminRolesRead     Permission = "admin.roles.read"
	PermissionAdminRolesWrite    Permission = "admin.roles.write"
)

type RoleDefinition struct {
	Code        Role         `json:"code"`
	Name        string       `json:"name"`
	Description string       `json:"description"`
	Permissions []Permission `json:"permissions"`
}

type Grant struct {
	UserID    string    `json:"user_id"`
	Role      Role      `json:"role"`
	GrantedAt time.Time `json:"granted_at"`
	GrantedBy string    `json:"granted_by"`
}

type Access struct {
	UserID      string       `json:"user_id,omitempty"`
	Roles       []Role       `json:"roles"`
	Permissions []Permission `json:"permissions"`
}

type Repository interface {
	ListUserRoles(context.Context, string) ([]Grant, error)
	ListRoleUsers(context.Context, Role) ([]string, error)
	ReplaceUserRoles(context.Context, string, []Role, string, time.Time) error
	Effective(context.Context, string) (Access, error)
}

var definitions = []RoleDefinition{
	{
		Code:        RoleSuperAdmin,
		Name:        "超级管理员",
		Description: "拥有全部后台权限，并可分配管理员角色。",
		Permissions: []Permission{PermissionAll},
	},
	{
		Code:        RoleIdentityAdmin,
		Name:        "身份管理员",
		Description: "管理用户、密码、会话与多因素认证。",
		Permissions: []Permission{
			PermissionUsersRead,
			PermissionUsersWrite,
		},
	},
	{
		Code:        RoleApplicationAdmin,
		Name:        "应用管理员",
		Description: "管理接入系统以及业务角色与权限。",
		Permissions: []Permission{
			PermissionClientsRead,
			PermissionClientsWrite,
			PermissionAccessRead,
			PermissionAccessWrite,
			PermissionUsersRead,
		},
	},
	{
		Code:        RoleSecurityAdmin,
		Name:        "安全管理员",
		Description: "管理签名密钥、清理任务并审阅安全事件。",
		Permissions: []Permission{
			PermissionSecurityRead,
			PermissionSecurityWrite,
			PermissionMaintenanceExecute,
			PermissionAuditRead,
			PermissionUsersRead,
		},
	},
	{
		Code:        RoleAuditor,
		Name:        "审计员",
		Description: "只读访问用户、客户端、安全状态与审计日志。",
		Permissions: []Permission{
			PermissionUsersRead,
			PermissionClientsRead,
			PermissionAccessRead,
			PermissionAuditRead,
			PermissionSecurityRead,
			PermissionAdminRolesRead,
		},
	},
}

func Definitions() []RoleDefinition {
	result := make([]RoleDefinition, len(definitions))
	for index, value := range definitions {
		result[index] = value
		result[index].Permissions = append([]Permission(nil), value.Permissions...)
	}
	return result
}

func ValidateRoles(roles []Role) error {
	seen := make(map[Role]struct{}, len(roles))
	for _, role := range roles {
		if !ValidRole(role) {
			return fmt.Errorf("%w: %q", ErrInvalid, role)
		}
		if _, duplicate := seen[role]; duplicate {
			return fmt.Errorf("%w: duplicate role %q", ErrInvalid, role)
		}
		seen[role] = struct{}{}
	}
	return nil
}

func ValidRole(role Role) bool {
	for _, definition := range definitions {
		if definition.Code == role {
			return true
		}
	}
	return false
}

func AccessFor(userID string, roles []Role) Access {
	roleSet := make(map[Role]struct{}, len(roles))
	permissionSet := make(map[Permission]struct{})
	for _, role := range roles {
		if !ValidRole(role) {
			continue
		}
		roleSet[role] = struct{}{}
		for _, definition := range definitions {
			if definition.Code != role {
				continue
			}
			for _, permission := range definition.Permissions {
				permissionSet[permission] = struct{}{}
			}
		}
	}
	result := Access{
		UserID:      strings.TrimSpace(userID),
		Roles:       make([]Role, 0, len(roleSet)),
		Permissions: make([]Permission, 0, len(permissionSet)),
	}
	for role := range roleSet {
		result.Roles = append(result.Roles, role)
	}
	for permission := range permissionSet {
		result.Permissions = append(result.Permissions, permission)
	}
	sort.Slice(result.Roles, func(i, j int) bool { return result.Roles[i] < result.Roles[j] })
	sort.Slice(result.Permissions, func(i, j int) bool {
		return result.Permissions[i] < result.Permissions[j]
	})
	return result
}

func (a Access) Has(permission Permission) bool {
	return slices.Contains(a.Permissions, PermissionAll) ||
		permission == "" ||
		slices.Contains(a.Permissions, permission)
}

func HasRole(roles []Role, expected Role) bool {
	return slices.Contains(roles, expected)
}
