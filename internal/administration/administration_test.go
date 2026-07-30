package administration

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRolePermissionsAndLastSuperAdmin(t *testing.T) {
	repository := NewMemoryRepository()
	ctx := context.Background()
	now := time.Now().UTC()
	if err := repository.ReplaceUserRoles(
		ctx, "user-a", []Role{RoleSuperAdmin}, "emergency-token", now,
	); err != nil {
		t.Fatal(err)
	}
	access, err := repository.Effective(ctx, "user-a")
	if err != nil || !access.Has(PermissionAdminRolesWrite) {
		t.Fatalf("super administrator did not receive all permissions: %#v %v", access, err)
	}
	if err := repository.ReplaceUserRoles(
		ctx, "user-a", []Role{RoleAuditor}, "user-a", now,
	); !errors.Is(err, ErrLastSuperAdmin) {
		t.Fatalf("last super administrator could be removed: %v", err)
	}
	if err := repository.ReplaceUserRoles(
		ctx, "user-b", []Role{RoleSuperAdmin}, "user-a", now,
	); err != nil {
		t.Fatal(err)
	}
	if err := repository.ReplaceUserRoles(
		ctx, "user-a", []Role{RoleAuditor}, "user-b", now,
	); err != nil {
		t.Fatalf("super administrator could not be removed after a replacement existed: %v", err)
	}
	access, err = repository.Effective(ctx, "user-a")
	if err != nil || !access.Has(PermissionAuditRead) || access.Has(PermissionUsersWrite) {
		t.Fatalf("auditor permissions are incorrect: %#v %v", access, err)
	}
}

func TestRejectsUnknownAndDuplicateRoles(t *testing.T) {
	for _, roles := range [][]Role{
		{"unknown"},
		{RoleAuditor, RoleAuditor},
	} {
		if err := ValidateRoles(roles); !errors.Is(err, ErrInvalid) {
			t.Fatalf("roles were accepted: %#v %v", roles, err)
		}
	}
}
