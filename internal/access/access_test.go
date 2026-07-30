package access

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestEffectiveEntitlementsAreClientScopedAndExpire(t *testing.T) {
	repository := NewMemoryRepository()
	now := time.Now().UTC()
	financeRole, err := NewRole("finance", CreateRole{Code: "approver", Name: "审批人"}, now)
	if err != nil {
		t.Fatal(err)
	}
	hrRole, err := NewRole("hr", CreateRole{Code: "viewer", Name: "查看者"}, now)
	if err != nil {
		t.Fatal(err)
	}
	permission, err := NewPermission("finance", CreatePermission{Code: "invoice.approve", Name: "审批发票"}, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, role := range []Role{financeRole, hrRole} {
		if _, err := repository.CreateRole(context.Background(), role); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := repository.CreatePermission(context.Background(), permission); err != nil {
		t.Fatal(err)
	}
	if err := repository.SetRolePermissions(context.Background(), "finance", financeRole.ID, []string{permission.ID}); err != nil {
		t.Fatal(err)
	}
	expiresAt := now.Add(time.Minute)
	if err := repository.ReplaceUserRoles(context.Background(), "user", []RoleGrant{
		{RoleID: financeRole.ID, ExpiresAt: &expiresAt},
		{RoleID: hrRole.ID},
	}, "admin", now); err != nil {
		t.Fatal(err)
	}

	finance, err := repository.Effective(context.Background(), "user", "finance", now)
	if err != nil {
		t.Fatal(err)
	}
	if len(finance.Roles) != 1 || finance.Roles[0] != "approver" ||
		len(finance.Permissions) != 1 || finance.Permissions[0] != "invoice.approve" {
		t.Fatalf("unexpected finance entitlements: %#v", finance)
	}
	hr, err := repository.Effective(context.Background(), "user", "hr", now)
	if err != nil {
		t.Fatal(err)
	}
	if len(hr.Roles) != 1 || hr.Roles[0] != "viewer" || len(hr.Permissions) != 0 {
		t.Fatalf("client isolation failed: %#v", hr)
	}
	expired, err := repository.Effective(context.Background(), "user", "finance", now.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if len(expired.Roles) != 0 || len(expired.Permissions) != 0 {
		t.Fatalf("expired grant remained active: %#v", expired)
	}
}

func TestDefinitionLifecycleProtectsReferencedAccess(t *testing.T) {
	ctx := context.Background()
	repository := NewMemoryRepository()
	now := time.Date(2026, time.July, 30, 8, 0, 0, 0, time.UTC)
	role, err := NewRole("finance", CreateRole{Code: "approver", Name: "审批人"}, now)
	if err != nil {
		t.Fatal(err)
	}
	permission, err := NewPermission("finance", CreatePermission{Code: "invoice.approve", Name: "审批发票"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if role, err = repository.CreateRole(ctx, role); err != nil {
		t.Fatal(err)
	}
	if permission, err = repository.CreatePermission(ctx, permission); err != nil {
		t.Fatal(err)
	}

	updatedRole, err := role.Updated(UpdateRole{
		Code:        "senior-approver",
		Name:        "高级审批人",
		Description: "负责大额发票",
	}, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	updatedRole, err = repository.ReplaceRole(ctx, updatedRole)
	if err != nil {
		t.Fatal(err)
	}
	if updatedRole.ID != role.ID || !updatedRole.CreatedAt.Equal(role.CreatedAt) ||
		updatedRole.Code != "senior-approver" || !updatedRole.UpdatedAt.Equal(now.Add(time.Minute)) {
		t.Fatalf("unexpected updated role: %#v", updatedRole)
	}
	foundRole, err := repository.FindRole(ctx, "finance", role.ID)
	if err != nil || foundRole != updatedRole {
		t.Fatalf("find updated role: %#v, %v", foundRole, err)
	}

	duplicate, err := NewRole("finance", CreateRole{Code: "viewer", Name: "查看者"}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.CreateRole(ctx, duplicate); err != nil {
		t.Fatal(err)
	}
	duplicateCode, err := duplicate.Updated(UpdateRole{Code: updatedRole.Code, Name: duplicate.Name}, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.ReplaceRole(ctx, duplicateCode); !errors.Is(err, ErrConflict) {
		t.Fatalf("replace with duplicate role code: %v", err)
	}

	updatedPermission, err := permission.Updated(UpdatePermission{
		Code:        "invoice.approve.high-value",
		Name:        "审批大额发票",
		Description: "大额发票审批权限",
	}, now.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := repository.ReplacePermission(ctx, updatedPermission); err != nil {
		t.Fatal(err)
	}
	if err := repository.SetRolePermissions(ctx, "finance", role.ID, []string{permission.ID}); err != nil {
		t.Fatal(err)
	}
	if err := repository.DeletePermission(ctx, "finance", permission.ID); !errors.Is(err, ErrInUse) {
		t.Fatalf("delete referenced permission: %v", err)
	}
	if err := repository.ReplaceUserRoles(ctx, "user", []RoleGrant{{RoleID: role.ID}}, "admin", now); err != nil {
		t.Fatal(err)
	}
	if err := repository.DeleteRole(ctx, "finance", role.ID); !errors.Is(err, ErrInUse) {
		t.Fatalf("delete assigned role: %v", err)
	}

	if err := repository.SetRolePermissions(ctx, "finance", role.ID, nil); err != nil {
		t.Fatal(err)
	}
	if err := repository.DeletePermission(ctx, "finance", permission.ID); err != nil {
		t.Fatal(err)
	}
	if err := repository.ReplaceUserRoles(ctx, "user", nil, "admin", now); err != nil {
		t.Fatal(err)
	}
	if err := repository.DeleteRole(ctx, "finance", role.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := repository.FindRole(ctx, "finance", role.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("find deleted role: %v", err)
	}
	if _, err := repository.FindPermission(ctx, "finance", permission.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("find deleted permission: %v", err)
	}
}
