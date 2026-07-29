package access

import (
	"context"
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
