package httpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"certus/internal/access"
	"certus/internal/audit"
	"certus/internal/cas"
	"certus/internal/client"
	"certus/internal/config"
	"certus/internal/identity"
	"certus/internal/oauth"
	"certus/internal/oidc"
	"certus/internal/session"
)

func TestAccessManagementAndEffectiveQuery(t *testing.T) {
	registered, secret, err := client.New(client.CreateClient{
		ID:              "finance",
		Name:            "Finance",
		ApplicationType: client.ApplicationConfidential,
		Protocols:       []client.Protocol{client.ProtocolOAuth21},
		GrantTypes:      []client.GrantType{client.GrantClientCredentials},
		AllowedScopes:   []string{"openid", "roles", "api.read"},
	})
	if err != nil {
		t.Fatal(err)
	}
	user, err := identity.NewUser(identity.CreateUser{
		Username:    "alice",
		DisplayName: "Alice",
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	users := identity.NewMemoryUserRepository(user)
	auditRepository := audit.NewMemoryRepository()
	handler, err := NewWithDependencies(
		context.Background(),
		config.Config{Issuer: "https://auth.example.com", AdminToken: "test-admin-token"},
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		Dependencies{
			Clients:   client.NewMemoryRepository(registered),
			Users:     users,
			Passwords: users,
			Sessions:  session.NewMemoryRepository(),
			OAuth:     oauth.NewMemoryRepository(),
			CAS:       cas.NewMemoryRepository(),
			Keys:      &oidc.MemoryKeyRepository{},
			Access:    access.NewMemoryRepository(),
			Audit:     auditRepository,
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	roleResponse := adminJSONRequest(t, handler, http.MethodPost, "/api/v1/admin/clients/finance/roles", `{
		"code":"approver",
		"name":"审批人"
	}`)
	if roleResponse.Code != http.StatusCreated {
		t.Fatalf("create role: %d %s", roleResponse.Code, roleResponse.Body.String())
	}
	var role access.Role
	if err := json.Unmarshal(roleResponse.Body.Bytes(), &role); err != nil {
		t.Fatal(err)
	}
	getRole := adminJSONRequest(t, handler, http.MethodGet, "/api/v1/admin/clients/finance/roles/"+role.ID, "")
	if getRole.Code != http.StatusOK || !strings.Contains(getRole.Body.String(), `"code":"approver"`) {
		t.Fatalf("get role: %d %s", getRole.Code, getRole.Body.String())
	}
	updateRole := adminJSONRequest(t, handler, http.MethodPut, "/api/v1/admin/clients/finance/roles/"+role.ID, `{
		"code":"senior-approver",
		"name":"高级审批人",
		"description":"负责大额发票"
	}`)
	if updateRole.Code != http.StatusOK {
		t.Fatalf("update role: %d %s", updateRole.Code, updateRole.Body.String())
	}
	permissionResponse := adminJSONRequest(t, handler, http.MethodPost, "/api/v1/admin/clients/finance/permissions", `{
		"code":"invoice.approve",
		"name":"审批发票"
	}`)
	if permissionResponse.Code != http.StatusCreated {
		t.Fatalf("create permission: %d %s", permissionResponse.Code, permissionResponse.Body.String())
	}
	var permission access.Permission
	if err := json.Unmarshal(permissionResponse.Body.Bytes(), &permission); err != nil {
		t.Fatal(err)
	}
	getPermission := adminJSONRequest(t, handler, http.MethodGet, "/api/v1/admin/clients/finance/permissions/"+permission.ID, "")
	if getPermission.Code != http.StatusOK || !strings.Contains(getPermission.Body.String(), `"code":"invoice.approve"`) {
		t.Fatalf("get permission: %d %s", getPermission.Code, getPermission.Body.String())
	}
	updatePermission := adminJSONRequest(t, handler, http.MethodPut, "/api/v1/admin/clients/finance/permissions/"+permission.ID, `{
		"code":"invoice.approve.high-value",
		"name":"审批大额发票",
		"description":"只允许审批高金额发票"
	}`)
	if updatePermission.Code != http.StatusOK {
		t.Fatalf("update permission: %d %s", updatePermission.Code, updatePermission.Body.String())
	}
	mapping := adminJSONRequest(
		t,
		handler,
		http.MethodPut,
		"/api/v1/admin/clients/finance/roles/"+role.ID+"/permissions",
		fmt.Sprintf(`{"permission_ids":[%q]}`, permission.ID),
	)
	if mapping.Code != http.StatusNoContent {
		t.Fatalf("map role permissions: %d %s", mapping.Code, mapping.Body.String())
	}
	referencedPermission := adminJSONRequest(t, handler, http.MethodDelete, "/api/v1/admin/clients/finance/permissions/"+permission.ID, "")
	if referencedPermission.Code != http.StatusConflict || !strings.Contains(referencedPermission.Body.String(), `"code":"permission_in_use"`) {
		t.Fatalf("delete referenced permission: %d %s", referencedPermission.Code, referencedPermission.Body.String())
	}
	assignment := adminJSONRequest(
		t,
		handler,
		http.MethodPut,
		"/api/v1/admin/users/"+user.ID+"/roles",
		fmt.Sprintf(`{"roles":[{"role_id":%q}]}`, role.ID),
	)
	if assignment.Code != http.StatusNoContent {
		t.Fatalf("assign user role: %d %s", assignment.Code, assignment.Body.String())
	}
	assignedRole := adminJSONRequest(t, handler, http.MethodDelete, "/api/v1/admin/clients/finance/roles/"+role.ID, "")
	if assignedRole.Code != http.StatusConflict || !strings.Contains(assignedRole.Body.String(), `"code":"role_in_use"`) {
		t.Fatalf("delete assigned role: %d %s", assignedRole.Code, assignedRole.Body.String())
	}
	listed := adminJSONRequest(t, handler, http.MethodGet, "/api/v1/admin/users/"+user.ID+"/roles?client_id=finance", "")
	if listed.Code != http.StatusOK || !strings.Contains(listed.Body.String(), `"code":"senior-approver"`) {
		t.Fatalf("list user roles: %d %s", listed.Code, listed.Body.String())
	}

	effectiveRequest := httptest.NewRequest(http.MethodGet, "/api/v1/access/users/"+user.ID, nil)
	effectiveRequest.SetBasicAuth(registered.ID, secret)
	effective := httptest.NewRecorder()
	handler.ServeHTTP(effective, effectiveRequest)
	if effective.Code != http.StatusOK ||
		!strings.Contains(effective.Body.String(), `"roles":["senior-approver"]`) ||
		!strings.Contains(effective.Body.String(), `"permissions":["invoice.approve.high-value"]`) {
		t.Fatalf("effective access: %d %s", effective.Code, effective.Body.String())
	}

	unassign := adminJSONRequest(t, handler, http.MethodPut, "/api/v1/admin/users/"+user.ID+"/roles", `{"roles":[]}`)
	if unassign.Code != http.StatusNoContent {
		t.Fatalf("unassign user role: %d %s", unassign.Code, unassign.Body.String())
	}
	unmap := adminJSONRequest(t, handler, http.MethodPut, "/api/v1/admin/clients/finance/roles/"+role.ID+"/permissions", `{"permission_ids":[]}`)
	if unmap.Code != http.StatusNoContent {
		t.Fatalf("unmap role permission: %d %s", unmap.Code, unmap.Body.String())
	}
	deletePermission := adminJSONRequest(t, handler, http.MethodDelete, "/api/v1/admin/clients/finance/permissions/"+permission.ID, "")
	if deletePermission.Code != http.StatusNoContent {
		t.Fatalf("delete permission: %d %s", deletePermission.Code, deletePermission.Body.String())
	}
	deleteRole := adminJSONRequest(t, handler, http.MethodDelete, "/api/v1/admin/clients/finance/roles/"+role.ID, "")
	if deleteRole.Code != http.StatusNoContent {
		t.Fatalf("delete role: %d %s", deleteRole.Code, deleteRole.Body.String())
	}
	missingRole := adminJSONRequest(t, handler, http.MethodGet, "/api/v1/admin/clients/finance/roles/"+role.ID, "")
	if missingRole.Code != http.StatusNotFound {
		t.Fatalf("get deleted role: %d %s", missingRole.Code, missingRole.Body.String())
	}

	auditPage, err := auditRepository.List(context.Background(), audit.Filter{Limit: 100})
	if err != nil {
		t.Fatal(err)
	}
	eventTypes := make(map[string]bool)
	for _, event := range auditPage.Items {
		eventTypes[event.EventType] = true
	}
	for _, eventType := range []string{
		"access.role.created",
		"access.role.updated",
		"access.permission.created",
		"access.permission.updated",
		"access.role_permissions.updated",
		"access.user_roles.updated",
		"access.permission.deleted",
		"access.role.deleted",
	} {
		if !eventTypes[eventType] {
			t.Errorf("missing audit event %q", eventType)
		}
	}
}
