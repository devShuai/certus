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
	listed := adminJSONRequest(t, handler, http.MethodGet, "/api/v1/admin/users/"+user.ID+"/roles?client_id=finance", "")
	if listed.Code != http.StatusOK || !strings.Contains(listed.Body.String(), `"code":"approver"`) {
		t.Fatalf("list user roles: %d %s", listed.Code, listed.Body.String())
	}

	effectiveRequest := httptest.NewRequest(http.MethodGet, "/api/v1/access/users/"+user.ID, nil)
	effectiveRequest.SetBasicAuth(registered.ID, secret)
	effective := httptest.NewRecorder()
	handler.ServeHTTP(effective, effectiveRequest)
	if effective.Code != http.StatusOK ||
		!strings.Contains(effective.Body.String(), `"roles":["approver"]`) ||
		!strings.Contains(effective.Body.String(), `"permissions":["invoice.approve"]`) {
		t.Fatalf("effective access: %d %s", effective.Code, effective.Body.String())
	}
}
