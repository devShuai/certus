package httpserver

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"certus/internal/administration"
	"certus/internal/audit"
	"certus/internal/cas"
	"certus/internal/client"
	"certus/internal/config"
	"certus/internal/identity"
	"certus/internal/oauth"
	"certus/internal/oidc"
	"certus/internal/session"
)

func TestAdministratorSessionRBACMFAAndAuditActor(t *testing.T) {
	ctx := context.Background()
	user, err := identity.NewUser(identity.CreateUser{
		Username:    "identity-admin",
		DisplayName: "Identity Admin",
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	users := identity.NewMemoryUserRepository(user)
	sessionRepository := session.NewMemoryRepository()
	sessionService := session.NewService(sessionRepository, 12*time.Hour)
	_, sessionToken, err := sessionService.CreateWithMethods(
		ctx,
		user.ID,
		"127.0.0.1",
		"test",
		[]string{"pwd", "otp"},
		"urn:certus:aal:2",
	)
	if err != nil {
		t.Fatal(err)
	}
	administratorRepository := administration.NewMemoryRepository()
	if err := administratorRepository.ReplaceUserRoles(
		ctx,
		user.ID,
		[]administration.Role{administration.RoleIdentityAdmin},
		"emergency_token",
		time.Now(),
	); err != nil {
		t.Fatal(err)
	}
	auditRepository := audit.NewMemoryRepository()
	handler, err := NewWithDependencies(
		ctx,
		config.Config{Issuer: "https://auth.example.com"},
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		Dependencies{
			Clients:        client.NewMemoryRepository(),
			Users:          users,
			Passwords:      users,
			Sessions:       sessionRepository,
			OAuth:          oauth.NewMemoryRepository(),
			CAS:            cas.NewMemoryRepository(),
			Administration: administratorRepository,
			Audit:          auditRepository,
			Keys:           &oidc.MemoryKeyRepository{},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	adminCookie := &http.Cookie{Name: sessionCookieName, Value: sessionToken}
	pageRequest := httptest.NewRequest(http.MethodGet, "/admin", nil)
	pageRequest.AddCookie(adminCookie)
	page := httptest.NewRecorder()
	handler.ServeHTTP(page, pageRequest)
	if page.Code != http.StatusOK ||
		!strings.Contains(page.Body.String(), "Identity Admin") ||
		strings.Contains(page.Body.String(), "管理员令牌") {
		t.Fatalf("administrator page did not use the authenticated identity: %d %s", page.Code, page.Body.String())
	}
	portalRequest := httptest.NewRequest(http.MethodGet, "/portal", nil)
	portalRequest.AddCookie(adminCookie)
	portal := httptest.NewRecorder()
	handler.ServeHTTP(portal, portalRequest)
	if portal.Code != http.StatusOK || !strings.Contains(portal.Body.String(), `href="/admin"`) {
		t.Fatalf("administrator did not receive a portal shortcut: %d %s", portal.Code, portal.Body.String())
	}
	var csrfCookie *http.Cookie
	for _, cookie := range page.Result().Cookies() {
		if cookie.Name == csrfCookieName {
			csrfCookie = cookie
			break
		}
	}
	if csrfCookie == nil || csrfCookie.Value == "" {
		t.Fatal("administrator page did not issue a CSRF token")
	}

	usersRequest := httptest.NewRequest(http.MethodGet, "/api/v1/admin/users", nil)
	usersRequest.AddCookie(adminCookie)
	usersResponse := httptest.NewRecorder()
	handler.ServeHTTP(usersResponse, usersRequest)
	if usersResponse.Code != http.StatusOK {
		t.Fatalf("identity administrator could not list users: %d %s", usersResponse.Code, usersResponse.Body.String())
	}
	clientsRequest := httptest.NewRequest(http.MethodGet, "/api/v1/admin/clients", nil)
	clientsRequest.AddCookie(adminCookie)
	clientsResponse := httptest.NewRecorder()
	handler.ServeHTTP(clientsResponse, clientsRequest)
	if clientsResponse.Code != http.StatusForbidden ||
		!strings.Contains(clientsResponse.Body.String(), `"insufficient_permission"`) {
		t.Fatalf("identity administrator could access clients: %d %s", clientsResponse.Code, clientsResponse.Body.String())
	}

	createWithoutCSRF := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/admin/users",
		bytes.NewBufferString(`{"username":"missing-csrf","display_name":"Missing CSRF"}`),
	)
	createWithoutCSRF.Header.Set("Content-Type", "application/json")
	createWithoutCSRF.AddCookie(adminCookie)
	missingCSRF := httptest.NewRecorder()
	handler.ServeHTTP(missingCSRF, createWithoutCSRF)
	if missingCSRF.Code != http.StatusForbidden ||
		!strings.Contains(missingCSRF.Body.String(), `"invalid_csrf"`) {
		t.Fatalf("administrator mutation without CSRF was accepted: %d %s", missingCSRF.Code, missingCSRF.Body.String())
	}

	create := httptest.NewRequest(
		http.MethodPost,
		"/api/v1/admin/users",
		bytes.NewBufferString(`{"username":"managed-user","display_name":"Managed User"}`),
	)
	create.Header.Set("Content-Type", "application/json")
	create.Header.Set("X-CSRF-Token", csrfCookie.Value)
	create.AddCookie(adminCookie)
	create.AddCookie(csrfCookie)
	created := httptest.NewRecorder()
	handler.ServeHTTP(created, create)
	if created.Code != http.StatusCreated {
		t.Fatalf("administrator mutation with CSRF failed: %d %s", created.Code, created.Body.String())
	}
	events, err := auditRepository.List(ctx, audit.Filter{
		ActorUserID: user.ID,
		EventType:   "admin.request",
		Limit:       20,
	})
	if err != nil || events.Total == 0 {
		t.Fatalf("administrator mutation was not attributed to the user: %#v %v", events, err)
	}
	protectedPassword := httptest.NewRequest(
		http.MethodPut,
		"/api/v1/admin/users/"+user.ID+"/password",
		bytes.NewBufferString(`{"password":"new-administrator-password"}`),
	)
	protectedPassword.Header.Set("Content-Type", "application/json")
	protectedPassword.Header.Set("X-CSRF-Token", csrfCookie.Value)
	protectedPassword.AddCookie(adminCookie)
	protectedPassword.AddCookie(csrfCookie)
	protectedResponse := httptest.NewRecorder()
	handler.ServeHTTP(protectedResponse, protectedPassword)
	if protectedResponse.Code != http.StatusForbidden ||
		!strings.Contains(protectedResponse.Body.String(), `"protected_administrator"`) {
		t.Fatalf("identity administrator could modify an administrator credential: %d %s", protectedResponse.Code, protectedResponse.Body.String())
	}

	_, aal1Token, err := sessionService.CreateWithMethods(
		ctx,
		user.ID,
		"127.0.0.1",
		"test",
		[]string{"pwd"},
		"urn:certus:aal:1",
	)
	if err != nil {
		t.Fatal(err)
	}
	aal1Request := httptest.NewRequest(http.MethodGet, "/api/v1/admin/users", nil)
	aal1Request.AddCookie(&http.Cookie{Name: sessionCookieName, Value: aal1Token})
	aal1Response := httptest.NewRecorder()
	handler.ServeHTTP(aal1Response, aal1Request)
	if aal1Response.Code != http.StatusForbidden ||
		!strings.Contains(aal1Response.Body.String(), `"admin_mfa_required"`) {
		t.Fatalf("AAL1 administrator session was accepted: %d %s", aal1Response.Code, aal1Response.Body.String())
	}
}

func TestEmergencyTokenBootstrapsRolesAndProtectsLastSuperAdmin(t *testing.T) {
	handler := New(
		config.Config{Issuer: "https://auth.example.com", AdminToken: "test-admin-token"},
		slog.New(slog.NewTextHandler(io.Discard, nil)),
	)
	created := adminJSONRequest(
		t,
		handler,
		http.MethodPost,
		"/api/v1/admin/users",
		`{"username":"bootstrap-admin","display_name":"Bootstrap Admin"}`,
	)
	if created.Code != http.StatusCreated {
		t.Fatalf("create bootstrap user: %d %s", created.Code, created.Body.String())
	}
	location := created.Header().Get("Location")
	userID := location[strings.LastIndex(location, "/")+1:]
	assigned := adminJSONRequest(
		t,
		handler,
		http.MethodPut,
		"/api/v1/admin/users/"+userID+"/admin-roles",
		`{"roles":["super_admin"]}`,
	)
	if assigned.Code != http.StatusOK ||
		!strings.Contains(assigned.Body.String(), `"role":"super_admin"`) {
		t.Fatalf("bootstrap role assignment failed: %d %s", assigned.Code, assigned.Body.String())
	}
	removed := adminJSONRequest(
		t,
		handler,
		http.MethodPut,
		"/api/v1/admin/users/"+userID+"/admin-roles",
		`{"roles":[]}`,
	)
	if removed.Code != http.StatusConflict ||
		!strings.Contains(removed.Body.String(), `"last_super_admin"`) {
		t.Fatalf("last super administrator was removable: %d %s", removed.Code, removed.Body.String())
	}
	disabled := adminJSONRequest(
		t,
		handler,
		http.MethodPut,
		"/api/v1/admin/users/"+userID,
		`{"display_name":"Bootstrap Admin","email":null,"status":"disabled"}`,
	)
	if disabled.Code != http.StatusConflict ||
		!strings.Contains(disabled.Body.String(), `"last_super_admin"`) {
		t.Fatalf("last super administrator was disableable: %d %s", disabled.Code, disabled.Body.String())
	}
}
