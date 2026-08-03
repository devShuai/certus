package httpserver

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net/http"
	"slices"
	"strings"

	"certus/internal/administration"
	"certus/internal/audit"
	"certus/internal/identity"
	"certus/internal/session"
)

const (
	adminAuthSession        = "session"
	adminAuthEmergencyToken = "emergency_token"
)

type adminPrincipal struct {
	Access     administration.Access
	AuthMethod string
}

type adminPrincipalContextKey struct{}

type adminPageData struct {
	Title       string
	CSRFToken   string
	User        identity.User
	Roles       []administration.Role
	Permissions []administration.Permission
}

func (s *server) requireAdmin(
	permission administration.Permission,
	next http.Handler,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		principal, status, code, detail := s.authenticateAdministrator(r, permission)
		if status != 0 {
			if status == http.StatusUnauthorized {
				w.Header().Set("WWW-Authenticate", `Bearer realm="certus-admin", Session realm="certus-admin"`)
			}
			writeProblem(w, status, code, detail)
			return
		}
		if principal.AuthMethod == adminAuthSession &&
			isMutation(r.Method) &&
			!s.validCSRF(r.Header.Get("X-CSRF-Token"), r) {
			writeProblem(w, http.StatusForbidden, "invalid_csrf", "管理页面已失效，请刷新后重试")
			return
		}
		next.ServeHTTP(w, withAdminPrincipal(r, principal))
	})
}

func (s *server) authenticateAdministrator(
	r *http.Request,
	permission administration.Permission,
) (adminPrincipal, int, string, string) {
	authorization := strings.TrimSpace(r.Header.Get("Authorization"))
	if authorization != "" {
		const prefix = "Bearer "
		if !strings.HasPrefix(authorization, prefix) ||
			!s.validEmergencyAdminToken(strings.TrimSpace(strings.TrimPrefix(authorization, prefix))) {
			return adminPrincipal{}, http.StatusUnauthorized, "unauthorized", "管理员应急凭据无效"
		}
		access := administration.AccessFor("", []administration.Role{administration.RoleSuperAdmin})
		return adminPrincipal{Access: access, AuthMethod: adminAuthEmergencyToken}, 0, "", ""
	}
	current, ok := s.currentSession(r)
	if !ok {
		return adminPrincipal{}, http.StatusUnauthorized, "unauthorized", "需要有效的管理员登录会话"
	}
	access, err := s.administrators.Effective(r.Context(), current.UserID)
	if err != nil {
		s.logger.Error("read administrator access", "user_id", current.UserID, "error", err)
		return adminPrincipal{}, http.StatusInternalServerError, "server_error", "读取管理员权限失败"
	}
	if len(access.Roles) == 0 || !access.Has(permission) {
		return adminPrincipal{}, http.StatusForbidden, "insufficient_permission", "当前账号没有执行此操作的管理员权限"
	}
	if !administratorMFA(current) {
		return adminPrincipal{}, http.StatusForbidden, "admin_mfa_required", "管理员必须使用多因素认证登录"
	}
	return adminPrincipal{Access: access, AuthMethod: adminAuthSession}, 0, "", ""
}

func (s *server) validEmergencyAdminToken(supplied string) bool {
	if s.cfg.AdminToken == "" || supplied == "" {
		return false
	}
	expectedHash := sha256.Sum256([]byte(s.cfg.AdminToken))
	suppliedHash := sha256.Sum256([]byte(supplied))
	return subtle.ConstantTimeCompare(expectedHash[:], suppliedHash[:]) == 1
}

func administratorMFA(current session.Session) bool {
	return current.AssuranceLevel == "urn:certus:aal:2" &&
		(slices.Contains(current.AuthMethods, "otp") ||
			slices.Contains(current.AuthMethods, "trusted_device"))
}

func isMutation(method string) bool {
	return method == http.MethodPost ||
		method == http.MethodPut ||
		method == http.MethodPatch ||
		method == http.MethodDelete
}

func withAdminPrincipal(r *http.Request, principal adminPrincipal) *http.Request {
	if state, ok := r.Context().Value(adminPrincipalContextKey{}).(*adminPrincipal); ok {
		*state = principal
		return r
	}
	state := &adminPrincipal{}
	*state = principal
	return r.WithContext(context.WithValue(r.Context(), adminPrincipalContextKey{}, state))
}

func adminPrincipalFrom(r *http.Request) (adminPrincipal, bool) {
	state, ok := r.Context().Value(adminPrincipalContextKey{}).(*adminPrincipal)
	return dereferenceAdminPrincipal(state), ok && state.AuthMethod != ""
}

func dereferenceAdminPrincipal(value *adminPrincipal) adminPrincipal {
	if value == nil {
		return adminPrincipal{}
	}
	return *value
}

func (p adminPrincipal) grantedBy() string {
	if p.Access.UserID != "" {
		return p.Access.UserID
	}
	return adminAuthEmergencyToken
}

func (s *server) adminMe(w http.ResponseWriter, r *http.Request) {
	principal, ok := adminPrincipalFrom(r)
	if !ok {
		writeProblem(w, http.StatusUnauthorized, "unauthorized", "需要有效的管理员凭据")
		return
	}
	var user *identity.User
	if principal.Access.UserID != "" {
		value, err := s.users.Find(r.Context(), principal.Access.UserID)
		if err != nil {
			writeProblem(w, http.StatusUnauthorized, "unauthorized", "管理员账号不可用")
			return
		}
		user = &value
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"user":        user,
		"roles":       principal.Access.Roles,
		"permissions": principal.Access.Permissions,
		"auth_method": principal.AuthMethod,
		"csrf_token":  s.ensureCSRF(w, r),
	})
}

func (s *server) listAdministratorRoleDefinitions(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"items": administration.Definitions()})
}

func (s *server) listUserAdministratorRoles(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.accessUser(w, r)
	if !ok {
		return
	}
	items, err := s.administrators.ListUserRoles(r.Context(), userID)
	if err != nil {
		s.logger.Error("list user administrator roles", "user_id", userID, "error", err)
		writeProblem(w, http.StatusInternalServerError, "server_error", "读取管理员角色失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *server) replaceUserAdministratorRoles(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.accessUser(w, r)
	if !ok {
		return
	}
	var input struct {
		Roles []administration.Role `json:"roles"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := administration.ValidateRoles(input.Roles); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_admin_roles", err.Error())
		return
	}
	currentGrants, err := s.administrators.ListUserRoles(r.Context(), userID)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "server_error", "读取当前管理员角色失败")
		return
	}
	if grantsContainRole(currentGrants, administration.RoleSuperAdmin) &&
		!administration.HasRole(input.Roles, administration.RoleSuperAdmin) {
		if err := s.ensureOtherActiveSuperAdministrator(r.Context(), userID); errors.Is(err, administration.ErrLastSuperAdmin) {
			writeProblem(w, http.StatusConflict, "last_super_admin", "不能移除最后一个可登录的超级管理员")
			return
		} else if err != nil {
			writeProblem(w, http.StatusInternalServerError, "server_error", "检查超级管理员可用性失败")
			return
		}
	}
	principal, _ := adminPrincipalFrom(r)
	err = s.administrators.ReplaceUserRoles(
		r.Context(), userID, input.Roles, principal.grantedBy(), s.now().UTC(),
	)
	if errors.Is(err, administration.ErrNotFound) {
		writeProblem(w, http.StatusNotFound, "not_found", "用户不存在")
		return
	}
	if errors.Is(err, administration.ErrLastSuperAdmin) {
		writeProblem(w, http.StatusConflict, "last_super_admin", "不能移除最后一个超级管理员")
		return
	}
	if err != nil {
		s.logger.Error("replace user administrator roles", "user_id", userID, "error", err)
		writeProblem(w, http.StatusInternalServerError, "server_error", "更新管理员角色失败")
		return
	}
	s.recordAudit(r, audit.Event{
		EventType: "admin.roles.replaced",
		Outcome:   audit.OutcomeSuccess,
		Details:   map[string]any{"user_id": userID, "roles": input.Roles},
	})
	items, err := s.administrators.ListUserRoles(r.Context(), userID)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "server_error", "读取更新后的管理员角色失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *server) authorizeSensitiveAdministratorTarget(
	w http.ResponseWriter,
	r *http.Request,
	userID string,
) bool {
	grants, err := s.administrators.ListUserRoles(r.Context(), userID)
	if err != nil {
		s.logger.Error("read protected administrator target", "user_id", userID, "error", err)
		writeProblem(w, http.StatusInternalServerError, "server_error", "读取管理员角色失败")
		return false
	}
	if len(grants) == 0 {
		return true
	}
	principal, ok := adminPrincipalFrom(r)
	if ok && principal.Access.Has(administration.PermissionAdminRolesWrite) {
		return true
	}
	writeProblem(w, http.StatusForbidden, "protected_administrator", "只有超级管理员可以修改管理员账号的安全状态")
	return false
}

func (s *server) authorizeAdministratorDeactivation(
	w http.ResponseWriter,
	r *http.Request,
	userID string,
) bool {
	if !s.authorizeSensitiveAdministratorTarget(w, r, userID) {
		return false
	}
	grants, err := s.administrators.ListUserRoles(r.Context(), userID)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "server_error", "读取管理员角色失败")
		return false
	}
	if !grantsContainRole(grants, administration.RoleSuperAdmin) {
		return true
	}
	if err := s.ensureOtherActiveSuperAdministrator(r.Context(), userID); errors.Is(err, administration.ErrLastSuperAdmin) {
		writeProblem(w, http.StatusConflict, "last_super_admin", "不能停用最后一个可登录的超级管理员")
		return false
	} else if err != nil {
		writeProblem(w, http.StatusInternalServerError, "server_error", "检查超级管理员可用性失败")
		return false
	}
	return true
}

func (s *server) ensureOtherActiveSuperAdministrator(
	ctx context.Context,
	excludedUserID string,
) error {
	userIDs, err := s.administrators.ListRoleUsers(ctx, administration.RoleSuperAdmin)
	if err != nil {
		return err
	}
	for _, userID := range userIDs {
		if userID == excludedUserID {
			continue
		}
		user, err := s.users.Find(ctx, userID)
		if errors.Is(err, identity.ErrNotFound) {
			continue
		}
		if err != nil {
			return err
		}
		if user.Status == identity.UserActive {
			return nil
		}
	}
	return administration.ErrLastSuperAdmin
}

func grantsContainRole(grants []administration.Grant, role administration.Role) bool {
	for _, grant := range grants {
		if grant.Role == role {
			return true
		}
	}
	return false
}
