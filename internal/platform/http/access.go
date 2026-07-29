package httpserver

import (
	"errors"
	"net/http"
	"slices"

	"certus/internal/access"
	"certus/internal/client"
	"certus/internal/identity"
)

func (s *server) listRoles(w http.ResponseWriter, r *http.Request) {
	registered, ok := s.accessClient(w, r)
	if !ok {
		return
	}
	items, err := s.accessControl.ListRoles(r.Context(), registered.ID)
	if err != nil {
		s.logger.Error("list roles", "client_id", registered.ID, "error", err)
		writeProblem(w, http.StatusInternalServerError, "server_error", "读取角色失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *server) createRole(w http.ResponseWriter, r *http.Request) {
	registered, ok := s.accessClient(w, r)
	if !ok {
		return
	}
	var input access.CreateRole
	if err := decodeJSON(w, r, &input); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	value, err := access.NewRole(registered.ID, input, s.now().UTC())
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_role", err.Error())
		return
	}
	value, err = s.accessControl.CreateRole(r.Context(), value)
	if errors.Is(err, access.ErrConflict) {
		writeProblem(w, http.StatusConflict, "role_conflict", "角色代码已存在")
		return
	}
	if err != nil {
		s.logger.Error("create role", "client_id", registered.ID, "error", err)
		writeProblem(w, http.StatusInternalServerError, "server_error", "创建角色失败")
		return
	}
	w.Header().Set("Location", "/api/v1/admin/clients/"+registered.ID+"/roles/"+value.ID)
	writeJSON(w, http.StatusCreated, value)
}

func (s *server) listPermissions(w http.ResponseWriter, r *http.Request) {
	registered, ok := s.accessClient(w, r)
	if !ok {
		return
	}
	items, err := s.accessControl.ListPermissions(r.Context(), registered.ID)
	if err != nil {
		s.logger.Error("list permissions", "client_id", registered.ID, "error", err)
		writeProblem(w, http.StatusInternalServerError, "server_error", "读取权限点失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *server) createPermission(w http.ResponseWriter, r *http.Request) {
	registered, ok := s.accessClient(w, r)
	if !ok {
		return
	}
	var input access.CreatePermission
	if err := decodeJSON(w, r, &input); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	value, err := access.NewPermission(registered.ID, input, s.now().UTC())
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_permission", err.Error())
		return
	}
	value, err = s.accessControl.CreatePermission(r.Context(), value)
	if errors.Is(err, access.ErrConflict) {
		writeProblem(w, http.StatusConflict, "permission_conflict", "权限代码已存在")
		return
	}
	if err != nil {
		s.logger.Error("create permission", "client_id", registered.ID, "error", err)
		writeProblem(w, http.StatusInternalServerError, "server_error", "创建权限点失败")
		return
	}
	writeJSON(w, http.StatusCreated, value)
}

func (s *server) listRolePermissions(w http.ResponseWriter, r *http.Request) {
	registered, ok := s.accessClient(w, r)
	if !ok {
		return
	}
	items, err := s.accessControl.ListRolePermissions(r.Context(), registered.ID, r.PathValue("roleID"))
	if errors.Is(err, access.ErrNotFound) {
		writeProblem(w, http.StatusNotFound, "not_found", "角色不存在")
		return
	}
	if err != nil {
		s.logger.Error("list role permissions", "client_id", registered.ID, "error", err)
		writeProblem(w, http.StatusInternalServerError, "server_error", "读取角色权限失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *server) replaceRolePermissions(w http.ResponseWriter, r *http.Request) {
	registered, ok := s.accessClient(w, r)
	if !ok {
		return
	}
	var input struct {
		PermissionIDs []string `json:"permission_ids"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	err := s.accessControl.SetRolePermissions(r.Context(), registered.ID, r.PathValue("roleID"), input.PermissionIDs)
	if errors.Is(err, access.ErrNotFound) {
		writeProblem(w, http.StatusNotFound, "not_found", "角色或权限点不存在")
		return
	}
	if err != nil {
		s.logger.Error("replace role permissions", "client_id", registered.ID, "error", err)
		writeProblem(w, http.StatusInternalServerError, "server_error", "更新角色权限失败")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) listUserRoles(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.accessUser(w, r)
	if !ok {
		return
	}
	items, err := s.accessControl.ListUserRoles(
		r.Context(),
		userID,
		r.URL.Query().Get("client_id"),
		r.URL.Query().Get("include_expired") == "true",
		s.now().UTC(),
	)
	if err != nil {
		s.logger.Error("list user roles", "user_id", userID, "error", err)
		writeProblem(w, http.StatusInternalServerError, "server_error", "读取用户角色失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *server) replaceUserRoles(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.accessUser(w, r)
	if !ok {
		return
	}
	var input struct {
		Roles []access.RoleGrant `json:"roles"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	now := s.now().UTC()
	if err := access.ValidateRoleGrants(input.Roles, now); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_role_grants", err.Error())
		return
	}
	err := s.accessControl.ReplaceUserRoles(r.Context(), userID, input.Roles, "admin-token", now)
	if errors.Is(err, access.ErrNotFound) {
		writeProblem(w, http.StatusNotFound, "not_found", "用户或角色不存在")
		return
	}
	if err != nil {
		s.logger.Error("replace user roles", "user_id", userID, "error", err)
		writeProblem(w, http.StatusInternalServerError, "server_error", "更新用户角色失败")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) getEffectiveAccess(w http.ResponseWriter, r *http.Request) {
	registered, ok := s.authenticateConfidentialOAuthClient(w, r)
	if !ok {
		return
	}
	if !slices.Contains(registered.AllowedScopes, "roles") {
		writeOAuthError(w, http.StatusForbidden, "insufficient_scope", "client is not allowed to read roles")
		return
	}
	userID := r.PathValue("userID")
	if !identity.ValidUserID(userID) {
		writeProblem(w, http.StatusNotFound, "not_found", "用户不存在")
		return
	}
	user, err := s.users.Find(r.Context(), userID)
	if err != nil || user.Status != identity.UserActive {
		writeProblem(w, http.StatusNotFound, "not_found", "用户不存在")
		return
	}
	value, err := s.accessControl.Effective(r.Context(), userID, registered.ID, s.now().UTC())
	if err != nil {
		s.logger.Error("read effective access", "user_id", userID, "client_id", registered.ID, "error", err)
		writeProblem(w, http.StatusInternalServerError, "server_error", "读取有效权限失败")
		return
	}
	writeJSON(w, http.StatusOK, value)
}

func (s *server) accessClient(w http.ResponseWriter, r *http.Request) (client.Client, bool) {
	value, err := s.clients.Find(r.Context(), r.PathValue("clientID"))
	if errors.Is(err, client.ErrNotFound) || err == nil && value.ArchivedAt != nil {
		writeProblem(w, http.StatusNotFound, "not_found", "接入系统不存在")
		return client.Client{}, false
	}
	if err != nil {
		s.logger.Error("find access client", "error", err)
		writeProblem(w, http.StatusInternalServerError, "server_error", "读取接入系统失败")
		return client.Client{}, false
	}
	return value, true
}

func (s *server) accessUser(w http.ResponseWriter, r *http.Request) (string, bool) {
	userID := r.PathValue("userID")
	if !identity.ValidUserID(userID) {
		writeProblem(w, http.StatusNotFound, "not_found", "用户不存在")
		return "", false
	}
	if _, err := s.users.Find(r.Context(), userID); errors.Is(err, identity.ErrNotFound) {
		writeProblem(w, http.StatusNotFound, "not_found", "用户不存在")
		return "", false
	} else if err != nil {
		s.logger.Error("find access user", "error", err)
		writeProblem(w, http.StatusInternalServerError, "server_error", "读取用户失败")
		return "", false
	}
	return userID, true
}
