package httpserver

import (
	"errors"
	"net/http"

	"certus/internal/audit"
	"certus/internal/identity"
)

func (s *server) listUserExternalIdentities(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("userID")
	if !identity.ValidUserID(userID) {
		writeProblem(w, http.StatusNotFound, "not_found", "用户不存在")
		return
	}
	items, err := s.externalUsers.ListExternalIdentities(r.Context(), userID)
	if errors.Is(err, identity.ErrNotFound) {
		writeProblem(w, http.StatusNotFound, "not_found", "用户不存在")
		return
	}
	if err != nil {
		s.logger.Error("list user external identities", "user_id", userID, "error", err)
		writeProblem(w, http.StatusInternalServerError, "server_error", "读取外部身份失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *server) deleteUserExternalIdentity(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("userID")
	externalIdentityID := r.PathValue("externalIdentityID")
	if !identity.ValidUserID(userID) {
		writeProblem(w, http.StatusNotFound, "not_found", "用户不存在")
		return
	}
	if !identity.ValidUserID(externalIdentityID) {
		writeProblem(w, http.StatusNotFound, "not_found", "外部身份不存在")
		return
	}
	if !s.authorizeSensitiveAdministratorTarget(w, r, userID) {
		return
	}
	items, err := s.externalUsers.ListExternalIdentities(r.Context(), userID)
	if errors.Is(err, identity.ErrNotFound) {
		writeProblem(w, http.StatusNotFound, "not_found", "用户不存在")
		return
	}
	if err != nil {
		s.logger.Error("list external identities before deletion", "user_id", userID, "error", err)
		writeProblem(w, http.StatusInternalServerError, "server_error", "读取外部身份失败")
		return
	}
	providerID := ""
	for _, item := range items {
		if item.ID == externalIdentityID {
			providerID = item.ProviderID
			break
		}
	}
	if providerID == "" {
		writeProblem(w, http.StatusNotFound, "not_found", "外部身份不存在")
		return
	}
	err = s.externalUsers.DeleteExternalIdentity(r.Context(), userID, externalIdentityID)
	if errors.Is(err, identity.ErrExternalIdentityMissing) ||
		errors.Is(err, identity.ErrNotFound) {
		writeProblem(w, http.StatusNotFound, "not_found", "外部身份不存在")
		return
	}
	if errors.Is(err, identity.ErrLastAuthentication) {
		writeProblem(
			w,
			http.StatusConflict,
			"last_authentication_method",
			"请先为用户设置密码或绑定另一个外部身份",
		)
		return
	}
	if err != nil {
		s.logger.Error(
			"delete user external identity",
			"user_id", userID,
			"external_identity_id", externalIdentityID,
			"error", err,
		)
		writeProblem(w, http.StatusInternalServerError, "server_error", "解除外部身份绑定失败")
		return
	}

	activeSessions := s.sessionsForRevocation(r.Context(), userID, "")
	revoked, revokeErr := s.sessions.RevokeAll(r.Context(), userID, "")
	if revokeErr != nil {
		s.logger.Error("revoke sessions after external identity deletion", "user_id", userID, "error", revokeErr)
	} else {
		s.cleanupRevokedSessions(r.Context(), activeSessions)
	}
	if err := s.oauth.RevokeUserTokens(r.Context(), userID, "", s.now().UTC()); err != nil {
		s.logger.Error("revoke OAuth tokens after external identity deletion", "user_id", userID, "error", err)
	}
	s.recordAudit(r, audit.Event{
		EventType: "external_identity.deleted_by_admin",
		Outcome:   audit.OutcomeSuccess,
		Details: map[string]any{
			"user_id":              userID,
			"external_identity_id": externalIdentityID,
			"provider_id":          providerID,
			"sessions_revoked":     revoked,
		},
	})
	w.WriteHeader(http.StatusNoContent)
}
