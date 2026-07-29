package httpserver

import (
	"errors"
	"net/http"
	"time"

	"certus/internal/audit"
	"certus/internal/identity"
	"certus/internal/session"
)

type accountSession struct {
	session.Session
	Current bool `json:"current"`
}

func (s *server) listAccountSessions(w http.ResponseWriter, r *http.Request) {
	current, ok := s.requireCurrentSession(w, r)
	if !ok {
		return
	}
	items, err := s.sessions.ListByUser(r.Context(), current.UserID)
	if err != nil {
		s.logger.Error("list account sessions", "error", err)
		writeProblem(w, http.StatusInternalServerError, "server_error", "读取会话失败")
		return
	}
	response := make([]accountSession, 0, len(items))
	for _, item := range items {
		response = append(response, accountSession{Session: item, Current: item.ID == current.ID})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items":      response,
		"csrf_token": s.ensureCSRF(w, r),
	})
}

func (s *server) revokeAccountSession(w http.ResponseWriter, r *http.Request) {
	current, ok := s.requireCurrentSession(w, r)
	if !ok || !s.requireAccountCSRF(w, r) {
		return
	}
	sessionID := r.PathValue("sessionID")
	if err := s.sessions.RevokeForUser(r.Context(), current.UserID, sessionID); errors.Is(err, session.ErrNotFound) {
		writeProblem(w, http.StatusNotFound, "not_found", "会话不存在")
		return
	} else if err != nil {
		s.logger.Error("revoke account session", "error", err)
		writeProblem(w, http.StatusInternalServerError, "server_error", "撤销会话失败")
		return
	}
	_ = s.cas.DeleteServiceSessions(r.Context(), sessionID)
	if sessionID == current.ID {
		s.clearSessionCookie(w)
	}
	s.recordAudit(r, audit.Event{
		ActorUserID: auditActor(current.UserID),
		EventType:   "session.revoked",
		Outcome:     audit.OutcomeSuccess,
		Details:     map[string]any{"session_id": sessionID, "self": sessionID == current.ID},
	})
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) changeAccountPassword(w http.ResponseWriter, r *http.Request) {
	current, ok := s.requireCurrentSession(w, r)
	if !ok || !s.requireAccountCSRF(w, r) {
		return
	}
	user, err := s.users.Find(r.Context(), current.UserID)
	if err != nil {
		writeProblem(w, http.StatusUnauthorized, "unauthorized", "登录会话无效")
		return
	}
	var input struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	err = s.passwords.Change(r.Context(), user.ID, user.Username, input.CurrentPassword, input.NewPassword)
	if errors.Is(err, identity.ErrInvalidCredentials) || errors.Is(err, identity.ErrCredentialLocked) {
		s.recordAudit(r, audit.Event{
			ActorUserID: auditActor(current.UserID),
			EventType:   "password.changed",
			Outcome:     audit.OutcomeFailure,
			Details:     map[string]any{"reason": "current_password_invalid"},
		})
		writeProblem(w, http.StatusBadRequest, "current_password_invalid", "当前密码不正确")
		return
	}
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_password", err.Error())
		return
	}
	revoked, revokeErr := s.sessions.RevokeAll(r.Context(), current.UserID, current.ID)
	if revokeErr != nil {
		s.logger.Error("revoke other sessions after password change", "error", revokeErr)
	}
	s.recordAudit(r, audit.Event{
		ActorUserID: auditActor(current.UserID),
		EventType:   "password.changed",
		Outcome:     audit.OutcomeSuccess,
		Details:     map[string]any{"other_sessions_revoked": revoked},
	})
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) issueUserPasswordReset(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("userID")
	if !identity.ValidUserID(userID) {
		writeProblem(w, http.StatusNotFound, "not_found", "用户不存在")
		return
	}
	if _, err := s.users.Find(r.Context(), userID); errors.Is(err, identity.ErrNotFound) {
		writeProblem(w, http.StatusNotFound, "not_found", "用户不存在")
		return
	} else if err != nil {
		writeProblem(w, http.StatusInternalServerError, "server_error", "读取用户失败")
		return
	}
	token, err := s.passwords.IssueReset(r.Context(), userID, 30*time.Minute)
	if err != nil {
		s.logger.Error("issue password reset", "error", err)
		writeProblem(w, http.StatusInternalServerError, "server_error", "创建密码重置凭据失败")
		return
	}
	s.recordAudit(r, audit.Event{
		EventType: "password.reset_issued",
		Outcome:   audit.OutcomeSuccess,
		Details:   map[string]any{"user_id": userID, "expires_in": 1800},
	})
	writeJSON(w, http.StatusCreated, map[string]any{
		"reset_token": token,
		"expires_in":  1800,
		"token_type":  "one_time",
	})
}

func (s *server) resetAccountPassword(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	var input struct {
		ResetToken  string `json:"reset_token"`
		NewPassword string `json:"new_password"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	userID, err := s.passwords.Reset(r.Context(), input.ResetToken, input.NewPassword)
	if errors.Is(err, identity.ErrInvalidResetToken) {
		s.recordAudit(r, audit.Event{
			EventType: "password.reset",
			Outcome:   audit.OutcomeFailure,
			Details:   map[string]any{"reason": "invalid_or_expired_token"},
		})
		writeProblem(w, http.StatusBadRequest, "invalid_reset_token", "重置凭据无效或已过期")
		return
	}
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_password", err.Error())
		return
	}
	revoked, revokeErr := s.sessions.RevokeAll(r.Context(), userID, "")
	if revokeErr != nil {
		s.logger.Error("revoke sessions after password reset", "error", revokeErr)
	}
	s.recordAudit(r, audit.Event{
		ActorUserID: auditActor(userID),
		EventType:   "password.reset",
		Outcome:     audit.OutcomeSuccess,
		Details:     map[string]any{"sessions_revoked": revoked},
	})
	s.clearSessionCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) listAdminUserSessions(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.adminSessionUser(w, r)
	if !ok {
		return
	}
	items, err := s.sessions.ListByUser(r.Context(), userID)
	if err != nil {
		s.logger.Error("list admin user sessions", "error", err)
		writeProblem(w, http.StatusInternalServerError, "server_error", "读取会话失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items})
}

func (s *server) revokeAdminUserSession(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.adminSessionUser(w, r)
	if !ok {
		return
	}
	sessionID := r.PathValue("sessionID")
	if err := s.sessions.RevokeForUser(r.Context(), userID, sessionID); errors.Is(err, session.ErrNotFound) {
		writeProblem(w, http.StatusNotFound, "not_found", "会话不存在")
		return
	} else if err != nil {
		writeProblem(w, http.StatusInternalServerError, "server_error", "撤销会话失败")
		return
	}
	_ = s.cas.DeleteServiceSessions(r.Context(), sessionID)
	s.recordAudit(r, audit.Event{
		EventType: "session.revoked_by_admin",
		Outcome:   audit.OutcomeSuccess,
		Details:   map[string]any{"user_id": userID, "session_id": sessionID},
	})
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) revokeAllAdminUserSessions(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.adminSessionUser(w, r)
	if !ok {
		return
	}
	items, err := s.sessions.ListByUser(r.Context(), userID)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "server_error", "读取会话失败")
		return
	}
	count, err := s.sessions.RevokeAll(r.Context(), userID, "")
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "server_error", "撤销会话失败")
		return
	}
	for _, item := range items {
		_ = s.cas.DeleteServiceSessions(r.Context(), item.ID)
	}
	s.recordAudit(r, audit.Event{
		EventType: "session.revoked_all_by_admin",
		Outcome:   audit.OutcomeSuccess,
		Details:   map[string]any{"user_id": userID, "count": count},
	})
	writeJSON(w, http.StatusOK, map[string]any{"revoked": count})
}

func (s *server) adminSessionUser(w http.ResponseWriter, r *http.Request) (string, bool) {
	userID := r.PathValue("userID")
	if !identity.ValidUserID(userID) {
		writeProblem(w, http.StatusNotFound, "not_found", "用户不存在")
		return "", false
	}
	if _, err := s.users.Find(r.Context(), userID); errors.Is(err, identity.ErrNotFound) {
		writeProblem(w, http.StatusNotFound, "not_found", "用户不存在")
		return "", false
	} else if err != nil {
		writeProblem(w, http.StatusInternalServerError, "server_error", "读取用户失败")
		return "", false
	}
	return userID, true
}

func (s *server) requireCurrentSession(w http.ResponseWriter, r *http.Request) (session.Session, bool) {
	current, ok := s.currentSession(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", `Session realm="certus-account"`)
		writeProblem(w, http.StatusUnauthorized, "unauthorized", "需要有效的登录会话")
		return session.Session{}, false
	}
	return current, true
}
