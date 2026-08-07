package httpserver

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"certus/internal/audit"
	"certus/internal/identity"
)

const maxRequestBody = 1 << 20

func (s *server) listUsers(w http.ResponseWriter, r *http.Request) {
	limit, err := queryInt(r, "limit", 20, 1, 100)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	offset, err := queryInt(r, "offset", 0, 0, 1_000_000)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	status := identity.UserStatus(r.URL.Query().Get("status"))
	if status != "" && !status.Valid() {
		writeProblem(w, http.StatusBadRequest, "invalid_request", "无效的用户状态")
		return
	}
	page, err := s.users.List(r.Context(), identity.UserFilter{
		Query:  r.URL.Query().Get("q"),
		Status: status,
		Limit:  limit,
		Offset: offset,
	})
	if err != nil {
		s.logger.Error("list users", "error", err)
		writeProblem(w, http.StatusInternalServerError, "server_error", "读取用户失败")
		return
	}
	writeJSON(w, http.StatusOK, page)
}

func (s *server) getUser(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("userID")
	if !identity.ValidUserID(userID) {
		writeProblem(w, http.StatusNotFound, "not_found", "用户不存在")
		return
	}
	user, err := s.users.Find(r.Context(), userID)
	if errors.Is(err, identity.ErrNotFound) {
		writeProblem(w, http.StatusNotFound, "not_found", "用户不存在")
		return
	}
	if err != nil {
		s.logger.Error("find user", "error", err)
		writeProblem(w, http.StatusInternalServerError, "server_error", "读取用户失败")
		return
	}
	writeJSON(w, http.StatusOK, user)
}

func (s *server) createUser(w http.ResponseWriter, r *http.Request) {
	var input identity.CreateUser
	if err := decodeJSON(w, r, &input); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	user, err := identity.NewUser(input, time.Now())
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_user", err.Error())
		return
	}
	user, err = s.users.Create(r.Context(), user)
	if errors.Is(err, identity.ErrConflict) {
		writeProblem(w, http.StatusConflict, "user_conflict", "用户名或邮箱已存在")
		return
	}
	if err != nil {
		s.logger.Error("create user", "error", err)
		writeProblem(w, http.StatusInternalServerError, "server_error", "创建用户失败")
		return
	}
	w.Header().Set("Location", "/api/v1/admin/users/"+user.ID)
	if err := s.sendEmailVerification(r.Context(), user); err != nil {
		s.logger.Warn("send verification email for created user", "user_id", user.ID, "error", err)
	}
	writeJSON(w, http.StatusCreated, user)
}

func (s *server) importUsers(w http.ResponseWriter, r *http.Request) {
	var input identity.ImportPasswordUsers
	if err := decodeJSON(w, r, &input); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	result, err := s.passwordMigration.Import(r.Context(), input)
	if errors.Is(err, identity.ErrInvalid) {
		writeProblem(w, http.StatusBadRequest, "invalid_password_migration", err.Error())
		return
	}
	if errors.Is(err, identity.ErrConflict) {
		writeProblem(w, http.StatusConflict, "user_conflict", "迁移用户中的用户名或邮箱已存在")
		return
	}
	if err != nil {
		s.logger.Error("import users with migrated passwords", "error", err)
		writeProblem(w, http.StatusInternalServerError, "server_error", "迁移用户失败")
		return
	}
	s.recordAudit(r, audit.Event{
		EventType: "users.password_migration",
		Outcome:   audit.OutcomeSuccess,
		Details: map[string]any{
			"password_algorithm": input.Algorithm,
			"count":              result.Count,
			"expires_at":         result.ExpiresAt,
		},
	})
	writeJSON(w, http.StatusCreated, result)
}

func (s *server) replaceUser(w http.ResponseWriter, r *http.Request) {
	userID := r.PathValue("userID")
	if !identity.ValidUserID(userID) {
		writeProblem(w, http.StatusNotFound, "not_found", "用户不存在")
		return
	}
	current, err := s.users.Find(r.Context(), userID)
	if errors.Is(err, identity.ErrNotFound) {
		writeProblem(w, http.StatusNotFound, "not_found", "用户不存在")
		return
	}
	if err != nil {
		s.logger.Error("find user for replacement", "error", err)
		writeProblem(w, http.StatusInternalServerError, "server_error", "读取用户失败")
		return
	}
	var input identity.ReplaceUser
	if err := decodeJSON(w, r, &input); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	user, err := identity.Replace(current, input, time.Now())
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_user", err.Error())
		return
	}
	if current.Status == identity.UserActive &&
		user.Status != identity.UserActive &&
		!s.authorizeAdministratorDeactivation(w, r, userID) {
		return
	}
	user, err = s.users.Replace(r.Context(), user)
	if errors.Is(err, identity.ErrConflict) {
		writeProblem(w, http.StatusConflict, "user_conflict", "邮箱已被其他用户使用")
		return
	}
	if errors.Is(err, identity.ErrNotFound) {
		writeProblem(w, http.StatusNotFound, "not_found", "用户不存在")
		return
	}
	if err != nil {
		s.logger.Error("replace user", "error", err)
		writeProblem(w, http.StatusInternalServerError, "server_error", "更新用户失败")
		return
	}
	if user.Status != identity.UserActive {
		activeSessions := s.sessionsForRevocation(r.Context(), user.ID, "")
		if _, err := s.sessions.RevokeAll(r.Context(), user.ID, ""); err != nil {
			s.logger.Error("revoke sessions for inactive user", "user_id", user.ID, "error", err)
		} else {
			s.cleanupRevokedSessions(r.Context(), activeSessions)
		}
		if err := s.oauth.RevokeUserTokens(r.Context(), user.ID, "", s.now().UTC()); err != nil {
			s.logger.Error("revoke OAuth tokens for inactive user", "user_id", user.ID, "error", err)
		}
	}
	if user.Email != nil && (current.Email == nil || !strings.EqualFold(*current.Email, *user.Email)) {
		if err := s.sendEmailVerification(r.Context(), user); err != nil {
			s.logger.Warn("send verification email after email change", "user_id", user.ID, "error", err)
		}
	}
	writeJSON(w, http.StatusOK, user)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, target any) error {
	if contentType := r.Header.Get("Content-Type"); !strings.HasPrefix(contentType, "application/json") {
		return errors.New("Content-Type 必须是 application/json")
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return errors.New("请求体必须是有效的 JSON")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("请求体只能包含一个 JSON 对象")
	}
	return nil
}

func queryInt(r *http.Request, name string, fallback, minimum, maximum int) (int, error) {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < minimum || value > maximum {
		return 0, errors.New(name + " 超出允许范围")
	}
	return value, nil
}
