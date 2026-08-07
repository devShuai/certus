package httpserver

import (
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"certus/internal/audit"
	"certus/internal/client"
	"certus/internal/identity"
)

type registrationPageData struct {
	Title        string
	Client       client.Client
	ReturnTo     string
	CSRFToken    string
	Error        string
	Username     string
	DisplayName  string
	Email        string
	RequireEmail bool
}

var errRegistrationClient = errors.New("registration is not available for this client")

func (s *server) registrationPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !s.cfg.Registration.Enabled {
		http.NotFound(w, r)
		return
	}
	returnTo := validatedReturnTo(r.URL.Query().Get("continue"))
	if returnTo == "" {
		returnTo = "/portal"
	}
	page, err := s.newRegistrationPageData(
		r,
		returnTo,
		strings.TrimSpace(r.URL.Query().Get("client_id")),
		s.ensureCSRF(w, r),
		"",
	)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "registration_not_available", "此接入系统不允许账号密码注册")
		return
	}
	s.render(w, "register.html", page)
}

func (s *server) register(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !s.cfg.Registration.Enabled || s.registrations == nil {
		http.NotFound(w, r)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request", "注册请求无效")
		return
	}
	returnTo := validatedReturnTo(r.Form.Get("continue"))
	if returnTo == "" {
		returnTo = "/portal"
	}
	requestedClientID := strings.TrimSpace(r.Form.Get("client_id"))
	if !s.validCSRF(r.Form.Get("csrf_token"), r) {
		writeProblem(w, http.StatusBadRequest, "invalid_csrf", "注册页面已失效，请刷新后重试")
		return
	}
	registered, err := s.registrationClient(r, returnTo, requestedClientID)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "registration_not_available", "此接入系统不允许账号密码注册")
		return
	}
	clientID := registered.ID
	if !s.allowRegistrationAttempt(w, r) {
		s.recordRegistrationFailure(r, clientID, "rate_limited")
		return
	}

	username := strings.TrimSpace(r.Form.Get("username"))
	displayName := strings.TrimSpace(r.Form.Get("display_name"))
	emailValue := strings.TrimSpace(r.Form.Get("email"))
	password := r.Form.Get("password")
	if password != r.Form.Get("password_confirmation") {
		s.renderRegistrationError(
			w, r, returnTo, requestedClientID,
			username, displayName, emailValue,
			"两次输入的密码不一致",
		)
		s.recordRegistrationFailure(r, clientID, "password_mismatch")
		return
	}
	if s.cfg.Registration.RequireEmail && emailValue == "" {
		s.renderRegistrationError(
			w, r, returnTo, requestedClientID,
			username, displayName, emailValue,
			"请输入邮箱地址",
		)
		s.recordRegistrationFailure(r, clientID, "email_required")
		return
	}
	var email *string
	if emailValue != "" {
		email = &emailValue
	}
	user, err := s.registrations.Register(r.Context(), identity.RegisterUser{
		Username:    username,
		DisplayName: displayName,
		Email:       email,
		Password:    password,
	})
	if err != nil {
		reason := registrationFailureReason(err)
		s.recordRegistrationFailure(r, clientID, reason)
		if reason == "storage_error" {
			s.logger.Error("register user", "error", err)
		}
		s.renderRegistrationError(
			w, r, returnTo, requestedClientID,
			username, displayName, emailValue,
			registrationErrorMessage(err),
		)
		return
	}
	s.recordAudit(r, audit.Event{
		ActorUserID: auditActor(user.ID),
		EventType:   "user.register",
		ClientID:    auditClient(clientID),
		Outcome:     audit.OutcomeSuccess,
	})
	if err := s.sendEmailVerification(r.Context(), user); err != nil {
		s.logger.Warn("send registration verification email", "user_id", user.ID, "error", err)
	}
	s.createLoginSession(w, r, user, returnTo, "registration", clientID, "")
}

func (s *server) newRegistrationPageData(
	r *http.Request,
	returnTo, requestedClientID, csrfToken, message string,
) (registrationPageData, error) {
	registered, err := s.registrationClient(r, returnTo, requestedClientID)
	if err != nil {
		return registrationPageData{}, err
	}
	return registrationPageData{
		Title:        "注册 Certus",
		Client:       registered,
		ReturnTo:     returnTo,
		CSRFToken:    csrfToken,
		Error:        message,
		RequireEmail: s.cfg.Registration.RequireEmail,
	}, nil
}

func (s *server) registrationClient(
	r *http.Request,
	returnTo, requestedClientID string,
) (client.Client, error) {
	target, err := url.Parse(returnTo)
	if err != nil {
		return client.Client{}, errRegistrationClient
	}
	registered, found := s.loginClient(r, returnTo)
	switch target.Path {
	case "/oauth2/authorize", "/cas/login", "/device":
		if !found {
			return client.Client{}, errRegistrationClient
		}
	default:
		if requestedClientID != "" {
			registered, err = s.clients.Find(r.Context(), requestedClientID)
			if err != nil {
				return client.Client{}, errRegistrationClient
			}
			found = true
		}
	}
	if !found {
		return client.Client{}, nil
	}
	if requestedClientID != "" && requestedClientID != registered.ID {
		return client.Client{}, errRegistrationClient
	}
	if !registered.Enabled ||
		registered.ArchivedAt != nil ||
		!slices.Contains(registered.LoginMethods, client.LoginPassword) {
		return client.Client{}, errRegistrationClient
	}
	return registered, nil
}

func (s *server) renderRegistrationError(
	w http.ResponseWriter,
	r *http.Request,
	returnTo, requestedClientID, username, displayName, email, message string,
) {
	page, err := s.newRegistrationPageData(
		r, returnTo, requestedClientID, s.ensureCSRF(w, r), message,
	)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "registration_not_available", "此接入系统不允许账号密码注册")
		return
	}
	page.Username = username
	page.DisplayName = displayName
	page.Email = email
	s.render(w, "register.html", page)
}

func (s *server) recordRegistrationFailure(r *http.Request, clientID, reason string) {
	s.recordAudit(r, audit.Event{
		EventType: "user.register",
		ClientID:  auditClient(clientID),
		Outcome:   audit.OutcomeFailure,
		Details:   map[string]any{"reason": reason},
	})
}

func registrationErrorMessage(err error) string {
	switch {
	case errors.Is(err, identity.ErrConflict):
		return "用户名或邮箱已被使用"
	case errors.Is(err, identity.ErrInvalid) && strings.Contains(err.Error(), "username"):
		return "用户名须为 3–64 位小写字母、数字、点、下划线或连字符"
	case errors.Is(err, identity.ErrInvalid) && strings.Contains(err.Error(), "display_name"):
		return "显示名称须为 1–128 个字符"
	case errors.Is(err, identity.ErrInvalid) && strings.Contains(err.Error(), "email"):
		return "邮箱地址格式不正确"
	case strings.Contains(err.Error(), "password must contain"):
		return "密码须为 12–1024 个字符"
	default:
		return "暂时无法完成注册，请稍后重试"
	}
}

func registrationFailureReason(err error) string {
	switch {
	case errors.Is(err, identity.ErrConflict):
		return "conflict"
	case errors.Is(err, identity.ErrInvalid):
		return "invalid_identity"
	case strings.Contains(err.Error(), "password must contain"):
		return "invalid_password"
	default:
		return "storage_error"
	}
}
