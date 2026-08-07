package httpserver

import (
	"context"
	"errors"
	"html"
	"net/http"
	"net/url"
	"time"

	"certus/internal/audit"
	"certus/internal/identity"
	"certus/internal/mailer"
)

func (s *server) issueAccountEmailVerification(w http.ResponseWriter, r *http.Request) {
	current, ok := s.requireCurrentSession(w, r)
	if !ok || !s.requireAccountCSRF(w, r) {
		return
	}
	if s.mailer == nil {
		writeProblem(w, http.StatusServiceUnavailable, "smtp_not_configured", "SMTP 尚未配置")
		return
	}
	if !s.allowEmailVerificationAttempt(w, r, current.UserID) {
		return
	}
	user, err := s.users.Find(r.Context(), current.UserID)
	if err != nil {
		writeProblem(w, http.StatusUnauthorized, "unauthorized", "登录会话无效")
		return
	}
	token, err := s.verifications.Issue(r.Context(), user.ID, s.cfg.EmailVerificationTTL)
	if errors.Is(err, identity.ErrEmailAlreadyVerified) {
		writeProblem(w, http.StatusConflict, "email_already_verified", "邮箱已通过验证")
		return
	}
	if errors.Is(err, identity.ErrEmailNotConfigured) {
		writeProblem(w, http.StatusBadRequest, "email_not_configured", "当前账号未设置邮箱")
		return
	}
	if err != nil {
		s.logger.Error("issue email verification", "user_id", user.ID, "error", err)
		writeProblem(w, http.StatusInternalServerError, "server_error", "创建邮箱验证凭据失败")
		return
	}
	if err := s.mailer.Send(r.Context(), s.buildVerificationMessage(user, token, s.cfg.EmailVerificationTTL)); err != nil {
		s.recordAudit(r, audit.Event{
			ActorUserID: auditActor(user.ID),
			EventType:   "email.verification_sent",
			Outcome:     audit.OutcomeFailure,
			Details:     map[string]any{"reason": "send_failed"},
		})
		s.logger.Error("send email verification", "user_id", user.ID, "error", err)
		writeProblem(w, http.StatusBadGateway, "smtp_send_failed", "验证邮件发送失败")
		return
	}
	s.recordAudit(r, audit.Event{
		ActorUserID: auditActor(user.ID),
		EventType:   "email.verification_sent",
		Outcome:     audit.OutcomeSuccess,
	})
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) verifyAccountEmail(w http.ResponseWriter, r *http.Request) {
	current, ok := s.requireCurrentSession(w, r)
	if !ok || !s.requireAccountCSRF(w, r) {
		return
	}
	if !s.allowEmailVerificationAttempt(w, r, current.UserID) {
		return
	}
	var input struct {
		Token string `json:"token"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	userID, err := s.verifications.Verify(r.Context(), input.Token, current.UserID)
	if errors.Is(err, identity.ErrInvalidVerificationToken) {
		s.recordAudit(r, audit.Event{
			ActorUserID: auditActor(current.UserID),
			EventType:   "email.verified",
			Outcome:     audit.OutcomeFailure,
			Details:     map[string]any{"reason": "invalid_or_expired_token"},
		})
		writeProblem(w, http.StatusBadRequest, "invalid_verification_token", "验证凭据无效或已过期")
		return
	}
	if err != nil {
		s.logger.Error("verify email", "user_id", current.UserID, "error", err)
		writeProblem(w, http.StatusInternalServerError, "server_error", "邮箱验证失败")
		return
	}
	s.recordAudit(r, audit.Event{
		ActorUserID: auditActor(userID),
		EventType:   "email.verified",
		Outcome:     audit.OutcomeSuccess,
	})
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) verifyEmailPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if _, ok := s.currentSession(r); !ok {
		http.Redirect(
			w,
			r,
			"/login?continue="+url.QueryEscape(r.URL.RequestURI()),
			http.StatusFound,
		)
		return
	}
	s.render(w, "verify-email.html", map[string]any{
		"Title":     "邮箱验证 · Certus",
		"CSRFToken": s.ensureCSRF(w, r),
	})
}

func (s *server) verifyAdminUserEmail(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.adminSessionUser(w, r)
	if !ok {
		return
	}
	if !s.authorizeSensitiveAdministratorTarget(w, r, userID) {
		return
	}
	user, err := s.users.Find(r.Context(), userID)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "server_error", "读取用户失败")
		return
	}
	if user.Email == nil {
		writeProblem(w, http.StatusBadRequest, "email_not_configured", "该用户未设置邮箱")
		return
	}
	if user.EmailVerified {
		writeProblem(w, http.StatusConflict, "email_already_verified", "该邮箱已通过验证")
		return
	}
	updated, err := s.users.SetEmailVerified(r.Context(), userID, s.now().UTC())
	if err != nil {
		s.logger.Error("mark user email verified", "user_id", userID, "error", err)
		writeProblem(w, http.StatusInternalServerError, "server_error", "标记邮箱已验证失败")
		return
	}
	s.recordAudit(r, audit.Event{
		EventType: "email.verified_by_admin",
		Outcome:   audit.OutcomeSuccess,
		Details:   map[string]any{"user_id": userID},
	})
	writeJSON(w, http.StatusOK, updated)
}

// sendEmailVerification issues a one-time token and delivers the verification
// email for a user whose address changed or was just created. It is a no-op
// when SMTP is unconfigured or the address is already verified.
func (s *server) sendEmailVerification(ctx context.Context, user identity.User) error {
	if s.verifications == nil || s.mailer == nil || user.Email == nil || user.EmailVerified {
		return nil
	}
	token, err := s.verifications.Issue(ctx, user.ID, s.cfg.EmailVerificationTTL)
	if err != nil {
		return err
	}
	return s.mailer.Send(ctx, s.buildVerificationMessage(user, token, s.cfg.EmailVerificationTTL))
}

func (s *server) buildVerificationMessage(user identity.User, token string, lifetime time.Duration) mailer.Message {
	link := s.cfg.Issuer + "/account/verify-email?token=" + url.QueryEscape(token)
	expires := lifetime.Round(time.Minute).String()
	text := "请验证你的 Certus 邮箱地址。\n\n" +
		"验证链接（" + expires + " 有效，仅可使用一次）：\n" + link + "\n\n" +
		"如果这不是你的操作，请忽略本邮件，你的账号不会受到影响。"
	htmlBody := "<p>请验证你的 Certus 邮箱地址。</p>" +
		"<p><a href=\"" + html.EscapeString(link) + "\">点击此链接完成验证</a>（" +
		html.EscapeString(expires) + " 有效，仅可使用一次）。</p>" +
		"<p>如果这不是你的操作，请忽略本邮件，你的账号不会受到影响。</p>"
	return mailer.Message{
		To:      *user.Email,
		Subject: "验证你的 Certus 邮箱",
		Text:    text,
		HTML:    htmlBody,
	}
}
