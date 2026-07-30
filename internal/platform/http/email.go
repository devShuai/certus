package httpserver

import (
	"errors"
	"net/http"

	"certus/internal/audit"
	"certus/internal/mailer"
)

func (s *server) testEmail(w http.ResponseWriter, r *http.Request) {
	if s.mailer == nil {
		writeProblem(w, http.StatusServiceUnavailable, "smtp_not_configured", "SMTP 尚未配置")
		return
	}
	var input struct {
		To string `json:"to"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	message := mailer.Message{
		To:      input.To,
		Subject: "Certus SMTP 配置测试",
		Text: "这是一封来自 Certus 的 SMTP 配置测试邮件。\n\n" +
			"Issuer: " + s.cfg.Issuer + "\n\n" +
			"如果你收到此邮件，说明 SMTP 连接、认证和发件人配置均可用。",
	}
	if err := message.Validate(); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_email", "收件邮箱地址无效")
		return
	}
	if err := s.mailer.Send(r.Context(), message); err != nil {
		s.recordAudit(r, audit.Event{
			EventType: "email.smtp_test",
			Outcome:   audit.OutcomeFailure,
			Details:   map[string]any{"reason": "send_failed"},
		})
		if errors.Is(err, mailer.ErrInvalidMessage) {
			writeProblem(w, http.StatusBadRequest, "invalid_email", "测试邮件内容无效")
			return
		}
		s.logger.Error("send SMTP test email", "error", err)
		writeProblem(w, http.StatusBadGateway, "smtp_send_failed", "SMTP 测试邮件发送失败")
		return
	}
	s.recordAudit(r, audit.Event{
		EventType: "email.smtp_test",
		Outcome:   audit.OutcomeSuccess,
	})
	w.WriteHeader(http.StatusNoContent)
}
