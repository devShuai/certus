package httpserver

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"certus/internal/audit"
	"certus/internal/identity"
	"certus/internal/mfa"

	qrcode "github.com/skip2/go-qrcode"
)

type mfaLoginPageData struct {
	Title          string
	CSRFToken      string
	Error          string
	RememberDevice bool
}

type mfaSetupResponse struct {
	mfa.Setup
	QRCodeRows []string `json:"qr_code_rows"`
}

func enrollmentQRCodeRows(value string) ([]string, error) {
	code, err := qrcode.New(value, qrcode.Medium)
	if err != nil {
		return nil, err
	}
	bitmap := code.Bitmap()
	rows := make([]string, len(bitmap))
	for y, modules := range bitmap {
		var row strings.Builder
		row.Grow(len(modules))
		for _, dark := range modules {
			if dark {
				row.WriteByte('1')
			} else {
				row.WriteByte('0')
			}
		}
		rows[y] = row.String()
	}
	return rows, nil
}

func (s *server) beginMFAChallenge(w http.ResponseWriter, r *http.Request, userID, returnTo, method, clientID string) {
	now := s.now().UTC()
	transaction, err := s.signer.Sign(map[string]any{
		"purpose":   "mfa_login",
		"user_id":   userID,
		"continue":  returnTo,
		"method":    method,
		"client_id": clientID,
		"iat":       now.Unix(),
		"exp":       now.Add(5 * time.Minute).Unix(),
	})
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "server_error", "创建多因素认证请求失败")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     mfaCookieName,
		Value:    transaction,
		Path:     "/login/mfa",
		MaxAge:   int((5 * time.Minute).Seconds()),
		HttpOnly: true,
		Secure:   s.secureCookies(),
		SameSite: http.SameSiteStrictMode,
	})
	http.Redirect(w, r, "/login/mfa", http.StatusSeeOther)
}

func (s *server) mfaLoginPage(w http.ResponseWriter, r *http.Request) {
	if _, _, _, _, ok := s.mfaLoginTransaction(r); !ok {
		s.clearMFACookie(w)
		writeProblem(w, http.StatusBadRequest, "invalid_login_transaction", "多因素认证请求无效或已过期")
		return
	}
	s.render(w, "mfa.html", mfaLoginPageData{
		Title:     "多因素认证 · Certus",
		CSRFToken: s.ensureCSRF(w, r),
	})
}

func (s *server) mfaLoginVerify(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	if err := r.ParseForm(); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request", "多因素认证请求无效")
		return
	}
	if !s.validCSRF(r.Form.Get("csrf_token"), r) {
		writeProblem(w, http.StatusBadRequest, "invalid_csrf", "验证页面已失效，请刷新后重试")
		return
	}
	userID, returnTo, method, clientID, ok := s.mfaLoginTransaction(r)
	if !ok {
		s.clearMFACookie(w)
		writeProblem(w, http.StatusBadRequest, "invalid_login_transaction", "多因素认证请求无效或已过期")
		return
	}
	if !s.allowMFAAttempt(w, r, userID) {
		return
	}
	err := s.mfa.Verify(r.Context(), userID, r.Form.Get("code"))
	rememberDevice := r.Form.Get("remember_device") == "on"
	if err != nil {
		message := "动态口令或恢复码不正确"
		if errors.Is(err, mfa.ErrLocked) {
			message = "验证失败次数过多，请稍后重试"
		} else if errors.Is(err, mfa.ErrReplay) {
			message = "该动态口令已使用，请等待下一个口令"
		}
		s.recordAudit(r, audit.Event{
			ActorUserID: auditActor(userID),
			EventType:   "login.mfa",
			ClientID:    auditClient(clientID),
			Outcome:     audit.OutcomeFailure,
			Details:     map[string]any{"locked": errors.Is(err, mfa.ErrLocked), "replay": errors.Is(err, mfa.ErrReplay)},
		})
		s.render(w, "mfa.html", mfaLoginPageData{
			Title:          "多因素认证 · Certus",
			CSRFToken:      s.ensureCSRF(w, r),
			Error:          message,
			RememberDevice: rememberDevice,
		})
		return
	}
	user, err := s.users.Find(r.Context(), userID)
	if err != nil || user.Status != identity.UserActive {
		s.clearMFACookie(w)
		writeProblem(w, http.StatusUnauthorized, "unauthorized", "账号当前不可登录")
		return
	}
	s.clearMFACookie(w)
	remembered := false
	if rememberDevice {
		trustedDevice, rememberErr := s.mfa.RememberDevice(r.Context(), userID, r.UserAgent())
		if rememberErr != nil {
			s.logger.Error("remember MFA trusted device", "user_id", userID, "error", rememberErr)
		} else {
			s.setTrustedDeviceCookie(w, trustedDevice)
			remembered = true
		}
	}
	s.recordAudit(r, audit.Event{
		ActorUserID: auditActor(userID),
		EventType:   "login.mfa",
		ClientID:    auditClient(clientID),
		Outcome:     audit.OutcomeSuccess,
		Details:     map[string]any{"remember_device": remembered},
	})
	s.createLoginSession(w, r, user, returnTo, method, clientID, "otp")
}

func (s *server) completeLoginWithTrustedDevice(
	w http.ResponseWriter,
	r *http.Request,
	user identity.User,
	returnTo, method, clientID string,
) bool {
	cookie, err := r.Cookie(trustedDeviceCookieName)
	if err != nil || strings.TrimSpace(cookie.Value) == "" {
		return false
	}
	replacement, trusted, err := s.mfa.UseTrustedDevice(r.Context(), user.ID, cookie.Value, r.UserAgent())
	if err != nil {
		s.logger.Error("verify MFA trusted device", "user_id", user.ID, "error", err)
		return false
	}
	if !trusted {
		s.clearTrustedDeviceCookie(w)
		return false
	}
	s.setTrustedDeviceCookie(w, replacement)
	s.recordAudit(r, audit.Event{
		ActorUserID: auditActor(user.ID),
		EventType:   "login.mfa_trusted_device",
		ClientID:    auditClient(clientID),
		Outcome:     audit.OutcomeSuccess,
	})
	s.createLoginSession(w, r, user, returnTo, method, clientID, "trusted_device")
	return true
}

func (s *server) setTrustedDeviceCookie(w http.ResponseWriter, device mfa.TrustedDeviceToken) {
	maxAge := int(device.ExpiresAt.Sub(s.now().UTC()).Seconds())
	if maxAge <= 0 {
		s.clearTrustedDeviceCookie(w)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     trustedDeviceCookieName,
		Value:    device.Token,
		Path:     "/",
		Expires:  device.ExpiresAt,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   s.secureCookies(),
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *server) clearTrustedDeviceCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     trustedDeviceCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.secureCookies(),
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *server) mfaLoginTransaction(r *http.Request) (string, string, string, string, bool) {
	cookie, err := r.Cookie(mfaCookieName)
	if err != nil {
		return "", "", "", "", false
	}
	claims, err := s.signer.Verify(cookie.Value)
	if err != nil {
		return "", "", "", "", false
	}
	purpose, _ := claims["purpose"].(string)
	userID, _ := claims["user_id"].(string)
	returnTo, _ := claims["continue"].(string)
	method, _ := claims["method"].(string)
	clientID, _ := claims["client_id"].(string)
	expiration, _ := claims["exp"].(float64)
	issuedAt, _ := claims["iat"].(float64)
	now := s.now().UTC().Unix()
	validMethod := method == "password" || method == "ldap" || method == "oidc"
	if purpose != "mfa_login" ||
		!identity.ValidUserID(userID) ||
		validatedReturnTo(returnTo) == "" ||
		!validMethod ||
		int64(expiration) <= now ||
		int64(issuedAt) > now+30 {
		return "", "", "", "", false
	}
	return userID, returnTo, method, clientID, true
}

func (s *server) clearMFACookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     mfaCookieName,
		Value:    "",
		Path:     "/login/mfa",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.secureCookies(),
		SameSite: http.SameSiteStrictMode,
	})
}

func (s *server) getAccountMFA(w http.ResponseWriter, r *http.Request) {
	current, ok := s.requireCurrentSession(w, r)
	if !ok {
		return
	}
	status, err := s.mfa.Status(r.Context(), current.UserID)
	if err != nil {
		s.logger.Error("read account MFA status", "error", err)
		writeProblem(w, http.StatusInternalServerError, "server_error", "读取多因素认证状态失败")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":     status,
		"csrf_token": s.ensureCSRF(w, r),
	})
}

func (s *server) setupAccountMFA(w http.ResponseWriter, r *http.Request) {
	current, ok := s.requireCurrentSession(w, r)
	if !ok || !s.requireAccountCSRF(w, r) {
		return
	}
	var input struct {
		CurrentPassword string `json:"current_password"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	user, ok := s.verifyAccountPassword(w, r, current.UserID, input.CurrentPassword)
	if !ok {
		return
	}
	setup, err := s.mfa.Setup(r.Context(), user.ID, user.Username)
	if errors.Is(err, mfa.ErrUnavailable) {
		writeProblem(w, http.StatusServiceUnavailable, "mfa_unavailable", "服务端尚未配置 MFA 加密密钥")
		return
	}
	if errors.Is(err, mfa.ErrAlreadyEnabled) {
		writeProblem(w, http.StatusConflict, "mfa_already_enabled", "多因素认证已启用")
		return
	}
	if err != nil {
		s.logger.Error("setup account MFA", "error", err)
		writeProblem(w, http.StatusInternalServerError, "server_error", "创建多因素认证配置失败")
		return
	}
	qrCodeRows, err := enrollmentQRCodeRows(setup.OTPAuthURI)
	if err != nil {
		s.logger.Error("generate account MFA QR code", "error", err)
		writeProblem(w, http.StatusInternalServerError, "server_error", "生成认证器二维码失败")
		return
	}
	s.recordAudit(r, audit.Event{
		ActorUserID: auditActor(user.ID),
		EventType:   "mfa.setup_started",
		Outcome:     audit.OutcomeSuccess,
	})
	writeJSON(w, http.StatusCreated, mfaSetupResponse{
		Setup:      setup,
		QRCodeRows: qrCodeRows,
	})
}

func (s *server) enableAccountMFA(w http.ResponseWriter, r *http.Request) {
	current, ok := s.requireCurrentSession(w, r)
	if !ok || !s.requireAccountCSRF(w, r) {
		return
	}
	var input struct {
		Code string `json:"code"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := s.mfa.Enable(r.Context(), current.UserID, input.Code); err != nil {
		s.recordAudit(r, audit.Event{
			ActorUserID: auditActor(current.UserID),
			EventType:   "mfa.enabled",
			Outcome:     audit.OutcomeFailure,
		})
		writeProblem(w, http.StatusBadRequest, "invalid_mfa_code", "动态口令无效")
		return
	}
	s.recordAudit(r, audit.Event{
		ActorUserID: auditActor(current.UserID),
		EventType:   "mfa.enabled",
		Outcome:     audit.OutcomeSuccess,
	})
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) regenerateAccountMFARecoveryCodes(w http.ResponseWriter, r *http.Request) {
	current, ok := s.requireCurrentSession(w, r)
	if !ok || !s.requireAccountCSRF(w, r) {
		return
	}
	var input struct {
		CurrentPassword string `json:"current_password"`
		Code            string `json:"code"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if _, ok := s.verifyAccountPassword(w, r, current.UserID, input.CurrentPassword); !ok {
		return
	}
	if !s.allowMFAAttempt(w, r, current.UserID) {
		return
	}
	if err := s.mfa.Verify(r.Context(), current.UserID, input.Code); err != nil {
		s.recordAudit(r, audit.Event{
			ActorUserID: auditActor(current.UserID),
			EventType:   "mfa.recovery_codes.regenerated",
			Outcome:     audit.OutcomeFailure,
			Details:     map[string]any{"reason": "invalid_mfa_code"},
		})
		writeProblem(w, http.StatusBadRequest, "invalid_mfa_code", "动态口令或恢复码无效")
		return
	}
	codes, err := s.mfa.RegenerateRecoveryCodes(r.Context(), current.UserID)
	if errors.Is(err, mfa.ErrNotFound) || errors.Is(err, mfa.ErrNotEnabled) {
		writeProblem(w, http.StatusConflict, "mfa_not_enabled", "多因素认证尚未启用")
		return
	}
	if err != nil {
		s.logger.Error("regenerate account MFA recovery codes", "error", err)
		writeProblem(w, http.StatusInternalServerError, "server_error", "重新生成恢复码失败")
		return
	}
	s.recordAudit(r, audit.Event{
		ActorUserID: auditActor(current.UserID),
		EventType:   "mfa.recovery_codes.regenerated",
		Outcome:     audit.OutcomeSuccess,
		Details:     map[string]any{"count": len(codes)},
	})
	writeJSON(w, http.StatusCreated, map[string]any{"recovery_codes": codes})
}

func (s *server) disableAccountMFA(w http.ResponseWriter, r *http.Request) {
	current, ok := s.requireCurrentSession(w, r)
	if !ok || !s.requireAccountCSRF(w, r) {
		return
	}
	var input struct {
		CurrentPassword string `json:"current_password"`
		Code            string `json:"code"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if _, ok := s.verifyAccountPassword(w, r, current.UserID, input.CurrentPassword); !ok {
		return
	}
	if !s.allowMFAAttempt(w, r, current.UserID) {
		return
	}
	if err := s.mfa.Verify(r.Context(), current.UserID, input.Code); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_mfa_code", "动态口令或恢复码无效")
		return
	}
	if err := s.mfa.Disable(r.Context(), current.UserID); err != nil && !errors.Is(err, mfa.ErrNotFound) {
		writeProblem(w, http.StatusInternalServerError, "server_error", "关闭多因素认证失败")
		return
	}
	s.clearTrustedDeviceCookie(w)
	s.recordAudit(r, audit.Event{
		ActorUserID: auditActor(current.UserID),
		EventType:   "mfa.disabled",
		Outcome:     audit.OutcomeSuccess,
	})
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) revokeAccountMFATrustedDevices(w http.ResponseWriter, r *http.Request) {
	current, ok := s.requireCurrentSession(w, r)
	if !ok || !s.requireAccountCSRF(w, r) {
		return
	}
	count, err := s.mfa.RevokeTrustedDevices(r.Context(), current.UserID)
	if err != nil {
		s.logger.Error("revoke account MFA trusted devices", "user_id", current.UserID, "error", err)
		writeProblem(w, http.StatusInternalServerError, "server_error", "移除受信任设备失败")
		return
	}
	s.clearTrustedDeviceCookie(w)
	s.recordAudit(r, audit.Event{
		ActorUserID: auditActor(current.UserID),
		EventType:   "mfa.trusted_devices.revoked",
		Outcome:     audit.OutcomeSuccess,
		Details:     map[string]any{"count": count},
	})
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) resetAdminUserMFA(w http.ResponseWriter, r *http.Request) {
	userID, ok := s.adminSessionUser(w, r)
	if !ok {
		return
	}
	if !s.authorizeSensitiveAdministratorTarget(w, r, userID) {
		return
	}
	if err := s.mfa.Disable(r.Context(), userID); err != nil && !errors.Is(err, mfa.ErrNotFound) {
		writeProblem(w, http.StatusInternalServerError, "server_error", "重置多因素认证失败")
		return
	}
	revokedSessions := s.sessionsForRevocation(r.Context(), userID, "")
	revoked, err := s.sessions.RevokeAll(r.Context(), userID, "")
	if err != nil {
		s.logger.Error("revoke sessions after admin MFA reset", "error", err)
		writeProblem(w, http.StatusInternalServerError, "server_error", "重置多因素认证后撤销会话失败")
		return
	}
	s.cleanupRevokedSessions(r.Context(), revokedSessions)
	if err := s.oauth.RevokeUserTokens(r.Context(), userID, "", s.now().UTC()); err != nil {
		s.logger.Error("revoke OAuth tokens after admin MFA reset", "error", err)
		writeProblem(w, http.StatusInternalServerError, "server_error", "重置多因素认证后撤销 OAuth 令牌失败")
		return
	}
	s.recordAudit(r, audit.Event{
		EventType: "mfa.reset_by_admin",
		Outcome:   audit.OutcomeSuccess,
		Details:   map[string]any{"user_id": userID, "sessions_revoked": revoked},
	})
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) verifyAccountPassword(w http.ResponseWriter, r *http.Request, userID, password string) (identity.User, bool) {
	user, err := s.users.Find(r.Context(), userID)
	if err != nil {
		writeProblem(w, http.StatusUnauthorized, "unauthorized", "登录会话无效")
		return identity.User{}, false
	}
	authenticated, err := s.passwords.Authenticate(r.Context(), user.Username, password)
	if err != nil || authenticated.ID != userID {
		writeProblem(w, http.StatusBadRequest, "current_password_invalid", "当前密码不正确")
		return identity.User{}, false
	}
	return user, true
}

func (s *server) requireAccountCSRF(w http.ResponseWriter, r *http.Request) bool {
	if !s.validCSRF(strings.TrimSpace(r.Header.Get("X-CSRF-Token")), r) {
		writeProblem(w, http.StatusBadRequest, "invalid_csrf", "账号安全页面已失效，请刷新后重试")
		return false
	}
	return true
}
