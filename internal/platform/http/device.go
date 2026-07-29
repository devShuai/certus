package httpserver

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"certus/internal/client"
	"certus/internal/oauth"
	"certus/internal/security"
)

type devicePageData struct {
	Title     string
	Client    client.Client
	Scopes    []string
	UserCode  string
	CSRFToken string
	Error     string
	Done      string
}

type deviceAttemptWindow struct {
	start time.Time
	count int
}

func (s *server) deviceAuthorization(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Content-Type must be application/x-www-form-urlencoded")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid form body")
		return
	}
	registered, ok := s.authenticateOAuthClient(w, r)
	if !ok {
		return
	}
	if !registered.SupportsGrant(client.GrantDeviceCode) {
		writeOAuthError(w, http.StatusBadRequest, "unauthorized_client", "device_code is not enabled")
		return
	}
	scopes, err := requestedScopes(r.Form.Get("scope"), registered, false)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_scope", err.Error())
		return
	}
	deviceCode, err := security.RandomToken(32)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not issue device code")
		return
	}
	userCode, err := randomUserCode()
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not issue user code")
		return
	}
	now := s.now().UTC()
	if err := s.oauth.SaveDeviceAuthorization(r.Context(), oauth.DeviceAuthorization{
		DeviceHash: security.HashToken(deviceCode),
		UserHash:   security.HashToken(normalizeUserCode(userCode)),
		ClientID:   registered.ID,
		Scope:      scopes,
		Status:     oauth.DevicePending,
		CreatedAt:  now,
		ExpiresAt:  now.Add(deviceCodeLifetime),
		Interval:   5 * time.Second,
	}); err != nil {
		s.logger.Error("save device authorization", "error", err)
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "could not save device authorization")
		return
	}
	verificationURI := s.cfg.Issuer + "/device"
	writeJSON(w, http.StatusOK, map[string]any{
		"device_code":               deviceCode,
		"user_code":                 userCode,
		"verification_uri":          verificationURI,
		"verification_uri_complete": verificationURI + "?user_code=" + url.QueryEscape(userCode),
		"expires_in":                int(deviceCodeLifetime / time.Second),
		"interval":                  5,
	})
}

func (s *server) devicePage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	userCode := displayUserCode(r.URL.Query().Get("user_code"))
	page := devicePageData{
		Title:     "设备登录 · Certus",
		UserCode:  userCode,
		CSRFToken: s.ensureCSRF(w, r),
	}
	if userCode == "" {
		s.render(w, "device.html", page)
		return
	}
	if !s.allowDeviceLookup(r) {
		w.Header().Set("Retry-After", "60")
		writeProblem(w, http.StatusTooManyRequests, "rate_limited", "设备代码尝试过多，请稍后重试")
		return
	}
	record, err := s.oauth.FindDeviceByUserCode(r.Context(), security.HashToken(normalizeUserCode(userCode)), s.now().UTC())
	if err != nil {
		page.Error = "设备代码无效或已过期"
		s.render(w, "device.html", page)
		return
	}
	registered, err := s.clients.Find(r.Context(), record.ClientID)
	if err != nil || !registered.Enabled {
		page.Error = "接入系统不可用"
		s.render(w, "device.html", page)
		return
	}
	if _, ok := s.currentSession(r); !ok {
		returnTo := "/device?user_code=" + url.QueryEscape(userCode)
		http.Redirect(w, r, "/login?continue="+url.QueryEscape(returnTo)+"&client_id="+url.QueryEscape(registered.ID), http.StatusFound)
		return
	}
	page.Client = registered
	page.Scopes = record.Scope
	s.render(w, "device.html", page)
}

func (s *server) deviceDecision(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request", "设备授权请求无效")
		return
	}
	if !s.validCSRF(r.Form.Get("csrf_token"), r) {
		writeProblem(w, http.StatusBadRequest, "invalid_csrf", "页面已失效，请刷新后重试")
		return
	}
	userCode := displayUserCode(r.Form.Get("user_code"))
	if r.Form.Get("action") == "lookup" {
		http.Redirect(w, r, "/device?user_code="+url.QueryEscape(userCode), http.StatusSeeOther)
		return
	}
	current, ok := s.currentSession(r)
	if !ok {
		http.Redirect(w, r, "/login?continue="+url.QueryEscape("/device?user_code="+url.QueryEscape(userCode)), http.StatusFound)
		return
	}
	approve := r.Form.Get("action") == "approve"
	if !approve && r.Form.Get("action") != "deny" {
		writeProblem(w, http.StatusBadRequest, "invalid_request", "无效的授权决定")
		return
	}
	if err := s.oauth.DecideDeviceAuthorization(
		r.Context(),
		security.HashToken(normalizeUserCode(userCode)),
		current.UserID,
		current.AuthenticatedAt,
		current.AuthMethods,
		current.AssuranceLevel,
		approve,
		s.now().UTC(),
	); err != nil {
		s.render(w, "device.html", devicePageData{
			Title:     "设备登录 · Certus",
			UserCode:  userCode,
			CSRFToken: s.ensureCSRF(w, r),
			Error:     "设备代码无效、已处理或已过期",
		})
		return
	}
	message := "已允许该设备登录，可以返回设备继续。"
	if !approve {
		message = "已拒绝该设备的登录请求。"
	}
	s.render(w, "device.html", devicePageData{
		Title:     "设备登录 · Certus",
		UserCode:  userCode,
		CSRFToken: s.ensureCSRF(w, r),
		Done:      message,
	})
}

func (s *server) deviceCodeToken(w http.ResponseWriter, r *http.Request, registered client.Client) {
	if !registered.SupportsGrant(client.GrantDeviceCode) {
		writeOAuthError(w, http.StatusBadRequest, "unauthorized_client", "device_code is not enabled")
		return
	}
	deviceCode := r.Form.Get("device_code")
	if deviceCode == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "device_code is required")
		return
	}
	record, err := s.oauth.PollDeviceAuthorization(
		r.Context(),
		security.HashToken(deviceCode),
		registered.ID,
		s.now().UTC(),
	)
	switch {
	case errors.Is(err, oauth.ErrAuthorizationPending):
		writeOAuthError(w, http.StatusBadRequest, "authorization_pending", "the user has not completed authorization")
		return
	case errors.Is(err, oauth.ErrSlowDown):
		writeOAuthError(w, http.StatusBadRequest, "slow_down", "polling too quickly")
		return
	case errors.Is(err, oauth.ErrAccessDenied):
		writeOAuthError(w, http.StatusBadRequest, "access_denied", "the user denied the request")
		return
	case errors.Is(err, oauth.ErrGrantExpired):
		writeOAuthError(w, http.StatusBadRequest, "expired_token", "the device code expired")
		return
	case err != nil:
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "the device code is invalid or already used")
		return
	}
	response, err := s.issueUserTokens(
		r, registered, record.UserID, record.Scope, "",
		record.AuthenticatedAt, record.AuthMethods, record.AssuranceLevel, true,
	)
	if err != nil {
		s.logger.Error("issue device tokens", "error", err)
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "token issuance failed")
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func normalizeUserCode(value string) string {
	return strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(value), "-", ""))
}

func displayUserCode(value string) string {
	normalized := normalizeUserCode(value)
	if len(normalized) != 8 {
		return ""
	}
	return normalized[:4] + "-" + normalized[4:]
}

func (s *server) allowDeviceLookup(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	now := s.now().UTC()
	s.deviceAttemptsMu.Lock()
	defer s.deviceAttemptsMu.Unlock()
	if len(s.deviceAttempts) > 4096 {
		for key, existing := range s.deviceAttempts {
			if now.Sub(existing.start) >= time.Minute {
				delete(s.deviceAttempts, key)
			}
		}
	}
	window := s.deviceAttempts[host]
	if window.start.IsZero() || now.Sub(window.start) >= time.Minute {
		s.deviceAttempts[host] = deviceAttemptWindow{start: now, count: 1}
		return true
	}
	if window.count >= 20 {
		return false
	}
	window.count++
	s.deviceAttempts[host] = window
	return true
}
