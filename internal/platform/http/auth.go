package httpserver

import (
	"crypto/subtle"
	"errors"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"certus/internal/audit"
	"certus/internal/client"
	"certus/internal/federation"
	"certus/internal/identity"
	"certus/internal/security"
	"certus/internal/session"
)

const (
	sessionCookieName      = "certus_session"
	csrfCookieName         = "certus_csrf"
	externalOIDCCookieName = "certus_oidc_transaction"
	mfaCookieName          = "certus_mfa_transaction"
)

type loginPageData struct {
	Title           string
	Client          client.Client
	Methods         []loginMethodView
	ReturnTo        string
	CSRFToken       string
	Error           string
	PasswordEnabled bool
	LDAPEnabled     bool
	OIDCEnabled     bool
	OIDCLabel       string
	Unavailable     bool
}

type loginMethodView struct {
	Label string
}

func (s *server) loginPage(w http.ResponseWriter, r *http.Request) {
	returnTo := validatedReturnTo(r.URL.Query().Get("continue"))
	if returnTo == "" {
		returnTo = "/portal"
	}
	page, err := s.newLoginPageData(r, returnTo, s.ensureCSRF(w, r), "")
	if err != nil {
		http.Error(w, "未知的接入系统", http.StatusBadRequest)
		return
	}
	s.render(w, "login.html", page)
}

func (s *server) newLoginPageData(r *http.Request, returnTo, csrfToken, message string) (loginPageData, error) {
	page := loginPageData{
		Title:           "登录 Certus",
		ReturnTo:        returnTo,
		CSRFToken:       csrfToken,
		Error:           message,
		PasswordEnabled: true,
		LDAPEnabled:     s.ldap.Enabled(),
		OIDCEnabled:     s.externalOIDC.Enabled(),
		OIDCLabel:       s.externalOIDC.Label(),
	}
	clientID := r.URL.Query().Get("client_id")
	if clientID == "" {
		if target, err := url.Parse(returnTo); err == nil {
			clientID = target.Query().Get("client_id")
		}
	}
	if clientID != "" {
		item, err := s.clients.Find(r.Context(), clientID)
		if err != nil {
			return loginPageData{}, err
		}
		if !item.Enabled || item.ArchivedAt != nil {
			return loginPageData{}, client.ErrNotFound
		}
		page.Client = item
		page.PasswordEnabled = slices.Contains(item.LoginMethods, client.LoginPassword)
		page.LDAPEnabled = slices.Contains(item.LoginMethods, client.LoginLDAP) && s.ldap.Enabled()
		page.OIDCEnabled = slices.Contains(item.LoginMethods, client.LoginOIDC) && s.externalOIDC.Enabled()
		for _, method := range item.LoginMethods {
			page.Methods = append(page.Methods, loginMethodView{Label: loginMethodLabel(method)})
			if method == client.LoginLDAP && !s.ldap.Enabled() || method == client.LoginOIDC && !s.externalOIDC.Enabled() {
				page.Unavailable = true
			}
		}
	} else {
		page.Methods = []loginMethodView{{Label: loginMethodLabel(client.LoginPassword)}}
		if s.ldap.Enabled() {
			page.Methods = append(page.Methods, loginMethodView{Label: loginMethodLabel(client.LoginLDAP)})
		}
		if s.externalOIDC.Enabled() {
			page.Methods = append(page.Methods, loginMethodView{Label: loginMethodLabel(client.LoginOIDC)})
		}
	}
	return page, nil
}

func (s *server) loginPassword(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request", "登录请求无效")
		return
	}
	returnTo := validatedReturnTo(r.Form.Get("continue"))
	if returnTo == "" {
		returnTo = "/portal"
	}
	if !s.validCSRF(r.Form.Get("csrf_token"), r) {
		writeProblem(w, http.StatusBadRequest, "invalid_csrf", "登录页面已失效，请刷新后重试")
		return
	}
	clientID := ""
	if registered, ok := s.loginClient(r, returnTo); ok {
		clientID = registered.ID
		if !slices.Contains(registered.LoginMethods, client.LoginPassword) {
			writeProblem(w, http.StatusBadRequest, "login_method_not_allowed", "此系统未启用账号密码登录")
			return
		}
	}
	user, err := s.passwords.Authenticate(r.Context(), r.Form.Get("username"), r.Form.Get("password"))
	if err != nil {
		s.recordAudit(r, audit.Event{
			EventType: "login.password",
			ClientID:  auditClient(clientID),
			Outcome:   audit.OutcomeFailure,
			Details: map[string]any{
				"username": strings.ToLower(strings.TrimSpace(r.Form.Get("username"))),
				"locked":   errors.Is(err, identity.ErrCredentialLocked),
			},
		})
		message := "用户名或密码不正确"
		if errors.Is(err, identity.ErrCredentialLocked) {
			message = "登录失败次数过多，请稍后重试"
		}
		s.renderLoginError(w, r, returnTo, message)
		return
	}
	s.completeLogin(w, r, user, returnTo, "password", clientID)
}

func (s *server) loginLDAP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request", "登录请求无效")
		return
	}
	returnTo := validatedReturnTo(r.Form.Get("continue"))
	if returnTo == "" {
		returnTo = "/portal"
	}
	if !s.validCSRF(r.Form.Get("csrf_token"), r) {
		writeProblem(w, http.StatusBadRequest, "invalid_csrf", "登录页面已失效，请刷新后重试")
		return
	}
	if !s.ldap.Enabled() {
		writeProblem(w, http.StatusServiceUnavailable, "login_method_unavailable", "LDAP 身份源尚未配置")
		return
	}
	clientID := ""
	if registered, ok := s.loginClient(r, returnTo); ok {
		clientID = registered.ID
		if !slices.Contains(registered.LoginMethods, client.LoginLDAP) {
			writeProblem(w, http.StatusBadRequest, "login_method_not_allowed", "此系统未启用 LDAP 登录")
			return
		}
	}
	profile, err := s.ldap.Authenticate(r.Context(), r.Form.Get("username"), r.Form.Get("password"))
	if err != nil {
		s.recordAudit(r, audit.Event{
			EventType: "login.ldap",
			ClientID:  auditClient(clientID),
			Outcome:   audit.OutcomeFailure,
			Details:   map[string]any{"username": strings.TrimSpace(r.Form.Get("username"))},
		})
		if errors.Is(err, federation.ErrUnavailable) {
			s.logger.Warn("LDAP login unavailable", "error", err)
			s.renderLoginError(w, r, returnTo, "LDAP 身份源暂时不可用，请稍后重试")
			return
		}
		s.renderLoginError(w, r, returnTo, "LDAP 用户名或密码不正确")
		return
	}
	user, err := s.externalUsers.ResolveExternalIdentity(r.Context(), profile, s.now().UTC())
	if err != nil {
		s.logger.Error("resolve LDAP identity", "error", err)
		s.renderLoginError(w, r, returnTo, "无法同步 LDAP 账号")
		return
	}
	if user.Status != identity.UserActive {
		s.renderLoginError(w, r, returnTo, "账号当前不可登录")
		return
	}
	s.completeLogin(w, r, user, returnTo, "ldap", clientID)
}

func (s *server) loginOIDC(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	returnTo := validatedReturnTo(r.URL.Query().Get("continue"))
	if returnTo == "" {
		returnTo = "/portal"
	}
	if !s.externalOIDC.Enabled() {
		writeProblem(w, http.StatusServiceUnavailable, "login_method_unavailable", "外部 OIDC 身份源尚未配置")
		return
	}
	if registered, ok := s.loginClient(r, returnTo); ok && !slices.Contains(registered.LoginMethods, client.LoginOIDC) {
		writeProblem(w, http.StatusBadRequest, "login_method_not_allowed", "此系统未启用外部身份提供商登录")
		return
	}
	state, err := security.RandomToken(24)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "server_error", "创建外部登录请求失败")
		return
	}
	nonce, err := security.RandomToken(24)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "server_error", "创建外部登录请求失败")
		return
	}
	verifier, err := security.RandomToken(32)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "server_error", "创建外部登录请求失败")
		return
	}
	now := s.now().UTC()
	transaction, err := s.signer.Sign(map[string]any{
		"purpose":  "external_oidc",
		"state":    state,
		"nonce":    nonce,
		"verifier": verifier,
		"continue": returnTo,
		"iat":      now.Unix(),
		"exp":      now.Add(5 * time.Minute).Unix(),
	})
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "server_error", "创建外部登录请求失败")
		return
	}
	target, err := s.externalOIDC.AuthorizationURL(r.Context(), state, nonce, verifier)
	if err != nil {
		s.logger.Warn("start external OIDC login", "error", err)
		writeProblem(w, http.StatusBadGateway, "identity_provider_unavailable", "外部身份提供商暂时不可用")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     externalOIDCCookieName,
		Value:    transaction,
		Path:     "/login/oidc/callback",
		MaxAge:   int((5 * time.Minute).Seconds()),
		HttpOnly: true,
		Secure:   s.secureCookies(),
		SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, target, http.StatusFound)
}

func (s *server) loginOIDCCallback(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	cookie, err := r.Cookie(externalOIDCCookieName)
	s.clearExternalOIDCCookie(w)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_login_transaction", "外部登录请求已失效")
		return
	}
	claims, err := s.signer.Verify(cookie.Value)
	if err != nil || !s.validExternalOIDCClaims(claims, r.URL.Query().Get("state")) {
		writeProblem(w, http.StatusBadRequest, "invalid_login_transaction", "外部登录请求无效或已过期")
		return
	}
	returnTo, _ := claims["continue"].(string)
	nonce, _ := claims["nonce"].(string)
	verifier, _ := claims["verifier"].(string)
	if providerError := r.URL.Query().Get("error"); providerError != "" {
		s.renderLoginError(w, r, returnTo, "外部身份提供商未完成登录")
		return
	}
	profile, err := s.externalOIDC.Exchange(r.Context(), r.URL.Query().Get("code"), nonce, verifier)
	if err != nil {
		s.logger.Warn("complete external OIDC login", "error", err)
		s.renderLoginError(w, r, returnTo, "外部身份验证失败")
		return
	}
	user, err := s.externalUsers.ResolveExternalIdentity(r.Context(), profile, s.now().UTC())
	if err != nil {
		s.logger.Error("resolve external OIDC identity", "error", err)
		s.renderLoginError(w, r, returnTo, "无法同步外部身份账号")
		return
	}
	if user.Status != identity.UserActive {
		s.renderLoginError(w, r, returnTo, "账号当前不可登录")
		return
	}
	clientID := ""
	if registered, ok := s.loginClient(r, returnTo); ok {
		clientID = registered.ID
	}
	s.completeLogin(w, r, user, returnTo, "oidc", clientID)
}

func (s *server) validExternalOIDCClaims(claims map[string]any, state string) bool {
	purpose, _ := claims["purpose"].(string)
	expectedState, _ := claims["state"].(string)
	nonce, _ := claims["nonce"].(string)
	verifier, _ := claims["verifier"].(string)
	returnTo, _ := claims["continue"].(string)
	expiration, _ := claims["exp"].(float64)
	issuedAt, _ := claims["iat"].(float64)
	now := s.now().UTC().Unix()
	return purpose == "external_oidc" &&
		state != "" &&
		subtle.ConstantTimeCompare([]byte(expectedState), []byte(state)) == 1 &&
		nonce != "" &&
		verifier != "" &&
		validatedReturnTo(returnTo) != "" &&
		int64(expiration) > now &&
		int64(issuedAt) <= now+30
}

func (s *server) clearExternalOIDCCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     externalOIDCCookieName,
		Value:    "",
		Path:     "/login/oidc/callback",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.secureCookies(),
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *server) renderLoginError(w http.ResponseWriter, r *http.Request, returnTo, message string) {
	page, err := s.newLoginPageData(r, returnTo, s.ensureCSRF(w, r), message)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_client", "未知的接入系统")
		return
	}
	s.render(w, "login.html", page)
}

func (s *server) completeLogin(w http.ResponseWriter, r *http.Request, user identity.User, returnTo, method, clientID string) {
	required, err := s.mfa.RequiresChallenge(r.Context(), user.ID)
	if err != nil {
		s.recordAudit(r, audit.Event{
			ActorUserID: auditActor(user.ID),
			EventType:   "login." + method,
			ClientID:    auditClient(clientID),
			Outcome:     audit.OutcomeFailure,
			Details:     map[string]any{"reason": "mfa_unavailable"},
		})
		s.logger.Error("read MFA login requirement", "user_id", user.ID, "error", err)
		writeProblem(w, http.StatusServiceUnavailable, "mfa_unavailable", "多因素认证暂时不可用，已拒绝降级登录")
		return
	}
	if required {
		s.beginMFAChallenge(w, r, user.ID, returnTo, method, clientID)
		return
	}
	s.createLoginSession(w, r, user, returnTo, method, clientID, false)
}

func (s *server) createLoginSession(w http.ResponseWriter, r *http.Request, user identity.User, returnTo, method, clientID string, mfaVerified bool) {
	ipAddress, _, _ := net.SplitHostPort(r.RemoteAddr)
	authMethods := []string{"pwd"}
	if method == "oidc" {
		authMethods = []string{"federated"}
	}
	assuranceLevel := "urn:certus:aal:1"
	if mfaVerified {
		authMethods = append(authMethods, "otp")
		assuranceLevel = "urn:certus:aal:2"
	}
	_, token, err := s.sessions.CreateWithMethods(
		r.Context(), user.ID, ipAddress, r.UserAgent(), authMethods, assuranceLevel,
	)
	if err != nil {
		s.recordAudit(r, audit.Event{
			ActorUserID: auditActor(user.ID),
			EventType:   "login." + method,
			ClientID:    auditClient(clientID),
			Outcome:     audit.OutcomeFailure,
			Details:     map[string]any{"reason": "session_creation_failed"},
		})
		s.logger.Error("create login session", "error", err)
		writeProblem(w, http.StatusInternalServerError, "server_error", "创建登录会话失败")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   int((12 * time.Hour).Seconds()),
		HttpOnly: true,
		Secure:   s.secureCookies(),
		SameSite: http.SameSiteLaxMode,
	})
	s.recordAudit(r, audit.Event{
		ActorUserID: auditActor(user.ID),
		EventType:   "login." + method,
		ClientID:    auditClient(clientID),
		Outcome:     audit.OutcomeSuccess,
	})
	http.Redirect(w, r, returnTo, http.StatusSeeOther)
}

func (s *server) loginClient(r *http.Request, returnTo string) (client.Client, bool) {
	target, err := url.Parse(returnTo)
	if err != nil {
		return client.Client{}, false
	}
	switch target.Path {
	case "/oauth2/authorize":
		item, err := s.clients.Find(r.Context(), target.Query().Get("client_id"))
		return item, err == nil
	case "/device":
		code := displayUserCode(target.Query().Get("user_code"))
		record, err := s.oauth.FindDeviceByUserCode(r.Context(), security.HashToken(normalizeUserCode(code)), s.now().UTC())
		if err != nil {
			return client.Client{}, false
		}
		item, err := s.clients.Find(r.Context(), record.ClientID)
		return item, err == nil
	case "/cas/login":
		return s.findCASClient(r.Context(), target.Query().Get("service"))
	default:
		return client.Client{}, false
	}
}

func (s *server) logout(w http.ResponseWriter, r *http.Request) {
	if current, ok := s.currentSession(r); ok {
		_ = s.cas.DeleteServiceSessions(r.Context(), current.ID)
		_ = s.sessions.Revoke(r.Context(), current.ID)
		s.recordAudit(r, audit.Event{
			ActorUserID: auditActor(current.UserID),
			EventType:   "logout",
			Outcome:     audit.OutcomeSuccess,
			Details:     map[string]any{"session_id": current.ID},
		})
	}
	s.clearSessionCookie(w)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *server) currentSession(r *http.Request) (session.Session, bool) {
	cookie, err := r.Cookie(sessionCookieName)
	if err != nil {
		return session.Session{}, false
	}
	current, err := s.sessions.Find(r.Context(), cookie.Value)
	if err != nil {
		return session.Session{}, false
	}
	user, err := s.users.Find(r.Context(), current.UserID)
	if err != nil || user.Status != identity.UserActive {
		return session.Session{}, false
	}
	return current, true
}

func (s *server) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.secureCookies(),
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *server) ensureCSRF(w http.ResponseWriter, r *http.Request) string {
	if cookie, err := r.Cookie(csrfCookieName); err == nil && len(cookie.Value) >= 32 {
		return cookie.Value
	}
	token, err := security.RandomToken(24)
	if err != nil {
		panic(err)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   int((30 * time.Minute).Seconds()),
		HttpOnly: true,
		Secure:   s.secureCookies(),
		SameSite: http.SameSiteStrictMode,
	})
	return token
}

func (s *server) validCSRF(supplied string, r *http.Request) bool {
	cookie, err := r.Cookie(csrfCookieName)
	if err != nil || len(supplied) < 32 || len(cookie.Value) != len(supplied) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(supplied)) == 1
}

func (s *server) secureCookies() bool {
	return strings.HasPrefix(strings.ToLower(s.cfg.Issuer), "https://")
}

func validatedReturnTo(value string) string {
	if value == "" {
		return ""
	}
	target, err := url.Parse(value)
	if err != nil || target.IsAbs() || target.Host != "" || !strings.HasPrefix(target.Path, "/") || strings.HasPrefix(target.Path, "//") {
		return ""
	}
	switch target.Path {
	case "/portal", "/oauth2/authorize", "/cas/login", "/device":
		return target.String()
	default:
		return ""
	}
}

func (s *server) setUserPassword(w http.ResponseWriter, r *http.Request) {
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
	var input struct {
		Password string `json:"password"`
	}
	if err := decodeJSON(w, r, &input); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	if err := s.passwords.Set(r.Context(), userID, input.Password); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_password", err.Error())
		return
	}
	revoked, err := s.sessions.RevokeAll(r.Context(), userID, "")
	if err != nil {
		s.logger.Error("revoke sessions after admin password update", "error", err)
	}
	s.recordAudit(r, audit.Event{
		EventType: "password.set_by_admin",
		Outcome:   audit.OutcomeSuccess,
		Details:   map[string]any{"user_id": userID, "sessions_revoked": revoked},
	})
	w.WriteHeader(http.StatusNoContent)
}
