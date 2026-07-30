package httpserver

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
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
	oauthReauthCookieName  = "certus_oauth_reauth"
	oauthConsentCookieName = "certus_oauth_consent"
)

type loginPageData struct {
	Title               string
	Client              client.Client
	Methods             []loginMethodView
	LDAPSources         []loginSourceView
	OIDCSources         []loginSourceView
	ReturnTo            string
	CSRFToken           string
	Error               string
	PasswordEnabled     bool
	RegistrationEnabled bool
	Unavailable         bool
}

type loginMethodView struct {
	Label string
}

type loginSourceView struct {
	ID    string
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
		Title:               "登录 Certus",
		ReturnTo:            returnTo,
		CSRFToken:           csrfToken,
		Error:               message,
		PasswordEnabled:     true,
		RegistrationEnabled: s.cfg.Registration.Enabled,
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
		if page.PasswordEnabled {
			page.Methods = append(page.Methods, loginMethodView{Label: loginMethodLabel(client.LoginPassword)})
		}
		if err := s.populateLoginSources(r.Context(), &page, &item); err != nil {
			return loginPageData{}, err
		}
	} else {
		page.Methods = []loginMethodView{{Label: loginMethodLabel(client.LoginPassword)}}
		if err := s.populateLoginSources(r.Context(), &page, nil); err != nil {
			return loginPageData{}, err
		}
	}
	return page, nil
}

func (s *server) populateLoginSources(
	ctx context.Context,
	page *loginPageData,
	registered *client.Client,
) error {
	sources, err := s.identitySources.List(ctx)
	if err != nil {
		return err
	}
	bound := make(map[string]struct{})
	dynamicOnly := registered != nil && len(registered.IdentitySourceIDs) > 0
	if dynamicOnly {
		for _, sourceID := range registered.IdentitySourceIDs {
			bound[sourceID] = struct{}{}
		}
	}
	for _, source := range sources {
		if source.ArchivedAt != nil {
			if _, selected := bound[source.ID]; selected {
				page.Unavailable = true
			}
			continue
		}
		if dynamicOnly {
			if _, selected := bound[source.ID]; !selected {
				continue
			}
			delete(bound, source.ID)
		}
		if registered != nil && !dynamicOnly {
			continue
		}
		allowed := registered == nil
		switch source.Type {
		case federation.SourceLDAP:
			allowed = allowed || slices.Contains(registered.LoginMethods, client.LoginLDAP)
		case federation.SourceOIDC:
			allowed = allowed || slices.Contains(registered.LoginMethods, client.LoginOIDC)
		}
		if !allowed {
			page.Unavailable = true
			continue
		}
		if !source.Enabled {
			page.Unavailable = true
			continue
		}
		view := loginSourceView{ID: source.ID, Label: source.Name}
		switch source.Type {
		case federation.SourceLDAP:
			page.LDAPSources = append(page.LDAPSources, view)
		case federation.SourceOIDC:
			page.OIDCSources = append(page.OIDCSources, view)
		}
		page.Methods = append(page.Methods, loginMethodView{Label: source.Name})
	}
	if len(bound) > 0 {
		page.Unavailable = true
	}
	if registered == nil || !dynamicOnly {
		allowLDAP := registered == nil || slices.Contains(registered.LoginMethods, client.LoginLDAP)
		allowOIDC := registered == nil || slices.Contains(registered.LoginMethods, client.LoginOIDC)
		if allowLDAP {
			if s.ldap.Enabled() {
				page.LDAPSources = append(page.LDAPSources, loginSourceView{
					Label: legacyLDAPLabel(s.ldap),
				})
				page.Methods = append(page.Methods, loginMethodView{Label: legacyLDAPLabel(s.ldap)})
			} else if registered != nil {
				page.Unavailable = true
			}
		}
		if allowOIDC {
			if s.externalOIDC.Enabled() {
				page.OIDCSources = append(page.OIDCSources, loginSourceView{
					Label: s.externalOIDC.Label(),
				})
				page.Methods = append(page.Methods, loginMethodView{Label: s.externalOIDC.Label()})
			} else if registered != nil {
				page.Unavailable = true
			}
		}
	}
	return nil
}

func legacyLDAPLabel(authenticator *federation.LDAPAuthenticator) string {
	if authenticator != nil && strings.TrimSpace(authenticator.Label()) != "" {
		return authenticator.Label()
	}
	return loginMethodLabel(client.LoginLDAP)
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
	if !s.allowLoginAttempt(w, r, r.Form.Get("username")) {
		return
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
	sourceID := strings.TrimSpace(r.Form.Get("source_id"))
	clientID := ""
	var registered *client.Client
	if value, ok := s.loginClient(r, returnTo); ok {
		clientID = value.ID
		if !slices.Contains(value.LoginMethods, client.LoginLDAP) {
			writeProblem(w, http.StatusBadRequest, "login_method_not_allowed", "此系统未启用 LDAP 登录")
			return
		}
		registered = &value
	}
	authenticator, err := s.ldapAuthenticatorForLogin(r.Context(), sourceID, registered)
	if err != nil {
		writeLoginSourceError(w, err, "LDAP")
		return
	}
	if !s.allowLoginAttempt(w, r, r.Form.Get("username")) {
		return
	}
	profile, err := authenticator.Authenticate(r.Context(), r.Form.Get("username"), r.Form.Get("password"))
	if err != nil {
		s.recordAudit(r, audit.Event{
			EventType: "login.ldap",
			ClientID:  auditClient(clientID),
			Outcome:   audit.OutcomeFailure,
			Details: map[string]any{
				"username":  strings.TrimSpace(r.Form.Get("username")),
				"source_id": sourceID,
			},
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
	sourceID := strings.TrimSpace(r.URL.Query().Get("source_id"))
	var registered *client.Client
	if value, ok := s.loginClient(r, returnTo); ok {
		if !slices.Contains(value.LoginMethods, client.LoginOIDC) {
			writeProblem(w, http.StatusBadRequest, "login_method_not_allowed", "此系统未启用外部身份提供商登录")
			return
		}
		registered = &value
	}
	authenticator, err := s.oidcAuthenticatorForLogin(r.Context(), sourceID, registered)
	if err != nil {
		writeLoginSourceError(w, err, "OIDC")
		return
	}
	if !s.allowLoginSource(w, r, "login.oidc_source") {
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
		"purpose":   "external_oidc",
		"state":     state,
		"nonce":     nonce,
		"verifier":  verifier,
		"continue":  returnTo,
		"source_id": sourceID,
		"iat":       now.Unix(),
		"exp":       now.Add(5 * time.Minute).Unix(),
	})
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "server_error", "创建外部登录请求失败")
		return
	}
	target, err := authenticator.AuthorizationURL(r.Context(), state, nonce, verifier)
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
		s.metrics.RecordAuthentication("oidc", "failure")
		writeProblem(w, http.StatusBadRequest, "invalid_login_transaction", "外部登录请求已失效")
		return
	}
	claims, err := s.signer.Verify(cookie.Value)
	if err != nil || !s.validExternalOIDCClaims(claims, r.URL.Query().Get("state")) {
		s.metrics.RecordAuthentication("oidc", "failure")
		writeProblem(w, http.StatusBadRequest, "invalid_login_transaction", "外部登录请求无效或已过期")
		return
	}
	returnTo, _ := claims["continue"].(string)
	nonce, _ := claims["nonce"].(string)
	verifier, _ := claims["verifier"].(string)
	sourceID, _ := claims["source_id"].(string)
	var registered *client.Client
	if value, ok := s.loginClient(r, returnTo); ok {
		registered = &value
	}
	authenticator, err := s.oidcAuthenticatorForLogin(r.Context(), sourceID, registered)
	if err != nil {
		s.metrics.RecordAuthentication("oidc", "failure")
		writeLoginSourceError(w, err, "OIDC")
		return
	}
	if providerError := r.URL.Query().Get("error"); providerError != "" {
		s.metrics.RecordAuthentication("oidc", "failure")
		s.renderLoginError(w, r, returnTo, "外部身份提供商未完成登录")
		return
	}
	profile, err := authenticator.Exchange(r.Context(), r.URL.Query().Get("code"), nonce, verifier)
	if err != nil {
		s.metrics.RecordAuthentication("oidc", "failure")
		s.logger.Warn("complete external OIDC login", "error", err)
		s.renderLoginError(w, r, returnTo, "外部身份验证失败")
		return
	}
	user, err := s.externalUsers.ResolveExternalIdentity(r.Context(), profile, s.now().UTC())
	if err != nil {
		s.metrics.RecordAuthentication("oidc", "failure")
		s.logger.Error("resolve external OIDC identity", "error", err)
		s.renderLoginError(w, r, returnTo, "无法同步外部身份账号")
		return
	}
	if user.Status != identity.UserActive {
		s.metrics.RecordAuthentication("oidc", "failure")
		s.renderLoginError(w, r, returnTo, "账号当前不可登录")
		return
	}
	clientID := ""
	if registered != nil {
		clientID = registered.ID
	}
	s.completeLogin(w, r, user, returnTo, "oidc", clientID)
}

func (s *server) ldapAuthenticatorForLogin(
	ctx context.Context,
	sourceID string,
	registered *client.Client,
) (*federation.LDAPAuthenticator, error) {
	if err := allowClientIdentitySource(registered, sourceID, client.LoginLDAP); err != nil {
		return nil, err
	}
	if sourceID == "" {
		if !s.ldap.Enabled() {
			return nil, federation.ErrSourceDisabled
		}
		return s.ldap, nil
	}
	return s.identitySources.LDAPAuthenticator(ctx, sourceID)
}

func (s *server) oidcAuthenticatorForLogin(
	ctx context.Context,
	sourceID string,
	registered *client.Client,
) (*federation.OIDCAuthenticator, error) {
	if err := allowClientIdentitySource(registered, sourceID, client.LoginOIDC); err != nil {
		return nil, err
	}
	if sourceID == "" {
		if !s.externalOIDC.Enabled() {
			return nil, federation.ErrSourceDisabled
		}
		return s.externalOIDC, nil
	}
	return s.identitySources.OIDCAuthenticator(
		ctx,
		sourceID,
		s.cfg.Issuer+"/login/oidc/callback",
		s.outbound,
	)
}

func allowClientIdentitySource(
	registered *client.Client,
	sourceID string,
	method client.LoginMethod,
) error {
	if registered == nil {
		return nil
	}
	if !slices.Contains(registered.LoginMethods, method) {
		return fmt.Errorf("%w: login method is not allowed", federation.ErrInvalidSource)
	}
	if sourceID == "" {
		if len(registered.IdentitySourceIDs) > 0 {
			return fmt.Errorf("%w: legacy identity source is not bound to client", federation.ErrInvalidSource)
		}
		return nil
	}
	if len(registered.IdentitySourceIDs) == 0 ||
		!slices.Contains(registered.IdentitySourceIDs, sourceID) {
		return fmt.Errorf("%w: identity source is not bound to client", federation.ErrInvalidSource)
	}
	return nil
}

func writeLoginSourceError(w http.ResponseWriter, err error, sourceType string) {
	switch {
	case errors.Is(err, federation.ErrInvalidSource):
		writeProblem(w, http.StatusBadRequest, "login_method_not_allowed", "此系统未启用所选身份源")
	case errors.Is(err, federation.ErrSourceEncryptionUnavailable):
		writeProblem(w, http.StatusServiceUnavailable, "identity_source_unavailable", "身份源密钥暂时无法解密")
	case errors.Is(err, federation.ErrSourceNotFound),
		errors.Is(err, federation.ErrSourceArchived),
		errors.Is(err, federation.ErrSourceDisabled):
		writeProblem(w, http.StatusServiceUnavailable, "login_method_unavailable", sourceType+" 身份源不可用")
	default:
		writeProblem(w, http.StatusInternalServerError, "server_error", "读取身份源失败")
	}
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
		r.Context(), user.ID, s.requestIPAddress(r), r.UserAgent(), authMethods, assuranceLevel,
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
	w.Header().Set("Cache-Control", "no-store")
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	if err := r.ParseForm(); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request", "退出请求无效")
		return
	}
	if !s.validCSRF(r.Form.Get("csrf_token"), r) {
		writeProblem(w, http.StatusBadRequest, "invalid_csrf", "页面已失效，请刷新后重试")
		return
	}
	if current, ok := s.currentSession(r); ok {
		_ = s.sessions.Revoke(r.Context(), current.ID)
		s.cleanupRevokedSessions(r.Context(), []session.Session{current})
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
	case "/portal", "/account", "/admin", "/admin/clients", "/oauth2/authorize", "/cas/login", "/device":
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
	if !s.authorizeSensitiveAdministratorTarget(w, r, userID) {
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
	revokedSessions := s.sessionsForRevocation(r.Context(), userID, "")
	revoked, err := s.sessions.RevokeAll(r.Context(), userID, "")
	if err != nil {
		s.logger.Error("revoke sessions after admin password update", "error", err)
	} else {
		s.cleanupRevokedSessions(r.Context(), revokedSessions)
	}
	if err := s.oauth.RevokeUserTokens(r.Context(), userID, "", s.now().UTC()); err != nil {
		s.logger.Error("revoke OAuth tokens after admin password update", "error", err)
	}
	s.recordAudit(r, audit.Event{
		EventType: "password.set_by_admin",
		Outcome:   audit.OutcomeSuccess,
		Details:   map[string]any{"user_id": userID, "sessions_revoked": revoked},
	})
	w.WriteHeader(http.StatusNoContent)
}
