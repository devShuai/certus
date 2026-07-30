package httpserver

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"certus/internal/audit"
	"certus/internal/client"
	"certus/internal/identity"
	"certus/internal/oauth"
	"certus/internal/session"
)

const oauthConsentLifetime = 5 * time.Minute

type oauthConsentPageData struct {
	Title     string
	Client    client.Client
	User      identity.User
	Scopes    []oauthConsentScope
	CSRFToken string
}

type oauthConsentScope struct {
	Code        string
	Title       string
	Description string
}

func (s *server) requiresOAuthConsent(
	r *http.Request,
	request oauth.AuthorizationRequest,
	current session.Session,
) (bool, error) {
	if request.HasPrompt("consent") {
		return true, nil
	}
	consent, err := s.oauth.FindConsent(r.Context(), current.UserID, request.ClientID)
	if errors.Is(err, oauth.ErrConsentNotFound) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	return !consent.Covers(request.Scope), nil
}

func (s *server) renderOAuthConsent(
	w http.ResponseWriter,
	r *http.Request,
	registered client.Client,
	request oauth.AuthorizationRequest,
	current session.Session,
) {
	user, err := s.users.Find(r.Context(), current.UserID)
	if err != nil || user.Status != identity.UserActive {
		writeProblem(w, http.StatusUnauthorized, "unauthorized", "登录会话无效")
		return
	}
	query := r.URL.Query()
	query.Del("certus_reauth")
	requestURI := r.URL.Path
	if encoded := query.Encode(); encoded != "" {
		requestURI += "?" + encoded
	}
	now := s.now().UTC()
	transaction, err := s.signer.Sign(map[string]any{
		"purpose":     "oauth_consent",
		"user_id":     current.UserID,
		"session_id":  current.ID,
		"request_uri": requestURI,
		"iat":         now.Unix(),
		"exp":         now.Add(oauthConsentLifetime).Unix(),
	})
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "server_error", "创建授权确认请求失败")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     oauthConsentCookieName,
		Value:    transaction,
		Path:     "/oauth2/authorize/consent",
		MaxAge:   int(oauthConsentLifetime.Seconds()),
		HttpOnly: true,
		Secure:   s.secureCookies(),
		SameSite: http.SameSiteStrictMode,
	})
	s.render(w, "consent.html", oauthConsentPageData{
		Title:     "授权确认 · Certus",
		Client:    registered,
		User:      user,
		Scopes:    oauthConsentScopes(request.Scope),
		CSRFToken: s.ensureCSRF(w, r),
	})
}

func (s *server) oauthConsentDecision(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	r.Body = http.MaxBytesReader(w, r.Body, 32<<10)
	if err := r.ParseForm(); err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request", "授权确认请求无效")
		return
	}
	if !s.validCSRF(r.Form.Get("csrf_token"), r) {
		writeProblem(w, http.StatusBadRequest, "invalid_csrf", "授权确认页面已失效，请刷新后重试")
		return
	}
	current, ok := s.currentSession(r)
	if !ok {
		s.clearOAuthConsentCookie(w)
		writeProblem(w, http.StatusUnauthorized, "unauthorized", "登录会话已失效")
		return
	}
	requestURI, ok := s.oauthConsentTransaction(r, current)
	if !ok {
		s.clearOAuthConsentCookie(w)
		writeProblem(w, http.StatusBadRequest, "invalid_consent_transaction", "授权确认请求无效或已过期")
		return
	}
	target, err := url.ParseRequestURI(requestURI)
	if err != nil || target.Path != "/oauth2/authorize" {
		s.clearOAuthConsentCookie(w)
		writeProblem(w, http.StatusBadRequest, "invalid_consent_transaction", "授权确认请求无效")
		return
	}
	registered, err := s.clients.Find(r.Context(), target.Query().Get("client_id"))
	if err != nil {
		s.clearOAuthConsentCookie(w)
		writeProblem(w, http.StatusBadRequest, "invalid_client", "接入系统不可用")
		return
	}
	request, err := oauth.ParseAuthorizationRequest(target.Query(), registered)
	if err != nil {
		s.clearOAuthConsentCookie(w)
		writeProblem(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	s.clearOAuthConsentCookie(w)
	switch r.Form.Get("decision") {
	case "deny":
		s.recordAudit(r, audit.Event{
			ActorUserID: auditActor(current.UserID),
			EventType:   "oauth.consent.denied",
			ClientID:    auditClient(registered.ID),
			Outcome:     audit.OutcomeSuccess,
			Details:     map[string]any{"scopes": request.Scope},
		})
		redirectOAuthAuthorizationError(
			w, r, request.RedirectURI, request.State,
			"access_denied", "The end-user denied the authorization request",
		)
	case "allow":
		if _, err := s.oauth.GrantConsent(
			r.Context(), current.UserID, registered.ID, request.Scope, s.now().UTC(),
		); err != nil {
			s.logger.Error("grant OAuth consent", "client_id", registered.ID, "user_id", current.UserID, "error", err)
			redirectOAuthAuthorizationError(w, r, request.RedirectURI, request.State, "server_error", "Unable to record authorization")
			return
		}
		s.recordAudit(r, audit.Event{
			ActorUserID: auditActor(current.UserID),
			EventType:   "oauth.consent.granted",
			ClientID:    auditClient(registered.ID),
			Outcome:     audit.OutcomeSuccess,
			Details:     map[string]any{"scopes": request.Scope},
		})
		s.issueAuthorizationCode(w, r, request, current)
	default:
		writeProblem(w, http.StatusBadRequest, "invalid_request", "无效的授权决定")
	}
}

func (s *server) oauthConsentTransaction(r *http.Request, current session.Session) (string, bool) {
	cookie, err := r.Cookie(oauthConsentCookieName)
	if err != nil {
		return "", false
	}
	claims, err := s.signer.Verify(cookie.Value)
	if err != nil {
		return "", false
	}
	purpose, _ := claims["purpose"].(string)
	userID, _ := claims["user_id"].(string)
	sessionID, _ := claims["session_id"].(string)
	requestURI, _ := claims["request_uri"].(string)
	expiration, _ := claims["exp"].(float64)
	issuedAt, _ := claims["iat"].(float64)
	now := s.now().UTC().Unix()
	return requestURI, purpose == "oauth_consent" &&
		userID == current.UserID &&
		sessionID == current.ID &&
		strings.HasPrefix(requestURI, "/oauth2/authorize?") &&
		int64(expiration) > now &&
		int64(issuedAt) <= now+30
}

func (s *server) clearOAuthConsentCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     oauthConsentCookieName,
		Value:    "",
		Path:     "/oauth2/authorize/consent",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.secureCookies(),
		SameSite: http.SameSiteStrictMode,
	})
}

func oauthConsentScopes(scopes []string) []oauthConsentScope {
	result := make([]oauthConsentScope, 0, len(scopes))
	for _, scope := range scopes {
		view := oauthConsentScope{Code: scope, Title: scope, Description: "允许接入系统使用此授权范围。"}
		switch scope {
		case "openid":
			view.Title = "确认您的身份"
			view.Description = "允许接入系统获得稳定的用户标识。"
		case "profile":
			view.Title = "基本资料"
			view.Description = "允许读取显示名称和用户名。"
		case "email":
			view.Title = "邮箱地址"
			view.Description = "允许读取账号绑定的邮箱地址。"
		case "roles":
			view.Title = "角色与权限"
			view.Description = "允许读取您在此系统中的角色和权限点。"
		}
		result = append(result, view)
	}
	return result
}
