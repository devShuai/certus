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

	"certus/internal/client"
	"certus/internal/identity"
	"certus/internal/security"
	"certus/internal/session"
)

const (
	sessionCookieName = "certus_session"
	csrfCookieName    = "certus_csrf"
)

type loginPageData struct {
	Title           string
	Client          client.Client
	Methods         []loginMethodView
	ReturnTo        string
	CSRFToken       string
	Error           string
	PasswordEnabled bool
}

type loginMethodView struct {
	Label string
}

func (s *server) loginPage(w http.ResponseWriter, r *http.Request) {
	returnTo := validatedReturnTo(r.URL.Query().Get("continue"))
	if returnTo == "" {
		returnTo = "/portal"
	}
	page := loginPageData{
		Title:           "登录 Certus",
		ReturnTo:        returnTo,
		CSRFToken:       s.ensureCSRF(w, r),
		PasswordEnabled: true,
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
			http.Error(w, "未知的接入系统", http.StatusBadRequest)
			return
		}
		page.Client = item
		page.PasswordEnabled = slices.Contains(item.LoginMethods, client.LoginPassword)
		for _, method := range item.LoginMethods {
			page.Methods = append(page.Methods, loginMethodView{Label: loginMethodLabel(method)})
		}
	} else {
		page.Methods = []loginMethodView{{Label: loginMethodLabel(client.LoginPassword)}}
	}
	s.render(w, "login.html", page)
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
	if registered, ok := s.loginClient(r, returnTo); ok && !slices.Contains(registered.LoginMethods, client.LoginPassword) {
		writeProblem(w, http.StatusBadRequest, "login_method_not_allowed", "此系统未启用账号密码登录")
		return
	}
	user, err := s.passwords.Authenticate(r.Context(), r.Form.Get("username"), r.Form.Get("password"))
	if err != nil {
		message := "用户名或密码不正确"
		if errors.Is(err, identity.ErrCredentialLocked) {
			message = "登录失败次数过多，请稍后重试"
		}
		s.render(w, "login.html", loginPageData{
			Title:           "登录 Certus",
			Methods:         []loginMethodView{{Label: loginMethodLabel(client.LoginPassword)}},
			ReturnTo:        returnTo,
			CSRFToken:       s.ensureCSRF(w, r),
			Error:           message,
			PasswordEnabled: true,
		})
		return
	}
	ipAddress, _, _ := net.SplitHostPort(r.RemoteAddr)
	_, token, err := s.sessions.Create(r.Context(), user.ID, ipAddress, r.UserAgent())
	if err != nil {
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
		_ = s.sessions.Revoke(r.Context(), current.ID)
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
	if err != nil || supplied == "" || len(cookie.Value) != len(supplied) {
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
	w.WriteHeader(http.StatusNoContent)
}
