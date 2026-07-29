package httpserver

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"certus/internal/cas"
	"certus/internal/client"
	"certus/internal/config"
	"certus/internal/identity"
	"certus/internal/oauth"
	"certus/internal/oidc"
	"certus/internal/session"
)

func TestAuthorizationCodeDeviceAndCASExecution(t *testing.T) {
	logoutRequests := make(chan string, 1)
	service := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("parse SLO form: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		logoutRequests <- r.Form.Get("logoutRequest")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer service.Close()

	handler := newProtocolTestHandler(t, service.URL)
	browser := newTestBrowser(handler)
	browser.login(t, "/portal")

	verifier := strings.Repeat("v", 64)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	authorizeQuery := url.Values{
		"client_id":             {"integration"},
		"redirect_uri":          {"https://app.example.com/callback"},
		"response_type":         {"code"},
		"scope":                 {"openid profile email"},
		"state":                 {"state-value"},
		"nonce":                 {"nonce-value"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	authorized := browser.request(t, http.MethodGet, "/oauth2/authorize?"+authorizeQuery.Encode(), "", "")
	if authorized.Code != http.StatusFound {
		t.Fatalf("authorize: %d %s", authorized.Code, authorized.Body.String())
	}
	callback, err := url.Parse(authorized.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if callback.Query().Get("state") != "state-value" || callback.Query().Get("code") == "" {
		t.Fatalf("unexpected authorization redirect: %s", callback.String())
	}

	tokenForm := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {"integration"},
		"code":          {callback.Query().Get("code")},
		"redirect_uri":  {"https://app.example.com/callback"},
		"code_verifier": {verifier},
	}
	tokenResponse := browser.request(t, http.MethodPost, "/oauth2/token", tokenForm.Encode(), "application/x-www-form-urlencoded")
	if tokenResponse.Code != http.StatusOK {
		t.Fatalf("token: %d %s", tokenResponse.Code, tokenResponse.Body.String())
	}
	var tokens map[string]any
	if err := json.Unmarshal(tokenResponse.Body.Bytes(), &tokens); err != nil {
		t.Fatal(err)
	}
	if strings.Count(tokens["id_token"].(string), ".") != 2 || tokens["refresh_token"] == "" {
		t.Fatalf("missing OIDC tokens: %#v", tokens)
	}
	userinfo := httptest.NewRequest(http.MethodGet, "/oauth2/userinfo", nil)
	userinfo.Header.Set("Authorization", "Bearer "+tokens["access_token"].(string))
	userinfoResponse := httptest.NewRecorder()
	handler.ServeHTTP(userinfoResponse, userinfo)
	if userinfoResponse.Code != http.StatusOK || !strings.Contains(userinfoResponse.Body.String(), `"preferred_username":"alice"`) {
		t.Fatalf("userinfo: %d %s", userinfoResponse.Code, userinfoResponse.Body.String())
	}

	refreshForm := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {"integration"},
		"refresh_token": {tokens["refresh_token"].(string)},
	}
	refreshed := browser.request(t, http.MethodPost, "/oauth2/token", refreshForm.Encode(), "application/x-www-form-urlencoded")
	if refreshed.Code != http.StatusOK || !strings.Contains(refreshed.Body.String(), `"refresh_token"`) {
		t.Fatalf("refresh: %d %s", refreshed.Code, refreshed.Body.String())
	}

	deviceForm := url.Values{
		"client_id": {"integration"},
		"scope":     {"openid profile"},
	}
	deviceResponse := browser.request(t, http.MethodPost, "/oauth2/device_authorization", deviceForm.Encode(), "application/x-www-form-urlencoded")
	if deviceResponse.Code != http.StatusOK {
		t.Fatalf("device authorization: %d %s", deviceResponse.Code, deviceResponse.Body.String())
	}
	var device map[string]any
	if err := json.Unmarshal(deviceResponse.Body.Bytes(), &device); err != nil {
		t.Fatal(err)
	}
	userCode := device["user_code"].(string)
	review := browser.request(t, http.MethodGet, "/device?user_code="+url.QueryEscape(userCode), "", "")
	if review.Code != http.StatusOK || !strings.Contains(review.Body.String(), "允许 Integration 登录") {
		t.Fatalf("device review: %d %s", review.Code, review.Body.String())
	}
	decision := url.Values{
		"csrf_token": {browser.cookies[csrfCookieName].Value},
		"user_code":  {userCode},
		"action":     {"approve"},
	}
	approved := browser.request(t, http.MethodPost, "/device", decision.Encode(), "application/x-www-form-urlencoded")
	if approved.Code != http.StatusOK || !strings.Contains(approved.Body.String(), "已允许") {
		t.Fatalf("device approval: %d %s", approved.Code, approved.Body.String())
	}
	deviceTokenForm := url.Values{
		"grant_type":  {string(client.GrantDeviceCode)},
		"client_id":   {"integration"},
		"device_code": {device["device_code"].(string)},
	}
	deviceTokens := browser.request(t, http.MethodPost, "/oauth2/token", deviceTokenForm.Encode(), "application/x-www-form-urlencoded")
	if deviceTokens.Code != http.StatusOK || !strings.Contains(deviceTokens.Body.String(), `"access_token"`) {
		t.Fatalf("device token: %d %s", deviceTokens.Code, deviceTokens.Body.String())
	}

	casLogin := browser.request(t, http.MethodGet, "/cas/login?service="+url.QueryEscape(service.URL), "", "")
	if casLogin.Code != http.StatusFound {
		t.Fatalf("CAS login: %d %s", casLogin.Code, casLogin.Body.String())
	}
	serviceRedirect, err := url.Parse(casLogin.Header().Get("Location"))
	if err != nil || serviceRedirect.Query().Get("ticket") == "" {
		t.Fatalf("invalid CAS redirect: %s %v", casLogin.Header().Get("Location"), err)
	}
	validateQuery := url.Values{"service": {service.URL}, "ticket": {serviceRedirect.Query().Get("ticket")}}
	renewRejected := browser.request(t, http.MethodGet, "/cas/p3/serviceValidate?"+validateQuery.Encode()+"&renew=true", "", "")
	if !strings.Contains(renewRejected.Body.String(), `code="INVALID_TICKET"`) {
		t.Fatalf("SSO ticket unexpectedly passed renew validation: %d %s", renewRejected.Code, renewRejected.Body.String())
	}
	validated := browser.request(t, http.MethodGet, "/cas/p3/serviceValidate?"+validateQuery.Encode(), "", "")
	if validated.Code != http.StatusOK || !strings.Contains(validated.Body.String(), "<cas:user>alice</cas:user>") {
		t.Fatalf("CAS validate: %d %s", validated.Code, validated.Body.String())
	}
	replayed := browser.request(t, http.MethodGet, "/cas/p3/serviceValidate?"+validateQuery.Encode(), "", "")
	if !strings.Contains(replayed.Body.String(), `code="INVALID_TICKET"`) {
		t.Fatalf("CAS ticket was reusable: %d %s", replayed.Code, replayed.Body.String())
	}

	renewStart := browser.request(t, http.MethodGet, "/cas/login?service="+url.QueryEscape(service.URL)+"&renew=true", "", "")
	if renewStart.Code != http.StatusFound || !strings.HasPrefix(renewStart.Header().Get("Location"), "/login?") {
		t.Fatalf("CAS renew did not require credentials: %d %s", renewStart.Code, renewStart.Header().Get("Location"))
	}
	loginLocation, err := url.Parse(renewStart.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	returnTo := loginLocation.Query().Get("continue")
	renewLoginPage := browser.request(t, http.MethodGet, loginLocation.String(), "", "")
	if renewLoginPage.Code != http.StatusOK {
		t.Fatalf("CAS renew login page: %d %s", renewLoginPage.Code, renewLoginPage.Body.String())
	}
	renewLoginForm := url.Values{
		"csrf_token": {browser.cookies[csrfCookieName].Value},
		"continue":   {returnTo},
		"username":   {"alice"},
		"password":   {"correct horse battery staple"},
	}
	renewLogin := browser.request(t, http.MethodPost, "/login", renewLoginForm.Encode(), "application/x-www-form-urlencoded")
	if renewLogin.Code != http.StatusSeeOther || renewLogin.Header().Get("Location") != returnTo {
		t.Fatalf("CAS primary login: %d %s", renewLogin.Code, renewLogin.Header().Get("Location"))
	}
	renewTicketResponse := browser.request(t, http.MethodGet, returnTo, "", "")
	renewServiceRedirect, err := url.Parse(renewTicketResponse.Header().Get("Location"))
	if err != nil || renewServiceRedirect.Query().Get("ticket") == "" {
		t.Fatalf("CAS renew ticket redirect: %d %s %v", renewTicketResponse.Code, renewTicketResponse.Header().Get("Location"), err)
	}
	renewValidateQuery := url.Values{
		"service": {service.URL},
		"ticket":  {renewServiceRedirect.Query().Get("ticket")},
		"renew":   {"true"},
	}
	renewValidated := browser.request(t, http.MethodGet, "/cas/p3/serviceValidate?"+renewValidateQuery.Encode(), "", "")
	if !strings.Contains(renewValidated.Body.String(), "<cas:user>alice</cas:user>") {
		t.Fatalf("primary CAS ticket failed renew validation: %d %s", renewValidated.Code, renewValidated.Body.String())
	}

	loggedOut := browser.request(t, http.MethodGet, "/cas/logout", "", "")
	if loggedOut.Code != http.StatusFound {
		t.Fatalf("CAS logout: %d %s", loggedOut.Code, loggedOut.Body.String())
	}
	select {
	case request := <-logoutRequests:
		if !strings.Contains(request, ">alice</saml:NameID>") || !strings.Contains(request, "<samlp:SessionIndex>ST-") {
			t.Fatalf("unexpected SLO request: %s", request)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("CAS back-channel logout was not sent")
	}
}

func newProtocolTestHandler(t *testing.T, serviceURL string) http.Handler {
	t.Helper()
	user, err := identity.NewUser(identity.CreateUser{
		Username:    "alice",
		DisplayName: "Alice",
		Email:       stringPointer("alice@example.com"),
	}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	users := identity.NewMemoryUserRepository(user)
	if err := identity.NewPasswordService(users).Set(context.Background(), user.ID, "correct horse battery staple"); err != nil {
		t.Fatal(err)
	}
	clients := client.NewMemoryRepository(client.Client{
		ID:              "integration",
		Name:            "Integration",
		ApplicationType: client.ApplicationPublic,
		Protocols:       []client.Protocol{client.ProtocolOAuth21, client.ProtocolCAS},
		GrantTypes:      []client.GrantType{client.GrantAuthorizationCode, client.GrantRefreshToken, client.GrantDeviceCode},
		RedirectURIs:    []string{"https://app.example.com/callback"},
		LoginMethods:    []client.LoginMethod{client.LoginPassword},
		AllowedScopes:   []string{"openid", "profile", "email"},
		CASVersion:      client.CASVersion3,
		CASServiceURLs:  []string{serviceURL},
		CASRenew:        true,
		CASSingleLogout: true,
		Enabled:         true,
	})
	handler, err := NewWithDependencies(context.Background(), config.Config{Issuer: "https://auth.example.com"}, slog.New(slog.NewTextHandler(io.Discard, nil)), Dependencies{
		Clients:   clients,
		Users:     users,
		Passwords: users,
		Sessions:  session.NewMemoryRepository(),
		OAuth:     oauth.NewMemoryRepository(),
		CAS:       cas.NewMemoryRepository(),
		Keys:      &oidc.MemoryKeyRepository{},
	})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

type testBrowser struct {
	handler http.Handler
	cookies map[string]*http.Cookie
}

func newTestBrowser(handler http.Handler) *testBrowser {
	return &testBrowser{handler: handler, cookies: make(map[string]*http.Cookie)}
}

func (b *testBrowser) request(t *testing.T, method, target, body, contentType string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, target, strings.NewReader(body))
	if contentType != "" {
		request.Header.Set("Content-Type", contentType)
	}
	for _, cookie := range b.cookies {
		request.AddCookie(cookie)
	}
	response := httptest.NewRecorder()
	b.handler.ServeHTTP(response, request)
	for _, cookie := range response.Result().Cookies() {
		b.cookies[cookie.Name] = cookie
	}
	return response
}

func (b *testBrowser) login(t *testing.T, returnTo string) {
	t.Helper()
	page := b.request(t, http.MethodGet, "/login?continue="+url.QueryEscape(returnTo), "", "")
	if page.Code != http.StatusOK {
		t.Fatalf("login page: %d %s", page.Code, page.Body.String())
	}
	form := url.Values{
		"csrf_token": {b.cookies[csrfCookieName].Value},
		"continue":   {returnTo},
		"username":   {"alice"},
		"password":   {"correct horse battery staple"},
	}
	response := b.request(t, http.MethodPost, "/login", form.Encode(), "application/x-www-form-urlencoded")
	if response.Code != http.StatusSeeOther || b.cookies[sessionCookieName] == nil {
		t.Fatalf("login: %d %s", response.Code, response.Body.String())
	}
}

func stringPointer(value string) *string {
	return &value
}
