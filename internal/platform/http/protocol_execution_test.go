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

	"certus/internal/access"
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
		"scope":                 {"openid profile email roles"},
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
	idTokenParts := strings.Split(tokens["id_token"].(string), ".")
	idTokenClaims, err := base64.RawURLEncoding.DecodeString(idTokenParts[1])
	if err != nil ||
		!strings.Contains(string(idTokenClaims), `"roles":["approver"]`) ||
		!strings.Contains(string(idTokenClaims), `"permissions":["invoice.approve"]`) ||
		!strings.Contains(string(idTokenClaims), `"amr":["pwd"]`) ||
		!strings.Contains(string(idTokenClaims), `"acr":"urn:certus:aal:1"`) {
		t.Fatalf("ID Token missing access claims: %s %v", idTokenClaims, err)
	}
	userinfo := httptest.NewRequest(http.MethodGet, "/oauth2/userinfo", nil)
	userinfo.Header.Set("Authorization", "Bearer "+tokens["access_token"].(string))
	userinfoResponse := httptest.NewRecorder()
	handler.ServeHTTP(userinfoResponse, userinfo)
	if userinfoResponse.Code != http.StatusOK ||
		!strings.Contains(userinfoResponse.Body.String(), `"preferred_username":"alice"`) ||
		!strings.Contains(userinfoResponse.Body.String(), `"roles":["approver"]`) ||
		!strings.Contains(userinfoResponse.Body.String(), `"permissions":["invoice.approve"]`) {
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
	if validated.Code != http.StatusOK ||
		!strings.Contains(validated.Body.String(), "<cas:user>alice</cas:user>") ||
		!strings.Contains(validated.Body.String(), "<cas:role>approver</cas:role>") ||
		!strings.Contains(validated.Body.String(), "<cas:permission>invoice.approve</cas:permission>") {
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

func TestCASProxyGrantingAndProxyTicketExecution(t *testing.T) {
	type callbackValues struct {
		pgt string
		iou string
	}
	callbacks := make(chan callbackValues, 1)
	service := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callbacks <- callbackValues{
			pgt: r.URL.Query().Get("pgtId"),
			iou: r.URL.Query().Get("pgtIou"),
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer service.Close()

	handler := newProtocolTestHandler(t, service.URL, service.Client())
	browser := newTestBrowser(handler)
	browser.login(t, "/portal")

	login := browser.request(t, http.MethodGet, "/cas/login?service="+url.QueryEscape(service.URL), "", "")
	serviceRedirect, err := url.Parse(login.Header().Get("Location"))
	if err != nil || serviceRedirect.Query().Get("ticket") == "" {
		t.Fatalf("invalid CAS redirect: %d %s %v", login.Code, login.Header().Get("Location"), err)
	}
	callbackURL := service.URL + "/proxy/callback?tenant=certus"
	validationQuery := url.Values{
		"service": {service.URL},
		"ticket":  {serviceRedirect.Query().Get("ticket")},
		"pgtUrl":  {callbackURL},
	}
	validated := browser.request(t, http.MethodGet, "/cas/p3/serviceValidate?"+validationQuery.Encode(), "", "")
	if validated.Code != http.StatusOK || !strings.Contains(validated.Body.String(), "<cas:proxyGrantingTicket>PGTIOU-") {
		t.Fatalf("CAS PGT validation: %d %s", validated.Code, validated.Body.String())
	}
	var callback callbackValues
	select {
	case callback = <-callbacks:
	case <-time.After(2 * time.Second):
		t.Fatal("CAS PGT callback was not sent")
	}
	if !strings.HasPrefix(callback.pgt, "PGT-") || !strings.HasPrefix(callback.iou, "PGTIOU-") ||
		!strings.Contains(validated.Body.String(), callback.iou) {
		t.Fatalf("unexpected PGT callback: %#v response=%s", callback, validated.Body.String())
	}

	proxyQuery := url.Values{"pgt": {callback.pgt}, "targetService": {service.URL}}
	proxied := browser.request(t, http.MethodGet, "/cas/proxy?"+proxyQuery.Encode(), "", "")
	if proxied.Code != http.StatusOK || !strings.Contains(proxied.Body.String(), "<cas:proxyTicket>PT-") {
		t.Fatalf("CAS proxy ticket: %d %s", proxied.Code, proxied.Body.String())
	}
	start := strings.Index(proxied.Body.String(), "PT-")
	end := strings.Index(proxied.Body.String()[start:], "</cas:proxyTicket>")
	proxyTicket := proxied.Body.String()[start : start+end]
	proxyValidateQuery := url.Values{"service": {service.URL}, "ticket": {proxyTicket}}
	proxyValidated := browser.request(t, http.MethodGet, "/cas/p3/proxyValidate?"+proxyValidateQuery.Encode(), "", "")
	if !strings.Contains(proxyValidated.Body.String(), "<cas:user>alice</cas:user>") ||
		!strings.Contains(proxyValidated.Body.String(), "<cas:proxy>"+callbackURL+"</cas:proxy>") {
		t.Fatalf("CAS proxy validation: %d %s", proxyValidated.Code, proxyValidated.Body.String())
	}
	replayed := browser.request(t, http.MethodGet, "/cas/p3/proxyValidate?"+proxyValidateQuery.Encode(), "", "")
	if !strings.Contains(replayed.Body.String(), `code="INVALID_TICKET"`) {
		t.Fatalf("CAS proxy ticket was reusable: %d %s", replayed.Code, replayed.Body.String())
	}
}

func TestOIDCAuthenticationRequestPrompts(t *testing.T) {
	handler := newProtocolTestHandler(t, "https://service.example.com")

	silentBrowser := newTestBrowser(handler)
	silentQuery := oidcAuthorizationQuery("silent-state")
	silentQuery.Set("prompt", "none")
	silent := silentBrowser.request(t, http.MethodGet, "/oauth2/authorize?"+silentQuery.Encode(), "", "")
	if silent.Code != http.StatusFound {
		t.Fatalf("silent authorize: %d %s", silent.Code, silent.Body.String())
	}
	silentCallback, err := url.Parse(silent.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if silentCallback.Host != "app.example.com" ||
		silentCallback.Query().Get("error") != "login_required" ||
		silentCallback.Query().Get("state") != "silent-state" {
		t.Fatalf("unexpected silent authorization response: %s", silentCallback.String())
	}

	browser := newTestBrowser(handler)
	browser.login(t, "/portal")
	freshQuery := oidcAuthorizationQuery("fresh-state")
	freshQuery.Set("prompt", "none")
	freshQuery.Set("max_age", "300")
	fresh := browser.request(t, http.MethodGet, "/oauth2/authorize?"+freshQuery.Encode(), "", "")
	freshCallback, err := url.Parse(fresh.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if fresh.Code != http.StatusFound || freshCallback.Query().Get("code") == "" {
		t.Fatalf("fresh silent authorize: %d %s", fresh.Code, fresh.Header().Get("Location"))
	}

	loginQuery := oidcAuthorizationQuery("login-state")
	loginQuery.Set("prompt", "login")
	forced := browser.request(t, http.MethodGet, "/oauth2/authorize?"+loginQuery.Encode(), "", "")
	loginLocation, err := url.Parse(forced.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if forced.Code != http.StatusFound || loginLocation.Path != "/login" {
		t.Fatalf("forced authorize did not request login: %d %s", forced.Code, forced.Header().Get("Location"))
	}
	returnTo := loginLocation.Query().Get("continue")
	if returnTo == "" || browser.cookies[oauthReauthCookieName] == nil {
		t.Fatalf("missing signed reauthentication transaction: %s", forced.Header().Get("Location"))
	}
	browser.login(t, returnTo)
	completed := browser.request(t, http.MethodGet, returnTo, "", "")
	completedCallback, err := url.Parse(completed.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if completed.Code != http.StatusFound || completedCallback.Query().Get("code") == "" ||
		completedCallback.Query().Get("state") != "login-state" {
		t.Fatalf("forced authorize did not complete: %d %s", completed.Code, completed.Header().Get("Location"))
	}

	replayed := browser.request(t, http.MethodGet, returnTo, "", "")
	replayLocation, err := url.Parse(replayed.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if replayed.Code != http.StatusFound || replayLocation.Path != "/login" {
		t.Fatalf("reauthentication transaction was reusable: %d %s", replayed.Code, replayed.Header().Get("Location"))
	}

	maxAgeQuery := oidcAuthorizationQuery("max-age-state")
	maxAgeQuery.Set("max_age", "0")
	maxAge := browser.request(t, http.MethodGet, "/oauth2/authorize?"+maxAgeQuery.Encode(), "", "")
	maxAgeLocation, err := url.Parse(maxAge.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if maxAge.Code != http.StatusFound || maxAgeLocation.Path != "/login" {
		t.Fatalf("max_age=0 did not request login: %d %s", maxAge.Code, maxAge.Header().Get("Location"))
	}
}

func TestOIDCRPInitiatedLogout(t *testing.T) {
	handler := newProtocolTestHandler(t, "https://service.example.com")
	browser := newTestBrowser(handler)
	browser.login(t, "/portal")

	authorizeQuery := oidcAuthorizationQuery("logout-state")
	authorized := browser.request(t, http.MethodGet, "/oauth2/authorize?"+authorizeQuery.Encode(), "", "")
	callback, err := url.Parse(authorized.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	code := callback.Query().Get("code")
	if authorized.Code != http.StatusFound || code == "" {
		t.Fatalf("authorize for logout: %d %s", authorized.Code, authorized.Header().Get("Location"))
	}
	tokenForm := url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {"integration"},
		"code":          {code},
		"redirect_uri":  {"https://app.example.com/callback"},
		"code_verifier": {strings.Repeat("v", 64)},
	}
	tokenResponse := browser.request(t, http.MethodPost, "/oauth2/token", tokenForm.Encode(), "application/x-www-form-urlencoded")
	var tokens map[string]any
	if tokenResponse.Code != http.StatusOK {
		t.Fatalf("token for logout: %d %s", tokenResponse.Code, tokenResponse.Body.String())
	}
	if err := json.Unmarshal(tokenResponse.Body.Bytes(), &tokens); err != nil {
		t.Fatal(err)
	}
	idToken, _ := tokens["id_token"].(string)
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		t.Fatalf("missing ID token: %#v", tokens)
	}
	claims, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || !strings.Contains(string(claims), `"sid":`) {
		t.Fatalf("ID token missing session identifier: %s %v", claims, err)
	}

	logoutQuery := url.Values{
		"id_token_hint":            {idToken},
		"post_logout_redirect_uri": {"https://app.example.com/logout/callback"},
		"state":                    {"logout-return-state"},
	}
	loggedOut := browser.request(t, http.MethodGet, "/oauth2/logout?"+logoutQuery.Encode(), "", "")
	logoutCallback, err := url.Parse(loggedOut.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	if loggedOut.Code != http.StatusFound ||
		logoutCallback.String() != "https://app.example.com/logout/callback?state=logout-return-state" {
		t.Fatalf("unexpected logout response: %d %s", loggedOut.Code, loggedOut.Header().Get("Location"))
	}
	account := browser.request(t, http.MethodGet, "/account", "", "")
	if account.Code != http.StatusFound || !strings.HasPrefix(account.Header().Get("Location"), "/login?") {
		t.Fatalf("OIDC logout did not revoke the Certus session: %d %s", account.Code, account.Header().Get("Location"))
	}

	postLogout := browser.request(
		t,
		http.MethodPost,
		"/oauth2/logout",
		url.Values{"id_token_hint": {idToken}}.Encode(),
		"application/x-www-form-urlencoded",
	)
	if postLogout.Code != http.StatusFound || postLogout.Header().Get("Location") != "/login" {
		t.Fatalf("POST logout was not idempotent: %d %s", postLogout.Code, postLogout.Header().Get("Location"))
	}

	logoutQuery.Set("post_logout_redirect_uri", "https://attacker.example.com/callback")
	rejected := browser.request(t, http.MethodGet, "/oauth2/logout?"+logoutQuery.Encode(), "", "")
	if rejected.Code != http.StatusBadRequest || strings.Contains(rejected.Header().Get("Location"), "attacker.example.com") {
		t.Fatalf("unregistered logout redirect was accepted: %d %s", rejected.Code, rejected.Header().Get("Location"))
	}
}

func oidcAuthorizationQuery(state string) url.Values {
	verifier := strings.Repeat("v", 64)
	sum := sha256.Sum256([]byte(verifier))
	return url.Values{
		"client_id":             {"integration"},
		"redirect_uri":          {"https://app.example.com/callback"},
		"response_type":         {"code"},
		"scope":                 {"openid profile"},
		"state":                 {state},
		"nonce":                 {"nonce-" + state},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
	}
}

func newProtocolTestHandler(t *testing.T, serviceURL string, outboundClients ...*http.Client) http.Handler {
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
		ID:                     "integration",
		Name:                   "Integration",
		ApplicationType:        client.ApplicationPublic,
		Protocols:              []client.Protocol{client.ProtocolOAuth21, client.ProtocolCAS},
		GrantTypes:             []client.GrantType{client.GrantAuthorizationCode, client.GrantRefreshToken, client.GrantDeviceCode},
		RedirectURIs:           []string{"https://app.example.com/callback"},
		PostLogoutRedirectURIs: []string{"https://app.example.com/logout/callback"},
		LoginMethods:           []client.LoginMethod{client.LoginPassword},
		AllowedScopes:          []string{"openid", "profile", "email", "roles"},
		CASVersion:             client.CASVersion3,
		CASServiceURLs:         []string{serviceURL},
		CASProxy:               true,
		CASRenew:               true,
		CASSingleLogout:        true,
		Enabled:                true,
	})
	accessRepository := access.NewMemoryRepository()
	role, err := access.NewRole("integration", access.CreateRole{Code: "approver", Name: "审批人"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	permission, err := access.NewPermission("integration", access.CreatePermission{Code: "invoice.approve", Name: "审批发票"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := accessRepository.CreateRole(context.Background(), role); err != nil {
		t.Fatal(err)
	}
	if _, err := accessRepository.CreatePermission(context.Background(), permission); err != nil {
		t.Fatal(err)
	}
	if err := accessRepository.SetRolePermissions(context.Background(), "integration", role.ID, []string{permission.ID}); err != nil {
		t.Fatal(err)
	}
	if err := accessRepository.ReplaceUserRoles(context.Background(), user.ID, []access.RoleGrant{{RoleID: role.ID}}, "test", time.Now()); err != nil {
		t.Fatal(err)
	}
	dependencies := Dependencies{
		Clients:   clients,
		Users:     users,
		Passwords: users,
		Sessions:  session.NewMemoryRepository(),
		OAuth:     oauth.NewMemoryRepository(),
		CAS:       cas.NewMemoryRepository(),
		Keys:      &oidc.MemoryKeyRepository{},
		Access:    accessRepository,
	}
	if len(outboundClients) > 0 {
		dependencies.OutboundHTTPClient = outboundClients[0]
	}
	handler, err := NewWithDependencies(context.Background(), config.Config{Issuer: "https://auth.example.com"}, slog.New(slog.NewTextHandler(io.Discard, nil)), dependencies)
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
