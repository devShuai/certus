package httpserver

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"certus/internal/audit"
	"certus/internal/client"
	"certus/internal/identity"
	"certus/internal/oauth"
	"certus/internal/security"
	"certus/internal/session"
)

const (
	authorizationCodeLifetime = 5 * time.Minute
	accessTokenLifetime       = 15 * time.Minute
	refreshTokenLifetime      = 30 * 24 * time.Hour
	deviceCodeLifetime        = 15 * time.Minute
	oidcLogoutHintMaxAge      = 24 * time.Hour
)

func (s *server) authorize(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	registered, err := s.clients.Find(r.Context(), r.URL.Query().Get("client_id"))
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request", "未知的 client_id")
		return
	}
	request, err := oauth.ParseAuthorizationRequest(r.URL.Query(), registered)
	if err != nil {
		redirectURI := r.URL.Query().Get("redirect_uri")
		if registered.Enabled && registered.SupportsOAuth() && registered.AllowsRedirectURI(redirectURI) {
			redirectOAuthAuthorizationError(w, r, redirectURI, r.URL.Query().Get("state"), "invalid_request", err.Error())
			return
		}
		writeProblem(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	current, ok := s.currentSession(r)
	now := s.now().UTC()
	stale := request.MaxAge != nil && authenticationTooOld(now, current.AuthenticatedAt, *request.MaxAge)
	marker := r.URL.Query().Get("certus_reauth")
	if marker != "" {
		if ok && s.validOAuthReauthMarker(r, marker, current.AuthenticatedAt) {
			s.clearOAuthReauthCookie(w)
			stale = false
		} else {
			if request.HasPrompt("none") {
				redirectOAuthAuthorizationError(w, r, request.RedirectURI, request.State, "login_required", "End-user authentication is required")
				return
			}
			s.redirectOAuthCredentials(w, r, registered.ID)
			return
		}
	} else if request.HasPrompt("none") {
		if !ok || stale {
			redirectOAuthAuthorizationError(w, r, request.RedirectURI, request.State, "login_required", "End-user authentication is required")
			return
		}
	} else if !ok || request.HasPrompt("login") || request.MaxAge != nil && *request.MaxAge == 0 || stale {
		if !ok && !request.HasPrompt("login") && (request.MaxAge == nil || *request.MaxAge > 0) {
			query := url.Values{
				"continue":  []string{r.URL.RequestURI()},
				"client_id": []string{registered.ID},
			}
			http.Redirect(w, r, "/login?"+query.Encode(), http.StatusFound)
			return
		}
		s.redirectOAuthCredentials(w, r, registered.ID)
		return
	}
	requiresConsent, err := s.requiresOAuthConsent(r, request, current)
	if err != nil {
		s.logger.Error("read OAuth consent", "client_id", request.ClientID, "user_id", current.UserID, "error", err)
		redirectOAuthAuthorizationError(w, r, request.RedirectURI, request.State, "server_error", "Unable to read authorization")
		return
	}
	if requiresConsent {
		if request.HasPrompt("none") {
			redirectOAuthAuthorizationError(
				w, r, request.RedirectURI, request.State,
				"consent_required", "End-user consent is required",
			)
			return
		}
		s.renderOAuthConsent(w, r, registered, request, current)
		return
	}
	s.issueAuthorizationCode(w, r, request, current)
}

func (s *server) issueAuthorizationCode(
	w http.ResponseWriter,
	r *http.Request,
	request oauth.AuthorizationRequest,
	current session.Session,
) {
	code, err := security.RandomToken(32)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "server_error", "生成授权码失败")
		return
	}
	now := s.now().UTC()
	if err := s.oauth.SaveAuthorizationCode(r.Context(), oauth.AuthorizationCode{
		Hash:            security.HashToken(code),
		ClientID:        request.ClientID,
		UserID:          current.UserID,
		SessionID:       current.ID,
		RedirectURI:     request.RedirectURI,
		Scope:           request.Scope,
		Nonce:           request.Nonce,
		CodeChallenge:   request.CodeChallenge,
		AuthenticatedAt: current.AuthenticatedAt,
		AuthMethods:     current.AuthMethods,
		AssuranceLevel:  current.AssuranceLevel,
		CreatedAt:       now,
		ExpiresAt:       now.Add(authorizationCodeLifetime),
	}); err != nil {
		s.logger.Error("save authorization code", "error", err)
		writeProblem(w, http.StatusInternalServerError, "server_error", "保存授权码失败")
		return
	}
	target, _ := url.Parse(request.RedirectURI)
	query := target.Query()
	query.Set("code", code)
	query.Set("state", request.State)
	target.RawQuery = query.Encode()
	http.Redirect(w, r, target.String(), http.StatusFound)
}

func (s *server) redirectOAuthCredentials(w http.ResponseWriter, r *http.Request, clientID string) {
	query := r.URL.Query()
	query.Del("certus_reauth")
	now := s.now().UTC()
	marker, err := s.signer.Sign(map[string]any{
		"purpose":     "oauth_reauth",
		"fingerprint": oauthAuthorizationFingerprint(query),
		"issued_at":   now.Format(time.RFC3339Nano),
		"exp":         now.Add(5 * time.Minute).Unix(),
	})
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "server_error", "创建重新认证请求失败")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     oauthReauthCookieName,
		Value:    marker,
		Path:     "/oauth2/authorize",
		MaxAge:   int((5 * time.Minute).Seconds()),
		HttpOnly: true,
		Secure:   s.secureCookies(),
		SameSite: http.SameSiteLaxMode,
	})
	query.Set("certus_reauth", marker)
	returnTo := "/oauth2/authorize?" + query.Encode()
	loginQuery := url.Values{
		"continue":  []string{returnTo},
		"client_id": []string{clientID},
	}
	http.Redirect(w, r, "/login?"+loginQuery.Encode(), http.StatusFound)
}

func (s *server) validOAuthReauthMarker(r *http.Request, marker string, authenticatedAt time.Time) bool {
	cookie, err := r.Cookie(oauthReauthCookieName)
	if err != nil || len(cookie.Value) != len(marker) ||
		subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(marker)) != 1 {
		return false
	}
	claims, err := s.signer.Verify(marker)
	if err != nil {
		return false
	}
	purpose, _ := claims["purpose"].(string)
	fingerprint, _ := claims["fingerprint"].(string)
	issuedAtValue, _ := claims["issued_at"].(string)
	expiration, _ := claims["exp"].(float64)
	issuedAt, err := time.Parse(time.RFC3339Nano, issuedAtValue)
	if err != nil {
		return false
	}
	query := r.URL.Query()
	query.Del("certus_reauth")
	now := s.now().UTC()
	return purpose == "oauth_reauth" &&
		subtle.ConstantTimeCompare([]byte(fingerprint), []byte(oauthAuthorizationFingerprint(query))) == 1 &&
		int64(expiration) > now.Unix() &&
		!issuedAt.After(now.Add(30*time.Second)) &&
		authenticatedAt.After(issuedAt)
}

func (s *server) clearOAuthReauthCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     oauthReauthCookieName,
		Value:    "",
		Path:     "/oauth2/authorize",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.secureCookies(),
		SameSite: http.SameSiteLaxMode,
	})
}

func oauthAuthorizationFingerprint(query url.Values) string {
	clone := make(url.Values, len(query))
	for key, values := range query {
		clone[key] = append([]string(nil), values...)
	}
	clone.Del("certus_reauth")
	sum := sha256.Sum256([]byte(clone.Encode()))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func authenticationTooOld(now, authenticatedAt time.Time, maxAge int64) bool {
	if authenticatedAt.IsZero() {
		return true
	}
	if !authenticatedAt.Before(now) {
		return false
	}
	return now.Unix()-authenticatedAt.Unix() > maxAge
}

func redirectOAuthAuthorizationError(
	w http.ResponseWriter,
	r *http.Request,
	redirectURI, state, code, description string,
) {
	target, err := url.Parse(redirectURI)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, code, description)
		return
	}
	query := target.Query()
	query.Set("error", code)
	query.Set("error_description", description)
	if state != "" {
		query.Set("state", state)
	}
	target.RawQuery = query.Encode()
	http.Redirect(w, r, target.String(), http.StatusFound)
}

func (s *server) token(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Content-Type must be application/x-www-form-urlencoded")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid form body")
		return
	}
	if !s.allowOAuthAttempt(w, r) {
		return
	}
	registered, ok := s.authenticateOAuthClient(w, r)
	if !ok {
		return
	}
	switch r.Form.Get("grant_type") {
	case string(client.GrantAuthorizationCode):
		s.authorizationCodeToken(w, r, registered)
	case string(client.GrantRefreshToken):
		s.refreshToken(w, r, registered)
	case string(client.GrantClientCredentials):
		s.clientCredentialsToken(w, r, registered)
	case string(client.GrantDeviceCode):
		s.deviceCodeToken(w, r, registered)
	default:
		writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "grant_type is not supported")
	}
}

func (s *server) authorizationCodeToken(w http.ResponseWriter, r *http.Request, registered client.Client) {
	if !registered.SupportsGrant(client.GrantAuthorizationCode) {
		writeOAuthError(w, http.StatusBadRequest, "unauthorized_client", "authorization_code is not enabled")
		return
	}
	code := r.Form.Get("code")
	redirectURI := r.Form.Get("redirect_uri")
	verifier := r.Form.Get("code_verifier")
	if code == "" || redirectURI == "" || !oauth.ValidCodeVerifier(verifier) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "code, redirect_uri and valid code_verifier are required")
		return
	}
	challengeHash := sha256.Sum256([]byte(verifier))
	actualChallenge := base64.RawURLEncoding.EncodeToString(challengeHash[:])
	record, err := s.oauth.ConsumeAuthorizationCode(
		r.Context(),
		security.HashToken(code),
		registered.ID,
		redirectURI,
		actualChallenge,
		s.now().UTC(),
	)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "authorization code is invalid or expired")
		return
	}
	response, err := s.issueUserTokens(
		r, registered, record.UserID, record.SessionID, record.Scope, record.Nonce,
		record.AuthenticatedAt, record.AuthMethods, record.AssuranceLevel, true,
	)
	if err != nil {
		s.logger.Error("issue authorization code tokens", "error", err)
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "token issuance failed")
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *server) refreshToken(w http.ResponseWriter, r *http.Request, registered client.Client) {
	if !registered.SupportsGrant(client.GrantRefreshToken) {
		writeOAuthError(w, http.StatusBadRequest, "unauthorized_client", "refresh_token is not enabled")
		return
	}
	raw := r.Form.Get("refresh_token")
	if raw == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "refresh token is invalid")
		return
	}
	now := s.now().UTC()
	var scopes []string
	if scopeValue := strings.TrimSpace(r.Form.Get("scope")); scopeValue != "" {
		requested, err := requestedScopes(scopeValue, registered, false)
		if err != nil {
			writeOAuthError(w, http.StatusBadRequest, "invalid_scope", "scope must not exceed the original grant")
			return
		}
		scopes = requested
	}
	replacementRaw, err := security.RandomToken(48)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "token issuance failed")
		return
	}
	replacement := oauth.RefreshToken{
		Hash:      security.HashToken(replacementRaw),
		ClientID:  registered.ID,
		Scope:     scopes,
		IssuedAt:  now,
		ExpiresAt: now.Add(refreshTokenLifetime),
	}
	current, err := s.oauth.RotateRefreshToken(r.Context(), security.HashToken(raw), replacement, now)
	if errors.Is(err, oauth.ErrInvalidScope) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_scope", "scope must not exceed the original grant")
		return
	}
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "refresh token is invalid, expired or reused")
		return
	}
	if scopes == nil {
		scopes = append([]string(nil), current.Scope...)
	}
	if _, err := s.validateOAuthUserGrant(
		r.Context(), current.UserID, current.ClientID, current.SessionID, scopes,
	); err != nil {
		_ = s.oauth.RevokeRefreshToken(r.Context(), security.HashToken(replacementRaw), registered.ID, s.now().UTC())
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "refresh token grant is no longer active")
		return
	}
	response, err := s.issueAccessToken(
		r, registered.ID, current.UserID, current.SessionID, current.FamilyID, scopes,
	)
	if err != nil {
		_ = s.oauth.RevokeRefreshToken(r.Context(), security.HashToken(replacementRaw), registered.ID, s.now().UTC())
		s.logger.Error("issue refreshed access token", "error", err)
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "token issuance failed")
		return
	}
	response["refresh_token"] = replacementRaw
	response["scope"] = strings.Join(scopes, " ")
	writeJSON(w, http.StatusOK, response)
}

func (s *server) clientCredentialsToken(w http.ResponseWriter, r *http.Request, registered client.Client) {
	if !registered.SupportsGrant(client.GrantClientCredentials) || registered.ApplicationType != client.ApplicationConfidential {
		writeOAuthError(w, http.StatusBadRequest, "unauthorized_client", "client_credentials is not enabled")
		return
	}
	scopeValue := r.Form.Get("scope")
	if strings.TrimSpace(scopeValue) == "" {
		defaults := make([]string, 0, len(registered.AllowedScopes))
		for _, scope := range registered.AllowedScopes {
			if scope != "openid" {
				defaults = append(defaults, scope)
			}
		}
		scopeValue = strings.Join(defaults, " ")
	}
	scopes, err := requestedScopes(scopeValue, registered, false)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_scope", err.Error())
		return
	}
	if slices.Contains(scopes, "openid") {
		writeOAuthError(w, http.StatusBadRequest, "invalid_scope", "openid is not valid with client_credentials")
		return
	}
	if slices.Contains(scopes, "roles") {
		writeOAuthError(w, http.StatusBadRequest, "invalid_scope", "roles is not valid with client_credentials")
		return
	}
	response, err := s.issueAccessToken(r, registered.ID, "", "", "", scopes)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "token issuance failed")
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *server) issueUserTokens(
	r *http.Request,
	registered client.Client,
	userID string,
	sessionID string,
	scopes []string,
	nonce string,
	authenticatedAt time.Time,
	authMethods []string,
	assuranceLevel string,
	allowRefresh bool,
) (map[string]any, error) {
	user, err := s.validateOAuthUserGrant(
		r.Context(), userID, registered.ID, sessionID, scopes,
	)
	if err != nil {
		return nil, err
	}
	var refreshRaw, familyID string
	if allowRefresh && registered.SupportsGrant(client.GrantRefreshToken) {
		refreshRaw, err = security.RandomToken(48)
		if err != nil {
			return nil, err
		}
		familyID, err = security.RandomUUID()
		if err != nil {
			return nil, err
		}
	}
	response, err := s.issueAccessToken(r, registered.ID, userID, sessionID, familyID, scopes)
	if err != nil {
		return nil, err
	}
	if refreshRaw != "" {
		now := s.now().UTC()
		if err := s.oauth.SaveRefreshToken(r.Context(), oauth.RefreshToken{
			Hash:      security.HashToken(refreshRaw),
			FamilyID:  familyID,
			ClientID:  registered.ID,
			UserID:    userID,
			SessionID: sessionID,
			Scope:     scopes,
			IssuedAt:  now,
			ExpiresAt: now.Add(refreshTokenLifetime),
		}); err != nil {
			return nil, err
		}
		response["refresh_token"] = refreshRaw
	}
	if slices.Contains(scopes, "openid") {
		now := s.now().UTC()
		claims := map[string]any{
			"iss":       s.cfg.Issuer,
			"sub":       user.ID,
			"aud":       registered.ID,
			"exp":       now.Add(accessTokenLifetime).Unix(),
			"iat":       now.Unix(),
			"auth_time": authenticatedAt.Unix(),
			"amr":       authMethods,
			"acr":       assuranceLevel,
		}
		if nonce != "" {
			claims["nonce"] = nonce
		}
		if sessionID != "" {
			claims["sid"] = sessionID
		}
		if slices.Contains(scopes, "profile") {
			claims["name"] = user.DisplayName
			claims["preferred_username"] = user.Username
		}
		if slices.Contains(scopes, "email") {
			addEmailClaims(claims, user)
		}
		if err := s.addEntitlementClaims(r.Context(), claims, user.ID, registered.ID, scopes); err != nil {
			return nil, err
		}
		idToken, err := s.signer.Sign(claims)
		if err != nil {
			return nil, err
		}
		if sessionID != "" && registered.BackchannelLogoutURI != "" {
			if err := s.oauth.SaveOIDCClientSession(r.Context(), oauth.OIDCClientSession{
				SessionID: sessionID,
				ClientID:  registered.ID,
				UserID:    userID,
				CreatedAt: now,
			}); err != nil {
				return nil, err
			}
		}
		response["id_token"] = idToken
	}
	return response, nil
}

func (s *server) issueAccessToken(
	r *http.Request,
	clientID, userID, sessionID, familyID string,
	scopes []string,
) (map[string]any, error) {
	raw, err := security.RandomToken(48)
	if err != nil {
		return nil, err
	}
	now := s.now().UTC()
	if err := s.oauth.SaveAccessToken(r.Context(), oauth.AccessToken{
		Hash:      security.HashToken(raw),
		ClientID:  clientID,
		UserID:    userID,
		SessionID: sessionID,
		FamilyID:  familyID,
		Scope:     scopes,
		IssuedAt:  now,
		ExpiresAt: now.Add(accessTokenLifetime),
	}); err != nil {
		return nil, err
	}
	return map[string]any{
		"access_token": raw,
		"token_type":   "Bearer",
		"expires_in":   int(accessTokenLifetime / time.Second),
		"scope":        strings.Join(scopes, " "),
	}, nil
}

func (s *server) validateOAuthUserGrant(
	ctx context.Context,
	userID, clientID, sessionID string,
	scopes []string,
) (identity.User, error) {
	user, err := s.users.Find(ctx, userID)
	if err != nil || user.Status != identity.UserActive {
		return identity.User{}, errors.New("user is unavailable")
	}
	if sessionID != "" {
		active, err := s.sessions.IsActive(ctx, userID, sessionID)
		if err != nil {
			return identity.User{}, fmt.Errorf("check OAuth grant session: %w", err)
		}
		if !active {
			return identity.User{}, errors.New("OAuth grant session is inactive")
		}
	}
	consent, err := s.oauth.FindConsent(ctx, userID, clientID)
	if err != nil || !consent.Covers(scopes) {
		return identity.User{}, errors.New("OAuth consent is unavailable")
	}
	return user, nil
}

func (s *server) authenticateOAuthClient(w http.ResponseWriter, r *http.Request) (client.Client, bool) {
	clientIDs := r.PostForm["client_id"]
	secrets := r.PostForm["client_secret"]
	if len(clientIDs) > 1 || len(secrets) > 1 {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "client credentials must not be repeated")
		return client.Client{}, false
	}
	formClientID := strings.TrimSpace(r.PostForm.Get("client_id"))
	basicID, basicSecret, usedBasic := r.BasicAuth()
	usedPost := len(secrets) == 1
	if usedBasic && usedPost {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "multiple client authentication methods are not allowed")
		return client.Client{}, false
	}
	if usedBasic && formClientID != "" && formClientID != basicID {
		s.writeInvalidOAuthClient(w, client.TokenEndpointAuthSecretBasic)
		return client.Client{}, false
	}
	clientID := formClientID
	secret := ""
	authenticationMethod := client.TokenEndpointAuthNone
	switch {
	case usedBasic:
		clientID = basicID
		secret = basicSecret
		authenticationMethod = client.TokenEndpointAuthSecretBasic
	case usedPost:
		secret = r.PostForm.Get("client_secret")
		authenticationMethod = client.TokenEndpointAuthSecretPost
	}
	registered, err := s.clients.Find(r.Context(), clientID)
	if err != nil || !registered.Enabled || !registered.SupportsOAuth() {
		s.writeInvalidOAuthClient(w, authenticationMethod)
		return client.Client{}, false
	}
	if authenticationMethod != registered.EffectiveTokenEndpointAuthMethod() {
		s.writeInvalidOAuthClient(w, authenticationMethod)
		return client.Client{}, false
	}
	if registered.ApplicationType == client.ApplicationConfidential {
		if !validOAuthClientSecret(registered, secret) {
			s.writeInvalidOAuthClient(w, authenticationMethod)
			return client.Client{}, false
		}
	}
	return registered, true
}

func (s *server) writeInvalidOAuthClient(w http.ResponseWriter, method client.TokenEndpointAuthMethod) {
	if method == client.TokenEndpointAuthSecretBasic || method == client.TokenEndpointAuthNone {
		w.Header().Set("WWW-Authenticate", `Basic realm="certus-token"`)
	}
	writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
}

func validOAuthClientSecret(registered client.Client, secret string) bool {
	hash := sha256.Sum256([]byte(secret))
	return secret != "" && subtle.ConstantTimeCompare(hash[:], registered.SecretHash) == 1
}

func (s *server) authenticateConfidentialOAuthClient(w http.ResponseWriter, r *http.Request) (client.Client, bool) {
	registered, ok := s.authenticateOAuthClient(w, r)
	if !ok {
		return client.Client{}, false
	}
	if registered.ApplicationType != client.ApplicationConfidential {
		w.Header().Set("WWW-Authenticate", `Basic realm="certus-token-metadata"`)
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "confidential client authentication is required")
		return client.Client{}, false
	}
	return registered, true
}

func (s *server) authenticateConfidentialOAuthClientBasic(w http.ResponseWriter, r *http.Request) (client.Client, bool) {
	clientID, secret, ok := r.BasicAuth()
	if !ok {
		w.Header().Set("WWW-Authenticate", `Basic realm="certus-access"`)
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "confidential client authentication is required")
		return client.Client{}, false
	}
	registered, err := s.clients.Find(r.Context(), clientID)
	if err != nil ||
		!registered.Enabled ||
		!registered.SupportsOAuth() ||
		registered.ApplicationType != client.ApplicationConfidential ||
		!validOAuthClientSecret(registered, secret) {
		w.Header().Set("WWW-Authenticate", `Basic realm="certus-access"`)
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return client.Client{}, false
	}
	return registered, true
}

func (s *server) introspect(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Content-Type must be application/x-www-form-urlencoded")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid form body")
		return
	}
	if !s.allowOAuthAttempt(w, r) {
		return
	}
	registered, ok := s.authenticateConfidentialOAuthClient(w, r)
	if !ok {
		return
	}
	raw := r.Form.Get("token")
	if raw == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "token is required")
		return
	}
	hash := security.HashToken(raw)
	now := s.now().UTC()
	hint := r.Form.Get("token_type_hint")
	if hint != "refresh_token" {
		if token, err := s.oauth.FindAccessToken(r.Context(), hash, now); err == nil &&
			s.canIntrospectAccessToken(r.Context(), token.ClientID, registered.ID) {
			s.writeAccessTokenIntrospection(w, r, token)
			return
		}
	}
	if token, err := s.oauth.FindRefreshToken(r.Context(), hash, now); err == nil && token.ClientID == registered.ID {
		s.writeRefreshTokenIntrospection(w, r, token)
		return
	}
	if hint == "refresh_token" {
		if token, err := s.oauth.FindAccessToken(r.Context(), hash, now); err == nil &&
			s.canIntrospectAccessToken(r.Context(), token.ClientID, registered.ID) {
			s.writeAccessTokenIntrospection(w, r, token)
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]bool{"active": false})
}

func (s *server) canIntrospectAccessToken(ctx context.Context, tokenClientID, introspectorClientID string) bool {
	if tokenClientID == introspectorClientID {
		return true
	}
	issuer, err := s.clients.Find(ctx, tokenClientID)
	if err != nil {
		if !errors.Is(err, client.ErrNotFound) {
			s.logger.Error(
				"read token client for introspection authorization",
				"client_id", tokenClientID,
				"error", err,
			)
		}
		return false
	}
	return issuer.Enabled && issuer.ArchivedAt == nil && issuer.AllowsIntrospectionBy(introspectorClientID)
}

func (s *server) writeAccessTokenIntrospection(w http.ResponseWriter, r *http.Request, token oauth.AccessToken) {
	response := map[string]any{
		"active":     true,
		"scope":      strings.Join(token.Scope, " "),
		"client_id":  token.ClientID,
		"token_type": "Bearer",
		"exp":        token.ExpiresAt.Unix(),
		"iat":        token.IssuedAt.Unix(),
		"iss":        s.cfg.Issuer,
	}
	if token.UserID != "" {
		user, err := s.validateOAuthUserGrant(
			r.Context(), token.UserID, token.ClientID, token.SessionID, token.Scope,
		)
		if err != nil {
			writeJSON(w, http.StatusOK, map[string]bool{"active": false})
			return
		}
		response["sub"] = user.ID
		response["username"] = user.Username
		if err := s.addEntitlementClaims(r.Context(), response, user.ID, token.ClientID, token.Scope); err != nil {
			s.logger.Error("read token entitlements for introspection", "error", err)
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "token introspection failed")
			return
		}
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *server) writeRefreshTokenIntrospection(w http.ResponseWriter, r *http.Request, token oauth.RefreshToken) {
	user, err := s.validateOAuthUserGrant(
		r.Context(), token.UserID, token.ClientID, token.SessionID, token.Scope,
	)
	if err != nil {
		writeJSON(w, http.StatusOK, map[string]bool{"active": false})
		return
	}
	response := map[string]any{
		"active":    true,
		"scope":     strings.Join(token.Scope, " "),
		"client_id": token.ClientID,
		"username":  user.Username,
		"sub":       user.ID,
		"exp":       token.ExpiresAt.Unix(),
		"iat":       token.IssuedAt.Unix(),
		"iss":       s.cfg.Issuer,
	}
	if err := s.addEntitlementClaims(r.Context(), response, user.ID, token.ClientID, token.Scope); err != nil {
		s.logger.Error("read refresh token entitlements for introspection", "error", err)
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "token introspection failed")
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *server) revokeToken(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "Content-Type must be application/x-www-form-urlencoded")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "invalid form body")
		return
	}
	if !s.allowOAuthAttempt(w, r) {
		return
	}
	registered, ok := s.authenticateOAuthClient(w, r)
	if !ok {
		return
	}
	raw := r.Form.Get("token")
	if raw == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "token is required")
		return
	}
	hash := security.HashToken(raw)
	now := s.now().UTC()
	hint := r.Form.Get("token_type_hint")
	if hint == "refresh_token" {
		if err := s.oauth.RevokeRefreshToken(r.Context(), hash, registered.ID, now); err == nil {
			w.WriteHeader(http.StatusOK)
			return
		}
		_ = s.oauth.RevokeAccessToken(r.Context(), hash, registered.ID, now)
		w.WriteHeader(http.StatusOK)
		return
	}
	if err := s.oauth.RevokeAccessToken(r.Context(), hash, registered.ID, now); err == nil {
		w.WriteHeader(http.StatusOK)
		return
	}
	_ = s.oauth.RevokeRefreshToken(r.Context(), hash, registered.ID, now)
	w.WriteHeader(http.StatusOK)
}

func (s *server) userinfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if !s.allowOAuthAttempt(w, r) {
		return
	}
	raw := ""
	authorization := strings.Fields(r.Header.Get("Authorization"))
	if len(authorization) == 2 && strings.EqualFold(authorization[0], "Bearer") {
		raw = authorization[1]
	}
	if raw == "" && r.Method == http.MethodPost {
		if err := r.ParseForm(); err == nil {
			raw = r.Form.Get("access_token")
		}
	}
	token, err := s.oauth.FindAccessToken(r.Context(), security.HashToken(raw), s.now().UTC())
	if raw == "" || err != nil || token.UserID == "" || !slices.Contains(token.Scope, "openid") {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		writeOAuthError(w, http.StatusUnauthorized, "invalid_token", "access token is invalid or expired")
		return
	}
	user, err := s.validateOAuthUserGrant(
		r.Context(), token.UserID, token.ClientID, token.SessionID, token.Scope,
	)
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		writeOAuthError(w, http.StatusUnauthorized, "invalid_token", "user is unavailable")
		return
	}
	claims := map[string]any{"sub": user.ID}
	if slices.Contains(token.Scope, "profile") {
		claims["name"] = user.DisplayName
		claims["preferred_username"] = user.Username
	}
	if slices.Contains(token.Scope, "email") {
		addEmailClaims(claims, user)
	}
	if err := s.addEntitlementClaims(r.Context(), claims, user.ID, token.ClientID, token.Scope); err != nil {
		s.logger.Error("read user entitlements", "error", err)
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "userinfo failed")
		return
	}
	writeJSON(w, http.StatusOK, claims)
}

func addEmailClaims(claims map[string]any, user identity.User) {
	if user.Email == nil {
		return
	}
	claims["email"] = *user.Email
	claims["email_verified"] = user.EmailVerified
}

func (s *server) addEntitlementClaims(ctx context.Context, claims map[string]any, userID, clientID string, scopes []string) error {
	if !slices.Contains(scopes, "roles") {
		return nil
	}
	value, err := s.accessControl.Effective(ctx, userID, clientID, s.now().UTC())
	if err != nil {
		return err
	}
	claims["roles"] = value.Roles
	claims["permissions"] = value.Permissions
	return nil
}

func (s *server) jwks(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=300")
	if err := s.signer.Refresh(r.Context()); err != nil {
		s.logger.Warn("refresh signing keys for JWKS", "error", err)
	}
	writeJSON(w, http.StatusOK, s.signer.JWKS())
}

func (s *server) oidcLogout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		if err := r.ParseForm(); err != nil {
			writeProblem(w, http.StatusBadRequest, "invalid_request", "invalid logout request")
			return
		}
	} else {
		r.Form = r.URL.Query()
	}
	hint := r.Form.Get("id_token_hint")
	registered, subject, sessionID, ok := s.validIDTokenHint(r, hint)
	if !ok {
		writeProblem(w, http.StatusBadRequest, "invalid_request", "id_token_hint is invalid")
		return
	}
	if clientID := r.Form.Get("client_id"); clientID != "" && clientID != registered.ID {
		writeProblem(w, http.StatusBadRequest, "invalid_request", "client_id does not match id_token_hint")
		return
	}
	target := "/login"
	if redirectURI := r.Form.Get("post_logout_redirect_uri"); redirectURI != "" {
		if !registered.AllowsPostLogoutRedirectURI(redirectURI) {
			writeProblem(w, http.StatusBadRequest, "invalid_request", "post_logout_redirect_uri is not registered")
			return
		}
		redirect, _ := url.Parse(redirectURI)
		if state := r.Form.Get("state"); state != "" {
			query := redirect.Query()
			query.Set("state", state)
			redirect.RawQuery = query.Encode()
		}
		target = redirect.String()
	}
	current, authenticated := s.currentSession(r)
	if authenticated && current.UserID != subject {
		writeProblem(w, http.StatusBadRequest, "invalid_request", "id_token_hint does not match the current user")
		return
	}
	revokedSessions := make(map[string]struct{}, 2)
	logoutSessions := make([]session.Session, 0, 2)
	if sessionID != "" {
		_ = s.sessions.Revoke(r.Context(), sessionID)
		revokedSessions[sessionID] = struct{}{}
		logoutSessions = append(logoutSessions, session.Session{ID: sessionID, UserID: subject})
	}
	if authenticated {
		if _, alreadyRevoked := revokedSessions[current.ID]; !alreadyRevoked {
			_ = s.sessions.Revoke(r.Context(), current.ID)
			logoutSessions = append(logoutSessions, current)
		}
	}
	s.cleanupRevokedSessions(r.Context(), logoutSessions)
	s.recordAudit(r, audit.Event{
		ActorUserID: auditActor(subject),
		EventType:   "logout.oidc",
		ClientID:    auditClient(registered.ID),
		Outcome:     audit.OutcomeSuccess,
		Details:     map[string]any{"session_id": sessionID},
	})
	s.clearSessionCookie(w)
	http.Redirect(w, r, target, http.StatusFound)
}

func (s *server) validIDTokenHint(r *http.Request, hint string) (client.Client, string, string, bool) {
	if hint == "" {
		return client.Client{}, "", "", false
	}
	claims, err := s.signer.Verify(hint)
	if err != nil {
		return client.Client{}, "", "", false
	}
	issuer, _ := claims["iss"].(string)
	subject, _ := claims["sub"].(string)
	audience, _ := claims["aud"].(string)
	issuedAt, _ := claims["iat"].(float64)
	expiration, _ := claims["exp"].(float64)
	now := s.now().UTC().Unix()
	if issuer != s.cfg.Issuer || subject == "" || audience == "" ||
		int64(issuedAt) <= 0 || int64(expiration) <= int64(issuedAt) ||
		int64(issuedAt) > now+30 ||
		int64(issuedAt) < now-int64(oidcLogoutHintMaxAge/time.Second) {
		return client.Client{}, "", "", false
	}
	registered, err := s.clients.Find(r.Context(), audience)
	if err != nil || !registered.SupportsOAuth() {
		return client.Client{}, "", "", false
	}
	sessionID, _ := claims["sid"].(string)
	return registered, subject, sessionID, true
}

func (s *server) discovery(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"issuer":                                        s.cfg.Issuer,
		"authorization_endpoint":                        s.cfg.Issuer + "/oauth2/authorize",
		"token_endpoint":                                s.cfg.Issuer + "/oauth2/token",
		"introspection_endpoint":                        s.cfg.Issuer + "/oauth2/introspect",
		"revocation_endpoint":                           s.cfg.Issuer + "/oauth2/revoke",
		"device_authorization_endpoint":                 s.cfg.Issuer + "/oauth2/device_authorization",
		"userinfo_endpoint":                             s.cfg.Issuer + "/oauth2/userinfo",
		"end_session_endpoint":                          s.cfg.Issuer + "/oauth2/logout",
		"jwks_uri":                                      s.cfg.Issuer + "/oauth2/jwks",
		"response_types_supported":                      []string{"code"},
		"grant_types_supported":                         []string{string(client.GrantAuthorizationCode), string(client.GrantRefreshToken), string(client.GrantClientCredentials), string(client.GrantDeviceCode)},
		"token_endpoint_auth_methods_supported":         []string{"client_secret_basic", "client_secret_post", "none"},
		"introspection_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		"revocation_endpoint_auth_methods_supported":    []string{"client_secret_basic", "client_secret_post", "none"},
		"code_challenge_methods_supported":              []string{"S256"},
		"scopes_supported":                              []string{"openid", "profile", "email", "roles"},
		"subject_types_supported":                       []string{"public"},
		"id_token_signing_alg_values_supported":         []string{"RS256"},
		"acr_values_supported":                          []string{"urn:certus:aal:1", "urn:certus:aal:2"},
		"claims_supported":                              []string{"sub", "iss", "aud", "exp", "iat", "auth_time", "sid", "nonce", "acr", "amr", "name", "preferred_username", "email", "email_verified", "roles", "permissions"},
		"backchannel_logout_supported":                  true,
		"backchannel_logout_session_supported":          true,
		"prompt_values_supported":                       []string{"none", "login", "consent"},
	})
}

func requestedScopes(raw string, registered client.Client, requireOpenID bool) ([]string, error) {
	scopes := strings.Fields(raw)
	if len(scopes) == 0 {
		scopes = append([]string(nil), registered.AllowedScopes...)
	}
	unique := make([]string, 0, len(scopes))
	seen := make(map[string]struct{}, len(scopes))
	for _, scope := range scopes {
		if _, exists := seen[scope]; exists {
			continue
		}
		seen[scope] = struct{}{}
		unique = append(unique, scope)
	}
	scopes = unique
	if requireOpenID && !slices.Contains(scopes, "openid") {
		return nil, errors.New("openid scope is required")
	}
	for _, scope := range scopes {
		if !slices.Contains(registered.AllowedScopes, scope) {
			return nil, fmt.Errorf("scope %q is not allowed", scope)
		}
	}
	return scopes, nil
}

func writeOAuthError(w http.ResponseWriter, status int, code, description string) {
	writeJSON(w, status, map[string]string{"error": code, "error_description": description})
}

func randomUserCode() (string, error) {
	const alphabet = "BCDFGHJKLMNPQRSTVWXZ23456789"
	value := make([]byte, 8)
	buffer := make([]byte, 16)
	position := 0
	for position < len(value) {
		if _, err := rand.Read(buffer); err != nil {
			return "", err
		}
		for _, candidate := range buffer {
			limit := 256 - (256 % len(alphabet))
			if int(candidate) >= limit {
				continue
			}
			value[position] = alphabet[int(candidate)%len(alphabet)]
			position++
			if position == len(value) {
				break
			}
		}
	}
	return string(value[:4]) + "-" + string(value[4:]), nil
}
