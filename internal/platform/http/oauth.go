package httpserver

import (
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

	"certus/internal/client"
	"certus/internal/identity"
	"certus/internal/oauth"
	"certus/internal/security"
)

const (
	authorizationCodeLifetime = 5 * time.Minute
	accessTokenLifetime       = 15 * time.Minute
	refreshTokenLifetime      = 30 * 24 * time.Hour
	deviceCodeLifetime        = 15 * time.Minute
)

func (s *server) authorize(w http.ResponseWriter, r *http.Request) {
	registered, err := s.clients.Find(r.Context(), r.URL.Query().Get("client_id"))
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request", "未知的 client_id")
		return
	}
	request, err := oauth.ParseAuthorizationRequest(r.URL.Query(), registered)
	if err != nil {
		writeProblem(w, http.StatusBadRequest, "invalid_request", err.Error())
		return
	}
	current, ok := s.currentSession(r)
	if !ok {
		query := url.Values{
			"continue":  []string{r.URL.RequestURI()},
			"client_id": []string{registered.ID},
		}
		http.Redirect(w, r, "/login?"+query.Encode(), http.StatusFound)
		return
	}
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
	response, err := s.issueUserTokens(r, registered, record.UserID, record.Scope, record.Nonce, record.AuthenticatedAt, true)
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
	replacementRaw, err := security.RandomToken(48)
	if raw == "" || err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "refresh token is invalid")
		return
	}
	now := s.now().UTC()
	replacement := oauth.RefreshToken{
		Hash:      security.HashToken(replacementRaw),
		ClientID:  registered.ID,
		IssuedAt:  now,
		ExpiresAt: now.Add(refreshTokenLifetime),
	}
	// The repository atomically copies the authoritative family, user and scope
	// values from the current token after validating the client.
	current, err := s.oauth.RotateRefreshToken(r.Context(), security.HashToken(raw), replacement, now)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "refresh token is invalid, expired or reused")
		return
	}
	// Some repositories require the replacement fields up front; persistently
	// backed repositories validate these values inside the same transaction.
	if replacement.FamilyID == "" {
		replacement.FamilyID = current.FamilyID
	}
	response, err := s.issueAccessToken(r, registered.ID, current.UserID, current.FamilyID, current.Scope)
	if err != nil {
		s.logger.Error("issue refreshed access token", "error", err)
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "token issuance failed")
		return
	}
	response["refresh_token"] = replacementRaw
	response["scope"] = strings.Join(current.Scope, " ")
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
	response, err := s.issueAccessToken(r, registered.ID, "", "", scopes)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "token issuance failed")
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *server) issueUserTokens(r *http.Request, registered client.Client, userID string, scopes []string, nonce string, authenticatedAt time.Time, allowRefresh bool) (map[string]any, error) {
	user, err := s.users.Find(r.Context(), userID)
	if err != nil || user.Status != identity.UserActive {
		return nil, errors.New("user is unavailable")
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
	response, err := s.issueAccessToken(r, registered.ID, userID, familyID, scopes)
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
		}
		if nonce != "" {
			claims["nonce"] = nonce
		}
		if slices.Contains(scopes, "profile") {
			claims["name"] = user.DisplayName
			claims["preferred_username"] = user.Username
		}
		if slices.Contains(scopes, "email") && user.Email != nil {
			claims["email"] = *user.Email
		}
		idToken, err := s.signer.Sign(claims)
		if err != nil {
			return nil, err
		}
		response["id_token"] = idToken
	}
	return response, nil
}

func (s *server) issueAccessToken(r *http.Request, clientID, userID, familyID string, scopes []string) (map[string]any, error) {
	raw, err := security.RandomToken(48)
	if err != nil {
		return nil, err
	}
	now := s.now().UTC()
	if err := s.oauth.SaveAccessToken(r.Context(), oauth.AccessToken{
		Hash:      security.HashToken(raw),
		ClientID:  clientID,
		UserID:    userID,
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

func (s *server) authenticateOAuthClient(w http.ResponseWriter, r *http.Request) (client.Client, bool) {
	clientID := r.Form.Get("client_id")
	secret := ""
	usedBasic := false
	if basicID, basicSecret, ok := r.BasicAuth(); ok {
		usedBasic = true
		clientID = basicID
		secret = basicSecret
	}
	registered, err := s.clients.Find(r.Context(), clientID)
	if err != nil || !registered.Enabled || !registered.SupportsOAuth() {
		w.Header().Set("WWW-Authenticate", `Basic realm="certus-token"`)
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
		return client.Client{}, false
	}
	if registered.ApplicationType == client.ApplicationConfidential {
		hash := sha256.Sum256([]byte(secret))
		if secret == "" || subtle.ConstantTimeCompare(hash[:], registered.SecretHash) != 1 {
			w.Header().Set("WWW-Authenticate", `Basic realm="certus-token"`)
			writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "client authentication failed")
			return client.Client{}, false
		}
	} else if usedBasic {
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client", "public clients must not use a client secret")
		return client.Client{}, false
	}
	return registered, true
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
		if token, err := s.oauth.FindAccessToken(r.Context(), hash, now); err == nil && token.ClientID == registered.ID {
			s.writeAccessTokenIntrospection(w, r, token)
			return
		}
	}
	if token, err := s.oauth.FindRefreshToken(r.Context(), hash, now); err == nil && token.ClientID == registered.ID {
		s.writeRefreshTokenIntrospection(w, r, token)
		return
	}
	if hint == "refresh_token" {
		if token, err := s.oauth.FindAccessToken(r.Context(), hash, now); err == nil && token.ClientID == registered.ID {
			s.writeAccessTokenIntrospection(w, r, token)
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]bool{"active": false})
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
		user, err := s.users.Find(r.Context(), token.UserID)
		if err != nil || user.Status != identity.UserActive {
			writeJSON(w, http.StatusOK, map[string]bool{"active": false})
			return
		}
		response["sub"] = user.ID
		response["username"] = user.Username
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *server) writeRefreshTokenIntrospection(w http.ResponseWriter, r *http.Request, token oauth.RefreshToken) {
	user, err := s.users.Find(r.Context(), token.UserID)
	if err != nil || user.Status != identity.UserActive {
		writeJSON(w, http.StatusOK, map[string]bool{"active": false})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"active":    true,
		"scope":     strings.Join(token.Scope, " "),
		"client_id": token.ClientID,
		"username":  user.Username,
		"sub":       user.ID,
		"exp":       token.ExpiresAt.Unix(),
		"iat":       token.IssuedAt.Unix(),
		"iss":       s.cfg.Issuer,
	})
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
	user, err := s.users.Find(r.Context(), token.UserID)
	if err != nil || user.Status != identity.UserActive {
		w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
		writeOAuthError(w, http.StatusUnauthorized, "invalid_token", "user is unavailable")
		return
	}
	claims := map[string]any{"sub": user.ID}
	if slices.Contains(token.Scope, "profile") {
		claims["name"] = user.DisplayName
		claims["preferred_username"] = user.Username
	}
	if slices.Contains(token.Scope, "email") && user.Email != nil {
		claims["email"] = *user.Email
	}
	writeJSON(w, http.StatusOK, claims)
}

func (s *server) jwks(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=300")
	writeJSON(w, http.StatusOK, s.signer.JWKS())
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
		"jwks_uri":                                      s.cfg.Issuer + "/oauth2/jwks",
		"response_types_supported":                      []string{"code"},
		"grant_types_supported":                         []string{string(client.GrantAuthorizationCode), string(client.GrantRefreshToken), string(client.GrantClientCredentials), string(client.GrantDeviceCode)},
		"token_endpoint_auth_methods_supported":         []string{"client_secret_basic", "none"},
		"introspection_endpoint_auth_methods_supported": []string{"client_secret_basic"},
		"revocation_endpoint_auth_methods_supported":    []string{"client_secret_basic", "none"},
		"code_challenge_methods_supported":              []string{"S256"},
		"scopes_supported":                              []string{"openid", "profile", "email"},
		"subject_types_supported":                       []string{"public"},
		"id_token_signing_alg_values_supported":         []string{"RS256"},
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
