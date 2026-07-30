package httpserver

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	"certus/internal/cas"
	"certus/internal/client"
	"certus/internal/identity"
	"certus/internal/security"
	"certus/internal/session"
)

const (
	serviceTicketLifetime       = 2 * time.Minute
	proxyTicketLifetime         = 2 * time.Minute
	proxyGrantingTicketLifetime = 8 * time.Hour
)

func (s *server) casLogin(w http.ResponseWriter, r *http.Request) {
	serviceURL := r.URL.Query().Get("service")
	registered, ok := s.findCASClient(r.Context(), serviceURL)
	if !ok {
		writeProblem(w, http.StatusBadRequest, "INVALID_SERVICE", "CAS service 未登记")
		return
	}
	renewRequested := r.URL.Query().Get("renew") == "true" && registered.CASRenew
	if r.URL.Query().Get("gateway") == "true" && renewRequested {
		writeProblem(w, http.StatusBadRequest, "INVALID_REQUEST", "gateway 与 renew 不能同时使用")
		return
	}
	current, authenticated := s.currentSession(r)
	if !authenticated {
		if r.URL.Query().Get("gateway") == "true" && registered.CASGateway {
			http.Redirect(w, r, serviceURL, http.StatusFound)
			return
		}
		s.redirectCASCredentials(w, r, registered, serviceURL, renewRequested, "")
		return
	}
	primaryCredentials := false
	if renewRequested {
		marker := r.URL.Query().Get("reauth")
		if !s.validCASReauthMarker(marker, serviceURL, current.AuthenticatedAt) {
			s.redirectCASCredentials(w, r, registered, serviceURL, true, marker)
			return
		}
		primaryCredentials = true
	}
	raw, err := security.RandomToken(32)
	if err != nil {
		writeProblem(w, http.StatusInternalServerError, "INTERNAL_ERROR", "生成 Service Ticket 失败")
		return
	}
	ticket := "ST-" + raw
	now := s.now().UTC()
	if err := s.cas.SaveServiceTicket(r.Context(), cas.ServiceTicket{
		Hash:               security.HashToken(ticket),
		Ticket:             ticket,
		ClientID:           registered.ID,
		Service:            serviceURL,
		UserID:             current.UserID,
		SessionID:          current.ID,
		PrimaryCredentials: primaryCredentials,
		IssuedAt:           now,
		ExpiresAt:          now.Add(serviceTicketLifetime),
	}); err != nil {
		s.logger.Error("save CAS service ticket", "error", err)
		writeProblem(w, http.StatusInternalServerError, "INTERNAL_ERROR", "保存 Service Ticket 失败")
		return
	}
	target, _ := url.Parse(serviceURL)
	query := target.Query()
	query.Set("ticket", ticket)
	target.RawQuery = query.Encode()
	http.Redirect(w, r, target.String(), http.StatusFound)
}

func (s *server) casValidate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	serviceURL := r.URL.Query().Get("service")
	if _, ok := s.findCASClient(r.Context(), serviceURL); !ok {
		_, _ = io.WriteString(w, "no\n\n")
		return
	}
	ticket, err := s.cas.ConsumeServiceTicket(
		r.Context(),
		security.HashToken(r.URL.Query().Get("ticket")),
		serviceURL,
		r.URL.Query().Get("renew") == "true",
		s.now().UTC(),
	)
	if err != nil {
		_, _ = io.WriteString(w, "no\n\n")
		return
	}
	user, err := s.users.Find(r.Context(), ticket.UserID)
	if err != nil || user.Status != identity.UserActive {
		_, _ = io.WriteString(w, "no\n\n")
		return
	}
	_, _ = fmt.Fprintf(w, "yes\n%s\n", user.Username)
}

func (s *server) casServiceValidate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	serviceURL := r.URL.Query().Get("service")
	registered, ok := s.findCASClient(r.Context(), serviceURL)
	if !ok {
		writeCASFailure(w, "INVALID_SERVICE", "service is not registered")
		return
	}
	ticket, err := s.cas.ConsumeServiceTicket(
		r.Context(),
		security.HashToken(r.URL.Query().Get("ticket")),
		serviceURL,
		r.URL.Query().Get("renew") == "true",
		s.now().UTC(),
	)
	if err != nil {
		writeCASFailure(w, "INVALID_TICKET", "ticket is invalid, expired, or already used")
		return
	}
	user, err := s.users.Find(r.Context(), ticket.UserID)
	if err != nil || user.Status != identity.UserActive {
		writeCASFailure(w, "INVALID_TICKET", "ticket user is unavailable")
		return
	}
	roles, permissions, err := s.casEntitlements(r.Context(), registered, user.ID, r.URL.Path == "/cas/p3/serviceValidate")
	if err != nil {
		s.logger.Error("read CAS entitlements", "error", err)
		writeCASFailure(w, "INTERNAL_ERROR", "could not read user roles")
		return
	}
	pgtIOU, err := s.issueProxyGrantingTicket(r, registered, cas.ProxyGrantingTicket{
		ClientID:           ticket.ClientID,
		UserID:             ticket.UserID,
		SessionID:          ticket.SessionID,
		PrimaryCredentials: ticket.PrimaryCredentials,
	}, r.URL.Query().Get("pgtUrl"))
	if err != nil {
		writeCASFailure(w, "INVALID_PROXY_CALLBACK", err.Error())
		return
	}
	writeCASSuccess(w, user, r.URL.Path == "/cas/p3/serviceValidate", pgtIOU, nil, roles, permissions)
}

func (s *server) casProxyValidate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	serviceURL := r.URL.Query().Get("service")
	registered, ok := s.findCASClient(r.Context(), serviceURL)
	if !ok {
		writeCASFailure(w, "INVALID_SERVICE", "service is not registered")
		return
	}
	rawTicket := r.URL.Query().Get("ticket")
	requirePrimary := r.URL.Query().Get("renew") == "true"
	now := s.now().UTC()
	var (
		userID             string
		sessionID          string
		primaryCredentials bool
		proxies            []string
	)
	if strings.HasPrefix(rawTicket, "PT-") {
		ticket, err := s.cas.ConsumeProxyTicket(
			r.Context(),
			security.HashToken(rawTicket),
			serviceURL,
			requirePrimary,
			now,
		)
		if err != nil {
			writeCASFailure(w, "INVALID_TICKET", "ticket is invalid, expired, or already used")
			return
		}
		userID = ticket.UserID
		sessionID = ticket.SessionID
		primaryCredentials = ticket.PrimaryCredentials
		proxies = ticket.Proxies
	} else {
		ticket, err := s.cas.ConsumeServiceTicket(
			r.Context(),
			security.HashToken(rawTicket),
			serviceURL,
			requirePrimary,
			now,
		)
		if err != nil {
			writeCASFailure(w, "INVALID_TICKET", "ticket is invalid, expired, or already used")
			return
		}
		userID = ticket.UserID
		sessionID = ticket.SessionID
		primaryCredentials = ticket.PrimaryCredentials
	}
	user, err := s.users.Find(r.Context(), userID)
	if err != nil || user.Status != identity.UserActive {
		writeCASFailure(w, "INVALID_TICKET", "ticket user is unavailable")
		return
	}
	roles, permissions, err := s.casEntitlements(r.Context(), registered, user.ID, r.URL.Path == "/cas/p3/proxyValidate")
	if err != nil {
		s.logger.Error("read CAS proxy entitlements", "error", err)
		writeCASFailure(w, "INTERNAL_ERROR", "could not read user roles")
		return
	}
	pgtIOU, err := s.issueProxyGrantingTicket(r, registered, cas.ProxyGrantingTicket{
		ClientID:           registered.ID,
		UserID:             userID,
		SessionID:          sessionID,
		Proxies:            proxies,
		PrimaryCredentials: primaryCredentials,
	}, r.URL.Query().Get("pgtUrl"))
	if err != nil {
		writeCASFailure(w, "INVALID_PROXY_CALLBACK", err.Error())
		return
	}
	writeCASSuccess(w, user, r.URL.Path == "/cas/p3/proxyValidate", pgtIOU, proxies, roles, permissions)
}

func (s *server) casProxy(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	rawPGT := r.URL.Query().Get("pgt")
	targetService := r.URL.Query().Get("targetService")
	if rawPGT == "" || targetService == "" {
		writeCASProxyFailure(w, "INVALID_REQUEST", "pgt and targetService are required")
		return
	}
	target, ok := s.findCASClient(r.Context(), targetService)
	if !ok {
		writeCASProxyFailure(w, "UNAUTHORIZED_SERVICE", "targetService is not registered")
		return
	}
	now := s.now().UTC()
	pgt, err := s.cas.FindProxyGrantingTicket(r.Context(), security.HashToken(rawPGT), now)
	if err != nil {
		writeCASProxyFailure(w, "UNAUTHORIZED_SERVICE", "proxy granting ticket is invalid or expired")
		return
	}
	source, err := s.clients.Find(r.Context(), pgt.ClientID)
	if err != nil || !source.Enabled || !source.CASProxy {
		writeCASProxyFailure(w, "UNAUTHORIZED_SERVICE", "service is not allowed to proxy authentication")
		return
	}
	rawTicket, err := security.RandomToken(32)
	if err != nil {
		writeCASProxyFailure(w, "INTERNAL_ERROR", "could not generate proxy ticket")
		return
	}
	rawTicket = "PT-" + rawTicket
	proxies := make([]string, 0, len(pgt.Proxies)+1)
	proxies = append(proxies, pgt.CallbackURL)
	proxies = append(proxies, pgt.Proxies...)
	if err := s.cas.SaveProxyTicket(r.Context(), cas.ProxyTicket{
		Hash:               security.HashToken(rawTicket),
		ClientID:           target.ID,
		TargetService:      targetService,
		UserID:             pgt.UserID,
		SessionID:          pgt.SessionID,
		Proxies:            proxies,
		PrimaryCredentials: pgt.PrimaryCredentials,
		IssuedAt:           now,
		ExpiresAt:          now.Add(proxyTicketLifetime),
	}, security.HashToken(rawPGT)); err != nil {
		s.logger.Error("save CAS proxy ticket", "error", err)
		writeCASProxyFailure(w, "INTERNAL_ERROR", "could not save proxy ticket")
		return
	}
	var body bytes.Buffer
	body.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	body.WriteString(`<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas"><cas:proxySuccess><cas:proxyTicket>`)
	xmlEscape(&body, rawTicket)
	body.WriteString(`</cas:proxyTicket></cas:proxySuccess></cas:serviceResponse>`)
	_, _ = w.Write(body.Bytes())
}

func (s *server) issueProxyGrantingTicket(r *http.Request, registered client.Client, value cas.ProxyGrantingTicket, callbackURL string) (string, error) {
	if callbackURL == "" {
		return "", nil
	}
	if !registered.CASProxy {
		return "", errors.New("service is not authorized for proxy authentication")
	}
	if !validCASProxyCallback(registered, r.URL.Query().Get("service"), callbackURL) {
		return "", errors.New("proxy callback must be HTTPS and use the registered service host")
	}
	rawPGT, err := security.RandomToken(32)
	if err != nil {
		return "", errors.New("could not generate proxy granting ticket")
	}
	rawPGT = "PGT-" + rawPGT
	rawIOU, err := security.RandomToken(32)
	if err != nil {
		return "", errors.New("could not generate proxy granting ticket IOU")
	}
	rawIOU = "PGTIOU-" + rawIOU
	callback, _ := url.Parse(callbackURL)
	query := callback.Query()
	query.Set("pgtId", rawPGT)
	query.Set("pgtIou", rawIOU)
	callback.RawQuery = query.Encode()
	request, err := http.NewRequestWithContext(r.Context(), http.MethodGet, callback.String(), nil)
	if err != nil {
		return "", errors.New("proxy callback is invalid")
	}
	response, err := s.outbound.Do(request)
	if err != nil {
		return "", fmt.Errorf("proxy callback failed: %w", err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("proxy callback returned HTTP %d", response.StatusCode)
	}
	now := s.now().UTC()
	value.Hash = security.HashToken(rawPGT)
	value.CallbackURL = callbackURL
	value.IssuedAt = now
	value.ExpiresAt = now.Add(proxyGrantingTicketLifetime)
	if err := s.cas.SaveProxyGrantingTicket(r.Context(), value); err != nil {
		s.logger.Error("save CAS proxy granting ticket", "error", err)
		return "", errors.New("could not save proxy granting ticket")
	}
	return rawIOU, nil
}

func validCASProxyCallback(registered client.Client, serviceURL, callbackURL string) bool {
	if !registered.CASProxy {
		return false
	}
	service, err := url.Parse(serviceURL)
	if err != nil {
		return false
	}
	callback, err := url.Parse(callbackURL)
	if err != nil ||
		callback.Scheme != "https" ||
		callback.Host == "" ||
		callback.User != nil ||
		callback.Fragment != "" {
		return false
	}
	return strings.EqualFold(service.Host, callback.Host)
}

func (s *server) casEntitlements(ctx context.Context, registered client.Client, userID string, includeAttributes bool) ([]string, []string, error) {
	if !includeAttributes || !slices.Contains(registered.AllowedScopes, "roles") {
		return nil, nil, nil
	}
	value, err := s.accessControl.Effective(ctx, userID, registered.ID, s.now().UTC())
	if err != nil {
		return nil, nil, err
	}
	return value.Roles, value.Permissions, nil
}

func writeCASSuccess(w http.ResponseWriter, user identity.User, includeAttributes bool, pgtIOU string, proxies, roles, permissions []string) {
	var body bytes.Buffer
	body.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	body.WriteString(`<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas"><cas:authenticationSuccess><cas:user>`)
	xmlEscape(&body, user.Username)
	body.WriteString(`</cas:user>`)
	if includeAttributes {
		body.WriteString(`<cas:attributes><cas:displayName>`)
		xmlEscape(&body, user.DisplayName)
		body.WriteString(`</cas:displayName>`)
		if user.Email != nil {
			body.WriteString(`<cas:email>`)
			xmlEscape(&body, *user.Email)
			body.WriteString(`</cas:email>`)
		}
		for _, role := range roles {
			body.WriteString(`<cas:role>`)
			xmlEscape(&body, role)
			body.WriteString(`</cas:role>`)
		}
		for _, permission := range permissions {
			body.WriteString(`<cas:permission>`)
			xmlEscape(&body, permission)
			body.WriteString(`</cas:permission>`)
		}
		body.WriteString(`</cas:attributes>`)
	}
	if pgtIOU != "" {
		body.WriteString(`<cas:proxyGrantingTicket>`)
		xmlEscape(&body, pgtIOU)
		body.WriteString(`</cas:proxyGrantingTicket>`)
	}
	if len(proxies) > 0 {
		body.WriteString(`<cas:proxies>`)
		for _, proxy := range proxies {
			body.WriteString(`<cas:proxy>`)
			xmlEscape(&body, proxy)
			body.WriteString(`</cas:proxy>`)
		}
		body.WriteString(`</cas:proxies>`)
	}
	body.WriteString(`</cas:authenticationSuccess></cas:serviceResponse>`)
	_, _ = w.Write(body.Bytes())
}

func (s *server) casLogout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if current, ok := s.currentSession(r); ok {
		principal := current.UserID
		if user, err := s.users.Find(r.Context(), current.UserID); err == nil {
			principal = user.Username
		}
		serviceSessions, err := s.cas.ListServiceSessions(r.Context(), current.ID)
		if err != nil {
			s.logger.Error("list CAS sessions for logout", "error", err)
		} else {
			logoutContext, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			var logoutGroup sync.WaitGroup
			concurrency := make(chan struct{}, 4)
			for _, serviceSession := range serviceSessions {
				registered, valid := s.findCASClient(r.Context(), serviceSession.Service)
				if !valid || !registered.CASSingleLogout {
					continue
				}
				logoutGroup.Add(1)
				go func(value cas.ServiceSession) {
					defer logoutGroup.Done()
					select {
					case concurrency <- struct{}{}:
						defer func() { <-concurrency }()
					case <-logoutContext.Done():
						return
					}
					if err := s.sendCASLogout(logoutContext, value, principal); err != nil {
						s.logger.Warn("CAS back-channel logout failed", "client_id", value.ClientID, "service", value.Service, "error", err)
					}
				}(serviceSession)
			}
			logoutGroup.Wait()
			cancel()
		}
		_ = s.sessions.Revoke(r.Context(), current.ID)
		s.cleanupRevokedSessions(r.Context(), []session.Session{current})
	}
	s.clearSessionCookie(w)
	target := r.URL.Query().Get("service")
	if target == "" {
		target = r.URL.Query().Get("url")
	}
	if _, ok := s.findCASClient(r.Context(), target); ok {
		http.Redirect(w, r, target, http.StatusFound)
		return
	}
	http.Redirect(w, r, "/login", http.StatusFound)
}

func (s *server) findCASClient(ctx context.Context, serviceURL string) (client.Client, bool) {
	if serviceURL == "" {
		return client.Client{}, false
	}
	clients, err := s.clients.List(ctx)
	if err != nil {
		return client.Client{}, false
	}
	for _, registered := range clients {
		if !registered.Enabled || !registered.SupportsProtocol(client.ProtocolCAS) {
			continue
		}
		for _, allowed := range registered.CASServiceURLs {
			if allowed == serviceURL {
				return registered, true
			}
		}
	}
	return client.Client{}, false
}

func (s *server) sendCASLogout(ctx context.Context, serviceSession cas.ServiceSession, principal string) error {
	requestID, err := security.RandomToken(16)
	if err != nil {
		return err
	}
	var request bytes.Buffer
	request.WriteString(`<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="`)
	xmlEscape(&request, "_"+requestID)
	request.WriteString(`" Version="2.0" IssueInstant="`)
	xmlEscape(&request, s.now().UTC().Format(time.RFC3339))
	request.WriteString(`"><saml:NameID xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">`)
	xmlEscape(&request, principal)
	request.WriteString(`</saml:NameID><samlp:SessionIndex>`)
	xmlEscape(&request, serviceSession.Ticket)
	request.WriteString(`</samlp:SessionIndex></samlp:LogoutRequest>`)

	form := url.Values{"logoutRequest": []string{request.String()}}
	httpRequest, err := http.NewRequestWithContext(ctx, http.MethodPost, serviceSession.Service, strings.NewReader(form.Encode()))
	if err != nil {
		return err
	}
	httpRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := s.outbound.Do(httpRequest)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("service returned HTTP %d", response.StatusCode)
	}
	return nil
}

func (s *server) redirectCASCredentials(w http.ResponseWriter, r *http.Request, registered client.Client, serviceURL string, renew bool, marker string) {
	targetQuery := url.Values{"service": []string{serviceURL}}
	if renew {
		targetQuery.Set("renew", "true")
		if !s.validUnsignedCASReauthMarker(marker, serviceURL) {
			now := s.now().UTC()
			var err error
			marker, err = s.signer.Sign(map[string]any{
				"purpose": "cas_reauth",
				"service": serviceURL,
				"iat":     now.Unix(),
				"exp":     now.Add(5 * time.Minute).Unix(),
			})
			if err != nil {
				writeProblem(w, http.StatusInternalServerError, "INTERNAL_ERROR", "创建重新认证请求失败")
				return
			}
		}
		targetQuery.Set("reauth", marker)
	}
	returnTo := "/cas/login?" + targetQuery.Encode()
	http.Redirect(w, r, "/login?continue="+url.QueryEscape(returnTo)+"&client_id="+url.QueryEscape(registered.ID), http.StatusFound)
}

func (s *server) validUnsignedCASReauthMarker(marker, serviceURL string) bool {
	claims, err := s.signer.Verify(marker)
	if err != nil {
		return false
	}
	purpose, _ := claims["purpose"].(string)
	service, _ := claims["service"].(string)
	expiration, _ := claims["exp"].(float64)
	issuedAt, _ := claims["iat"].(float64)
	now := s.now().UTC().Unix()
	return purpose == "cas_reauth" &&
		service == serviceURL &&
		int64(expiration) > now &&
		int64(issuedAt) <= now+30
}

func (s *server) validCASReauthMarker(marker, serviceURL string, authenticatedAt time.Time) bool {
	if !s.validUnsignedCASReauthMarker(marker, serviceURL) {
		return false
	}
	claims, _ := s.signer.Verify(marker)
	issuedAt, _ := claims["iat"].(float64)
	return authenticatedAt.Unix() >= int64(issuedAt)
}

func writeCASFailure(w http.ResponseWriter, code, message string) {
	var body bytes.Buffer
	body.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	body.WriteString(`<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas"><cas:authenticationFailure code="`)
	xmlEscape(&body, code)
	body.WriteString(`">`)
	xmlEscape(&body, message)
	body.WriteString(`</cas:authenticationFailure></cas:serviceResponse>`)
	_, _ = w.Write(body.Bytes())
}

func writeCASProxyFailure(w http.ResponseWriter, code, message string) {
	var body bytes.Buffer
	body.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	body.WriteString(`<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas"><cas:proxyFailure code="`)
	xmlEscape(&body, code)
	body.WriteString(`">`)
	xmlEscape(&body, message)
	body.WriteString(`</cas:proxyFailure></cas:serviceResponse>`)
	_, _ = w.Write(body.Bytes())
}

func xmlEscape(destination *bytes.Buffer, value string) {
	_ = xml.EscapeText(destination, []byte(value))
}
