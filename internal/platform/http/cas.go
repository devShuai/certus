package httpserver

import (
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"certus/internal/cas"
	"certus/internal/client"
	"certus/internal/identity"
	"certus/internal/security"
)

const serviceTicketLifetime = 2 * time.Minute

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
	if _, ok := s.findCASClient(r.Context(), serviceURL); !ok {
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
	var body bytes.Buffer
	body.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	body.WriteString(`<cas:serviceResponse xmlns:cas="http://www.yale.edu/tp/cas"><cas:authenticationSuccess><cas:user>`)
	xmlEscape(&body, user.Username)
	body.WriteString(`</cas:user>`)
	if r.URL.Path == "/cas/p3/serviceValidate" {
		body.WriteString(`<cas:attributes><cas:displayName>`)
		xmlEscape(&body, user.DisplayName)
		body.WriteString(`</cas:displayName>`)
		if user.Email != nil {
			body.WriteString(`<cas:email>`)
			xmlEscape(&body, *user.Email)
			body.WriteString(`</cas:email>`)
		}
		body.WriteString(`</cas:attributes>`)
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
		_ = s.cas.DeleteServiceSessions(r.Context(), current.ID)
		_ = s.sessions.Revoke(r.Context(), current.ID)
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

func xmlEscape(destination *bytes.Buffer, value string) {
	_ = xml.EscapeText(destination, []byte(value))
}
