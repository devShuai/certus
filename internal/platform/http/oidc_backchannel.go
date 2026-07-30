package httpserver

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"certus/internal/client"
	"certus/internal/oauth"
	"certus/internal/security"
	"certus/internal/session"
)

const (
	oidcBackchannelLogoutTimeout = 5 * time.Second
	oidcLogoutTokenLifetime      = 2 * time.Minute
	oidcBackchannelLogoutEvent   = "http://schemas.openid.net/event/backchannel-logout"
)

type oidcLogoutSession struct {
	SessionID string
	UserID    string
}

type oidcBackchannelLogoutJob struct {
	Session oauth.OIDCClientSession
	Client  client.Client
}

func (s *server) sessionsForRevocation(ctx context.Context, userID, exceptID string) []session.Session {
	items, err := s.sessions.ListByUser(ctx, userID)
	if err != nil {
		s.logger.Warn("list sessions before revocation cleanup", "user_id", userID, "error", err)
		return nil
	}
	result := make([]session.Session, 0, len(items))
	for _, item := range items {
		if item.ID != exceptID {
			result = append(result, item)
		}
	}
	return result
}

func (s *server) cleanupRevokedSessions(ctx context.Context, sessions []session.Session) {
	logoutSessions := make([]oidcLogoutSession, 0, len(sessions))
	for _, current := range sessions {
		_ = s.cas.DeleteServiceSessions(ctx, current.ID)
		logoutSessions = append(logoutSessions, oidcLogoutSession{
			SessionID: current.ID,
			UserID:    current.UserID,
		})
	}
	s.notifyOIDCBackchannelLogout(ctx, logoutSessions)
}

func (s *server) notifyOIDCBackchannelLogout(ctx context.Context, sessions []oidcLogoutSession) {
	unique := make(map[string]oidcLogoutSession, len(sessions))
	for _, current := range sessions {
		if current.SessionID != "" {
			unique[current.SessionID] = current
		}
	}
	jobs := make([]oidcBackchannelLogoutJob, 0)
	listedSessions := make(map[string]struct{}, len(unique))
	for _, current := range unique {
		registeredSessions, err := s.oauth.ListOIDCClientSessions(ctx, current.SessionID)
		if err != nil {
			s.logger.Warn("list OIDC client sessions for logout", "session_id", current.SessionID, "error", err)
			continue
		}
		listedSessions[current.SessionID] = struct{}{}
		for _, registeredSession := range registeredSessions {
			registered, err := s.clients.Find(ctx, registeredSession.ClientID)
			if err != nil || registered.BackchannelLogoutURI == "" {
				continue
			}
			if registeredSession.UserID == "" {
				registeredSession.UserID = current.UserID
			}
			jobs = append(jobs, oidcBackchannelLogoutJob{Session: registeredSession, Client: registered})
		}
	}

	logoutContext, cancel := context.WithTimeout(ctx, oidcBackchannelLogoutTimeout)
	defer cancel()
	var group sync.WaitGroup
	concurrency := make(chan struct{}, 4)
	for _, job := range jobs {
		group.Add(1)
		go func(current oidcBackchannelLogoutJob) {
			defer group.Done()
			select {
			case concurrency <- struct{}{}:
				defer func() { <-concurrency }()
			case <-logoutContext.Done():
				return
			}
			if err := s.sendOIDCBackchannelLogout(logoutContext, current); err != nil {
				s.logger.Warn(
					"OIDC back-channel logout failed",
					"client_id", current.Client.ID,
					"session_id", current.Session.SessionID,
					"error", err,
				)
			}
		}(job)
	}
	group.Wait()
	for sessionID := range listedSessions {
		if err := s.oauth.DeleteOIDCClientSessions(ctx, sessionID); err != nil {
			s.logger.Warn("delete OIDC client sessions after logout", "session_id", sessionID, "error", err)
		}
	}
}

func (s *server) sendOIDCBackchannelLogout(ctx context.Context, job oidcBackchannelLogoutJob) error {
	jti, err := security.RandomUUID()
	if err != nil {
		return fmt.Errorf("generate logout token identifier: %w", err)
	}
	now := s.now().UTC()
	claims := map[string]any{
		"iss": s.cfg.Issuer,
		"sub": job.Session.UserID,
		"aud": job.Client.ID,
		"iat": now.Unix(),
		"exp": now.Add(oidcLogoutTokenLifetime).Unix(),
		"jti": jti,
		"sid": job.Session.SessionID,
		"events": map[string]any{
			oidcBackchannelLogoutEvent: map[string]any{},
		},
	}
	token, err := s.signer.SignTyped(claims, "logout+jwt")
	if err != nil {
		return fmt.Errorf("sign logout token: %w", err)
	}
	form := url.Values{"logout_token": {token}}
	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		job.Client.BackchannelLogoutURI,
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		return fmt.Errorf("create back-channel logout request: %w", err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := s.outbound.Do(request)
	if err != nil {
		return fmt.Errorf("send back-channel logout request: %w", err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	if response.StatusCode != http.StatusOK && response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("back-channel endpoint returned HTTP %d", response.StatusCode)
	}
	return nil
}
