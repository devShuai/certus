package httpserver

import (
	"fmt"
	"math"
	"net/http"
	"strings"

	"certus/internal/ratelimit"
)

func (s *server) allowLoginAttempt(
	w http.ResponseWriter,
	r *http.Request,
	username string,
) bool {
	if !s.allowLoginSource(w, r, "login.source") {
		return false
	}
	username = strings.ToLower(strings.TrimSpace(username))
	if username == "" {
		username = "<empty>"
	}
	return s.allowRateLimitedRequest(
		w, r,
		"login.identity",
		username,
		s.cfg.RateLimits.LoginIdentity,
		false,
	)
}

func (s *server) allowLoginSource(
	w http.ResponseWriter,
	r *http.Request,
	scope string,
) bool {
	return s.allowRateLimitedRequest(
		w, r,
		scope,
		s.requestIPAddress(r),
		s.cfg.RateLimits.LoginSource,
		false,
	)
}

func (s *server) allowMFAAttempt(
	w http.ResponseWriter,
	r *http.Request,
	userID string,
) bool {
	if !s.allowRateLimitedRequest(
		w, r,
		"mfa.source",
		s.requestIPAddress(r),
		s.cfg.RateLimits.MFA,
		false,
	) {
		return false
	}
	return s.allowRateLimitedRequest(
		w, r,
		"mfa.identity",
		userID,
		s.cfg.RateLimits.MFA,
		false,
	)
}

func (s *server) allowRegistrationAttempt(w http.ResponseWriter, r *http.Request) bool {
	return s.allowRateLimitedRequest(
		w, r,
		"registration.source",
		s.requestIPAddress(r),
		s.cfg.RateLimits.Registration,
		false,
	)
}

func (s *server) allowOAuthAttempt(w http.ResponseWriter, r *http.Request) bool {
	return s.allowRateLimitedRequest(
		w, r,
		"oauth.source",
		s.requestIPAddress(r),
		s.cfg.RateLimits.OAuth,
		true,
	)
}

func (s *server) allowDeviceLookup(w http.ResponseWriter, r *http.Request) bool {
	return s.allowRateLimitedRequest(
		w, r,
		"device.source",
		s.requestIPAddress(r),
		s.cfg.RateLimits.Device,
		false,
	)
}

func (s *server) allowEmailVerificationAttempt(w http.ResponseWriter, r *http.Request, userID string) bool {
	if !s.allowRateLimitedRequest(
		w, r,
		"email.verification.source",
		s.requestIPAddress(r),
		s.cfg.RateLimits.EmailVerification,
		false,
	) {
		return false
	}
	return s.allowRateLimitedRequest(
		w, r,
		"email.verification.identity",
		userID,
		s.cfg.RateLimits.EmailVerification,
		false,
	)
}

func (s *server) allowClientStatusLookup(w http.ResponseWriter, r *http.Request, clientID string) bool {
	return s.allowRateLimitedRequest(
		w, r,
		"client.status",
		clientID,
		s.cfg.RateLimits.ClientStatus,
		true,
	)
}

func (s *server) allowRateLimitedRequest(
	w http.ResponseWriter,
	r *http.Request,
	scope string,
	subject string,
	policy ratelimit.Policy,
	oauthStyle bool,
) bool {
	if subject == "" {
		subject = "<unknown>"
	}
	now := s.now().UTC()
	result, err := s.rateLimits.Allow(r.Context(), scope, subject, policy, now)
	if err != nil {
		s.metrics.RecordRateLimit(scope, "error")
		s.logger.Error("apply rate limit", "scope", scope, "error", err)
		if oauthStyle {
			writeOAuthError(
				w, http.StatusServiceUnavailable,
				"temporarily_unavailable", "rate-limit service is unavailable",
			)
		} else {
			writeProblem(
				w, http.StatusServiceUnavailable,
				"rate_limit_unavailable", "请求保护服务暂时不可用",
			)
		}
		return false
	}
	if result.ResetAt.IsZero() {
		return true
	}
	w.Header().Set("X-RateLimit-Limit", fmt.Sprint(policy.Limit))
	w.Header().Set("X-RateLimit-Remaining", fmt.Sprint(result.Remaining))
	w.Header().Set("X-RateLimit-Reset", fmt.Sprint(result.ResetAt.Unix()))
	if result.Allowed {
		s.metrics.RecordRateLimit(scope, "allowed")
		return true
	}
	s.metrics.RecordRateLimit(scope, "blocked")
	retryAfter := int(math.Ceil(result.ResetAt.Sub(now).Seconds()))
	if retryAfter < 1 {
		retryAfter = 1
	}
	w.Header().Set("Retry-After", fmt.Sprint(retryAfter))
	if oauthStyle {
		writeOAuthError(
			w, http.StatusTooManyRequests,
			"temporarily_unavailable", "too many requests; retry later",
		)
	} else {
		writeProblem(
			w, http.StatusTooManyRequests,
			"rate_limited", "请求过于频繁，请稍后重试",
		)
	}
	return false
}
