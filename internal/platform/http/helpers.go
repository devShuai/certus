package httpserver

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/netip"
	"strings"
)

type requestIDContextKey struct{}

func requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if id == "" {
			var value [16]byte
			if _, err := rand.Read(value[:]); err == nil {
				id = hex.EncodeToString(value[:])
			}
		}
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDContextKey{}, id)))
	})
}

func requestIDValue(r *http.Request) string {
	value, _ := r.Context().Value(requestIDContextKey{}).(string)
	return value
}

func (s *server) requestIPAddress(r *http.Request) string {
	return clientIPAddress(r, s.cfg.TrustedProxies)
}

func clientIPAddress(r *http.Request, trustedProxies []netip.Prefix) string {
	peer, ok := parseIPAddress(r.RemoteAddr)
	if !ok {
		return ""
	}
	if !isTrustedProxy(peer, trustedProxies) {
		return peer.String()
	}
	forwarded := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	if len(forwarded) > 32 {
		return peer.String()
	}
	current := peer
	for index := len(forwarded) - 1; index >= 0; index-- {
		candidate, valid := parseIPAddress(forwarded[index])
		if !valid {
			return peer.String()
		}
		current = candidate
		if !isTrustedProxy(current, trustedProxies) {
			return current.String()
		}
	}
	return current.String()
}

func parseIPAddress(raw string) (netip.Addr, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return netip.Addr{}, false
	}
	if addressPort, err := netip.ParseAddrPort(raw); err == nil {
		address := addressPort.Addr().Unmap()
		if address.Zone() != "" {
			address = address.WithZone("")
		}
		return address, true
	}
	address, err := netip.ParseAddr(strings.Trim(raw, "[]"))
	if err != nil {
		return netip.Addr{}, false
	}
	address = address.Unmap()
	if address.Zone() != "" {
		address = address.WithZone("")
	}
	return address, true
}

func isTrustedProxy(address netip.Addr, trustedProxies []netip.Prefix) bool {
	for _, prefix := range trustedProxies {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeProblem(w http.ResponseWriter, status int, code, detail string) {
	writeJSON(w, status, map[string]any{
		"type":   "about:blank",
		"title":  http.StatusText(status),
		"status": status,
		"code":   code,
		"detail": detail,
	})
}
