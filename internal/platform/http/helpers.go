package httpserver

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
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

func requestIPAddress(r *http.Request) string {
	address := strings.TrimSpace(r.RemoteAddr)
	host, _, err := net.SplitHostPort(address)
	if err == nil {
		return host
	}
	if net.ParseIP(address) != nil {
		return address
	}
	return ""
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
