package admin

import (
	"net/http"
	"strings"

	"github.com/saezro/hodor/internal/auth"
	"github.com/saezro/hodor/internal/pass"
)

// securityHeaders sets a few defensive headers on every admin response.
func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'self'")
		next.ServeHTTP(w, r)
	})
}

// cidrCheck enforces that the admin listener is only reachable from the
// configured allow-list, resolving the real client IP through
// admin.trusted_proxies/trusted_header when behind a reverse proxy.
func (s *Server) cidrCheck(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := auth.ClientIP(r, s.cfg.Admin.ParsedProxies, s.cfg.Admin.TrustedHeader)
		if ip == nil || !auth.IPAllowed(s.cfg.Admin.ParsedCIDRs, ip) {
			s.log.Warn("admin: rejected client outside allow_cidrs", "remote", r.RemoteAddr)
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// csrfAndAuth guards mutating/API requests:
//   - GET /, GET /static/* and GET /healthz need no further check (CIDR
//     already applied).
//   - /api/* and /metrics optionally require the bearer token
//     (admin.token) when configured.
//   - mutating /api/* requests (POST/DELETE) additionally require the
//     panel CSRF token in X-CSRF-Token, unless a valid bearer token was
//     presented (that covers the CLI and other machine clients). The
//     token is available to any CIDR-allowed caller via GET /api/csrf.
func (s *Server) csrfAndAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		isAPI := strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == "/metrics"
		bearerOK := s.checkBearer(r)

		if isAPI && s.cfg.Admin.Token != "" && !bearerOK {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		if isAPI && (r.Method == http.MethodPost || r.Method == http.MethodDelete) && !bearerOK {
			if !pass.ConstantTimeEqual(r.Header.Get("X-CSRF-Token"), s.csrfToken) {
				http.Error(w, "invalid csrf token", http.StatusForbidden)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

// checkBearer reports whether r carries the configured admin bearer
// token. If no token is configured, it always reports false (bearer
// auth is simply not in use).
func (s *Server) checkBearer(r *http.Request) bool {
	if s.cfg.Admin.Token == "" {
		return false
	}
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(h, prefix) {
		return false
	}
	return pass.ConstantTimeEqual(strings.TrimPrefix(h, prefix), s.cfg.Admin.Token)
}
