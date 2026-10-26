package admin

import (
	"net/http"
	"strings"

	"github.com/saezro/hodor/internal/apikey"
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
		ip := auth.ClientIP(r, s.cfg().Admin.ParsedProxies, s.cfg().Admin.TrustedHeader)
		if ip == nil || !auth.IPAllowed(s.cfg().Admin.ParsedCIDRs, ip) {
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
//   - /api/* (except /api/v1/*, which has its own auth in apiV1Guard)
//     and /metrics always require the effective bearer token
//     (admin.token, or the in-memory setup token while none is
//     configured - see Server.effectiveToken/setupToken): there is no
//     unauthenticated mode.
//   - mutating /api/* requests (POST/PUT/DELETE) additionally require
//     the panel CSRF token in X-CSRF-Token, unless a valid bearer token
//     was presented (that covers the CLI and other machine clients).
//     In practice this is now dead weight for the panel/CLI path since
//     bearerOK is already required above, but it's kept as-is (also
//     relevant to any future caller that gets a free pass on the
//     bearer check).
func (s *Server) csrfAndAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/v1/") {
			// Authenticated and scoped by apiV1Guard, further down the
			// chain: the panel's admin.token/CSRF rules don't apply.
			next.ServeHTTP(w, r)
			return
		}
		isAPI := strings.HasPrefix(r.URL.Path, "/api/") || r.URL.Path == "/metrics"
		bearerOK := s.checkBearer(r)

		// A scoped /api/v1 key is never valid on the panel's own /api/*:
		// reject explicitly (403) instead of falling through to the
		// generic "no/invalid admin.token" 401 below.
		if isAPI && !bearerOK {
			if tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer "); ok && tok != "" {
				if apikey.Match(s.cfg().APIKeys, tok) != nil {
					http.Error(w, "scoped api keys cannot access this endpoint", http.StatusForbidden)
					return
				}
			}
		}

		if isAPI && !bearerOK {
			if s.cfg().Admin.Token == "" {
				// No admin.token configured yet: the setup token is
				// the only valid bearer (see Server.effectiveToken).
				// Tell the panel so it can show the setup prompt
				// instead of a plain "unauthorized".
				w.Header().Set("X-Hodor-Setup", "1")
			}
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}

		if isAPI && (r.Method == http.MethodPost || r.Method == http.MethodPut || r.Method == http.MethodDelete) && !bearerOK {
			if !pass.ConstantTimeEqual(r.Header.Get("X-CSRF-Token"), s.csrfToken) {
				http.Error(w, "invalid csrf token", http.StatusForbidden)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

// checkBearer reports whether r carries the effective admin bearer
// token: admin.token once configured, otherwise the in-memory setup
// token (see Server.effectiveToken) - there is no longer an
// unauthenticated mode.
func (s *Server) checkBearer(r *http.Request) bool {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(h, prefix) {
		return false
	}
	return pass.ConstantTimeEqual(strings.TrimPrefix(h, prefix), s.effectiveToken())
}
