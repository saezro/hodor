package admin

import (
	"net"
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
//     and /metrics require either the effective bearer token
//     (admin.token, or the in-memory setup token while none is
//     configured - see Server.effectiveToken/setupToken) or, when
//     admin.auth_header is configured, a trusted reverse proxy's SSO
//     header identifying an allow-listed user (see headerUser): there
//     is no unauthenticated mode.
//   - mutating /api/* requests (POST/PUT/DELETE) additionally require
//     the panel CSRF token in X-CSRF-Token, unless a valid bearer token
//     was presented (that covers the CLI and other machine clients).
//     Header-based (SSO) auth does NOT get this free pass: it relies on
//     the proxy's own session cookie, which is exactly the kind of
//     ambient credential CSRF protects against, so those mutations
//     still need X-CSRF-Token.
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

		headerOK := false
		if isAPI && !bearerOK {
			user, present, allowed := s.headerUser(r)
			if present && !allowed {
				s.log.Warn("admin: rejected SSO header user outside allowlist", "user", user)
				http.Error(w, "forbidden", http.StatusForbidden)
				return
			}
			headerOK = present && allowed
		}

		if isAPI && !bearerOK && !headerOK {
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

// headerUser reports whether r carries a usable SSO identity via
// admin.auth_header: present is true only when auth_header is
// configured, the DIRECT peer (r.RemoteAddr - deliberately not the
// resolved auth.ClientIP, which would itself trust a chain of forwarded
// headers one of which could be this very header's proxy) is in
// admin.trusted_proxies, and the header's value is non-empty after
// trimming. allowed is then whichever of that user's identity/groups
// passes the configured allowlist (see headerAllowed); it is
// meaningless when present is false. user is returned for logging even
// when not allowed.
func (s *Server) headerUser(r *http.Request) (user string, present, allowed bool) {
	cfg := s.cfg()
	if cfg.Admin.AuthHeader == "" {
		return "", false, false
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer := net.ParseIP(host)
	if peer == nil || !auth.IPAllowed(cfg.Admin.ParsedProxies, peer) {
		return "", false, false
	}
	user = strings.TrimSpace(r.Header.Get(cfg.Admin.AuthHeader))
	if user == "" {
		return "", false, false
	}
	return user, true, headerAllowed(cfg.Admin.AllowedUsers, cfg.Admin.AllowedGroups, user, r.Header.Get(cfg.Admin.AuthGroupsHeader))
}

// headerAllowed reports whether user (or one of the comma-separated
// groups in groupsHeader) passes the allow_users/allow_groups
// allowlist: both empty means any authenticated user passes; otherwise
// user must exactly match an entry in allowedUsers, or one of its
// groups must exactly match an entry in allowedGroups.
func headerAllowed(allowedUsers, allowedGroups []string, user, groupsHeader string) bool {
	if len(allowedUsers) == 0 && len(allowedGroups) == 0 {
		return true
	}
	for _, u := range allowedUsers {
		if u == user {
			return true
		}
	}
	if len(allowedGroups) == 0 {
		return false
	}
	for _, g := range strings.Split(groupsHeader, ",") {
		g = strings.TrimSpace(g)
		if g == "" {
			continue
		}
		for _, allowed := range allowedGroups {
			if allowed == g {
				return true
			}
		}
	}
	return false
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
