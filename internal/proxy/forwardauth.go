package proxy

import (
	"net"
	"net/http"

	"github.com/saezro/hodor/internal/auth"
	"github.com/saezro/hodor/internal/config"
)

// remoteTrusted reports whether r's direct peer (RemoteAddr, never a
// header) is one of the configured public.trusted_proxies, i.e. a
// reverse proxy hodor is known to sit behind and may therefore trust
// for X-Forwarded-* values.
func (s *Server) remoteTrusted(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return auth.IPAllowed(s.cfg.Public.ParsedProxies, ip)
}

// handleForwardAuth implements GET /auth for Traefik forwardAuth / Caddy
// forward_auth / nginx auth_request: it decides whether the original
// request may proceed. X-Forwarded-Host/Proto are only honored when the
// caller is a trusted proxy; otherwise hodor falls back to the actual
// connection's own Host/TLS, so an untrusted client cannot spoof its way
// into an arbitrary redirect target or host lookup.
func (s *Server) handleForwardAuth(w http.ResponseWriter, r *http.Request) {
	host := r.Host
	proto := "http"
	if r.TLS != nil {
		proto = "https"
	}

	if s.remoteTrusted(r) {
		if h := r.Header.Get("X-Forwarded-Host"); h != "" {
			host = h
		}
		if p := r.Header.Get("X-Forwarded-Proto"); p != "" {
			proto = p
		}
	}

	svc := s.lookupHost(host)
	if svc == nil {
		http.Error(w, "unknown host", http.StatusNotFound)
		return
	}

	if s.allowed(r, svc) {
		w.WriteHeader(http.StatusOK)
		return
	}

	onDeny := svc.Auth.OnDeny
	if onDeny == "" {
		onDeny = config.OnDenyRedirect
	}
	if onDeny == config.OnDeny401 {
		http.Error(w, "closed", http.StatusUnauthorized)
		return
	}

	// host was just resolved to a configured service above, so this
	// redirect target is never attacker-controlled.
	http.Redirect(w, r, proto+"://"+host+"/.hodor/closed", http.StatusFound)
}
