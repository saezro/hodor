package proxy

import (
	"net"
	"net/http"
	"net/url"

	"github.com/saezro/hodor/internal/auth"
	"github.com/saezro/hodor/internal/config"
)

// remoteTrusted reports whether r's direct peer (RemoteAddr, never a
// header) is one of the configured public.trusted_proxies, i.e. a
// reverse proxy hodor is known to sit behind and may therefore trust
// for X-Forwarded-* values. cfg must be the config already read for
// this request.
func (s *Server) remoteTrusted(cfg *config.Config, r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	return auth.IPAllowed(cfg.Public.ParsedProxies, ip)
}

// handleForwardAuth implements GET /auth for Traefik forwardAuth / Caddy
// forward_auth / nginx auth_request: it decides whether the original
// request may proceed. X-Forwarded-Host/Proto are only honored when the
// caller is a trusted proxy; otherwise hodor falls back to the actual
// connection's own Host/TLS, so an untrusted client cannot spoof its way
// into an arbitrary redirect target or host lookup.
func (s *Server) handleForwardAuth(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfg()
	host := r.Host
	proto := "http"
	if r.TLS != nil {
		proto = "https"
	}
	// reqPath/reqMethod describe the *original* request the front proxy
	// is asking about, not this /auth call itself; they only ever come
	// from X-Forwarded-Uri/X-Forwarded-Method, same trust boundary as
	// Host/Proto below, since an untrusted caller could otherwise forge
	// them to pick whichever path rule it likes.
	reqPath := r.URL.Path
	reqMethod := r.Method

	if s.remoteTrusted(cfg, r) {
		if h := r.Header.Get("X-Forwarded-Host"); h != "" {
			host = h
		}
		if p := r.Header.Get("X-Forwarded-Proto"); p != "" {
			proto = p
		}
		if u := r.Header.Get("X-Forwarded-Uri"); u != "" {
			if parsed, err := url.Parse(u); err == nil && parsed.Path != "" {
				reqPath = parsed.Path
			}
		}
		if m := r.Header.Get("X-Forwarded-Method"); m != "" {
			reqMethod = m
		}
	}

	svc := s.lookupHost(cfg, host)
	if svc == nil {
		http.Error(w, "unknown host", http.StatusNotFound)
		return
	}

	access := svc.MatchAccess(reqPath, reqMethod)
	if access == config.AccessDeny {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	if access == config.AccessPublic {
		w.WriteHeader(http.StatusOK)
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
	http.Redirect(w, r, proto+"://"+host+"/.hodor/closed", http.StatusFound) // #nosec G710 -- host/proto come from a service already resolved above, never attacker input
}
