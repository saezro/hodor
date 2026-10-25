// Package proxy implements hodor's public listener: Host-based routing
// to configured services, the proxy and forwardauth gate modes, the
// /.hodor/closed and /tv pages and /healthz.
package proxy

import (
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/saezro/hodor/internal/config"
	"github.com/saezro/hodor/internal/i18n"
	"github.com/saezro/hodor/internal/pass"
	"github.com/saezro/hodor/internal/pin"
	"github.com/saezro/hodor/internal/state"
)

// Server is the public-listener HTTP handler.
type Server struct {
	cfg    *config.Config
	state  *state.Store
	pins   *pin.Manager
	secret []byte
	lang   i18n.Lang
	log    *slog.Logger

	hostToService map[string]*config.Service
	reverseProxy  map[string]*httputil.ReverseProxy

	mux *http.ServeMux
}

// New builds the public-listener handler for cfg.
func New(cfg *config.Config, st *state.Store, pins *pin.Manager, secret []byte, log *slog.Logger) (*Server, error) {
	if log == nil {
		log = slog.Default()
	}
	s := &Server{
		cfg:           cfg,
		state:         st,
		pins:          pins,
		secret:        secret,
		lang:          i18n.Parse(cfg.Lang),
		log:           log,
		hostToService: make(map[string]*config.Service),
		reverseProxy:  make(map[string]*httputil.ReverseProxy),
	}

	for i := range cfg.Services {
		svc := &cfg.Services[i]
		for _, h := range svc.Hosts {
			s.hostToService[h] = svc
		}
		if svc.Mode == config.ModeProxy {
			u, err := url.Parse(svc.Upstream)
			if err != nil {
				return nil, err
			}
			s.reverseProxy[svc.Name] = newReverseProxy(u)
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /auth", s.handleForwardAuth)
	mux.HandleFunc("GET /.hodor/closed", s.handleClosed)
	mux.HandleFunc("GET /tv", s.handleTV)
	mux.HandleFunc("GET /.hodor/tv/status", s.handleTVStatus)
	mux.HandleFunc("/", s.handleDefault)
	s.mux = mux

	return s, nil
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// lookupHost finds the configured service for a Host header value,
// stripping any port.
func (s *Server) lookupHost(host string) *config.Service {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return s.hostToService[host]
}

// stateKey returns the state-store key for a service: its group name if
// it belongs to one (so grouped services share one open/closed switch),
// otherwise its own name.
func stateKey(s *config.Service) string {
	if s.Group != "" {
		return s.Group
	}
	return s.Name
}

// hasValidPass reports whether r carries a valid, non-revoked device
// pass cookie for svc.
func (s *Server) hasValidPass(r *http.Request, svc *config.Service) bool {
	c, err := r.Cookie(pass.CookieName(svc.Name))
	if err != nil {
		return false
	}
	id, service, err := pass.Verify(s.secret, c.Value)
	if err != nil || service != svc.Name {
		return false
	}
	return s.state.IsPassValid(id, svc.Name)
}

// allowed reports whether r should be let through for svc right now.
func (s *Server) allowed(r *http.Request, svc *config.Service) bool {
	if s.state.IsOpen(stateKey(svc)) {
		return true
	}
	if svc.PassBypassesClosed != nil && *svc.PassBypassesClosed && s.hasValidPass(r, svc) {
		return true
	}
	return false
}

// issuePass creates and persists a new device pass for svc and sets its
// signed cookie on w.
func (s *Server) issuePass(w http.ResponseWriter, r *http.Request, svc *config.Service) error {
	id, err := pass.NewID()
	if err != nil {
		return err
	}
	ttl := s.cfg.ParsedPassTTL
	if ttl <= 0 {
		ttl = 30 * 24 * time.Hour
	}
	expiry := time.Now().Add(ttl)
	if err := s.state.AddPass(state.Pass{ID: id, Service: svc.Name, Label: "tv"}); err != nil {
		return err
	}
	token := pass.Issue(s.secret, id, svc.Name, expiry)
	http.SetCookie(w, &http.Cookie{ // #nosec G124 -- HttpOnly/Secure/SameSite are all set below
		Name:     pass.CookieName(svc.Name),
		Value:    token,
		Path:     "/",
		Expires:  expiry,
		HttpOnly: true,
		Secure:   s.cookieSecure(r),
		SameSite: http.SameSiteLaxMode,
	})
	return nil
}

// cookieSecure decides the Secure flag for a device-pass cookie: it is
// true for a direct TLS connection, for an HTTPS request relayed by a
// trusted reverse proxy (X-Forwarded-Proto, only honored from
// public.trusted_proxies), or when public.cookie_secure forces it.
func (s *Server) cookieSecure(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if s.remoteTrusted(r) && r.Header.Get("X-Forwarded-Proto") == "https" {
		return true
	}
	if s.cfg.Public.CookieSecure != nil {
		return *s.cfg.Public.CookieSecure
	}
	return true
}

func newReverseProxy(upstream *url.URL) *httputil.ReverseProxy {
	rp := httputil.NewSingleHostReverseProxy(upstream)
	rp.FlushInterval = -1 // SSE/streaming flush-through.
	//nolint:staticcheck // Director (not Rewrite) keeps this a minimal wrap of the stdlib default; revisit if ReverseProxy.Rewrite is adopted more broadly here.
	origDirector := rp.Director
	rp.Director = func(r *http.Request) {
		stripHodorCookies(r)
		origDirector(r)
	}
	return rp
}

// stripHodorCookies removes hodor_* cookies (device passes) from r
// before it is forwarded upstream: the upstream service has no business
// seeing hodor's own session state.
func stripHodorCookies(r *http.Request) {
	cookies := r.Cookies()
	if len(cookies) == 0 {
		return
	}
	kept := make([]string, 0, len(cookies))
	for _, c := range cookies {
		if strings.HasPrefix(c.Name, "hodor_") {
			continue
		}
		kept = append(kept, c.Name+"="+c.Value)
	}
	if len(kept) == 0 {
		r.Header.Del("Cookie")
		return
	}
	r.Header.Set("Cookie", strings.Join(kept, "; "))
}
