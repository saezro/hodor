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
	"sync/atomic"
	"time"

	"github.com/saezro/hodor/internal/config"
	"github.com/saezro/hodor/internal/i18n"
	"github.com/saezro/hodor/internal/pass"
	"github.com/saezro/hodor/internal/pin"
	"github.com/saezro/hodor/internal/state"
)

// routing is the Host-based lookup tables derived from one Config: it
// is rebuilt (see buildRouting/routingFor) whenever the live config is
// swapped by a reload or a panel save, so a hot-reloaded service's
// host/upstream take effect without a restart.
type routing struct {
	cfg           *config.Config
	hostToService map[string]*config.Service
	reverseProxy  map[string]*httputil.ReverseProxy
}

// Server is the public-listener HTTP handler.
type Server struct {
	live   *config.Live
	state  *state.Store
	pins   *pin.Manager
	secret []byte
	lang   i18n.Lang
	log    *slog.Logger

	routingPtr atomic.Pointer[routing]

	mux *http.ServeMux
}

// New builds the public-listener handler for live's current config.
// Every request re-reads live.Get(), so a later reload/save (see
// internal/config.Live) takes effect immediately, with no restart.
func New(live *config.Live, st *state.Store, pins *pin.Manager, secret []byte, log *slog.Logger) (*Server, error) {
	if log == nil {
		log = slog.Default()
	}
	cfg := live.Get()
	s := &Server{
		live:   live,
		state:  st,
		pins:   pins,
		secret: secret,
		lang:   i18n.Parse(cfg.Lang),
		log:    log,
	}
	if _, err := s.buildRouting(cfg); err != nil {
		return nil, err
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

// cfg returns the currently active config. Called per request (never
// cached in a field) so a reload/save is visible to the very next
// request.
func (s *Server) cfg() *config.Config { return s.live.Get() }

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// buildRouting derives the Host->Service map and the per-service
// reverse proxies from cfg and stores them as the current routing
// table.
func (s *Server) buildRouting(cfg *config.Config) (*routing, error) {
	rt := &routing{
		cfg:           cfg,
		hostToService: make(map[string]*config.Service),
		reverseProxy:  make(map[string]*httputil.ReverseProxy),
	}
	for i := range cfg.Services {
		svc := &cfg.Services[i]
		for _, h := range svc.Hosts {
			rt.hostToService[h] = svc
		}
		if svc.Mode == config.ModeProxy {
			u, err := url.Parse(svc.Upstream)
			if err != nil {
				return nil, err
			}
			rt.reverseProxy[svc.Name] = newReverseProxy(u)
		}
	}
	s.routingPtr.Store(rt)
	return rt, nil
}

// routingFor returns the routing tables for cfg, rebuilding them if cfg
// isn't the one they were last built from: a reload or panel save
// always swaps in a brand new *config.Config value, so pointer identity
// is enough to detect that host routing needs rebuilding.
func (s *Server) routingFor(cfg *config.Config) *routing {
	if rt := s.routingPtr.Load(); rt != nil && rt.cfg == cfg {
		return rt
	}
	rt, err := s.buildRouting(cfg)
	if err != nil {
		// cfg was already validated (config.Validate) before it became
		// live, so this should be unreachable. buildRouting left
		// routingPtr untouched on this error path, so fail safe by
		// keeping whatever routing table was already serving traffic
		// instead of swapping in an empty one (which would 404 every
		// request until the next successful rebuild).
		s.log.Error("proxy: rebuild routing failed, keeping previous routing table", "err", err)
		if prev := s.routingPtr.Load(); prev != nil {
			return prev
		}
		return &routing{cfg: cfg, hostToService: map[string]*config.Service{}, reverseProxy: map[string]*httputil.ReverseProxy{}}
	}
	return rt
}

// lookupHost finds the configured service for a Host header value,
// stripping any port. cfg must be the config already read for this
// request (via s.cfg()), so the lookup and any routing table built from
// it (e.g. the reverse proxy) stay consistent even if a reload/save
// swaps the live config mid-request.
func (s *Server) lookupHost(cfg *config.Config, host string) *config.Service {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return s.routingFor(cfg).hostToService[host]
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
// signed cookie on w. cfg must be the config already read for this
// request.
func (s *Server) issuePass(cfg *config.Config, w http.ResponseWriter, r *http.Request, svc *config.Service) error {
	id, err := pass.NewID()
	if err != nil {
		return err
	}
	ttl := cfg.ParsedPassTTL
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
		Secure:   s.cookieSecure(cfg, r),
		SameSite: http.SameSiteLaxMode,
	})
	return nil
}

// cookieSecure decides the Secure flag for a device-pass cookie: it is
// true for a direct TLS connection, for an HTTPS request relayed by a
// trusted reverse proxy (X-Forwarded-Proto, only honored from
// public.trusted_proxies), or when public.cookie_secure forces it. cfg
// must be the config already read for this request.
func (s *Server) cookieSecure(cfg *config.Config, r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	if s.remoteTrusted(cfg, r) && r.Header.Get("X-Forwarded-Proto") == "https" {
		return true
	}
	if cfg.Public.CookieSecure != nil {
		return *cfg.Public.CookieSecure
	}
	return true
}

func newReverseProxy(upstream *url.URL) *httputil.ReverseProxy {
	rp := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			stripHodorCookies(pr.Out)
			pr.SetURL(upstream)
			pr.Out.Host = pr.In.Host // keep client Host, as the old Director did.
			pr.SetXForwarded()
		},
	}
	rp.FlushInterval = -1 // SSE/streaming flush-through.
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
