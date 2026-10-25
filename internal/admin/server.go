// Package admin implements hodor's admin listener: the JSON control API,
// the embedded panel page/static assets, /healthz and a hand-written
// Prometheus /metrics endpoint. It MUST only be reachable from LAN/VPN;
// enforcement is a CIDR allow-list checked on every request.
package admin

import (
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"time"

	"github.com/saezro/hodor/internal/auth"
	"github.com/saezro/hodor/internal/config"
	"github.com/saezro/hodor/internal/i18n"
	"github.com/saezro/hodor/internal/pin"
	"github.com/saezro/hodor/internal/state"
)

// pinApproveLimit/pinApproveWindow bound how many PIN-approval attempts
// one client IP may make: brute-forcing the 6-digit code this way would
// otherwise take at most 10^6 tries.
const (
	pinApproveLimit  = 5
	pinApproveWindow = 10 * time.Minute
)

// apiV1KeyLimit/apiV1KeyWindow bound how many requests one scoped API
// key (identified by its id) may make to /api/v1/*.
const (
	apiV1KeyLimit  = 30
	apiV1KeyWindow = time.Minute
)

// Server is the admin-listener HTTP handler.
type Server struct {
	cfg       *config.Config
	state     *state.Store
	pins      *pin.Manager
	secret    []byte
	lang      i18n.Lang
	log       *slog.Logger
	csrfToken string
	pinLimit  *auth.RateLimiter
	keyLimit  *auth.RateLimiter

	handler http.Handler
}

// New builds the admin-listener handler for cfg.
func New(cfg *config.Config, st *state.Store, pins *pin.Manager, secret []byte, log *slog.Logger) (*Server, error) {
	if log == nil {
		log = slog.Default()
	}
	token, err := randomHex(32)
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg:       cfg,
		state:     st,
		pins:      pins,
		secret:    secret,
		lang:      i18n.Parse(cfg.Lang),
		log:       log,
		csrfToken: token,
		pinLimit:  auth.NewRateLimiter(pinApproveLimit, pinApproveWindow),
		keyLimit:  auth.NewRateLimiter(apiV1KeyLimit, apiV1KeyWindow),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /metrics", s.handleMetrics)
	mux.HandleFunc("GET /", s.handlePanel)
	mux.Handle("GET /static/", s.staticHandler())
	mux.HandleFunc("GET /embed/{svc}", s.handleEmbed)

	mux.HandleFunc("GET /api/csrf", s.handleCSRF)
	mux.HandleFunc("GET /api/services", s.handleServicesList)
	mux.HandleFunc("POST /api/services/{name}/open", s.handleServiceOpen)
	mux.HandleFunc("POST /api/services/{name}/close", s.handleServiceClose)
	mux.HandleFunc("GET /api/pins", s.handlePinsList)
	mux.HandleFunc("POST /api/pins", s.handlePinsApprove)
	mux.HandleFunc("GET /api/passes", s.handlePassesList)
	mux.HandleFunc("DELETE /api/passes/{id}", s.handlePassRevoke)
	mux.HandleFunc("GET /api/events", s.handleEventsList)

	mux.HandleFunc("GET /api/v1/services/{name}", s.handleV1ServiceGet)
	mux.HandleFunc("POST /api/v1/services/{name}/open", s.handleV1ServiceOpen)
	mux.HandleFunc("POST /api/v1/services/{name}/close", s.handleV1ServiceClose)
	mux.HandleFunc("OPTIONS /api/v1/services/{name}", s.handleV1Preflight)
	mux.HandleFunc("OPTIONS /api/v1/services/{name}/{action}", s.handleV1Preflight)

	s.handler = s.securityHeaders(s.cidrCheck(s.csrfAndAuth(s.apiV1Guard(mux))))
	return s, nil
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.handler.ServeHTTP(w, r)
}

func (s *Server) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
