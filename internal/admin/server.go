// Package admin implements hodor's admin listener: the JSON control API,
// the embedded panel page/static assets, /healthz and a hand-written
// Prometheus /metrics endpoint. It MUST only be reachable from LAN/VPN;
// enforcement is a CIDR allow-list checked on every request.
package admin

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
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
	live      *config.Live
	state     *state.Store
	pins      *pin.Manager
	secret    []byte
	lang      i18n.Lang
	log       *slog.Logger
	csrfToken string
	// setupToken is a random, in-memory-only bearer token used instead
	// of admin.token while none is configured (docs/DESIGN.md "Phase
	// 3 — zero-file setup"): without it, every /api/* request would be
	// unauthenticated. Never persisted/serialized and never equal to
	// admin.token; see checkBearer/effectiveToken. It changes on every
	// restart until an admin.token is set via PUT /api/config/general.
	setupToken string
	pinLimit   *auth.RateLimiter
	keyLimit   *auth.RateLimiter

	handler http.Handler
}

// New builds the admin-listener handler for live's current config.
// Every request re-reads live.Get() (see Server.cfg), so a reload or a
// panel save (internal/config.Live) is visible to the very next
// request, with no restart.
func New(live *config.Live, st *state.Store, pins *pin.Manager, secret []byte, log *slog.Logger) (*Server, error) {
	if log == nil {
		log = slog.Default()
	}
	token, err := randomHex(32)
	if err != nil {
		return nil, err
	}
	setupToken, err := randomHex(32)
	if err != nil {
		return nil, err
	}
	cfg := live.Get()
	s := &Server{
		live:       live,
		state:      st,
		pins:       pins,
		secret:     secret,
		lang:       i18n.Parse(cfg.Lang),
		log:        log,
		csrfToken:  token,
		setupToken: setupToken,
		pinLimit:   auth.NewRateLimiter(pinApproveLimit, pinApproveWindow),
		keyLimit:   auth.NewRateLimiter(apiV1KeyLimit, apiV1KeyWindow),
	}
	setupTokenFile := setupTokenPath(cfg)
	if cfg.Admin.Token == "" {
		log.Warn("no admin token set: panel locked until you log in with this setup token", "setup_token", setupToken)
		fmt.Fprintln(os.Stderr, "hodor setup token:", setupToken)
		fmt.Fprintln(os.Stderr, "hodor setup token: use it as the admin Bearer token to log in, then set admin_token to replace it")
		if err := writeSetupTokenFile(setupTokenFile, setupToken); err != nil {
			log.Warn("failed to write setup token file (CLI commands will need admin.token or ADMIN_TOKEN)", "path", setupTokenFile, "err", err)
		}
	} else {
		// A stale file from a previous no-admin.token run would let the
		// CLI pick up a bearer that's no longer valid; best effort only.
		_ = os.Remove(setupTokenFile)
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

	mux.HandleFunc("GET /api/config", s.handleConfigGet)
	mux.HandleFunc("PUT /api/config/general", s.handleConfigGeneralPut)
	mux.HandleFunc("PUT /api/config/services/{name}", s.handleConfigServicePut)
	mux.HandleFunc("DELETE /api/config/services/{name}", s.handleConfigServiceDelete)
	mux.HandleFunc("PUT /api/config/durations", s.handleConfigDurationsPut)
	mux.HandleFunc("POST /api/config/keys", s.handleConfigKeyCreate)
	mux.HandleFunc("DELETE /api/config/keys/{id}", s.handleConfigKeyDelete)
	mux.HandleFunc("POST /api/config/reload", s.handleConfigReload)

	mux.HandleFunc("GET /api/v1/services/{name}", s.handleV1ServiceGet)
	mux.HandleFunc("POST /api/v1/services/{name}/open", s.handleV1ServiceOpen)
	mux.HandleFunc("POST /api/v1/services/{name}/close", s.handleV1ServiceClose)
	mux.HandleFunc("OPTIONS /api/v1/services/{name}", s.handleV1Preflight)
	mux.HandleFunc("OPTIONS /api/v1/services/{name}/{action}", s.handleV1Preflight)

	s.handler = s.securityHeaders(s.cidrCheck(s.csrfAndAuth(s.apiV1Guard(mux))))
	return s, nil
}

// cfg returns the currently active config. Called per request (never
// cached in a field) so a reload/save is visible immediately.
func (s *Server) cfg() *config.Config { return s.live.Get() }

// effectiveToken returns the bearer token currently accepted by
// checkBearer: admin.token once one is configured, s.setupToken while
// it isn't. Setting admin.token via PUT /api/config/general makes this
// switch over on the very next request (cfg() always re-reads live).
func (s *Server) effectiveToken() string {
	if t := s.cfg().Admin.Token; t != "" {
		return t
	}
	return s.setupToken
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

// setupTokenPath returns the path of the file the CLI (cmd/hodor,
// adminRequest) reads the setup token from when cfg.Admin.Token is
// empty: next to state_file, which is itself already defaulted to the
// zero-file-setup data dir (HODOR_DATA_DIR, or /data - see
// internal/config.dataDir/Config.Validate). Both the server and the
// CLI derive it the same way, so no new config field is needed.
func setupTokenPath(cfg *config.Config) string {
	return filepath.Join(filepath.Dir(cfg.StateFile), "setup.token")
}

// writeSetupTokenFile atomically (write-to-temp + rename) writes token
// to path with 0600 permissions, so the CLI (running as the same user/
// container, e.g. `docker exec hodor hodor open x`) can read it without
// it ever appearing half-written or world-readable.
func writeSetupTokenFile(path, token string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(token+"\n"), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
