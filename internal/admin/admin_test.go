package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/saezro/hodor/internal/config"
	"github.com/saezro/hodor/internal/pin"
	"github.com/saezro/hodor/internal/state"
)

// newTestConfig builds a minimal, valid Config with one standalone
// service ("svc1") and two grouped services ("svcA", "svcB" sharing
// group "grp"), then applies mutate (if any) before Validate fills in
// defaults and parsed CIDRs.
func newTestConfig(t *testing.T, mutate func(*config.Config)) *config.Config {
	t.Helper()
	cfg := &config.Config{
		Services: []config.Service{
			{Name: "svc1", Hosts: []string{"svc1.example.com"}, Mode: config.ModeProxy, Upstream: "http://127.0.0.1:9"},
			{Name: "svcA", Hosts: []string{"a.example.com"}, Mode: config.ModeProxy, Upstream: "http://127.0.0.1:9", Group: "grp"},
			{Name: "svcB", Hosts: []string{"b.example.com"}, Mode: config.ModeProxy, Upstream: "http://127.0.0.1:9", Group: "grp"},
		},
	}
	if mutate != nil {
		mutate(cfg)
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	return cfg
}

// newTestServer builds an admin.Server backed by a fresh on-disk state
// store (in t.TempDir()) and PIN manager, returning the server together
// with its state and PIN manager for assertions.
func newTestServer(t *testing.T, cfg *config.Config) (*Server, *state.Store, *pin.Manager) {
	t.Helper()
	keys := map[string]bool{}
	var names []string
	for i := range cfg.Services {
		k := stateKey(&cfg.Services[i])
		if !keys[k] {
			keys[k] = true
			names = append(names, k)
		}
	}
	st, err := state.New(t.TempDir()+"/state.json", names, nil)
	if err != nil {
		t.Fatalf("state.New: %v", err)
	}
	pins := pin.New(nil)
	srv, err := New(config.NewLiveFrom(cfg), st, pins, []byte("test-secret"), nil)
	if err != nil {
		t.Fatalf("admin.New: %v", err)
	}
	return srv, st, pins
}

func doReq(srv *Server, method, path, remoteAddr string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	req.RemoteAddr = remoteAddr
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

// bearerHeaders returns an Authorization header carrying srv's
// effective bearer token (admin.token once configured, otherwise the
// in-memory setup token - see Server.effectiveToken): every /api/*
// request needs one since the zero-file/no-admin.token fix, there is
// no more unauthenticated mode.
func bearerHeaders(srv *Server) map[string]string {
	return map[string]string{"Authorization": "Bearer " + srv.effectiveToken()}
}

func csrfToken(t *testing.T, srv *Server, remoteAddr string) string {
	t.Helper()
	rec := doReq(srv, http.MethodGet, "/api/csrf", remoteAddr, bearerHeaders(srv))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/csrf = %d, want 200", rec.Code)
	}
	var resp CSRFResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode csrf response: %v", err)
	}
	return resp.Token
}

func TestCidrCheck_AllowAndDeny(t *testing.T) {
	cfg := newTestConfig(t, func(c *config.Config) {
		c.Admin.AllowCIDRs = []string{"10.0.0.0/8"}
	})
	srv, _, _ := newTestServer(t, cfg)

	tests := []struct {
		name       string
		remoteAddr string
		want       int
	}{
		{"inside allow_cidrs", "10.0.0.5:1234", http.StatusOK},
		{"outside allow_cidrs", "8.8.8.8:1234", http.StatusForbidden},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := doReq(srv, http.MethodGet, "/healthz", tt.remoteAddr, nil)
			if rec.Code != tt.want {
				t.Errorf("GET /healthz from %s = %d, want %d", tt.remoteAddr, rec.Code, tt.want)
			}
		})
	}
}

func TestBearerToken(t *testing.T) {
	cfg := newTestConfig(t, func(c *config.Config) {
		c.Admin.Token = "s3cr3t"
	})
	srv, _, _ := newTestServer(t, cfg)
	const remote = "127.0.0.1:1234"

	tests := []struct {
		name   string
		header string
		want   int
	}{
		{"missing bearer", "", http.StatusUnauthorized},
		{"wrong bearer", "Bearer nope", http.StatusUnauthorized},
		{"correct bearer", "Bearer s3cr3t", http.StatusOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := map[string]string{}
			if tt.header != "" {
				headers["Authorization"] = tt.header
			}
			rec := doReq(srv, http.MethodGet, "/api/services", remote, headers)
			if rec.Code != tt.want {
				t.Errorf("GET /api/services (%s) = %d, want %d: %s", tt.name, rec.Code, tt.want, rec.Body.String())
			}
		})
	}
}

func TestCSRF_RequiredForMutatingAPI(t *testing.T) {
	cfg := newTestConfig(t, nil)
	srv, _, _ := newTestServer(t, cfg)
	const remote = "127.0.0.1:1234"

	// No bearer at all (even with a would-be CSRF token): 401, same as
	// any other unauthenticated /api/* call now that there's no
	// unauthenticated mode (checkBearer/effectiveToken).
	rec := doReq(srv, http.MethodPost, "/api/services/svc1/open", remote, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("POST without bearer = %d, want 401: %s", rec.Code, rec.Body.String())
	}

	// A valid bearer short-circuits the CSRF check entirely (csrfAndAuth
	// only enforces it when !bearerOK): no X-CSRF-Token needed here.
	rec = doReq(srv, http.MethodPost, "/api/services/svc1/open", remote, bearerHeaders(srv))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("POST with valid bearer (no CSRF token) = %d, want 204: %s", rec.Code, rec.Body.String())
	}
}

func TestOpenClose_ServiceAndGroup(t *testing.T) {
	cfg := newTestConfig(t, nil)
	srv, st, _ := newTestServer(t, cfg)
	const remote = "127.0.0.1:1234"
	token := csrfToken(t, srv, remote)
	headers := map[string]string{"X-CSRF-Token": token, "Authorization": "Bearer " + srv.effectiveToken()}

	// Standalone service.
	rec := doReq(srv, http.MethodPost, "/api/services/svc1/open", remote, headers)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("open svc1 = %d, want 204", rec.Code)
	}
	if got, ok := st.Get("svc1"); !ok || !got.Open {
		t.Errorf("svc1 state = %+v, ok=%v, want open", got, ok)
	}

	rec = doReq(srv, http.MethodPost, "/api/services/svc1/close", remote, headers)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("close svc1 = %d, want 204", rec.Code)
	}
	if got, ok := st.Get("svc1"); !ok || got.Open {
		t.Errorf("svc1 state = %+v, ok=%v, want closed", got, ok)
	}

	// Group, addressed by its group name and also by a member name.
	rec = doReq(srv, http.MethodPost, "/api/services/grp/open", remote, headers)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("open grp = %d, want 204", rec.Code)
	}
	if got, ok := st.Get("grp"); !ok || !got.Open {
		t.Errorf("grp state = %+v, ok=%v, want open", got, ok)
	}

	rec = doReq(srv, http.MethodPost, "/api/services/svcA/close", remote, headers)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("close svcA (member of grp) = %d, want 204", rec.Code)
	}
	if got, ok := st.Get("grp"); !ok || got.Open {
		t.Errorf("grp state after closing member svcA = %+v, ok=%v, want closed", got, ok)
	}

	// Unknown name.
	rec = doReq(srv, http.MethodPost, "/api/services/nope/open", remote, headers)
	if rec.Code != http.StatusNotFound {
		t.Errorf("open unknown service = %d, want 404", rec.Code)
	}
}

func TestApprovePin_RateLimitedPerIP(t *testing.T) {
	cfg := newTestConfig(t, nil)
	srv, _, pins := newTestServer(t, cfg)
	const remote = "127.0.0.1:1234"

	if _, err := pins.Create("svc1"); err != nil {
		t.Fatalf("pins.Create: %v", err)
	}
	token := csrfToken(t, srv, remote)

	body := func() *strings.Reader { return strings.NewReader(`{"code":"000000"}`) }
	post := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/pins", body())
		req.RemoteAddr = remote
		req.Header.Set("X-CSRF-Token", token)
		req.Header.Set("Authorization", "Bearer "+srv.effectiveToken())
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		return rec
	}

	// pinApproveLimit (5) wrong-code attempts are each let through to the
	// pin manager, which reports no match (wrong code).
	for i := 0; i < pinApproveLimit; i++ {
		rec := post()
		if rec.Code != http.StatusNotFound {
			t.Fatalf("attempt %d: POST /api/pins = %d, want 404 (no matching pin): %s", i+1, rec.Code, rec.Body.String())
		}
	}

	// The next attempt from the same IP is rate-limited, regardless of
	// the (still wrong) code.
	rec := post()
	if rec.Code != http.StatusTooManyRequests {
		t.Errorf("attempt %d: POST /api/pins = %d, want 429 (rate limited): %s", pinApproveLimit+1, rec.Code, rec.Body.String())
	}
}
