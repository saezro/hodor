package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/saezro/hodor/internal/apikey"
	"github.com/saezro/hodor/internal/config"
)

// doReqOrigin is doReq plus an optional Origin header, for CORS tests.
func doReqOrigin(srv *Server, method, path, remoteAddr, bearer, origin string) *httptest.ResponseRecorder {
	headers := map[string]string{}
	if bearer != "" {
		headers["Authorization"] = "Bearer " + bearer
	}
	if origin != "" {
		headers["Origin"] = origin
	}
	return doReq(srv, method, path, remoteAddr, headers)
}

func cfgWithKey(t *testing.T, key config.APIKey) (*config.Config, string) {
	t.Helper()
	raw, hashHex, err := apikey.Generate()
	if err != nil {
		t.Fatalf("apikey.Generate: %v", err)
	}
	key.Hash = hashHex
	cfg := newTestConfig(t, func(c *config.Config) {
		c.APIKeys = []config.APIKey{key}
	})
	return cfg, raw
}

func TestV1_UnknownBearer_Unauthorized(t *testing.T) {
	cfg := newTestConfig(t, nil)
	srv, _, _ := newTestServer(t, cfg)
	rec := doReqOrigin(srv, http.MethodGet, "/api/v1/services/svc1", "127.0.0.1:1234", "not-a-real-key", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("GET /api/v1/services/svc1 with unknown bearer = %d, want 401: %s", rec.Code, rec.Body.String())
	}

	rec = doReqOrigin(srv, http.MethodGet, "/api/v1/services/svc1", "127.0.0.1:1234", "", "")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("GET /api/v1/services/svc1 with no bearer = %d, want 401: %s", rec.Code, rec.Body.String())
	}
}

func TestV1_AdminToken_AllowsEverything(t *testing.T) {
	cfg := newTestConfig(t, func(c *config.Config) { c.Admin.Token = "admin-tok" })
	srv, _, _ := newTestServer(t, cfg)
	const remote = "127.0.0.1:1234"

	rec := doReqOrigin(srv, http.MethodGet, "/api/v1/services/svc1", remote, "admin-tok", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/services/svc1 (admin) = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	rec = doReqOrigin(srv, http.MethodPost, "/api/v1/services/svc1/open", remote, "admin-tok", "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("POST .../open (admin) = %d, want 204: %s", rec.Code, rec.Body.String())
	}

	var view ServiceView
	rec = doReqOrigin(srv, http.MethodGet, "/api/v1/services/svc1", remote, "admin-tok", "")
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if view.OpenedBy != "api" {
		t.Errorf("OpenedBy = %q, want %q", view.OpenedBy, "api")
	}
}

func TestV1_ScopeMatrix(t *testing.T) {
	const remote = "127.0.0.1:1234"

	tests := []struct {
		name   string
		key    config.APIKey
		method string
		path   string
		want   int
	}{
		{
			name:   "direct service, status allowed",
			key:    config.APIKey{ID: "k1", Name: "n1", Services: []string{"svc1"}, Actions: []string{"status"}},
			method: http.MethodGet,
			path:   "/api/v1/services/svc1",
			want:   http.StatusOK,
		},
		{
			name:   "group scope, open allowed",
			key:    config.APIKey{ID: "k1", Name: "n1", Services: []string{"grp"}, Actions: []string{"open"}},
			method: http.MethodPost,
			path:   "/api/v1/services/svcA/open",
			want:   http.StatusNoContent,
		},
		{
			name:   "wildcard service, close allowed",
			key:    config.APIKey{ID: "k1", Name: "n1", Services: []string{"*"}, Actions: []string{"close"}},
			method: http.MethodPost,
			path:   "/api/v1/services/svc1/close",
			want:   http.StatusNoContent,
		},
		{
			name:   "action not permitted",
			key:    config.APIKey{ID: "k1", Name: "n1", Services: []string{"svc1"}, Actions: []string{"status"}},
			method: http.MethodPost,
			path:   "/api/v1/services/svc1/open",
			want:   http.StatusForbidden,
		},
		{
			name:   "service out of scope",
			key:    config.APIKey{ID: "k1", Name: "n1", Services: []string{"svcA"}, Actions: []string{"status"}},
			method: http.MethodGet,
			path:   "/api/v1/services/svc1",
			want:   http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, raw := cfgWithKey(t, tt.key)
			srv, _, _ := newTestServer(t, cfg)
			rec := doReqOrigin(srv, tt.method, tt.path, remote, raw, "")
			if rec.Code != tt.want {
				t.Fatalf("%s %s = %d, want %d: %s", tt.method, tt.path, rec.Code, tt.want, rec.Body.String())
			}
		})
	}
}

func TestV1_OpenedBy_KeyName(t *testing.T) {
	cfg, raw := cfgWithKey(t, config.APIKey{ID: "k1", Name: "my-button", Services: []string{"svc1"}, Actions: []string{"open", "status"}})
	srv, _, _ := newTestServer(t, cfg)
	const remote = "127.0.0.1:1234"

	rec := doReqOrigin(srv, http.MethodPost, "/api/v1/services/svc1/open", remote, raw, "")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("open = %d, want 204: %s", rec.Code, rec.Body.String())
	}

	rec = doReqOrigin(srv, http.MethodGet, "/api/v1/services/svc1", remote, raw, "")
	var view ServiceView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if view.OpenedBy != "key:my-button" {
		t.Errorf("OpenedBy = %q, want %q", view.OpenedBy, "key:my-button")
	}
}

func TestV1_CORS_AllowDenyPreflight(t *testing.T) {
	const remote = "127.0.0.1:1234"
	cfg, raw := cfgWithKey(t, config.APIKey{
		ID: "k1", Name: "n1",
		Services: []string{"svc1"}, Actions: []string{"status"},
		AllowOrigins: []string{"https://geo.lan"},
	})
	srv, _, _ := newTestServer(t, cfg)

	// Allowed origin: echoed back, with Vary.
	rec := doReqOrigin(srv, http.MethodGet, "/api/v1/services/svc1", remote, raw, "https://geo.lan")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET with allowed origin = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://geo.lan" {
		t.Errorf("ACAO = %q, want %q", got, "https://geo.lan")
	}
	if got := rec.Header().Get("Vary"); got != "Origin" {
		t.Errorf("Vary = %q, want %q", got, "Origin")
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got == "*" {
		t.Errorf("ACAO must never be *")
	}

	// Denied origin: no ACAO, but still 200 (CORS is a browser-side
	// concern, not a server-side authorization one).
	rec = doReqOrigin(srv, http.MethodGet, "/api/v1/services/svc1", remote, raw, "https://evil.example")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET with denied origin = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("ACAO for denied origin = %q, want empty", got)
	}

	// Preflight for an origin covered by a key that scopes this
	// service+action: 204 with CORS headers.
	rec = doReqOrigin(srv, http.MethodOptions, "/api/v1/services/svc1", remote, "", "https://geo.lan")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("OPTIONS allowed origin = %d, want 204: %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "https://geo.lan" {
		t.Errorf("preflight ACAO = %q, want %q", got, "https://geo.lan")
	}
	if got := rec.Header().Get("Access-Control-Allow-Methods"); got == "" {
		t.Errorf("preflight missing Access-Control-Allow-Methods")
	}

	// Preflight for an origin nobody lists: 204, no CORS headers.
	rec = doReqOrigin(srv, http.MethodOptions, "/api/v1/services/svc1", remote, "", "https://evil.example")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("OPTIONS denied origin = %d, want 204: %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("preflight ACAO for denied origin = %q, want empty", got)
	}
}

func TestV1_RateLimitPerKey(t *testing.T) {
	cfg, raw := cfgWithKey(t, config.APIKey{ID: "k1", Name: "n1", Services: []string{"svc1"}, Actions: []string{"status"}})
	srv, _, _ := newTestServer(t, cfg)
	const remote = "127.0.0.1:1234"

	for i := 0; i < apiV1KeyLimit; i++ {
		rec := doReqOrigin(srv, http.MethodGet, "/api/v1/services/svc1", remote, raw, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("attempt %d = %d, want 200: %s", i+1, rec.Code, rec.Body.String())
		}
	}
	rec := doReqOrigin(srv, http.MethodGet, "/api/v1/services/svc1", remote, raw, "")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("attempt %d = %d, want 429: %s", apiV1KeyLimit+1, rec.Code, rec.Body.String())
	}
}

// TestV1_PanelAPIStillRequiresCSRF makes sure introducing /api/v1/*
// did not loosen the existing /api/* CSRF requirement.
func TestV1_PanelAPIStillRequiresCSRF(t *testing.T) {
	cfg := newTestConfig(t, nil)
	srv, _, _ := newTestServer(t, cfg)
	const remote = "127.0.0.1:1234"

	rec := doReq(srv, http.MethodPost, "/api/services/svc1/open", remote, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("POST /api/services/svc1/open without CSRF = %d, want 403: %s", rec.Code, rec.Body.String())
	}
}
