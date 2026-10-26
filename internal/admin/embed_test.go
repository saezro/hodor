package admin

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/saezro/hodor/internal/apikey"
	"github.com/saezro/hodor/internal/config"
)

// cfgWithJellyfinKey is cfgWithKey plus a "jellyfin" service (cfgWithKey's base
// config only has svc1/svcA/svcB), for the embed tests below. The jellyfin
// service must exist in cfg.Services BEFORE cfg.Validate() runs, since
// Validate rejects api_keys scoped to an unknown service/group; it
// can't be appended after cfgWithKey's own (already-run) Validate.
func cfgWithJellyfinKey(t *testing.T, key config.APIKey) (*config.Config, string) {
	t.Helper()
	raw, hashHex, err := apikey.Generate()
	if err != nil {
		t.Fatalf("apikey.Generate: %v", err)
	}
	key.Hash = hashHex
	cfg := newTestConfig(t, func(c *config.Config) {
		c.Services = append(c.Services, config.Service{
			Name: "jellyfin", Hosts: []string{"jellyfin.example.com"}, Mode: config.ModeProxy, Upstream: "http://127.0.0.1:9",
		})
		c.APIKeys = []config.APIKey{key}
	})
	return cfg, raw
}

func TestEmbed_ValidKey_OK(t *testing.T) {
	cfg, raw := cfgWithJellyfinKey(t, config.APIKey{ID: "k1", Name: "n1", Services: []string{"jellyfin"}, Actions: []string{config.KeyActionStatus}, AllowOrigins: []string{"https://a.example.com", "https://b.example.com"}})
	srv, _, _ := newTestServer(t, cfg)

	rec := doReq(srv, http.MethodGet, "/embed/jellyfin?k="+raw, "127.0.0.1:1234", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /embed/jellyfin = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if xfo := rec.Header().Get("X-Frame-Options"); xfo != "" {
		t.Errorf("X-Frame-Options = %q, want unset", xfo)
	}
	wantCSP := "default-src 'self'; frame-ancestors https://a.example.com https://b.example.com"
	if csp := rec.Header().Get("Content-Security-Policy"); csp != wantCSP {
		t.Errorf("Content-Security-Policy = %q, want %q", csp, wantCSP)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, want %q", cc, "no-store")
	}
	if !strings.Contains(rec.Body.String(), `data-service="jellyfin"`) {
		t.Errorf("body missing data-service=%q attribute: %s", "jellyfin", rec.Body.String())
	}
}

func TestEmbed_NoAllowOrigins_FrameAncestorsNone(t *testing.T) {
	cfg, raw := cfgWithJellyfinKey(t, config.APIKey{ID: "k1", Name: "n1", Services: []string{"jellyfin"}, Actions: []string{config.KeyActionStatus}})
	srv, _, _ := newTestServer(t, cfg)

	rec := doReq(srv, http.MethodGet, "/embed/jellyfin?k="+raw, "127.0.0.1:1234", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /embed/jellyfin = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	wantCSP := "default-src 'self'; frame-ancestors 'none'"
	if csp := rec.Header().Get("Content-Security-Policy"); csp != wantCSP {
		t.Errorf("Content-Security-Policy = %q, want %q", csp, wantCSP)
	}
}

func TestEmbed_KeyWithoutScope_Forbidden(t *testing.T) {
	cfg, raw := cfgWithJellyfinKey(t, config.APIKey{ID: "k1", Name: "n1", Services: []string{"svc1"}, Actions: []string{config.KeyActionStatus}})
	srv, _, _ := newTestServer(t, cfg)

	rec := doReq(srv, http.MethodGet, "/embed/jellyfin?k="+raw, "127.0.0.1:1234", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("GET /embed/jellyfin (key out of scope) = %d, want 403: %s", rec.Code, rec.Body.String())
	}
}

func TestEmbed_UnknownKey_Forbidden(t *testing.T) {
	cfg, _ := cfgWithJellyfinKey(t, config.APIKey{ID: "k1", Name: "n1", Services: []string{"jellyfin"}, Actions: []string{config.KeyActionStatus}})
	srv, _, _ := newTestServer(t, cfg)

	rec := doReq(srv, http.MethodGet, "/embed/jellyfin?k=hdr_not-a-real-key", "127.0.0.1:1234", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("GET /embed/jellyfin (unknown key) = %d, want 403: %s", rec.Code, rec.Body.String())
	}
}

func TestEmbed_AdminToken_Forbidden(t *testing.T) {
	cfg, _ := cfgWithJellyfinKey(t, config.APIKey{ID: "k1", Name: "n1", Services: []string{"jellyfin"}, Actions: []string{config.KeyActionStatus}})
	cfg.Admin.Token = "admin-tok"
	srv, _, _ := newTestServer(t, cfg)

	// admin.token is never a valid api_key, so it doesn't match
	// apikey.Match either as ?k= or as a bearer header.
	rec := doReq(srv, http.MethodGet, "/embed/jellyfin?k=admin-tok", "127.0.0.1:1234", nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("GET /embed/jellyfin (admin.token as k) = %d, want 403: %s", rec.Code, rec.Body.String())
	}
	rec = doReq(srv, http.MethodGet, "/embed/jellyfin", "127.0.0.1:1234", map[string]string{"Authorization": "Bearer admin-tok"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("GET /embed/jellyfin (admin.token as bearer) = %d, want 403: %s", rec.Code, rec.Body.String())
	}
}

func TestEmbed_EscapedKey_ForbiddenAndNeverReflected(t *testing.T) {
	cfg, _ := cfgWithJellyfinKey(t, config.APIKey{ID: "k1", Name: "n1", Services: []string{"jellyfin"}, Actions: []string{config.KeyActionStatus}})
	srv, _, _ := newTestServer(t, cfg)

	payload := `"><script>alert(1)</script>`
	req := httptest.NewRequest(http.MethodGet, "/embed/jellyfin", nil)
	req.RemoteAddr = "127.0.0.1:1234"
	req.URL.RawQuery = "k=" + httpQueryEscape(payload)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("GET /embed/jellyfin (garbage k) = %d, want 403: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "<script>") {
		t.Errorf("response body reflects unescaped k: %s", rec.Body.String())
	}
}

// httpQueryEscape avoids importing net/url just for this one call.
func httpQueryEscape(s string) string {
	req, _ := http.NewRequest(http.MethodGet, "http://example.invalid/?k="+s, nil)
	return req.URL.Query().Get("k")
}

func TestStaticEmbedJS_ContentTypeAndCORP(t *testing.T) {
	jsPath := "../../web/static/embed.js"
	if _, err := os.Stat(jsPath); err != nil {
		t.Skip("web/static/embed.js not present yet (written by the frontend agent)")
	}

	cfg := newTestConfig(t, nil)
	srv, _, _ := newTestServer(t, cfg)

	rec := doReq(srv, http.MethodGet, "/static/embed.js", "127.0.0.1:1234", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /static/embed.js = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/javascript; charset=utf-8" {
		t.Errorf("Content-Type = %q, want %q", ct, "text/javascript; charset=utf-8")
	}
	if corp := rec.Header().Get("Cross-Origin-Resource-Policy"); corp != "cross-origin" {
		t.Errorf("Cross-Origin-Resource-Policy = %q, want %q", corp, "cross-origin")
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "public, max-age=300" {
		t.Errorf("Cache-Control = %q, want %q", cc, "public, max-age=300")
	}
}

func TestV1ServiceGet_IncludesDurations(t *testing.T) {
	cfg := newTestConfig(t, func(c *config.Config) {
		c.Admin.Token = "admin-tok"
		c.Durations = []string{"1h", "3h"}
	})
	srv, _, _ := newTestServer(t, cfg)

	rec := doReq(srv, http.MethodGet, "/api/v1/services/svc1", "127.0.0.1:1234", map[string]string{"Authorization": "Bearer admin-tok"})
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/services/svc1 = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"durations":["1h","3h"]`) {
		t.Errorf("body missing durations: %s", rec.Body.String())
	}
}
