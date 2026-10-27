package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/saezro/hodor/internal/config"
)

func TestForwardAuth_PathRules(t *testing.T) {
	cfg := newForwardAuthConfig(t, func(c *config.Config) {
		c.Services[0].Paths = []config.PathRule{
			{Path: "/laboratorio", Access: config.AccessDeny},
			{Prefix: "/vendor/", Access: config.AccessPublic},
		}
		// X-Forwarded-Uri/Method are only honored from a trusted proxy,
		// same boundary as X-Forwarded-Host/Proto (see handleForwardAuth).
		c.Public.TrustedProxies = []string{"10.0.0.0/8"}
	})
	srv, st := newProxyTestServer(t, cfg)

	t.Run("deny: 404 even with a valid pass", func(t *testing.T) {
		cookie := validPassCookie(t, st, []byte("test-secret"), "fa1")
		req := httptest.NewRequest(http.MethodGet, "/auth", nil)
		req.Host = "fa1.example.com"
		req.RemoteAddr = "10.0.0.5:1234"
		req.Header.Set("Cookie", cookie)
		req.Header.Set("X-Forwarded-Uri", "/laboratorio")
		req.Header.Set("X-Forwarded-Method", "GET")
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Errorf("deny path = %d, want 404", rec.Code)
		}
	})

	t.Run("public: 200 while service is closed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/auth", nil)
		req.Host = "fa1.example.com"
		req.RemoteAddr = "10.0.0.5:1234"
		req.Header.Set("X-Forwarded-Uri", "/vendor/x.js")
		req.Header.Set("X-Forwarded-Method", "GET")
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("public path while closed = %d, want 200", rec.Code)
		}
	})

	t.Run("no rule matches: gated (closed, no pass) redirects as before", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/auth", nil)
		req.Host = "fa1.example.com"
		req.RemoteAddr = "10.0.0.5:1234"
		req.Header.Set("X-Forwarded-Uri", "/anything-else")
		req.Header.Set("X-Forwarded-Method", "GET")
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		if rec.Code != http.StatusFound {
			t.Errorf("unmatched path while closed = %d, want 302", rec.Code)
		}
	})

	t.Run("X-Forwarded-Uri/Method ignored when remote is untrusted", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/auth", nil)
		req.Host = "fa1.example.com"
		req.Header.Set("X-Forwarded-Uri", "/vendor/x.js") // would be public if honored
		req.RemoteAddr = "8.8.8.8:1234"                   // not in Public.TrustedProxies (unset -> none trusted)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		if rec.Code != http.StatusFound {
			t.Errorf("untrusted XForwardedUri = %d, want 302 (header must be ignored)", rec.Code)
		}
	})
}
