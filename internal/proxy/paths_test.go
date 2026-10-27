package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/saezro/hodor/internal/config"
)

func TestHandleDefault_PathRules(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(upstreamBody))
	}))
	defer upstream.Close()

	cfg := newProxyTestConfig(t, upstream.URL, func(c *config.Config) {
		c.Services[0].Paths = []config.PathRule{
			{Path: "/laboratorio", Access: config.AccessDeny},
			{Prefix: "/vendor/", Access: config.AccessPublic},
			{Path: "/mundos", Access: config.AccessGated},
		}
	})
	srv, st := newProxyTestServer(t, cfg)

	t.Run("deny: 404 even with a valid pass", func(t *testing.T) {
		cookie := validPassCookie(t, st, []byte("test-secret"), "svc1")
		req := httptest.NewRequest(http.MethodGet, "/laboratorio", nil)
		req.Host = "svc1.example.com"
		req.Header.Set("Cookie", cookie)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Errorf("deny path = %d, want 404", rec.Code)
		}
	})

	t.Run("public: passes through while service is closed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/vendor/jquery.js", nil)
		req.Host = "svc1.example.com"
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), upstreamBody) {
			t.Errorf("public path while closed = %d, body=%s, want 200 reaching upstream", rec.Code, rec.Body.String())
		}
	})

	t.Run("gated path: closed service without pass shows closed page", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/mundos", nil)
		req.Host = "svc1.example.com"
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), upstreamBody) {
			t.Errorf("gated path while closed = %d, body=%s, want closed page (not upstream)", rec.Code, rec.Body.String())
		}
	})

	t.Run("no rule matches: default_access (unset -> gated) applies, same as before", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.Host = "svc1.example.com"
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), upstreamBody) {
			t.Errorf("unmatched path while closed = %d, body=%s, want closed page (not upstream)", rec.Code, rec.Body.String())
		}
	})
}

func TestHandleDefault_PathRules_DefaultAccessDeny(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(upstreamBody))
	}))
	defer upstream.Close()

	cfg := newProxyTestConfig(t, upstream.URL, func(c *config.Config) {
		c.Services[0].DefaultAccess = config.AccessDeny
		c.Services[0].Paths = []config.PathRule{
			{Path: "/mundos", Access: config.AccessGated},
		}
	})
	srv, st := newProxyTestServer(t, cfg)
	if err := st.Open("svc1", 0, "tester"); err != nil {
		t.Fatalf("Open: %v", err)
	}

	t.Run("allowed path still reaches upstream when open", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/mundos", nil)
		req.Host = "svc1.example.com"
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), upstreamBody) {
			t.Errorf("mundos while open = %d, body=%s, want 200 reaching upstream", rec.Code, rec.Body.String())
		}
	})

	t.Run("default_access deny blocks everything else, even when open", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/anything-else", nil)
		req.Host = "svc1.example.com"
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Errorf("default-denied path while open = %d, want 404", rec.Code)
		}
	})
}

func TestHandleDefault_PathRules_MethodsRestrictMatch(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(upstreamBody))
	}))
	defer upstream.Close()

	cfg := newProxyTestConfig(t, upstream.URL, func(c *config.Config) {
		c.Services[0].Paths = []config.PathRule{
			{Prefix: "/vendor/", Methods: []string{"GET", "HEAD"}, Access: config.AccessPublic},
		}
	})
	srv, _ := newProxyTestServer(t, cfg)

	t.Run("matching method: public applies", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/vendor/x.js", nil)
		req.Host = "svc1.example.com"
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), upstreamBody) {
			t.Errorf("GET /vendor/x.js = %d, want 200 reaching upstream", rec.Code)
		}
	})

	t.Run("non-matching method: rule skipped, falls back to default (gated, closed)", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/vendor/x.js", nil)
		req.Host = "svc1.example.com"
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), upstreamBody) {
			t.Errorf("POST /vendor/x.js = %d, body=%s, want closed page (not upstream)", rec.Code, rec.Body.String())
		}
	})
}
