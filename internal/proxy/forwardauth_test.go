package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/saezro/hodor/internal/config"
)

// newForwardAuthConfig builds a Config with one forwardauth-mode service
// "fa1" (host "fa1.example.com"). No upstream is needed: hodor itself
// never proxies forwardauth services, it only answers GET /auth.
func newForwardAuthConfig(t *testing.T, mutate func(*config.Config)) *config.Config {
	t.Helper()
	cfg := &config.Config{
		Services: []config.Service{
			{
				Name:  "fa1",
				Title: "FA1",
				Hosts: []string{"fa1.example.com"},
				Mode:  config.ModeForwardAuth,
			},
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

func TestForwardAuth_OpenAllows200(t *testing.T) {
	cfg := newForwardAuthConfig(t, nil)
	srv, st := newProxyTestServer(t, cfg)
	if err := st.Open("fa1", 0, "tester"); err != nil {
		t.Fatalf("Open: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/auth", nil)
	req.Host = "fa1.example.com"
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("open service /auth = %d, want 200", rec.Code)
	}
}

func TestForwardAuth_ClosedDefaultRedirects302(t *testing.T) {
	cfg := newForwardAuthConfig(t, nil) // Auth.OnDeny defaults to "redirect"
	srv, _ := newProxyTestServer(t, cfg)

	req := httptest.NewRequest(http.MethodGet, "/auth", nil)
	req.Host = "fa1.example.com"
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("closed service /auth = %d, want 302", rec.Code)
	}
	loc := rec.Header().Get("Location")
	want := "http://fa1.example.com/.hodor/closed"
	if loc != want {
		t.Errorf("Location = %q, want %q", loc, want)
	}
}

func TestForwardAuth_ClosedOnDeny401(t *testing.T) {
	cfg := newForwardAuthConfig(t, func(c *config.Config) {
		c.Services[0].Auth.OnDeny = config.OnDeny401
	})
	srv, _ := newProxyTestServer(t, cfg)

	req := httptest.NewRequest(http.MethodGet, "/auth", nil)
	req.Host = "fa1.example.com"
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Errorf("closed service (on_deny=401) /auth = %d, want 401", rec.Code)
	}
}

func TestForwardAuth_PassBypassesClosed(t *testing.T) {
	secret := []byte("test-secret")

	t.Run("bypass enabled: valid pass allows closed service", func(t *testing.T) {
		cfg := newForwardAuthConfig(t, func(c *config.Config) {
			b := true
			c.Services[0].PassBypassesClosed = &b
		})
		srv, st := newProxyTestServer(t, cfg)

		cookie := validPassCookie(t, st, secret, "fa1")
		req := httptest.NewRequest(http.MethodGet, "/auth", nil)
		req.Host = "fa1.example.com"
		req.Header.Set("Cookie", cookie)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("closed service with valid pass (bypass=true) = %d, want 200", rec.Code)
		}
	})

	t.Run("bypass disabled: valid pass does not help", func(t *testing.T) {
		cfg := newForwardAuthConfig(t, func(c *config.Config) {
			b := false
			c.Services[0].PassBypassesClosed = &b
		})
		srv, st := newProxyTestServer(t, cfg)

		cookie := validPassCookie(t, st, secret, "fa1")
		req := httptest.NewRequest(http.MethodGet, "/auth", nil)
		req.Host = "fa1.example.com"
		req.Header.Set("Cookie", cookie)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusFound {
			t.Errorf("closed service with valid pass (bypass=false) = %d, want 302 (pass ignored)", rec.Code)
		}
	})
}

func TestForwardAuth_XForwardedHostIgnoredWhenUntrusted(t *testing.T) {
	cfg := newForwardAuthConfig(t, func(c *config.Config) {
		c.Services = append(c.Services, config.Service{
			Name:  "other",
			Title: "Other",
			Hosts: []string{"other.example.com"},
			Mode:  config.ModeForwardAuth,
		})
		c.Public.TrustedProxies = []string{"10.0.0.0/8"}
	})
	srv, st := newProxyTestServer(t, cfg)
	if err := st.Open("fa1", 0, "tester"); err != nil {
		t.Fatalf("Open: %v", err)
	}

	t.Run("untrusted remote: header ignored, routes by real Host", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/auth", nil)
		req.Host = "fa1.example.com"
		req.Header.Set("X-Forwarded-Host", "other.example.com")
		req.RemoteAddr = "8.8.8.8:1234"
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		// fa1 is open, so if the header were honored (routing to "other",
		// which is closed) this would redirect instead of 200.
		if rec.Code != http.StatusOK {
			t.Errorf("untrusted XFH = %d, want 200 (header must be ignored, fa1 is open)", rec.Code)
		}
	})

	t.Run("trusted remote: header honored, routes by X-Forwarded-Host", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/auth", nil)
		req.Host = "fa1.example.com"
		req.Header.Set("X-Forwarded-Host", "other.example.com")
		req.RemoteAddr = "10.0.0.5:1234"
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		// "other" is closed (default on_deny redirect), so a trusted
		// X-Forwarded-Host must steer this to 302, not fa1's 200.
		if rec.Code != http.StatusFound {
			t.Errorf("trusted XFH = %d, want 302 (header honored, routes to closed 'other')", rec.Code)
		}
	})
}
