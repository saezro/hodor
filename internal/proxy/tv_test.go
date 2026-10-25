package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// newTVRequest builds a GET /tv request for svc1.example.com from
// remoteAddr (host:port, as http.Server would set it).
func newTVRequest(remoteAddr string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "http://svc1.example.com/tv", nil)
	r.RemoteAddr = remoteAddr
	return r
}

func TestHandleTV_RateLimitsPerClientIP(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	defer upstream.Close()
	cfg := newProxyTestConfig(t, upstream.URL, nil)
	srv, _ := newProxyTestServer(t, cfg)

	// Unique IP for this test so the shared, package-level limiter isn't
	// polluted by other tests' requests.
	const ip = "198.51.100.77"

	for i := 0; i < tvPinLimitCount; i++ {
		w := httptest.NewRecorder()
		srv.handleTV(w, newTVRequest(ip+":1234"))
		if w.Code != http.StatusOK {
			t.Fatalf("request %d: status = %d, want 200", i, w.Code)
		}
	}

	w := httptest.NewRecorder()
	srv.handleTV(w, newTVRequest(ip+":9999"))
	if w.Code != http.StatusTooManyRequests {
		t.Errorf("request past limit: status = %d, want 429", w.Code)
	}
}

func TestHandleTV_RateLimit_IndependentPerClientIP(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {}))
	defer upstream.Close()
	cfg := newProxyTestConfig(t, upstream.URL, nil)
	srv, _ := newProxyTestServer(t, cfg)

	const ipA = "198.51.100.78"
	const ipB = "198.51.100.79"

	for i := 0; i < tvPinLimitCount; i++ {
		w := httptest.NewRecorder()
		srv.handleTV(w, newTVRequest(ipA+":1000"))
		if w.Code != http.StatusOK {
			t.Fatalf("ipA request %d: status = %d, want 200", i, w.Code)
		}
	}
	w := httptest.NewRecorder()
	srv.handleTV(w, newTVRequest(ipA+":1001"))
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("ipA past limit: status = %d, want 429", w.Code)
	}

	// A different client IP must not be affected by ipA's limit.
	w = httptest.NewRecorder()
	srv.handleTV(w, newTVRequest(ipB+":1000"))
	if w.Code != http.StatusOK {
		t.Errorf("ipB first request: status = %d, want 200 (independent of ipA's limit)", w.Code)
	}
}
