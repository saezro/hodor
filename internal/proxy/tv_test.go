package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/saezro/hodor/internal/pin"
)

// TestHandleTV_OpenServiceForwardsToUpstream covers the geo/location-style
// upstream that has its own /tv page: when svc is already open, GET /tv
// must reach the upstream (not hodor's pairing page), and must not mint a
// pin.Manager entry — otherwise the upstream page's own reload loop would
// come straight back here and create a new PIN forever (the bug this
// fixes).
func TestHandleTV_OpenServiceForwardsToUpstream(t *testing.T) {
	const upstreamTVBody = "upstream-tv-page"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/tv" {
			t.Errorf("upstream got path %q, want /tv", r.URL.Path)
		}
		_, _ = w.Write([]byte(upstreamTVBody))
	}))
	defer upstream.Close()

	cfg := newProxyTestConfig(t, upstream.URL, nil)
	srv, st := newProxyTestServer(t, cfg)
	if err := st.Open("svc1", 0, "test"); err != nil {
		t.Fatalf("Open: %v", err)
	}

	w := httptest.NewRecorder()
	srv.handleTV(w, newTVRequest("198.51.100.80:1234"))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if got := w.Body.String(); got != upstreamTVBody {
		t.Errorf("body = %q, want upstream's %q (hodor must not serve its own pairing page for an open service)", got, upstreamTVBody)
	}
	if n := pendingCountFor(srv.pins, "svc1"); n != 0 {
		t.Errorf("pins pending for svc1 = %d, want 0 (open service must not mint a pairing pin on /tv)", n)
	}
}

// pendingCountFor counts svc's pending pins among pins.Pending().
func pendingCountFor(pins *pin.Manager, svc string) int {
	n := 0
	for _, e := range pins.Pending() {
		if e.Service == svc {
			n++
		}
	}
	return n
}

// TestHandleTV_ClosedServiceStillShowsPinPage is the closed-service
// counterpart: /tv must keep serving hodor's own pairing page (not the
// upstream's), since the device isn't allowed through yet.
func TestHandleTV_ClosedServiceStillShowsPinPage(t *testing.T) {
	const upstreamTVBody = "upstream-tv-page"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(upstreamTVBody))
	}))
	defer upstream.Close()

	cfg := newProxyTestConfig(t, upstream.URL, nil)
	srv, _ := newProxyTestServer(t, cfg)

	w := httptest.NewRecorder()
	srv.handleTV(w, newTVRequest("198.51.100.81:1234"))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if got := w.Body.String(); got == upstreamTVBody {
		t.Errorf("body matched upstream's /tv page; closed service must still get hodor's own pairing page")
	}
	if n := pendingCountFor(srv.pins, "svc1"); n != 1 {
		t.Errorf("pins pending for svc1 = %d, want 1 (closed service must mint a pairing pin on /tv)", n)
	}
}

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
