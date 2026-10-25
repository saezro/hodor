package proxy

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/saezro/hodor/internal/config"
	"github.com/saezro/hodor/internal/pass"
	"github.com/saezro/hodor/internal/pin"
	"github.com/saezro/hodor/internal/state"
)

const upstreamBody = "upstream-ok"

// newProxyTestConfig builds a minimal, valid Config whose single service
// "svc1" (host "svc1.example.com") proxies to upstreamURL. mutate (if
// non-nil) is applied before Validate fills in defaults/parsed CIDRs.
func newProxyTestConfig(t *testing.T, upstreamURL string, mutate func(*config.Config)) *config.Config {
	t.Helper()
	cfg := &config.Config{
		Services: []config.Service{
			{Name: "svc1", Title: "Svc1", Hosts: []string{"svc1.example.com"}, Mode: config.ModeProxy, Upstream: upstreamURL},
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

// newProxyTestServer builds a proxy.Server and its backing state store
// (in t.TempDir()) for cfg.
func newProxyTestServer(t *testing.T, cfg *config.Config) (*Server, *state.Store) {
	t.Helper()
	var names []string
	for i := range cfg.Services {
		names = append(names, stateKey(&cfg.Services[i]))
	}
	st, err := state.New(t.TempDir()+"/state.json", names, nil)
	if err != nil {
		t.Fatalf("state.New: %v", err)
	}
	srv, err := New(config.NewLiveFrom(cfg), st, pin.New(nil), []byte("test-secret"), nil)
	if err != nil {
		t.Fatalf("proxy.New: %v", err)
	}
	return srv, st
}

func TestHandleDefault_UnknownHost(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(upstreamBody))
	}))
	defer upstream.Close()

	cfg := newProxyTestConfig(t, upstream.URL, nil)
	srv, _ := newProxyTestServer(t, cfg)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "nope.example.com"
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Errorf("unknown host = %d, want 404", rec.Code)
	}
}

func TestHandleDefault_ClosedThenOpen(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(upstreamBody))
	}))
	defer upstream.Close()

	cfg := newProxyTestConfig(t, upstream.URL, nil)
	srv, st := newProxyTestServer(t, cfg)

	// Closed (default): serves the closed page, never reaches upstream.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "svc1.example.com"
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("closed service = %d, want 200 (closed page)", rec.Code)
	}
	if strings.Contains(rec.Body.String(), upstreamBody) {
		t.Errorf("closed service response reached upstream: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Svc1") {
		t.Errorf("closed page missing service title, body=%s", rec.Body.String())
	}

	// Open: request is proxied through to upstream.
	if err := st.Open("svc1", 0, "tester"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "svc1.example.com"
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("open service = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), upstreamBody) {
		t.Errorf("open service did not reach upstream, body=%s", rec.Body.String())
	}
}

func TestHandleDefault_StripsHodorCookiesBeforeUpstream(t *testing.T) {
	var sawCookie string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawCookie = r.Header.Get("Cookie")
		_, _ = w.Write([]byte(upstreamBody))
	}))
	defer upstream.Close()

	cfg := newProxyTestConfig(t, upstream.URL, nil)
	srv, st := newProxyTestServer(t, cfg)
	if err := st.Open("svc1", 0, "tester"); err != nil {
		t.Fatalf("Open: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Host = "svc1.example.com"
	req.Header.Set("Cookie", "hodor_pass_svc1=secrettoken; other=keepme")
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if strings.Contains(sawCookie, "hodor_") {
		t.Errorf("upstream saw hodor_* cookie: %q", sawCookie)
	}
	if !strings.Contains(sawCookie, "other=keepme") {
		t.Errorf("upstream lost non-hodor cookie: %q", sawCookie)
	}
}

// wsEchoHandler performs a minimal manual WebSocket-style upgrade (via
// Hijack, no external library) and echoes one line back prefixed with
// "echo:", to exercise httputil.ReverseProxy's raw-tunnel Upgrade
// handling end-to-end through the proxy.
func wsEchoHandler(w http.ResponseWriter, _ *http.Request) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "no hijack", http.StatusInternalServerError)
		return
	}
	conn, buf, err := hj.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()

	_, _ = conn.Write([]byte("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n"))
	line, err := buf.ReadString('\n')
	if err != nil {
		return
	}
	_, _ = conn.Write([]byte("echo:" + line))
}

func TestWebSocket_EndToEndThroughProxy(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(wsEchoHandler))
	defer upstream.Close()

	cfg := newProxyTestConfig(t, upstream.URL, nil)
	srv, st := newProxyTestServer(t, cfg)
	if err := st.Open("svc1", 0, "tester"); err != nil {
		t.Fatalf("Open: %v", err)
	}

	// The proxy itself must be a real listener: Hijack-based tunneling
	// needs an actual TCP connection, not an httptest.ResponseRecorder.
	proxyTS := httptest.NewServer(srv)
	defer proxyTS.Close()

	conn, err := net.DialTimeout("tcp", proxyTS.Listener.Addr().String(), 2*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	req := "GET / HTTP/1.1\r\n" +
		"Host: svc1.example.com\r\n" +
		"Connection: Upgrade\r\n" +
		"Upgrade: websocket\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write handshake: %v", err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatalf("read handshake response: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("handshake status = %d, want 101", resp.StatusCode)
	}

	if _, err := conn.Write([]byte("hello\n")); err != nil {
		t.Fatalf("write tunneled payload: %v", err)
	}
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read tunneled payload: %v", err)
	}
	if line != "echo:hello\n" {
		t.Errorf("tunneled echo = %q, want %q", line, "echo:hello\n")
	}
}

// validPassCookie builds a signed pass cookie for service that the state
// store also knows about (so hasValidPass succeeds), returning the
// Cookie header value.
func validPassCookie(t *testing.T, st *state.Store, secret []byte, service string) string {
	t.Helper()
	id, err := pass.NewID()
	if err != nil {
		t.Fatalf("pass.NewID: %v", err)
	}
	if err := st.AddPass(state.Pass{ID: id, Service: service, Label: "test"}); err != nil {
		t.Fatalf("AddPass: %v", err)
	}
	token := pass.Issue(secret, id, service, time.Now().Add(time.Hour))
	return fmt.Sprintf("%s=%s", pass.CookieName(service), token)
}
