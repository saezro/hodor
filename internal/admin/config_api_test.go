package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/saezro/hodor/internal/apikey"
	"github.com/saezro/hodor/internal/config"
	"github.com/saezro/hodor/internal/pin"
	"github.com/saezro/hodor/internal/state"
)

// newLiveTestServer builds an admin.Server backed by a real on-disk
// base hodor.yaml (with one base service "svc1") and config_overlay
// file under t.TempDir(), so config_api handlers can actually read and
// write through to disk. It returns the server and the resolved
// overlay path.
func newLiveTestServer(t *testing.T, extraBaseYAML string) (*Server, string) {
	t.Helper()
	dir := t.TempDir()
	overlayPath := filepath.Join(dir, "managed.yaml")
	basePath := filepath.Join(dir, "hodor.yaml")

	data := "state_file: " + filepath.Join(dir, "state.json") + "\n" +
		"config_overlay: " + overlayPath + "\n" +
		"services:\n" +
		"  - name: svc1\n" +
		"    hosts: [svc1.example.com]\n" +
		"    mode: proxy\n" +
		"    upstream: http://127.0.0.1:9001\n" +
		extraBaseYAML
	if err := os.WriteFile(basePath, []byte(data), 0o600); err != nil {
		t.Fatalf("write base: %v", err)
	}

	live, err := config.NewLive(basePath)
	if err != nil {
		t.Fatalf("NewLive: %v", err)
	}
	st, err := state.New(t.TempDir()+"/state.json", []string{"svc1"}, nil)
	if err != nil {
		t.Fatalf("state.New: %v", err)
	}
	pins := pin.New(nil)
	srv, err := New(live, st, pins, []byte("test-secret"), nil)
	if err != nil {
		t.Fatalf("admin.New: %v", err)
	}
	return srv, overlayPath
}

func doReqBody(srv *Server, method, path, remoteAddr string, headers map[string]string, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = remoteAddr
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	return rec
}

func TestConfigAPI_ScopedV1Key_Forbidden(t *testing.T) {
	raw, hashHex, err := apikey.Generate()
	if err != nil {
		t.Fatalf("apikey.Generate: %v", err)
	}
	srv, _ := newLiveTestServer(t, "api_keys:\n  - id: k1\n    name: k\n    hash: \""+hashHex+"\"\n    services: [svc1]\n    actions: [status]\n")
	rec := doReq(srv, http.MethodGet, "/api/config", "127.0.0.1:1234", map[string]string{"Authorization": "Bearer " + raw})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("GET /api/config with scoped v1 key = %d, want 403: %s", rec.Code, rec.Body.String())
	}
}

func TestConfigAPI_AdminToken_GetNoHash(t *testing.T) {
	srv, _ := newLiveTestServer(t, "admin:\n  token: s3cr3t\n")
	rec := doReq(srv, http.MethodGet, "/api/config", "127.0.0.1:1234", map[string]string{"Authorization": "Bearer s3cr3t"})
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/config = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "hash") {
		t.Errorf("GET /api/config response leaks a hash field: %s", rec.Body.String())
	}
}

func TestConfigAPI_ServicePutDelete_BaseConflict(t *testing.T) {
	srv, _ := newLiveTestServer(t, "")
	const remote = "127.0.0.1:1234"
	token := csrfToken(t, srv, remote)
	headers := map[string]string{"X-CSRF-Token": token, "Authorization": "Bearer " + srv.effectiveToken()}

	rec := doReqBody(srv, http.MethodPut, "/api/config/services/svc1", remote, headers, `{"hosts":["x.example.com"],"mode":"proxy","upstream":"http://127.0.0.1:1"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("PUT base service svc1 = %d, want 409: %s", rec.Code, rec.Body.String())
	}

	rec = doReqBody(srv, http.MethodDelete, "/api/config/services/svc1", remote, headers, "")
	if rec.Code != http.StatusConflict {
		t.Fatalf("DELETE base service svc1 = %d, want 409: %s", rec.Code, rec.Body.String())
	}
}

func TestConfigAPI_ServicePut_NewOverlayService_RoutesAndSourced(t *testing.T) {
	srv, _ := newLiveTestServer(t, "")
	const remote = "127.0.0.1:1234"
	token := csrfToken(t, srv, remote)
	headers := map[string]string{"X-CSRF-Token": token, "Authorization": "Bearer " + srv.effectiveToken()}

	rec := doReqBody(srv, http.MethodPut, "/api/config/services/svc2", remote, headers, `{"hosts":["svc2.example.com"],"mode":"proxy","upstream":"http://127.0.0.1:9002"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT new overlay service svc2 = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	rec = doReq(srv, http.MethodGet, "/api/config", remote, bearerHeaders(srv))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/config = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var resp ConfigGetResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	found := false
	for _, s := range resp.Services {
		if s.Name == "svc2" {
			found = true
			if s.Source != "overlay" {
				t.Errorf("svc2 Source = %q, want %q", s.Source, "overlay")
			}
		}
	}
	if !found {
		t.Fatalf("svc2 not present in merged config: %+v", resp.Services)
	}

	// Enrouted: GET /api/services (the state/routing list) carries it too.
	rec = doReq(srv, http.MethodGet, "/api/services", remote, bearerHeaders(srv))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/services = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "svc2") {
		t.Errorf("GET /api/services does not list newly added svc2: %s", rec.Body.String())
	}
}

func TestConfigAPI_ServicePut_InvalidUpstream_400(t *testing.T) {
	srv, _ := newLiveTestServer(t, "")
	const remote = "127.0.0.1:1234"
	token := csrfToken(t, srv, remote)
	headers := map[string]string{"X-CSRF-Token": token, "Authorization": "Bearer " + srv.effectiveToken()}

	rec := doReqBody(srv, http.MethodPut, "/api/config/services/svc2", remote, headers, `{"hosts":["svc2.example.com"],"mode":"proxy","upstream":"not-a-url"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("PUT service with invalid upstream = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	var resp validationErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Errors) == 0 {
		t.Errorf("validation error response has no errors: %s", rec.Body.String())
	}
}

func TestConfigAPI_ServicePut_InvalidName_400(t *testing.T) {
	srv, _ := newLiveTestServer(t, "")
	const remote = "127.0.0.1:1234"
	token := csrfToken(t, srv, remote)
	headers := map[string]string{"X-CSRF-Token": token, "Authorization": "Bearer " + srv.effectiveToken()}

	rec := doReqBody(srv, http.MethodPut, "/api/config/services/bad%20name", remote, headers, `{"hosts":["svc2.example.com"],"mode":"proxy","upstream":"http://127.0.0.1:9002"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("PUT service with invalid name = %d, want 400: %s", rec.Code, rec.Body.String())
	}
}

func TestConfigAPI_KeyCreate_RawOnceAndHashOnDisk(t *testing.T) {
	srv, overlayPath := newLiveTestServer(t, "")
	const remote = "127.0.0.1:1234"
	token := csrfToken(t, srv, remote)
	headers := map[string]string{"X-CSRF-Token": token, "Authorization": "Bearer " + srv.effectiveToken()}

	rec := doReqBody(srv, http.MethodPost, "/api/config/keys", remote, headers, `{"name":"btn","services":["svc1"],"actions":["open"]}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST /api/config/keys = %d, want 201: %s", rec.Code, rec.Body.String())
	}
	var resp ConfigKeyCreateResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Key == "" {
		t.Fatalf("response has no raw key: %+v", resp)
	}

	onDisk, err := os.ReadFile(overlayPath)
	if err != nil {
		t.Fatalf("read overlay: %v", err)
	}
	if strings.Contains(string(onDisk), resp.Key) {
		t.Errorf("overlay on disk contains the raw key, want hash only:\n%s", onDisk)
	}
	if !strings.Contains(string(onDisk), "hash:") {
		t.Errorf("overlay on disk has no hash field:\n%s", onDisk)
	}
}

func TestConfigAPI_KeyDelete_BaseConflict(t *testing.T) {
	srv, _ := newLiveTestServer(t, "api_keys:\n  - id: k1\n    name: k\n    hash: \""+strings.Repeat("a", 64)+"\"\n    services: [svc1]\n    actions: [status]\n")
	const remote = "127.0.0.1:1234"
	token := csrfToken(t, srv, remote)
	headers := map[string]string{"X-CSRF-Token": token, "Authorization": "Bearer " + srv.effectiveToken()}

	rec := doReqBody(srv, http.MethodDelete, "/api/config/keys/k1", remote, headers, "")
	if rec.Code != http.StatusConflict {
		t.Fatalf("DELETE base key k1 = %d, want 409: %s", rec.Code, rec.Body.String())
	}
}

func TestConfigAPI_Reload_OK(t *testing.T) {
	srv, _ := newLiveTestServer(t, "")
	const remote = "127.0.0.1:1234"
	token := csrfToken(t, srv, remote)
	headers := map[string]string{"X-CSRF-Token": token, "Authorization": "Bearer " + srv.effectiveToken()}

	rec := doReqBody(srv, http.MethodPost, "/api/config/reload", remote, headers, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /api/config/reload = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var resp ConfigReloadResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !resp.OK {
		t.Errorf("reload response OK = false, want true: %+v", resp)
	}
}

func TestConfigAPI_GeneralPut_OKAndNotExposed(t *testing.T) {
	srv, overlayPath := newLiveTestServer(t, "")
	const remote = "127.0.0.1:1234"
	token := csrfToken(t, srv, remote)
	headers := map[string]string{"X-CSRF-Token": token, "Authorization": "Bearer " + srv.effectiveToken()}

	rec := doReqBody(srv, http.MethodPut, "/api/config/general", remote, headers, `{"admin_token":"newtok","pass_ttl":"48h"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT /api/config/general = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var view GeneralView
	if err := json.Unmarshal(rec.Body.Bytes(), &view); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !view.AdminTokenSet {
		t.Errorf("GeneralView.AdminTokenSet = false, want true after setting admin_token")
	}
	if view.PassTTL != "48h" {
		t.Errorf("GeneralView.PassTTL = %q, want %q", view.PassTTL, "48h")
	}
	if strings.Contains(rec.Body.String(), "newtok") {
		t.Errorf("PUT /api/config/general response leaks the raw token: %s", rec.Body.String())
	}

	onDisk, err := os.ReadFile(overlayPath)
	if err != nil {
		t.Fatalf("read overlay: %v", err)
	}
	if !strings.Contains(string(onDisk), "newtok") {
		t.Errorf("overlay on disk does not contain the saved admin_token:\n%s", onDisk)
	}

	// GET /api/config must not expose it either.
	rec = doReq(srv, http.MethodGet, "/api/config", remote, bearerHeaders(srv))
	if strings.Contains(rec.Body.String(), "newtok") {
		t.Errorf("GET /api/config response leaks the raw token: %s", rec.Body.String())
	}
}

func TestConfigAPI_GeneralPut_BaseFieldLocked409(t *testing.T) {
	srv, _ := newLiveTestServer(t, "pass_ttl: 12h\n")
	const remote = "127.0.0.1:1234"
	token := csrfToken(t, srv, remote)
	headers := map[string]string{"X-CSRF-Token": token, "Authorization": "Bearer " + srv.effectiveToken()}

	rec := doReqBody(srv, http.MethodPut, "/api/config/general", remote, headers, `{"pass_ttl":"24h"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("PUT /api/config/general on base-locked field = %d, want 409: %s", rec.Code, rec.Body.String())
	}

	rec = doReq(srv, http.MethodGet, "/api/config", remote, bearerHeaders(srv))
	var resp ConfigGetResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	found := false
	for _, f := range resp.General.Locked {
		if f == "pass_ttl" {
			found = true
		}
	}
	if !found {
		t.Errorf("GeneralView.Locked = %+v, want pass_ttl locked", resp.General.Locked)
	}
}

func TestConfigAPI_GeneralPut_Lockout400(t *testing.T) {
	srv, _ := newLiveTestServer(t, "")
	const remote = "127.0.0.1:1234"
	token := csrfToken(t, srv, remote)
	headers := map[string]string{"X-CSRF-Token": token, "Authorization": "Bearer " + srv.effectiveToken()}

	// Setting allow_cidrs to a range that excludes the caller's own IP
	// (127.0.0.1) must be rejected before anything is written.
	rec := doReqBody(srv, http.MethodPut, "/api/config/general", remote, headers, `{"admin_allow_cidrs":["10.0.0.0/8"]}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("PUT /api/config/general locking caller out = %d, want 400: %s", rec.Code, rec.Body.String())
	}

	rec = doReq(srv, http.MethodGet, "/api/config", remote, bearerHeaders(srv))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/config after rejected lockout = %d, want 200 (caller still allowed): %s", rec.Code, rec.Body.String())
	}
}

// TestConfigAPI_GeneralPut_UnknownField_RejectedAndNotWritten: the
// request body naming a non-panel-editable field (admin_trusted_proxies
// - see General's doc comment in internal/config/overlay.go) must be
// rejected by DisallowUnknownFields with 400, and nothing written to
// the overlay.
func TestConfigAPI_GeneralPut_UnknownField_RejectedAndNotWritten(t *testing.T) {
	srv, overlayPath := newLiveTestServer(t, "")
	const remote = "127.0.0.1:1234"
	token := csrfToken(t, srv, remote)
	headers := map[string]string{"X-CSRF-Token": token, "Authorization": "Bearer " + srv.effectiveToken()}

	rec := doReqBody(srv, http.MethodPut, "/api/config/general", remote, headers, `{"admin_trusted_proxies":["0.0.0.0/0"]}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("PUT /api/config/general with admin_trusted_proxies = %d, want 400: %s", rec.Code, rec.Body.String())
	}

	if _, err := os.Stat(overlayPath); err == nil {
		onDisk, readErr := os.ReadFile(overlayPath)
		if readErr != nil {
			t.Fatalf("read overlay: %v", readErr)
		}
		if strings.Contains(string(onDisk), "trusted_proxies") {
			t.Errorf("overlay was written despite rejected request:\n%s", onDisk)
		}
	} else if !os.IsNotExist(err) {
		t.Fatalf("stat overlay: %v", err)
	}
}

func TestConfigAPI_GeneralPut_HotSwap_AllowCIDRsTakeEffectImmediately(t *testing.T) {
	srv, _ := newLiveTestServer(t, "")
	const remote = "127.0.0.1:1234"
	const otherRemote = "203.0.113.5:1234"
	token := csrfToken(t, srv, remote)
	headers := map[string]string{"X-CSRF-Token": token, "Authorization": "Bearer " + srv.effectiveToken()}

	// otherRemote starts out allowed (default CIDRs include public space? no -
	// defaults are private ranges only, so confirm it's denied beforehand).
	rec := doReq(srv, http.MethodGet, "/healthz", otherRemote, nil)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("GET /healthz from %s before change = %d, want 403", otherRemote, rec.Code)
	}

	// Widen allow_cidrs to include otherRemote, keeping the current caller in too.
	rec = doReqBody(srv, http.MethodPut, "/api/config/general", remote, headers, `{"admin_allow_cidrs":["127.0.0.1/32","203.0.113.0/24"]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT /api/config/general = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	// No restart: otherRemote must now be let in by the very next request.
	rec = doReq(srv, http.MethodGet, "/healthz", otherRemote, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /healthz from %s after hot-swap = %d, want 200: %s", otherRemote, rec.Code, rec.Body.String())
	}

	// And the old caller's IP is no longer implicitly trusted by the
	// defaults alone - it's only in because we explicitly kept it.
	rec = doReq(srv, http.MethodGet, "/healthz", remote, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /healthz from %s after hot-swap = %d, want 200 (still in the new list): %s", remote, rec.Code, rec.Body.String())
	}
}

func TestConfigAPI_DurationsPut_Invalid(t *testing.T) {
	srv, _ := newLiveTestServer(t, "")
	const remote = "127.0.0.1:1234"
	token := csrfToken(t, srv, remote)
	headers := map[string]string{"X-CSRF-Token": token, "Authorization": "Bearer " + srv.effectiveToken()}

	rec := doReqBody(srv, http.MethodPut, "/api/config/durations", remote, headers, `{"durations":["not-a-duration"]}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("PUT invalid durations = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	var resp validationErrorResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Errors) == 0 {
		t.Errorf("validation error response has no errors: %s", rec.Body.String())
	}
}
