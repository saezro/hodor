package admin

import (
	"net/http"
	"testing"
)

// TestCsrfAndAuth_SetupTokenThenLive exercises the zero-file/no-admin.token
// path end to end: while Admin.Token is empty, only the in-memory setup
// token is a valid bearer (and the response carries X-Hodor-Setup so the
// panel can show the setup prompt); once admin.token is configured (live),
// the setup token stops working and the configured admin.token is the only
// valid bearer - see Server.effectiveToken/checkBearer.
func TestCsrfAndAuth_SetupTokenThenLive(t *testing.T) {
	srv, _ := newLiveTestServer(t, "")
	const remote = "127.0.0.1:1234"

	// No Admin.Token configured yet: no bearer at all -> 401 with the
	// setup-mode hint header.
	rec := doReq(srv, http.MethodGet, "/api/services", remote, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("GET /api/services without bearer (no admin.token) = %d, want 401: %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("X-Hodor-Setup") != "1" {
		t.Fatalf("GET /api/services without bearer: X-Hodor-Setup = %q, want %q", rec.Header().Get("X-Hodor-Setup"), "1")
	}

	// The setup token is accepted as the effective bearer.
	setupTok := srv.setupToken
	rec = doReq(srv, http.MethodGet, "/api/services", remote, map[string]string{"Authorization": "Bearer " + setupTok})
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/services with setup token = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	// Fix admin.token via the live config (as PUT /api/config/general
	// would do), simulating the "setup complete" transition.
	token := csrfToken(t, srv, remote)
	headers := map[string]string{"X-CSRF-Token": token, "Authorization": "Bearer " + setupTok}
	rec = doReqBody(srv, http.MethodPut, "/api/config/general", remote, headers, `{"admin_token":"live-tok"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PUT /api/config/general admin_token = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	// The now-stale setup token no longer works, and doesn't carry the
	// setup hint (admin.token is configured, so this is a plain 401).
	rec = doReq(srv, http.MethodGet, "/api/services", remote, map[string]string{"Authorization": "Bearer " + setupTok})
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("GET /api/services with stale setup token (admin.token now set) = %d, want 401: %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("X-Hodor-Setup") != "" {
		t.Errorf("GET /api/services with stale setup token: X-Hodor-Setup = %q, want empty", rec.Header().Get("X-Hodor-Setup"))
	}

	// Admin.Token is the new effective bearer.
	rec = doReq(srv, http.MethodGet, "/api/services", remote, map[string]string{"Authorization": "Bearer live-tok"})
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/services with admin.token = %d, want 200: %s", rec.Code, rec.Body.String())
	}
}
