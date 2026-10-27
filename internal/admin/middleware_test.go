package admin

import (
	"encoding/json"
	"net/http"
	"testing"
)

// headerCSRFToken fetches a CSRF token the same way csrfToken does, but
// authenticating via the SSO header (headers must already carry a
// trusted peer's remoteAddr + the configured auth_header) instead of a
// bearer token: GET /api/csrf doesn't need CSRF itself (only
// POST/PUT/DELETE do), so header auth alone is enough to reach it.
func headerCSRFToken(t *testing.T, srv *Server, remoteAddr string, headers map[string]string) string {
	t.Helper()
	rec := doReq(srv, http.MethodGet, "/api/csrf", remoteAddr, headers)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /api/csrf via header auth = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var resp CSRFResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode csrf response: %v", err)
	}
	return resp.Token
}

// TestCsrfAndAuth_HeaderSSO exercises Server.headerUser/headerAllowed
// through the full csrfAndAuth chain: a trusted reverse proxy's
// Remote-User (+ Remote-Groups) header is an alternative to the admin
// bearer token for /api/* GETs, gated by trusted_proxies (the DIRECT
// peer, not auth.ClientIP) and, when set, allowed_users/allowed_groups.
func TestCsrfAndAuth_HeaderSSO(t *testing.T) {
	const adminYAML = "admin:\n  token: sekret\n  trusted_proxies: [10.0.0.1/32]\n  auth_header: Remote-User\n"

	t.Run("trusted peer with header -> 200", func(t *testing.T) {
		srv, _ := newLiveTestServer(t, adminYAML)
		rec := doReq(srv, http.MethodGet, "/api/services", "10.0.0.1:1234", map[string]string{"Remote-User": "ro"})
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /api/services from trusted peer with Remote-User = %d, want 200: %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("untrusted peer with header -> 401", func(t *testing.T) {
		srv, _ := newLiveTestServer(t, adminYAML)
		// 10.0.0.2 is not in trusted_proxies, but IS inside the default
		// allow_cidrs (10.0.0.0/8), so it reaches csrfAndAuth and fails
		// there (headerUser's direct-peer check), not at cidrCheck.
		rec := doReq(srv, http.MethodGet, "/api/services", "10.0.0.2:1234", map[string]string{"Remote-User": "ro"})
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("GET /api/services from untrusted peer with Remote-User = %d, want 401: %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("no auth_header configured -> 401", func(t *testing.T) {
		srv, _ := newLiveTestServer(t, "admin:\n  token: sekret\n  trusted_proxies: [10.0.0.1/32]\n")
		rec := doReq(srv, http.MethodGet, "/api/services", "10.0.0.1:1234", map[string]string{"Remote-User": "ro"})
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("GET /api/services with Remote-User but no auth_header = %d, want 401: %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("allowed_users: matching user -> 200, other user -> 403", func(t *testing.T) {
		const yaml = "admin:\n  token: sekret\n  trusted_proxies: [10.0.0.1/32]\n  auth_header: Remote-User\n  allowed_users: [ro]\n"
		srv, _ := newLiveTestServer(t, yaml)

		rec := doReq(srv, http.MethodGet, "/api/services", "10.0.0.1:1234", map[string]string{"Remote-User": "ro"})
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /api/services as allowed user ro = %d, want 200: %s", rec.Code, rec.Body.String())
		}

		rec = doReq(srv, http.MethodGet, "/api/services", "10.0.0.1:1234", map[string]string{"Remote-User": "bob"})
		if rec.Code != http.StatusForbidden {
			t.Fatalf("GET /api/services as disallowed user bob = %d, want 403: %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("allowed_groups: matching group -> 200", func(t *testing.T) {
		const yaml = "admin:\n  token: sekret\n  trusted_proxies: [10.0.0.1/32]\n  auth_header: Remote-User\n  allowed_groups: [admins]\n"
		srv, _ := newLiveTestServer(t, yaml)

		rec := doReq(srv, http.MethodGet, "/api/services", "10.0.0.1:1234", map[string]string{"Remote-User": "ro", "Remote-Groups": "x, admins"})
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /api/services with matching Remote-Groups = %d, want 200: %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("header auth on a mutation needs CSRF, bearer still works", func(t *testing.T) {
		srv, _ := newLiveTestServer(t, adminYAML)
		headerCreds := map[string]string{"Remote-User": "ro"}

		rec := doReqBody(srv, http.MethodPut, "/api/config/general", "10.0.0.1:1234", headerCreds, `{}`)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("PUT /api/config/general via header auth without X-CSRF-Token = %d, want 403: %s", rec.Code, rec.Body.String())
		}

		token := headerCSRFToken(t, srv, "10.0.0.1:1234", headerCreds)
		withCSRF := map[string]string{"Remote-User": "ro", "X-CSRF-Token": token}
		rec = doReqBody(srv, http.MethodPut, "/api/config/general", "10.0.0.1:1234", withCSRF, `{}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("PUT /api/config/general via header auth with X-CSRF-Token = %d, want 200: %s", rec.Code, rec.Body.String())
		}

		bearer := map[string]string{"Authorization": "Bearer sekret"}
		rec = doReqBody(srv, http.MethodPut, "/api/config/general", "10.0.0.1:1234", bearer, `{}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("PUT /api/config/general via bearer token (no CSRF needed) = %d, want 200: %s", rec.Code, rec.Body.String())
		}
	})
}

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
