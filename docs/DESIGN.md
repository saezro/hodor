# hodor — spec v0.1 ("Hold the door.")

Self-hosted gatekeeper: services published to the internet stay CLOSED by default; someone on LAN/VPN opens them for N hours; screens without keyboard (TV) pair with a PIN and get a device pass. Single static Go binary, no CGO, stdlib-first (allowed deps: gopkg.in/yaml.v3 only; everything else stdlib). English code/docs, Spanish+English UI strings (i18n map, `lang` config, default en).

## Listeners
- `public` (default :8080): what the tunnel / reverse proxy hits. Routes by Host header to a service.
- `admin` (default :8081): control panel. MUST only be reachable from LAN/VPN: bind address configurable + `admin.allow_cidrs` (default RFC1918 + 100.64.0.0/10 + loopback). Optional `admin.trusted_proxies` + header for real IP when behind Traefik.
- `/healthz` on both, `/metrics` (Prometheus text, hand-written) on admin.

## Modes (per service)
- `proxy`: hodor reverse-proxies to `upstream` (httputil.ReverseProxy, WebSocket Upgrade + SSE flush-through: FlushInterval -1). Strip hodor cookies before upstream.
- `forwardauth`: endpoint `GET /auth` on public listener for Traefik forwardAuth / Caddy forward_auth / nginx auth_request. Reads X-Forwarded-Host/Uri/Proto. 200 = pass; closed → 302 to closed page served by hodor at `https://<host>/.hodor/closed` (needs proxy to route `/.hodor/*` to hodor; document it) or 401 for nginx (`auth.on_deny: redirect|401`).

## State
- Per service: `{open bool, until time, opened_by string}`. Open for duration (presets from config, default [1h,3h,6h,24h]) or until closed. Auto-close by timer.
- Optional `group`: services sharing a group share one switch (e.g. "games").
- Persisted to `state_file` (JSON, atomic write tmp+rename) so restart keeps state; if expired on load → closed. Default closed.
- Event log ring buffer (last 200) shown in panel; optional webhook `on_change` (POST JSON) — e.g. ntfy/Telegram.

## Access while closed
- Device pass: on the device go to `https://<host>/tv` → shows 6-digit PIN + QR (QR pure-Go, hand-written encoder or vendored minimal one; no external deps — if too big, show only PIN in v0.1 and leave QR as TODO). Admin panel shows pending PINs; admin approves (or types PIN). Device gets cookie `hodor_pass_<svc>` (HMAC-SHA256 signed, HttpOnly, Secure, SameSite=Lax, ttl `pass_ttl` default 30d). PIN expires 10 min, max 5 attempts.
- Passes are per service, listed in panel, revocable (revocation list in state file; pass carries random id).
- Pass works even when service is closed? Config `pass_bypasses_closed: true` (default true — that's the TV use case: TV always works, phones only when open).
- Closed page: nice, themable (title, message, accent color, logo url), shows "Ask someone at home to open it" + optional button linking to admin panel URL (`admin.public_url`, only shown if set).

## Config (`hodor.yaml`, env `HODOR_CONFIG`; secrets via env `HODOR_SECRET` or `secret_file`)
```yaml
lang: es
secret_file: /run/secrets/hodor   # 32+ bytes, used for HMAC; generated on first run if missing (0600)
state_file: /data/state.json
listen: { public: ":8080", admin: ":8081" }
admin:
  allow_cidrs: [192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 100.64.0.0/10, 127.0.0.0/8]
  public_url: https://games.home.example.com
durations: [1h, 3h, 6h, 24h]
services:
  - name: geo
    title: GeoGuessr casero
    hosts: [geo.example.com]
    mode: proxy
    upstream: http://geo:3469
    group: games
    pass_bypasses_closed: true
  - name: cluedo
    hosts: [cluedo.example.com]
    mode: proxy
    upstream: http://cluedo:3465
    group: games
```
Validation on start with clear errors; `hodor check -c hodor.yaml` subcommand.

## CLI
`hodor serve`, `hodor check`, `hodor open <svc|group> [--for 3h]`, `hodor close <svc>`, `hodor status` (CLI talks to admin API).

## Admin API (JSON, same CIDR restriction; optional bearer token `admin.token`)
GET /api/services · POST /api/services/{name}/open {for} · POST /api/services/{name}/close · GET/POST /api/pins · GET/DELETE /api/passes/{id}. Panel = single embedded HTML page (embed.FS), vanilla JS, no build step, dark/light, mobile-first.

## Security
Constant-time compares, CSRF token on panel POSTs, rate limits, no secrets in logs, security headers on hodor pages, structured logs (log/slog).

## Repo layout
cmd/hodor/main.go · internal/{config,state,proxy,auth,pass,pin,admin,web,i18n} · web/ (embedded assets) · examples/{docker-compose.cloudflared.yml, traefik-forwardauth/, caddy/, nginx/} · Dockerfile (multi-stage, distroless static, nonroot) · .goreleaser.yaml · .github/workflows/{ci.yml,release.yml} (go vet, test -race, golangci-lint, ghcr image multi-arch amd64/arm64) · docs/ · README.md · LICENSE (MIT, © 2026 saezro) · CONTRIBUTING.md · SECURITY.md · CHANGELOG.md.

## Tests
Table tests: config validation, state timers (fake clock), HMAC pass sign/verify/revoke, PIN flow, Host routing, CIDR check, WebSocket proxied end-to-end (httptest), forwardauth decisions.

## Phase 2 — scoped API keys, embeddable button, panel config editing (requested 2026-10-25)
Goal: a custom button inside each service (or a home dashboard) opens/closes it without visiting the hodor panel. Still LAN/VPN only: every endpoint stays on the admin listener behind `admin.allow_cidrs`; nothing new on the public listener.

### 2a. Scoped API keys
- `api_keys` (in overlay, see 2c): `{id, name, services: [svc|group…], actions: [open, close, status], allow_origins: [https://geo.lan…], created_at}`. Key = 32 random bytes, shown ONCE on creation; only sha256 stored. Constant-time compare.
- Endpoints (versioned, keep current `/api/*` for the panel): `GET /api/v1/services/{name}` · `POST /api/v1/services/{name}/open {for}` · `POST /api/v1/services/{name}/close`. Auth `Authorization: Bearer <key>`; key must cover service+action, else 403. `admin.token` (global) still works for everything.
- CORS only for bearer requests: `Access-Control-Allow-Origin` echoed iff Origin ∈ key.allow_origins (no `*`), `OPTIONS` preflight, `Vary: Origin`. Bearer requests skip CSRF (already the rule).
- Rate limit per key; events log records key name as `opened_by`.

### 2b. Embeddable button
- `GET /embed.js` (static, embedded): `<script src="https://hodor.lan/embed.js" data-service="geo" data-key="…" defer></script>` renders a small open/close button + countdown into `<hodor-button>` or after the script tag; shadow DOM, dark theme tokens, i18n via `data-lang`.
- `GET /embed/{svc}?k=<key>` iframe alternative; `Content-Security-Policy: frame-ancestors` = key.allow_origins.
- README snippet + docs/embed.md. Note: key is visible in page source to LAN viewers → scope keys narrowly.

### 2c. Panel config editing + hot reload
- Base `hodor.yaml` stays hand-owned, never rewritten. Panel edits go to overlay `config_overlay` (default `<dir of state_file>/managed.yaml`, 0600): services added/edited from panel, durations, api_keys. Merge: overlay service with same `name` replaces base one; base services marked read-only in panel.
- Save = validate merged config → atomic write (tmp+rename) → swap live config (`atomic.Pointer`), rebuild host routing. Invalid → 400 with field errors, nothing changes.
- Reload also on `SIGHUP` and `POST /api/config/reload` (re-reads base + overlay). Listen addresses, secret and state_file are NOT hot-reloadable (log warning, need restart).
- Panel: "Settings" tab — services CRUD, durations, API keys (create shows key once + copy-paste snippet, revoke).

### Tests
Key scope matrix (svc/group × action), CORS allow/deny/preflight, overlay merge, invalid save leaves config untouched, concurrent reload under `-race`, embed.js served with correct headers.

## Phase 3 — zero-file setup (requested 2026-10-26)
Goal: `docker run` with no `hodor.yaml` at all is a fully working install.

- Base config optional: missing file → defaults only, not an error (`Load` logs at info level). 0 services is valid now (panel adds them).
- `dataDir()`: env `HODOR_DATA_DIR`, else `/data` (matches Dockerfile `VOLUME`). Defaults `state_file`/`secret_file`/`config_overlay` (via `state_file`'s dir) under it when unset.
- Env always wins over base file AND overlay, every time a Config is built: `HODOR_LISTEN_PUBLIC`/`HODOR_LISTEN_ADMIN`, `HODOR_ADMIN_ALLOW_CIDRS` (comma-separated; the anti-lockout valve — works even if the panel's own `allow_cidrs` is broken).
- New overlay section `general` (`internal/config/overlay.go` `General`/`GeneralPatch`): `lang, admin_public_url, admin_allow_cidrs, admin_token, public_trusted_proxies, public_cookie_secure, pass_ttl, on_change`. Per-field: base (or env, for `admin_allow_cidrs`) wins if set at all → that field is "locked" (`LockedGeneralFields`, computed off `LoadRaw`'s *unvalidated* base so defaults don't make everything look set); otherwise overlay applies; `Validate`'s defaults/env run last. `admin_trusted_proxies`/`admin_trusted_header` are NOT in the overlay (a spoofed client IP would bypass `allow_cidrs`): yaml or env `HODOR_ADMIN_TRUSTED_PROXIES`/`HODOR_ADMIN_TRUSTED_HEADER` only; PUT with them → 400.
- `PUT /api/config/general` (`internal/admin/config_api.go`): partial patch, nil = untouched. Locked field touched → 409 (`GeneralLockedError`). Anti-lockout: if the resulting `admin.allow_cidrs` would exclude the caller's own IP → 400 "would lock you out" (`config.ErrLockout`), nothing written.
- `GET /api/config.general` (`GeneralView`): effective values + `locked` list + `admin_token_set` bool — the raw token is never serialized either way.
- Dockerfile: `ENV HODOR_CONFIG=/data/hodor.yaml`, `ENV HODOR_DATA_DIR=/data`; `/data` pre-created and chowned to nonroot (65532) in the distroless final stage so it's writable without a host bind-mount.
- `examples/docker-compose.yml`: new minimal file, image only, no `hodor.yaml`. `examples/docker-compose.cloudflared.yml`: dropped the `hodor.yaml` mount and `HODOR_CONFIG` env — also zero-file now.
- README Quick start leads with `docker run` + "open the panel, add services"; the yaml-based setup moved to "Avanzado (opcional)".
- Setup token: random hex, in-memory, printed to `docker logs` and written 0600 to `<data dir>/setup.token` for the CLI, while `admin.token` is unset; a new one on every restart until an `admin_token` is fixed, after which it stops working.
- The 401 on `/api/*` and `/metrics` carries `X-Hodor-Setup: 1` while the setup token is still active, so the panel knows to prompt for it; there is no longer an admin-without-auth mode, and `/metrics` is bearer-gated same as the API.
- `on_change` (`validateOnChange`): only `http`/`https` with a host; `webhook.Notifier`'s client never follows redirects, so a 3xx from the configured endpoint can't retarget the POST.
- Missing `hodor.yaml` → defaults only, accepted (zero-file setup); the Dockerfile's `HODOR_CONFIG=/data/hodor.yaml` is intentional and has no auth impact.
