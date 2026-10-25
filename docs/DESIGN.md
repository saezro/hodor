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
