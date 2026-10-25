# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `proxy` mode: reverse-proxies to a service's `upstream` (WebSocket upgrade
  and SSE flush-through supported), stripping hodor cookies before
  forwarding.
- `forwardauth` mode: `GET /auth` endpoint on the public listener for
  Traefik `forwardAuth`, Caddy `forward_auth` and nginx `auth_request`
  (`auth.on_deny: redirect|401`).
- Host-based routing to services via `hosts`.
- Time-boxed open/close per service with configurable duration presets
  (default `1h, 3h, 6h, 24h`), auto-close on expiry, state persisted to
  `state_file` (atomic JSON write).
- Service `group`: several services sharing a single open/close switch.
- Device pass flow: `/tv` PIN pairing, HMAC-signed `hodor_pass_<svc>`
  cookie, configurable `pass_ttl` (default 30 days), per-service
  `pass_bypasses_closed`.
- PIN expiry (10 min) and max attempt limit (5).
- Per-service pass listing and revocation.
- Themable closed page (`message`, `accent_color`, `logo_url`,
  `admin.public_url` link).
- Admin listener (default `:8081`) restricted by `admin.allow_cidrs`
  (default RFC1918 + CGNAT + loopback), with optional `admin.trusted_proxies`
  / `admin.trusted_header` for real-IP resolution behind a reverse proxy.
- Admin JSON API: list/open/close services, list/create PINs,
  list/delete passes. Optional bearer token via `admin.token`.
- Embedded single-page admin panel (vanilla JS, no build step, dark/light,
  mobile-first).
- `/healthz` on both listeners, `/metrics` (hand-written Prometheus text
  exposition) on the admin listener.
- Event log ring buffer (last 200 entries) and optional `on_change` webhook.
- CLI: `hodor serve`, `hodor check`, `hodor open <svc|group> [--for 3h]`,
  `hodor close <svc>`, `hodor status`.
- Config validation with descriptive errors on startup.
- i18n: English and Spanish UI strings, `lang` config (default `en`).
- Security: constant-time comparisons, CSRF tokens on panel POSTs, PIN
  rate limiting, no secrets in logs, security headers on hodor-served
  pages, structured logging via `log/slog`.
- Multi-stage Dockerfile (distroless static, nonroot) and multi-arch
  `ghcr.io/saezro/hodor` images (linux/amd64, linux/arm64).
- Example deployments: Cloudflare Tunnel, Traefik forwardAuth, Caddy
  `forward_auth`, nginx `auth_request`.

[Unreleased]: https://github.com/saezro/hodor/compare/main...HEAD
