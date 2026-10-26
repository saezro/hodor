<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/logo-dark.svg">
  <img src="docs/assets/logo.svg" width="96" height="96" alt="hodor logo">
</picture>

# hodor

**Hold the door.**

Self-hosted gatekeeper that keeps your homelab closed to the internet — until someone on the LAN opens it.

[![CI](https://img.shields.io/github/actions/workflow/status/saezro/hodor/ci.yml?branch=main&label=CI&logo=github)](https://github.com/saezro/hodor/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/saezro/hodor?label=release&sort=semver)](https://github.com/saezro/hodor/releases)
[![Go Report Card](https://goreportcard.com/badge/github.com/saezro/hodor)](https://goreportcard.com/report/github.com/saezro/hodor)
[![License: MIT](https://img.shields.io/badge/license-MIT-C97A2E.svg)](LICENSE)
[![ghcr.io](https://img.shields.io/badge/ghcr.io-saezro%2Fhodor-1C1B19?logo=docker&logoColor=white)](https://github.com/saezro/hodor/pkgs/container/hodor)

</div>

---

## Why

Homelabs leak. A Jellyfin media server, a Navidrome music library, a family photo gallery — the moment it's reachable from the internet, it's reachable by everyone, all the time, whether anyone's actually using it or not.

hodor sits in front of those services and keeps them **closed by default**. Someone on the LAN or VPN opens a service for a few hours when it's actually needed; it closes itself when the timer runs out. No separate auth system, no account to manage per service, no exposure when nobody's playing.

## Features

- 🚪 **Closed by default** — every published service starts shut; opening it is a deliberate action, not a config you forget.
- ⏱️ **Time-boxed access** — open for 1h / 3h / 6h / 24h (configurable presets), auto-closes on its own.
- 🔁 **Proxy or forwardAuth** — run hodor as the reverse proxy itself, or bolt it onto Traefik, Caddy or nginx as an auth check.
- 📺 **TV-friendly pairing** — a screen with no keyboard goes to `/tv`, shows a PIN, and gets a long-lived pass once someone approves it from the panel.
- 🧩 **Groups** — several services behind one switch ("media" opens Jellyfin *and* Navidrome together).
- 🔒 **Admin panel stays on the LAN** — CIDR-restricted, never exposed through the tunnel.
- 🪶 **Single static binary** — Go, no CGO, practically no dependencies, one `hodor.yaml`.

## How it works

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/assets/how-it-works.svg">
  <img src="docs/assets/how-it-works.svg" alt="internet traffic flows through Cloudflare Tunnel or Traefik into hodor, which stays closed by default; LAN or VPN opens it from the admin panel, a TV pairs via PIN at /tv" width="100%">
</picture>

1. Internet traffic hits your tunnel/proxy, which forwards to hodor.
2. hodor checks whether the service is open. Closed → closed page (or `401`/redirect for forwardAuth). Open → request goes through.
3. Someone on the LAN/VPN opens the admin panel and flips the switch for N hours.
4. A TV or other keyboard-less screen goes to `/tv`, shows a PIN, gets approved once, and keeps a long-lived pass from then on — the service being closed doesn't lock it out.

## Quick start

```
docker run -d --name hodor \
  -p 8080:8080 -p 8081:8081 \
  -v hodor-data:/data \
  ghcr.io/saezro/hodor
```

No config file needed. Open `http://<ip-lan>:8081` → **Settings** tab → add services (the UI is available in English and Spanish, per the `lang` setting). hodor starts closed by default and stays that way until someone on the LAN opens something.

First access asks for the setup token: `docker logs hodor | grep 'setup token'`. It's replaced once you set `admin_token`.

Point your Cloudflare Tunnel (or Traefik/Caddy/nginx) at hodor's public listener (`8080`), keep `8081` on the LAN/VPN only, and you're closed by default. See [`examples/`](examples/) for ready-to-adapt compose files.

### Advanced (optional): `hodor.yaml`

Everything above also works with a hand-written base config for anything you'd rather pin outside the panel (listen addresses, the secret, services pre-provisioned at deploy time...). Startup-time env vars:

| Env var | Overrides |
|---|---|
| `HODOR_CONFIG` | path to the base `hodor.yaml` (default `/data/hodor.yaml`) |
| `HODOR_DATA_DIR` | directory for `state.json`/`secret`/`managed.yaml` when not set explicitly (default `/data`) |
| `HODOR_LISTEN_PUBLIC` / `HODOR_LISTEN_ADMIN` | listener addresses |
| `HODOR_ADMIN_ALLOW_CIDRS` | admin CIDR allowlist, comma-separated — always wins, the anti-lockout valve; set but empty/blank is a validation error |
| `HODOR_ADMIN_TRUSTED_PROXIES` | admin listener's trusted reverse-proxy CIDRs, comma-separated — wins over `hodor.yaml`'s `admin.trusted_proxies`; set but empty/blank is a validation error |
| `HODOR_ADMIN_TRUSTED_HEADER` | admin listener's trusted forwarded-for header name — wins over `hodor.yaml`'s `admin.trusted_header` |
| `HODOR_SECRET` | HMAC secret value, instead of `secret_file` |

```yaml
lang: en
secret_file: /run/secrets/hodor      # generated on first run if missing
state_file: /data/state.json
listen: { public: ":8080", admin: ":8081" }
admin:
  allow_cidrs: [192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 100.64.0.0/10, 127.0.0.0/8]
  public_url: https://media.home.example.com
durations: [1h, 3h, 6h, 24h]
services:
  - name: jellyfin
    title: Jellyfin
    hosts: [jellyfin.example.com]
    mode: proxy
    upstream: http://jellyfin:8096
    group: media
    pass_bypasses_closed: true
  - name: navidrome
    hosts: [navidrome.example.com]
    mode: proxy
    upstream: http://navidrome:4533
    group: media
```

Validate it anytime with `hodor check -c hodor.yaml`.

Ports, the secret and `state_file`/`config_overlay`'s location are not editable from the panel: they're fixed at startup (base file + env), same as above. Everything else (services, durations, api_keys, and the handful of `general` fields: `lang`, `admin_public_url`, `admin_allow_cidrs`, `admin_token`, `admin_trusted_proxies`, `admin_trusted_header`, `public_trusted_proxies`, `public_cookie_secure`, `pass_ttl`, `on_change`) can be set from the admin panel instead. Whatever a base `hodor.yaml` (or an env override, for `admin_allow_cidrs`) already sets there is read-only from the panel (`409` on write).

Panel edits aren't written back into `hodor.yaml`: they live in a separate `config_overlay` file (default `managed.yaml` next to `state_file`), merged on top of the base config at every request. `hodor.yaml` stays hand-owned and is never rewritten. `listen`, `secret_file` and `state_file` only ever come from the base file and are not hot-reloadable; everything else picks up changes immediately via a panel save, `SIGHUP`, or `POST /api/config/reload`.

## API keys

For a custom button or dashboard that opens/closes a service without visiting the panel, mint a scoped key:

```
hodor key new --name jellyfin-button --services jellyfin --actions open,close,status
```

This prints the raw key once and a YAML block to paste under `api_keys` in `hodor.yaml` (only its sha256 hash is stored). Use it against the versioned, LAN-only admin API:

```
curl -H "Authorization: Bearer <key>" https://hodor.lan:8081/api/v1/services/jellyfin
curl -X POST -H "Authorization: Bearer <key>" -d '{"for":"1h"}' https://hodor.lan:8081/api/v1/services/jellyfin/open
```

Add `allow_origins: [https://media.home.example.com]` to the key for CORS from a browser page embedding the button.

## Embeddable button

Want an open/close button on your homepage dashboard instead of the admin panel? Drop in `embed.js` with a scoped key:

```html
<script src="https://hodor.lan/static/embed.js"
        data-service="jellyfin" data-key="hdr_..." data-lang="es" defer></script>
```

No deps, no build step, Shadow DOM, i18n es/en. LAN/VPN only, same as everything else admin-side. Full guide (custom element for multiple buttons, iframe mode, key scoping): [docs/embed.md](docs/embed.md).

## forwardAuth mode

Don't want hodor proxying traffic itself? Point your existing reverse proxy at `GET /auth` on hodor's public listener instead — `200` means pass, a closed service redirects (or `401`s, for nginx) to hodor's own closed page.

**Traefik**

```yaml
labels:
  - traefik.http.middlewares.hodor.forwardauth.address=http://hodor:8080/auth
  - traefik.http.routers.jellyfin.middlewares=hodor
```

**Caddy**

```caddyfile
jellyfin.example.com {
    forward_auth hodor:8080 {
        uri /auth
    }
    reverse_proxy jellyfin:8096
}
```

**nginx**

```nginx
location / {
    auth_request /hodor-auth;
    error_page 401 = @hodor_closed;
    proxy_pass http://jellyfin:8096;
}
location = /hodor-auth {
    internal;
    proxy_pass http://hodor:8080/auth;
}
```

Either way, route `/.hodor/*` through to hodor so the closed page and `/tv` pairing flow are reachable on the real hostname.

## The TV flow

A living-room screen has no keyboard and no browser extensions — so it doesn't log in, it *pairs*:

1. Open `https://<host>/tv` on the screen. It shows a 6-digit PIN (QR code coming in a later release).
2. From the admin panel (or by typing the PIN there), someone approves it.
3. The TV gets a signed, long-lived cookie (`hodor_pass_<service>`, default 30-day TTL) and from then on gets in even while the service is closed to everyone else — that's the whole point of a device pass.
4. Passes are listed per service in the panel and can be revoked individually at any time.

## How it compares

hodor is deliberately narrow: it's a *time-boxed, physically-gated switch*, not a full auth platform.

| | hodor | [Sablier](https://github.com/sablierapp/sablier) | [tinyauth](https://github.com/steveiliop56/tinyauth) | Cloudflare Access | Tailscale Funnel |
|---|---|---|---|---|---|
| Closed-by-default, opened by someone on the LAN | ✅ | ❌ (scales containers on demand, not access-gated) | ❌ (always-on auth) | ❌ (always-on policy) | ❌ (always reachable while funneled) |
| Auto-closes after N hours | ✅ | ➖ (idle-based, not a timer) | ❌ | ➖ (session-based) | ❌ |
| Keyboard-less device pairing (TV, console) | ✅ | ❌ | ❌ | ➖ (service tokens, not PIN pairing) | ❌ |
| Per-user login / SSO | ❌ | ❌ | ✅ | ✅ | ✅ (via Tailscale identity) |
| Scales containers to zero | ❌ | ✅ | ❌ | ❌ | ❌ |
| Needs an external account/service | ❌ | ❌ | ❌ | ✅ (Cloudflare) | ✅ (Tailscale) |
| forwardAuth for Traefik/Caddy/nginx | ✅ | ✅ | ✅ | ➖ (own edge only) | ❌ |

If you need per-user identity and audit logs, pair hodor with Cloudflare Access or Tailscale rather than replacing them — hodor solves "is this even open right now", not "who are you".

## Screenshots

| Admin panel | Closed page | TV pairing |
|---|---|---|
| ![Admin panel with services, switches and durations](docs/assets/screenshot-panel.png) | ![Closed page shown to visitors when a service is shut](docs/assets/screenshot-closed.png) | ![TV pairing screen showing a 6-digit PIN](docs/assets/screenshot-tv.png) |
| Open/close services and manage passes | What visitors see while closed | PIN pairing for keyboard-less devices |

## Security

- Constant-time comparisons for secrets and PINs, HMAC-signed passes, CSRF tokens on every panel POST.
- Admin listener is CIDR-restricted by default (RFC1918 + CGNAT + loopback) and never meant to sit behind the public tunnel.
- Rate limiting on PIN attempts (10 min expiry, 5 attempts), no secrets in logs, security headers on every hodor-served page.
- Found an issue? See [SECURITY.md](SECURITY.md) for how to report it privately.

## Roadmap

- [ ] QR code on `/tv` (currently PIN-only)
- [ ] Prometheus histograms for request latency
- [ ] Multi-admin accounts with per-user audit trail
- [ ] Optional email/push digest of what's currently open

## Contributing

Issues and PRs welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) for the dev setup (`go test ./...`, `golangci-lint run`) and the table-test conventions used across the codebase.

## License

[MIT](LICENSE) — © 2026 saezro

---

<sub>Named after a certain doorkeeper who held the door. Not affiliated with HBO.</sub>
