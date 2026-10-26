# Caddy + hodor forward_auth

hodor runs in `forwardauth` mode behind Caddy's native `forward_auth`
directive. Caddy does the actual reverse-proxying to `jellyfin`.

- `Caddyfile` — `forward_auth` pointed at hodor's `/auth`, plus routes for
  `/.hodor/*` and `/tv` so the closed page and TV pairing work on the real
  hostname.
- `hodor.yaml` — matching hodor config (`mode: forwardauth`,
  `auth.on_deny: redirect`).
- `docker-compose.yml` — Caddy, hodor and a sample `jellyfin` service.

Bring it up:

```sh
docker compose up -d
```
