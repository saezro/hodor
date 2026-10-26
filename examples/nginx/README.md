# nginx + hodor auth_request

hodor runs in `forwardauth` mode behind nginx's `auth_request`. Since
nginx's `auth_request` only understands a 2xx/401/403 verdict (no
redirects), hodor is configured with `auth.on_deny: "401"` and nginx maps
that 401 to an internal redirect that fetches hodor's closed page.

- `nginx.conf` — `auth_request /hodor-auth` + `error_page 401 = @hodor_closed`,
  plus `/.hodor/*` and `/tv` routed through to hodor for the closed page and
  TV pairing flow.
- `hodor.yaml` — matching hodor config (`mode: forwardauth`,
  `auth.on_deny: "401"`).
- `docker-compose.yml` — nginx, hodor and a sample `jellyfin` service.

Bring it up:

```sh
docker compose up -d
```
