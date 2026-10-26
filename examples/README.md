# hodor examples

- [`docker-compose.yml`](docker-compose.yml) — minimal zero-file setup: no
  hodor.yaml at all, add services from the admin panel.
- [`docker-compose.cloudflared.yml`](docker-compose.cloudflared.yml) — hodor
  in `proxy` mode behind a Cloudflare Tunnel, also zero-file.
- [`traefik-forwardauth/`](traefik-forwardauth/) — hodor in `forwardauth`
  mode as a Traefik middleware, Traefik does the actual proxying.
- [`caddy/`](caddy/) — hodor in `forwardauth` mode via Caddy's
  `forward_auth` directive.
- [`nginx/`](nginx/) — hodor in `forwardauth` mode via nginx's
  `auth_request`, with a 401-based denial.

Each directory has its own `README.md` and a `hodor.yaml` that matches the
proxy config shown, ready to adapt.
