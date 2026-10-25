# Traefik + hodor forwardAuth

hodor runs in `forwardauth` mode: Traefik proxies traffic itself and asks
hodor's `GET /auth` endpoint whether a request should pass.

- `docker-compose.yml` — Traefik, hodor and a sample `geo` service wired
  together with the `forwardauth` middleware.
- `hodor.yaml` — matching hodor config (`mode: forwardauth`,
  `auth.on_deny: redirect`).

The `hodor-internal` router routes `/.hodor/*` and `/tv` on the public
hostname through to hodor itself, so the closed page and TV pairing flow
work on `geo.example.com` even though Traefik is the one proxying.

Bring it up:

```sh
docker compose up -d
```

Then open the admin panel on the LAN (`http://<host>:8081`) to open `geo`
for a few hours.
