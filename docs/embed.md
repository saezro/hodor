# Embeddable button

Drop a small open/close button for one service into any page on your LAN/VPN
— a homepage dashboard, the service's own landing page, a wiki. It talks
directly to hodor's admin API with a scoped key; nobody has to visit the
hodor panel.

> Everything here only works from LAN/VPN: the button calls the **admin**
> listener (`admin.allow_cidrs`), never the public one. There is nothing new
> on the public listener.

## 1. Create a scoped key

```
hodor key new --name geo-btn --services geo --actions open,close,status
```

This prints the raw key **once** — copy it now, only its sha256 is stored —
and a YAML block to paste under `api_keys` in `hodor.yaml`:

```yaml
api_keys:
  - id: 4f9a...
    name: geo-btn
    services: [geo]
    actions: [open, close, status]
    allow_origins: [https://dashboard.home.example.com]
    created_at: 2026-10-25T12:00:00Z
```

- `services` can list several service names or a `group`.
- `allow_origins` is required for the `<script>`/custom-element modes (CORS
  for the bearer request) — add every origin the button will be embedded
  on. The iframe mode (`/embed/{svc}`) uses it for `Content-Security-Policy:
  frame-ancestors` instead.
- Keep the scope minimal: a key only needs `status` if the button is
  read-only, `open,close` only on the services it actually controls.

## 2. Embed it

### `<script>` tag (simplest)

```html
<script src="https://hodor.lan/static/embed.js"
        data-service="geo"
        data-key="hdr_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        data-lang="es"
        defer></script>
```

Renders one button right after the script tag.

### Custom element (several buttons, one script load)

```html
<script src="https://hodor.lan/static/embed.js" defer></script>

<hodor-button data-service="geo" data-key="hdr_..." data-lang="es"></hodor-button>
<hodor-button data-service="cluedo" data-key="hdr_..." data-lang="es"></hodor-button>
```

Each `<hodor-button>`'s own `data-*` wins over the `<script>` tag's, so one
script load can power several buttons with different keys/services/langs.
`data-base` overrides the API origin if it's not the same as the script's
`src` (defaults to it).

### iframe (fully isolated, e.g. inside a CMS that strips `<script>`)

```html
<iframe src="https://hodor.lan/embed/geo?k=hdr_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        width="220" height="56" style="border:0" title="GeoGuessr casero"></iframe>
```

hodor renders a minimal page (`web/templates/embed.html`) that loads the
same `embed.js` internally; `Content-Security-Policy: frame-ancestors` is
set from the key's `allow_origins`, so only pages on those origins can
embed it.

## Security note

**The key is visible in the page source** to anyone who can view that page
— on a LAN dashboard that's "anyone at home", which is the whole point of
hodor. Treat it like a doorbell button, not a secret:

- Scope each key to the one service/group and the one or two actions
  (`open`, `close`, `status`) the button actually needs.
- Set `allow_origins` to the exact page(s) embedding it — a stolen key only
  works from CORS-allowed origins for the script/custom-element modes.
- Revoke and reissue a key (`hodor key revoke <id>`) if a page it's embedded
  on leaks outside the LAN.
