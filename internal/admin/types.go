package admin

import (
	"time"

	"github.com/saezro/hodor/internal/config"
)

// ServiceView is the JSON shape of one entry in GET /api/services. It is
// also used by cmd/hodor to decode the response for `hodor status`.
type ServiceView struct {
	Name     string     `json:"name"`
	Title    string     `json:"title"`
	Hosts    []string   `json:"hosts"`
	Mode     string     `json:"mode"`
	Group    string     `json:"group"`
	Open     bool       `json:"open"`
	Until    *time.Time `json:"until,omitempty"`
	OpenedBy string     `json:"opened_by,omitempty"`
}

// ServiceV1View is the JSON shape of GET /api/v1/services/{name}: the
// same fields as ServiceView (kept separate so `hodor status`, which
// decodes ServiceView, is unaffected) plus the configured open-for
// durations, so an embed consumer can build its own open control
// without a second request.
type ServiceV1View struct {
	ServiceView
	Durations []string `json:"durations"`
}

// PinView is the JSON shape of one entry in GET /api/pins.
type PinView struct {
	SessionID string    `json:"session_id"`
	Service   string    `json:"service"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// PassView is the JSON shape of one entry in GET /api/passes.
type PassView struct {
	ID        string    `json:"id"`
	Service   string    `json:"service"`
	CreatedAt time.Time `json:"created_at"`
	Revoked   bool      `json:"revoked"`
	Label     string    `json:"label"`
}

// EventView is the JSON shape of one entry in GET /api/events.
type EventView struct {
	Time    time.Time `json:"time"`
	Message string    `json:"message"`
}

// OpenRequest is the JSON body of POST /api/services/{name}/open.
type OpenRequest struct {
	For string `json:"for"` // duration string, e.g. "3h"; empty = until closed
}

// ApprovePinRequest is the JSON body of POST /api/pins.
type ApprovePinRequest struct {
	Code string `json:"code"`
}

// CSRFResponse is the JSON body of GET /api/csrf.
type CSRFResponse struct {
	Token string `json:"token"`
}

// errorResponse is the JSON body returned on API errors.
type errorResponse struct {
	Error string `json:"error"`
}

// validationErrorResponse is the 400 body returned by every
// /api/config/* write when the resulting config fails validation:
// one message per offending field, nothing applied (see
// internal/config.Live.mutateOverlay).
type validationErrorResponse struct {
	Errors map[string]string `json:"errors"`
}

// okResponse is the 200 body for /api/config/* writes that have
// nothing richer to report back.
type okResponse struct {
	OK bool `json:"ok"`
}

// ConfigGetResponse is the JSON body of GET /api/config: the merged
// (base + overlay) services/durations/api_keys, plus the on-disk
// paths backing them (docs/DESIGN.md "2c. Panel config editing + hot
// reload"). Services and APIKeys carry their own Source field
// ("base"/"overlay") already; APIKey.Hash never serializes.
type ConfigGetResponse struct {
	Services    []config.Service `json:"services"`
	Durations   []string         `json:"durations"`
	APIKeys     []config.APIKey  `json:"api_keys"`
	General     GeneralView      `json:"general"`
	BasePath    string           `json:"base_path"`
	OverlayPath string           `json:"overlay_path"`
}

// GeneralView is the JSON shape of ConfigGetResponse.General and the
// 200 body of PUT /api/config/general: the effective (merged)
// value of every general-section field (docs/DESIGN.md "Phase 3"),
// plus Locked - the subset of field names below that the panel can't
// write (base config or env override already sets them; PUT on one
// of them is a 409). AdminToken itself is never serialized, only
// whether one is set.
type GeneralView struct {
	Lang                 string   `json:"lang"`
	AdminPublicURL       string   `json:"admin_public_url"`
	AdminAllowCIDRs      []string `json:"admin_allow_cidrs"`
	AdminTokenSet        bool     `json:"admin_token_set"`
	AdminTrustedProxies  []string `json:"admin_trusted_proxies"`
	AdminTrustedHeader   string   `json:"admin_trusted_header"`
	PublicTrustedProxies []string `json:"public_trusted_proxies"`
	PublicCookieSecure   bool     `json:"public_cookie_secure"`
	PassTTL              string   `json:"pass_ttl"`
	OnChange             string   `json:"on_change"`
	Locked               []string `json:"locked"`
}

// ConfigGeneralRequest is the JSON body of PUT /api/config/general: a
// partial update - every field is optional (field absent/null = leave
// untouched); AdminToken present as "" clears a previously-set
// overlay token. Field names and semantics mirror GeneralView (minus
// Locked, which the client can't set) and config.GeneralPatch (which
// this converts to 1:1 in config_api.go).
// AdminTrustedProxies/AdminTrustedHeader are deliberately absent: they
// are read-only from the panel (see config.General's doc comment),
// settable only via hodor.yaml or HODOR_ADMIN_TRUSTED_PROXIES/
// HODOR_ADMIN_TRUSTED_HEADER.
type ConfigGeneralRequest struct {
	Lang                 *string   `json:"lang,omitempty"`
	AdminPublicURL       *string   `json:"admin_public_url,omitempty"`
	AdminAllowCIDRs      *[]string `json:"admin_allow_cidrs,omitempty"`
	AdminToken           *string   `json:"admin_token,omitempty"`
	PublicTrustedProxies *[]string `json:"public_trusted_proxies,omitempty"`
	PublicCookieSecure   *bool     `json:"public_cookie_secure,omitempty"`
	PassTTL              *string   `json:"pass_ttl,omitempty"`
	OnChange             *string   `json:"on_change,omitempty"`
}

// ConfigDurationsRequest is the JSON body of PUT /api/config/durations.
type ConfigDurationsRequest struct {
	Durations []string `json:"durations"`
}

// ConfigKeyCreateRequest is the JSON body of POST /api/config/keys.
type ConfigKeyCreateRequest struct {
	Name         string   `json:"name"`
	Services     []string `json:"services"`
	Actions      []string `json:"actions"`
	AllowOrigins []string `json:"allow_origins"`
}

// ConfigKeyCreateResponse is the JSON body of a successful POST
// /api/config/keys: Key is the raw key, shown this once only (only its
// hash is ever persisted, same as `hodor key new`).
type ConfigKeyCreateResponse struct {
	ID          string `json:"id"`
	Key         string `json:"key"`
	YAMLSnippet string `json:"yaml_snippet"`
}

// ConfigReloadResponse is the JSON body of POST /api/config/reload.
type ConfigReloadResponse struct {
	OK       bool     `json:"ok"`
	Warnings []string `json:"warnings"`
}
