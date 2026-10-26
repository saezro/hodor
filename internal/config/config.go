// Package config loads and validates hodor.yaml.
package config

import (
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the root of hodor.yaml.
type Config struct {
	Lang       string    `yaml:"lang"`
	SecretFile string    `yaml:"secret_file"`
	StateFile  string    `yaml:"state_file"`
	Listen     Listen    `yaml:"listen"`
	Admin      Admin     `yaml:"admin"`
	Public     Public    `yaml:"public"`
	Durations  []string  `yaml:"durations"`
	PassTTL    string    `yaml:"pass_ttl"`
	Services   []Service `yaml:"services"`
	APIKeys    []APIKey  `yaml:"api_keys"`
	OnChange   string    `yaml:"on_change"` // webhook URL, optional

	// ConfigOverlay is the path to the panel-editable overlay file (see
	// overlay.go): services/durations/api_keys added or changed from the
	// admin panel live there instead of this file, which stays hand-owned
	// and is never rewritten. Defaults to "managed.yaml" next to
	// StateFile; see OverlayPath.
	ConfigOverlay string `yaml:"config_overlay"`

	// Parsed form, filled by Validate.
	ParsedDurations []time.Duration `yaml:"-"`
	ParsedPassTTL   time.Duration   `yaml:"-"`
}

// Listen holds the two listener addresses.
type Listen struct {
	Public string `yaml:"public"`
	Admin  string `yaml:"admin"`
}

// Admin controls the admin listener and its API.
type Admin struct {
	AllowCIDRs     []string `yaml:"allow_cidrs"`
	PublicURL      string   `yaml:"public_url"`
	Token          string   `yaml:"token"`
	TrustedProxies []string `yaml:"trusted_proxies"`
	TrustedHeader  string   `yaml:"trusted_header"`

	ParsedCIDRs   []*net.IPNet `yaml:"-"`
	ParsedProxies []*net.IPNet `yaml:"-"`
}

// Public controls the trust boundary of the public listener: by
// default it never trusts X-Forwarded-* headers (a client could set
// them directly), only when the reverse proxy in front of it is known.
type Public struct {
	// TrustedProxies lists the CIDRs of reverse proxies allowed to set
	// X-Forwarded-Host/Proto/Uri on requests to the public listener. A
	// request whose RemoteAddr is outside this list is handled using
	// r.Host/r.URL/the actual TLS state instead, ignoring those headers.
	TrustedProxies []string `yaml:"trusted_proxies"`
	// CookieSecure forces (or disables) the Secure flag on device-pass
	// cookies regardless of the request's own scheme. Defaults to true
	// unless listen.public is bound to loopback only (a common local-dev
	// setup with no TLS anywhere in front).
	CookieSecure *bool `yaml:"cookie_secure"`

	ParsedProxies []*net.IPNet `yaml:"-"`
}

// OnDeny selects the forwardauth denial behavior.
type OnDeny string

const (
	// OnDenyRedirect redirects denied requests to the closed page.
	OnDenyRedirect OnDeny = "redirect"
	// OnDeny401 responds to denied requests with a bare 401.
	OnDeny401 OnDeny = "401"
)

// Service is one proxied/guarded service.
type Service struct {
	Name               string      `yaml:"name" json:"name"`
	Title              string      `yaml:"title" json:"title"`
	Hosts              []string    `yaml:"hosts" json:"hosts"`
	Mode               string      `yaml:"mode" json:"mode"` // "proxy" or "forwardauth"
	Upstream           string      `yaml:"upstream" json:"upstream,omitempty"`
	Group              string      `yaml:"group" json:"group,omitempty"`
	PassBypassesClosed *bool       `yaml:"pass_bypasses_closed" json:"pass_bypasses_closed,omitempty"`
	Auth               ServiceAuth `yaml:"auth" json:"auth,omitempty"`

	// Closed-page theming.
	Message     string `yaml:"message" json:"message,omitempty"`
	AccentColor string `yaml:"accent_color" json:"accent_color,omitempty"`
	LogoURL     string `yaml:"logo_url" json:"logo_url,omitempty"`

	// Source is "base" or "overlay", set by MergeOverlay (see overlay.go)
	// to tell the panel which services are read-only. It is derived, not
	// configuration: never read from or written to either YAML file.
	Source string `yaml:"-" json:"source,omitempty"`
}

// APIKey is one scoped credential for the versioned /api/v1 endpoints
// (see internal/admin and internal/apikey). Only its sha256 hash is
// ever persisted; the raw key is shown once, at creation time, by
// `hodor key new`.
type APIKey struct {
	ID           string   `yaml:"id" json:"id"`
	Name         string   `yaml:"name" json:"name"`
	Hash         string   `yaml:"hash" json:"-"`            // sha256 hex of the raw key; never exposed back over JSON
	Services     []string `yaml:"services" json:"services"` // service name, group name, or "*" for all
	Actions      []string `yaml:"actions" json:"actions"`   // subset of "open", "close", "status"
	AllowOrigins []string `yaml:"allow_origins" json:"allow_origins,omitempty"`
	CreatedAt    string   `yaml:"created_at" json:"created_at,omitempty"`

	// Source is "base" or "overlay", set by MergeOverlay. Derived, not
	// configuration: never (un)marshaled to/from YAML.
	Source string `yaml:"-" json:"source,omitempty"`
}

const (
	// KeyActionOpen is the API key action matching POST .../open.
	KeyActionOpen = "open"
	// KeyActionClose is the API key action matching POST .../close.
	KeyActionClose = "close"
	// KeyActionStatus is the API key action matching GET .../{name}.
	KeyActionStatus = "status"
)

// ServiceAuth holds forwardauth-mode specific options.
type ServiceAuth struct {
	OnDeny OnDeny `yaml:"on_deny" json:"on_deny,omitempty"`
}

const (
	// ModeProxy reverse-proxies the service through hodor.
	ModeProxy = "proxy"
	// ModeForwardAuth guards the service via forward-auth instead of proxying it.
	ModeForwardAuth = "forwardauth"
)

// serviceNameRe constrains service names: used as map keys, YAML
// keys-ish identifiers and in URL paths/ids, so no whitespace or
// characters that would need escaping.
var serviceNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

var defaultDurations = []string{"1h", "3h", "6h", "24h"}

var defaultCIDRs = []string{
	"127.0.0.0/8",
	"::1/128",
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"100.64.0.0/10",
	"fc00::/7",
}

// dataDir resolves the zero-file-setup data directory (docs/DESIGN.md
// "Phase 3 — zero-file setup"): env HODOR_DATA_DIR, or "/data" to match
// the Dockerfile's VOLUME. Used to default state_file/secret_file/the
// config_overlay (via StateFile's directory) when hodor.yaml doesn't
// set them - or doesn't exist at all.
func dataDir() string {
	if v := os.Getenv("HODOR_DATA_DIR"); v != "" {
		return v
	}
	return "/data"
}

// LoadRaw reads and parses path's YAML *without* applying defaults or
// validation. It exists for callers that need to know whether a field
// was actually set in the base file, as opposed to defaulted - e.g.
// the admin "general" settings' read-only check (see
// LockedGeneralFields) - since Validate's defaults would otherwise
// make every field look "set". A missing file is not an error: it
// returns an empty Config, same as Load (see Load's zero-file-setup
// doc comment).
func LoadRaw(path string) (*Config, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path comes from this process's own config, not request input
	if err != nil {
		if os.IsNotExist(err) {
			return &Config{}, nil
		}
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	return &c, nil
}

// Load reads and parses the YAML file at path, then validates it. A
// missing file is not an error (docs/DESIGN.md "Phase 3 — zero-file
// setup"): hodor starts fine with no hodor.yaml at all, using only
// defaults/env/the panel from then on; this is logged at info level so
// it's clear on startup whether a base config was actually found. A
// file that exists but fails to parse is still a hard error, same as
// before.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path comes from this process's own config, not request input
	if err != nil {
		if os.IsNotExist(err) {
			slog.Info("config file not found, starting with defaults only", "path", path)
			c := &Config{}
			if err := c.Validate(); err != nil {
				return nil, err
			}
			return c, nil
		}
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

// Validate applies defaults and checks the configuration for errors,
// returning a descriptive error on the first problem found.
func (c *Config) Validate() error {
	if c.Lang == "" {
		c.Lang = "es"
	}
	if c.StateFile == "" {
		c.StateFile = filepath.Join(dataDir(), "state.json")
	}
	if c.SecretFile == "" {
		c.SecretFile = filepath.Join(dataDir(), "secret")
	}
	if c.Listen.Public == "" {
		c.Listen.Public = ":8080"
	}
	if c.Listen.Admin == "" {
		c.Listen.Admin = ":8081"
	}
	if len(c.Admin.AllowCIDRs) == 0 {
		c.Admin.AllowCIDRs = defaultCIDRs
	}
	if len(c.Durations) == 0 {
		c.Durations = defaultDurations
	}
	if c.PassTTL == "" {
		c.PassTTL = "720h" // 30 days
	}

	// Startup-only env overrides (docs/DESIGN.md "Phase 3"): not
	// hot-reloadable (read once, here, every time a Config is built,
	// including on reload/panel-save - but the env itself never
	// changes at runtime so that's a no-op in practice), and always win
	// over both hodor.yaml and the panel overlay. HODOR_ADMIN_ALLOW_CIDRS
	// in particular is the anti-lockout valve: it always works even if
	// the panel's own allow_cidrs is broken.
	if v := os.Getenv("HODOR_LISTEN_PUBLIC"); v != "" {
		c.Listen.Public = v
	}
	if v := os.Getenv("HODOR_LISTEN_ADMIN"); v != "" {
		c.Listen.Admin = v
	}
	if v, ok := os.LookupEnv("HODOR_ADMIN_ALLOW_CIDRS"); ok {
		cidrs := splitTrimmedComma(v)
		if len(cidrs) == 0 {
			return fmt.Errorf("admin.allow_cidrs: HODOR_ADMIN_ALLOW_CIDRS is set but empty")
		}
		c.Admin.AllowCIDRs = cidrs
	}
	if v, ok := os.LookupEnv("HODOR_ADMIN_TRUSTED_PROXIES"); ok {
		proxies := splitTrimmedComma(v)
		if len(proxies) == 0 {
			return fmt.Errorf("admin.trusted_proxies: HODOR_ADMIN_TRUSTED_PROXIES is set but empty")
		}
		c.Admin.TrustedProxies = proxies
	}
	if v := strings.TrimSpace(os.Getenv("HODOR_ADMIN_TRUSTED_HEADER")); v != "" {
		c.Admin.TrustedHeader = v
	}

	for _, s := range c.Admin.AllowCIDRs {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return fmt.Errorf("admin.allow_cidrs: invalid CIDR %q: %w", s, err)
		}
		c.Admin.ParsedCIDRs = append(c.Admin.ParsedCIDRs, n)
	}
	for _, s := range c.Admin.TrustedProxies {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return fmt.Errorf("admin.trusted_proxies: invalid CIDR %q: %w", s, err)
		}
		c.Admin.ParsedProxies = append(c.Admin.ParsedProxies, n)
	}
	for _, s := range c.Public.TrustedProxies {
		_, n, err := net.ParseCIDR(s)
		if err != nil {
			return fmt.Errorf("public.trusted_proxies: invalid CIDR %q: %w", s, err)
		}
		c.Public.ParsedProxies = append(c.Public.ParsedProxies, n)
	}
	if c.Public.CookieSecure == nil {
		secure := !isLoopbackListen(c.Listen.Public)
		c.Public.CookieSecure = &secure
	}

	for _, d := range c.Durations {
		dur, err := time.ParseDuration(d)
		if err != nil {
			return fmt.Errorf("durations: invalid duration %q: %w", d, err)
		}
		c.ParsedDurations = append(c.ParsedDurations, dur)
	}

	ttl, err := time.ParseDuration(c.PassTTL)
	if err != nil {
		return fmt.Errorf("pass_ttl: invalid duration %q: %w", c.PassTTL, err)
	}
	c.ParsedPassTTL = ttl

	if err := validateOnChange(c.OnChange); err != nil {
		return err
	}

	names := map[string]bool{}
	hosts := map[string]string{}
	for i := range c.Services {
		s := &c.Services[i]
		if s.Name == "" {
			return fmt.Errorf("services[%d]: name is required", i)
		}
		if !serviceNameRe.MatchString(s.Name) {
			return fmt.Errorf("services[%d]: name %q is invalid (must match %s)", i, s.Name, serviceNameRe.String())
		}
		if names[s.Name] {
			return fmt.Errorf("services: duplicate name %q", s.Name)
		}
		names[s.Name] = true

		if len(s.Hosts) == 0 {
			return fmt.Errorf("services[%s]: hosts is required", s.Name)
		}
		for _, h := range s.Hosts {
			if owner, ok := hosts[h]; ok {
				return fmt.Errorf("services[%s]: host %q already used by service %q", s.Name, h, owner)
			}
			hosts[h] = s.Name
		}

		switch s.Mode {
		case "":
			s.Mode = ModeProxy
		case ModeProxy, ModeForwardAuth:
		default:
			return fmt.Errorf("services[%s]: invalid mode %q (want %q or %q)", s.Name, s.Mode, ModeProxy, ModeForwardAuth)
		}

		if s.Mode == ModeProxy {
			if s.Upstream == "" {
				return fmt.Errorf("services[%s]: upstream is required in proxy mode", s.Name)
			}
			u, err := url.Parse(s.Upstream)
			if err != nil {
				return fmt.Errorf("services[%s]: upstream: invalid URL %q: %w", s.Name, s.Upstream, err)
			}
			if u.Scheme != "http" && u.Scheme != "https" {
				return fmt.Errorf("services[%s]: upstream: %q must use http or https", s.Name, s.Upstream)
			}
			if u.Host == "" {
				return fmt.Errorf("services[%s]: upstream: %q is missing a host", s.Name, s.Upstream)
			}
		}
		if s.Mode == ModeForwardAuth {
			switch s.Auth.OnDeny {
			case "":
				s.Auth.OnDeny = OnDenyRedirect
			case OnDenyRedirect, OnDeny401:
			default:
				return fmt.Errorf("services[%s]: invalid auth.on_deny %q", s.Name, s.Auth.OnDeny)
			}
		}

		if s.PassBypassesClosed == nil {
			b := true
			s.PassBypassesClosed = &b
		}
		if s.Title == "" {
			s.Title = s.Name
		}
	}

	groups := map[string]bool{}
	for i := range c.Services {
		if g := c.Services[i].Group; g != "" {
			groups[g] = true
		}
	}
	for name := range names {
		if groups[name] {
			return fmt.Errorf("services: %q is used both as a service name and as a group name", name)
		}
	}

	if err := c.validateAPIKeys(names, groups); err != nil {
		return err
	}

	return nil
}

// validateAPIKeys checks c.APIKeys against the already-validated set of
// service names and group names.
func (c *Config) validateAPIKeys(names, groups map[string]bool) error {
	ids := map[string]bool{}
	validActions := map[string]bool{KeyActionOpen: true, KeyActionClose: true, KeyActionStatus: true}

	for i := range c.APIKeys {
		k := &c.APIKeys[i]
		if k.ID == "" {
			return fmt.Errorf("api_keys[%d]: id is required", i)
		}
		if ids[k.ID] {
			return fmt.Errorf("api_keys: duplicate id %q", k.ID)
		}
		ids[k.ID] = true

		if k.Name == "" {
			return fmt.Errorf("api_keys[%s]: name is required", k.ID)
		}
		if len(k.Hash) != 64 || !isHexString(k.Hash) {
			return fmt.Errorf("api_keys[%s]: hash must be 64 hex characters (sha256)", k.ID)
		}

		if len(k.Actions) == 0 {
			return fmt.Errorf("api_keys[%s]: actions is required", k.ID)
		}
		for _, a := range k.Actions {
			if !validActions[a] {
				return fmt.Errorf("api_keys[%s]: invalid action %q (want one of open, close, status)", k.ID, a)
			}
		}

		if len(k.Services) == 0 {
			return fmt.Errorf("api_keys[%s]: services is required", k.ID)
		}
		for _, svc := range k.Services {
			if svc == "*" || names[svc] || groups[svc] {
				continue
			}
			return fmt.Errorf("api_keys[%s]: %q is not a known service, group or \"*\"", k.ID, svc)
		}

		for _, origin := range k.AllowOrigins {
			if err := ValidateOrigin(origin); err != nil {
				return fmt.Errorf("api_keys[%s]: allow_origins: %w", k.ID, err)
			}
		}
	}
	return nil
}

// splitTrimmedComma splits s on commas, trimming whitespace and
// dropping empty elements - used for env-provided lists like
// HODOR_ADMIN_ALLOW_CIDRS.
func splitTrimmedComma(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func isHexString(s string) bool {
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') && (r < 'A' || r > 'F') {
			return false
		}
	}
	return true
}

// validateOnChange checks that onChange, if set, is an http(s) URL with
// a host: internal/webhook.Notifier POSTs to it unauthenticated, so a
// scheme like file:// or javascript: (or a bare host with no scheme)
// must be rejected rather than reaching http.Client.
func validateOnChange(onChange string) error {
	if onChange == "" {
		return nil
	}
	u, err := url.Parse(onChange)
	if err != nil {
		return fmt.Errorf("on_change: invalid URL %q: %w", onChange, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("on_change: %q must use http or https", onChange)
	}
	if u.Host == "" {
		return fmt.Errorf("on_change: %q is missing a host", onChange)
	}
	return nil
}

// ValidateOrigin checks that origin is a bare scheme+host, as required
// for an Access-Control-Allow-Origin echo value: http(s) only, no path,
// no query, no wildcard.
func ValidateOrigin(origin string) error {
	if origin == "*" {
		return fmt.Errorf("wildcard %q is not allowed", origin)
	}
	u, err := url.Parse(origin)
	if err != nil {
		return fmt.Errorf("invalid origin %q: %w", origin, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("origin %q must use http or https", origin)
	}
	if u.Host == "" {
		return fmt.Errorf("origin %q is missing a host", origin)
	}
	if u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("origin %q must be scheme+host only, no path", origin)
	}
	rebuilt := u.Scheme + "://" + u.Host
	if rebuilt != origin {
		return fmt.Errorf("origin %q must be scheme+host only (got extra: %q)", origin, origin)
	}
	return nil
}

// isLoopbackListen reports whether addr (a listen address like ":8080",
// "127.0.0.1:8080" or "localhost:8080") is bound to loopback only,
// meaning nothing but the local machine can ever reach it directly.
func isLoopbackListen(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if host == "" {
		return false // e.g. ":8080" binds all interfaces
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Secret resolves the HMAC secret: env HODOR_SECRET takes priority over
// secret_file. If the file does not exist, it is generated (32 random
// bytes, base64, mode 0600) so first run works without manual setup.
func (c *Config) Secret() ([]byte, error) {
	if v := os.Getenv("HODOR_SECRET"); v != "" {
		return []byte(v), nil
	}
	return loadOrCreateSecret(c.SecretFile)
}
