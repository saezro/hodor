// Package config loads and validates hodor.yaml.
package config

import (
	"fmt"
	"net"
	"os"
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
	OnChange   string    `yaml:"on_change"` // webhook URL, optional

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
	OnDeny401      OnDeny = "401"
)

// Service is one proxied/guarded service.
type Service struct {
	Name               string      `yaml:"name"`
	Title              string      `yaml:"title"`
	Hosts              []string    `yaml:"hosts"`
	Mode               string      `yaml:"mode"` // "proxy" or "forwardauth"
	Upstream           string      `yaml:"upstream"`
	Group              string      `yaml:"group"`
	PassBypassesClosed *bool       `yaml:"pass_bypasses_closed"`
	Auth               ServiceAuth `yaml:"auth"`

	// Closed-page theming.
	Message     string `yaml:"message"`
	AccentColor string `yaml:"accent_color"`
	LogoURL     string `yaml:"logo_url"`
}

// ServiceAuth holds forwardauth-mode specific options.
type ServiceAuth struct {
	OnDeny OnDeny `yaml:"on_deny"`
}

const (
	// ModeProxy reverse-proxies the service through hodor.
	ModeProxy       = "proxy"
	ModeForwardAuth = "forwardauth"
)

var defaultDurations = []string{"1h", "3h", "6h", "24h"}

var defaultCIDRs = []string{
	"192.168.0.0/16",
	"10.0.0.0/8",
	"172.16.0.0/12",
	"100.64.0.0/10",
	"127.0.0.0/8",
	"::1/128",
}

// Load reads and parses the YAML file at path, then validates it.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path comes from this process's own config, not request input
	if err != nil {
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
	if c.StateFile == "" {
		c.StateFile = "/data/state.json"
	}
	if c.SecretFile == "" {
		c.SecretFile = "/run/secrets/hodor"
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

	if len(c.Services) == 0 {
		return fmt.Errorf("services: at least one service is required")
	}

	names := map[string]bool{}
	hosts := map[string]string{}
	for i := range c.Services {
		s := &c.Services[i]
		if s.Name == "" {
			return fmt.Errorf("services[%d]: name is required", i)
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

		if s.Mode == ModeProxy && s.Upstream == "" {
			return fmt.Errorf("services[%s]: upstream is required in proxy mode", s.Name)
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
