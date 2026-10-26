package config

import (
	"strings"
	"testing"
)

// validAPIKey returns an APIKey that passes Validate against
// baseValidConfig's single service "svc1".
func validAPIKey() APIKey {
	return APIKey{
		ID:        "key1",
		Name:      "test key",
		Hash:      strings.Repeat("a", 64),
		Services:  []string{"svc1"},
		Actions:   []string{KeyActionStatus},
		CreatedAt: "2026-10-25T00:00:00Z",
	}
}

func baseValidConfig() Config {
	return Config{
		Services: []Service{
			{Name: "svc1", Hosts: []string{"svc1.example.com"}, Mode: ModeProxy, Upstream: "http://127.0.0.1:9000"},
		},
	}
}

func TestValidate_Defaults(t *testing.T) {
	c := baseValidConfig()
	if err := c.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.StateFile != "/data/state.json" {
		t.Errorf("StateFile default = %q", c.StateFile)
	}
	if c.SecretFile != "/data/secret" {
		t.Errorf("SecretFile default = %q", c.SecretFile)
	}
	if c.Listen.Public != ":8080" {
		t.Errorf("Listen.Public default = %q", c.Listen.Public)
	}
	if c.Listen.Admin != ":8081" {
		t.Errorf("Listen.Admin default = %q", c.Listen.Admin)
	}
	if len(c.Admin.AllowCIDRs) == 0 || len(c.Admin.ParsedCIDRs) != len(c.Admin.AllowCIDRs) {
		t.Errorf("Admin CIDR defaults not applied: %+v", c.Admin)
	}
	if len(c.Durations) == 0 || len(c.ParsedDurations) != len(c.Durations) {
		t.Errorf("Durations defaults not applied: %+v", c.Durations)
	}
	if c.PassTTL != "720h" {
		t.Errorf("PassTTL default = %q", c.PassTTL)
	}
	if c.Services[0].Mode != ModeProxy {
		t.Errorf("Mode default = %q", c.Services[0].Mode)
	}
	if c.Services[0].Title != c.Services[0].Name {
		t.Errorf("Title default = %q, want %q", c.Services[0].Title, c.Services[0].Name)
	}
	if c.Services[0].PassBypassesClosed == nil || !*c.Services[0].PassBypassesClosed {
		t.Errorf("PassBypassesClosed default should be true")
	}
}

func TestValidate_Table(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr bool
	}{
		{
			name:    "no services is valid (zero-file setup)",
			mutate:  func(c *Config) { c.Services = nil },
			wantErr: false,
		},
		{
			name:    "service missing name",
			mutate:  func(c *Config) { c.Services[0].Name = "" },
			wantErr: true,
		},
		{
			name: "duplicate service name",
			mutate: func(c *Config) {
				c.Services = append(c.Services, Service{Name: "svc1", Hosts: []string{"other.example.com"}, Upstream: "http://127.0.0.1:9001"})
			},
			wantErr: true,
		},
		{
			name:    "service missing hosts",
			mutate:  func(c *Config) { c.Services[0].Hosts = nil },
			wantErr: true,
		},
		{
			name: "duplicate host across services",
			mutate: func(c *Config) {
				c.Services = append(c.Services, Service{Name: "svc2", Hosts: []string{"svc1.example.com"}, Upstream: "http://127.0.0.1:9001"})
			},
			wantErr: true,
		},
		{
			name:    "invalid mode",
			mutate:  func(c *Config) { c.Services[0].Mode = "bogus" },
			wantErr: true,
		},
		{
			name: "proxy mode without upstream",
			mutate: func(c *Config) {
				c.Services[0].Upstream = ""
			},
			wantErr: true,
		},
		{
			name: "proxy mode with malformed upstream",
			mutate: func(c *Config) {
				c.Services[0].Upstream = "http://[::1"
			},
			wantErr: true,
		},
		{
			name: "proxy mode with upstream missing scheme",
			mutate: func(c *Config) {
				c.Services[0].Upstream = "127.0.0.1:9000"
			},
			wantErr: true,
		},
		{
			name: "proxy mode with upstream invalid scheme",
			mutate: func(c *Config) {
				c.Services[0].Upstream = "ftp://127.0.0.1:9000"
			},
			wantErr: true,
		},
		{
			name: "proxy mode with upstream missing host",
			mutate: func(c *Config) {
				c.Services[0].Upstream = "http://"
			},
			wantErr: true,
		},
		{
			name: "invalid service name",
			mutate: func(c *Config) {
				c.Services[0].Name = "svc with spaces"
			},
			wantErr: true,
		},
		{
			name: "forwardauth mode without upstream is fine",
			mutate: func(c *Config) {
				c.Services[0].Mode = ModeForwardAuth
				c.Services[0].Upstream = ""
			},
			wantErr: false,
		},
		{
			name: "forwardauth invalid on_deny",
			mutate: func(c *Config) {
				c.Services[0].Mode = ModeForwardAuth
				c.Services[0].Upstream = ""
				c.Services[0].Auth.OnDeny = "bogus"
			},
			wantErr: true,
		},
		{
			name: "forwardauth on_deny 401 valid",
			mutate: func(c *Config) {
				c.Services[0].Mode = ModeForwardAuth
				c.Services[0].Upstream = ""
				c.Services[0].Auth.OnDeny = OnDeny401
			},
			wantErr: false,
		},
		{
			name:    "invalid admin cidr",
			mutate:  func(c *Config) { c.Admin.AllowCIDRs = []string{"not-a-cidr"} },
			wantErr: true,
		},
		{
			name:    "invalid trusted proxy cidr",
			mutate:  func(c *Config) { c.Admin.TrustedProxies = []string{"not-a-cidr"} },
			wantErr: true,
		},
		{
			name:    "invalid duration",
			mutate:  func(c *Config) { c.Durations = []string{"not-a-duration"} },
			wantErr: true,
		},
		{
			name:    "invalid pass_ttl",
			mutate:  func(c *Config) { c.PassTTL = "not-a-duration" },
			wantErr: true,
		},
		{
			name:    "valid api key",
			mutate:  func(c *Config) { c.APIKeys = []APIKey{validAPIKey()} },
			wantErr: false,
		},
		{
			name: "api key missing id",
			mutate: func(c *Config) {
				k := validAPIKey()
				k.ID = ""
				c.APIKeys = []APIKey{k}
			},
			wantErr: true,
		},
		{
			name: "api key duplicate id",
			mutate: func(c *Config) {
				k := validAPIKey()
				c.APIKeys = []APIKey{k, k}
			},
			wantErr: true,
		},
		{
			name: "api key missing name",
			mutate: func(c *Config) {
				k := validAPIKey()
				k.Name = ""
				c.APIKeys = []APIKey{k}
			},
			wantErr: true,
		},
		{
			name: "api key bad hash length",
			mutate: func(c *Config) {
				k := validAPIKey()
				k.Hash = "abc123"
				c.APIKeys = []APIKey{k}
			},
			wantErr: true,
		},
		{
			name: "api key non-hex hash",
			mutate: func(c *Config) {
				k := validAPIKey()
				k.Hash = strings.Repeat("g", 64)
				c.APIKeys = []APIKey{k}
			},
			wantErr: true,
		},
		{
			name: "api key empty actions",
			mutate: func(c *Config) {
				k := validAPIKey()
				k.Actions = nil
				c.APIKeys = []APIKey{k}
			},
			wantErr: true,
		},
		{
			name: "api key invalid action",
			mutate: func(c *Config) {
				k := validAPIKey()
				k.Actions = []string{"delete"}
				c.APIKeys = []APIKey{k}
			},
			wantErr: true,
		},
		{
			name: "api key empty services",
			mutate: func(c *Config) {
				k := validAPIKey()
				k.Services = nil
				c.APIKeys = []APIKey{k}
			},
			wantErr: true,
		},
		{
			name: "api key unknown service",
			mutate: func(c *Config) {
				k := validAPIKey()
				k.Services = []string{"nope"}
				c.APIKeys = []APIKey{k}
			},
			wantErr: true,
		},
		{
			name: "api key wildcard service",
			mutate: func(c *Config) {
				k := validAPIKey()
				k.Services = []string{"*"}
				c.APIKeys = []APIKey{k}
			},
			wantErr: false,
		},
		{
			name: "api key invalid allow_origin with path",
			mutate: func(c *Config) {
				k := validAPIKey()
				k.AllowOrigins = []string{"https://geo.lan/path"}
				c.APIKeys = []APIKey{k}
			},
			wantErr: true,
		},
		{
			name: "api key invalid allow_origin wildcard",
			mutate: func(c *Config) {
				k := validAPIKey()
				k.AllowOrigins = []string{"*"}
				c.APIKeys = []APIKey{k}
			},
			wantErr: true,
		},
		{
			name: "api key invalid allow_origin scheme",
			mutate: func(c *Config) {
				k := validAPIKey()
				k.AllowOrigins = []string{"ftp://geo.lan"}
				c.APIKeys = []APIKey{k}
			},
			wantErr: true,
		},
		{
			name: "api key valid allow_origin",
			mutate: func(c *Config) {
				k := validAPIKey()
				k.AllowOrigins = []string{"https://geo.lan"}
				c.APIKeys = []APIKey{k}
			},
			wantErr: false,
		},
		{
			name:    "on_change invalid scheme ftp",
			mutate:  func(c *Config) { c.OnChange = "ftp://x" },
			wantErr: true,
		},
		{
			name:    "on_change javascript scheme",
			mutate:  func(c *Config) { c.OnChange = "javascript:alert(1)" },
			wantErr: true,
		},
		{
			name:    "on_change missing host",
			mutate:  func(c *Config) { c.OnChange = "http://" },
			wantErr: true,
		},
		{
			name:    "on_change valid https with path",
			mutate:  func(c *Config) { c.OnChange = "https://h/x" },
			wantErr: false,
		},
		{
			name:    "on_change empty is fine (optional)",
			mutate:  func(c *Config) { c.OnChange = "" },
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := baseValidConfig()
			tt.mutate(&c)
			err := c.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("Validate() err = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestLoad_MissingFile_Defaults(t *testing.T) {
	c, err := Load("/nonexistent/path/hodor.yaml")
	if err != nil {
		t.Fatalf("Load() error = %v, want nil (missing file is not an error)", err)
	}
	if len(c.Services) != 0 {
		t.Errorf("Services = %+v, want empty", c.Services)
	}
	if c.Listen.Public != ":8080" || c.Listen.Admin != ":8081" {
		t.Errorf("Listen defaults not applied: %+v", c.Listen)
	}
	if c.StateFile != "/data/state.json" {
		t.Errorf("StateFile default = %q", c.StateFile)
	}
}

func TestDataDir_EnvOverride(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HODOR_DATA_DIR", dir)
	c := Config{}
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if c.StateFile != dir+"/state.json" {
		t.Errorf("StateFile = %q, want %q", c.StateFile, dir+"/state.json")
	}
	if c.SecretFile != dir+"/secret" {
		t.Errorf("SecretFile = %q, want %q", c.SecretFile, dir+"/secret")
	}
}

func TestValidate_AdminAllowCIDRsEnvOverride(t *testing.T) {
	t.Setenv("HODOR_ADMIN_ALLOW_CIDRS", "203.0.113.0/24, 198.51.100.0/24")
	c := baseValidConfig()
	c.Admin.AllowCIDRs = []string{"10.0.0.0/8"} // set in hodor.yaml, must still be overridden
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if len(c.Admin.AllowCIDRs) != 2 || c.Admin.AllowCIDRs[0] != "203.0.113.0/24" || c.Admin.AllowCIDRs[1] != "198.51.100.0/24" {
		t.Errorf("Admin.AllowCIDRs = %+v, want env override", c.Admin.AllowCIDRs)
	}
	if len(c.Admin.ParsedCIDRs) != 2 {
		t.Errorf("Admin.ParsedCIDRs = %+v, want 2 parsed from env override", c.Admin.ParsedCIDRs)
	}
}

func TestLockedGeneralFields_AdminAllowCIDRsEnvLocksEvenWhenBaseUnset(t *testing.T) {
	t.Setenv("HODOR_ADMIN_ALLOW_CIDRS", "203.0.113.0/24")
	raw := &Config{} // base hodor.yaml does not set admin.allow_cidrs at all
	locked := LockedGeneralFields(raw)
	found := false
	for _, f := range locked {
		if f == "admin_allow_cidrs" {
			found = true
		}
	}
	if !found {
		t.Errorf("LockedGeneralFields() = %+v, want admin_allow_cidrs locked due to env override", locked)
	}
}

func TestSecret_EnvOverridesFile(t *testing.T) {
	t.Setenv("HODOR_SECRET", "env-secret-value")
	c := baseValidConfig()
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	c.SecretFile = "/nonexistent/path/should-not-be-read"
	got, err := c.Secret()
	if err != nil {
		t.Fatalf("Secret() error = %v", err)
	}
	if string(got) != "env-secret-value" {
		t.Errorf("Secret() = %q, want env value", got)
	}
}

func TestSecret_LoadsOrCreatesFile(t *testing.T) {
	dir := t.TempDir()
	c := baseValidConfig()
	c.SecretFile = dir + "/secret"
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	got1, err := c.Secret()
	if err != nil {
		t.Fatalf("Secret() error = %v", err)
	}
	if len(got1) == 0 {
		t.Fatalf("Secret() returned empty secret")
	}
	got2, err := c.Secret()
	if err != nil {
		t.Fatalf("Secret() second call error = %v", err)
	}
	if string(got1) != string(got2) {
		t.Errorf("Secret() not stable across calls: %q != %q", got1, got2)
	}
}
