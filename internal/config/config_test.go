package config

import (
	"testing"
)

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
	if c.SecretFile != "/run/secrets/hodor" {
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
			name:    "no services",
			mutate:  func(c *Config) { c.Services = nil },
			wantErr: true,
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
