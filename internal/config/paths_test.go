package config

import "testing"

func TestNormalizePath(t *testing.T) {
	cases := []struct {
		raw  string
		want string
	}{
		{"", "/"},
		{"/", "/"},
		{"/foo", "/foo"},
		{"/foo/", "/foo/"},
		{"/foo//bar", "/foo/bar"},
		{"/vendor/../laboratorio", "/laboratorio"},
		{"/vendor/./assets", "/vendor/assets"},
		{"/../../etc/passwd", "/etc/passwd"},
		{"/vendor/", "/vendor/"},
	}
	for _, c := range cases {
		if got := NormalizePath(c.raw); got != c.want {
			t.Errorf("NormalizePath(%q) = %q, want %q", c.raw, got, c.want)
		}
	}
}

func TestService_MatchAccess(t *testing.T) {
	svc := Service{
		DefaultAccess: AccessDeny,
		Paths: []PathRule{
			{Path: "/mundos", Access: AccessGated},
			{Prefix: "/vendor/", Methods: []string{"GET", "HEAD"}, Access: AccessPublic},
			{Path: "/laboratorio", Access: AccessDeny},
		},
	}

	cases := []struct {
		name   string
		path   string
		method string
		want   Access
	}{
		{"exact path match", "/mundos", "GET", AccessGated},
		{"prefix match, allowed method", "/vendor/jquery.js", "GET", AccessPublic},
		{"prefix match, disallowed method falls through", "/vendor/jquery.js", "POST", AccessDeny},
		{"explicit deny rule", "/laboratorio", "GET", AccessDeny},
		{"no rule matches: default_access applies", "/anything-else", "GET", AccessDeny},
		{"path normalized before matching", "/vendor/../mundos", "GET", AccessGated},
		{"trailing slash preserved for prefix", "/vendor/", "HEAD", AccessPublic},
		{"method is case-insensitive via uppercasing", "/vendor/x", "get", AccessPublic},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := svc.MatchAccess(c.path, c.method); got != c.want {
				t.Errorf("MatchAccess(%q, %q) = %q, want %q", c.path, c.method, got, c.want)
			}
		})
	}
}

func TestService_MatchAccess_DefaultsToGatedWhenUnset(t *testing.T) {
	svc := Service{} // no default_access, no paths: exactly today's behavior
	if got := svc.MatchAccess("/anything", "GET"); got != AccessGated {
		t.Errorf("MatchAccess() = %q, want %q (retrocompatible default)", got, AccessGated)
	}
}

func TestService_MatchAccess_FirstRuleWins(t *testing.T) {
	svc := Service{
		Paths: []PathRule{
			{Prefix: "/api/", Access: AccessDeny},
			{Path: "/api/public", Access: AccessPublic}, // never reached: prefix above already matched
		},
	}
	if got := svc.MatchAccess("/api/public", "GET"); got != AccessDeny {
		t.Errorf("MatchAccess() = %q, want %q (first matching rule wins)", got, AccessDeny)
	}
}

func TestValidate_ServicePaths(t *testing.T) {
	validSvc := func() Service {
		return Service{Name: "svc1", Hosts: []string{"svc1.example.com"}, Mode: ModeProxy, Upstream: "http://127.0.0.1:9000"}
	}

	t.Run("valid default_access and paths", func(t *testing.T) {
		c := Config{Services: []Service{validSvc()}}
		c.Services[0].DefaultAccess = AccessDeny
		c.Services[0].Paths = []PathRule{
			{Path: "/mundos", Access: AccessGated},
			{Prefix: "/vendor/", Methods: []string{"GET", "HEAD"}, Access: AccessGated},
		}
		if err := c.Validate(); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("invalid default_access", func(t *testing.T) {
		c := Config{Services: []Service{validSvc()}}
		c.Services[0].DefaultAccess = "bogus"
		if err := c.Validate(); err == nil {
			t.Fatal("expected error for invalid default_access")
		}
	})

	t.Run("rule missing both path and prefix", func(t *testing.T) {
		c := Config{Services: []Service{validSvc()}}
		c.Services[0].Paths = []PathRule{{Access: AccessDeny}}
		if err := c.Validate(); err == nil {
			t.Fatal("expected error for rule with neither path nor prefix")
		}
	})

	t.Run("rule with both path and prefix", func(t *testing.T) {
		c := Config{Services: []Service{validSvc()}}
		c.Services[0].Paths = []PathRule{{Path: "/a", Prefix: "/b/", Access: AccessDeny}}
		if err := c.Validate(); err == nil {
			t.Fatal("expected error for rule with both path and prefix")
		}
	})

	t.Run("path not starting with /", func(t *testing.T) {
		c := Config{Services: []Service{validSvc()}}
		c.Services[0].Paths = []PathRule{{Path: "mundos", Access: AccessDeny}}
		if err := c.Validate(); err == nil {
			t.Fatal("expected error for path not starting with /")
		}
	})

	t.Run("invalid access on rule", func(t *testing.T) {
		c := Config{Services: []Service{validSvc()}}
		c.Services[0].Paths = []PathRule{{Path: "/mundos", Access: "bogus"}}
		if err := c.Validate(); err == nil {
			t.Fatal("expected error for invalid access")
		}
	})

	t.Run("missing access on rule", func(t *testing.T) {
		c := Config{Services: []Service{validSvc()}}
		c.Services[0].Paths = []PathRule{{Path: "/mundos"}}
		if err := c.Validate(); err == nil {
			t.Fatal("expected error for missing access")
		}
	})

	t.Run("invalid method", func(t *testing.T) {
		c := Config{Services: []Service{validSvc()}}
		c.Services[0].Paths = []PathRule{{Path: "/mundos", Methods: []string{"get"}, Access: AccessDeny}}
		if err := c.Validate(); err == nil {
			t.Fatal("expected error for lowercase method")
		}
	})
}
