package auth

import (
	"net"
	"net/http"
	"testing"
	"time"
)

func parseCIDRs(t *testing.T, cidrs ...string) []*net.IPNet {
	t.Helper()
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			t.Fatalf("ParseCIDR(%q): %v", c, err)
		}
		out = append(out, n)
	}
	return out
}

func TestIPAllowed(t *testing.T) {
	nets := parseCIDRs(t, "192.168.0.0/16", "10.0.0.0/8")
	tests := []struct {
		ip   string
		want bool
	}{
		{"192.168.1.5", true},
		{"10.1.2.3", true},
		{"8.8.8.8", false},
		{"172.16.0.1", false},
	}
	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		if got := IPAllowed(nets, ip); got != tt.want {
			t.Errorf("IPAllowed(%s) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}

func TestClientIP_NoTrustedProxy_UsesRemoteAddr(t *testing.T) {
	r := &http.Request{RemoteAddr: "203.0.113.5:1234", Header: http.Header{}}
	r.Header.Set("X-Forwarded-For", "9.9.9.9")
	ip := ClientIP(r, nil, "X-Forwarded-For")
	if ip == nil || ip.String() != "203.0.113.5" {
		t.Errorf("ClientIP() = %v, want 203.0.113.5 (untrusted proxy ignored)", ip)
	}
}

func TestClientIP_TrustedProxy_UsesHeader(t *testing.T) {
	trusted := parseCIDRs(t, "10.0.0.0/8")
	r := &http.Request{RemoteAddr: "10.0.0.1:1234", Header: http.Header{}}
	r.Header.Set("X-Forwarded-For", "203.0.113.9, 10.0.0.1")
	ip := ClientIP(r, trusted, "X-Forwarded-For")
	if ip == nil || ip.String() != "203.0.113.9" {
		t.Errorf("ClientIP() = %v, want 203.0.113.9 (first entry of XFF)", ip)
	}
}

func TestClientIP_TrustedProxy_EmptyHeader_FallsBackToRemote(t *testing.T) {
	trusted := parseCIDRs(t, "10.0.0.0/8")
	r := &http.Request{RemoteAddr: "10.0.0.1:1234", Header: http.Header{}}
	ip := ClientIP(r, trusted, "X-Forwarded-For")
	if ip == nil || ip.String() != "10.0.0.1" {
		t.Errorf("ClientIP() = %v, want 10.0.0.1 (no header value)", ip)
	}
}

func TestClientIP_NoHeaderConfigured(t *testing.T) {
	trusted := parseCIDRs(t, "10.0.0.0/8")
	r := &http.Request{RemoteAddr: "10.0.0.1:1234", Header: http.Header{}}
	r.Header.Set("X-Forwarded-For", "203.0.113.9")
	ip := ClientIP(r, trusted, "")
	if ip == nil || ip.String() != "10.0.0.1" {
		t.Errorf("ClientIP() = %v, want remote addr when header is unconfigured", ip)
	}
}

func TestClientIP_InvalidRemoteAddr(t *testing.T) {
	r := &http.Request{RemoteAddr: "not-an-ip", Header: http.Header{}}
	ip := ClientIP(r, nil, "")
	if ip != nil {
		t.Errorf("ClientIP() = %v, want nil for invalid RemoteAddr", ip)
	}
}

func TestClientIP_RemoteAddrWithoutPort(t *testing.T) {
	// SplitHostPort fails without a port; ClientIP falls back to the raw value.
	r := &http.Request{RemoteAddr: "203.0.113.5", Header: http.Header{}}
	ip := ClientIP(r, nil, "")
	if ip == nil || ip.String() != "203.0.113.5" {
		t.Errorf("ClientIP() = %v, want 203.0.113.5", ip)
	}
}

func TestRateLimiter_AllowsUpToLimit(t *testing.T) {
	rl := NewRateLimiter(3, time.Minute)
	cur := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	rl.now = func() time.Time { return cur }

	for i := 0; i < 3; i++ {
		if !rl.Allow("key") {
			t.Fatalf("expected Allow() true on attempt %d", i+1)
		}
	}
	if rl.Allow("key") {
		t.Errorf("expected 4th Allow() to be rate-limited")
	}
}

func TestRateLimiter_WindowResets(t *testing.T) {
	rl := NewRateLimiter(1, time.Minute)
	cur := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	rl.now = func() time.Time { return cur }

	if !rl.Allow("key") {
		t.Fatalf("expected first Allow() true")
	}
	if rl.Allow("key") {
		t.Errorf("expected second Allow() within window to be denied")
	}

	cur = cur.Add(2 * time.Minute)
	if !rl.Allow("key") {
		t.Errorf("expected Allow() true after window reset")
	}
}

func TestRateLimiter_IndependentKeys(t *testing.T) {
	rl := NewRateLimiter(1, time.Minute)
	cur := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	rl.now = func() time.Time { return cur }

	if !rl.Allow("a") {
		t.Fatalf("expected Allow(a) true")
	}
	if !rl.Allow("b") {
		t.Errorf("expected Allow(b) true (independent key)")
	}
	if rl.Allow("a") {
		t.Errorf("expected second Allow(a) to be denied")
	}
}
