package pass

import (
	"testing"
	"time"
)

func TestIssueVerify_RoundTrip(t *testing.T) {
	secret := []byte("super-secret-key")
	token := Issue(secret, "id1", "svc1", time.Now().Add(time.Hour))

	id, service, err := Verify(secret, token)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if id != "id1" || service != "svc1" {
		t.Errorf("Verify() = %q, %q, want id1, svc1", id, service)
	}
}

func TestVerify_TamperedPayload(t *testing.T) {
	secret := []byte("super-secret-key")
	token := Issue(secret, "id1", "svc1", time.Now().Add(time.Hour))

	// Flip the service by issuing a new payload but keeping the old sig.
	parts := splitToken(t, token)
	tampered := Issue(secret, "id1", "svc2", time.Now().Add(time.Hour))
	tamperedParts := splitToken(t, tampered)
	forged := tamperedParts[0] + "." + parts[1] // mismatched payload/sig

	if _, _, err := Verify(secret, forged); err != ErrInvalid {
		t.Errorf("Verify(tampered) err = %v, want ErrInvalid", err)
	}
}

func TestVerify_WrongSecret(t *testing.T) {
	token := Issue([]byte("secret-a"), "id1", "svc1", time.Now().Add(time.Hour))
	if _, _, err := Verify([]byte("secret-b"), token); err != ErrInvalid {
		t.Errorf("Verify(wrong secret) err = %v, want ErrInvalid", err)
	}
}

func TestVerify_Expired(t *testing.T) {
	secret := []byte("super-secret-key")
	token := Issue(secret, "id1", "svc1", time.Now().Add(-time.Minute))
	if _, _, err := Verify(secret, token); err != ErrInvalid {
		t.Errorf("Verify(expired) err = %v, want ErrInvalid", err)
	}
}

func TestVerify_Malformed(t *testing.T) {
	secret := []byte("super-secret-key")
	tests := []string{
		"",
		"no-dot-separator",
		"payload.not-hex-sig",
		"!!!invalidbase64!!!.deadbeef",
	}
	for _, tok := range tests {
		if _, _, err := Verify(secret, tok); err != ErrInvalid {
			t.Errorf("Verify(%q) err = %v, want ErrInvalid", tok, err)
		}
	}
}

func TestCookieName(t *testing.T) {
	if got := CookieName("jellyfin"); got != "hodor_pass_jellyfin" {
		t.Errorf("CookieName() = %q", got)
	}
}

func TestNewID_Unique(t *testing.T) {
	a, err := NewID()
	if err != nil {
		t.Fatalf("NewID: %v", err)
	}
	b, err := NewID()
	if err != nil {
		t.Fatalf("NewID: %v", err)
	}
	if a == b {
		t.Errorf("NewID() produced duplicate IDs")
	}
	if len(a) != 32 { // 16 random bytes hex-encoded
		t.Errorf("NewID() len = %d, want 32", len(a))
	}
}

func TestConstantTimeEqual(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"same", "same", true},
		{"same", "different", false},
		{"", "", true},
		{"a", "", false},
	}
	for _, tt := range tests {
		if got := ConstantTimeEqual(tt.a, tt.b); got != tt.want {
			t.Errorf("ConstantTimeEqual(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}

// splitToken is a tiny test helper around the "payload.sig" token format.
func splitToken(t *testing.T, token string) [2]string {
	t.Helper()
	for i := 0; i < len(token); i++ {
		if token[i] == '.' {
			return [2]string{token[:i], token[i+1:]}
		}
	}
	t.Fatalf("token %q has no separator", token)
	return [2]string{}
}
