package apikey

import (
	"strings"
	"testing"

	"github.com/saezro/hodor/internal/config"
)

func TestGenerate_Format(t *testing.T) {
	key, hashHex, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if !strings.HasPrefix(key, keyPrefix) {
		t.Errorf("key %q missing prefix %q", key, keyPrefix)
	}
	if len(hashHex) != 64 {
		t.Errorf("hashHex len = %d, want 64", len(hashHex))
	}
	if got := Hash(key); got != hashHex {
		t.Errorf("Hash(key) = %q, want %q", got, hashHex)
	}

	key2, _, err := Generate()
	if err != nil {
		t.Fatalf("Generate (2nd): %v", err)
	}
	if key2 == key {
		t.Errorf("two calls to Generate produced the same key")
	}
}

func TestMatch(t *testing.T) {
	key, hashHex, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	keys := []config.APIKey{
		{ID: "a", Name: "a", Hash: strings.Repeat("0", 64)},
		{ID: "b", Name: "b", Hash: hashHex},
	}

	got := Match(keys, key)
	if got == nil || got.ID != "b" {
		t.Fatalf("Match(correct key) = %+v, want id b", got)
	}

	if got := Match(keys, "wrong-key"); got != nil {
		t.Errorf("Match(wrong key) = %+v, want nil", got)
	}

	if got := Match(keys, ""); got != nil {
		t.Errorf("Match(empty) = %+v, want nil", got)
	}

	if got := Match(nil, key); got != nil {
		t.Errorf("Match(no keys) = %+v, want nil", got)
	}
}

func TestAllows(t *testing.T) {
	svcDirect := config.Service{Name: "jellyfin"}
	svcGrouped := config.Service{Name: "navidrome", Group: "media"}

	tests := []struct {
		name string
		key  config.APIKey
		svc  config.Service
		act  string
		want bool
	}{
		{"direct service name match", config.APIKey{Services: []string{"jellyfin"}, Actions: []string{"status"}}, svcDirect, "status", true},
		{"group match", config.APIKey{Services: []string{"media"}, Actions: []string{"open"}}, svcGrouped, "open", true},
		{"wildcard service", config.APIKey{Services: []string{"*"}, Actions: []string{"close"}}, svcDirect, "close", true},
		{"wrong action", config.APIKey{Services: []string{"jellyfin"}, Actions: []string{"status"}}, svcDirect, "open", false},
		{"service not covered", config.APIKey{Services: []string{"other"}, Actions: []string{"status"}}, svcDirect, "status", false},
		{"group name does not match direct service without group", config.APIKey{Services: []string{"media"}, Actions: []string{"status"}}, svcDirect, "status", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Allows(tt.key, tt.svc, tt.act); got != tt.want {
				t.Errorf("Allows() = %v, want %v", got, tt.want)
			}
		})
	}
}
