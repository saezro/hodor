package config

import (
	"os"
	"path/filepath"
	"testing"
)

// baseWithTwoServices returns an already-validated base Config with
// two services, "svc1" and "svc2", used across the merge tests below.
func baseWithTwoServices(t *testing.T) *Config {
	t.Helper()
	c := &Config{
		Durations: []string{"1h", "3h"},
		Services: []Service{
			{Name: "svc1", Hosts: []string{"svc1.example.com"}, Mode: ModeProxy, Upstream: "http://127.0.0.1:9001"},
			{Name: "svc2", Hosts: []string{"svc2.example.com"}, Mode: ModeProxy, Upstream: "http://127.0.0.1:9002"},
		},
		APIKeys: []APIKey{
			{ID: "a", Name: "key a", Hash: strVal(64, 'a'), Services: []string{"svc1"}, Actions: []string{KeyActionStatus}},
		},
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate base: %v", err)
	}
	return c
}

func strVal(n int, b byte) string {
	buf := make([]byte, n)
	for i := range buf {
		buf[i] = b
	}
	return string(buf)
}

func TestMergeOverlay_ServiceOverrideAddAndSource(t *testing.T) {
	base := baseWithTwoServices(t)
	ov := &Overlay{
		Services: []Service{
			// overrides svc2's upstream, replacing it wholesale.
			{Name: "svc2", Hosts: []string{"svc2.example.com"}, Mode: ModeProxy, Upstream: "http://127.0.0.1:9999"},
			// brand new overlay-only service.
			{Name: "svc3", Hosts: []string{"svc3.example.com"}, Mode: ModeProxy, Upstream: "http://127.0.0.1:9003"},
		},
	}

	merged := MergeOverlay(base, ov)
	if err := merged.Validate(); err != nil {
		t.Fatalf("Validate merged: %v", err)
	}

	byName := map[string]Service{}
	for _, s := range merged.Services {
		byName[s.Name] = s
	}

	if got := byName["svc1"].Source; got != "base" {
		t.Errorf("svc1.Source = %q, want base", got)
	}
	svc2 := byName["svc2"]
	if svc2.Source != "overlay" {
		t.Errorf("svc2.Source = %q, want overlay", svc2.Source)
	}
	if svc2.Upstream != "http://127.0.0.1:9999" {
		t.Errorf("svc2.Upstream = %q, want overridden value", svc2.Upstream)
	}
	if byName["svc3"].Source != "overlay" {
		t.Errorf("svc3.Source = %q, want overlay", byName["svc3"].Source)
	}
	if len(merged.Services) != 3 {
		t.Fatalf("len(merged.Services) = %d, want 3", len(merged.Services))
	}

	// base itself must stay untouched by the merge.
	if len(base.Services) != 2 {
		t.Fatalf("base.Services mutated by MergeOverlay: len = %d", len(base.Services))
	}
}

func TestMergeOverlay_DurationsFallbackAndOverride(t *testing.T) {
	base := baseWithTwoServices(t)

	merged := MergeOverlay(base, &Overlay{})
	if len(merged.Durations) != 2 || merged.Durations[0] != "1h" {
		t.Errorf("empty overlay durations = %v, want base's [1h 3h]", merged.Durations)
	}

	merged = MergeOverlay(base, &Overlay{Durations: []string{"30m"}})
	if len(merged.Durations) != 1 || merged.Durations[0] != "30m" {
		t.Errorf("overlay durations = %v, want [30m]", merged.Durations)
	}
}

func TestMergeOverlay_APIKeysMergeByID(t *testing.T) {
	base := baseWithTwoServices(t)
	ov := &Overlay{
		APIKeys: []APIKey{
			// replaces base key "a".
			{ID: "a", Name: "key a overridden", Hash: strVal(64, 'b'), Services: []string{"svc1"}, Actions: []string{KeyActionOpen}},
			// brand new overlay-only key.
			{ID: "b", Name: "key b", Hash: strVal(64, 'c'), Services: []string{"svc2"}, Actions: []string{KeyActionClose}},
		},
	}

	merged := MergeOverlay(base, ov)
	if err := merged.Validate(); err != nil {
		t.Fatalf("Validate merged: %v", err)
	}

	byID := map[string]APIKey{}
	for _, k := range merged.APIKeys {
		byID[k.ID] = k
	}
	if len(byID) != 2 {
		t.Fatalf("len(merged.APIKeys) = %d, want 2", len(byID))
	}
	a := byID["a"]
	if a.Source != "overlay" || a.Name != "key a overridden" {
		t.Errorf("key a = %+v, want overlay override", a)
	}
	b := byID["b"]
	if b.Source != "overlay" {
		t.Errorf("key b.Source = %q, want overlay", b.Source)
	}
}

func TestMergeOverlay_DuplicateIDWithinOverlay_CaughtByValidate(t *testing.T) {
	base := baseWithTwoServices(t)
	ov := &Overlay{
		APIKeys: []APIKey{
			// both brand new (id "c" is not in base) and sharing an id:
			// must not be silently merged into one entry.
			{ID: "c", Name: "key c1", Hash: strVal(64, 'd'), Services: []string{"svc1"}, Actions: []string{KeyActionStatus}},
			{ID: "c", Name: "key c2", Hash: strVal(64, 'e'), Services: []string{"svc2"}, Actions: []string{KeyActionStatus}},
		},
	}

	merged := MergeOverlay(base, ov)
	if err := merged.Validate(); err == nil {
		t.Fatalf("Validate merged with duplicate overlay api key id: want error, got nil")
	}
}

func TestLoadWithOverlay_MergesFromDisk(t *testing.T) {
	dir := t.TempDir()
	basePath := filepath.Join(dir, "hodor.yaml")
	overlayPath := filepath.Join(dir, "managed.yaml")

	baseYAML := "state_file: " + filepath.Join(dir, "state.json") + "\n" +
		"config_overlay: " + overlayPath + "\n" +
		"services:\n" +
		"  - name: svc1\n" +
		"    hosts: [svc1.example.com]\n" +
		"    upstream: http://127.0.0.1:9001\n"
	if err := os.WriteFile(basePath, []byte(baseYAML), 0o600); err != nil {
		t.Fatalf("write base: %v", err)
	}

	overlayYAML := "services:\n" +
		"  - name: svc2\n" +
		"    hosts: [svc2.example.com]\n" +
		"    upstream: http://127.0.0.1:9002\n"
	if err := os.WriteFile(overlayPath, []byte(overlayYAML), 0o600); err != nil {
		t.Fatalf("write overlay: %v", err)
	}

	merged, base, gotOverlayPath, err := LoadWithOverlay(basePath)
	if err != nil {
		t.Fatalf("LoadWithOverlay: %v", err)
	}
	if gotOverlayPath != overlayPath {
		t.Errorf("overlayPath = %q, want %q", gotOverlayPath, overlayPath)
	}
	if len(base.Services) != 1 {
		t.Errorf("base.Services = %d, want 1 (overlay must not leak into base)", len(base.Services))
	}
	if len(merged.Services) != 2 {
		t.Fatalf("merged.Services = %d, want 2", len(merged.Services))
	}
}
