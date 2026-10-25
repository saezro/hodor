package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Overlay is the panel-editable counterpart to hodor.yaml (see
// docs/DESIGN.md "2c. Panel config editing + hot reload"): services
// added or edited, durations and api_keys set from the admin panel live
// here instead, so the base file stays hand-owned and is never
// rewritten by hodor itself.
type Overlay struct {
	Services  []Service `yaml:"services"`
	Durations []string  `yaml:"durations"`
	APIKeys   []APIKey  `yaml:"api_keys"`
}

// OverlayPath resolves base.ConfigOverlay, defaulting to
// "managed.yaml" next to base.StateFile (mirroring the state_file
// default applied by Validate, in case base hasn't been validated yet).
func OverlayPath(base *Config) string {
	if base.ConfigOverlay != "" {
		return base.ConfigOverlay
	}
	stateFile := base.StateFile
	if stateFile == "" {
		stateFile = "/data/state.json"
	}
	return filepath.Join(filepath.Dir(stateFile), "managed.yaml")
}

// LoadOverlay reads and parses the overlay YAML at path. A missing file
// is not an error: it just means no overlay has been saved yet.
func LoadOverlay(path string) (*Overlay, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path comes from this process's own config, not request input
	if err != nil {
		if os.IsNotExist(err) {
			return &Overlay{}, nil
		}
		return nil, fmt.Errorf("read config_overlay %s: %w", path, err)
	}
	var ov Overlay
	if err := yaml.Unmarshal(data, &ov); err != nil {
		return nil, fmt.Errorf("parse config_overlay %s: %w", path, err)
	}
	return &ov, nil
}

// SaveOverlay writes ov to path atomically (tmp file in the same
// directory, then rename) with mode 0600, creating the parent directory
// if needed.
func SaveOverlay(path string, ov *Overlay) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil { // #nosec G301 -- overlay dir only ever holds hodor's own state/config
		return fmt.Errorf("config_overlay: mkdir %s: %w", dir, err)
	}
	data, err := yaml.Marshal(ov)
	if err != nil {
		return fmt.Errorf("config_overlay: marshal: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".managed-*.yaml.tmp")
	if err != nil {
		return fmt.Errorf("config_overlay: create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }() // no-op once the rename below succeeds

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("config_overlay: write temp file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("config_overlay: close temp file: %w", err)
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		return fmt.Errorf("config_overlay: chmod: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("config_overlay: rename into place: %w", err)
	}
	return nil
}

// MergeOverlay merges ov on top of base, returning a new, independent
// Config: services/durations/api_keys only (everything else - listen,
// secret, state_file... - only ever comes from base). An overlay
// service with the same name as a base one replaces it; durations
// replace base's wholesale if non-empty; api_keys merge by id, overlay
// winning on conflict. Every merged service/key is tagged with its
// Source ("base" or "overlay"). The returned Config's Parsed* fields are
// cleared so the caller can call Validate on it fresh.
func MergeOverlay(base *Config, ov *Overlay) *Config {
	merged := *base
	merged.ParsedDurations = nil
	merged.ParsedPassTTL = 0
	merged.Admin.ParsedCIDRs = nil
	merged.Admin.ParsedProxies = nil
	merged.Public.ParsedProxies = nil

	svcIndex := make(map[string]int, len(base.Services)+len(ov.Services))
	services := make([]Service, 0, len(base.Services)+len(ov.Services))
	for _, s := range base.Services {
		s.Source = "base"
		services = append(services, s)
		svcIndex[s.Name] = len(services) - 1
	}
	for _, s := range ov.Services {
		s.Source = "overlay"
		if i, ok := svcIndex[s.Name]; ok {
			services[i] = s
		} else {
			services = append(services, s)
			svcIndex[s.Name] = len(services) - 1
		}
	}
	merged.Services = services

	if len(ov.Durations) > 0 {
		merged.Durations = append([]string(nil), ov.Durations...)
	} else {
		merged.Durations = append([]string(nil), base.Durations...)
	}

	// keyIndex only ever maps ids that came from base: an overlay entry
	// may override one of those (by id) exactly once. A second overlay
	// entry with that same id - or two overlay entries sharing an id
	// not in base at all - is a duplicate-id mistake in the overlay
	// itself, so it is appended rather than silently merged into the
	// earlier slot; Validate's own duplicate-id check then catches it.
	keyIndex := make(map[string]int, len(base.APIKeys))
	keys := make([]APIKey, 0, len(base.APIKeys)+len(ov.APIKeys))
	for _, k := range base.APIKeys {
		k.Source = "base"
		keys = append(keys, k)
		keyIndex[k.ID] = len(keys) - 1
	}
	overriddenFromBase := map[string]bool{}
	for _, k := range ov.APIKeys {
		k.Source = "overlay"
		if i, ok := keyIndex[k.ID]; ok && !overriddenFromBase[k.ID] {
			keys[i] = k
			overriddenFromBase[k.ID] = true
		} else {
			keys = append(keys, k)
		}
	}
	merged.APIKeys = keys

	return &merged
}

// LoadWithOverlay loads and validates the base config at basePath, then
// merges in its config_overlay and validates the result too. It returns
// the merged (live) config, the validated base alone (listen, secret,
// state_file... are only ever read from this one) and the resolved
// overlay path.
func LoadWithOverlay(basePath string) (merged, base *Config, overlayPath string, err error) {
	base, err = Load(basePath)
	if err != nil {
		return nil, nil, "", err
	}
	overlayPath = OverlayPath(base)
	ov, err := LoadOverlay(overlayPath)
	if err != nil {
		return nil, nil, "", err
	}
	merged = MergeOverlay(base, ov)
	if err := merged.Validate(); err != nil {
		return nil, nil, "", fmt.Errorf("merged config (base + overlay %s): %w", overlayPath, err)
	}
	return merged, base, overlayPath, nil
}
