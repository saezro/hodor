package config

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
)

// ErrNotFound is returned by Live's overlay-mutating methods when asked
// to delete something that isn't in the overlay (it may still exist in
// base, which the caller - internal/admin - checks separately to answer
// 409 instead).
var ErrNotFound = errors.New("not found")

// Live holds the currently active, validated Config behind an
// atomic.Pointer, plus the machinery to swap it after a SIGHUP/API
// reload or a panel save (docs/DESIGN.md "2c. Panel config editing +
// hot reload"). Every consumer (proxy, admin, pin...) should call Get
// per request rather than caching the result: that's what makes a
// reload or a save take effect immediately, without a restart.
//
// Base hodor.yaml is parsed from BasePath but never rewritten; panel
// edits go to the resolved overlay file instead (see overlay.go).
// Listen addresses, secret_file and state_file are fixed at NewLive
// time: Reload refuses to apply changes to them (see Reload).
type Live struct {
	basePath    string
	overlayPath string

	ptr atomic.Pointer[Config]

	// saveMu serializes every write to the overlay file (and the reload
	// that reads it back), so two concurrent panel saves - or a save
	// racing a reload - can't interleave their read-modify-write of
	// managed.yaml.
	saveMu sync.Mutex
}

// NewLive loads basePath and its config_overlay for the first time and
// returns a Live ready to serve.
func NewLive(basePath string) (*Live, error) {
	merged, _, overlayPath, err := LoadWithOverlay(basePath)
	if err != nil {
		return nil, err
	}
	l := &Live{basePath: basePath, overlayPath: overlayPath}
	l.ptr.Store(merged)
	return l, nil
}

// Get returns the currently active, validated config.
func (l *Live) Get() *Config { return l.ptr.Load() }

// BasePath is the hodor.yaml path this Live was built from.
func (l *Live) BasePath() string { return l.basePath }

// OverlayPath is the resolved config_overlay path (base.ConfigOverlay
// with its default already applied).
func (l *Live) OverlayPath() string { return l.overlayPath }

// keepNonHotReloadable copies listen/secret_file/state_file from cur
// into next whenever they differ, since the already-running
// listeners/secret/state store can't pick up a change to those without
// a restart. Returns a human-readable warning per field that was reset,
// if any.
func keepNonHotReloadable(cur, next *Config) (warnings []string) {
	if next.Listen != cur.Listen {
		warnings = append(warnings, "listen changed on disk but is not hot-reloadable; restart hodor to apply it")
		next.Listen = cur.Listen
	}
	if next.SecretFile != cur.SecretFile {
		warnings = append(warnings, "secret_file changed on disk but is not hot-reloadable; restart hodor to apply it")
		next.SecretFile = cur.SecretFile
	}
	if next.StateFile != cur.StateFile {
		warnings = append(warnings, "state_file changed on disk but is not hot-reloadable; restart hodor to apply it")
		next.StateFile = cur.StateFile
	}
	return warnings
}

// Reload re-reads base + overlay from disk, validates the result and,
// if valid, swaps it in. If the newly read config disagrees with the
// live one on listen, secret_file or state_file, those fields are kept
// as they are (with a warning) instead of applied: the listeners,
// secret and state store are already running against the old values.
func (l *Live) Reload() (warnings []string, err error) {
	l.saveMu.Lock()
	defer l.saveMu.Unlock()

	cur := l.Get()
	next, _, _, err := LoadWithOverlay(l.basePath)
	if err != nil {
		return nil, err
	}
	warnings = keepNonHotReloadable(cur, next)
	l.ptr.Store(next)
	return warnings, nil
}

// mutateOverlay is the shared core of every panel write: under saveMu,
// it re-reads base + overlay from disk (so a save can't silently
// clobber a concurrent edit made some other way), lets fn mutate the
// overlay in place, re-merges and validates the result, writes the
// overlay atomically only if that succeeds, and swaps the live config
// in. On any error, the overlay file and the live config are both left
// untouched.
func (l *Live) mutateOverlay(fn func(base *Config, ov *Overlay) error) (*Config, error) {
	l.saveMu.Lock()
	defer l.saveMu.Unlock()

	base, err := Load(l.basePath)
	if err != nil {
		return nil, err
	}
	ov, err := LoadOverlay(l.overlayPath)
	if err != nil {
		return nil, err
	}
	if err := fn(base, ov); err != nil {
		return nil, err
	}

	merged := MergeOverlay(base, ov)
	if err := merged.Validate(); err != nil {
		return nil, err
	}
	// Defensive: the overlay never touches these, but keep the running
	// values authoritative regardless of what base now says on disk.
	keepNonHotReloadable(l.Get(), merged)

	if err := SaveOverlay(l.overlayPath, ov); err != nil {
		return nil, err
	}
	l.ptr.Store(merged)
	return merged, nil
}

// PutService creates or replaces the overlay entry named svc.Name
// (overwriting any earlier overlay entry with that name; a base service
// of the same name is shadowed, not merged field-by-field).
func (l *Live) PutService(svc Service) (*Config, error) {
	svc.Source = ""
	return l.mutateOverlay(func(_ *Config, ov *Overlay) error {
		for i := range ov.Services {
			if ov.Services[i].Name == svc.Name {
				ov.Services[i] = svc
				return nil
			}
		}
		ov.Services = append(ov.Services, svc)
		return nil
	})
}

// DeleteService removes name from the overlay. ErrNotFound if it isn't
// there (it may still be a base service, which callers must check for
// separately before calling this, since that's a 409 not a 404).
func (l *Live) DeleteService(name string) (*Config, error) {
	return l.mutateOverlay(func(_ *Config, ov *Overlay) error {
		for i := range ov.Services {
			if ov.Services[i].Name == name {
				ov.Services = append(ov.Services[:i], ov.Services[i+1:]...)
				return nil
			}
		}
		return ErrNotFound
	})
}

// SetDurations replaces the overlay's durations list wholesale. An
// empty list clears the override (merged config falls back to base's
// durations).
func (l *Live) SetDurations(durations []string) (*Config, error) {
	return l.mutateOverlay(func(_ *Config, ov *Overlay) error {
		ov.Durations = append([]string(nil), durations...)
		return nil
	})
}

// AddAPIKey appends k (with its ID set to id) to the overlay's
// api_keys. It errors if id already names a key in either base or the
// overlay: ids are meant to be unique, and MergeOverlay treats a
// matching id as "replace this key", not "add a second one".
func (l *Live) AddAPIKey(id string, k APIKey) (*Config, error) {
	k.ID = id
	k.Source = ""
	return l.mutateOverlay(func(base *Config, ov *Overlay) error {
		for _, existing := range base.APIKeys {
			if existing.ID == id {
				return fmt.Errorf("api_keys[%s]: id already exists", id)
			}
		}
		for _, existing := range ov.APIKeys {
			if existing.ID == id {
				return fmt.Errorf("api_keys[%s]: id already exists", id)
			}
		}
		ov.APIKeys = append(ov.APIKeys, k)
		return nil
	})
}

// DeleteAPIKey removes id from the overlay's api_keys. ErrNotFound if
// it isn't there (it may still be a base key, a 409 not a 404).
func (l *Live) DeleteAPIKey(id string) (*Config, error) {
	return l.mutateOverlay(func(_ *Config, ov *Overlay) error {
		for i := range ov.APIKeys {
			if ov.APIKeys[i].ID == id {
				ov.APIKeys = append(ov.APIKeys[:i], ov.APIKeys[i+1:]...)
				return nil
			}
		}
		return ErrNotFound
	})
}

// NewLiveFrom wraps an already-built, already-validated Config as a
// Live with no backing files: Get works, but Reload/the overlay
// mutators all fail against basePath "" (there is nothing on disk to
// read). Used by tests that build a Config in-memory instead of from a
// real hodor.yaml.
func NewLiveFrom(cfg *Config) *Live {
	l := &Live{}
	l.ptr.Store(cfg)
	return l
}
