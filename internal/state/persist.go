package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// load reads the state file from disk if it exists. A missing file is
// not an error: the store simply starts empty (default closed).
func (s *Store) load() error {
	raw, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("read state file %s: %w", s.path, err)
	}
	if len(raw) == 0 {
		return nil
	}
	var d data
	if err := json.Unmarshal(raw, &d); err != nil {
		return fmt.Errorf("parse state file %s: %w", s.path, err)
	}
	if d.Services != nil {
		s.d.Services = d.Services
	}
	if d.Passes != nil {
		s.d.Passes = d.Passes
	}
	s.d.Events = d.Events
	return nil
}

// saveLocked writes the current state to disk atomically (write to a
// temp file in the same directory, then rename). Caller must hold s.mu.
func (s *Store) saveLocked() error {
	raw, err := json.MarshalIndent(s.d, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal state: %w", err)
	}

	dir := filepath.Dir(s.path)
	if dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create state dir %s: %w", dir, err)
		}
	}

	tmp, err := os.CreateTemp(dir, ".hodor-state-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp state file: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }() // no-op once rename succeeds

	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write temp state file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp state file: %w", err)
	}
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		return fmt.Errorf("chmod temp state file: %w", err)
	}
	if err := os.Rename(tmpPath, s.path); err != nil {
		return fmt.Errorf("rename temp state file to %s: %w", s.path, err)
	}
	return nil
}
