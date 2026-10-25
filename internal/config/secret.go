package config

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
)

// loadOrCreateSecret reads the HMAC secret from path, generating a new
// random 32-byte secret (base64-encoded, file mode 0600) on first run if
// the file does not exist yet.
func loadOrCreateSecret(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		if len(data) < 32 {
			return nil, fmt.Errorf("secret_file %s: too short (want >= 32 bytes, got %d)", path, len(data))
		}
		return data, nil
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read secret_file %s: %w", path, err)
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, fmt.Errorf("generate secret: %w", err)
	}
	encoded := []byte(base64.StdEncoding.EncodeToString(raw))

	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("create secret dir %s: %w", dir, err)
		}
	}
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		return nil, fmt.Errorf("write secret_file %s: %w", path, err)
	}
	return encoded, nil
}
