// Package apikey implements scoped API keys for hodor's versioned
// /api/v1 endpoints: generation, hashing and constant-time matching
// against internal/config.APIKey entries.
package apikey

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/saezro/hodor/internal/config"
)

// keyBytes is the amount of random entropy in a generated key.
const keyBytes = 32

// keyPrefix tags generated keys so they are recognizable in logs,
// shell history, etc. without revealing anything about the secret.
const keyPrefix = "hdr_"

// Generate returns a new random key together with its sha256 hash
// (lowercase hex), as stored in config.APIKey.Hash. The raw key is
// shown to the operator once, at creation time; only hashHex is ever
// persisted.
func Generate() (key, hashHex string, err error) {
	raw := make([]byte, keyBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", "", fmt.Errorf("apikey: generate: %w", err)
	}
	key = keyPrefix + base64.RawURLEncoding.EncodeToString(raw)
	return key, Hash(key), nil
}

// Hash returns the sha256 hex digest of key, as stored in
// config.APIKey.Hash.
func Hash(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

// Match looks for the entry in keys whose hash matches presented,
// comparing every entry in constant time (no early return on the
// first match) so that the time taken does not leak which, if any,
// key index matched. It returns nil if presented matches none of
// them.
func Match(keys []config.APIKey, presented string) *config.APIKey {
	if presented == "" {
		return nil
	}
	presentedHash := sha256.Sum256([]byte(presented))

	var found *config.APIKey
	for i := range keys {
		wantHash, err := hex.DecodeString(keys[i].Hash)
		if err != nil || len(wantHash) != len(presentedHash) {
			continue
		}
		if subtle.ConstantTimeCompare(presentedHash[:], wantHash) == 1 {
			found = &keys[i]
		}
	}
	return found
}

// Allows reports whether API key k is scoped to perform action on
// service svc: svc.Name, svc.Group or the wildcard "*" must appear in
// k.Services, and action must appear in k.Actions.
func Allows(k config.APIKey, svc config.Service, action string) bool {
	actionOK := false
	for _, a := range k.Actions {
		if a == action {
			actionOK = true
			break
		}
	}
	if !actionOK {
		return false
	}

	for _, s := range k.Services {
		if s == "*" || s == svc.Name || (svc.Group != "" && s == svc.Group) {
			return true
		}
	}
	return false
}
