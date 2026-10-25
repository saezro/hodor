// Package pass implements device passes: long-lived, HMAC-signed cookie
// tokens that let a device reach a service without going through the
// open/closed gate (used by the TV pass flow and any paired phone).
package pass

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// ErrInvalid is returned by Verify for any malformed, expired or
// mis-signed token.
var ErrInvalid = errors.New("pass: invalid token")

// CookieName returns the per-service cookie name, e.g. hodor_pass_geo.
func CookieName(service string) string {
	return "hodor_pass_" + service
}

// NewID returns a random, URL-safe pass identifier.
func NewID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("pass: generate id: %w", err)
	}
	return hex.EncodeToString(raw), nil
}

// Issue builds a signed cookie value for a pass with the given id,
// service and expiry. The token format is:
//
//	base64url(id|service|expiryUnix) + "." + hex(hmacSHA256)
func Issue(secret []byte, id, service string, expiry time.Time) string {
	payload := encodePayload(id, service, expiry)
	mac := sign(secret, payload)
	return payload + "." + hex.EncodeToString(mac)
}

// Verify checks token's signature and expiry and, if valid, returns the
// pass id and service it was issued for.
func Verify(secret []byte, token string) (id, service string, err error) {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return "", "", ErrInvalid
	}
	payload, sigHex := parts[0], parts[1]
	sig, err := hex.DecodeString(sigHex)
	if err != nil {
		return "", "", ErrInvalid
	}
	want := sign(secret, payload)
	if !hmac.Equal(sig, want) {
		return "", "", ErrInvalid
	}

	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return "", "", ErrInvalid
	}
	fields := strings.SplitN(string(raw), "|", 3)
	if len(fields) != 3 {
		return "", "", ErrInvalid
	}
	expiryUnix, err := strconv.ParseInt(fields[2], 10, 64)
	if err != nil {
		return "", "", ErrInvalid
	}
	if time.Now().After(time.Unix(expiryUnix, 0)) {
		return "", "", ErrInvalid
	}
	return fields[0], fields[1], nil
}

func encodePayload(id, service string, expiry time.Time) string {
	raw := id + "|" + service + "|" + strconv.FormatInt(expiry.Unix(), 10)
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

func sign(secret []byte, payload string) []byte {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(payload))
	return mac.Sum(nil)
}

// ConstantTimeEqual compares two strings in constant time, for anything
// compared outside of Verify's HMAC check (e.g. admin bearer tokens).
func ConstantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
