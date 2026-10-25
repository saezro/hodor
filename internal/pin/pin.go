// Package pin implements the device-pairing PIN flow: a TV (or any
// keyboard-less device) requests a 6-digit PIN for a service, an admin
// approves it from the panel, and the device's polling request then
// learns it was approved so the caller can issue it a pass.
package pin

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"
)

// ErrNotFound is returned by Approve when no pending PIN matches code.
var ErrNotFound = errors.New("pin: no matching pending PIN")

// ErrAmbiguous is returned by Approve when code matches more than one
// pending PIN, so approving it could approve the wrong device.
var ErrAmbiguous = errors.New("pin: code matches more than one pending PIN")

// errCodeExhausted is an internal sentinel for when Create cannot find a
// code that is not already in use among pending, non-expired entries
// after maxCodeAttempts tries.
var errCodeExhausted = errors.New("pin: could not generate a unique code")

// ErrTooManyPending is returned by Create when there are already
// maxPendingPins non-expired entries, to bound memory and prevent abuse
// from a flood of PIN requests.
var ErrTooManyPending = errors.New("pin: too many pending PINs")

const ttl = 10 * time.Minute

// maxPendingPins bounds how many non-expired entries Create allows at
// once (expired ones are purged before counting, so this only limits
// genuinely live PINs).
const maxPendingPins = 100

// maxCodeAttempts bounds retries when Create regenerates a colliding
// code; with a 6-digit space and few pending PINs at once, collisions
// are rare enough that this is effectively never hit in practice.
const maxCodeAttempts = 20

// Clock abstracts time.Now for tests.
type Clock interface{ Now() time.Time }

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

// Entry is one pending or resolved PIN.
type Entry struct {
	SessionID string
	Code      string
	Service   string
	CreatedAt time.Time
	ExpiresAt time.Time
	Approved  bool
}

func (e Entry) expired(now time.Time) bool { return !now.Before(e.ExpiresAt) }

// Manager tracks pending PINs in memory (deliberately not persisted:
// they are short-lived and meaningless after a restart).
type Manager struct {
	mu    sync.Mutex
	clock Clock
	byID  map[string]*Entry
}

// New returns a Manager. clock may be nil to use the real wall clock.
func New(clock Clock) *Manager {
	if clock == nil {
		clock = realClock{}
	}
	return &Manager{clock: clock, byID: make(map[string]*Entry)}
}

// Create generates a new pending PIN for service and returns its entry.
// The code is regenerated until it is unique among currently pending,
// non-expired entries (a collision would otherwise make Approve
// ambiguous about which device to approve).
func (m *Manager) Create(service string) (*Entry, error) {
	sid, err := randomHex(16)
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.clock.Now()
	m.gcLocked(now)

	if len(m.byID) >= maxPendingPins {
		return nil, ErrTooManyPending
	}

	var code string
	for attempt := 0; ; attempt++ {
		c, err := randomCode()
		if err != nil {
			return nil, err
		}
		if !m.codeInUseLocked(c, now) {
			code = c
			break
		}
		if attempt+1 >= maxCodeAttempts {
			return nil, errCodeExhausted
		}
	}

	e := &Entry{
		SessionID: sid,
		Code:      code,
		Service:   service,
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
	}
	m.byID[sid] = e
	m.gcLocked(now)
	cp := *e
	return &cp, nil
}

// Get returns a copy of the entry for sessionID, if present and not
// expired.
func (m *Manager) Get(sessionID string) (Entry, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e, ok := m.byID[sessionID]
	if !ok || e.expired(m.clock.Now()) {
		return Entry{}, false
	}
	return *e, true
}

// Pending lists all non-expired, non-approved PINs (for the admin
// panel).
func (m *Manager) Pending() []Entry {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.clock.Now()
	var out []Entry
	for _, e := range m.byID {
		if !e.Approved && !e.expired(now) {
			out = append(out, *e)
		}
	}
	return out
}

// Approve marks the pending PIN matching code as approved and returns
// its entry. Code comparison is constant-time. If code matches more
// than one pending entry (which Create's uniqueness check should make
// exceedingly rare, but two entries could still collide if one expires
// and is GC'd between checks, or under a bug), Approve refuses to guess
// which device to approve and returns ErrAmbiguous rather than
// approving an arbitrary one of them. Brute-force protection against
// repeated wrong codes is the caller's responsibility (see
// auth.RateLimiter, applied per client IP in the admin handler).
func (m *Manager) Approve(code string) (Entry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.clock.Now()

	var match *Entry
	ambiguous := false
	for _, e := range m.byID {
		if e.expired(now) || e.Approved {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(e.Code), []byte(code)) == 1 {
			if match != nil {
				ambiguous = true
				continue
			}
			match = e
		}
	}

	if ambiguous {
		return Entry{}, ErrAmbiguous
	}
	if match == nil {
		return Entry{}, ErrNotFound
	}
	match.Approved = true
	return *match, nil
}

// codeInUseLocked reports whether code is already used by a pending,
// non-expired entry. Caller must hold m.mu.
func (m *Manager) codeInUseLocked(code string, now time.Time) bool {
	for _, e := range m.byID {
		if e.expired(now) || e.Approved {
			continue
		}
		if e.Code == code {
			return true
		}
	}
	return false
}

// Consume removes sessionID so a later poll sees it as gone (used once a
// pass has been issued for it, so the same approval cannot issue a second
// pass).
func (m *Manager) Consume(sessionID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.byID, sessionID)
}

// gcLocked drops expired entries. Caller must hold m.mu.
func (m *Manager) gcLocked(now time.Time) {
	for id, e := range m.byID {
		if e.expired(now) {
			delete(m.byID, id)
		}
	}
}

func randomCode() (string, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("pin: generate code: %w", err)
	}
	n := binary.BigEndian.Uint32(b[:]) % 1000000
	return fmt.Sprintf("%06d", n), nil
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("pin: generate id: %w", err)
	}
	const hexChars = "0123456789abcdef"
	out := make([]byte, n*2)
	for i, c := range b {
		out[i*2] = hexChars[c>>4]
		out[i*2+1] = hexChars[c&0x0f]
	}
	return string(out), nil
}
