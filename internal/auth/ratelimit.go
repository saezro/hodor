package auth

import (
	"sync"
	"time"
)

// maxRateLimiterKeys bounds how many distinct keys a RateLimiter keeps
// buckets for at once. Without a cap, an attacker who can make Allow see
// an arbitrary, attacker-controlled key (e.g. one derived from a
// spoofable header) could grow the map without bound and exhaust
// memory. Once the cap is hit, the periodic sweep in Allow is given a
// chance to drop expired buckets first; if the map is still full after
// that, new keys are simply not tracked and their calls are allowed
// through rather than panicking or blocking (failing open on unrelated
// keys is less bad than an OOM taking down every other key's limiting
// too).
const maxRateLimiterKeys = 10000

// sweepEvery makes Allow prune expired buckets roughly every N calls
// instead of on every call, so the periodic cleanup cost stays
// amortized rather than making every request pay for a full map scan.
const sweepEvery = 256

// RateLimiter is a minimal fixed-window limiter keyed by an arbitrary
// string (typically a client IP). It is intentionally simple: hodor's
// surface is small (PIN verification, admin login) and does not need a
// sliding window or token bucket.
type RateLimiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	hits   map[string]*bucket
	now    func() time.Time
	calls  uint64
}

type bucket struct {
	count     int
	windowEnd time.Time
}

// NewRateLimiter returns a limiter allowing up to limit calls per window
// for a given key.
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		limit:  limit,
		window: window,
		hits:   make(map[string]*bucket),
		now:    time.Now,
	}
}

// Allow reports whether key may perform another action right now, and
// records the attempt if so.
func (r *RateLimiter) Allow(key string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := r.now()
	r.calls++
	if r.calls%sweepEvery == 0 {
		r.sweepLocked(now)
	}

	b, ok := r.hits[key]
	if !ok || now.After(b.windowEnd) {
		if !ok && len(r.hits) >= maxRateLimiterKeys {
			// Map is at capacity and this is a brand new key: try one
			// more sweep in case expired buckets just freed up room.
			r.sweepLocked(now)
			if len(r.hits) >= maxRateLimiterKeys {
				// Still full: fail open for this unrelated key rather
				// than letting the map grow without bound.
				return true
			}
		}
		r.hits[key] = &bucket{count: 1, windowEnd: now.Add(r.window)}
		return true
	}
	if b.count >= r.limit {
		return false
	}
	b.count++
	return true
}

// sweepLocked drops every bucket whose window has already ended.
// Caller must hold r.mu.
func (r *RateLimiter) sweepLocked(now time.Time) {
	for key, b := range r.hits {
		if now.After(b.windowEnd) {
			delete(r.hits, key)
		}
	}
}
