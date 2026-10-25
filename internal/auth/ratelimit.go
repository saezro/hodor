package auth

import (
	"sync"
	"time"
)

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
	b, ok := r.hits[key]
	if !ok || now.After(b.windowEnd) {
		r.hits[key] = &bucket{count: 1, windowEnd: now.Add(r.window)}
		return true
	}
	if b.count >= r.limit {
		return false
	}
	b.count++
	return true
}
