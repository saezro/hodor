package pin

import (
	"testing"
	"time"
)

type fakeClock struct{ t time.Time }

func (f *fakeClock) Now() time.Time { return f.t }

func TestCreate_And_Get(t *testing.T) {
	clock := &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	m := New(clock)

	e, err := m.Create("svc")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if e.Service != "svc" {
		t.Errorf("Service = %q", e.Service)
	}
	if len(e.Code) != 6 {
		t.Errorf("Code len = %d, want 6", len(e.Code))
	}
	if !e.ExpiresAt.Equal(clock.t.Add(ttl)) {
		t.Errorf("ExpiresAt = %v, want %v", e.ExpiresAt, clock.t.Add(ttl))
	}

	got, ok := m.Get(e.SessionID)
	if !ok {
		t.Fatalf("Get: expected entry present")
	}
	if got.Code != e.Code {
		t.Errorf("Get() Code = %q, want %q", got.Code, e.Code)
	}
}

func TestGet_ExpiredAt10Minutes(t *testing.T) {
	clock := &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	m := New(clock)
	e, err := m.Create("svc")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	clock.t = clock.t.Add(10 * time.Minute)
	if _, ok := m.Get(e.SessionID); ok {
		t.Errorf("expected entry expired at exactly ttl (10min)")
	}
}

func TestGet_NotYetExpired(t *testing.T) {
	clock := &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	m := New(clock)
	e, err := m.Create("svc")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	clock.t = clock.t.Add(9*time.Minute + 59*time.Second)
	if _, ok := m.Get(e.SessionID); !ok {
		t.Errorf("expected entry still valid just before ttl")
	}
}

func TestApprove_CorrectCode(t *testing.T) {
	clock := &fakeClock{t: time.Now()}
	m := New(clock)
	e, err := m.Create("svc")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := m.Approve(e.Code)
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if got.SessionID != e.SessionID {
		t.Errorf("Approve() SessionID = %q, want %q", got.SessionID, e.SessionID)
	}
	if !got.Approved {
		t.Errorf("expected entry marked Approved")
	}

	entry, ok := m.Get(e.SessionID)
	if !ok || !entry.Approved {
		t.Errorf("expected stored entry to be Approved")
	}
}

func TestApprove_NotFound(t *testing.T) {
	m := New(&fakeClock{t: time.Now()})
	if _, err := m.Approve("000000"); err != ErrNotFound {
		t.Errorf("Approve(unknown) err = %v, want ErrNotFound", err)
	}
}

// NOTE: pin.Manager itself no longer implements the max-5-attempts
// brute-force guard (moved to internal/admin, keyed per client IP via
// auth.RateLimiter around s.pins.Approve). See internal/admin tests for
// that behavior; pin.Manager.Approve just matches or returns ErrNotFound.
func TestApprove_WrongCodeAlwaysNotFound(t *testing.T) {
	clock := &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	m := New(clock)
	if _, err := m.Create("svc"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	for i := 0; i < 10; i++ {
		if _, err := m.Approve("999999"); err != ErrNotFound {
			t.Fatalf("attempt %d: err = %v, want ErrNotFound", i, err)
		}
	}
}

func TestConsume_RemovesEntry(t *testing.T) {
	m := New(&fakeClock{t: time.Now()})
	e, err := m.Create("svc")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	m.Consume(e.SessionID)
	if _, ok := m.Get(e.SessionID); ok {
		t.Errorf("expected entry gone after Consume")
	}
}

func TestPending_ExcludesApprovedAndExpired(t *testing.T) {
	clock := &fakeClock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	m := New(clock)

	approved, err := m.Create("svc2")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := m.Approve(approved.Code); err != nil {
		t.Fatalf("Approve: %v", err)
	}

	expiring, err := m.Create("svc3")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Advance the clock past expiring's TTL, then create a fresh pending
	// entry so it is NOT expired relative to the new "now".
	clock.t = clock.t.Add(ttl + time.Minute)
	pending, err := m.Create("svc1")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	list := m.Pending()
	for _, e := range list {
		if e.SessionID == approved.SessionID {
			t.Errorf("Pending() should exclude approved entries")
		}
		if e.SessionID == expiring.SessionID {
			t.Errorf("Pending() should exclude expired entries")
		}
	}
	found := false
	for _, e := range list {
		if e.SessionID == pending.SessionID {
			found = true
		}
	}
	if !found {
		t.Errorf("Pending() should include the still-valid pending entry")
	}
}
