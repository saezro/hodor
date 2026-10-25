package state

import (
	"path/filepath"
	"testing"
	"time"
)

// fakeClock is a mutable Clock for tests.
type fakeClock struct{ t time.Time }

func (f *fakeClock) Now() time.Time { return f.t }

func newFakeClock(t time.Time) *fakeClock { return &fakeClock{t: t} }

func TestOpen_WithDuration_SetsUntil(t *testing.T) {
	clock := newFakeClock(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	st, err := New(filepath.Join(t.TempDir(), "state.json"), []string{"svc"}, clock)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := st.Open("svc", time.Hour, "tester"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !st.IsOpen("svc") {
		t.Fatalf("expected svc to be open")
	}
	got, ok := st.Get("svc")
	if !ok {
		t.Fatalf("expected service to exist")
	}
	want := clock.t.Add(time.Hour)
	if !got.Until.Equal(want) {
		t.Errorf("Until = %v, want %v", got.Until, want)
	}
}

func TestOpen_ZeroDuration_NoTimer(t *testing.T) {
	clock := newFakeClock(time.Now())
	st, err := New(filepath.Join(t.TempDir(), "state.json"), []string{"svc"}, clock)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := st.Open("svc", 0, "tester"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	clock.t = clock.t.Add(1000 * time.Hour)
	if !st.IsOpen("svc") {
		t.Errorf("service with no timer should stay open regardless of elapsed time")
	}
}

func TestIsOpen_ExpiresAtTimer(t *testing.T) {
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := newFakeClock(start)
	st, err := New(filepath.Join(t.TempDir(), "state.json"), []string{"svc"}, clock)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := st.Open("svc", time.Hour, "tester"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	// Just before expiry: still open.
	clock.t = start.Add(59 * time.Minute)
	if !st.IsOpen("svc") {
		t.Errorf("expected still open before expiry")
	}
	// Exactly at expiry: closed (isExpired uses !t.Before(Until)).
	clock.t = start.Add(time.Hour)
	if st.IsOpen("svc") {
		t.Errorf("expected closed exactly at expiry")
	}
	// Confirm auto-close persisted in-memory.
	got, _ := st.Get("svc")
	if got.Open {
		t.Errorf("expected ServiceState.Open=false after auto-close")
	}
}

func TestIsOpen_UnknownService(t *testing.T) {
	st, err := New(filepath.Join(t.TempDir(), "state.json"), nil, newFakeClock(time.Now()))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if st.IsOpen("ghost") {
		t.Errorf("unknown service should report closed")
	}
}

func TestClose_ClearsState(t *testing.T) {
	st, err := New(filepath.Join(t.TempDir(), "state.json"), []string{"svc"}, newFakeClock(time.Now()))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := st.Open("svc", time.Hour, "tester"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := st.Close("svc"); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if st.IsOpen("svc") {
		t.Errorf("expected closed after Close")
	}
}

func TestPersistence_RoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := newFakeClock(start)

	st1, err := New(path, []string{"svc"}, clock)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := st1.Open("svc", time.Hour, "tester"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	if err := st1.AddPass(Pass{ID: "p1", Service: "svc", Label: "tv"}); err != nil {
		t.Fatalf("AddPass: %v", err)
	}

	// Reload with the same (unexpired) clock time: should still be open.
	st2, err := New(path, []string{"svc"}, newFakeClock(start.Add(30*time.Minute)))
	if err != nil {
		t.Fatalf("New (reload): %v", err)
	}
	if !st2.IsOpen("svc") {
		t.Errorf("expected service still open after reload before expiry")
	}
	if !st2.IsPassValid("p1", "svc") {
		t.Errorf("expected pass to survive reload")
	}
}

func TestPersistence_ExpiresOnLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	st1, err := New(path, []string{"svc"}, newFakeClock(start))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := st1.Open("svc", time.Hour, "tester"); err != nil {
		t.Fatalf("Open: %v", err)
	}

	// Reload with a clock well past expiry: New() should close it immediately.
	st2, err := New(path, []string{"svc"}, newFakeClock(start.Add(2*time.Hour)))
	if err != nil {
		t.Fatalf("New (reload): %v", err)
	}
	got, ok := st2.Get("svc")
	if !ok {
		t.Fatalf("expected svc to exist after reload")
	}
	if got.Open {
		t.Errorf("expected service closed on load past expiry")
	}
}

func TestGroups_ShareStateKey(t *testing.T) {
	// internal/state has no notion of "groups" itself: callers (proxy,
	// admin) pass a shared key for grouped services. Verify that Open
	// under a group key is visible to any lookup using that same key.
	st, err := New(filepath.Join(t.TempDir(), "state.json"), []string{"groupA"}, newFakeClock(time.Now()))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := st.Open("groupA", time.Hour, "tester"); err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !st.IsOpen("groupA") {
		t.Errorf("expected group key to be open")
	}
}

func TestAddPass_RevokeAndValidity(t *testing.T) {
	st, err := New(filepath.Join(t.TempDir(), "state.json"), nil, newFakeClock(time.Now()))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := st.AddPass(Pass{ID: "p1", Service: "svc"}); err != nil {
		t.Fatalf("AddPass: %v", err)
	}
	if !st.IsPassValid("p1", "svc") {
		t.Errorf("expected pass valid")
	}
	if st.IsPassValid("p1", "other-svc") {
		t.Errorf("expected pass invalid for different service")
	}
	if st.IsPassValid("unknown", "svc") {
		t.Errorf("expected unknown pass invalid")
	}

	ok, err := st.RevokePass("p1")
	if err != nil || !ok {
		t.Fatalf("RevokePass: ok=%v err=%v", ok, err)
	}
	if st.IsPassValid("p1", "svc") {
		t.Errorf("expected revoked pass invalid")
	}

	ok, err = st.RevokePass("unknown")
	if err != nil {
		t.Fatalf("RevokePass(unknown): %v", err)
	}
	if ok {
		t.Errorf("expected RevokePass(unknown) to report false")
	}
}

func TestEvents_RingBufferCap(t *testing.T) {
	st, err := New(filepath.Join(t.TempDir(), "state.json"), []string{"svc"}, newFakeClock(time.Now()))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for i := 0; i < maxEvents+10; i++ {
		if err := st.Open("svc", time.Hour, "tester"); err != nil {
			t.Fatalf("Open: %v", err)
		}
	}
	events := st.Events()
	if len(events) != maxEvents {
		t.Errorf("Events() len = %d, want %d", len(events), maxEvents)
	}
}
