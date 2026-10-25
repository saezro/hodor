// Package state tracks the open/closed status of every configured
// service, device passes and a short event log, and persists all of it
// to a JSON file so a restart does not forget what was open.
package state

import (
	"sync"
	"time"
)

// Clock abstracts time.Now so tests can use a fake clock.
type Clock interface {
	Now() time.Time
}

// RealClock is the production Clock backed by time.Now.
type RealClock struct{}

func (RealClock) Now() time.Time { return time.Now() }

// ServiceState is the persisted open/closed status of one service.
type ServiceState struct {
	Open bool `json:"open"`
	// Until is the time the service auto-closes. The zero Time means
	// "open until explicitly closed" (no timer).
	Until    time.Time `json:"until"`
	OpenedBy string    `json:"opened_by"`
}

// isExpired reports whether this state should be considered closed at t.
func (s ServiceState) isExpired(t time.Time) bool {
	return s.Open && !s.Until.IsZero() && !t.Before(s.Until)
}

// Pass is a device pass: a long-lived grant for one service, identified
// by a random ID carried inside the signed cookie.
type Pass struct {
	ID        string    `json:"id"`
	Service   string    `json:"service"`
	CreatedAt time.Time `json:"created_at"`
	Revoked   bool      `json:"revoked"`
	Label     string    `json:"label"`
}

// Event is one line in the ring buffer shown in the admin panel.
type Event struct {
	Time    time.Time `json:"time"`
	Message string    `json:"message"`
}

const maxEvents = 200

// data is the full persisted document.
type data struct {
	Services map[string]ServiceState `json:"services"`
	Passes   map[string]Pass         `json:"passes"`
	Events   []Event                 `json:"events"`
}

// OnChangeFunc is invoked after any mutation (open/close/pass change)
// with a short human-readable message, e.g. to fire the on_change
// webhook.
type OnChangeFunc func(msg string)

// Store is the in-memory, mutex-guarded, disk-backed state holder.
type Store struct {
	mu            sync.Mutex
	path          string
	clock         Clock
	d             data
	onChange      OnChangeFunc
	autoCloseStop chan struct{}
}

// New creates a Store for the given service names, loading existing
// state from path if present. Services not present in the loaded file
// start closed. Expired services are closed on load.
func New(path string, serviceNames []string, clock Clock) (*Store, error) {
	if clock == nil {
		clock = RealClock{}
	}
	st := &Store{
		path:  path,
		clock: clock,
		d: data{
			Services: make(map[string]ServiceState),
			Passes:   make(map[string]Pass),
		},
	}
	if err := st.load(); err != nil {
		return nil, err
	}
	now := clock.Now()
	for _, name := range serviceNames {
		s, ok := st.d.Services[name]
		if !ok {
			st.d.Services[name] = ServiceState{Open: false}
			continue
		}
		if s.isExpired(now) {
			st.d.Services[name] = ServiceState{Open: false}
		}
	}
	return st, nil
}

// SetOnChange registers a callback invoked (outside the lock) after each
// mutation.
func (s *Store) SetOnChange(f OnChangeFunc) {
	s.mu.Lock()
	s.onChange = f
	s.mu.Unlock()
}

func (s *Store) notify(msg string) {
	s.mu.Lock()
	f := s.onChange
	s.mu.Unlock()
	if f != nil {
		f(msg)
	}
}

func (s *Store) appendEventLocked(msg string) {
	s.d.Events = append(s.d.Events, Event{Time: s.clock.Now(), Message: msg})
	if len(s.d.Events) > maxEvents {
		s.d.Events = s.d.Events[len(s.d.Events)-maxEvents:]
	}
}

// IsOpen reports whether name is currently open, auto-closing it first
// if its timer has expired.
func (s *Store) IsOpen(name string) bool {
	s.mu.Lock()
	open, expired := s.isOpenLocked(name)
	s.mu.Unlock()
	if expired {
		s.notify("closed:" + name)
	}
	return open
}

// isOpenLocked reports whether name is open, closing and persisting it
// first if its timer has expired. Caller must hold s.mu. expired is true
// only when this call is the one that just flipped it closed, so the
// caller can notify (outside the lock) exactly once.
func (s *Store) isOpenLocked(name string) (open, expired bool) {
	st, ok := s.d.Services[name]
	if !ok {
		return false, false
	}
	if st.isExpired(s.clock.Now()) {
		s.d.Services[name] = ServiceState{Open: false}
		s.appendEventLocked("close " + name + " (expired)")
		_ = s.saveLocked()
		return false, true
	}
	return st.Open, false
}

// Get returns the current state of name (auto-closing if expired).
func (s *Store) Get(name string) (ServiceState, bool) {
	s.mu.Lock()
	_, expired := s.isOpenLocked(name) // trigger expiry
	st, ok := s.d.Services[name]
	s.mu.Unlock()
	if expired {
		s.notify("closed:" + name)
	}
	return st, ok
}

// All returns a snapshot of every known service's state.
func (s *Store) All() map[string]ServiceState {
	s.mu.Lock()
	var expiredNames []string
	for name := range s.d.Services {
		if _, expired := s.isOpenLocked(name); expired {
			expiredNames = append(expiredNames, name)
		}
	}
	out := make(map[string]ServiceState, len(s.d.Services))
	for k, v := range s.d.Services {
		out[k] = v
	}
	s.mu.Unlock()
	for _, name := range expiredNames {
		s.notify("closed:" + name)
	}
	return out
}

// CheckExpirations scans every known service and closes (persists +
// logs + notifies) any whose timer has expired, even if nobody actively
// queries it. This is what the auto-close ticker started by
// StartAutoClose calls on each tick; tests can call it directly after
// advancing a fake Clock instead of waiting on a real timer.
func (s *Store) CheckExpirations() {
	s.mu.Lock()
	var expiredNames []string
	for name := range s.d.Services {
		if _, expired := s.isOpenLocked(name); expired {
			expiredNames = append(expiredNames, name)
		}
	}
	s.mu.Unlock()
	for _, name := range expiredNames {
		s.notify("closed:" + name)
	}
}

// StartAutoClose launches a background goroutine that calls
// CheckExpirations every interval, so a service closes on schedule even
// if nothing ever reads its state. Call Stop on shutdown. Calling it
// again after Stop restarts the ticker.
func (s *Store) StartAutoClose(interval time.Duration) {
	if interval <= 0 {
		interval = time.Minute
	}
	stop := make(chan struct{})
	s.mu.Lock()
	s.autoCloseStop = stop
	s.mu.Unlock()

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				s.CheckExpirations()
			case <-stop:
				return
			}
		}
	}()
}

// Stop halts the auto-close ticker started by StartAutoClose, if any.
// Safe to call even if it was never started.
func (s *Store) Stop() {
	s.mu.Lock()
	stop := s.autoCloseStop
	s.autoCloseStop = nil
	s.mu.Unlock()
	if stop != nil {
		close(stop)
	}
}

// Open opens name for duration (0 means "until explicitly closed") on
// behalf of openedBy, and persists the change.
func (s *Store) Open(name string, duration time.Duration, openedBy string) error {
	s.mu.Lock()
	var until time.Time
	if duration > 0 {
		until = s.clock.Now().Add(duration)
	}
	s.d.Services[name] = ServiceState{Open: true, Until: until, OpenedBy: openedBy}
	s.appendEventLocked("open " + name + " by " + openedBy)
	err := s.saveLocked()
	s.mu.Unlock()
	if err == nil {
		s.notify("opened:" + name)
	}
	return err
}

// Close closes name immediately and persists the change.
func (s *Store) Close(name string) error {
	s.mu.Lock()
	s.d.Services[name] = ServiceState{Open: false}
	s.appendEventLocked("close " + name)
	err := s.saveLocked()
	s.mu.Unlock()
	if err == nil {
		s.notify("closed:" + name)
	}
	return err
}

// Events returns a snapshot of the event ring buffer, most recent last.
func (s *Store) Events() []Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Event, len(s.d.Events))
	copy(out, s.d.Events)
	return out
}
