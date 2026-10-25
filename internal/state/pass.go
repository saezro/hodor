package state

// AddPass records a newly issued pass. The caller is responsible for
// generating a unique, unguessable ID (see internal/pass).
func (s *Store) AddPass(p Pass) error {
	s.mu.Lock()
	p.CreatedAt = s.clock.Now()
	s.d.Passes[p.ID] = p
	s.appendEventLocked("pass issued for " + p.Service)
	err := s.saveLocked()
	s.mu.Unlock()
	if err == nil {
		s.notify("pass:" + p.Service)
	}
	return err
}

// RevokePass marks a pass as revoked. Returns false if the ID is unknown.
func (s *Store) RevokePass(id string) (bool, error) {
	s.mu.Lock()
	p, ok := s.d.Passes[id]
	if !ok {
		s.mu.Unlock()
		return false, nil
	}
	p.Revoked = true
	s.d.Passes[id] = p
	s.appendEventLocked("pass revoked: " + id)
	err := s.saveLocked()
	s.mu.Unlock()
	if err == nil {
		s.notify("pass-revoked:" + id)
	}
	return true, err
}

// IsPassValid reports whether id is a known, non-revoked pass for
// service.
func (s *Store) IsPassValid(id, service string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.d.Passes[id]
	return ok && !p.Revoked && p.Service == service
}

// Passes returns every known pass (all services).
func (s *Store) Passes() []Pass {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Pass, 0, len(s.d.Passes))
	for _, p := range s.d.Passes {
		out = append(out, p)
	}
	return out
}

// PassesForService returns known passes for one service.
func (s *Store) PassesForService(service string) []Pass {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Pass, 0)
	for _, p := range s.d.Passes {
		if p.Service == service {
			out = append(out, p)
		}
	}
	return out
}
