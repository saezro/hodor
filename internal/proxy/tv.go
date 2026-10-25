package proxy

import (
	"encoding/json"
	"net/http"

	"github.com/saezro/hodor/internal/web"
)

// handleTV serves GET /tv: the device-pairing page for keyboard-less
// screens. The service is resolved from the Host header, same as the
// closed page, since the device visits https://<host>/tv.
func (s *Server) handleTV(w http.ResponseWriter, r *http.Request) {
	svc := s.lookupHost(r.Host)
	if svc == nil {
		http.NotFound(w, r)
		return
	}

	entry, err := s.pins.Create(svc.Name)
	if err != nil {
		http.Error(w, "could not create pin", http.StatusInternalServerError)
		return
	}

	secs := int(entry.ExpiresAt.Sub(entry.CreatedAt).Seconds())
	d := web.NewTVData(s.lang, svc.Name, svc.Title, entry.Code, entry.SessionID, secs)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	_ = web.RenderTV(w, d)
}

// handleTVStatus implements the poll endpoint the tv.html JS calls: once
// an admin approves the PIN from the panel, this issues the device pass
// (signed cookie) and reports approved so the page reloads.
func (s *Server) handleTVStatus(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("session")
	entry, ok := s.pins.Get(sessionID)
	if !ok {
		writeJSON(w, map[string]any{"approved": false})
		return
	}
	if !entry.Approved {
		writeJSON(w, map[string]any{"approved": false})
		return
	}

	svc := s.lookupHost(r.Host)
	if svc == nil || svc.Name != entry.Service {
		writeJSON(w, map[string]any{"approved": false})
		return
	}

	if err := s.issuePass(w, r, svc); err != nil {
		http.Error(w, "could not issue pass", http.StatusInternalServerError)
		return
	}
	s.pins.Consume(sessionID)
	writeJSON(w, map[string]any{"approved": true})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}
