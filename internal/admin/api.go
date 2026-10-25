package admin

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/saezro/hodor/internal/auth"
	"github.com/saezro/hodor/internal/config"
	"github.com/saezro/hodor/internal/pin"
)

func (s *Server) handleCSRF(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, CSRFResponse{Token: s.csrfToken})
}

// stateKey mirrors internal/proxy.stateKey: grouped services share one
// switch, keyed by group name.
func stateKey(svc *config.Service) string {
	if svc.Group != "" {
		return svc.Group
	}
	return svc.Name
}

// resolveKey resolves a CLI/API argument that may be a service name or a
// group name to the state-store key to act on.
func (s *Server) resolveKey(name string) (string, bool) {
	for i := range s.cfg.Services {
		if s.cfg.Services[i].Name == name {
			return stateKey(&s.cfg.Services[i]), true
		}
	}
	for i := range s.cfg.Services {
		if s.cfg.Services[i].Group == name {
			return name, true
		}
	}
	return "", false
}

func (s *Server) handleServicesList(w http.ResponseWriter, _ *http.Request) {
	out := make([]ServiceView, 0, len(s.cfg.Services))
	for i := range s.cfg.Services {
		svc := &s.cfg.Services[i]
		st, _ := s.state.Get(stateKey(svc))
		v := ServiceView{
			Name:  svc.Name,
			Title: svc.Title,
			Hosts: svc.Hosts,
			Mode:  svc.Mode,
			Group: svc.Group,
			Open:  st.Open,
		}
		if !st.Until.IsZero() {
			until := st.Until
			v.Until = &until
		}
		v.OpenedBy = st.OpenedBy
		out = append(out, v)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleServiceOpen(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	key, ok := s.resolveKey(name)
	if !ok {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "unknown service or group"})
		return
	}
	s.openService(w, r, key, clientLabel(r, s.cfg))
}

func (s *Server) handleServiceClose(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	key, ok := s.resolveKey(name)
	if !ok {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "unknown service or group"})
		return
	}
	s.closeService(w, key)
}

// openService opens the state entry identified by key (a resolved
// service or group state key, see stateKey/resolveKey) for the
// duration in r's JSON body ({"for": "3h"}, empty = until closed),
// recording openedBy as who did it. Shared by the panel's
// /api/services/{name}/open and the scoped /api/v1/services/{name}/open.
func (s *Server) openService(w http.ResponseWriter, r *http.Request, key, openedBy string) {
	var req OpenRequest
	if r.ContentLength != 0 {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}

	var dur time.Duration
	if req.For != "" {
		d, err := time.ParseDuration(req.For)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid for duration"})
			return
		}
		dur = d
	}

	if err := s.state.Open(key, dur, openedBy); err != nil {
		s.log.Error("open failed", "key", key, "err", err)
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "could not open"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// closeService closes the state entry identified by key. Shared by
// the panel's /api/services/{name}/close and the scoped
// /api/v1/services/{name}/close.
func (s *Server) closeService(w http.ResponseWriter, key string) {
	if err := s.state.Close(key); err != nil {
		s.log.Error("close failed", "key", key, "err", err)
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "could not close"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handlePinsList(w http.ResponseWriter, _ *http.Request) {
	entries := s.pins.Pending()
	out := make([]PinView, 0, len(entries))
	for _, e := range entries {
		out = append(out, PinView{
			SessionID: e.SessionID,
			Service:   e.Service,
			CreatedAt: e.CreatedAt,
			ExpiresAt: e.ExpiresAt,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handlePinsApprove(w http.ResponseWriter, r *http.Request) {
	limitKey := clientLabel(r, s.cfg)
	if !s.pinLimit.Allow(limitKey) {
		writeJSON(w, http.StatusTooManyRequests, errorResponse{Error: "too many attempts, try later"})
		return
	}

	var req ApprovePinRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, errorResponse{Error: "invalid body"})
		return
	}
	entry, err := s.pins.Approve(req.Code)
	switch err {
	case nil:
		writeJSON(w, http.StatusOK, PinView{
			SessionID: entry.SessionID,
			Service:   entry.Service,
			CreatedAt: entry.CreatedAt,
			ExpiresAt: entry.ExpiresAt,
		})
	case pin.ErrNotFound:
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "no matching pending pin"})
	default:
		s.log.Error("pin approve failed", "err", err)
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "could not approve"})
	}
}

func (s *Server) handlePassesList(w http.ResponseWriter, _ *http.Request) {
	passes := s.state.Passes()
	out := make([]PassView, 0, len(passes))
	for _, p := range passes {
		out = append(out, PassView{
			ID:        p.ID,
			Service:   p.Service,
			CreatedAt: p.CreatedAt,
			Revoked:   p.Revoked,
			Label:     p.Label,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handlePassRevoke(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	ok, err := s.state.RevokePass(id)
	if err != nil {
		s.log.Error("revoke failed", "id", id, "err", err)
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "could not revoke"})
		return
	}
	if !ok {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "unknown pass"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleEventsList(w http.ResponseWriter, _ *http.Request) {
	events := s.state.Events()
	out := make([]EventView, 0, len(events))
	for _, e := range events {
		out = append(out, EventView{Time: e.Time, Message: e.Message})
	}
	writeJSON(w, http.StatusOK, out)
}

func clientLabel(r *http.Request, cfg *config.Config) string {
	ip := auth.ClientIP(r, cfg.Admin.ParsedProxies, cfg.Admin.TrustedHeader)
	if ip == nil {
		return "admin"
	}
	return ip.String()
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
