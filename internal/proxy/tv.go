package proxy

import (
	"encoding/json"
	"net"
	"net/http"
	"time"

	"github.com/saezro/hodor/internal/auth"
	"github.com/saezro/hodor/internal/pin"
	"github.com/saezro/hodor/internal/web"
)

// tvPinLimit bounds how many PINs a single client IP may request from
// GET /tv. Without this, anyone who can reach the public listener could
// flood the admin panel's pending-PIN list (and chew through the
// 6-digit code space) just by repeatedly loading the page. Package-level
// since Server's fields live in proxy.go; keyed per client IP like the
// admin-side approve limiter in internal/admin/server.go.
var tvPinLimit = auth.NewRateLimiter(tvPinLimitCount, tvPinLimitWindow)

const (
	tvPinLimitCount  = 10
	tvPinLimitWindow = time.Minute
)

// tvPinLimitKey normalizes ip to the limiter key for its address family:
// a /32 (the full address) for IPv4, a /64 for IPv6. A single IPv6 user
// is commonly handed an entire /64 (or larger) by their ISP and can
// cycle through addresses within it per request, so keying on the exact
// address would let them bypass the limiter just by hopping within
// their own prefix; IPv4 addresses are scarce enough (and usually
// NATed, so a /32 is already shared by many devices) that narrowing
// further would be too easy to abuse the other way.
func tvPinLimitKey(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	mask := net.CIDRMask(64, 128)
	return ip.Mask(mask).String()
}

// handleTV serves GET /tv: the device-pairing page for keyboard-less
// screens. The service is resolved from the Host header, same as the
// closed page, since the device visits https://<host>/tv.
func (s *Server) handleTV(w http.ResponseWriter, r *http.Request) {
	cfg := s.cfg()
	svc := s.lookupHost(cfg, r.Host)
	if svc == nil {
		http.NotFound(w, r)
		return
	}

	ip := auth.ClientIP(r, cfg.Public.ParsedProxies, "X-Forwarded-For")
	key := ""
	if ip != nil {
		key = tvPinLimitKey(ip)
	}
	if !tvPinLimit.Allow(key) {
		http.Error(w, "too many pin requests", http.StatusTooManyRequests)
		return
	}

	entry, err := s.pins.Create(svc.Name)
	if err == pin.ErrTooManyPending {
		http.Error(w, "service busy", http.StatusServiceUnavailable)
		return
	}
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

	cfg := s.cfg()
	svc := s.lookupHost(cfg, r.Host)
	if svc == nil || svc.Name != entry.Service {
		writeJSON(w, map[string]any{"approved": false})
		return
	}

	if err := s.issuePass(cfg, w, r, svc); err != nil {
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
