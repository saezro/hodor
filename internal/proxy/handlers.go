package proxy

import (
	"net/http"

	"github.com/saezro/hodor/internal/config"
	"github.com/saezro/hodor/internal/web"
)

// handleDefault is the catch-all for the public listener: it routes by
// Host header to a configured service, then applies that service's mode.
func (s *Server) handleDefault(w http.ResponseWriter, r *http.Request) {
	svc := s.lookupHost(r.Host)
	if svc == nil {
		http.NotFound(w, r)
		return
	}

	switch svc.Mode {
	case config.ModeForwardAuth:
		// forwardauth services are not proxied by hodor itself: the
		// reverse proxy in front (Traefik/Caddy/nginx) talks to the
		// upstream directly after calling GET /auth. Reaching this host
		// straight on hodor's public listener is a misconfiguration;
		// show the closed page as the safest fallback.
		s.renderClosedFor(w, svc)
		return
	case config.ModeProxy:
		if !s.allowed(r, svc) {
			s.renderClosedFor(w, svc)
			return
		}
		rp := s.reverseProxy[svc.Name]
		if rp == nil {
			http.Error(w, "no upstream configured", http.StatusBadGateway)
			return
		}
		rp.ServeHTTP(w, r)
	default:
		http.NotFound(w, r)
	}
}

// handleClosed serves the standalone closed page at /.hodor/closed, used
// as the forwardauth redirect target. The service is resolved from the
// Host header, which the front proxy must preserve when routing
// /.hodor/* to hodor (see docs).
func (s *Server) handleClosed(w http.ResponseWriter, r *http.Request) {
	svc := s.lookupHost(r.Host)
	if svc == nil {
		http.NotFound(w, r)
		return
	}
	s.renderClosedFor(w, svc)
}

func (s *Server) renderClosedFor(w http.ResponseWriter, svc *config.Service) {
	d := web.NewClosedData(s.lang, svc.Title, svc.Message, svc.AccentColor, svc.LogoURL, s.cfg.Admin.PublicURL)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(http.StatusOK)
	_ = web.RenderClosed(w, d)
}
