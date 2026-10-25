package admin

import (
	"net/http"
	"strings"

	"github.com/saezro/hodor/internal/apikey"
	"github.com/saezro/hodor/internal/config"
	"github.com/saezro/hodor/internal/web"
)

// handleEmbed serves GET /embed/{svc}?k=<api-key>: the small HTML page
// (embed.html) that a third-party page can put in an <iframe> to show
// one service's status and an open control, scoped to the given API
// key. Unlike the rest of the admin surface, admin.token never grants
// access here — only a config.APIKey matched by apikey.Match, so that
// frame-ancestors can be derived from that key's allow_origins. On any
// failure (unknown service/group, unknown key, key not scoped to
// status on this service) it answers a flat 403 without indicating
// which check failed, so a caller can't use it to enumerate keys or
// services.
func (s *Server) handleEmbed(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("svc")
	scopeSvc, ok := s.v1ScopeTarget(name)
	if !ok {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	k := r.URL.Query().Get("k")
	key := apikey.Match(s.cfg.APIKeys, k)
	if key == nil || !apikey.Allows(*key, scopeSvc, config.KeyActionStatus) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	if !s.keyLimit.Allow(key.ID) {
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	frameAncestors := "'none'"
	if len(key.AllowOrigins) > 0 {
		frameAncestors = strings.Join(key.AllowOrigins, " ")
	}

	h := w.Header()
	h.Del("X-Frame-Options")
	h.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors "+frameAncestors)
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Type", "text/html; charset=utf-8")

	d := web.EmbedData{Service: name, Key: k, Lang: string(s.lang)}
	_ = web.RenderEmbed(w, d)
}
