package admin

import (
	"net/http"

	"github.com/saezro/hodor/internal/web"
	hodorweb "github.com/saezro/hodor/web"
)

func (s *Server) handlePanel(w http.ResponseWriter, _ *http.Request) {
	d := web.NewPanelData(s.lang, s.csrfToken, s.cfg.Durations)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = web.RenderPanel(w, d)
}

// embedJSPath is the static asset backing the embed widget (served by
// staticHandler, below, with its own cache/Content-Type/COR-Policy so
// third-party pages embedding /embed/{svc} can load it cross-origin
// even behind a COEP policy).
const embedJSPath = "/static/embed.js"

func (s *Server) staticHandler() http.Handler {
	fileServer := http.FileServerFS(hodorweb.Static)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == embedJSPath {
			h := w.Header()
			h.Set("Content-Type", "text/javascript; charset=utf-8")
			h.Set("Cache-Control", "public, max-age=300")
			h.Set("Cross-Origin-Resource-Policy", "cross-origin")
		}
		fileServer.ServeHTTP(w, r)
	})
}
