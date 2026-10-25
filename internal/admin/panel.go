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

func (s *Server) staticHandler() http.Handler {
	return http.FileServerFS(hodorweb.Static)
}
