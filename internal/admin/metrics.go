package admin

import (
	"fmt"
	"net/http"
)

// handleMetrics writes a minimal, hand-rolled Prometheus text exposition
// (no client library dependency, per the stdlib-only constraint).
func (s *Server) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	_, _ = fmt.Fprintln(w, "# HELP hodor_service_open 1 if the service (or its group) is currently open")
	_, _ = fmt.Fprintln(w, "# TYPE hodor_service_open gauge")
	for i := range s.cfg().Services {
		svc := &s.cfg().Services[i]
		v := 0
		if s.state.IsOpen(stateKey(svc)) {
			v = 1
		}
		_, _ = fmt.Fprintf(w, "hodor_service_open{service=%q} %d\n", svc.Name, v)
	}

	_, _ = fmt.Fprintln(w, "# HELP hodor_passes_total number of device passes known (any state)")
	_, _ = fmt.Fprintln(w, "# TYPE hodor_passes_total gauge")
	_, _ = fmt.Fprintf(w, "hodor_passes_total %d\n", len(s.state.Passes()))

	_, _ = fmt.Fprintln(w, "# HELP hodor_pins_pending number of pending (unapproved, unexpired) PINs")
	_, _ = fmt.Fprintln(w, "# TYPE hodor_pins_pending gauge")
	_, _ = fmt.Fprintf(w, "hodor_pins_pending %d\n", len(s.pins.Pending()))
}
