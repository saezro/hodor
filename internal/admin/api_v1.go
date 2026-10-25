package admin

import (
	"context"
	"net/http"
	"strings"

	"github.com/saezro/hodor/internal/apikey"
	"github.com/saezro/hodor/internal/config"
	"github.com/saezro/hodor/internal/pass"
)

// v1Identity is the caller resolved by apiV1Guard for an /api/v1/*
// request: either the global admin.token (admin == true) or one
// scoped config.APIKey.
type v1Identity struct {
	admin bool
	key   *config.APIKey
}

// allows reports whether this identity may perform action on svc.
// The admin token can do anything; a scoped key is checked against
// its services/actions.
func (id v1Identity) allows(svc config.Service, action string) bool {
	if id.admin {
		return true
	}
	if id.key == nil {
		return false
	}
	return apikey.Allows(*id.key, svc, action)
}

// openedBy is the label recorded as state.Entry.OpenedBy for actions
// performed through this identity.
func (id v1Identity) openedBy() string {
	if id.admin {
		return "api"
	}
	if id.key != nil {
		return "key:" + id.key.Name
	}
	return "api:unknown"
}

type v1CtxKeyType struct{}

var v1CtxKey = v1CtxKeyType{}

func v1IdentityFrom(r *http.Request) v1Identity {
	if id, ok := r.Context().Value(v1CtxKey).(v1Identity); ok {
		return id
	}
	return v1Identity{}
}

// v1Authenticate resolves the Authorization: Bearer header on r against
// admin.token and cfg.APIKeys. ok is false if there is no bearer token
// or it matches neither.
func (s *Server) v1Authenticate(r *http.Request) (v1Identity, bool) {
	h := r.Header.Get("Authorization")
	const prefix = "Bearer "
	if !strings.HasPrefix(h, prefix) {
		return v1Identity{}, false
	}
	token := strings.TrimPrefix(h, prefix)
	if token == "" {
		return v1Identity{}, false
	}
	if s.cfg.Admin.Token != "" && pass.ConstantTimeEqual(token, s.cfg.Admin.Token) {
		return v1Identity{admin: true}, true
	}
	if k := apikey.Match(s.cfg.APIKeys, token); k != nil {
		return v1Identity{key: k}, true
	}
	return v1Identity{}, false
}

// apiV1Guard is the dedicated auth/CORS/rate-limit middleware for
// /api/v1/*; everything else passes through untouched (csrfAndAuth,
// further up the chain, already treats /api/v1/* as opaque to it).
func (s *Server) apiV1Guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.URL.Path, "/api/v1/") {
			next.ServeHTTP(w, r)
			return
		}

		w.Header().Set("Vary", "Origin")

		if r.Method == http.MethodOptions {
			s.v1Preflight(w, r)
			return
		}

		ident, ok := s.v1Authenticate(r)
		if !ok {
			writeJSON(w, http.StatusUnauthorized, errorResponse{Error: "missing or invalid bearer token"})
			return
		}

		if !ident.admin && ident.key != nil {
			if !s.keyLimit.Allow(ident.key.ID) {
				writeJSON(w, http.StatusTooManyRequests, errorResponse{Error: "rate limit exceeded"})
				return
			}
		}

		if origin := r.Header.Get("Origin"); origin != "" && !ident.admin && ident.key != nil {
			if originAllowed(ident.key.AllowOrigins, origin) {
				setV1CORSHeaders(w, origin)
			}
		}

		r = r.WithContext(context.WithValue(r.Context(), v1CtxKey, ident))
		next.ServeHTTP(w, r)
	})
}

// v1ActionFromPath returns the api_keys action implied by an
// /api/v1/services/{name}[/{action}] path: a bare {name} means
// "status" (the GET endpoint); /open and /close map to themselves.
func v1ActionFromPath(path string) string {
	switch {
	case strings.HasSuffix(path, "/open"):
		return config.KeyActionOpen
	case strings.HasSuffix(path, "/close"):
		return config.KeyActionClose
	default:
		return config.KeyActionStatus
	}
}

// v1ServiceNameFromPath extracts {name} out of
// /api/v1/services/{name}[/{action}].
func v1ServiceNameFromPath(path string) string {
	rest := strings.TrimPrefix(path, "/api/v1/services/")
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		rest = rest[:i]
	}
	return rest
}

// v1Preflight answers a CORS preflight for /api/v1/*. Preflight
// requests carry no Authorization header, so instead of a single
// identity it checks the union of every configured API key that both
// covers the target service+action and lists Origin in its
// allow_origins. admin.token never grants CORS (it has no
// allow_origins of its own).
func (s *Server) v1Preflight(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if origin == "" {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	name := v1ServiceNameFromPath(r.URL.Path)
	action := v1ActionFromPath(r.URL.Path)
	scopeSvc, ok := s.v1ScopeTarget(name)
	if ok {
		for i := range s.cfg.APIKeys {
			k := &s.cfg.APIKeys[i]
			if apikey.Allows(*k, scopeSvc, action) && originAllowed(k.AllowOrigins, origin) {
				setV1CORSHeaders(w, origin)
				break
			}
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func setV1CORSHeaders(w http.ResponseWriter, origin string) {
	h := w.Header()
	h.Set("Access-Control-Allow-Origin", origin)
	h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
	h.Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	h.Set("Access-Control-Max-Age", "600")
}

// originAllowed reports whether origin is exactly one of the entries
// in allowed (no wildcards, no normalization beyond what
// config.Validate already enforces on allow_origins).
func originAllowed(allowed []string, origin string) bool {
	for _, a := range allowed {
		if a == origin {
			return true
		}
	}
	return false
}

// v1ScopeTarget resolves name (a service or group name) to the
// config.Service used to evaluate api_keys scope: the literal service
// if name matches one, or a synthetic Service{Group: name} if name
// matches a group instead.
func (s *Server) v1ScopeTarget(name string) (config.Service, bool) {
	for i := range s.cfg.Services {
		if s.cfg.Services[i].Name == name {
			return s.cfg.Services[i], true
		}
	}
	for i := range s.cfg.Services {
		if s.cfg.Services[i].Group == name {
			return config.Service{Group: name}, true
		}
	}
	return config.Service{}, false
}

// v1ServiceView builds the GET /api/v1/services/{name} response for
// name, whether it is a literal service or a group (aggregating hosts
// across its members, state keyed by the group name itself, same as
// resolveKey/stateKey do for open/close).
func (s *Server) v1ServiceView(name string) (ServiceView, bool) {
	for i := range s.cfg.Services {
		svc := &s.cfg.Services[i]
		if svc.Name != name {
			continue
		}
		st, _ := s.state.Get(stateKey(svc))
		v := ServiceView{Name: svc.Name, Title: svc.Title, Hosts: svc.Hosts, Mode: svc.Mode, Group: svc.Group, Open: st.Open, OpenedBy: st.OpenedBy}
		if !st.Until.IsZero() {
			until := st.Until
			v.Until = &until
		}
		return v, true
	}

	var hosts []string
	mode := ""
	member := false
	for i := range s.cfg.Services {
		svc := &s.cfg.Services[i]
		if svc.Group != name {
			continue
		}
		member = true
		hosts = append(hosts, svc.Hosts...)
		if mode == "" {
			mode = svc.Mode
		}
	}
	if !member {
		return ServiceView{}, false
	}
	st, _ := s.state.Get(name)
	v := ServiceView{Name: name, Title: name, Hosts: hosts, Mode: mode, Group: name, Open: st.Open, OpenedBy: st.OpenedBy}
	if !st.Until.IsZero() {
		until := st.Until
		v.Until = &until
	}
	return v, true
}

func (s *Server) handleV1ServiceGet(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	scopeSvc, ok := s.v1ScopeTarget(name)
	if !ok {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "unknown service or group"})
		return
	}
	ident := v1IdentityFrom(r)
	if !ident.allows(scopeSvc, config.KeyActionStatus) {
		writeJSON(w, http.StatusForbidden, errorResponse{Error: "key does not cover this service/action"})
		return
	}
	view, ok := s.v1ServiceView(name)
	if !ok {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "unknown service or group"})
		return
	}
	writeJSON(w, http.StatusOK, view)
}

func (s *Server) handleV1ServiceOpen(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	scopeSvc, ok := s.v1ScopeTarget(name)
	if !ok {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "unknown service or group"})
		return
	}
	ident := v1IdentityFrom(r)
	if !ident.allows(scopeSvc, config.KeyActionOpen) {
		writeJSON(w, http.StatusForbidden, errorResponse{Error: "key does not cover this service/action"})
		return
	}
	key, ok := s.resolveKey(name)
	if !ok {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "unknown service or group"})
		return
	}
	s.openService(w, r, key, ident.openedBy())
}

func (s *Server) handleV1ServiceClose(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	scopeSvc, ok := s.v1ScopeTarget(name)
	if !ok {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "unknown service or group"})
		return
	}
	ident := v1IdentityFrom(r)
	if !ident.allows(scopeSvc, config.KeyActionClose) {
		writeJSON(w, http.StatusForbidden, errorResponse{Error: "key does not cover this service/action"})
		return
	}
	key, ok := s.resolveKey(name)
	if !ok {
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "unknown service or group"})
		return
	}
	s.closeService(w, key)
}

func (s *Server) handleV1Preflight(_ http.ResponseWriter, _ *http.Request) {
	// Unreachable in practice: apiV1Guard intercepts every OPTIONS
	// request under /api/v1/ before the mux dispatches here. Registered
	// anyway so the mux itself answers 200/204 instead of 405 if that
	// ever changes.
}
