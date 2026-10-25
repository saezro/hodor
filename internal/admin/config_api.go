package admin

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/saezro/hodor/internal/apikey"
	"github.com/saezro/hodor/internal/config"
)

// handleConfigGet answers GET /api/config: the merged (base + overlay)
// services, durations and api_keys currently live, plus the on-disk
// paths the panel's "Settings" tab needs to show which file owns what
// (docs/DESIGN.md "2c. Panel config editing + hot reload").
func (s *Server) handleConfigGet(w http.ResponseWriter, _ *http.Request) {
	cfg := s.cfg()
	writeJSON(w, http.StatusOK, ConfigGetResponse{
		Services:    cfg.Services,
		Durations:   cfg.Durations,
		APIKeys:     cfg.APIKeys,
		BasePath:    s.live.BasePath(),
		OverlayPath: s.live.OverlayPath(),
	})
}

// serviceSource returns the merged Source ("base"/"overlay") of the
// service named name, or "" if there is no such service.
func (s *Server) serviceSource(name string) string {
	for i := range s.cfg().Services {
		if s.cfg().Services[i].Name == name {
			return s.cfg().Services[i].Source
		}
	}
	return ""
}

// apiKeySource returns the merged Source of the api key with id id, or
// "" if there is no such key.
func (s *Server) apiKeySource(id string) string {
	for i := range s.cfg().APIKeys {
		if s.cfg().APIKeys[i].ID == id {
			return s.cfg().APIKeys[i].Source
		}
	}
	return ""
}

// handleConfigServicePut answers PUT /api/config/services/{name}:
// creates or replaces the overlay entry for name. A base service of
// the same name is read-only from the panel (409); the body's own
// "name" (if any) is ignored in favor of the path value.
func (s *Server) handleConfigServicePut(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if s.serviceSource(name) == "base" {
		writeJSON(w, http.StatusConflict, errorResponse{Error: "service " + name + " comes from the base config and is read-only"})
		return
	}

	var svc config.Service
	if err := json.NewDecoder(r.Body).Decode(&svc); err != nil {
		writeValidationError(w, "body", "invalid json: "+err.Error())
		return
	}
	svc.Name = name

	if _, err := s.live.PutService(svc); err != nil {
		writeConfigError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, okResponse{OK: true})
}

// handleConfigServiceDelete answers DELETE /api/config/services/{name}:
// removes an overlay-only service. Unknown name -> 404; a base service
// -> 409 (it is not the panel's to delete).
func (s *Server) handleConfigServiceDelete(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	switch s.serviceSource(name) {
	case "base":
		writeJSON(w, http.StatusConflict, errorResponse{Error: "service " + name + " comes from the base config and is read-only"})
		return
	case "":
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "unknown service"})
		return
	}
	if _, err := s.live.DeleteService(name); err != nil {
		writeConfigError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleConfigDurationsPut answers PUT /api/config/durations: replaces
// the overlay's durations list wholesale (an empty list clears the
// override, falling back to base's).
func (s *Server) handleConfigDurationsPut(w http.ResponseWriter, r *http.Request) {
	var req ConfigDurationsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeValidationError(w, "body", "invalid json: "+err.Error())
		return
	}
	if _, err := s.live.SetDurations(req.Durations); err != nil {
		writeConfigError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, okResponse{OK: true})
}

// handleConfigKeyCreate answers POST /api/config/keys: generates a new
// scoped API key, stores only its sha256 hash in the overlay and
// returns the raw key once, together with a ready-to-paste hodor.yaml
// snippet (for operators who'd rather hand-move it into the base
// config later).
func (s *Server) handleConfigKeyCreate(w http.ResponseWriter, r *http.Request) {
	var req ConfigKeyCreateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeValidationError(w, "body", "invalid json: "+err.Error())
		return
	}

	id, err := randomHex(8) // 16 hex chars: wider than `hodor key new`'s 8, to keep collisions negligible now that AddAPIKey rejects them instead of silently overwriting
	if err != nil {
		s.log.Error("config key create: id generation failed", "err", err)
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "could not generate key"})
		return
	}
	rawKey, hashHex, err := apikey.Generate()
	if err != nil {
		s.log.Error("config key create: key generation failed", "err", err)
		writeJSON(w, http.StatusInternalServerError, errorResponse{Error: "could not generate key"})
		return
	}

	k := config.APIKey{
		Name:         req.Name,
		Hash:         hashHex,
		Services:     req.Services,
		Actions:      req.Actions,
		AllowOrigins: req.AllowOrigins,
		CreatedAt:    time.Now().UTC().Format(time.RFC3339),
	}
	if _, err := s.live.AddAPIKey(id, k); err != nil {
		writeConfigError(w, err)
		return
	}
	k.ID = id

	writeJSON(w, http.StatusCreated, ConfigKeyCreateResponse{
		ID:          id,
		Key:         rawKey,
		YAMLSnippet: apiKeyYAML(k),
	})
}

// handleConfigKeyDelete answers DELETE /api/config/keys/{id}: revokes
// an overlay-only key. Unknown id -> 404; a base key -> 409.
func (s *Server) handleConfigKeyDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	switch s.apiKeySource(id) {
	case "base":
		writeJSON(w, http.StatusConflict, errorResponse{Error: "key " + id + " comes from the base config and is read-only"})
		return
	case "":
		writeJSON(w, http.StatusNotFound, errorResponse{Error: "unknown key"})
		return
	}
	if _, err := s.live.DeleteAPIKey(id); err != nil {
		writeConfigError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleConfigReload answers POST /api/config/reload: re-reads base +
// overlay from disk (same as SIGHUP, see cmd/hodor) and reports any
// fields that could not be hot-reloaded.
func (s *Server) handleConfigReload(w http.ResponseWriter, _ *http.Request) {
	warnings, err := s.live.Reload()
	if err != nil {
		writeConfigError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, ConfigReloadResponse{OK: true, Warnings: warnings})
}

// writeConfigError reports err (always a config.Validate failure, by
// construction: every Live mutator validates before touching disk) as
// a 400 with the field it points to, extracted from the leading
// "field: message" shape every Validate error uses.
func writeConfigError(w http.ResponseWriter, err error) {
	field, msg := splitFieldError(err)
	writeValidationError(w, field, msg)
}

func writeValidationError(w http.ResponseWriter, field, msg string) {
	writeJSON(w, http.StatusBadRequest, validationErrorResponse{Errors: map[string]string{field: msg}})
}

// splitFieldError splits a config.Validate error of the form
// "field[x]: message" (or "field: message") into its field and
// message parts. Errors with no leading "field:" are reported under
// the catch-all key "config".
func splitFieldError(err error) (field, msg string) {
	s := err.Error()
	if i := strings.Index(s, ":"); i >= 0 {
		return strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+1:])
	}
	return "config", s
}

// apiKeyYAML renders k as a hodor.yaml api_keys entry, mirroring
// cmd/hodor's keyYAML (kept separate: that one has no id/allow_origins
// yet at generation time, these always do).
func apiKeyYAML(k config.APIKey) string {
	var b strings.Builder
	b.WriteString("api_keys:\n")
	b.WriteString("  - id: " + strconv.Quote(k.ID) + "\n")
	b.WriteString("    name: " + strconv.Quote(k.Name) + "\n")
	b.WriteString("    hash: " + strconv.Quote(k.Hash) + "\n")
	b.WriteString("    services: [" + quoteYAMLList(k.Services) + "]\n")
	b.WriteString("    actions: [" + quoteYAMLList(k.Actions) + "]\n")
	if len(k.AllowOrigins) > 0 {
		b.WriteString("    allow_origins: [" + quoteYAMLList(k.AllowOrigins) + "]\n")
	}
	b.WriteString("    created_at: " + strconv.Quote(k.CreatedAt) + "\n")
	return b.String()
}

func quoteYAMLList(items []string) string {
	quoted := make([]string, len(items))
	for i, it := range items {
		quoted[i] = strconv.Quote(it)
	}
	return strings.Join(quoted, ", ")
}
