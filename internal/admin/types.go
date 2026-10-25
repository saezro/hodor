package admin

import "time"

// ServiceView is the JSON shape of one entry in GET /api/services. It is
// also used by cmd/hodor to decode the response for `hodor status`.
type ServiceView struct {
	Name     string     `json:"name"`
	Title    string     `json:"title"`
	Hosts    []string   `json:"hosts"`
	Mode     string     `json:"mode"`
	Group    string     `json:"group"`
	Open     bool       `json:"open"`
	Until    *time.Time `json:"until,omitempty"`
	OpenedBy string     `json:"opened_by,omitempty"`
}

// ServiceV1View is the JSON shape of GET /api/v1/services/{name}: the
// same fields as ServiceView (kept separate so `hodor status`, which
// decodes ServiceView, is unaffected) plus the configured open-for
// durations, so an embed consumer can build its own open control
// without a second request.
type ServiceV1View struct {
	ServiceView
	Durations []string `json:"durations"`
}

// PinView is the JSON shape of one entry in GET /api/pins.
type PinView struct {
	SessionID string    `json:"session_id"`
	Service   string    `json:"service"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// PassView is the JSON shape of one entry in GET /api/passes.
type PassView struct {
	ID        string    `json:"id"`
	Service   string    `json:"service"`
	CreatedAt time.Time `json:"created_at"`
	Revoked   bool      `json:"revoked"`
	Label     string    `json:"label"`
}

// EventView is the JSON shape of one entry in GET /api/events.
type EventView struct {
	Time    time.Time `json:"time"`
	Message string    `json:"message"`
}

// OpenRequest is the JSON body of POST /api/services/{name}/open.
type OpenRequest struct {
	For string `json:"for"` // duration string, e.g. "3h"; empty = until closed
}

// ApprovePinRequest is the JSON body of POST /api/pins.
type ApprovePinRequest struct {
	Code string `json:"code"`
}

// CSRFResponse is the JSON body of GET /api/csrf.
type CSRFResponse struct {
	Token string `json:"token"`
}

// errorResponse is the JSON body returned on API errors.
type errorResponse struct {
	Error string `json:"error"`
}
