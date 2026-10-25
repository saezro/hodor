// Package web renders hodor's three HTML pages (closed, tv, panel) from
// the templates embedded by the web package (repo-root web/templates),
// filling in the small view-model structs documented at the top of each
// template file. It intentionally contains no business logic: callers in
// internal/proxy and internal/admin build the view models.
package web

import (
	"html/template"
	"io"

	"github.com/saezro/hodor/internal/i18n"
	hodorweb "github.com/saezro/hodor/web"
)

var tmpl = template.Must(template.ParseFS(hodorweb.Templates, "templates/*.html"))

// ClosedStrings holds the translated strings used by closed.html.
type ClosedStrings struct {
	Title       string
	Ask         string
	AdminButton string
}

// ClosedData is the view model for closed.html.
type ClosedData struct {
	Lang         string
	ServiceTitle string
	Message      string
	AccentColor  string
	LogoURL      string
	AdminURL     string
	Strings      ClosedStrings
}

// NewClosedData builds a ClosedData with translated strings for lang.
func NewClosedData(lang i18n.Lang, serviceTitle, message, accentColor, logoURL, adminURL string) ClosedData {
	return ClosedData{
		Lang:         string(lang),
		ServiceTitle: serviceTitle,
		Message:      message,
		AccentColor:  accentColor,
		LogoURL:      logoURL,
		AdminURL:     adminURL,
		Strings: ClosedStrings{
			Title:       i18n.T(lang, "closed.title"),
			Ask:         i18n.T(lang, "closed.ask"),
			AdminButton: i18n.T(lang, "closed.admin_button"),
		},
	}
}

// RenderClosed writes closed.html for d to w.
func RenderClosed(w io.Writer, d ClosedData) error {
	return tmpl.ExecuteTemplate(w, "closed.html", d)
}

// TVStrings holds the translated strings used by tv.html.
type TVStrings struct {
	Title    string
	EnterPin string
	Expires  string
	QRTodo   string
}

// TVData is the view model for tv.html.
type TVData struct {
	Lang             string
	ServiceName      string
	ServiceTitle     string
	Code             string
	SessionID        string
	ExpiresInSeconds int
	QRAvailable      bool
	QRDataURI        string
	Strings          TVStrings
}

// NewTVData builds a TVData with translated strings for lang.
func NewTVData(lang i18n.Lang, serviceName, serviceTitle, code, sessionID string, expiresInSeconds int) TVData {
	return TVData{
		Lang:             string(lang),
		ServiceName:      serviceName,
		ServiceTitle:     serviceTitle,
		Code:             code,
		SessionID:        sessionID,
		ExpiresInSeconds: expiresInSeconds,
		QRAvailable:      false, // TODO: pure-Go QR encoder; PIN-only in v0.1.
		Strings: TVStrings{
			Title:    i18n.T(lang, "tv.title"),
			EnterPin: i18n.T(lang, "tv.enter_pin"),
			Expires:  i18n.T(lang, "tv.expires"),
			QRTodo:   i18n.T(lang, "tv.qr_todo"),
		},
	}
}

// RenderTV writes tv.html for d to w.
func RenderTV(w io.Writer, d TVData) error {
	return tmpl.ExecuteTemplate(w, "tv.html", d)
}

// PanelStrings holds the translated strings used by panel.html. The
// skeleton/empty/error/action strings rendered dynamically by panel.js
// (service rows, PIN rows, toasts) are translated client-side instead —
// see the STR dict in panel.js — since they depend on data not known at
// render time.
type PanelStrings struct {
	Title        string
	NavLabel     string
	TabServices  string
	TabPins      string
	TabPasses    string
	TabEvents    string
	HintServices string
	HintPins     string
	HintPasses   string
	HintEvents   string
}

// PanelData is the view model for panel.html.
type PanelData struct {
	Lang      string
	CSRFToken string
	Durations []string
	Strings   PanelStrings
}

// NewPanelData builds a PanelData with translated strings for lang.
// durations is the configured open-for presets (config.Config.Durations,
// e.g. ["1h","3h","6h","24h"]), passed through so the panel's "open for"
// control matches the deployment instead of hardcoding a guess.
func NewPanelData(lang i18n.Lang, csrfToken string, durations []string) PanelData {
	return PanelData{
		Lang:      string(lang),
		CSRFToken: csrfToken,
		Durations: durations,
		Strings: PanelStrings{
			Title:        i18n.T(lang, "panel.title"),
			NavLabel:     i18n.T(lang, "panel.nav_label"),
			TabServices:  i18n.T(lang, "panel.tab.services"),
			TabPins:      i18n.T(lang, "panel.tab.pins"),
			TabPasses:    i18n.T(lang, "panel.tab.passes"),
			TabEvents:    i18n.T(lang, "panel.tab.events"),
			HintServices: i18n.T(lang, "panel.hint.services"),
			HintPins:     i18n.T(lang, "panel.hint.pins"),
			HintPasses:   i18n.T(lang, "panel.hint.passes"),
			HintEvents:   i18n.T(lang, "panel.hint.events"),
		},
	}
}

// RenderPanel writes panel.html for d to w.
func RenderPanel(w io.Writer, d PanelData) error {
	return tmpl.ExecuteTemplate(w, "panel.html", d)
}

// EmbedData is the view model for embed.html: the tiny iframe-able
// status/open widget served by GET /embed/{svc}. Key is passed through
// verbatim so embed.js can call /api/v1/services/{svc} with it; it is
// rendered via html/template, so it is escaped like any other field
// (never trust it to be safe on its own).
type EmbedData struct {
	Service string
	Key     string
	Lang    string
}

// RenderEmbed writes embed.html for d to w.
func RenderEmbed(w io.Writer, d EmbedData) error {
	return tmpl.ExecuteTemplate(w, "embed.html", d)
}
