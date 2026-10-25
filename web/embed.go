// Package web embeds hodor's HTML templates and static assets into the
// binary. It intentionally contains no logic: internal/web/render.go
// parses and renders these files. Keeping the embed.FS declaration here,
// at the top of the actual web/ directory, is required because Go's
// //go:embed patterns cannot reach outside the package directory (no
// "../" patterns), while the repo layout wants web/ at the repo root.
package web

import "embed"

// Templates holds web/templates/*.html.
//
//go:embed templates/*.html
var Templates embed.FS

// Static holds web/static/* (CSS/JS served as-is, no build step).
//
//go:embed static
var Static embed.FS
