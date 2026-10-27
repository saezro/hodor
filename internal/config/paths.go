package config

import (
	"fmt"
	"path"
	"strings"
)

// Access controls how a request is treated once it is matched to a
// path rule (or falls through to a service's DefaultAccess).
type Access string

const (
	// AccessGated is today's behavior: let the request through if the
	// service is open, or if it carries a valid device pass and
	// PassBypassesClosed allows it; otherwise show the closed page (or,
	// in forwardauth mode, deny per Auth.OnDeny). It is the implicit
	// default when DefaultAccess/an individual rule's Access is empty.
	AccessGated Access = "gated"
	// AccessDeny always answers 404, regardless of open/closed state or
	// any device pass - a hard block carved out of an otherwise gated
	// or public service.
	AccessDeny Access = "deny"
	// AccessPublic always lets the request through, even while the
	// service is closed and with no pass at all.
	AccessPublic Access = "public"
)

// validMethods is the set of HTTP methods a PathRule may restrict
// itself to.
var validMethods = map[string]bool{
	"GET": true, "HEAD": true, "POST": true, "PUT": true, "PATCH": true,
	"DELETE": true, "OPTIONS": true, "CONNECT": true, "TRACE": true,
}

// PathRule is one per-path access override for a Service (see
// Service.Paths). Exactly one of Path/Prefix must be set.
type PathRule struct {
	// Path matches the normalized request path exactly.
	Path string `yaml:"path,omitempty" json:"path,omitempty"`
	// Prefix matches any normalized request path starting with it.
	Prefix string `yaml:"prefix,omitempty" json:"prefix,omitempty"`
	// Methods restricts the rule to these HTTP methods (uppercase). An
	// empty list matches every method.
	Methods []string `yaml:"methods,omitempty" json:"methods,omitempty"`
	// Access is the decision applied when this rule matches.
	Access Access `yaml:"access" json:"access"`
}

// validate checks one PathRule in isolation: it does not know about
// its sibling rules (order/overlap is intentional, see MatchAccess).
func (r *PathRule) validate() error {
	if r.Path == "" && r.Prefix == "" {
		return fmt.Errorf("exactly one of path or prefix is required")
	}
	if r.Path != "" && r.Prefix != "" {
		return fmt.Errorf("exactly one of path or prefix is required, not both")
	}
	if r.Path != "" && !strings.HasPrefix(r.Path, "/") {
		return fmt.Errorf("path %q must start with /", r.Path)
	}
	if r.Prefix != "" && !strings.HasPrefix(r.Prefix, "/") {
		return fmt.Errorf("prefix %q must start with /", r.Prefix)
	}
	switch r.Access {
	case AccessGated, AccessDeny, AccessPublic:
	case "":
		return fmt.Errorf("access is required")
	default:
		return fmt.Errorf("invalid access %q (want %q, %q or %q)", r.Access, AccessGated, AccessDeny, AccessPublic)
	}
	for _, m := range r.Methods {
		if !validMethods[m] {
			return fmt.Errorf("invalid method %q (must be uppercase, one of the standard HTTP methods)", m)
		}
	}
	return nil
}

// matches reports whether this rule applies to the already-normalized
// path p and the already-uppercased method.
func (r *PathRule) matches(p, method string) bool {
	if len(r.Methods) > 0 {
		found := false
		for _, m := range r.Methods {
			if m == method {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if r.Path != "" {
		return p == r.Path
	}
	return strings.HasPrefix(p, r.Prefix)
}

// NormalizePath cleans raw (a request path) with path.Clean - which
// also collapses any ".." segment into its resolved, always-rooted
// form, so a request can never use "../" to step outside of what it
// looks like it's requesting - while preserving a trailing slash when
// raw had one, since that matters for Prefix rules (e.g. "/vendor/"
// should still match "/vendor/" after cleaning, not just "/vendor").
// An empty raw normalizes to "/".
func NormalizePath(raw string) string {
	if raw == "" {
		return "/"
	}
	hadTrailingSlash := raw != "/" && strings.HasSuffix(raw, "/")
	cleaned := path.Clean(raw)
	if !strings.HasPrefix(cleaned, "/") {
		cleaned = "/" + cleaned
	}
	if hadTrailingSlash && !strings.HasSuffix(cleaned, "/") {
		cleaned += "/"
	}
	return cleaned
}

// MatchAccess resolves the Access that applies to rawPath/method for
// this service: the first rule in s.Paths that matches wins; if none
// does, s.DefaultAccess applies (AccessGated if that is empty too -
// i.e. exactly today's behavior when no paths/default_access are
// configured at all). rawPath is normalized internally (see
// NormalizePath); method is uppercased.
func (s *Service) MatchAccess(rawPath, method string) Access {
	p := NormalizePath(rawPath)
	m := strings.ToUpper(method)
	for i := range s.Paths {
		if s.Paths[i].matches(p, m) {
			return s.Paths[i].Access
		}
	}
	if s.DefaultAccess == "" {
		return AccessGated
	}
	return s.DefaultAccess
}
