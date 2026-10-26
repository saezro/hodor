package config

import (
	"errors"
	"fmt"
	"net"
	"os"
)

// ErrLockout is returned by Live.PutGeneral when applying patch would
// leave the requesting client's own IP outside the resulting
// admin.allow_cidrs - the anti-lockout check from docs/DESIGN.md
// "Phase 3". Nothing is written when this happens.
var ErrLockout = errors.New("would lock you out")

// GeneralLockedError is returned by Live.PutGeneral when patch touches
// a field that the base config (or, for AdminAllowCIDRs, an env
// override) already sets: those fields are read-only from the panel,
// same rule as a base service/api_key (see internal/admin's 409 on
// PUT /api/config/services/{name}).
type GeneralLockedError struct {
	// Field is the JSON/patch field name, e.g. "admin_allow_cidrs" -
	// matches the "locked" list returned by LockedGeneralFields.
	Field string
}

func (e *GeneralLockedError) Error() string {
	return fmt.Sprintf("general.%s: comes from the base config (or an env override) and is read-only", e.Field)
}

// LockedGeneralFields returns the general-section field names that are
// not writable from the panel's PUT /api/config/general: raw is the
// *unvalidated* base config (see LoadRaw - Load's defaults would
// otherwise make every field look "set"). AdminAllowCIDRs is also
// locked when HODOR_ADMIN_ALLOW_CIDRS is set, independent of what
// hodor.yaml says.
func LockedGeneralFields(raw *Config) []string {
	var locked []string
	if raw.Lang != "" {
		locked = append(locked, "lang")
	}
	if raw.Admin.PublicURL != "" {
		locked = append(locked, "admin_public_url")
	}
	if len(raw.Admin.AllowCIDRs) > 0 || os.Getenv("HODOR_ADMIN_ALLOW_CIDRS") != "" {
		locked = append(locked, "admin_allow_cidrs")
	}
	if raw.Admin.Token != "" {
		locked = append(locked, "admin_token")
	}
	if len(raw.Public.TrustedProxies) > 0 {
		locked = append(locked, "public_trusted_proxies")
	}
	if raw.Public.CookieSecure != nil {
		locked = append(locked, "public_cookie_secure")
	}
	if raw.PassTTL != "" {
		locked = append(locked, "pass_ttl")
	}
	if raw.OnChange != "" {
		locked = append(locked, "on_change")
	}
	return locked
}

// GeneralPatch is a partial update to the overlay's General section
// (PUT /api/config/general): a nil field is left untouched; a non-nil
// one replaces the overlay's value for it, even if it points at a
// zero value (e.g. AdminToken pointing at "" clears a previously-set
// overlay token). Built by internal/admin from the request body with
// the same field names as LockedGeneralFields.
type GeneralPatch struct {
	Lang                 *string
	AdminPublicURL       *string
	AdminAllowCIDRs      *[]string
	AdminToken           *string
	PublicTrustedProxies *[]string
	PublicCookieSecure   *bool
	PassTTL              *string
	OnChange             *string
}

// fieldsTouched lists the field names patch actually sets (non-nil),
// in LockedGeneralFields' naming, so Live.PutGeneral can reject a
// patch that touches a locked one before writing anything.
func (p GeneralPatch) fieldsTouched() []string {
	var f []string
	if p.Lang != nil {
		f = append(f, "lang")
	}
	if p.AdminPublicURL != nil {
		f = append(f, "admin_public_url")
	}
	if p.AdminAllowCIDRs != nil {
		f = append(f, "admin_allow_cidrs")
	}
	if p.AdminToken != nil {
		f = append(f, "admin_token")
	}
	if p.PublicTrustedProxies != nil {
		f = append(f, "public_trusted_proxies")
	}
	if p.PublicCookieSecure != nil {
		f = append(f, "public_cookie_secure")
	}
	if p.PassTTL != nil {
		f = append(f, "pass_ttl")
	}
	if p.OnChange != nil {
		f = append(f, "on_change")
	}
	return f
}

// apply writes patch's non-nil fields into g (the overlay's General
// section), in place.
func (p GeneralPatch) apply(g *General) {
	if p.Lang != nil {
		g.Lang = p.Lang
	}
	if p.AdminPublicURL != nil {
		g.AdminPublicURL = p.AdminPublicURL
	}
	if p.AdminAllowCIDRs != nil {
		g.AdminAllowCIDRs = *p.AdminAllowCIDRs
	}
	if p.AdminToken != nil {
		g.AdminToken = p.AdminToken
	}
	if p.PublicTrustedProxies != nil {
		g.PublicTrustedProxies = *p.PublicTrustedProxies
	}
	if p.PublicCookieSecure != nil {
		g.PublicCookieSecure = p.PublicCookieSecure
	}
	if p.PassTTL != nil {
		g.PassTTL = p.PassTTL
	}
	if p.OnChange != nil {
		g.OnChange = p.OnChange
	}
}

// ipInCIDRs reports whether ip is covered by any net in nets.
func ipInCIDRs(nets []*net.IPNet, ip net.IP) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
