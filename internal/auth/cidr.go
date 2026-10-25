// Package auth holds small, focused security helpers shared by the proxy
// and admin packages: client IP resolution, CIDR allow-listing, constant
// time comparisons and a basic rate limiter.
package auth

import (
	"net"
	"net/http"
	"strings"
)

// IPAllowed reports whether ip is contained in any of the given networks.
func IPAllowed(nets []*net.IPNet, ip net.IP) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// ClientIP resolves the real client IP for r. If r.RemoteAddr's host is
// within trustedProxies, the given header (e.g. X-Forwarded-For) is
// walked from right to left, skipping entries that are themselves
// trusted proxies, and the first non-trusted entry found is returned
// (classic "walk back through the trusted hop chain" handling for a
// reverse proxy like Traefik). This defeats a client spoofing its own
// IP by prepending a fake entry to XFF: an attacker controls only the
// leftmost entries, never the ones appended by trusted proxies, so
// trusting the leftmost (as a naive implementation does) lets anyone
// claim any IP. If every entry turns out to be a trusted proxy, the
// leftmost one is returned as a last resort. If r.RemoteAddr's host is
// not within trustedProxies, the header is ignored entirely and
// RemoteAddr is used as-is.
func ClientIP(r *http.Request, trustedProxies []*net.IPNet, header string) net.IP {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	remote := net.ParseIP(host)
	if remote == nil {
		return nil
	}
	if header == "" || len(trustedProxies) == 0 || !IPAllowed(trustedProxies, remote) {
		return remote
	}
	v := r.Header.Get(header)
	if v == "" {
		return remote
	}

	parts := strings.Split(v, ",")
	var parsed []net.IP
	for _, p := range parts {
		ip := net.ParseIP(strings.TrimSpace(p))
		if ip == nil {
			continue
		}
		parsed = append(parsed, ip)
	}
	if len(parsed) == 0 {
		return remote
	}

	for i := len(parsed) - 1; i >= 0; i-- {
		if !IPAllowed(trustedProxies, parsed[i]) {
			return parsed[i]
		}
	}
	// Every hop in the header is itself a trusted proxy; fall back to
	// the leftmost (original) entry.
	return parsed[0]
}
