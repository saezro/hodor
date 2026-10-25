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
// within trustedProxies, the first IP in the given header is used instead
// (classic X-Forwarded-For / X-Real-IP handling for a reverse proxy like
// Traefik). Otherwise RemoteAddr is used as-is.
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
	// X-Forwarded-For may be a comma-separated list; the first entry is
	// the original client.
	first := strings.TrimSpace(strings.Split(v, ",")[0])
	if ip := net.ParseIP(first); ip != nil {
		return ip
	}
	return remote
}
