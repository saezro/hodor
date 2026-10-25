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
// claim any IP. If every parseable entry turns out to be a trusted
// proxy, the rightmost one is returned as a last resort (never the
// leftmost: it is still client-supplied and no trusted proxy is known
// to have vouched for it). If an entry cannot be parsed as an IP, the
// walk stops there and the last trusted hop seen so far (or remote, if
// none yet) is returned, rather than skipping over the bad entry and
// treating whatever is further left as trustworthy. If r.RemoteAddr's
// host is not within trustedProxies, the header is ignored entirely and
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
	// http.Header.Get only returns the first occurrence of the header;
	// joining every occurrence (as the spec treats repeated headers,
	// comma-joined, as equivalent to one) avoids missing entries an
	// earlier hop appended in a second X-Forwarded-For line.
	v := strings.Join(r.Header.Values(header), ",")
	if v == "" {
		return remote
	}

	parts := strings.Split(v, ",")

	// Walk right to left. The rightmost entries are appended by proxies
	// we trust, so they can be relied on to identify the real hop chain;
	// the leftmost entries are supplied by the client and cannot be
	// trusted. Stop at the first entry that fails to parse: trusting
	// anything to its left would mean trusting a value a trusted proxy
	// never actually vouched for (an untrusted entry could be hidden
	// behind a garbage one, e.g. "ip:port" instead of a bare IP, to make
	// a naive implementation skip past it).
	last := remote
	for i := len(parts) - 1; i >= 0; i-- {
		ip := net.ParseIP(strings.TrimSpace(parts[i]))
		if ip == nil {
			return last
		}
		if !IPAllowed(trustedProxies, ip) {
			return ip
		}
		if i == len(parts)-1 {
			// Remember the rightmost entry only: it is the fallback if
			// every entry turns out to be trusted. Hops further left,
			// though also trusted here, must not overwrite it (they are
			// not the rightmost one and keeping the loop's "last" on
			// them would make the all-trusted fallback leftmost again).
			last = ip
		}
	}
	// Every parseable hop in the header is itself a trusted proxy. The
	// leftmost entry is still client-controlled (nothing proves a
	// trusted proxy ever saw or appended it), so it must not be
	// returned; fall back to the rightmost trusted hop seen, or remote
	// if the header was empty of entries.
	return last
}
