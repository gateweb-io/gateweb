package urldb

import "strings"

// NormalizeDomain lowercases the domain, strips "www." prefix and port.
func NormalizeDomain(host string) string {
	// Strip port.
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		// Make sure it's a port, not part of IPv6.
		if !strings.Contains(host[idx:], "]") {
			host = host[:idx]
		}
	}
	host = strings.ToLower(host)
	host = strings.TrimPrefix(host, "www.")
	host = strings.TrimSuffix(host, ".")
	return host
}
