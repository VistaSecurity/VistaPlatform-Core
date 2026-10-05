package discovery

import (
	"net"
	"strings"
)

// MaxSNICandidates bounds the server names a scan may offer a TLS port that
// refused the nameless attempt. It is the whole extra cost of the feature: at
// most this many more ClientHellos, to a port that already proved it speaks TLS.
const MaxSNICandidates = 3

// SanitizeSNICandidates returns the names from in that a scan may present as SNI,
// in order: lower-cased DNS names (RFC 1035 labels, at most 253 octets), no IP
// literals, no duplicates, at most MaxSNICandidates. Anything else is DROPPED and
// the rest kept: a request that crosses a service boundary is never refused for
// one bad name, it just offers fewer.
//
// The names are only ever presented in the TLS handshake. They are never
// resolved and never choose where a connection goes (the pinned address does).
func SanitizeSNICandidates(in []string) []string {
	var out []string
	seen := make(map[string]bool, len(in))
	for _, raw := range in {
		if len(out) >= MaxSNICandidates {
			break
		}
		name := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(raw), "."))
		if seen[name] || !validSNIName(name) {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	return out
}

func validSNIName(name string) bool {
	if name == "" || len(name) > 253 || net.ParseIP(name) != nil {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			switch {
			case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
			default:
				return false
			}
		}
	}
	return true
}
