package hostinventory

import (
	"net/url"
	"strings"
)

// normaliseMAC renders a MAC as lower-case colon-separated hex, or "" when the
// input is not one.
//
// It rejects the all-zero and broadcast forms for the same reason
// deviceinterrogation's canonicalMAC does: both are placeholders a device
// returns for "nothing here", and storing one as an identity is how two
// unrelated assets merge into one.
func normaliseMAC(v string) string {
	var hex strings.Builder
	hex.Grow(12)
	for _, r := range strings.ToLower(strings.TrimSpace(v)) {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
			hex.WriteRune(r)
		case r == ':', r == '-', r == '.', r == ' ':
			// separator
		default:
			return ""
		}
	}
	h := hex.String()
	if len(h) != 12 || h == "000000000000" || h == "ffffffffffff" {
		return ""
	}
	var out strings.Builder
	out.Grow(17)
	for i := 0; i < 12; i += 2 {
		if i > 0 {
			out.WriteByte(':')
		}
		out.WriteString(h[i : i+2])
	}
	return out.String()
}

// virtualInterfacePrefixes name interfaces whose MAC is generated rather than
// burned in.
//
// A container's veth, a bridge, a tunnel and a loopback all have MACs, and all
// of those MACs are ephemeral or synthesised. Minting an asset identity from
// one produces a new asset on every container restart — the same failure mode
// as a locally-administered MAC, which the passive host-observation contract
// already refuses for the same reason.
var virtualInterfacePrefixes = []string{
	"lo", "docker", "br-", "veth", "virbr", "vmnet", "vboxnet", "tun", "tap",
	"cni", "flannel", "cali", "cilium", "kube-", "wg", "utun", "bridge",
	"awdl", "llw", "gif", "stf", "ap1", "anpi",
}

// isVirtualInterface reports whether an interface's MAC is unsuitable as an
// asset key.
func isVirtualInterface(name string, loopback bool) bool {
	if loopback {
		return true
	}
	n := strings.ToLower(strings.TrimSpace(name))
	if n == "" {
		return true
	}
	for _, p := range virtualInterfacePrefixes {
		if strings.HasPrefix(n, p) {
			return true
		}
	}
	return false
}

// locallyAdministered reports whether a MAC has the locally-administered bit
// set, which means it was assigned by software and is not a manufacturer
// identity. Kept separate from the name heuristic because a physical NIC can
// be given one and a virtual interface can borrow a real one.
func locallyAdministered(mac string) bool {
	if len(mac) < 2 {
		return false
	}
	var b byte
	switch {
	case mac[1] >= '0' && mac[1] <= '9':
		b = mac[1] - '0'
	case mac[1] >= 'a' && mac[1] <= 'f':
		b = mac[1] - 'a' + 10
	default:
		return false
	}
	return b&0x02 != 0
}

// splitFQDN separates a fully-qualified name into its short hostname and its
// domain. A single-label name has no domain, and this returns none rather than
// inventing one.
func splitFQDN(fqdn string) (host, domain string) {
	f := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(fqdn)), ".")
	if f == "" {
		return "", ""
	}
	i := strings.Index(f, ".")
	if i <= 0 || i == len(f)-1 {
		return f, ""
	}
	return f[:i], f[i+1:]
}

// ---------------------------------------------------------------------------
// Package URLs
// ---------------------------------------------------------------------------
//
// Per the purl spec (github.com/package-url/purl-spec). Only the three
// ecosystems that HAVE a purl type get one:
//
//	pkg:deb/debian/openssl@3.0.2-0ubuntu1?arch=amd64
//	pkg:rpm/rhel/openssl@3.0.7-27.el9?arch=x86_64
//	pkg:apk/alpine/openssl@3.1.4-r5?arch=x86_64
//
// Windows registry entries and macOS applications get NO purl. There is no
// registered purl type for either, and minting `pkg:windows/...` would put a
// string that looks like a join key into a column consumers join on.

// purlDeb builds a Debian/Ubuntu purl. namespace is the distribution family
// ("debian" or "ubuntu") as /etc/os-release reports it.
func purlDeb(namespace, name, version, arch string) string {
	return buildPURL("deb", namespace, name, version, arch)
}

// purlRPM builds an RPM purl.
func purlRPM(namespace, name, version, arch string) string {
	return buildPURL("rpm", namespace, name, version, arch)
}

// purlAPK builds an Alpine purl. The namespace is always "alpine" — apk is
// Alpine's package manager and the spec's registered namespace for it.
func purlAPK(name, version, arch string) string {
	return buildPURL("apk", "alpine", name, version, arch)
}

// buildPURL assembles pkg:<type>/<namespace>/<name>@<version>?arch=<arch>.
//
// A package with no name yields "" — a purl without a name identifies nothing,
// and an identifier that identifies nothing is worse in a join column than an
// absent one. Namespace and arch are each omitted when unknown rather than
// defaulted, for the same reason.
func buildPURL(typ, namespace, name, version, arch string) string {
	name = strings.TrimSpace(name)
	if typ == "" || name == "" {
		return ""
	}
	var b strings.Builder
	b.WriteString("pkg:")
	b.WriteString(typ)
	b.WriteByte('/')
	if ns := strings.ToLower(strings.TrimSpace(namespace)); ns != "" {
		b.WriteString(url.PathEscape(ns))
		b.WriteByte('/')
	}
	b.WriteString(url.PathEscape(name))
	if v := strings.TrimSpace(version); v != "" {
		b.WriteByte('@')
		b.WriteString(url.PathEscape(v))
	}
	if a := strings.TrimSpace(arch); a != "" {
		b.WriteString("?arch=")
		b.WriteString(url.QueryEscape(a))
	}
	return b.String()
}
