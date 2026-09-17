package autoscan

import (
	"net"
	"net/netip"
	"os"
	"strings"

	sharedautoscan "github.com/vistasecurity/vistaplatform/shared/autoscan"
)

// EnvExcludeCIDRs names ranges the platform must never probe on its own
// initiative. The process already excludes its own addresses, but it cannot
// discover the cluster's pod/service CIDRs from inside a pod, so an operator
// who wants those out of scope names them here (comma-separated CIDRs or bare
// addresses).
const EnvExcludeCIDRs = "DISCOVERY_AUTO_SCAN_EXCLUDE_CIDRS"

// PlatformExcludedPrefixes is the platform protecting itself: every address
// this process holds, the in-cluster Kubernetes API when the downward
// environment names it, and anything the operator listed.
//
// Classify checks these BEFORE the private-address rule, so nothing — not
// RFC 1918, not a tenant's own segment declaration — can put them back in
// scope.
//
// It lives here rather than in the worker because the settings page's
// "assets in scope" count has to be computed with the SAME exclusions the
// sweep uses. A number on a page that describes a different set from the one
// the platform scans is worse than no number.
func PlatformExcludedPrefixes() []netip.Prefix {
	var raw []string
	if v := os.Getenv(EnvExcludeCIDRs); v != "" {
		for _, part := range strings.Split(v, ",") {
			raw = append(raw, strings.TrimSpace(part))
		}
	}
	if host := os.Getenv("KUBERNETES_SERVICE_HOST"); host != "" {
		raw = append(raw, host)
	}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if ipnet, ok := a.(*net.IPNet); ok {
				raw = append(raw, ipnet.IP.String())
			}
		}
	}
	return sharedautoscan.ParsePrefixes(raw)
}
