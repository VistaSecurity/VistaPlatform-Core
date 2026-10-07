package autoscan

import (
	"net"
	"net/netip"
	"os"
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/network"
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
	return ParsePrefixes(raw)
}

// ClusterInternalPrefixes are this cluster's own pod and Service CIDRs, from the
// one list the chart hands every service that dials customer private networks
// (networkPolicy.clusterInternalCIDRs, as VISTA_PLATFORM_INTERNAL_CIDRS). An
// unset or empty variable yields none.
//
// They are deliberately NOT part of [PlatformExcludedPrefixes]. That list is
// the platform protecting itself and applies to every scan whoever executes it.
// These ranges mean something only to a scan the in-cluster Platform Sensor
// executes: from inside the cluster 10.43.0.0/16 IS the Services (RFC 1918 space
// counts as the tenant's own by address class, so without this a tenant's scan
// of it was authorized and its results read back), while to a tenant's own
// on-premises sensor the same numbers are customer address space it has every
// right to scan. Callers apply them only where the executor is the Platform
// Sensor.
func ClusterInternalPrefixes() []netip.Prefix {
	var raw []string
	if v := os.Getenv(network.PlatformInternalCIDRsEnv); v != "" {
		for _, part := range strings.Split(v, ",") {
			raw = append(raw, strings.TrimSpace(part))
		}
	}
	return ParsePrefixes(raw)
}
