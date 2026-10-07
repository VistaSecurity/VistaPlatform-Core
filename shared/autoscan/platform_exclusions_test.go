package autoscan

import (
	"net/netip"
	"testing"
)

func containsPrefix(prefixes []netip.Prefix, want string) bool {
	w := netip.MustParsePrefix(want)
	for _, p := range prefixes {
		if p == w {
			return true
		}
	}
	return false
}

// ClusterInternalPrefixes reads the chart's VISTA_PLATFORM_INTERNAL_CIDRS.
func TestClusterInternalPrefixes_ReadsTheChartList(t *testing.T) {
	t.Setenv("VISTA_PLATFORM_INTERNAL_CIDRS", "10.42.0.0/16, 10.43.0.0/16")
	got := ClusterInternalPrefixes()
	for _, want := range []string{"10.42.0.0/16", "10.43.0.0/16"} {
		if !containsPrefix(got, want) {
			t.Errorf("ClusterInternalPrefixes() lacks %s: %v", want, got)
		}
	}
}

// Unset adds nothing: a deployment that has not set it keeps its behaviour.
func TestClusterInternalPrefixes_UnsetIsEmpty(t *testing.T) {
	t.Setenv("VISTA_PLATFORM_INTERNAL_CIDRS", "")
	if got := ClusterInternalPrefixes(); len(got) != 0 {
		t.Errorf("ClusterInternalPrefixes() = %v with the variable unset", got)
	}
}

// The over-reach guard. PlatformExcludedPrefixes is consumed by paths whose
// executor is a TENANT's own collector (AuthorizeProbe, the owned-network
// scope, inventory's auto-scan scope and counts). To those the cluster's pod and
// Service numbers are customer address space, so they must NOT be in it —
// even with the variable set. Only the Platform Sensor's own authorization adds
// ClusterInternalPrefixes, explicitly.
func TestPlatformExcludedPrefixes_NeverIncludesTheClusterRanges(t *testing.T) {
	t.Setenv("VISTA_PLATFORM_INTERNAL_CIDRS", "10.42.0.0/16,10.43.0.0/16")
	t.Setenv(EnvExcludeCIDRs, "192.0.2.0/24")

	got := PlatformExcludedPrefixes()
	for _, cluster := range []string{"10.42.0.0/16", "10.43.0.0/16"} {
		if containsPrefix(got, cluster) {
			t.Errorf("PlatformExcludedPrefixes() contains %s: a tenant sensor's own LAN would be refused", cluster)
		}
	}
	// ...and the operator's own list still applies, as before.
	if !containsPrefix(got, "192.0.2.0/24") {
		t.Errorf("the operator exclusion list was lost: %v", got)
	}
}
