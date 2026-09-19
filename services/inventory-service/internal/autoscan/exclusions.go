package autoscan

import (
	sharedautoscan "github.com/vistasecurity/vistaplatform/shared/autoscan"
	"net/netip"
)

// EnvExcludeCIDRs and PlatformExcludedPrefixes are shared by automatic scans
// and configured-source refreshes, so a source lookup cannot bypass exclusions.
const EnvExcludeCIDRs = sharedautoscan.EnvExcludeCIDRs

func PlatformExcludedPrefixes() []netip.Prefix { return sharedautoscan.PlatformExcludedPrefixes() }
