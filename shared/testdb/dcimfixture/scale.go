// Package dcimfixture generates the DCIM scale tenant (DATA_MODEL §12) for
// integration tests that carry a performance budget.
//
// Populate is deterministic (a seeded PRNG plus stable names such as
// site-0042, rack-0042-07, sw-0042-07-01, Gi1/0/24) and phase-aware: it
// populates every table that exists in the connected database, checked with
// to_regclass, and reports the rest in Summary.Skipped. See README.md for how
// a later workstream adds its populator.
package dcimfixture

import "fmt"

// Scale is the shape of the generated tenant. Totals are products: Racks =
// Sites*RacksPerSite, Assets = Racks*AssetsPerRack, and so on.
type Scale struct {
	Sites              int
	RacksPerSite       int
	AssetsPerRack      int
	InterfacesPerAsset int
	PrefixesPerSite    int
	IPsPerPrefix       int
	CablesPerRack      int
	// Seed feeds the PRNG. The same Seed yields the same names and ids.
	Seed uint64
}

// Scale1 is DATA_MODEL §12: 500 sites, 5,000 racks, 50,000 assets, 500,000
// interfaces, 20,000 prefixes holding 200,000 IP addresses, 100,000 cables.
func Scale1() Scale {
	return Scale{
		Sites: 500, RacksPerSite: 10, AssetsPerRack: 10,
		InterfacesPerAsset: 10, PrefixesPerSite: 40, IPsPerPrefix: 10,
		CablesPerRack: 20, Seed: 1,
	}
}

// Small is a unit-ish shape: 4 sites, 40 racks, 400 assets.
func Small() Scale {
	return Scale{
		Sites: 4, RacksPerSite: 10, AssetsPerRack: 10,
		InterfacesPerAsset: 4, PrefixesPerSite: 4, IPsPerPrefix: 4,
		CablesPerRack: 4, Seed: 1,
	}
}

// Racks, Assets, Interfaces, Prefixes, IPs and Cables are the derived totals.
func (s Scale) Racks() int      { return s.Sites * s.RacksPerSite }
func (s Scale) Assets() int     { return s.Racks() * s.AssetsPerRack }
func (s Scale) Interfaces() int { return s.Assets() * s.InterfacesPerAsset }
func (s Scale) Prefixes() int   { return s.Sites * s.PrefixesPerSite }
func (s Scale) IPs() int        { return s.Prefixes() * s.IPsPerPrefix }
func (s Scale) Cables() int     { return s.Racks() * s.CablesPerRack }

// Stable names. Indexes are 0-based; the slot number in an asset name is
// 1-based (sw-0042-07-01 is the first device in rack 7 of site 42).
func SiteName(site int) string       { return fmt.Sprintf("site-%04d", site) }
func RackName(site, rack int) string { return fmt.Sprintf("rack-%04d-%02d", site, rack) }
func AssetName(site, rack, slot int) string {
	prefix := "srv"
	if slot == 0 {
		prefix = "sw"
	}
	return fmt.Sprintf("%s-%04d-%02d-%02d", prefix, site, rack, slot+1)
}

// InterfaceName is the 1-based port name on a 48-port access switch: Gi1/0/24.
func InterfaceName(port int) string { return fmt.Sprintf("Gi1/0/%d", port+1) }
