package dispatchguard

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/autoscan"
	"github.com/vistasecurity/vistaplatform/shared/network"
)

// Target authorization — the check that applies to EVERY dispatch, not just the
// unattended one.
//
// AuthorizeAutomaticScan short-circuits on `options["origin"] == "auto_scan"`,
// an option the CALLER supplies. A manually-created job therefore reached the
// scanner authorized by nothing at all: a tenant user could name 127.0.0.1, the
// cluster's own Service CIDR, 169.254.169.254 (cloud instance metadata) or an
// arbitrary public host and read the results back. CLAUDE.md's "never probe
// external third parties" was enforced on the unattended path only, and
// documentation is not enforcement.
//
// What this adds is deliberately narrower than the automatic-scan policy. It
// does NOT consult the auto-scan enable flag, the protocol/port allowlist, the
// per-asset sensitivity list or asset eligibility — a person pressing "scan"
// may legitimately probe an address the unattended sweep would leave alone.
// It authorizes exactly one thing: the ADDRESS is inside what this tenant is
// entitled to scan, and outside what nobody may scan. Both guards run on the
// automatic path; only this one runs on the manual path.
//
// The scope is an interval test rather than a per-address one so a CIDR or a
// range is authorized as a whole. A prefix is a contiguous numeric interval, so
// "some allowed prefix contains both endpoints" proves every address between
// them is in scope, and "no excluded prefix overlaps the interval" proves none
// of them is out of it.

// reservedPrefixes are refused for every tenant, on every path, regardless of
// what the tenant declared as a network segment. Exclusions are evaluated
// before the allow rules (see Authorize), so declaring 169.254.0.0/16 as "my
// network" cannot put the cloud metadata service back in scope.
//
// The cluster's own Service/Pod CIDRs are NOT here because they are RFC 1918
// and differ per install; an operator names them in
// DISCOVERY_AUTO_SCAN_EXCLUDE_CIDRS (autoscan.EnvExcludeCIDRs), which
// PlatformExcludedPrefixes reads and LoadTargetScope folds in below along with
// the in-cluster Kubernetes API address and every address this process holds.
var reservedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),       // "this network" / unspecified
	netip.MustParsePrefix("127.0.0.0/8"),     // loopback
	netip.MustParsePrefix("169.254.0.0/16"),  // link-local, incl. 169.254.169.254
	netip.MustParsePrefix("100.64.0.0/10"),   // RFC 6598 carrier-grade NAT
	netip.MustParsePrefix("192.0.0.0/24"),    // IETF protocol assignments
	netip.MustParsePrefix("192.0.2.0/24"),    // documentation
	netip.MustParsePrefix("198.51.100.0/24"), // documentation
	netip.MustParsePrefix("203.0.113.0/24"),  // documentation
	netip.MustParsePrefix("224.0.0.0/4"),     // multicast
	netip.MustParsePrefix("240.0.0.0/4"),     // reserved, incl. 255.255.255.255
	netip.MustParsePrefix("::/128"),          // unspecified
	netip.MustParsePrefix("::1/128"),         // loopback
	netip.MustParsePrefix("fe80::/10"),       // link-local
	netip.MustParsePrefix("fec0::/10"),       // deprecated site-local
	netip.MustParsePrefix("ff00::/8"),        // multicast
	netip.MustParsePrefix("2001:db8::/32"),   // documentation
	netip.MustParsePrefix("64:ff9b::/96"),    // NAT64 — a prefix onto arbitrary IPv4
	netip.MustParsePrefix("64:ff9b:1::/48"),  // local-use NAT64 (RFC 8215) — the same, locally
	netip.MustParsePrefix("::/96"),           // IPv4-compatible (deprecated): ::a9fe:a9fe is 169.254.169.254
	netip.MustParsePrefix("::ffff:0:0:0/96"), // SIIT IPv4-translated (RFC 2765): the same, translated
}

// 6to4 (RFC 3056) and Teredo (RFC 4380) addresses carry an IPv4 address inside
// them, which a relay may deliver to. They are not refused wholesale — they are
// real, if rare, addresses — but the embedded IPv4 is judged against the same
// exclusions (embeddedIPv4Interval). The extraction itself is
// network.EmbeddedIPv4, the one definition probe consent uses too.
var (
	sixToFourPrefix = netip.MustParsePrefix("2002::/16")
	teredoPrefix    = netip.MustParsePrefix("2001::/32")
)

// embeddedIPv4Interval returns the IPv4 interval an IPv6 interval embeds.
// For 6to4 the IPv4 address is the top bits after the prefix, so an interval
// maps to an interval. A Teredo address's IPv4 is bit-inverted in the low bits,
// so only a single address can be judged; a Teredo RANGE, or any interval that
// straddles the edge of either prefix, is reported unjudgeable. ok=false when
// nothing is embedded. (The forms reserved outright — NAT64, IPv4-compatible,
// SIIT — never get here; IPv4-mapped is unmapped by targetInterval.)
func embeddedIPv4Interval(lo, hi netip.Addr) (addrs [][2]netip.Addr, judgeable, ok bool) {
	if !lo.Is6() {
		return nil, true, false
	}
	inLo := sixToFourPrefix.Contains(lo) || teredoPrefix.Contains(lo)
	inHi := sixToFourPrefix.Contains(hi) || teredoPrefix.Contains(hi)
	if !inLo && !inHi {
		return nil, true, false
	}
	sameScheme := (sixToFourPrefix.Contains(lo) && sixToFourPrefix.Contains(hi)) || (lo == hi)
	if !sameScheme {
		return nil, false, true
	}
	loV4, okLo := network.EmbeddedIPv4(lo)
	hiV4, okHi := network.EmbeddedIPv4(hi)
	if !okLo || !okHi {
		return nil, false, true
	}
	return [][2]netip.Addr{{loV4, hiV4}}, true, true
}

// reservedReason says, in words a person can act on, why an address in a
// reserved prefix can never be scanned. The explicit-external-targets path
// (external.go) shows it beside each refused target: "refused" alone reads as
// "try again with the box ticked", and for these ranges no box exists.
func reservedReason(p netip.Prefix) (string, bool) {
	switch p.String() {
	case "0.0.0.0/8", "::/128":
		return "the unspecified address is not a host", true
	case "127.0.0.0/8", "::1/128":
		return "loopback addresses are the scanner itself", true
	case "169.254.0.0/16":
		return "link-local addresses include the cloud instance-metadata service (169.254.169.254)", true
	case "fe80::/10", "fec0::/10":
		return "link-local addresses are never scanned", true
	case "100.64.0.0/10":
		return "carrier-grade NAT space is shared between operators; register it as a network segment if it really is yours", true
	case "192.0.0.0/24":
		return "IETF protocol-assignment space is not a host range", true
	case "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32":
		return "documentation address space is not routable", true
	case "224.0.0.0/4", "ff00::/8":
		return "multicast addresses are not hosts", true
	case "240.0.0.0/4":
		return "reserved address space (including broadcast) is not a host range", true
	case "64:ff9b::/96", "64:ff9b:1::/48", "::/96", "::ffff:0:0:0/96":
		return "these IPv6 forms carry an IPv4 address and can reach reserved ones; name the IPv4 address instead", true
	}
	return "", false
}

// privatePrefixes is the address-class allowance: RFC 1918 and RFC 4193. A
// tenant may always scan its own private space. Anything else — a public
// address in particular — has to be inside a network segment the tenant
// explicitly registered as theirs, which is the statement of ownership this
// code requires before the platform will send a packet at it.
var privatePrefixes = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("fc00::/7"),
}

// TargetScope is one tenant's scannable address space at one moment.
type TargetScope struct {
	allowed  []netip.Prefix
	excluded []netip.Prefix
}

// LoadTargetScope reads the tenant's registered network segments and its
// exclusion policy inside the caller's transaction, and folds in the platform's
// own self-protection ranges. Call it in the same transaction that queues or
// starts the work, so a segment withdrawn or marked sensitive a moment ago wins
// the race.
func LoadTargetScope(tx Queryer, tenantID string) (TargetScope, error) {
	scope := TargetScope{excluded: append(append([]netip.Prefix{}, reservedPrefixes...), autoscan.PlatformExcludedPrefixes()...)}

	var raw []byte
	if err := tx.QueryRow(`SELECT config FROM tenant_admin_settings WHERE tenant_id=$1 FOR SHARE`, tenantID).Scan(&raw); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return scope, err
	}
	if len(raw) > 0 {
		config := map[string]interface{}{}
		if err := json.Unmarshal(raw, &config); err != nil {
			return scope, denied("invalid scan restrictions")
		}
		restrictions, err := autoscan.RestrictionsFromConfig(config)
		if err != nil {
			return scope, denied("invalid scan restrictions")
		}
		scope.excluded = append(scope.excluded, restrictions.Excluded...)
	}

	var segmentRaw []byte
	if err := tx.QueryRow(`SELECT COALESCE(jsonb_agg(jsonb_build_object('value',value,'network_type',network_type,'learned',`+learnedSegmentSQL+`,'blocked',COALESCE(metadata->>'sensitive','false')='true' OR COALESCE(metadata->>'active_probes_disabled','false')='true')),'[]') FROM network_segments WHERE tenant_id=$1 AND is_active AND segment_type='cidr'`, tenantID).Scan(&segmentRaw); err != nil {
		return scope, err
	}
	var segments []struct {
		Value       string
		NetworkType string `json:"network_type"`
		Learned     bool
		Blocked     bool
	}
	if err := json.Unmarshal(segmentRaw, &segments); err != nil {
		return scope, err
	}
	for _, seg := range segments {
		prefix, err := netip.ParsePrefix(seg.Value)
		if err != nil {
			continue
		}
		prefix = prefix.Masked()
		if seg.Blocked {
			scope.excluded = append(scope.excluded, prefix)
			continue
		}
		// A segment the tenant registered is a claim of ownership. The
		// automatic sweep additionally refuses "public" segments; a person
		// pressing scan on their own registered public estate is the case the
		// segment registry exists to permit — but only one the tenant
		// DECLARED. See [SegmentGrantsOwnership].
		if SegmentPrefixGrantsOwnership(prefix, seg.NetworkType, seg.Learned, false) {
			scope.allowed = append(scope.allowed, prefix)
		}
	}
	return scope, nil
}

// learnedSegmentSQL is true for a network segment the platform LEARNED from an
// interrogated device's VLAN data rather than one an operator declared.
// `unifi` is the label such segments carried before every vendor could
// produce one.
const learnedSegmentSQL = `COALESCE(metadata->>'source','') IN ('interrogation','unifi')`

// SegmentGrantsOwnership decides whether a registered segment puts its range
// in scope for a scan.
//
// Private, VPN and cloud segments do, for manual and automatic scans alike.
// A PUBLIC segment is ownership only when an operator declared it, and only
// for a scan a person asked for:
//
//   - automatic scans never treat public space as the tenant's — the Active
//     Scanning page promises public addresses are never probed unattended;
//   - a LEARNED public segment is not a claim of ownership at all. A firewall
//     reporting its ISP transit /30 or its carrier-NAT WAN VLAN is telling us
//     where it is connected, not that the far end is the tenant's. Learned
//     public segments exist to scope identities, and nothing else.
func SegmentGrantsOwnership(networkType string, learned, automatic bool) bool {
	switch networkType {
	case "private", "vpn", "cloud":
		return true
	case "public":
		return !automatic && !learned
	}
	return false
}

// SegmentPrefixGrantsOwnership is SegmentGrantsOwnership for a concrete
// prefix, and what every scope loader calls: a segment wider than /8 (IPv4)
// or /16 (IPv6) is never a claim of ownership, whatever its type, unless it
// lies wholly inside private space (network.TooBroadToClaim — the one
// definition the segment API and probe consent use too). The segment API
// refuses new saves of such prefixes; this keeps a PRE-EXISTING 0.0.0.0/0 from
// making every public address "registered" — which would skip the
// explicit-external-target confirmation and its size bounds.
func SegmentPrefixGrantsOwnership(prefix netip.Prefix, networkType string, learned, automatic bool) bool {
	return SegmentGrantsOwnership(networkType, learned, automatic) && !network.TooBroadToClaim(prefix)
}

// Authorize accepts a single literal target: an address, a CIDR, or an
// `a-b` range. Hostnames are refused — a name is not an address and this guard
// will not guess; callers resolve the name first and authorize the addresses it
// resolves to.
func (s TargetScope) Authorize(target string) error {
	lo, hi, ok := targetInterval(target)
	if !ok {
		return denied(fmt.Sprintf("scan target %q is not an IP address, CIDR or range", target))
	}
	// One classifier for every path (external.go), so an exclusion added for
	// the manual path — embedded IPv4, the mapped block — holds here too.
	switch class, _ := s.classify(lo, hi); class {
	case classExcluded:
		return denied(fmt.Sprintf("scan target %q is excluded from scanning", target))
	case classInScope:
		return nil
	}
	return denied(fmt.Sprintf("scan target %q is outside the network segments this tenant has registered", target))
}

// AuthorizeTargets is the call site guard: load the scope once, authorize every
// target against it. An empty target list is refused — a dispatch that names
// nothing has nothing to authorize and must not be read as permission.
func AuthorizeTargets(tx Queryer, tenantID string, targets []string) error {
	if len(targets) == 0 {
		return denied("scan dispatch names no targets")
	}
	scope, err := LoadTargetScope(tx, tenantID)
	if err != nil {
		return err
	}
	for _, target := range targets {
		if err := scope.Authorize(target); err != nil {
			return err
		}
	}
	return nil
}

// targetInterval reduces a literal target to the closed numeric interval of
// addresses it names.
func targetInterval(target string) (netip.Addr, netip.Addr, bool) {
	s := strings.TrimSpace(target)
	if s == "" || strings.Contains(s, "%") {
		// A zone identifier means the value did not come from an `inet`
		// column; autoscan.ParseTarget refuses it for the same reason.
		return netip.Addr{}, netip.Addr{}, false
	}
	if strings.Contains(s, "/") {
		prefix, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Addr{}, netip.Addr{}, false
		}
		// An IPv4-mapped IPv6 prefix (::ffff:a.b.c.d/n) names IPv4 addresses —
		// the dialer connects to ::ffff:169.254.169.254 as 169.254.169.254.
		// Judge it as the IPv4 prefix it is, the way a single mapped address
		// and a mapped range are unmapped below; left as IPv6 it would compare
		// against none of the IPv4 exclusions. A mapped prefix shorter than
		// /96 is not a mapped prefix at all but one that straddles the mapped
		// block, and no scan needs that.
		if prefix.Addr().Is4In6() {
			if prefix.Bits() < 96 {
				return netip.Addr{}, netip.Addr{}, false
			}
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
		}
		prefix = prefix.Masked()
		return prefix.Addr(), lastAddr(prefix), true
	}
	if lo, hi, found := strings.Cut(s, "-"); found {
		start, err := netip.ParseAddr(strings.TrimSpace(lo))
		if err != nil {
			return netip.Addr{}, netip.Addr{}, false
		}
		end, err := netip.ParseAddr(strings.TrimSpace(hi))
		if err != nil {
			return netip.Addr{}, netip.Addr{}, false
		}
		start, end = start.Unmap(), end.Unmap()
		if start.Is4() != end.Is4() || end.Less(start) {
			return netip.Addr{}, netip.Addr{}, false
		}
		return start, end, true
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, netip.Addr{}, false
	}
	addr = addr.Unmap()
	return addr, addr, true
}

// intervalsOverlap reports whether [lo,hi] shares any address with prefix.
func intervalsOverlap(lo, hi netip.Addr, prefix netip.Prefix) bool {
	if !prefix.IsValid() || lo.Is4() != prefix.Addr().Unmap().Is4() {
		return false
	}
	p := prefix.Masked()
	return !hi.Less(p.Addr()) && !lastAddr(p).Less(lo)
}

// lastAddr is the highest address in a prefix.
func lastAddr(prefix netip.Prefix) netip.Addr {
	p := prefix.Masked()
	bytes := p.Addr().AsSlice()
	bits := p.Bits()
	for i := range bytes {
		for bit := 0; bit < 8; bit++ {
			if i*8+bit >= bits {
				bytes[i] |= 1 << (7 - bit)
			}
		}
	}
	addr, _ := netip.AddrFromSlice(bytes)
	return addr.Unmap()
}
