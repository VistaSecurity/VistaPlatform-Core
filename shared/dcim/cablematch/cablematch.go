// Package cablematch resolves the far end of an LLDP / CDP neighbour to a known
// interface (DCIM BUILD_PLAN row 3.3; asset-inventory ADR-0010 D6).
//
// A neighbour names its far end by what that device ADVERTISED: a chassis id
// (usually its base MAC), a system name, a management address, and its own
// name for the port. This package answers "which interface is that?" in two
// steps, deterministically and without a model:
//
//  1. The far DEVICE: the assets the chassis id names (an asset MAC identifier
//     or any of its interfaces' MACs; a non-MAC chassis id is tried as a name
//     and an address), else the assets the system name names (hostname / FQDN
//     identifiers, the asset's hostname or display name, the short name before
//     the first dot), else the assets the management address names (an address
//     identifier or an address assigned to one of its interfaces). Exactly one
//     asset or no answer: two candidates are ambiguous, and ambiguity is never
//     resolved by guessing.
//  2. The far PORT on that device ([MatchPort]): the interface whose MAC the
//     port id is, else whose name the port id (or, failing it, the port
//     description) spells under any vendor family's canonical form
//     (shared/dcim/ifnames). Again exactly one or none.
//
// The [Directory] is the lookup seam; [PGDirectory] is the Postgres one, read
// inside the caller's tenant transaction. inventory-service's cable intake and
// its unresolved-termination matcher are the two callers.
package cablematch

import (
	"context"
	"net/netip"
	"strings"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/dcim/ifnames"
	"github.com/vistasecurity/vistaplatform/shared/dcim/unresolved"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// FarIdentity is what a neighbour advertised about its far end.
type FarIdentity struct {
	ChassisID   string
	PortID      string
	PortDescr   string
	SystemName  string
	MgmtAddress string
}

// FromNeighbor is the far identity of an observed neighbour.
func FromNeighbor(n identity.ObservedNeighbor) FarIdentity {
	return FarIdentity{
		ChassisID: n.RemoteChassisID, PortID: n.RemotePortID, PortDescr: n.RemotePortDescr,
		SystemName: n.RemoteSystemName, MgmtAddress: n.RemoteMgmtAddress,
	}
}

// Map is the far identity as an unresolved termination's flat key map (only
// the keys that are set; DATA_MODEL §4).
func (f FarIdentity) Map() map[string]string {
	m := map[string]string{}
	for k, v := range map[string]string{
		unresolved.KeyChassisID: f.ChassisID, unresolved.KeyPortID: f.PortID, unresolved.KeyPortDescr: f.PortDescr,
		unresolved.KeySystemName: f.SystemName, unresolved.KeyMgmtAddress: f.MgmtAddress,
	} {
		if strings.TrimSpace(v) != "" {
			m[k] = v
		}
	}
	return m
}

// FromMap reads a parked row's far identity back.
func FromMap(m map[string]string) FarIdentity {
	return FarIdentity{
		ChassisID: m[unresolved.KeyChassisID], PortID: m[unresolved.KeyPortID], PortDescr: m[unresolved.KeyPortDescr],
		SystemName: m[unresolved.KeySystemName], MgmtAddress: m[unresolved.KeyMgmtAddress],
	}
}

// Port is one interface as the matcher sees it.
type Port struct {
	ID      uuid.UUID
	AssetID uuid.UUID
	Name    string
	MAC     string // aa:bb:cc:dd:ee:ff, "" when none
}

// Directory answers the lookups, scoped to one tenant. Each returns the live
// assets (or ports) carrying the value; an empty answer is "nobody".
type Directory interface {
	AssetsByMAC(ctx context.Context, mac string) ([]uuid.UUID, error)
	AssetsBySystemName(ctx context.Context, name string) ([]uuid.UUID, error)
	AssetsByAddress(ctx context.Context, addr string) ([]uuid.UUID, error)
	Ports(ctx context.Context, asset uuid.UUID) ([]Port, error)
}

// Outcome is how far a resolution got.
type Outcome string

const (
	// Matched: the far device and the far port are both known.
	Matched Outcome = "matched"
	// DeviceUnknown: nothing in the inventory carries the far identity yet.
	DeviceUnknown Outcome = "device_unknown"
	// PortUnknown: the far device is known, the port it named is not (yet).
	PortUnknown Outcome = "port_unknown"
	// Ambiguous: two or more assets (or ports) carry the identity.
	Ambiguous Outcome = "ambiguous"
)

// Result is one resolution.
type Result struct {
	Outcome Outcome
	// Asset is the far device (Matched, PortUnknown).
	Asset uuid.UUID
	// Port is the far interface (Matched).
	Port Port
	// Via names the identity that found the device: chassis_id, system_name
	// or mgmt_address.
	Via string
}

// Candidates returns the assets the far identity names, by the first identity
// that names any (chassis id, system name, management address) and which one
// it was. More than one asset is returned as-is: the caller decides what
// ambiguity means (Resolve refuses it; a drift check asks whether a declared
// far device is among them).
func Candidates(ctx context.Context, dir Directory, f FarIdentity) ([]uuid.UUID, string, error) {
	type step struct {
		via string
		run func() ([]uuid.UUID, error)
	}
	var steps []step
	if c := strings.TrimSpace(f.ChassisID); c != "" {
		if mac := identity.NeighborChassisID(c); isMAC(mac) {
			steps = append(steps, step{unresolved.KeyChassisID, func() ([]uuid.UUID, error) { return dir.AssetsByMAC(ctx, mac) }})
		} else if a, err := netip.ParseAddr(c); err == nil {
			addr := a.Unmap().String()
			steps = append(steps, step{unresolved.KeyChassisID, func() ([]uuid.UUID, error) { return dir.AssetsByAddress(ctx, addr) }})
		} else {
			steps = append(steps, step{unresolved.KeyChassisID, func() ([]uuid.UUID, error) { return dir.AssetsBySystemName(ctx, SystemName(c)) }})
		}
	}
	if n := SystemName(f.SystemName); n != "" {
		steps = append(steps, step{unresolved.KeySystemName, func() ([]uuid.UUID, error) { return dir.AssetsBySystemName(ctx, n) }})
	}
	if a, err := netip.ParseAddr(strings.TrimSpace(f.MgmtAddress)); err == nil {
		addr := a.Unmap().String()
		steps = append(steps, step{unresolved.KeyMgmtAddress, func() ([]uuid.UUID, error) { return dir.AssetsByAddress(ctx, addr) }})
	}
	for _, s := range steps {
		ids, err := s.run()
		if err != nil {
			return nil, "", err
		}
		if ids = dedupe(ids); len(ids) > 0 {
			return ids, s.via, nil
		}
	}
	return nil, "", nil
}

// Resolve finds the far interface of f. exclude is the asset the neighbour was
// observed ON: a device does not neighbour itself, so it is never the answer.
func Resolve(ctx context.Context, dir Directory, f FarIdentity, exclude uuid.UUID) (Result, error) {
	ids, via, err := Candidates(ctx, dir, f)
	if err != nil {
		return Result{}, err
	}
	var live []uuid.UUID
	for _, id := range ids {
		if id != exclude {
			live = append(live, id)
		}
	}
	switch {
	case len(live) == 0:
		return Result{Outcome: DeviceUnknown}, nil
	case len(live) > 1:
		return Result{Outcome: Ambiguous, Via: via}, nil
	}
	asset := live[0]
	ports, err := dir.Ports(ctx, asset)
	if err != nil {
		return Result{}, err
	}
	p, outcome := MatchPort(f.PortID, f.PortDescr, ports)
	switch outcome {
	case Matched:
		return Result{Outcome: Matched, Asset: asset, Port: p, Via: via}, nil
	case Ambiguous:
		return Result{Outcome: Ambiguous, Asset: asset, Via: via}, nil
	}
	return Result{Outcome: PortUnknown, Asset: asset, Via: via}, nil
}

// nameFamilies are the ifnames vendor families a port name is folded under:
// the far device's family is not known here, and a name that folds to the
// same canonical form under any family is one interface (ifnames folds
// conservatively, so a family that does not recognise a name leaves it as is).
var nameFamilies = []string{
	ifnames.VendorAuto, ifnames.VendorCisco, ifnames.VendorArista, ifnames.VendorJuniper,
	ifnames.VendorFortinet, ifnames.VendorUniFi, ifnames.VendorLinux,
}

func folds(raw string) map[string]bool {
	out := map[string]bool{}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return out
	}
	out[strings.ToLower(raw)] = true
	for _, v := range nameFamilies {
		c, _ := ifnames.Canonical(v, raw)
		if c = strings.ToLower(strings.TrimSpace(c)); c != "" {
			out[c] = true
		}
	}
	return out
}

// MatchPort picks the port a neighbour named on its own device: by MAC when
// the port id is one (LLDP port-id subtype macAddress), else by name — the
// port id first, the port description only when the port id names nothing
// (some agents put the interface name in the description and an ifIndex in
// the id). Exactly one port or none; two is [Ambiguous].
func MatchPort(portID, portDescr string, ports []Port) (Port, Outcome) {
	if mac := identity.NeighborChassisID(portID); isMAC(mac) {
		var hit []Port
		for _, p := range ports {
			if p.MAC != "" && strings.EqualFold(p.MAC, mac) {
				hit = append(hit, p)
			}
		}
		switch len(hit) {
		case 1:
			return hit[0], Matched
		case 0:
		default:
			return Port{}, Ambiguous
		}
	}
	for _, raw := range []string{portID, portDescr} {
		want := folds(raw)
		if len(want) == 0 {
			continue
		}
		var hit []Port
		for _, p := range ports {
			for f := range folds(p.Name) {
				if want[f] {
					hit = append(hit, p)
					break
				}
			}
		}
		switch len(hit) {
		case 1:
			return hit[0], Matched
		case 0:
			continue
		default:
			return Port{}, Ambiguous
		}
	}
	return Port{}, PortUnknown
}

// SystemName normalises an advertised system name for lookup: lower case,
// trailing dot and an NX-OS serial suffix ("n9k-1(FDO123)") removed.
func SystemName(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if i := strings.IndexByte(v, '('); i > 0 && strings.HasSuffix(v, ")") {
		v = strings.TrimSpace(v[:i])
	}
	return strings.TrimSuffix(v, ".")
}

func isMAC(v string) bool {
	if len(v) != 17 {
		return false
	}
	for i, c := range v {
		if i%3 == 2 {
			if c != ':' {
				return false
			}
			continue
		}
		if !strings.ContainsRune("0123456789abcdef", c) {
			return false
		}
	}
	return true
}

func dedupe(ids []uuid.UUID) []uuid.UUID {
	seen := map[uuid.UUID]bool{}
	var out []uuid.UUID
	for _, id := range ids {
		if id != uuid.Nil && !seen[id] {
			seen[id] = true
			out = append(out, id)
		}
	}
	return out
}
