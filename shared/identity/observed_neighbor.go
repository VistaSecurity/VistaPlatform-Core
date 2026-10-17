package identity

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/dcim/ifnames"
)

// The neighbour half of the intake seam (DCIM row 3.3, asset-inventory
// ADR-0010 D6): what a device's LLDP or CDP table says is on the far end of
// each of its ports. Like the tunnels of observed_tunnel.go it rides on the
// sighting beside the identifiers and is NOT identity — the engine never reads
// it. inventory-service turns each neighbour into a proposed cable between two
// known interfaces, a parked unresolved termination when the far end is not
// in the inventory yet, or a `topology/cable_drift` finding when it
// contradicts a cable someone declared (cable_intake.go). No collector writes
// a cable any other way.
//
// Posture only: a neighbour is the identity its far end ADVERTISED (chassis
// id, port id, system name, management address) and the local port it was
// heard on. Nothing a neighbour sends is a secret, and the system description
// banner is deliberately absent — what classifies a peer travels on its
// PeerRef, not here.

// Neighbour discovery protocols an ObservedNeighbor may name.
const (
	NeighborProtocolLLDP = "lldp"
	NeighborProtocolCDP  = "cdp"
)

// ObservedNeighbor is one row of a device's LLDP or CDP neighbour table.
type ObservedNeighbor struct {
	// LocalInterface is the observed device's own port the neighbour was
	// heard on, canonicalised like an ObservedInterface name.
	LocalInterface string `json:"local_interface"`
	// RemoteChassisID is the neighbour's LLDP chassis id: a MAC (normalised
	// aa:bb:cc:dd:ee:ff) or, for the other chassis-id subtypes, the advertised
	// text. CDP has none (its device id is the system name).
	RemoteChassisID string `json:"remote_chassis_id,omitempty"`
	// RemotePortID and RemotePortDescr are the neighbour's own name for the
	// port and its description, as advertised.
	RemotePortID    string `json:"remote_port_id,omitempty"`
	RemotePortDescr string `json:"remote_port_descr,omitempty"`
	// RemoteSystemName is LLDP's system name or CDP's device id.
	RemoteSystemName string `json:"remote_system_name,omitempty"`
	// RemoteMgmtAddress is the management address the neighbour advertised.
	RemoteMgmtAddress string `json:"remote_mgmt_address,omitempty"`
	// Protocol is lldp or cdp.
	Protocol string `json:"protocol"`
}

// Bounds on what one sighting may carry.
const (
	MaxObservedNeighbors = 1024
	maxNeighborField     = 255
)

// NormalizeObservedNeighbors canonicalises a sighting's neighbours: the local
// interface through shared/dcim/ifnames (vendor auto, as Intake folds
// interface names), a MAC chassis id normalised, the management address parsed
// and zone-stripped, every field trimmed and bounded. A neighbour with no local
// interface, an unknown protocol, or nothing the far end could be found by is
// dropped and reported. A neighbour repeated on the same local interface with
// the same far identity keeps its first occurrence (LLDP and CDP often both
// report one link; the first protocol named wins).
func NormalizeObservedNeighbors(in []ObservedNeighbor) ([]ObservedNeighbor, []string) {
	var (
		out     []ObservedNeighbor
		dropped []string
	)
	seen := map[string]bool{}
	for _, raw := range in {
		if len(out) >= MaxObservedNeighbors {
			dropped = append(dropped, fmt.Sprintf("neighbours beyond %d", MaxObservedNeighbors))
			break
		}
		n := ObservedNeighbor{Protocol: strings.ToLower(strings.TrimSpace(raw.Protocol))}
		if n.Protocol != NeighborProtocolLLDP && n.Protocol != NeighborProtocolCDP {
			dropped = append(dropped, fmt.Sprintf("neighbour on %q: protocol %q is not lldp or cdp", raw.LocalInterface, raw.Protocol))
			continue
		}
		local, _ := ifnames.Canonical("", strings.TrimSpace(raw.LocalInterface))
		n.LocalInterface = strings.TrimSpace(local)
		if n.LocalInterface == "" || len(n.LocalInterface) > maxInterfaceName {
			dropped = append(dropped, fmt.Sprintf("neighbour %q: no local interface the interfaces table can hold", raw.RemoteSystemName))
			continue
		}
		n.RemoteChassisID = NeighborChassisID(raw.RemoteChassisID)
		n.RemotePortID = boundedNeighborField(raw.RemotePortID)
		n.RemotePortDescr = boundedNeighborField(raw.RemotePortDescr)
		n.RemoteSystemName = boundedNeighborField(raw.RemoteSystemName)
		if a, err := netip.ParseAddr(strings.TrimSpace(raw.RemoteMgmtAddress)); err == nil && a.IsValid() && !a.IsUnspecified() {
			n.RemoteMgmtAddress = a.WithZone("").Unmap().String()
		}
		if n.RemoteChassisID == "" && n.RemoteSystemName == "" && n.RemoteMgmtAddress == "" {
			dropped = append(dropped, fmt.Sprintf("neighbour on %s: no chassis id, system name or management address", n.LocalInterface))
			continue
		}
		key := strings.ToLower(n.LocalInterface) + "|" + n.RemoteChassisID + "|" + strings.ToLower(n.RemoteSystemName) + "|" + n.RemotePortID
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, n)
	}
	return out, dropped
}

// NeighborChassisID normalises an advertised chassis id: a MAC in any
// spelling becomes aa:bb:cc:dd:ee:ff; anything else is trimmed and bounded.
func NeighborChassisID(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	if mac := normalizedMAC(v); mac != "" {
		return mac
	}
	return boundedNeighborField(v)
}

func boundedNeighborField(v string) string {
	v = strings.TrimSpace(v)
	if strings.ContainsFunc(v, isControl) {
		v = strings.Map(func(r rune) rune {
			if isControl(r) {
				return -1
			}
			return r
		}, v)
	}
	if len(v) > maxNeighborField {
		v = v[:maxNeighborField]
	}
	return v
}
