package identity

import (
	"fmt"
	"net/netip"
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/cryptoparse"
)

// The tunnel half of the intake seam (DCIM row 4.3, ADR-0010 D8): the VPN
// tunnels a collector read off the device it interrogated, with the IKE and
// IPsec proposals they negotiate. Like the interfaces of observed_network.go
// it rides on the sighting beside the identifiers, and inventory-service
// writes it — tunnels, terminations, proposals, policies, the profile and the
// tunnel's crypto configurations — on the engine's own transaction once the
// sighting resolved to an asset. No collector writes a tunnel any other way.
//
// Posture only. There is no field here a pre-shared key could travel in:
// PresharedKeyPresent records THAT one is configured ("collect posture, never
// key material"); the collector projects the vendor object onto these typed
// fields and nothing else.

// ObservedIKEProposal is one IKE (phase-1) proposal: one encryption, one
// integrity transform and one Diffie-Hellman group, as NetBox models it. A
// vendor list that crosses several of each is several proposals.
type ObservedIKEProposal struct {
	// Encryption and Integrity in any vendor spelling; Intake-side
	// normalisation (cryptoparse.CanonicalIKEEncryption / Integrity) turns
	// them into NetBox's choices. Integrity is empty for an AEAD cipher.
	Encryption string `json:"encryption"`
	Integrity  string `json:"integrity,omitempty"`
	// Group is the IANA key-exchange transform ID (14, 19, …), 0 when unknown.
	Group int `json:"group,omitempty"`
	// LifetimeSeconds is the IKE SA lifetime, 0 when the source does not say.
	LifetimeSeconds int `json:"lifetime_seconds,omitempty"`
}

// ObservedIPsecProposal is one IPsec (phase-2) proposal.
type ObservedIPsecProposal struct {
	Encryption      string `json:"encryption"`
	Integrity       string `json:"integrity,omitempty"`
	LifetimeSeconds int    `json:"lifetime_seconds,omitempty"`
	LifetimeKB      int    `json:"lifetime_kb,omitempty"`
}

// ObservedTunnel is one tunnel as the interrogated device configures it.
type ObservedTunnel struct {
	// Name is the device's name for the tunnel (FortiOS phase1-interface
	// name, Palo Alto IKE gateway / tunnel name, Cisco crypto-map entry). It
	// is the tunnel's identity within the tenant.
	Name string `json:"name"`
	// Encapsulation is a `tunnels.encapsulation` value: ipsec-tunnel,
	// ipsec-transport, gre, ip-ip, wireguard, l2tp, pptp, openvpn.
	Encapsulation string `json:"encapsulation"`
	// Status is NetBox's tunnel status: planned, active, disabled. Empty is
	// active (the device has it configured).
	Status string `json:"status,omitempty"`
	// LocalInterface names the interface of the observed device the tunnel
	// terminates on (the tunnel interface where the platform has one, else
	// the underlay interface). It must be an interface of the same asset to
	// carry a termination.
	LocalInterface string `json:"local_interface,omitempty"`
	// LocalIP is the device's own outside address for the tunnel; PeerIP the
	// remote gateway's.
	LocalIP string `json:"local_ip,omitempty"`
	PeerIP  string `json:"peer_ip,omitempty"`
	// IKEVersion is 1 or 2, 0 when unknown. IKEMode is main or aggressive
	// (IKEv1 only).
	IKEVersion int    `json:"ike_version,omitempty"`
	IKEMode    string `json:"ike_mode,omitempty"`
	// AuthenticationMethod is NetBox's: preshared-keys, certificates,
	// rsa-signatures, dsa-signatures.
	AuthenticationMethod string `json:"authentication_method,omitempty"`
	// PresharedKeyPresent says a pre-shared key is configured. Never the key.
	PresharedKeyPresent bool                    `json:"preshared_key_present,omitempty"`
	IKEProposals        []ObservedIKEProposal   `json:"ike_proposals,omitempty"`
	IPsecProposals      []ObservedIPsecProposal `json:"ipsec_proposals,omitempty"`
	// PFSGroup is the phase-2 perfect-forward-secrecy group (IANA ID), 0 for
	// none or unknown.
	PFSGroup int `json:"pfs_group,omitempty"`
	// IPsecMode is esp or ah; empty is esp.
	IPsecMode string `json:"ipsec_mode,omitempty"`
}

// Bounds on what one sighting may carry, so a malformed or hostile collector
// result cannot generate unbounded work.
const (
	MaxObservedTunnels   = 1024
	maxTunnelProposals   = 32
	maxTunnelNameLen     = 100
	maxTunnelIfaceName   = 64
	maxIKEGroupTransform = 65535
)

var tunnelEncapsulations = map[string]bool{
	"ipsec-transport": true, "ipsec-tunnel": true, "ip-ip": true, "gre": true,
	"wireguard": true, "l2tp": true, "pptp": true, "openvpn": true,
}

// NormalizeObservedTunnels canonicalises a sighting's tunnels: names trimmed
// and bounded, enumerations onto the schema's, algorithms onto NetBox's
// spellings, addresses parsed and zone-stripped, proposals de-duplicated and
// bounded. A tunnel with no usable name or encapsulation is dropped and
// reported; a field the schema could not hold is cleared. Duplicate names keep
// their first occurrence.
func NormalizeObservedTunnels(in []ObservedTunnel) ([]ObservedTunnel, []string) {
	var (
		out     []ObservedTunnel
		dropped []string
	)
	seen := map[string]bool{}
	for _, raw := range in {
		if len(out) >= MaxObservedTunnels {
			dropped = append(dropped, fmt.Sprintf("tunnels beyond %d", MaxObservedTunnels))
			break
		}
		t := raw
		t.Name = strings.TrimSpace(t.Name)
		if t.Name == "" || len(t.Name) > maxTunnelNameLen {
			dropped = append(dropped, fmt.Sprintf("tunnel %q: no name the tunnels table can hold", raw.Name))
			continue
		}
		t.Encapsulation = strings.ToLower(strings.TrimSpace(t.Encapsulation))
		if !tunnelEncapsulations[t.Encapsulation] {
			dropped = append(dropped, fmt.Sprintf("tunnel %q: encapsulation %q is not one the tunnels table holds", t.Name, raw.Encapsulation))
			continue
		}
		key := strings.ToLower(t.Name)
		if seen[key] {
			continue
		}
		seen[key] = true
		switch t.Status = strings.ToLower(strings.TrimSpace(t.Status)); t.Status {
		case "planned", "active", "disabled":
		default:
			t.Status = "active"
		}
		t.LocalInterface = strings.TrimSpace(t.LocalInterface)
		if len(t.LocalInterface) > maxTunnelIfaceName {
			t.LocalInterface = ""
		}
		if t.LocalInterface != "" {
			t.LocalInterface = CanonicalInterfaceName(t.LocalInterface)
		}
		t.LocalIP = tunnelAddress(t.LocalIP)
		t.PeerIP = tunnelAddress(t.PeerIP)
		if t.IKEVersion != 1 && t.IKEVersion != 2 {
			t.IKEVersion = 0
		}
		switch t.IKEMode = strings.ToLower(strings.TrimSpace(t.IKEMode)); t.IKEMode {
		case "main", "aggressive":
		default:
			t.IKEMode = ""
		}
		switch t.AuthenticationMethod = strings.ToLower(strings.TrimSpace(t.AuthenticationMethod)); t.AuthenticationMethod {
		case "preshared-keys", "certificates", "rsa-signatures", "dsa-signatures":
		default:
			t.AuthenticationMethod = ""
		}
		switch t.IPsecMode = strings.ToLower(strings.TrimSpace(t.IPsecMode)); t.IPsecMode {
		case "esp", "ah":
		default:
			t.IPsecMode = "esp"
		}
		if !validIKEGroup(t.PFSGroup) {
			t.PFSGroup = 0
		}
		t.IKEProposals = normalizeIKEProposals(t.IKEProposals)
		t.IPsecProposals = normalizeIPsecProposals(t.IPsecProposals)
		out = append(out, t)
	}
	return out, dropped
}

func validIKEGroup(g int) bool { return g >= 1 && g <= maxIKEGroupTransform }

// tunnelAddress is an address in its canonical spelling, or "" when the value
// is not a single IP address (a FQDN remote gateway is not an address).
func tunnelAddress(v string) string {
	a, err := netip.ParseAddr(strings.TrimSpace(v))
	if err != nil || !a.IsValid() || a.IsUnspecified() {
		return ""
	}
	return a.Unmap().WithZone("").String()
}

func normalizeIKEProposals(in []ObservedIKEProposal) []ObservedIKEProposal {
	var out []ObservedIKEProposal
	seen := map[ObservedIKEProposal]bool{}
	for _, p := range in {
		if len(out) >= maxTunnelProposals {
			break
		}
		p.Encryption, _ = cryptoparse.CanonicalIKEEncryption(p.Encryption)
		p.Integrity, _ = cryptoparse.CanonicalIKEIntegrity(p.Integrity)
		if cryptoparse.IKEEncryptionIsAEAD(p.Encryption) && p.Integrity != "" && !strings.HasPrefix(p.Integrity, "hmac-") {
			p.Integrity = ""
		}
		if p.Encryption == "" && p.Integrity == "" && p.Group == 0 {
			continue
		}
		if !validIKEGroup(p.Group) {
			p.Group = 0
		}
		if p.LifetimeSeconds < 0 {
			p.LifetimeSeconds = 0
		}
		if seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

func normalizeIPsecProposals(in []ObservedIPsecProposal) []ObservedIPsecProposal {
	var out []ObservedIPsecProposal
	seen := map[ObservedIPsecProposal]bool{}
	for _, p := range in {
		if len(out) >= maxTunnelProposals {
			break
		}
		p.Encryption, _ = cryptoparse.CanonicalIKEEncryption(p.Encryption)
		p.Integrity, _ = cryptoparse.CanonicalIKEIntegrity(p.Integrity)
		if p.Encryption == "" && p.Integrity == "" {
			continue
		}
		if p.LifetimeSeconds < 0 {
			p.LifetimeSeconds = 0
		}
		if p.LifetimeKB < 0 {
			p.LifetimeKB = 0
		}
		if seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}
