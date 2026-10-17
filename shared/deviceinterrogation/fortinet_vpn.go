package deviceinterrogation

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/vistasecurity/vistaplatform/shared/cryptoparse"
	"github.com/vistasecurity/vistaplatform/shared/dcim/ifnames"
)

// FortiOS IPsec tunnels as objects (DCIM row 4.3).
//
// `cmdb/vpn.ipsec/phase1-interface` is the IKE side of each route-based
// tunnel, `cmdb/vpn.ipsec/phase2-interface` its child SAs (phase1name joins
// them). Both objects carry key material — phase-1 `psksecret` (the tunnel's
// pre-shared key), phase-2 nothing secret but many fields nothing reads — so
// each item is decoded into a TYPED struct. `psksecret` lands in a
// [fortinetSecretPresence], whose UnmarshalJSON keeps only whether a value was
// there: the key is never held in a field, never logged and never sent.

// fortinetSecretPresence records that a secret field was set, and nothing else.
type fortinetSecretPresence bool

func (p *fortinetSecretPresence) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		*p = len(strings.TrimSpace(string(b))) > 0 && string(b) != "null"
		return nil
	}
	*p = strings.TrimSpace(s) != ""
	return nil
}

type fortinetPhase1 struct {
	Name       string                 `json:"name"`
	Interface  string                 `json:"interface"`
	IKEVersion string                 `json:"ike-version"`
	Proposal   string                 `json:"proposal"`
	DHGroup    string                 `json:"dhgrp"`
	KeyLife    fortiInt               `json:"keylife"`
	RemoteGW   string                 `json:"remote-gw"`
	LocalGW    string                 `json:"local-gw"`
	Mode       string                 `json:"mode"`
	AuthMethod string                 `json:"authmethod"`
	PSK        fortinetSecretPresence `json:"psksecret"`
}

type fortinetPhase2 struct {
	Name           string   `json:"name"`
	Phase1Name     string   `json:"phase1name"`
	Proposal       string   `json:"proposal"`
	PFS            string   `json:"pfs"`
	DHGroup        string   `json:"dhgrp"`
	KeyLifeSeconds fortiInt `json:"keylifeseconds"`
	KeyLifeKBs     fortiInt `json:"keylifekbs"`
	Encapsulation  string   `json:"encapsulation"`
}

// fortinetTunnels projects the phase-1 and phase-2 tables onto tunnels.
func fortinetTunnels(phase1, phase2 []map[string]interface{}) []ObservedTunnel {
	byP1 := map[string][]fortinetPhase2{}
	for _, raw := range phase2 {
		p2, ok := fortinetDecode[fortinetPhase2](raw)
		if !ok || strings.TrimSpace(p2.Phase1Name) == "" {
			continue
		}
		byP1[p2.Phase1Name] = append(byP1[p2.Phase1Name], p2)
	}
	var out []ObservedTunnel
	for _, raw := range phase1 {
		p1, ok := fortinetDecode[fortinetPhase1](raw)
		if !ok || strings.TrimSpace(p1.Name) == "" {
			continue
		}
		t := ObservedTunnel{
			Name:                p1.Name,
			Encapsulation:       "ipsec-tunnel",
			LocalInterface:      p1.Name, // a route-based tunnel is an interface named after phase 1
			LocalIP:             p1.LocalGW,
			PeerIP:              p1.RemoteGW,
			IKEMode:             p1.Mode,
			PresharedKeyPresent: bool(p1.PSK),
		}
		if v, err := strconv.Atoi(strings.TrimSpace(p1.IKEVersion)); err == nil {
			t.IKEVersion = v
		}
		switch strings.ToLower(strings.TrimSpace(p1.AuthMethod)) {
		case "psk":
			t.AuthenticationMethod = "preshared-keys"
		case "signature":
			t.AuthenticationMethod = "certificates"
		}
		groups := ikeGroupIDs(p1.DHGroup)
		for _, pair := range cryptoparse.ParseIKETransformPairs(p1.Proposal) {
			if len(groups) == 0 {
				t.IKEProposals = append(t.IKEProposals, ObservedIKEProposal{Encryption: pair.Encryption, Integrity: pair.Integrity, LifetimeSeconds: int(p1.KeyLife)})
			}
			for _, g := range groups {
				t.IKEProposals = append(t.IKEProposals, ObservedIKEProposal{Encryption: pair.Encryption, Integrity: pair.Integrity, Group: g, LifetimeSeconds: int(p1.KeyLife)})
			}
		}
		for _, p2 := range byP1[p1.Name] {
			if strings.EqualFold(strings.TrimSpace(p2.Encapsulation), "transport-mode") {
				t.Encapsulation = "ipsec-transport"
			}
			for _, pair := range cryptoparse.ParseIKETransformPairs(p2.Proposal) {
				t.IPsecProposals = append(t.IPsecProposals, ObservedIPsecProposal{Encryption: pair.Encryption, Integrity: pair.Integrity,
					LifetimeSeconds: int(p2.KeyLifeSeconds), LifetimeKB: int(p2.KeyLifeKBs)})
			}
			if t.PFSGroup == 0 && !strings.EqualFold(strings.TrimSpace(p2.PFS), "disable") {
				if ids := ikeGroupIDs(p2.DHGroup); len(ids) > 0 {
					t.PFSGroup = ids[0]
				}
			}
		}
		out = append(out, t)
	}
	return out
}

// ikeGroupIDs is a DH-group setting's IANA IDs in preference order.
func ikeGroupIDs(setting string) []int {
	var ids []int
	for _, g := range cryptoparse.ParseIKEGroups(setting) {
		ids = append(ids, g.ID)
	}
	return ids
}

// addFortinetTunnels files the tunnels phase 1 and phase 2 describe on the result.
func (c *fortinetClient) addFortinetTunnels(result *InterrogateResult, phase1, phase2 []map[string]interface{}) {
	result.addTunnels(fortinetTunnels(phase1, phase2), ifnames.VendorFortinet, "/api/v2/cmdb/vpn.ipsec/phase1-interface")
}
