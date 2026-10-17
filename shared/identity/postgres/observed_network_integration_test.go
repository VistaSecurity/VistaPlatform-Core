package postgres_test

// DCIM row 1.5a: the posture half of an observation's network evidence,
// written by RecordObservedNetwork on the engine's transaction. The parity
// test below is also the worked example of identitytest.RunAdapterParity for
// a NETWORK source (rows 1.5b–1.5f): a switch-shaped recorded response with
// trunk ports, a LAG, VLANs, prefixes and an address in a named VRF.

import (
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/identity/identitytest"
)

// switchResponse is the recorded response's shape: a typed projection, so a
// field the adapter does not name (the planted `snmp_community`, the
// per-port `psk`) is discarded structurally — the rule every 1.5 adapter
// follows.
type switchResponse struct {
	Serial string `json:"serial"`
	Mgmt   string `json:"mgmt_ip"`
	Ports  []struct {
		Name    string   `json:"name"`
		MAC     string   `json:"mac"`
		Speed   int64    `json:"speed_mbps"`
		MTU     int      `json:"mtu"`
		Up      bool     `json:"up"`
		Enabled bool     `json:"enabled"`
		Native  int      `json:"native_vlan"`
		Tagged  []int    `json:"tagged_vlans"`
		LAG     string   `json:"lag"`
		Addrs   []string `json:"addresses"`
		VRF     string   `json:"vrf"`
	} `json:"ports"`
	Networks []struct {
		VID    int    `json:"vid"`
		Name   string `json:"name"`
		Subnet string `json:"subnet"`
		DHCP   bool   `json:"dhcp"`
	} `json:"networks"`
}

const switchRecording = `{
  "serial": "SW-PARITY-01", "mgmt_ip": "10.0.99.2", "snmp_community": "PlantedSwitchSecret4471",
  "ports": [
    {"name": "Port 1", "mac": "00:00:5e:00:53:a1", "speed_mbps": 1000, "mtu": 1500, "up": true, "enabled": true,
     "native_vlan": 10, "tagged_vlans": [20, 30], "lag": "Port-channel1"},
    {"name": "Port 2", "mac": "00:00:5e:00:53:a2", "speed_mbps": 0, "mtu": 1500, "up": false, "enabled": false,
     "native_vlan": 10, "lag": "Port-channel1", "psk": "PlantedSwitchSecret4471"},
    {"name": "Port-channel1", "mtu": 1500, "up": true, "enabled": true, "native_vlan": 10, "tagged_vlans": [20, 30]},
    {"name": "Vlan99", "mac": "00:00:5e:00:53:99", "up": true, "enabled": true, "addresses": ["10.0.99.2/24"]},
    {"name": "Vlan50", "up": true, "enabled": true, "addresses": ["172.16.50.1/24"], "vrf": "mgmt"}
  ],
  "networks": [
    {"vid": 10, "name": "users", "subnet": "10.0.10.0/24", "dhcp": true},
    {"vid": 20, "name": "voice", "subnet": "10.0.20.0/24", "dhcp": false},
    {"vid": 99, "name": "infra", "subnet": "10.0.99.0/24", "dhcp": false}
  ]
}`

var switchAdapter = identitytest.ParityAdapterFunc{
	AdapterName: "example-switch",
	Fn: func(tenantID string, response []byte, at time.Time) (identity.Sighting, error) {
		var r switchResponse
		if err := json.Unmarshal(response, &r); err != nil {
			return identity.Sighting{}, err
		}
		s := identity.Sighting{
			TenantID: tenantID, Channel: identity.ChannelAuthenticatedSession, ObservedAt: at, ClassHint: "switch",
			Source:            identity.Source{Kind: identity.SourceMeasured, Ref: "interrogation:example-switch", Mode: identity.ModeActive},
			Identifiers:       []identity.SightedIdentifier{{Kind: identity.KindSerialNumber, Value: r.Serial}},
			ManagementAddress: r.Mgmt,
		}
		for _, p := range r.Ports {
			o := identity.ObservedInterface{Name: p.Name, MAC: p.MAC, LAG: p.LAG, TaggedVLANs: p.Tagged, UntaggedVLAN: p.Native}
			if p.MTU > 0 {
				mtu := p.MTU
				o.MTU = &mtu
			}
			if p.Speed > 0 {
				kbps := p.Speed * 1000
				o.SpeedKbps = &kbps
			}
			enabled := p.Enabled
			o.Enabled = &enabled
			o.OperStatus = map[bool]string{true: "up", false: "down"}[p.Up]
			if len(p.Tagged) > 0 {
				o.Mode = "tagged"
			} else if p.Native > 0 {
				o.Mode = "access"
			}
			for _, a := range p.Addrs {
				o.Addresses = append(o.Addresses, identity.ObservedAddress{Address: a, VRF: p.VRF})
			}
			s.Interfaces = append(s.Interfaces, o)
		}
		for _, n := range r.Networks {
			dhcp := n.DHCP
			s.VLANs = append(s.VLANs, identity.ObservedVLAN{VID: n.VID, Name: n.Name})
			s.Prefixes = append(s.Prefixes, identity.ObservedPrefix{Prefix: n.Subnet, VLAN: n.VID, DHCPManaged: &dhcp})
		}
		return s, nil
	},
}

func boolPtr(b bool) *bool { return &b }

// TestIntegration_AdapterParity_ExampleSwitch: a network device's ports,
// LAG, VLANs (access, trunk), prefixes with their VLAN and DHCP posture, a
// management SVI that becomes the primary IP, and an SVI in a declared VRF
// that is recorded on the interface but never becomes identity.
//
// Mutations (each red, then restored green): skip the tagged-VLAN insert;
// skip the prefix's VLAN link; record a named-VRF address in the global
// table (drop the VRF lookup); count observation_count twice on an interface
// the identity half already touched (drop the `last_seen_at >= $9` guard).
func TestIntegration_AdapterParity_ExampleSwitch(t *testing.T) {
	identitytest.RunAdapterParity(t, switchAdapter, []identitytest.ParityFixture{{
		Name:     "trunks-lag-vrf",
		Response: []byte(switchRecording),
		Secrets:  []string{"PlantedSwitchSecret4471"},
		Setup: func(t *testing.T, db *sql.DB, tenantID string) {
			if _, err := db.Exec(`INSERT INTO public.vrfs (tenant_id, name) VALUES ($1, 'mgmt')`, tenantID); err != nil {
				t.Fatal(err)
			}
		},
		Want: identitytest.ParityWant{
			Interfaces: []identitytest.WantInterface{
				{Name: "Port 1", MAC: "00:00:5e:00:53:a1", MTU: 1500, SpeedKbps: 1_000_000, OperStatus: "up", AdminStatus: "up",
					Mode: "tagged", UntaggedVLAN: 10, TaggedVLANs: []int{20, 30}, LAG: "Port-channel1"},
				{Name: "Port 2", MAC: "00:00:5e:00:53:a2", MTU: 1500, OperStatus: "down", AdminStatus: "down",
					Mode: "access", UntaggedVLAN: 10, LAG: "Port-channel1"},
				{Name: "Port-channel1", Type: "lag", MTU: 1500, OperStatus: "up", AdminStatus: "up",
					Mode: "tagged", UntaggedVLAN: 10, TaggedVLANs: []int{20, 30}},
				{Name: "Vlan99", Type: "virtual", MAC: "00:00:5e:00:53:99", OperStatus: "up", AdminStatus: "up",
					Addresses: []string{"10.0.99.2/24"}},
				{Name: "Vlan50", Type: "virtual", OperStatus: "up", AdminStatus: "up",
					Addresses: []string{"mgmt|172.16.50.1/24"}},
			},
			Prefixes: []identitytest.WantPrefix{
				{Prefix: "10.0.10.0/24", VLAN: 10, DHCPManaged: boolPtr(true)},
				{Prefix: "10.0.20.0/24", VLAN: 20, DHCPManaged: boolPtr(false)},
				{Prefix: "10.0.99.0/24", VLAN: 99, DHCPManaged: boolPtr(false)},
			},
			VLANs: []identitytest.WantVLAN{{VID: 10, Name: "users"}, {VID: 20, Name: "voice"}, {VID: 30, Name: "VLAN 30"}, {VID: 99, Name: "infra"}},
			// Vlan99's address is the management address; the VRF address is
			// never a candidate (it is not identity).
			PrimaryIP4: "10.0.99.2",
		},
	}})
}

// TestIntegration_ObservedNetwork_NeverOverwritesDeclared: a person's
// statements outrank a measurement. An interface declared through the API
// keeps its `enabled`, description, mode and (non-`other`) type; a declared
// prefix keeps its DHCP posture; a named VLAN keeps its name — while the
// measured fields (MTU, speed, status) are refreshed.
//
// Mutation: put `enabled` in refreshInterface's column list — red.
func TestIntegration_ObservedNetwork_NeverOverwritesDeclared(t *testing.T) {
	h := newIfaceHarness(t)
	first := h.resolve(h.agent(identity.SightedIdentifier{Kind: identity.KindSerialNumber, Value: "SN-DECLARED"}))
	asset := first.Asset.ID
	if _, err := h.db.Exec(`
		INSERT INTO public.interfaces (tenant_id, asset_id, name, type, enabled, mode, description, source_kind)
		VALUES ($1, $2, 'xe-0/0/1', '10gbase-x-sfpp', false, 'tagged', 'uplink to core — declared', 'declared')`, h.tenant, asset); err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Exec(`INSERT INTO public.prefixes (tenant_id, prefix, dhcp_managed, source_kind) VALUES ($1, '10.7.0.0/24', false, 'declared')`, h.tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Exec(`INSERT INTO public.vlans (tenant_id, vid, name, source_kind) VALUES ($1, 70, 'corp', 'declared')`, h.tenant); err != nil {
		t.Fatal(err)
	}

	mtu, speed, on := 9000, int64(10_000_000), true
	s := h.agent(identity.SightedIdentifier{Kind: identity.KindSerialNumber, Value: "SN-DECLARED"})
	s.Interfaces = []identity.ObservedInterface{{Name: "xe-0/0/1", Type: "1000base-t", MTU: &mtu, SpeedKbps: &speed,
		Enabled: &on, OperStatus: "up", Mode: "access", UntaggedVLAN: 70}}
	s.Prefixes = []identity.ObservedPrefix{{Prefix: "10.7.0.0/24", DHCPManaged: &on, VLAN: 70}}
	s.VLANs = []identity.ObservedVLAN{{VID: 70, Name: "measured-name"}}
	if res := h.resolve(s); res.Asset.ID != asset {
		t.Fatalf("resolved to %s, want %s", res.Asset.ID, asset)
	}

	var (
		typ, mode, desc, oper, admin string
		enabled                      bool
		gotMTU                       int
		gotSpeed                     int64
		untagged                     sql.NullString
	)
	if err := h.db.QueryRow(`
		SELECT type, enabled, coalesce(mode, ''), coalesce(description, ''), mtu, speed_kbps,
		       coalesce(operational_status, ''), coalesce(admin_status, ''), untagged_vlan_id::text
		  FROM public.interfaces WHERE tenant_id = $1 AND asset_id = $2 AND name = 'xe-0/0/1'`, h.tenant, asset).
		Scan(&typ, &enabled, &mode, &desc, &gotMTU, &gotSpeed, &oper, &admin, &untagged); err != nil {
		t.Fatal(err)
	}
	if typ != "10gbase-x-sfpp" || enabled || mode != "tagged" || desc != "uplink to core — declared" {
		t.Errorf("declared fields moved: type=%q enabled=%t mode=%q description=%q", typ, enabled, mode, desc)
	}
	if gotMTU != 9000 || gotSpeed != 10_000_000 || oper != "up" || admin != "up" {
		t.Errorf("measured fields not refreshed: mtu=%d speed=%d oper=%q admin=%q", gotMTU, gotSpeed, oper, admin)
	}
	if !untagged.Valid {
		t.Error("the empty untagged VLAN was not filled from the measurement")
	}
	var dhcp bool
	var vlanName string
	if err := h.db.QueryRow(`SELECT dhcp_managed FROM public.prefixes WHERE tenant_id = $1 AND prefix = '10.7.0.0/24'`, h.tenant).Scan(&dhcp); err != nil {
		t.Fatal(err)
	}
	if err := h.db.QueryRow(`SELECT name FROM public.vlans WHERE tenant_id = $1 AND vid = 70`, h.tenant).Scan(&vlanName); err != nil {
		t.Fatal(err)
	}
	if dhcp || vlanName != "corp" {
		t.Errorf("declared prefix dhcp_managed=%t, VLAN name=%q; want false and corp", dhcp, vlanName)
	}

	// Every write the posture half made is in the change log.
	var changed int
	if err := h.db.QueryRow(`SELECT count(*) FROM public.object_changes WHERE tenant_id = $1 AND source = 'intake:identity' AND object_kind = 'interface'`, h.tenant).Scan(&changed); err != nil {
		t.Fatal(err)
	}
	if changed == 0 {
		t.Error("the interface's measured refresh was not recorded in object_changes")
	}
}
