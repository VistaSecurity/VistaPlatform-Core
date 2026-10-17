package services

import (
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/hostobs"
)

func hostObsWireFinding(method, sensorID string) IngestFinding {
	f := IngestFinding{Kind: KindHostObservation, RawData: map[string]interface{}{"discovery_method": method}}
	if sensorID != "" {
		f.SourceSensorID = &sensorID
	}
	return f
}

// TestHostObservationSightingSource_NamesTheBindingProtocol pins how a lease
// and an ARP binding reach ip_addresses.last_seen_source (DCIM row 1.5e): the
// protocol rides in the ref, Origin keeps the plain ref observations group
// by, and the pcap upload path maps exactly like the live sensor.
func TestHostObservationSightingSource_NamesTheBindingProtocol(t *testing.T) {
	const sensor = "3f0c9a52-6f1d-4b8e-9a77-1c2d3e4f5a60"
	for _, tc := range []struct {
		name      string
		f         IngestFinding
		ho        hostobs.HostObservation
		self      bool
		ref, orig string
	}{
		{"sensor dhcp lease", hostObsWireFinding("passive_host_observation", sensor),
			hostobs.HostObservation{Source: "dhcp", Sources: []string{"dhcp"}}, false, "sensor:" + sensor + ":dhcp", "sensor:" + sensor},
		{"coalesced arp+dhcp+mdns is a lease", hostObsWireFinding("passive_host_observation", sensor),
			hostobs.HostObservation{Source: "arp", Sources: []string{"arp", "dhcp", "mdns"}}, false, "sensor:" + sensor + ":dhcp", "sensor:" + sensor},
		{"a DISCOVER's wish is no lease", hostObsWireFinding("passive_host_observation", sensor),
			hostobs.HostObservation{Source: "dhcp", Sources: []string{"dhcp"}, Attributes: map[string]any{"dhcp_address_requested_only": true}}, false, "sensor:" + sensor, ""},
		{"arp binding", hostObsWireFinding("passive_host_observation", sensor),
			hostobs.HostObservation{Source: "arp", Sources: []string{"arp", "mdns"}}, false, "sensor:" + sensor + ":arp", "sensor:" + sensor},
		{"mdns alone is passive", hostObsWireFinding("passive_host_observation", sensor),
			hostobs.HostObservation{Source: "mdns", Sources: []string{"mdns"}}, false, "sensor:" + sensor, ""},
		{"pcap upload lease", hostObsWireFinding("pcap_upload", ""),
			hostobs.HostObservation{Source: "dhcp", Sources: []string{"dhcp"}}, false, "sensor:pcap:dhcp", "sensor:pcap"},
		{"self-report keeps its ref", hostObsWireFinding("sensor_self_report", sensor),
			hostobs.HostObservation{AgentID: sensor, Sources: []string{"dhcp"}}, true, "sensor:" + sensor, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := hostObservationSightingSource(tc.f, &tc.ho, tc.self)
			if got.Ref != tc.ref || got.Origin != tc.orig {
				t.Errorf("source = %q (origin %q), want %q (origin %q)", got.Ref, got.Origin, tc.ref, tc.orig)
			}
			if got.Grouping().Ref != hostObservationSource(tc.f).Ref {
				t.Errorf("grouping ref %q differs from the plain ref %q: one host's observations would split by protocol", got.Grouping().Ref, hostObservationSource(tc.f).Ref)
			}
		})
	}
}

// TestHostObservationSighting_SendsNoUnnamedInterface: a passive frame's MAC
// and address travel as identifiers (filed on a synthetic interface by the
// engine), never as an ObservedInterface the seam would drop for lacking a
// name; an unverified self-report's interface table is not trusted.
func TestHostObservationSighting_SendsNoUnnamedInterface(t *testing.T) {
	tenant := uuid.New()
	ho := &hostobs.HostObservation{
		AgentID: "3f0c9a52-6f1d-4b8e-9a77-1c2d3e4f5a61", MAC: "00:1a:2b:3c:4d:01",
		Interfaces: []hostobs.Interface{{Name: "enp1s0", MAC: "00:1a:2b:3c:4d:01", Addresses: []string{"192.0.2.10/24"}}},
	}
	if sg := hostObservationSighting(tenant, hostObsWireFinding("sensor_self_report", ""), ho, false); len(sg.Interfaces) != 0 {
		t.Errorf("an unverified self-report sent interfaces: %+v", sg.Interfaces)
	}
	sg := hostObservationSighting(tenant, hostObsWireFinding("sensor_self_report", ""), ho, true)
	if len(sg.Interfaces) != 1 || sg.Interfaces[0].Name != "enp1s0" || sg.Interfaces[0].Addresses[0].Source != "agent" {
		t.Errorf("verified self-report interfaces = %+v", sg.Interfaces)
	}

	passive := &hostobs.HostObservation{MAC: "28:cf:da:01:02:03", Source: "dhcp", Sources: []string{"dhcp"},
		Attributes: map[string]any{hostobs.AttrDHCPSubnet: "10.20.30.0/24"}}
	sg = hostObservationSighting(tenant, hostObsWireFinding("passive_host_observation", ""), passive, false)
	if len(sg.Interfaces) != 0 {
		t.Errorf("a passive observation sent interfaces: %+v", sg.Interfaces)
	}
	if len(sg.Prefixes) != 1 || sg.Prefixes[0].Prefix != "10.20.30.0/24" || sg.Prefixes[0].DHCPManaged == nil || !*sg.Prefixes[0].DHCPManaged {
		t.Errorf("prefixes = %+v, want 10.20.30.0/24 DHCP-managed", sg.Prefixes)
	}
	for _, bad := range []string{"10.20.30.41/32", "0.0.0.0/0", "2001:db8::/64", "garbage"} {
		passive.Attributes[hostobs.AttrDHCPSubnet] = bad
		if sg := hostObservationSighting(tenant, hostObsWireFinding("passive_host_observation", ""), passive, false); len(sg.Prefixes) != 0 {
			t.Errorf("dhcp_subnet %q produced prefix %+v", bad, sg.Prefixes)
		}
	}
}
