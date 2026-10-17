package services

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// jsonNames lists a struct's JSON field names, recursing into slices of structs.
func jsonNames(t reflect.Type, prefix string, out map[string]string) {
	for t.Kind() == reflect.Slice || t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		name := strings.Split(f.Tag.Get("json"), ",")[0]
		if name == "" || name == "-" {
			continue
		}
		ft := f.Type
		for ft.Kind() == reflect.Slice || ft.Kind() == reflect.Pointer {
			ft = ft.Elem()
		}
		out[prefix+name] = ft.Kind().String()
		if ft.Kind() == reflect.Struct {
			jsonNames(ft, prefix+name+".", out)
		}
	}
}

// The collector's wire types (shared/deviceinterrogation, which must not import
// shared/identity) and identity's observed types carry the same JSON names. A
// field added to one side and not the other is a build-time-invisible drift;
// this holds them together.
//
// Mutation: add a field to di.ObservedInterface — red.
func TestSNMPNetwork_WireTypesMatchIdentity(t *testing.T) {
	pairs := []struct {
		name      string
		di, ident reflect.Type
	}{
		{"interface", reflect.TypeOf(di.ObservedInterface{}), reflect.TypeOf(identity.ObservedInterface{})},
		{"address", reflect.TypeOf(di.ObservedAddress{}), reflect.TypeOf(identity.ObservedAddress{})},
		{"prefix", reflect.TypeOf(di.ObservedPrefix{}), reflect.TypeOf(identity.ObservedPrefix{})},
		{"vlan", reflect.TypeOf(di.ObservedVLAN{}), reflect.TypeOf(identity.ObservedVLAN{})},
		{"tunnel", reflect.TypeOf(di.ObservedTunnel{}), reflect.TypeOf(identity.ObservedTunnel{})},
		{"neighbor", reflect.TypeOf(di.ObservedNeighbor{}), reflect.TypeOf(identity.ObservedNeighbor{})},
		{"inventory item", reflect.TypeOf(di.ObservedInventoryItem{}), reflect.TypeOf(identity.ObservedInventoryItem{})},
		{"module", reflect.TypeOf(di.ObservedModule{}), reflect.TypeOf(identity.ObservedModule{})},
		{"virtual chassis", reflect.TypeOf(di.ObservedVirtualChassis{}), reflect.TypeOf(identity.ObservedVirtualChassis{})},
	}
	for _, p := range pairs {
		a, b := map[string]string{}, map[string]string{}
		jsonNames(p.di, "", a)
		jsonNames(p.ident, "", b)
		if !reflect.DeepEqual(a, b) {
			t.Errorf("%s: wire fields %v differ from identity's %v", p.name, a, b)
		}
	}
}

func TestSNMPNetworkSighting_ManagementAddressAndNoFacts(t *testing.T) {
	tenant := uuid.New()
	n := &di.NetworkObservation{
		ManagementAddress: "10.0.99.2",
		Interfaces:        []di.ObservedInterface{{Name: "Vlan99", Addresses: []di.ObservedAddress{{Address: "10.0.99.2", PrefixLen: 24, Assignment: "static"}}}},
	}
	sg, err := snmpNetworkSighting(tenant, identity.Source{Kind: identity.SourceMeasured, Ref: "interrogation:x"}, time.Now(),
		[]identity.SightedIdentifier{{Kind: identity.KindSerialNumber, Value: "SN1"}}, n)
	if err != nil {
		t.Fatal(err)
	}
	if sg.ManagementAddress != "10.0.99.2" || len(sg.Interfaces) != 1 || sg.Interfaces[0].Addresses[0].Assignment != identity.AssignmentStatic {
		t.Errorf("sighting = %+v", sg)
	}
	// Listed on an interface already: not added a second time as an identifier.
	for _, id := range sg.Identifiers {
		if id.Kind == identity.KindIPAddress {
			t.Errorf("the management address was added as an identifier although Vlan99 lists it: %+v", sg.Identifiers)
		}
	}

	// Not listed anywhere: added, so the engine can make it the primary.
	n.Interfaces = nil
	n.VLANs = []di.ObservedVLAN{{VID: 10}}
	sg, err = snmpNetworkSighting(tenant, identity.Source{Kind: identity.SourceMeasured, Ref: "interrogation:x"}, time.Now(), nil, n)
	if err != nil {
		t.Fatal(err)
	}
	if len(sg.Identifiers) != 1 || sg.Identifiers[0].Kind != identity.KindIPAddress {
		t.Errorf("identifiers = %+v, want the management address", sg.Identifiers)
	}
}

func TestInterrogationObservations_NetworkAloneIsNotEmpty(t *testing.T) {
	if !(InterrogationObservations{}).Empty() {
		t.Error("an empty observation is not empty")
	}
	if (InterrogationObservations{Network: &di.NetworkObservation{ARP: []di.ObservedARPEntry{{Address: "10.0.0.2", MAC: "00:00:5e:00:53:01"}}}}).Empty() {
		t.Error("a network observation was dropped as empty")
	}
}

// The device's tunnels ride the same sighting as its interfaces (DCIM row
// 4.3). Mutation: drop Tunnels from decodedNetwork — red.
func TestNetworkSighting_CarriesTunnels(t *testing.T) {
	n := &di.NetworkObservation{Tunnels: []di.ObservedTunnel{{Name: "to-hq", Encapsulation: "ipsec-tunnel", PeerIP: "198.51.100.1",
		IKEProposals: []di.ObservedIKEProposal{{Encryption: "aes-256-cbc", Integrity: "hmac-sha1", Group: 14}}}}}
	sg, err := snmpNetworkSighting(uuid.New(), identity.Source{Kind: identity.SourceMeasured, Ref: "interrogation:x"}, time.Now(),
		[]identity.SightedIdentifier{{Kind: identity.KindSerialNumber, Value: "SN1"}}, n)
	if err != nil {
		t.Fatal(err)
	}
	if len(sg.Tunnels) != 1 || sg.Tunnels[0].Name != "to-hq" || sg.Tunnels[0].IKEProposals[0].Group != 14 {
		t.Fatalf("sighting tunnels = %+v", sg.Tunnels)
	}
}

// A device's LLDP / CDP neighbours ride its sighting (DCIM row 3.3), for
// inventory-service to propose cables from. Mutation: drop Neighbors from
// decodedNetwork or from the sighting — red; a neighbour-only observation
// must still be posted.
func TestNetworkSighting_CarriesNeighbors(t *testing.T) {
	nb := di.ObservedNeighbor{Protocol: "cdp", LocalInterface: "GigabitEthernet1/0/16", RemotePortID: "GigabitEthernet0/1",
		RemoteSystemName: "desktop-switch", RemoteMgmtAddress: "192.0.2.2"}
	n := &di.NetworkObservation{Neighbors: []di.ObservedNeighbor{nb}}
	if n.Empty() {
		t.Fatal("a neighbour-only network observation reads as empty and would never be posted")
	}
	sg, err := snmpNetworkSighting(uuid.New(), identity.Source{Kind: identity.SourceMeasured, Ref: "interrogation:x"}, time.Now(),
		[]identity.SightedIdentifier{{Kind: identity.KindSerialNumber, Value: "SN1"}}, n)
	if err != nil {
		t.Fatal(err)
	}
	want := identity.ObservedNeighbor{Protocol: "cdp", LocalInterface: "GigabitEthernet1/0/16", RemotePortID: "GigabitEthernet0/1",
		RemoteSystemName: "desktop-switch", RemoteMgmtAddress: "192.0.2.2"}
	if len(sg.Neighbors) != 1 || sg.Neighbors[0] != want {
		t.Fatalf("sighting neighbours = %+v", sg.Neighbors)
	}
}

// A UniFi controller's subject-bound net.neighbors (a managed device's LLDP
// table and wired uplink) becomes that subject's sighting neighbours, named
// the way its interfaces are, and is not stored as a fact. Mutation: drop
// KeyNetNeighbors from isSubjectNetworkFact — red.
func TestSubjectNetworks_NeighborsRideTheSubjectsSighting(t *testing.T) {
	subject := di.PeerRef{Identifiers: []di.PeerIdentifier{{Kind: di.IdentifierMACAddress, Value: "78:8a:20:4b:ee:52"}}}
	f := di.FactObservation{Key: "net.neighbors", Subject: subject, Confidence: 1, Value: []map[string]interface{}{
		{"protocol": "lldp", "local_port": "port1", "remote_mac": "78:8a:20:4b:ee:41", "remote_port": "Port 2", "remote_name": "Office Switch"},
		{"protocol": "arp", "local_port": "Port 1", "remote_mac": "00:00:5e:00:53:01", "remote_address": "10.0.0.9"},
	}}
	if !isSubjectNetworkFact(f) {
		t.Fatal("a subject-bound net.neighbors fact would be stored rather than carried on the sighting")
	}
	n, ok := subjectNetworks([]di.FactObservation{f})[retainedPeerKey(subject)]
	if !ok || len(n.Neighbors) != 1 {
		t.Fatalf("subject network = %+v", n)
	}
	var sg identity.Sighting
	n.applyTo(&sg, subject)
	if len(sg.Neighbors) != 1 || sg.Neighbors[0].LocalInterface != "Port 1" || sg.Neighbors[0].RemoteChassisID != "78:8a:20:4b:ee:41" ||
		sg.Neighbors[0].RemotePortID != "Port 2" {
		t.Fatalf("sighting neighbours = %+v", sg.Neighbors)
	}
}
