package services

// DCIM row 1.5b: the UniFi adapter. These tests need no database: they drive
// the REAL projection (shared/deviceinterrogation.UnifiSiteObservations over
// a recorded controller response set) and the REAL sighting builder
// (subjectNetworks → peerSighting) and look at the sightings the platform
// would post. The parity of what the engine then WRITES is
// unifi_network_sighting_integration_test.go.

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform/shared/facts"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// The recorded site (testdata/unifi_parity/site.json): a UDM serving three
// networks, a 24-port switch (plus two SFP+ ports in a LAG) with a trunk to
// the gateway and an access point, an AP broadcasting two SSIDs on two
// radios, and five clients.
const (
	unifiParityUDM    = "74:ac:b9:10:00:01"
	unifiParitySwitch = "78:8a:20:20:00:01"
	unifiParityAP     = "f4:92:bf:30:00:01"
	unifiParityLaptop = "3c:22:fb:00:00:01"
	unifiParityCamera = "9c:8e:cd:00:00:03"
)

// unifiParitySecrets are planted in the recording: wireless PSKs, the SMTP
// relay password, the PPPoE password. None may reach a sighting or a row.
var unifiParitySecrets = []string{"PlantedWlanPassphrase5521", "PlantedWlanPsk7730", "PlantedSmtpPassword3318"}

// unifiRecording is the recorded response set's envelope.
type unifiRecording struct {
	ControllerHost string                   `json:"controller_host"`
	Controller     map[string]interface{}   `json:"controller"`
	NetworkConfs   []map[string]interface{} `json:"networkconf"`
	WLANConfs      []map[string]interface{} `json:"wlanconf"`
	Devices        []map[string]interface{} `json:"devices"`
	Clients        []map[string]interface{} `json:"clients"`
}

func unifiParityRecording(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "unifi_parity", "site.json"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// unifiSiteResult runs the collector's real projection over a recording.
func unifiSiteResult(response []byte) (*di.InterrogateResult, error) {
	return unifiSiteResultAt(response, "")
}

// unifiSiteResultAt is unifiSiteResult for a controller reached at host
// ("" keeps the recording's).
func unifiSiteResultAt(response []byte, host string) (*di.InterrogateResult, error) {
	var rec unifiRecording
	if err := json.Unmarshal(response, &rec); err != nil {
		return nil, err
	}
	if host != "" {
		rec.ControllerHost = host
	}
	result := di.UnifiSiteObservations(di.UnifiSite{
		ControllerHost: rec.ControllerHost,
		Controller:     rec.Controller,
		NetworkConfs:   rec.NetworkConfs,
		WLANConfs:      rec.WLANConfs,
		Devices:        rec.Devices,
		Clients:        rec.Clients,
	})
	// The redactor every interrogation result passes through, at the
	// collector boundary and again on receipt (persist).
	di.Sanitize(result)
	return result, nil
}

// unifiSubjectSighting is the sighting the platform builds for the subject
// whose MAC is mac: every subject of the run is gathered as persist gathers
// them, its observed network attached by the same builder.
func unifiSubjectSighting(tenantID string, response []byte, at time.Time, mac string) (identity.Sighting, error) {
	result, err := unifiSiteResult(response)
	if err != nil {
		return identity.Sighting{}, err
	}
	tenant, err := uuid.Parse(tenantID)
	if err != nil {
		return identity.Sighting{}, err
	}
	ctx := withSubjectNetworks(context.Background(), subjectNetworks(result.Facts))
	for _, f := range result.Facts {
		if f.Subject.Identifier(di.IdentifierMACAddress) != mac {
			continue
		}
		source := identity.Source{Kind: identity.SourceMeasured, Ref: "interrogation:unifi-parity", Mode: identity.ModeActive}
		s, _, err := NewObservationSink(nil).peerSighting(ctx, tenant, f.Subject, source, at)
		return s, err
	}
	return identity.Sighting{}, fmt.Errorf("no subject with MAC %s in the recording", mac)
}

func sightingFor(t *testing.T, mac string) identity.Sighting {
	t.Helper()
	s, err := unifiSubjectSighting(uuid.NewString(), unifiParityRecording(t), time.Now(), mac)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func interfaceNamed(s identity.Sighting, name string) (identity.ObservedInterface, bool) {
	for _, i := range s.Interfaces {
		if i.Name == name {
			return i, true
		}
	}
	return identity.ObservedInterface{}, false
}

// TestUniFiAdapter_SwitchPortsLAGAndTrunks: the switch's sighting carries one
// interface per port named `Port N` (an operator's label "Printer" is not a
// name; `sfp+2` is `SFP+ 2`), typed from the medium, with the trunk's tagged
// VLANs resolved through networkconf, the LAG built from aggregated_by, and
// the management address on the interface holding the device's MAC.
func TestUniFiAdapter_SwitchPortsLAGAndTrunks(t *testing.T) {
	s := sightingFor(t, unifiParitySwitch)
	if len(s.Interfaces) != 28 { // 26 ports + eth0 + LAG 25
		names := make([]string, 0, len(s.Interfaces))
		for _, i := range s.Interfaces {
			names = append(names, i.Name)
		}
		t.Fatalf("switch interfaces = %d %v, want 26 ports, eth0 and LAG 25", len(s.Interfaces), names)
	}
	if s.ManagementAddress != "10.20.0.11" {
		t.Errorf("management address = %q, want the address the controller lists the switch at", s.ManagementAddress)
	}
	if len(s.Prefixes) != 0 || len(s.VLANs) != 0 {
		t.Errorf("the switch is not the site's gateway, yet carries prefixes %+v / VLANs %+v", s.Prefixes, s.VLANs)
	}
	trunk, _ := interfaceNamed(s, "Port 1")
	if trunk.Mode != "tagged" || trunk.UntaggedVLAN != 0 || fmt.Sprint(trunk.TaggedVLANs) != "[20 30]" || trunk.Type != "1000base-t" {
		t.Errorf("trunk = %+v, want tagged [20 30] on the untagged default LAN, 1000base-t", trunk)
	}
	if trunk.SpeedKbps == nil || *trunk.SpeedKbps != 1_000_000 || trunk.OperStatus != "up" || trunk.Enabled == nil || !*trunk.Enabled {
		t.Errorf("trunk state lost: %+v", trunk)
	}
	ap, _ := interfaceNamed(s, "Port 2")
	if ap.Mode != "tagged" || fmt.Sprint(ap.TaggedVLANs) != "[30]" {
		t.Errorf("AP port = %+v, want tagged [30] (IoT excluded)", ap)
	}
	iot, _ := interfaceNamed(s, "Port 3")
	if iot.Mode != "access" || iot.UntaggedVLAN != 20 || iot.Type != "100base-tx" {
		t.Errorf("IoT access port = %+v, want access on VLAN 20, 100base-tx", iot)
	}
	if _, ok := interfaceNamed(s, "Printer"); ok {
		t.Errorf("an operator's port label became an interface name")
	}
	if p9, ok := interfaceNamed(s, "Port 9"); !ok || p9.Mode != "access" {
		t.Errorf("Port 9 (labelled Printer) = %+v", p9)
	}
	shut, _ := interfaceNamed(s, "Port 10")
	if shut.Enabled == nil || *shut.Enabled || shut.OperStatus != "down" || shut.Mode != "" || shut.SpeedKbps != nil {
		t.Errorf("disabled port = %+v, want admin down, oper down, no mode, no speed", shut)
	}
	down, _ := interfaceNamed(s, "Port 12")
	if down.Mode != "tagged-all" || down.Type != "1000base-t" || down.SpeedKbps != nil {
		t.Errorf("idle default port = %+v, want tagged-all 1000base-t with no speed", down)
	}
	lag, _ := interfaceNamed(s, "LAG 25")
	if lag.Type != "lag" || lag.Mode != "tagged" || fmt.Sprint(lag.TaggedVLANs) != "[20 30]" || lag.OperStatus != "up" {
		t.Errorf("LAG = %+v, want a tagged lag carrying the master's VLANs", lag)
	}
	for _, member := range []string{"SFP+ 1", "SFP+ 2"} {
		m, ok := interfaceNamed(s, member)
		if !ok || m.LAG != "LAG 25" || m.Type != "10gbase-x-sfpp" || m.Mode != "" || len(m.TaggedVLANs) != 0 {
			t.Errorf("LAG member %s = %+v (present %v), want a 10gbase-x-sfpp member of LAG 25 with no VLANs of its own", member, m, ok)
		}
	}
	eth0, _ := interfaceNamed(s, "eth0")
	if eth0.MAC != unifiParitySwitch || len(eth0.Addresses) != 1 || eth0.Addresses[0].Address != "10.20.0.11" {
		t.Errorf("eth0 = %+v, want the device MAC and its management address", eth0)
	}
}

// TestUniFiAdapter_GatewayNetworksAndWAN: the UDM's sighting carries the
// site's prefixes and VLANs, a bridge interface per network with the
// gateway's own (static) address, and its WAN address on the port the WAN is.
func TestUniFiAdapter_GatewayNetworksAndWAN(t *testing.T) {
	s := sightingFor(t, unifiParityUDM)
	if got := fmt.Sprint(s.VLANs); got != "[{20 IoT} {30 Guest}]" {
		t.Errorf("VLANs = %s", got)
	}
	want := map[string]string{"10.20.0.0/24": "0 true corporate", "10.20.20.0/24": "20 false corporate", "10.20.30.0/24": "30 true guest"}
	if len(s.Prefixes) != len(want) {
		t.Fatalf("prefixes = %+v, want the three LAN networks (no WAN, no VPN)", s.Prefixes)
	}
	for _, p := range s.Prefixes {
		dhcp := "unset"
		if p.DHCPManaged != nil {
			dhcp = fmt.Sprint(*p.DHCPManaged)
		}
		if got := fmt.Sprintf("%d %s %s", p.VLAN, dhcp, p.NetworkType); got != want[p.Prefix] {
			t.Errorf("prefix %s = %s, want %s", p.Prefix, got, want[p.Prefix])
		}
	}
	br20, ok := interfaceNamed(s, "br20")
	if !ok || br20.UntaggedVLAN != 20 || len(br20.Addresses) != 1 || br20.Addresses[0].Address != "10.20.20.1" ||
		br20.Addresses[0].PrefixLen != 24 || br20.Addresses[0].Assignment != identity.AssignmentStatic {
		t.Errorf("br20 = %+v, want the gateway's static 10.20.20.1/24 on VLAN 20", br20)
	}
	wan, ok := interfaceNamed(s, "Port 9")
	if !ok || wan.MAC != "74:ac:b9:10:00:09" || len(wan.Addresses) != 1 || wan.Addresses[0].Address != "203.0.113.10" || wan.Addresses[0].PrefixLen != 24 {
		t.Errorf("WAN port = %+v, want eth8's MAC and 203.0.113.10/24", wan)
	}
	if s.ManagementAddress != "10.20.0.1" {
		t.Errorf("management address = %q", s.ManagementAddress)
	}
}

// TestUniFiAdapter_AccessPointRadios: one wireless interface per SSID per
// radio, typed by band, the BSSID as its MAC.
func TestUniFiAdapter_AccessPointRadios(t *testing.T) {
	s := sightingFor(t, unifiParityAP)
	for name, typ := range map[string]string{"ra0": "ieee802.11n", "rai0": "ieee802.11ac", "ra1": "ieee802.11n", "rai1": "ieee802.11ac"} {
		i, ok := interfaceNamed(s, name)
		if !ok || i.Type != typ {
			t.Errorf("%s = %+v (present %v), want type %s", name, i, ok, typ)
		}
	}
	if i, _ := interfaceNamed(s, "rai1"); i.OperStatus != "down" {
		t.Errorf("a VAP that is down = %+v", i)
	}
	if i, _ := interfaceNamed(s, "ra0"); i.MAC != "f4:92:bf:30:00:02" {
		t.Errorf("ra0 BSSID = %q", i.MAC)
	}
}

// TestUniFiAdapter_ClientAddressIsTheClients: a client's sighting carries its
// MAC and address as identifiers with no interface name (the engine files
// them on a synthetic interface) — and they are on the CLIENT's sighting, not
// the access point's or the switch's.
func TestUniFiAdapter_ClientAddressIsTheClients(t *testing.T) {
	laptop := sightingFor(t, unifiParityLaptop)
	if len(laptop.Interfaces) != 0 {
		t.Errorf("a client's interface was named for it: %+v", laptop.Interfaces)
	}
	var ip, mac bool
	for _, id := range laptop.Identifiers {
		ip = ip || (id.Kind == identity.KindIPAddress && id.Value == "10.20.0.101" && id.Interface == "")
		mac = mac || (id.Kind == identity.KindMACAddress && id.Value == unifiParityLaptop && id.Interface == "")
	}
	if !ip || !mac {
		t.Errorf("client identifiers = %+v, want its MAC and 10.20.0.101 with no interface", laptop.Identifiers)
	}
	for _, infra := range []string{unifiParityAP, unifiParitySwitch} {
		s := sightingFor(t, infra)
		for _, id := range s.Identifiers {
			if id.Value == "10.20.0.101" || id.Value == unifiParityLaptop {
				t.Errorf("the client's %s reached %s's sighting", id.Value, infra)
			}
		}
	}
}

// TestUniFiAdapter_SecretsNeverReachASighting: what the platform posts for
// every subject of the run carries none of the planted secrets.
func TestUniFiAdapter_SecretsNeverReachASighting(t *testing.T) {
	rec := unifiParityRecording(t)
	for _, s := range unifiParitySecrets {
		if !strings.Contains(string(rec), s) {
			t.Fatalf("secret %q is not planted in the recording", s)
		}
	}
	result, err := unifiSiteResult(rec)
	if err != nil {
		t.Fatal(err)
	}
	ctx := withSubjectNetworks(context.Background(), subjectNetworks(result.Facts))
	sink := NewObservationSink(nil)
	seen := map[string]bool{}
	for _, f := range result.Facts {
		if f.Subject.IsZero() || seen[retainedPeerKey(f.Subject)] {
			continue
		}
		seen[retainedPeerKey(f.Subject)] = true
		sg, _, err := sink.peerSighting(ctx, uuid.New(), f.Subject, identity.Source{Kind: identity.SourceMeasured, Ref: "x"}, time.Now())
		if err != nil {
			continue
		}
		blob, _ := json.Marshal(sg)
		for _, secret := range unifiParitySecrets {
			if strings.Contains(string(blob), secret) {
				t.Errorf("secret %q reached the sighting of %s", secret, sg.DisplayName)
			}
		}
	}
	if len(seen) < 8 {
		t.Fatalf("only %d subjects were built; the recording has 3 devices and 5 clients", len(seen))
	}
}

// TestSubjectNetworkFacts_OnlySubjectBound: the controller's interfaces and
// networks ride on sightings only when bound to a subject; the interrogated
// device's own net.interfaces / net.vlans (Cisco, Fortinet, …) are untouched.
func TestSubjectNetworkFacts_OnlySubjectBound(t *testing.T) {
	subject := di.PeerRef{}
	subject.AddIdentifier(di.IdentifierMACAddress, unifiParitySwitch)
	self := di.FactObservation{Key: facts.KeyNetInterfaces, Value: []map[string]any{{"name": "Gi1/0/1"}}}
	bound := di.FactObservation{Key: facts.KeyNetInterfaces, Value: []map[string]any{{"name": "Port 1"}}, Subject: subject}
	vlans := di.FactObservation{Key: facts.KeyNetVlans, Value: []map[string]any{{"id": 20, "subnet": "10.0.20.0/24"}}}
	if isSubjectNetworkFact(self) || isSubjectNetworkFact(vlans) || !isSubjectNetworkFact(bound) {
		t.Fatal("only subject-bound net.interfaces / net.vlans are a controller's account of a subject")
	}
	if networksMeasuredAsPrefixes([]di.FactObservation{self, vlans, bound}) {
		t.Error("a run whose networks are the device's own was taken as measured prefixes")
	}
	if !networksMeasuredAsPrefixes([]di.FactObservation{{Key: facts.KeyNetVlans, Value: []map[string]any{}, Subject: subject}}) {
		t.Error("a subject-bound net.vlans was not recognised")
	}
	got := subjectNetworks([]di.FactObservation{self, vlans, bound})
	if len(got) != 1 || len(got[retainedPeerKey(subject)].Interfaces) != 1 {
		t.Errorf("subject networks = %+v", got)
	}
}

// The controller's own net.vlans names the gateway's addresses (for the
// claims) unless the controller is KNOWN not to be the gateway.
func TestUniFiAdapter_ControllerClaimsGatewayOnlyWhenItMayBeIt(t *testing.T) {
	for host, wantGateway := range map[string]bool{
		"":             true,  // the recording's FQDN: it may be the console
		"10.20.0.1":    true,  // the UDM's own LAN address: it is the console
		"203.0.113.10": true,  // its WAN address
		"10.20.0.250":  false, // a Cloud Key beside the UDM
	} {
		result, err := unifiSiteResultAt(unifiParityRecording(t), host)
		if err != nil {
			t.Fatal(err)
		}
		gotGateway := false
		for _, f := range result.Facts {
			if f.Key != facts.KeyNetVlans || !f.Subject.IsZero() {
				continue
			}
			blob, _ := json.Marshal(f.Value)
			gotGateway = strings.Contains(string(blob), `"gateway"`)
		}
		if gotGateway != wantGateway {
			t.Errorf("controller at %q: gateway addresses in its net.vlans = %v, want %v", host, gotGateway, wantGateway)
		}
	}
}

// TestUniFiAdapter_AccessPointSSIDsCarryAuthPosture (row 4.4): the access
// point's sighting carries each SSID as an observed wireless LAN with the
// authentication scheme and cipher wlanconf states and that a passphrase
// EXISTS -- and each radio interface names the SSID it serves. The planted
// passphrase is in the sighting nowhere (TestUniFiAdapter_SecretsNeverReachASighting).
//
// Mutation: map wpa_enc "tkip" to "aes" (unifiWLANPostures) -> Guest's cipher
// assertion fails; drop `entry["ssids"]` (unifiInterfaces) -> the radios serve
// nothing.
func TestUniFiAdapter_AccessPointSSIDsCarryAuthPosture(t *testing.T) {
	s := sightingFor(t, unifiParityAP)
	got := map[string]identity.ObservedWirelessLAN{}
	for _, l := range s.WirelessLANs {
		got[l.SSID] = l
	}
	corp, guest := got["Corp"], got["Guest"]
	if corp.AuthType != "wpa-personal" || corp.AuthCipher != "aes" || !corp.PSKPresent {
		t.Errorf("Corp = %+v, want wpa-personal / aes / psk present", corp)
	}
	if guest.AuthType != "wpa-personal" || guest.AuthCipher != "tkip" || !guest.PSKPresent || guest.VLAN != 30 {
		t.Errorf("Guest = %+v, want wpa-personal / tkip / psk present / VLAN 30", guest)
	}
	for name, ssid := range map[string]string{"ra0": "Corp", "rai0": "Corp", "ra1": "Guest", "rai1": "Guest"} {
		ifc, ok := interfaceNamed(s, name)
		if !ok || ifc.RFRole != "ap" || len(ifc.SSIDs) != 1 || ifc.SSIDs[0] != ssid {
			t.Errorf("interface %s = %+v, want an ap radio serving %s", name, ifc, ssid)
		}
	}
	// A switch has no radios: nothing wireless.
	if sw := sightingFor(t, unifiParitySwitch); len(sw.WirelessLANs) != 0 {
		t.Errorf("the switch's sighting carries wireless LANs: %+v", sw.WirelessLANs)
	}
}
