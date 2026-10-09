package services

import (
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/hostobs"
	sharednetwork "github.com/vistasecurity/vistaplatform/shared/network"
)

var selfObsSensorID = uuid.MustParse("22222222-2222-2222-2222-222222222222")

// TestSelfHostObservation_CarriesAgentIDAsTheStrongestIdentifier pins the
// whole point of the feature: a self-report's AgentID is the sensor's own id
// — identity.KindAgentID's job, applied downstream in inventory-service — so
// this test only needs to confirm sensor-manager actually SETS it (nothing
// here should ever be tempted to leave it for the consumer to derive).
func TestSelfHostObservation_CarriesAgentIDAsTheStrongestIdentifier(t *testing.T) {
	host := &models.HostIdentity{Hostname: "xps16-sensor", OS: "linux", Arch: "amd64"}
	ho := selfHostObservation(selfObsSensorID, "linux", "datacenter_host", host)
	if ho.AgentID != selfObsSensorID.String() {
		t.Fatalf("AgentID = %q, want %q", ho.AgentID, selfObsSensorID.String())
	}
	if !ho.Identifies() {
		t.Fatal("a self-observation with an AgentID must always identify")
	}
	if ho.Platform != "linux" || ho.Profile != "datacenter_host" {
		t.Fatalf("Platform/Profile = %q/%q, want linux/datacenter_host", ho.Platform, ho.Profile)
	}
}

// TestSelfHostObservation_PicksThePrimaryMAC: several interfaces, only the
// one flagged primary should be picked as the (single) MAC hostobs carries.
func TestSelfHostObservation_PicksThePrimaryMAC(t *testing.T) {
	host := &models.HostIdentity{
		Hostname: "h",
		Interfaces: []sharednetwork.InterfaceAddress{
			{InterfaceName: "eth1", Address: "10.0.0.2", MAC: "00:1a:2b:3c:4d:60"},
			{InterfaceName: "eth0", Address: "10.0.0.1", MAC: "00:1a:2b:3c:4d:5e", IsPrimary: true},
		},
	}
	ho := selfHostObservation(selfObsSensorID, "linux", "", host)
	if ho.MAC != "00:1a:2b:3c:4d:5e" {
		t.Fatalf("MAC = %q, want the primary interface's 00:1a:2b:3c:4d:5e", ho.MAC)
	}
	if len(ho.Addresses) != 2 {
		t.Fatalf("Addresses = %v, want both interfaces' addresses carried", ho.Addresses)
	}
}

// TestSelfHostObservation_FallsBackToFirstUsableMACWhenNonePrimary.
func TestSelfHostObservation_FallsBackToFirstUsableMACWhenNonePrimary(t *testing.T) {
	host := &models.HostIdentity{
		Hostname: "h",
		Interfaces: []sharednetwork.InterfaceAddress{
			{InterfaceName: "eth0", Address: "10.0.0.1", MAC: ""},
			{InterfaceName: "eth1", Address: "10.0.0.2", MAC: "00:1a:2b:3c:4d:60"},
		},
	}
	ho := selfHostObservation(selfObsSensorID, "linux", "", host)
	if ho.MAC != "00:1a:2b:3c:4d:60" {
		t.Fatalf("MAC = %q, want the first interface that reported one", ho.MAC)
	}
}

// TestSelfHostObservation_SplitsHostnameAndFQDN mirrors the sensor's own
// hostname/FQDN convention: a name with a dot is filed as an FQDN, a bare
// name as a hostname — never both from one field.
func TestSelfHostObservation_SplitsHostnameAndFQDN(t *testing.T) {
	host := &models.HostIdentity{Hostname: "xps16-sensor", FQDN: "xps16-sensor.corp.example.com"}
	ho := selfHostObservation(selfObsSensorID, "linux", "", host)
	if len(ho.Hostnames) != 1 || ho.Hostnames[0] != "xps16-sensor" {
		t.Fatalf("Hostnames = %v, want [xps16-sensor]", ho.Hostnames)
	}
	if len(ho.FQDNs) != 1 || ho.FQDNs[0] != "xps16-sensor.corp.example.com" {
		t.Fatalf("FQDNs = %v, want [xps16-sensor.corp.example.com]", ho.FQDNs)
	}
}

// TestSelfObservationDiscovery_UsesADistinctDiscoveryMethod pins the marker
// hostObservationIsSelfReport (inventory-service) reads to tell a self-report
// apart from an ordinary passive capture.
func TestSelfObservationDiscovery_UsesADistinctDiscoveryMethod(t *testing.T) {
	host := &models.HostIdentity{Hostname: "xps16-sensor"}
	ho := selfHostObservation(selfObsSensorID, "linux", "datacenter_host", host)
	d := selfObservationDiscovery(ho)

	if d.DiscoveryMethod != "sensor_self_report" {
		t.Fatalf("DiscoveryMethod = %q, want %q", d.DiscoveryMethod, "sensor_self_report")
	}
	if d.DiscoveryType != "host_observation" {
		t.Fatalf("DiscoveryType = %q, want host_observation", d.DiscoveryType)
	}
	if d.Confidence != 1 {
		t.Fatalf("Confidence = %v, want 1 (an agent's own id is not graded on the passive-decoder ladder)", d.Confidence)
	}
	if d.Hostname != "xps16-sensor" {
		t.Fatalf("Hostname = %q, want xps16-sensor", d.Hostname)
	}
	raw, ok := d.RawMetadata["host_observation"].(*hostobs.HostObservation)
	if !ok {
		t.Fatalf("RawMetadata[host_observation] = %T, want *hostobs.HostObservation", d.RawMetadata["host_observation"])
	}
	if raw.AgentID != selfObsSensorID.String() {
		t.Fatalf("embedded observation AgentID = %q, want %q", raw.AgentID, selfObsSensorID.String())
	}
}

// TestSelfObservationDiscovery_DestIPFallsBackToUnspecified: a self-report
// with no usable address still gets a valid inet value for the NOT NULL
// dest_ip column, the same convention the passive path uses.
func TestSelfObservationDiscovery_DestIPFallsBackToUnspecified(t *testing.T) {
	ho := selfHostObservation(selfObsSensorID, "linux", "", &models.HostIdentity{Hostname: "h"})
	d := selfObservationDiscovery(ho)
	if d.DestIP != "0.0.0.0" {
		t.Fatalf("DestIP = %q, want 0.0.0.0 when no address was reported", d.DestIP)
	}
}

// TestSelfObservationHash_StableAndSensitiveToContent mirrors
// sensor/internal/hostid's own Hash test — sensor-manager keeps an
// independent implementation of the same idea (registration-side throttle,
// no shared state with the sensor process) and it needs the same two
// properties.
func TestSelfObservationHash_StableAndSensitiveToContent(t *testing.T) {
	a := &models.HostIdentity{Hostname: "h", OS: "linux", Arch: "amd64", Interfaces: []sharednetwork.InterfaceAddress{
		{InterfaceName: "eth0", Address: "10.0.0.1", MAC: "aa:aa:aa:aa:aa:aa"},
	}}
	b := &models.HostIdentity{Hostname: "h", OS: "linux", Arch: "amd64", Interfaces: []sharednetwork.InterfaceAddress{
		{InterfaceName: "eth0", Address: "10.0.0.1", MAC: "aa:aa:aa:aa:aa:aa"},
	}}
	if selfObservationHash(a) != selfObservationHash(b) {
		t.Fatal("hash of two identical Host blocks differed")
	}

	c := &models.HostIdentity{Hostname: "h-renamed", OS: "linux", Arch: "amd64", Interfaces: a.Interfaces}
	if selfObservationHash(a) == selfObservationHash(c) {
		t.Fatal("hash did not change when the hostname changed")
	}
}

// TestEmitSelfObservationIfDue_NilHostIsANoOp pins backward compatibility
// with an older sensor build that sends no `host` block at all: nil must be a
// pure no-op, including never touching the database, so the call is safe on
// every heartbeat/registration regardless of build age.
//
// Mutation check: deleting the `if host == nil { return }` guard in
// EmitSelfObservationIfDue makes this test panic (nil bypassDB dereference)
// instead of returning quietly.
func TestEmitSelfObservationIfDue_NilHostIsANoOp(t *testing.T) {
	svc := &SensorService{}
	svc.EmitSelfObservationIfDue(selfObsSensorID, nil) // must not panic
}

func TestSelfObservationHash_IgnoresInterfaceOrder(t *testing.T) {
	a := &models.HostIdentity{Hostname: "h", Interfaces: []sharednetwork.InterfaceAddress{
		{InterfaceName: "eth0", Address: "10.0.0.1", MAC: "aa:aa:aa:aa:aa:aa"},
		{InterfaceName: "eth1", Address: "10.0.0.2", MAC: "bb:bb:bb:bb:bb:bb"},
	}}
	b := &models.HostIdentity{Hostname: "h", Interfaces: []sharednetwork.InterfaceAddress{
		{InterfaceName: "eth1", Address: "10.0.0.2", MAC: "bb:bb:bb:bb:bb:bb"},
		{InterfaceName: "eth0", Address: "10.0.0.1", MAC: "aa:aa:aa:aa:aa:aa"},
	}}
	if selfObservationHash(a) != selfObservationHash(b) {
		t.Fatal("hash depends on interface order")
	}
}

// dockerNodeHost is the shape a Kubernetes node running Docker reports: one
// real NIC (the primary), a Wi-Fi NIC on a second network, and the bridges and
// overlays its container runtimes created. docker0's 172.17.0.1 is the same
// address on every Docker host.
func dockerNodeHost(bridges ...sharednetwork.InterfaceAddress) *models.HostIdentity {
	return &models.HostIdentity{
		Hostname: "node-a",
		Interfaces: append([]sharednetwork.InterfaceAddress{
			{InterfaceName: "enp2s0", Address: "10.0.0.10", MAC: "00:1a:2b:3c:4d:01", IsPrimary: true},
			{InterfaceName: "wlp4s0", Address: "10.1.0.10", MAC: "00:1a:2b:3c:4d:02"},
			{InterfaceName: "docker0", Address: "172.17.0.1"},
			{InterfaceName: "br-0bd1b3acd33d", Address: "172.18.0.1"},
			{InterfaceName: "flannel.1", Address: "10.42.0.0"},
		}, bridges...),
	}
}

// TestSelfHostObservation_ContainerBridgesAreNotIdentity: a container bridge's
// address names every host running the same software, so it must not reach the
// identification engine as this host's address.
func TestSelfHostObservation_ContainerBridgesAreNotIdentity(t *testing.T) {
	ho := selfHostObservation(selfObsSensorID, "linux", "", dockerNodeHost())
	got := map[string]bool{}
	for _, a := range ho.Addresses {
		got[a.String()] = true
	}
	for _, bridge := range []string{"172.17.0.1", "172.18.0.1", "10.42.0.0"} {
		if got[bridge] {
			t.Errorf("self-observation carries container bridge address %s as identity: %v", bridge, ho.Addresses)
		}
	}
	for _, real := range []string{"10.0.0.10", "10.1.0.10"} {
		if !got[real] {
			t.Errorf("self-observation dropped the host's own address %s: %v", real, ho.Addresses)
		}
	}
}

// TestSelfHostObservation_CarriesEveryHardwareMAC: a host's Ethernet and Wi-Fi
// are one device, and this report is the only evidence of it. The primary
// interface's MAC stays in MAC; the other NIC's rides in OtherMACs.
func TestSelfHostObservation_CarriesEveryHardwareMAC(t *testing.T) {
	ho := selfHostObservation(selfObsSensorID, "linux", "", dockerNodeHost())
	if ho.MAC != "00:1a:2b:3c:4d:01" {
		t.Fatalf("MAC = %q, want the primary NIC's", ho.MAC)
	}
	if len(ho.OtherMACs) != 1 || ho.OtherMACs[0] != "00:1a:2b:3c:4d:02" {
		t.Fatalf("OtherMACs = %v, want the Wi-Fi NIC's 00:1a:2b:3c:4d:02", ho.OtherMACs)
	}
}

// TestSelfHostObservation_PrimaryInterfaceIsNeverDropped: on a Hyper-V host
// with an external virtual switch the host's real LAN address lives on
// "vEthernet (...)". The interface the sensor reaches the platform from is how
// the host is reached, whatever it is called.
func TestSelfHostObservation_PrimaryInterfaceIsNeverDropped(t *testing.T) {
	host := &models.HostIdentity{Hostname: "hv", Interfaces: []sharednetwork.InterfaceAddress{
		{InterfaceName: "vEthernet (External Switch)", Address: "10.0.0.20", MAC: "00:15:5d:01:02:03", IsPrimary: true},
		{InterfaceName: "vEthernet (WSL)", Address: "172.29.48.1", MAC: "00:15:5d:aa:bb:cc"},
	}}
	ho := selfHostObservation(selfObsSensorID, "windows", "", host)
	if len(ho.Addresses) != 1 || ho.Addresses[0].String() != "10.0.0.20" {
		t.Fatalf("Addresses = %v, want only the primary vEthernet's 10.0.0.20", ho.Addresses)
	}
	if ho.MAC != "00:15:5d:01:02:03" || len(ho.OtherMACs) != 0 {
		t.Fatalf("MAC/OtherMACs = %q/%v, want the primary's MAC and not the WSL switch's", ho.MAC, ho.OtherMACs)
	}
}

// TestSelfHostObservation_UnnamedInterfacesAreKept: an older sensor that
// reports no interface names keeps every address it always carried. Nothing
// says those interfaces are virtual.
func TestSelfHostObservation_UnnamedInterfacesAreKept(t *testing.T) {
	host := &models.HostIdentity{Hostname: "h", Interfaces: []sharednetwork.InterfaceAddress{
		{Address: "10.0.0.1", MAC: "00:1a:2b:3c:4d:5e", IsPrimary: true},
		{Address: "10.0.1.1", MAC: "00:1a:2b:3c:4d:5f"},
	}}
	ho := selfHostObservation(selfObsSensorID, "linux", "", host)
	if len(ho.Addresses) != 2 || len(ho.OtherMACs) != 1 {
		t.Fatalf("Addresses/OtherMACs = %v/%v, want both unnamed interfaces kept", ho.Addresses, ho.OtherMACs)
	}
}

// TestSelfObservationHash_IgnoresContainerBridgeChurn: CI jobs and container
// workloads create and remove bridges constantly. Identity did not change, so
// the throttled report must not be re-sent — before this it went out every few
// minutes on a CI host instead of hourly.
func TestSelfObservationHash_IgnoresContainerBridgeChurn(t *testing.T) {
	before := dockerNodeHost()
	after := dockerNodeHost(
		sharednetwork.InterfaceAddress{InterfaceName: "br-5c3026f94607", Address: "172.21.0.1"},
		sharednetwork.InterfaceAddress{InterfaceName: "veth9a8b7c6", Address: ""},
	)
	if selfObservationHash(before) != selfObservationHash(after) {
		t.Fatal("hash changed when only container bridges came and went")
	}
	moved := dockerNodeHost()
	moved.Interfaces[1].Address = "10.1.0.11"
	if selfObservationHash(before) == selfObservationHash(moved) {
		t.Fatal("hash ignored a real NIC's address changing")
	}
}
