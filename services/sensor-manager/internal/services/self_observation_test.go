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
