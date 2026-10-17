package services

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/vistasecurity/vistaplatform/sensor-manager/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/hostobs"
	sharednetwork "github.com/vistasecurity/vistaplatform/shared/network"
)

// TestSelfHostObservation_ReportsNamedInterfacesAndTheCaptureInterface pins
// DCIM row 1.5e's self-report: the sensor host's real interfaces travel by
// name with their MAC and configured addresses, container bridges stay out,
// and the interface the sensor captures on is flagged — on the interface and
// in the `capture_interfaces` attribute the asset's metadata keeps.
// Mutation: drop the Capture flag in selfInterfaceTable → red.
func TestSelfHostObservation_ReportsNamedInterfacesAndTheCaptureInterface(t *testing.T) {
	host := dockerNodeHost(sharednetwork.InterfaceAddress{InterfaceName: "enp2s0", Address: "2001:db8::10", PrefixLength: 64, MAC: "00:1a:2b:3c:4d:01"})
	host.Interfaces[0].PrefixLength = 24
	ho := selfHostObservation(selfObsSensorID, "linux", "", host, "wlp4s0")

	byName := map[string]hostobs.Interface{}
	var names []string
	for _, ifc := range ho.Interfaces {
		byName[ifc.Name] = ifc
		names = append(names, ifc.Name)
	}
	if !slices.Equal(names, []string{"enp2s0", "wlp4s0"}) {
		t.Fatalf("interfaces = %v, want the two real NICs and no container bridge", names)
	}
	if got := byName["enp2s0"]; got.MAC != "00:1a:2b:3c:4d:01" || !slices.Equal(got.Addresses, []string{"10.0.0.10/24", "2001:db8::10/64"}) || got.Capture {
		t.Errorf("enp2s0 = %+v", got)
	}
	if got := byName["wlp4s0"]; got.MAC != "00:1a:2b:3c:4d:02" || !slices.Equal(got.Addresses, []string{"10.1.0.10"}) || !got.Capture {
		t.Errorf("wlp4s0 = %+v, want the capture interface flagged", got)
	}
	if capture, _ := ho.Attributes[hostobs.AttrCaptureInterfaces].([]string); !slices.Equal(capture, []string{"wlp4s0"}) {
		t.Errorf("%s = %v, want [wlp4s0]", hostobs.AttrCaptureInterfaces, ho.Attributes[hostobs.AttrCaptureInterfaces])
	}

	// The table rides the discovery's raw metadata to inventory unchanged.
	blob, err := json.Marshal(selfObservationDiscovery(ho).RawMetadata["host_observation"])
	if err != nil {
		t.Fatal(err)
	}
	var back hostobs.HostObservation
	if err := json.Unmarshal(blob, &back); err != nil {
		t.Fatal(err)
	}
	if len(back.Interfaces) != 2 || !back.Interfaces[1].Capture {
		t.Errorf("interfaces did not survive the wire: %+v", back.Interfaces)
	}
}

// An older sensor reports addresses with no interface name: they stay unnamed
// addresses and no interface table is invented.
func TestSelfHostObservation_UnnamedRowsMakeNoInterfaceTable(t *testing.T) {
	host := &models.HostIdentity{Hostname: "old", Interfaces: []sharednetwork.InterfaceAddress{{Address: "10.0.0.2", MAC: "00:1a:2b:3c:4d:60"}}}
	ho := selfHostObservation(selfObsSensorID, "linux", "", host, "eth0")
	if len(ho.Interfaces) != 0 || ho.Attributes[hostobs.AttrCaptureInterfaces] != nil {
		t.Errorf("an unnamed report produced an interface table: %+v", ho.Interfaces)
	}
	if len(ho.Addresses) != 1 || ho.MAC != "00:1a:2b:3c:4d:60" {
		t.Errorf("the unnamed address and MAC were lost: %+v", ho)
	}
}
