package services

import (
	"reflect"
	"testing"
	"time"

	"github.com/google/uuid"

	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// The virtual device contexts of a collector's NetworkObservation (DCIM gap
// 1) reach the sighting, with each interface's context — decodeNetwork
// refuses a field one side lacks, so this also pins the two spellings.
//
// Mutation: drop VirtualDeviceContexts from snmpNetworkSighting → red; drop
// the field from decodedNetwork → decodeNetwork refuses the observation.
func TestNetworkSighting_CarriesVirtualDeviceContexts(t *testing.T) {
	two := 2
	n := &di.NetworkObservation{
		Interfaces:            []di.ObservedInterface{{Name: "ethernet1/2", VirtualDeviceContext: "vsys2"}},
		VirtualDeviceContexts: []di.ObservedVirtualDeviceContext{{Name: "vsys2", Identifier: &two}, {Name: "root"}},
	}
	sg, err := snmpNetworkSighting(uuid.New(), identity.Source{Kind: identity.SourceMeasured, Ref: "interrogation:test"}, time.Now(),
		[]identity.SightedIdentifier{{Kind: identity.KindSerialNumber, Value: "PA-TEST-0001"}}, n)
	if err != nil {
		t.Fatal(err)
	}
	want := []identity.ObservedVirtualDeviceContext{{Name: "vsys2", Identifier: &two}, {Name: "root"}}
	if !reflect.DeepEqual(sg.VirtualDeviceContexts, want) {
		t.Errorf("contexts %+v, want %+v", sg.VirtualDeviceContexts, want)
	}
	if len(sg.Interfaces) != 1 || sg.Interfaces[0].VirtualDeviceContext != "vsys2" {
		t.Errorf("interfaces %+v, want ethernet1/2 in vsys2", sg.Interfaces)
	}
}
