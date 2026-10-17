package services

import (
	"testing"
	"time"

	"github.com/google/uuid"

	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// The hardware half of a collector's NetworkObservation (DCIM row 2.4) reaches
// the sighting field for field — decodeNetwork refuses a field one side lacks,
// so this also pins the two spellings together.
//
// Mutation: drop InventoryItems / VirtualChassis from snmpNetworkSighting →
// red.
func TestNetworkSighting_CarriesHardware(t *testing.T) {
	pri := 15
	n := &di.NetworkObservation{
		InventoryItems: []di.ObservedInventoryItem{{Name: "Te1/1/1", Role: "transceiver", Manufacturer: "Cisco Systems", PartID: "SFP-10G-SR",
			Serial: "AVD2201A001", Description: "SFP-10GBase-SR", Interface: "TenGigabitEthernet1/1/1", Parent: "x", AssetTag: "T1"}},
		Modules:        []di.ObservedModule{{Bay: "Network Module", PartID: "C9300-NM-8X", Serial: "FOC1", AssetTag: "T2"}},
		VirtualChassis: &di.ObservedVirtualChassis{Name: "c93xx Stack", Domain: "d", Members: []di.ObservedVirtualChassisMember{{Position: 1, Priority: &pri, Master: true, Serial: "FOC2432L0AB", Model: "C9300-48P"}, {Position: 2}}},
	}
	sg, err := snmpNetworkSighting(uuid.New(), identity.Source{Kind: "interrogation", Ref: "test"}, time.Now(),
		[]identity.SightedIdentifier{{Kind: identity.KindSerialNumber, Value: "FOC2432L0AB"}}, n)
	if err != nil {
		t.Fatal(err)
	}
	if len(sg.InventoryItems) != 1 || sg.InventoryItems[0] != (identity.ObservedInventoryItem{Name: "Te1/1/1", Parent: "x", Role: "transceiver",
		Manufacturer: "Cisco Systems", PartID: "SFP-10G-SR", Serial: "AVD2201A001", AssetTag: "T1", Description: "SFP-10GBase-SR", Interface: "TenGigabitEthernet1/1/1"}) {
		t.Errorf("items %+v", sg.InventoryItems)
	}
	if len(sg.Modules) != 1 || sg.Modules[0] != (identity.ObservedModule{Bay: "Network Module", PartID: "C9300-NM-8X", Serial: "FOC1", AssetTag: "T2"}) {
		t.Errorf("modules %+v", sg.Modules)
	}
	vc := sg.VirtualChassis
	if vc == nil || vc.Name != "c93xx Stack" || vc.Domain != "d" || len(vc.Members) != 2 || !vc.Members[0].Master ||
		vc.Members[0].Priority == nil || *vc.Members[0].Priority != 15 || vc.Members[0].Serial != "FOC2432L0AB" || vc.Members[0].Model != "C9300-48P" {
		t.Errorf("virtual chassis %+v", vc)
	}
}
