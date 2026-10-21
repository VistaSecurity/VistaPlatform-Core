package services

import (
	"testing"
	"time"

	"github.com/google/uuid"

	di "github.com/vistasecurity/vistaplatform/shared/deviceinterrogation"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// The power half of a collector's NetworkObservation (DCIM row 6.2) reaches
// the sighting field for field — decodeNetwork refuses a field one side lacks.
//
// Mutation: drop PowerOutlets from snmpNetworkSighting → red.
func TestNetworkSighting_CarriesPower(t *testing.T) {
	w, a := 1230, 2.1
	n := &di.NetworkObservation{
		PowerPorts: []di.ObservedPowerPort{{Name: "Input", Number: 1, MeasuredDraw: &w,
			Legs: []di.ObservedPowerLeg{{Leg: "A", MeasuredCurrent: &a, MeasuredDraw: &w}}}},
		PowerOutlets: []di.ObservedPowerOutlet{{Name: "Outlet 1", Number: 1, PowerPort: "Input", FeedLeg: "A", State: "on", MeasuredDraw: &w, MeasuredCurrent: &a}},
	}
	sg, err := snmpNetworkSighting(uuid.New(), identity.Source{Kind: "interrogation", Ref: "test"}, time.Now(),
		[]identity.SightedIdentifier{{Kind: identity.KindSerialNumber, Value: "SN-PDU-0001"}}, n)
	if err != nil {
		t.Fatal(err)
	}
	if len(sg.PowerPorts) != 1 || sg.PowerPorts[0].Name != "Input" || sg.PowerPorts[0].Number != 1 || *sg.PowerPorts[0].MeasuredDraw != 1230 ||
		len(sg.PowerPorts[0].Legs) != 1 || *sg.PowerPorts[0].Legs[0].MeasuredCurrent != 2.1 {
		t.Errorf("power ports %+v", sg.PowerPorts)
	}
	if len(sg.PowerOutlets) != 1 {
		t.Fatalf("power outlets %+v", sg.PowerOutlets)
	}
	o := sg.PowerOutlets[0]
	if o.Name != "Outlet 1" || o.Number != 1 || o.PowerPort != "Input" || o.FeedLeg != "A" || o.State != "on" || *o.MeasuredDraw != 1230 || *o.MeasuredCurrent != 2.1 {
		t.Errorf("outlet %+v", o)
	}
}

// A PDU that reported power sockets and no interface still posts a sighting;
// an ARP-only observation does not.
//
// Mutation: drop `|| n.HasPower()` from networkNeedsSighting → red.
func TestNetworkNeedsSighting_PowerOnly(t *testing.T) {
	w := 100
	if !networkNeedsSighting(&di.NetworkObservation{PowerOutlets: []di.ObservedPowerOutlet{{Name: "Outlet 1", MeasuredDraw: &w}}}) {
		t.Error("a power-only observation posts no sighting: its readings would never be recorded")
	}
	if networkNeedsSighting(&di.NetworkObservation{ARP: []di.ObservedARPEntry{{Address: "192.0.2.1", MAC: "00:00:5e:00:53:01"}}}) {
		t.Error("an ARP-only observation posts a sighting")
	}
}
