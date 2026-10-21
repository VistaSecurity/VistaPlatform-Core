package deviceinterrogation

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/deviceinterrogation/snmpfake"
)

// The PDU collectors (DCIM row 6.2), each driven end to end through the SNMP
// interrogator against a synthesised agent (snmpfake/pdu.go), then held to
// the posture rule: nothing but the named columns reaches the observation.

func powerOf(t *testing.T, rec snmpfake.Recording) ([]ObservedPowerPort, []ObservedPowerOutlet, *InterrogateResult) {
	t.Helper()
	r := snmpNetworkOf(t, rec)
	return r.Network.PowerPorts, r.Network.PowerOutlets, r
}

func wantPowerInt(t *testing.T, label string, got *int, want int) {
	t.Helper()
	if got == nil || *got != want {
		t.Errorf("%s = %v, want %d", label, derefPowerInt(got), want)
	}
}

func wantPowerAmps(t *testing.T, label string, got *float64, want float64) {
	t.Helper()
	if got == nil || *got != want {
		var v any = "nil"
		if got != nil {
			v = *got
		}
		t.Errorf("%s = %v, want %v", label, v, want)
	}
}

func derefPowerInt(p *int) any {
	if p == nil {
		return "nil"
	}
	return *p
}

// assertNoPlanted fails when a planted secret survived into the observation.
func assertNoPlantedPower(t *testing.T, label string, v any) {
	t.Helper()
	blob, _ := json.Marshal(v)
	for _, s := range []string{snmpfake.PDUCommunity, snmpfake.PDUSecret} {
		if strings.Contains(string(blob), s) {
			t.Errorf("%s: planted %q reached the observation: %s", label, s, blob)
		}
	}
}

// APC PowerNet-MIB: the inlet's total load from rPDU2DeviceStatusPower, the
// three phases as legs, the eight outlets of module 1 (module 2 ignored) with
// state, current and power, named by the operator's label where it has one.
//
// Mutation: drop the module filter on the switched table → nine outlets, red;
// read rPDU2DeviceStatusPower as watts (no ×10) → the draw assertion fails;
// swap off(1)/on(2) → the state assertions fail.
func TestSNMPPower_APC(t *testing.T) {
	ports, outlets, r := powerOf(t, snmpfake.APCRackPDU())
	assertNoPlantedPower(t, "apc", r.Network)
	if len(ports) != 1 || ports[0].Name != "Input" || ports[0].Number != 1 {
		t.Fatalf("ports %+v; want one Input", ports)
	}
	wantPowerInt(t, "inlet draw", ports[0].MeasuredDraw, 1230)
	if len(ports[0].Legs) != 3 || ports[0].Legs[0].Leg != "A" || ports[0].Legs[2].Leg != "C" {
		t.Fatalf("legs %+v", ports[0].Legs)
	}
	wantPowerAmps(t, "leg A current", ports[0].Legs[0].MeasuredCurrent, 2.1)
	wantPowerInt(t, "leg A draw", ports[0].Legs[0].MeasuredDraw, 450)
	if ports[0].MeasuredCurrent != nil {
		t.Errorf("a three-phase inlet's own current is not the sum of its legs: %v", *ports[0].MeasuredCurrent)
	}
	if len(outlets) != 8 {
		t.Fatalf("outlets %d; want 8 (module 2 ignored): %+v", len(outlets), outlets)
	}
	o1, o3, o8 := outlets[0], outlets[2], outlets[7]
	if o1.Name != "Outlet 1" || o1.Number != 1 || o1.State != "on" || o1.PowerPort != "Input" {
		t.Errorf("outlet 1 %+v", o1)
	}
	wantPowerAmps(t, "outlet 1 current", o1.MeasuredCurrent, 0.2)
	wantPowerInt(t, "outlet 1 draw", o1.MeasuredDraw, 40)
	if o3.State != "off" {
		t.Errorf("outlet 3 state %q, want off", o3.State)
	}
	wantPowerInt(t, "outlet 3 draw (off, measured 0)", o3.MeasuredDraw, 0)
	if o8.Name != "web-01 PSU A" || o8.Number != 8 {
		t.Errorf("outlet 8 %+v", o8)
	}
}

// Raritan PDU2-MIB: readings scaled by their decimal digits, the inlet named
// by its label when it has no user name, the three line poles as legs (the
// neutral ignored), outlet on / off from the onOff sensor's state.
//
// Mutation: ignore outletSensorDecimalDigits → outlet current 5 not 0.5, red;
// map pole 4 to a leg → four legs, red.
func TestSNMPPower_Raritan(t *testing.T) {
	ports, outlets, r := powerOf(t, snmpfake.RaritanPDU())
	assertNoPlantedPower(t, "raritan", r.Network)
	if len(ports) != 1 || ports[0].Name != "Inlet I1" || ports[0].Number != 1 {
		t.Fatalf("ports %+v", ports)
	}
	wantPowerInt(t, "inlet draw", ports[0].MeasuredDraw, 1834)
	wantPowerAmps(t, "inlet current", ports[0].MeasuredCurrent, 9.11)
	if len(ports[0].Legs) != 3 {
		t.Fatalf("legs %+v; want L1-L3", ports[0].Legs)
	}
	wantPowerAmps(t, "leg C current", ports[0].Legs[2].MeasuredCurrent, 2.91)
	wantPowerInt(t, "leg B draw", ports[0].Legs[1].MeasuredDraw, 600)
	if len(outlets) != 6 {
		t.Fatalf("outlets %+v", outlets)
	}
	if outlets[0].Name != "Outlet 1" || outlets[1].Name != "db-02 PSU1" || outlets[0].PowerPort != "Inlet I1" {
		t.Errorf("names %q %q, power port %q", outlets[0].Name, outlets[1].Name, outlets[0].PowerPort)
	}
	wantPowerAmps(t, "outlet 1 current", outlets[0].MeasuredCurrent, 0.5)
	wantPowerInt(t, "outlet 3 draw", outlets[2].MeasuredDraw, 300)
	if outlets[0].State != "on" || outlets[4].State != "off" {
		t.Errorf("states %q / %q", outlets[0].State, outlets[4].State)
	}
}

// Eaton EATON-EPDU-MIB: strapping index 1 only, the input's feed name, total
// power, per-phase current (mA) and power as legs, outlet control status read
// as the outlet's present state, a negative outletWatts as not measured.
//
// Mutation: read strapping 2 as well → Feed B and a fifth outlet, red; treat
// outletWatts -1 as a reading → outlet 4's draw assertion fails.
func TestSNMPPower_Eaton(t *testing.T) {
	ports, outlets, r := powerOf(t, snmpfake.EatonEPDU())
	assertNoPlantedPower(t, "eaton", r.Network)
	if len(ports) != 1 || ports[0].Name != "Feed A" {
		t.Fatalf("ports %+v; want Feed A only", ports)
	}
	wantPowerInt(t, "input draw", ports[0].MeasuredDraw, 2100)
	if len(ports[0].Legs) != 3 {
		t.Fatalf("legs %+v", ports[0].Legs)
	}
	wantPowerAmps(t, "leg A current", ports[0].Legs[0].MeasuredCurrent, 3.1)
	wantPowerInt(t, "leg C draw", ports[0].Legs[2].MeasuredDraw, 710)
	if len(outlets) != 4 {
		t.Fatalf("outlets %+v", outlets)
	}
	wantPowerAmps(t, "outlet 2 current", outlets[1].MeasuredCurrent, 0.5)
	if outlets[1].State != "off" || outlets[3].State != "on" {
		t.Errorf("states: outlet 2 %q (want off), outlet 4 %q (pendingOff is still on)", outlets[1].State, outlets[3].State)
	}
	if outlets[3].MeasuredDraw != nil {
		t.Errorf("outletWatts -1 is not a reading, got %d", *outlets[3].MeasuredDraw)
	}
	if outlets[0].PowerPort != "Feed A" {
		t.Errorf("an outlet of a single-input PDU draws from it: %+v", outlets[0])
	}
}

// ENTITY-SENSOR-MIB: a power supply with watts / amperes sensors is a power
// port carrying the reading (milli scale applied); a temperature sensor and a
// power supply whose sensors are not operating report nothing.
//
// Mutation: ignore entPhySensorOperStatus → PSU 3 appears, red; ignore the
// scale → 950 A, red.
func TestSNMPPower_EntitySensors(t *testing.T) {
	ports, outlets, r := powerOf(t, snmpfake.ServerWithPSUSensors())
	assertNoPlantedPower(t, "entity sensors", r.Network)
	if len(outlets) != 0 {
		t.Errorf("a server has no outlets: %+v", outlets)
	}
	if len(ports) != 2 || ports[0].Name != "PSU 1" || ports[1].Name != "PSU 2" {
		t.Fatalf("ports %+v; want PSU 1 and PSU 2", ports)
	}
	wantPowerInt(t, "PSU 1 draw", ports[0].MeasuredDraw, 212)
	wantPowerAmps(t, "PSU 2 current", ports[1].MeasuredCurrent, 0.88)
}

// A switch (L3Switch48) is no PDU and has no power sensors: no power sockets.
func TestSNMPPower_SwitchReportsNone(t *testing.T) {
	r := snmpNetworkOf(t, snmpfake.L3Switch48())
	if r.Network.HasPower() {
		t.Errorf("a switch with no power sensors reported power sockets: %+v %+v", r.Network.PowerPorts, r.Network.PowerOutlets)
	}
}

// The projection allowlist, structurally: drive each vendor path with a walk
// that answers EVERY column with a planted value, and record what was asked.
// The collector may ask only for its named columns (snmpPowerColumns and the
// entPhysicalTable columns the hardware already reads), and no planted text
// may come back in anything but a socket name.
//
// Mutation: walk an extra PowerNet-MIB column (e.g. the outlet external link)
// in apcPower → the "walked a column outside the allowlist" assertion fails.
func TestSNMPPower_WalksOnlyTheNamedColumns(t *testing.T) {
	allowed := map[string]bool{snmpOIDEntPhysicalClass: true, snmpOIDEntPhysicalContainedIn: true, snmpOIDEntPhysicalName: true}
	for oid := range snmpPowerColumns {
		allowed[oid] = true
	}
	for _, sys := range []string{"1.3.6.1.4.1.318.1.3.4.6", "1.3.6.1.4.1.13742.6", "1.3.6.1.4.1.534.6.6.7", "1.3.6.1.4.1.674.10892.5"} {
		var asked []string
		walk := func(col string) map[string]snmpVarBind {
			asked = append(asked, col)
			return map[string]snmpVarBind{"1.1": {Tag: snmpTagOctetString, Raw: []byte(snmpfake.PDUSecret)}}
		}
		ports, outlets := snmpPower(walk, sys)
		for _, col := range asked {
			if !allowed[col] {
				t.Errorf("%s: walked a column outside the allowlist: %s", sys, col)
			}
		}
		for _, p := range ports {
			if p.MeasuredDraw != nil || p.MeasuredCurrent != nil || len(p.Legs) > 0 {
				t.Errorf("%s: text answers became a reading: %+v", sys, p)
			}
		}
		for _, o := range outlets {
			if o.State != "" || o.MeasuredDraw != nil || o.MeasuredCurrent != nil {
				t.Errorf("%s: text answers became a reading: %+v", sys, o)
			}
		}
	}
}

// The power sockets a collector set before the interface table was projected
// survive the projection (setNetwork), and the sanitiser runs the value rules
// over their device-given names.
//
// Mutations: drop the PowerPorts/PowerOutlets carry in setNetwork → red; drop
// the power names from sanitizeNetwork → the planted secret survives, red.
func TestSNMPPower_SurvivesProjectionAndSanitiser(t *testing.T) {
	w := 40
	r := &InterrogateResult{Network: &NetworkObservation{
		PowerPorts:   []ObservedPowerPort{{Name: "Input", Number: 1}},
		PowerOutlets: []ObservedPowerOutlet{{Name: "https://pdu/?key=" + snmpfake.PDUSecret, Number: 1, PowerPort: "Input", MeasuredDraw: &w}},
	}}
	r.setNetwork(&vendorNetwork{Interfaces: []netIface{{Name: "eth0"}}}, "test")
	if r.Network == nil || len(r.Network.PowerPorts) != 1 || len(r.Network.PowerOutlets) != 1 {
		t.Fatalf("the projection dropped the power sockets: %+v", r.Network)
	}
	sanitizeNetwork(r.Network)
	assertNoPlantedPower(t, "sanitised", r.Network)
	if o := r.Network.PowerOutlets[0]; o.PowerPort != "Input" || o.MeasuredDraw == nil || *o.MeasuredDraw != 40 {
		t.Errorf("sanitiser changed the reading: %+v", o)
	}
}
