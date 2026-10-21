package identity

import (
	"fmt"
	"math"
	"strings"
)

// The power half of the intake seam (DCIM BUILD_PLAN row 6.2, ADR-0010 D9):
// what a PDU collector measured of a device's power sockets — its inlets
// (power ports: the total and per-leg load) and its outlets (each outlet's
// draw, current and switched state) — read over SNMP from ENTITY-SENSOR-MIB,
// APC PowerNet-MIB, Raritan PDU2-MIB or EATON-EPDU-MIB. Like the hardware
// (observed_hardware.go), none of it is identity: the engine never reads it,
// and inventory-service writes it on the engine's transaction once the
// sighting resolved to an asset (power_intake.go UpsertObservedPower).
//
// Measured only. A collector never reports a declared draw: allocated_draw
// and maximum_draw belong to a person or the NetBox sync
// (standards/sync-authority.yaml power_port: peer), so a reading lands in the
// measured_* columns beside them. Posture only: names, amps, watts and an
// on / off state; nothing here can carry a credential.

// ObservedPowerLeg is one leg (phase) of a three-phase inlet.
type ObservedPowerLeg struct {
	// Leg is A, B or C (NetBox PowerOutletFeedLegChoices).
	Leg string `json:"leg"`
	// MeasuredDraw is the leg's active power in watts; nil when not metered.
	MeasuredDraw *int `json:"measured_draw,omitempty"`
	// MeasuredCurrent is the leg's RMS current in amps; nil when not metered.
	MeasuredCurrent *float64 `json:"measured_current,omitempty"`
}

// ObservedPowerPort is a power port (a PDU inlet, a power supply) a collector
// measured.
type ObservedPowerPort struct {
	// Name as the device names it ("Inlet I1", "Input 1"); 1-64 characters,
	// the port's identity on its asset.
	Name string `json:"name"`
	// Number is the port's position on the device (the inlet index), 0 when
	// the device gives none. A port not found by name is matched by it: a
	// device type names its inlet "Power Port 1", the PDU "Input".
	Number int `json:"number,omitempty"`
	// MeasuredDraw is the total active power through the port in watts.
	MeasuredDraw *int `json:"measured_draw,omitempty"`
	// MeasuredCurrent is the total RMS current in amps.
	MeasuredCurrent *float64 `json:"measured_current,omitempty"`
	// Legs are a three-phase inlet's per-leg readings.
	Legs []ObservedPowerLeg `json:"legs,omitempty"`
}

// ObservedPowerOutlet is a power outlet a collector measured.
type ObservedPowerOutlet struct {
	// Name as the device names it ("Outlet 3", "web-01 PSU A"); 1-64
	// characters, the outlet's identity on its asset.
	Name string `json:"name"`
	// Number is the outlet's position on the device (1-based), 0 when the
	// device gives none; an outlet not found by name is matched by it.
	Number int `json:"number,omitempty"`
	// PowerPort names the observation's power port the outlet draws from
	// (the PDU's inlet); empty when the device does not say.
	PowerPort string `json:"power_port,omitempty"`
	// FeedLeg is the leg of a three-phase inlet the outlet is on (A, B, C).
	FeedLeg string `json:"feed_leg,omitempty"`
	// State is the outlet's switched state, on or off; empty for an outlet
	// the device does not switch.
	State string `json:"state,omitempty"`
	// MeasuredDraw is the outlet's active power in watts.
	MeasuredDraw *int `json:"measured_draw,omitempty"`
	// MeasuredCurrent is the outlet's RMS current in amps.
	MeasuredCurrent *float64 `json:"measured_current,omitempty"`
}

// maxObservedPowerSockets bounds one sighting's ports and outlets: the
// largest rack PDUs have a few dozen outlets, a chained set a few hundred.
const maxObservedPowerSockets = 1024

// Bounds on a reading (the schema holds watts in an integer and amps in
// numeric(8,2)): anything outside is a misread, dropped, never clamped.
const (
	maxMeasuredWatts = 10_000_000
	maxMeasuredAmps  = 999_999.99
)

func validLeg(s string) bool { return s == "A" || s == "B" || s == "C" }

func boundNumber(n int) int {
	if n < 1 || n > maxObservedPowerSockets {
		return 0
	}
	return n
}

func boundWatts(w *int) *int {
	if w == nil || *w < 0 || *w > maxMeasuredWatts {
		return nil
	}
	v := *w
	return &v
}

func boundAmps(a *float64) *float64 {
	if a == nil || math.IsNaN(*a) || math.IsInf(*a, 0) || *a < 0 || *a > maxMeasuredAmps {
		return nil
	}
	v := math.Round(*a*100) / 100
	return &v
}

// NormalizeObservedPower canonicalises a sighting's power sockets: names
// trimmed and bounded, duplicates (by name) kept once, an outlet's power port
// kept only when the observation lists a port of that name, legs and states
// outside NetBox's / the schema's lists dropped, readings outside what the
// schema can hold dropped. What could not be held is reported.
func NormalizeObservedPower(ports []ObservedPowerPort, outlets []ObservedPowerOutlet) ([]ObservedPowerPort, []ObservedPowerOutlet, []string) {
	var dropped []string
	name := func(kind, raw string) (string, bool) {
		n := strings.TrimSpace(raw)
		if n == "" || len(n) > 64 {
			dropped = append(dropped, fmt.Sprintf("%s %q: a name is 1-64 characters", kind, raw))
			return "", false
		}
		return n, true
	}
	var outP []ObservedPowerPort
	portNames := map[string]bool{}
	for _, raw := range ports {
		n, ok := name("power port", raw.Name)
		if !ok || portNames[n] {
			continue
		}
		if len(outP) == maxObservedPowerSockets {
			dropped = append(dropped, fmt.Sprintf("power ports beyond %d not recorded", maxObservedPowerSockets))
			break
		}
		portNames[n] = true
		p := ObservedPowerPort{Name: n, Number: boundNumber(raw.Number), MeasuredDraw: boundWatts(raw.MeasuredDraw), MeasuredCurrent: boundAmps(raw.MeasuredCurrent)}
		legs := map[string]bool{}
		for _, l := range raw.Legs {
			leg := strings.ToUpper(strings.TrimSpace(l.Leg))
			if !validLeg(leg) || legs[leg] {
				continue
			}
			legs[leg] = true
			nl := ObservedPowerLeg{Leg: leg, MeasuredDraw: boundWatts(l.MeasuredDraw), MeasuredCurrent: boundAmps(l.MeasuredCurrent)}
			if nl.MeasuredDraw != nil || nl.MeasuredCurrent != nil {
				p.Legs = append(p.Legs, nl)
			}
		}
		outP = append(outP, p)
	}
	var outO []ObservedPowerOutlet
	seen := map[string]bool{}
	for _, raw := range outlets {
		n, ok := name("power outlet", raw.Name)
		if !ok || seen[n] {
			continue
		}
		if len(outO) == maxObservedPowerSockets {
			dropped = append(dropped, fmt.Sprintf("power outlets beyond %d not recorded", maxObservedPowerSockets))
			break
		}
		seen[n] = true
		o := ObservedPowerOutlet{Name: n, Number: boundNumber(raw.Number), MeasuredDraw: boundWatts(raw.MeasuredDraw), MeasuredCurrent: boundAmps(raw.MeasuredCurrent)}
		if pp := strings.TrimSpace(raw.PowerPort); portNames[pp] {
			o.PowerPort = pp
		}
		if leg := strings.ToUpper(strings.TrimSpace(raw.FeedLeg)); validLeg(leg) {
			o.FeedLeg = leg
		}
		if st := strings.ToLower(strings.TrimSpace(raw.State)); st == "on" || st == "off" {
			o.State = st
		}
		outO = append(outO, o)
	}
	return outP, outO, dropped
}
