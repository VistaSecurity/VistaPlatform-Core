package deviceinterrogation

// The power sockets an interrogated device measured about itself (DCIM
// BUILD_PLAN row 6.2, ADR-0010 D9): a PDU's inlets with their total and
// per-leg load, and its outlets with each outlet's draw, current and switched
// state. Read over SNMP (snmp_power.go) from ENTITY-SENSOR-MIB, APC
// PowerNet-MIB, Raritan PDU2-MIB and EATON-EPDU-MIB.
//
// The wire form of identity.ObservedPowerPort / ObservedPowerOutlet
// (shared/identity/observed_power.go), spelled here with the same JSON names
// for the reason the network types are (this package is vendored into the
// standalone device agent). device-interrogation-service decodes it with
// unknown fields refused, so the two spellings cannot drift.
//
// Measured only, posture only: amps, watts, an on / off state, and the names
// the device gives its sockets. Every field is a typed projection of a MIB
// column the collector names; nothing a device returns is carried whole.

// ObservedPowerLeg mirrors identity.ObservedPowerLeg.
type ObservedPowerLeg struct {
	Leg             string   `json:"leg"`
	MeasuredDraw    *int     `json:"measured_draw,omitempty"`
	MeasuredCurrent *float64 `json:"measured_current,omitempty"`
}

// ObservedPowerPort mirrors identity.ObservedPowerPort.
type ObservedPowerPort struct {
	Name            string             `json:"name"`
	Number          int                `json:"number,omitempty"`
	MeasuredDraw    *int               `json:"measured_draw,omitempty"`
	MeasuredCurrent *float64           `json:"measured_current,omitempty"`
	Legs            []ObservedPowerLeg `json:"legs,omitempty"`
}

// ObservedPowerOutlet mirrors identity.ObservedPowerOutlet.
type ObservedPowerOutlet struct {
	Name            string   `json:"name"`
	Number          int      `json:"number,omitempty"`
	PowerPort       string   `json:"power_port,omitempty"`
	FeedLeg         string   `json:"feed_leg,omitempty"`
	State           string   `json:"state,omitempty"`
	MeasuredDraw    *int     `json:"measured_draw,omitempty"`
	MeasuredCurrent *float64 `json:"measured_current,omitempty"`
}

// maxPowerSockets bounds the ports and the outlets one interrogation reports.
const maxPowerSockets = 1024
