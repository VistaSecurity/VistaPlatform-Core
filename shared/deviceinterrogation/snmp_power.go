package deviceinterrogation

// The PDU collectors (DCIM BUILD_PLAN row 6.2, ADR-0010 D9): what an SNMP
// agent measures of the device's power sockets, projected onto
// [ObservedPowerPort] / [ObservedPowerOutlet] and filed by
// device-interrogation-service through the identity engine with the rest of
// the network observation. Nothing here writes; a reading never becomes a
// declared draw (see shared/identity/observed_power.go).
//
// Four sources, chosen by the agent's sysObjectID enterprise (an IANA
// registry, not a guess), the generic one for every other agent:
//
//	APC PowerNet-MIB (318)      rPDU2DeviceStatusTable  the PDU's total load (hundredths of kW)
//	                            rPDU2PhaseStatusTable   per-phase current (tenths of A) and load
//	                            rPDU2OutletSwitchedStatusTable  outlet name, number, on / off
//	                            rPDU2OutletMeteredStatusTable   outlet current (tenths of A), power (W)
//	Raritan PDU2-MIB (13742)    inletConfigurationTable / outletConfigurationTable  labels and names
//	                            inlet / inletPole / outlet SensorMeasurementsTable  rmsCurrent, activePower,
//	                            onOff, each scaled by its *SensorDecimalDigits
//	Eaton EATON-EPDU-MIB (534)  inputTable / inputCurrentTable / inputPowerTable / inputTotalPowerTable
//	                            outletTable / outletCurrentTable (mA) / outletPowerTable (W) / outletControlTable
//	ENTITY-SENSOR-MIB (generic) entPhySensorTable watts / amperes sensors inside an
//	                            entPhysicalClass powerSupply(6) entity: a power supply's draw
//
// Only the first unit of a daisy-chained set is read (APC module 1, Raritan
// PDU 1, Eaton strapping index 1): a chained unit is its own device, and one
// asset's sockets cannot carry two units' "Outlet 1".
//
// Posture only. Only the columns below are walked; a user-defined label is
// carried as the socket's name (bounded, value-redacted by sanitizeNetwork),
// and nothing else a PDU reports — its contact, location, user accounts or
// the community the session used — is read at all.

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
)

// Enterprise arcs of the PDU vendors.
const (
	snmpEnterpriseAPC     = "1.3.6.1.4.1.318."
	snmpEnterpriseRaritan = "1.3.6.1.4.1.13742."
	snmpEnterpriseEaton   = "1.3.6.1.4.1.534."
)

// APC PowerNet-MIB rPDU2 (1.3.6.1.4.1.318.1.1.26).
const (
	snmpOIDAPCDeviceModule = "1.3.6.1.4.1.318.1.1.26.4.3.1.2"
	snmpOIDAPCDevicePower  = "1.3.6.1.4.1.318.1.1.26.4.3.1.5" // hundredths of kW
	snmpOIDAPCPhaseModule  = "1.3.6.1.4.1.318.1.1.26.6.3.1.2"
	snmpOIDAPCPhaseNumber  = "1.3.6.1.4.1.318.1.1.26.6.3.1.3"
	snmpOIDAPCPhaseCurrent = "1.3.6.1.4.1.318.1.1.26.6.3.1.5" // tenths of A
	snmpOIDAPCPhasePower   = "1.3.6.1.4.1.318.1.1.26.6.3.1.7" // hundredths of kW
	snmpOIDAPCSwModule     = "1.3.6.1.4.1.318.1.1.26.9.2.3.1.2"
	snmpOIDAPCSwName       = "1.3.6.1.4.1.318.1.1.26.9.2.3.1.3"
	snmpOIDAPCSwNumber     = "1.3.6.1.4.1.318.1.1.26.9.2.3.1.4"
	snmpOIDAPCSwState      = "1.3.6.1.4.1.318.1.1.26.9.2.3.1.5" // off(1), on(2)
	snmpOIDAPCMtModule     = "1.3.6.1.4.1.318.1.1.26.9.4.3.1.2"
	snmpOIDAPCMtName       = "1.3.6.1.4.1.318.1.1.26.9.4.3.1.3"
	snmpOIDAPCMtNumber     = "1.3.6.1.4.1.318.1.1.26.9.4.3.1.4"
	snmpOIDAPCMtCurrent    = "1.3.6.1.4.1.318.1.1.26.9.4.3.1.6" // tenths of A
	snmpOIDAPCMtPower      = "1.3.6.1.4.1.318.1.1.26.9.4.3.1.7" // W
)

// Raritan PDU2-MIB (1.3.6.1.4.1.13742.6).
const (
	snmpOIDRaritanInletLabel        = "1.3.6.1.4.1.13742.6.3.3.3.1.2" // (pdu, inlet)
	snmpOIDRaritanInletName         = "1.3.6.1.4.1.13742.6.3.3.3.1.3"
	snmpOIDRaritanInletDigits       = "1.3.6.1.4.1.13742.6.3.3.4.1.7" // (pdu, inlet, sensorType)
	snmpOIDRaritanInletValue        = "1.3.6.1.4.1.13742.6.5.2.3.1.4"
	snmpOIDRaritanInletPoleDigits   = "1.3.6.1.4.1.13742.6.3.3.6.1.7" // (pdu, inlet, pole, sensorType)
	snmpOIDRaritanInletPoleValue    = "1.3.6.1.4.1.13742.6.5.2.4.1.4"
	snmpOIDRaritanOutletLabel       = "1.3.6.1.4.1.13742.6.3.5.3.1.2" // (pdu, outlet)
	snmpOIDRaritanOutletName        = "1.3.6.1.4.1.13742.6.3.5.3.1.3"
	snmpOIDRaritanOutletDigits      = "1.3.6.1.4.1.13742.6.3.5.4.1.7" // (pdu, outlet, sensorType)
	snmpOIDRaritanOutletSensorState = "1.3.6.1.4.1.13742.6.5.4.3.1.3"
	snmpOIDRaritanOutletSensorValue = "1.3.6.1.4.1.13742.6.5.4.3.1.4"
	raritanSensorRMSCurrent         = 1
	raritanSensorActivePower        = 5
	raritanSensorOnOff              = 14
	raritanStateOn, raritanStateOff = 7, 8
	raritanMaxDecimalDigits         = 6
	raritanLinePoles                = 3 // L1-L3; pole 4 is the neutral
)

// Eaton EATON-EPDU-MIB (1.3.6.1.4.1.534.6.6.7).
const (
	snmpOIDEatonInputFeedName  = "1.3.6.1.4.1.534.6.6.7.3.1.1.10" // (strap, input)
	snmpOIDEatonInputCurType   = "1.3.6.1.4.1.534.6.6.7.3.3.1.2"  // (strap, input, idx)
	snmpOIDEatonInputCurrent   = "1.3.6.1.4.1.534.6.6.7.3.3.1.3"  // mA
	snmpOIDEatonInputPowerType = "1.3.6.1.4.1.534.6.6.7.3.4.1.2"
	snmpOIDEatonInputWatts     = "1.3.6.1.4.1.534.6.6.7.3.4.1.3"
	snmpOIDEatonInputTotalW    = "1.3.6.1.4.1.534.6.6.7.3.5.1.4" // (strap, input)
	snmpOIDEatonOutletName     = "1.3.6.1.4.1.534.6.6.7.6.1.1.3" // (strap, outlet)
	snmpOIDEatonOutletCurrent  = "1.3.6.1.4.1.534.6.6.7.6.4.1.3" // mA
	snmpOIDEatonOutletWatts    = "1.3.6.1.4.1.534.6.6.7.6.5.1.3" // W, negative = not available
	snmpOIDEatonOutletControl  = "1.3.6.1.4.1.534.6.6.7.6.6.1.2" // off(0) on(1) pendingOff(2) pendingOn(3)
)

// ENTITY-SENSOR-MIB entPhySensorTable (RFC 3433), indexed by entPhysicalIndex.
const (
	snmpOIDEntPhySensorType      = "1.3.6.1.2.1.99.1.1.1.1"
	snmpOIDEntPhySensorScale     = "1.3.6.1.2.1.99.1.1.1.2"
	snmpOIDEntPhySensorPrecision = "1.3.6.1.2.1.99.1.1.1.3"
	snmpOIDEntPhySensorValue     = "1.3.6.1.2.1.99.1.1.1.4"
	snmpOIDEntPhySensorOper      = "1.3.6.1.2.1.99.1.1.1.5"
	entSensorAmperes             = 5
	entSensorWatts               = 6
	entSensorScaleUnits          = 9 // SensorDataScale units(9); milli(8), kilo(10) …
	entSensorOperOK              = 1
	entClassPowerSupply          = 6
)

// snmpPowerColumns are every column the PDU collectors walk, by source: the
// allowlist the projection test holds them to, and the warning names.
var snmpPowerColumns = map[string]string{
	snmpOIDAPCDeviceModule: "PowerNet-MIB::rPDU2DeviceStatusModule", snmpOIDAPCDevicePower: "PowerNet-MIB::rPDU2DeviceStatusPower",
	snmpOIDAPCPhaseModule: "PowerNet-MIB::rPDU2PhaseStatusModule", snmpOIDAPCPhaseNumber: "PowerNet-MIB::rPDU2PhaseStatusNumber",
	snmpOIDAPCPhaseCurrent: "PowerNet-MIB::rPDU2PhaseStatusCurrent", snmpOIDAPCPhasePower: "PowerNet-MIB::rPDU2PhaseStatusPower",
	snmpOIDAPCSwModule: "PowerNet-MIB::rPDU2OutletSwitchedStatusModule", snmpOIDAPCSwName: "PowerNet-MIB::rPDU2OutletSwitchedStatusName",
	snmpOIDAPCSwNumber: "PowerNet-MIB::rPDU2OutletSwitchedStatusNumber", snmpOIDAPCSwState: "PowerNet-MIB::rPDU2OutletSwitchedStatusState",
	snmpOIDAPCMtModule: "PowerNet-MIB::rPDU2OutletMeteredStatusModule", snmpOIDAPCMtName: "PowerNet-MIB::rPDU2OutletMeteredStatusName",
	snmpOIDAPCMtNumber: "PowerNet-MIB::rPDU2OutletMeteredStatusNumber", snmpOIDAPCMtCurrent: "PowerNet-MIB::rPDU2OutletMeteredStatusCurrent",
	snmpOIDAPCMtPower: "PowerNet-MIB::rPDU2OutletMeteredStatusPower",

	snmpOIDRaritanInletLabel: "PDU2-MIB::inletLabel", snmpOIDRaritanInletName: "PDU2-MIB::inletName",
	snmpOIDRaritanInletDigits: "PDU2-MIB::inletSensorDecimalDigits", snmpOIDRaritanInletValue: "PDU2-MIB::measurementsInletSensorValue",
	snmpOIDRaritanInletPoleDigits: "PDU2-MIB::inletPoleSensorDecimalDigits", snmpOIDRaritanInletPoleValue: "PDU2-MIB::measurementsInletPoleSensorValue",
	snmpOIDRaritanOutletLabel: "PDU2-MIB::outletLabel", snmpOIDRaritanOutletName: "PDU2-MIB::outletName",
	snmpOIDRaritanOutletDigits: "PDU2-MIB::outletSensorDecimalDigits", snmpOIDRaritanOutletSensorState: "PDU2-MIB::measurementsOutletSensorState",
	snmpOIDRaritanOutletSensorValue: "PDU2-MIB::measurementsOutletSensorValue",

	snmpOIDEatonInputFeedName: "EATON-EPDU-MIB::inputFeedName", snmpOIDEatonInputCurType: "EATON-EPDU-MIB::inputCurrentMeasType",
	snmpOIDEatonInputCurrent: "EATON-EPDU-MIB::inputCurrent", snmpOIDEatonInputPowerType: "EATON-EPDU-MIB::inputPowerMeasType",
	snmpOIDEatonInputWatts: "EATON-EPDU-MIB::inputWatts", snmpOIDEatonInputTotalW: "EATON-EPDU-MIB::inputTotalWatts",
	snmpOIDEatonOutletName: "EATON-EPDU-MIB::outletName", snmpOIDEatonOutletCurrent: "EATON-EPDU-MIB::outletCurrent",
	snmpOIDEatonOutletWatts: "EATON-EPDU-MIB::outletWatts", snmpOIDEatonOutletControl: "EATON-EPDU-MIB::outletControlStatus",

	snmpOIDEntPhySensorType: "ENTITY-SENSOR-MIB::entPhySensorType", snmpOIDEntPhySensorScale: "ENTITY-SENSOR-MIB::entPhySensorScale",
	snmpOIDEntPhySensorPrecision: "ENTITY-SENSOR-MIB::entPhySensorPrecision", snmpOIDEntPhySensorValue: "ENTITY-SENSOR-MIB::entPhySensorValue",
	snmpOIDEntPhySensorOper: "ENTITY-SENSOR-MIB::entPhySensorOperStatus",
}

func init() {
	for oid, name := range snmpPowerColumns {
		snmpColumnNames[oid] = name
	}
}

// snmpPower reads the device's power sockets for its sysObjectID. The generic
// ENTITY-SENSOR path also needs entPhysicalClass / entPhysicalName /
// entPhysicalContainedIn (already walked for the hardware).
func snmpPower(walk func(string) map[string]snmpVarBind, sysObjectID string) ([]ObservedPowerPort, []ObservedPowerOutlet) {
	var ports []ObservedPowerPort
	var outlets []ObservedPowerOutlet
	switch {
	case strings.HasPrefix(sysObjectID, snmpEnterpriseAPC):
		ports, outlets = apcPower(walk)
	case strings.HasPrefix(sysObjectID, snmpEnterpriseRaritan):
		ports, outlets = raritanPower(walk)
	case strings.HasPrefix(sysObjectID, snmpEnterpriseEaton):
		ports, outlets = eatonPower(walk)
	default:
		ports = entitySensorPower(walk)
	}
	if len(ports) > maxPowerSockets {
		ports = ports[:maxPowerSockets]
	}
	if len(outlets) > maxPowerSockets {
		outlets = outlets[:maxPowerSockets]
	}
	return ports, outlets
}

// ---------------------------------------------------------------------------
// helpers

func floatPtr(f float64) *float64 {
	v := math.Round(f*100) / 100
	return &v
}

// bindInt is a column's integer at index, false when absent or not an integer.
func bindInt(col map[string]snmpVarBind, index string) (int64, bool) {
	b, ok := col[index]
	if !ok || b.IsException() {
		return 0, false
	}
	return b.Int()
}

func bindText(col map[string]snmpVarBind, index string) string {
	b, ok := col[index]
	if !ok {
		return ""
	}
	return strings.TrimSpace(b.Text())
}

// indexParts splits a table index ("1.3.5") into its integers; nil when a
// part is not a number.
func indexParts(index string) []int64 {
	var out []int64
	for _, p := range strings.Split(index, ".") {
		n, err := strconv.ParseInt(p, 10, 64)
		if err != nil {
			return nil
		}
		out = append(out, n)
	}
	return out
}

// legName is the NetBox feed leg of phase / pole n (1-3), "" otherwise.
func legName(n int64) string {
	switch n {
	case 1:
		return "A"
	case 2:
		return "B"
	case 3:
		return "C"
	}
	return ""
}

func sortOutlets(outlets []ObservedPowerOutlet) {
	sort.SliceStable(outlets, func(i, j int) bool {
		if outlets[i].Number != outlets[j].Number {
			return outlets[i].Number < outlets[j].Number
		}
		return outlets[i].Name < outlets[j].Name
	})
}

// ---------------------------------------------------------------------------
// APC PowerNet-MIB

// apcInput names the one power port of an APC rack PDU (module 1): the MIB has
// no inlet table, and the device type names it "Power Port 1".
const apcInput = "Input"

func apcPower(walk func(string) map[string]snmpVarBind) ([]ObservedPowerPort, []ObservedPowerOutlet) {
	port := ObservedPowerPort{Name: apcInput, Number: 1}
	found := false
	devModule := walk(snmpOIDAPCDeviceModule)
	for idx, b := range walk(snmpOIDAPCDevicePower) {
		if m, ok := bindInt(devModule, idx); ok && m != 1 {
			continue
		}
		if v, ok := b.Int(); ok && v >= 0 {
			port.MeasuredDraw = intPtr(int(v * 10)) // hundredths of kW → W
			found = true
		}
	}
	phModule, phNumber, phPower := walk(snmpOIDAPCPhaseModule), walk(snmpOIDAPCPhaseNumber), walk(snmpOIDAPCPhasePower)
	type phase struct {
		n          int64
		amps, watt *float64
	}
	var phases []phase
	for idx, b := range walk(snmpOIDAPCPhaseCurrent) {
		if m, ok := bindInt(phModule, idx); ok && m != 1 {
			continue
		}
		p := phase{}
		p.n, _ = bindInt(phNumber, idx)
		if v, ok := b.Int(); ok && v >= 0 {
			p.amps = floatPtr(float64(v) / 10)
		}
		if v, ok := bindInt(phPower, idx); ok && v >= 0 {
			p.watt = floatPtr(float64(v) * 10)
		}
		phases = append(phases, p)
	}
	sort.Slice(phases, func(i, j int) bool { return phases[i].n < phases[j].n })
	switch {
	case len(phases) == 1:
		port.MeasuredCurrent = phases[0].amps
		found = found || phases[0].amps != nil
	case len(phases) > 1:
		have := false
		for _, p := range phases {
			leg := legName(p.n)
			if leg == "" {
				continue
			}
			l := ObservedPowerLeg{Leg: leg, MeasuredCurrent: p.amps}
			if p.watt != nil {
				l.MeasuredDraw = intPtr(int(*p.watt))
			}
			have = have || p.amps != nil || p.watt != nil
			port.Legs = append(port.Legs, l)
		}
		// A three-phase inlet's current is per leg; their sum is not a line
		// current, so the port's own current stays unset.
		found = found || have
	}

	swModule, swName, swNumber := walk(snmpOIDAPCSwModule), walk(snmpOIDAPCSwName), walk(snmpOIDAPCSwNumber)
	mtModule, mtName, mtNumber, mtPower := walk(snmpOIDAPCMtModule), walk(snmpOIDAPCMtName), walk(snmpOIDAPCMtNumber), walk(snmpOIDAPCMtPower)
	byNumber := map[int64]*ObservedPowerOutlet{}
	outlet := func(n int64, name string) *ObservedPowerOutlet {
		if o, ok := byNumber[n]; ok {
			if o.Name == "" {
				o.Name = name
			}
			return o
		}
		o := &ObservedPowerOutlet{Number: int(n), Name: name, PowerPort: apcInput}
		byNumber[n] = o
		return o
	}
	for idx, b := range walk(snmpOIDAPCSwState) {
		if m, ok := bindInt(swModule, idx); ok && m != 1 {
			continue
		}
		n, ok := bindInt(swNumber, idx)
		if !ok || n < 1 {
			continue
		}
		o := outlet(n, bindText(swName, idx))
		switch v, _ := b.Int(); v {
		case 1:
			o.State = "off"
		case 2:
			o.State = "on"
		}
	}
	for idx, b := range walk(snmpOIDAPCMtCurrent) {
		if m, ok := bindInt(mtModule, idx); ok && m != 1 {
			continue
		}
		n, ok := bindInt(mtNumber, idx)
		if !ok || n < 1 {
			continue
		}
		o := outlet(n, bindText(mtName, idx))
		if v, ok := b.Int(); ok && v >= 0 {
			o.MeasuredCurrent = floatPtr(float64(v) / 10)
		}
		if v, ok := bindInt(mtPower, idx); ok && v >= 0 {
			o.MeasuredDraw = intPtr(int(v))
		}
	}
	var outlets []ObservedPowerOutlet
	for n, o := range byNumber {
		if o.Name == "" {
			o.Name = fmt.Sprintf("Outlet %d", n)
		}
		outlets = append(outlets, *o)
	}
	sortOutlets(outlets)
	if !found && len(outlets) == 0 {
		return nil, nil
	}
	return []ObservedPowerPort{port}, outlets
}

// ---------------------------------------------------------------------------
// Raritan PDU2-MIB

// raritanReading scales a measurements value by its decimal digits (same index
// in the configuration table); ok false when either is missing.
func raritanReading(values, digits map[string]snmpVarBind, index string) (float64, bool) {
	v, ok := bindInt(values, index)
	if !ok || v < 0 {
		return 0, false
	}
	d, _ := bindInt(digits, index)
	if d < 0 || d > raritanMaxDecimalDigits {
		d = 0
	}
	return float64(v) / math.Pow10(int(d)), true
}

func raritanPower(walk func(string) map[string]snmpVarBind) ([]ObservedPowerPort, []ObservedPowerOutlet) {
	labels, names := walk(snmpOIDRaritanInletLabel), walk(snmpOIDRaritanInletName)
	inValues, inDigits := walk(snmpOIDRaritanInletValue), walk(snmpOIDRaritanInletDigits)
	poleValues, poleDigits := walk(snmpOIDRaritanInletPoleValue), walk(snmpOIDRaritanInletPoleDigits)

	var ports []ObservedPowerPort
	inletName := map[int64]string{}
	for idx := range labels {
		parts := indexParts(idx)
		if len(parts) != 2 || parts[0] != 1 {
			continue
		}
		inlet := parts[1]
		name := bindText(names, idx)
		if name == "" {
			name = "Inlet " + bindText(labels, idx)
		}
		inletName[inlet] = name
		p := ObservedPowerPort{Name: name, Number: int(inlet)}
		if w, ok := raritanReading(inValues, inDigits, fmt.Sprintf("%s.%d", idx, raritanSensorActivePower)); ok {
			p.MeasuredDraw = intPtr(int(math.Round(w)))
		}
		if a, ok := raritanReading(inValues, inDigits, fmt.Sprintf("%s.%d", idx, raritanSensorRMSCurrent)); ok {
			p.MeasuredCurrent = floatPtr(a)
		}
		for pole := int64(1); pole <= raritanLinePoles; pole++ {
			l := ObservedPowerLeg{Leg: legName(pole)}
			if w, ok := raritanReading(poleValues, poleDigits, fmt.Sprintf("%s.%d.%d", idx, pole, raritanSensorActivePower)); ok {
				l.MeasuredDraw = intPtr(int(math.Round(w)))
			}
			if a, ok := raritanReading(poleValues, poleDigits, fmt.Sprintf("%s.%d.%d", idx, pole, raritanSensorRMSCurrent)); ok {
				l.MeasuredCurrent = floatPtr(a)
			}
			if l.MeasuredDraw != nil || l.MeasuredCurrent != nil {
				p.Legs = append(p.Legs, l)
			}
		}
		// A single-phase inlet reports one line pole; legs are a three-phase
		// inlet's.
		if len(p.Legs) < 2 {
			p.Legs = nil
		}
		ports = append(ports, p)
	}
	sort.Slice(ports, func(i, j int) bool { return ports[i].Number < ports[j].Number })
	// An outlet draws from the inlet only when the PDU has one.
	single := ""
	if len(ports) == 1 {
		single = ports[0].Name
	}

	oLabels, oNames := walk(snmpOIDRaritanOutletLabel), walk(snmpOIDRaritanOutletName)
	oValues, oDigits, oStates := walk(snmpOIDRaritanOutletSensorValue), walk(snmpOIDRaritanOutletDigits), walk(snmpOIDRaritanOutletSensorState)
	var outlets []ObservedPowerOutlet
	for idx := range oLabels {
		parts := indexParts(idx)
		if len(parts) != 2 || parts[0] != 1 {
			continue
		}
		name := bindText(oNames, idx)
		if name == "" {
			name = "Outlet " + bindText(oLabels, idx)
		}
		o := ObservedPowerOutlet{Name: name, Number: int(parts[1]), PowerPort: single}
		if w, ok := raritanReading(oValues, oDigits, fmt.Sprintf("%s.%d", idx, raritanSensorActivePower)); ok {
			o.MeasuredDraw = intPtr(int(math.Round(w)))
		}
		if a, ok := raritanReading(oValues, oDigits, fmt.Sprintf("%s.%d", idx, raritanSensorRMSCurrent)); ok {
			o.MeasuredCurrent = floatPtr(a)
		}
		switch st, _ := bindInt(oStates, fmt.Sprintf("%s.%d", idx, raritanSensorOnOff)); st {
		case raritanStateOn:
			o.State = "on"
		case raritanStateOff:
			o.State = "off"
		}
		outlets = append(outlets, o)
	}
	sortOutlets(outlets)
	return ports, outlets
}

// ---------------------------------------------------------------------------
// Eaton EATON-EPDU-MIB

func eatonPower(walk func(string) map[string]snmpVarBind) ([]ObservedPowerPort, []ObservedPowerOutlet) {
	feedNames, totals := walk(snmpOIDEatonInputFeedName), walk(snmpOIDEatonInputTotalW)
	curType, cur := walk(snmpOIDEatonInputCurType), walk(snmpOIDEatonInputCurrent)
	powType, pow := walk(snmpOIDEatonInputPowerType), walk(snmpOIDEatonInputWatts)

	inputs := map[int64]*ObservedPowerPort{}
	input := func(n int64) *ObservedPowerPort {
		if p, ok := inputs[n]; ok {
			return p
		}
		name := bindText(feedNames, fmt.Sprintf("1.%d", n))
		if name == "" {
			name = fmt.Sprintf("Input %d", n)
		}
		p := &ObservedPowerPort{Name: name, Number: int(n)}
		inputs[n] = p
		return p
	}
	legs := map[int64]map[string]*ObservedPowerLeg{}
	leg := func(in int64, name string) *ObservedPowerLeg {
		if legs[in] == nil {
			legs[in] = map[string]*ObservedPowerLeg{}
		}
		if l, ok := legs[in][name]; ok {
			return l
		}
		l := &ObservedPowerLeg{Leg: name}
		legs[in][name] = l
		return l
	}
	for idx := range feedNames {
		if parts := indexParts(idx); len(parts) == 2 && parts[0] == 1 {
			input(parts[1])
		}
	}
	for idx, b := range totals {
		parts := indexParts(idx)
		if len(parts) != 2 || parts[0] != 1 {
			continue
		}
		if v, ok := b.Int(); ok && v >= 0 {
			input(parts[1]).MeasuredDraw = intPtr(int(v))
		}
	}
	for idx, b := range cur {
		parts := indexParts(idx)
		if len(parts) != 3 || parts[0] != 1 {
			continue
		}
		v, ok := b.Int()
		if !ok || v < 0 {
			continue
		}
		amps := floatPtr(float64(v) / 1000)
		switch t, _ := bindInt(curType, idx); t {
		case 1: // singlePhase
			input(parts[1]).MeasuredCurrent = amps
		case 3, 4, 5: // phase1..phase3
			input(parts[1])
			leg(parts[1], legName(t-2)).MeasuredCurrent = amps
		}
	}
	for idx, b := range pow {
		parts := indexParts(idx)
		if len(parts) != 3 || parts[0] != 1 {
			continue
		}
		v, ok := b.Int()
		if !ok || v < 0 {
			continue
		}
		switch t, _ := bindInt(powType, idx); t {
		case 1, 2, 3: // phase1..phase3
			input(parts[1])
			leg(parts[1], legName(t)).MeasuredDraw = intPtr(int(v))
		case 4: // total
			if p := input(parts[1]); p.MeasuredDraw == nil {
				p.MeasuredDraw = intPtr(int(v))
			}
		}
	}
	var ports []ObservedPowerPort
	for n, p := range inputs {
		if len(legs[n]) > 1 {
			for _, name := range []string{"A", "B", "C"} {
				if l, ok := legs[n][name]; ok {
					p.Legs = append(p.Legs, *l)
				}
			}
		}
		ports = append(ports, *p)
	}
	sort.Slice(ports, func(i, j int) bool { return ports[i].Number < ports[j].Number })
	single := ""
	if len(ports) == 1 {
		single = ports[0].Name
	}

	oNames, oCur, oWatts, oCtl := walk(snmpOIDEatonOutletName), walk(snmpOIDEatonOutletCurrent), walk(snmpOIDEatonOutletWatts), walk(snmpOIDEatonOutletControl)
	var outlets []ObservedPowerOutlet
	for idx := range oNames {
		parts := indexParts(idx)
		if len(parts) != 2 || parts[0] != 1 {
			continue
		}
		name := bindText(oNames, idx)
		if name == "" {
			name = fmt.Sprintf("Outlet %d", parts[1])
		}
		o := ObservedPowerOutlet{Name: name, Number: int(parts[1]), PowerPort: single}
		if v, ok := bindInt(oCur, idx); ok && v >= 0 {
			o.MeasuredCurrent = floatPtr(float64(v) / 1000)
		}
		if v, ok := bindInt(oWatts, idx); ok && v >= 0 {
			o.MeasuredDraw = intPtr(int(v))
		}
		// pendingOff is still on, pendingOn still off: the state is what the
		// outlet is now.
		if v, ok := bindInt(oCtl, idx); ok {
			switch v {
			case 0, 3:
				o.State = "off"
			case 1, 2:
				o.State = "on"
			}
		}
		outlets = append(outlets, o)
	}
	sortOutlets(outlets)
	return ports, outlets
}

// ---------------------------------------------------------------------------
// ENTITY-SENSOR-MIB (generic)

// entitySensorValue scales a sensor's value by its SensorDataScale and
// precision; ok false for a sensor that is not operating.
func entitySensorValue(value, scale, precision, oper map[string]snmpVarBind, index string) (float64, bool) {
	if st, ok := bindInt(oper, index); ok && st != entSensorOperOK {
		return 0, false
	}
	v, ok := bindInt(value, index)
	if !ok {
		return 0, false
	}
	sc, ok := bindInt(scale, index)
	if !ok {
		sc = entSensorScaleUnits
	}
	pr, _ := bindInt(precision, index)
	if sc < 1 || sc > 17 || pr < -8 || pr > 9 {
		return 0, false
	}
	return float64(v) * math.Pow10(int((sc-entSensorScaleUnits)*3)) / math.Pow10(int(pr)), true
}

// entitySensorPower is each power supply (entPhysicalClass powerSupply) with a
// watts or amperes sensor inside it, as a power port carrying the reading. A
// power supply with no such sensor is not reported: the hardware's inventory
// item already lists it, and a power port with nothing measured on it is a
// guess at a name.
func entitySensorPower(walk func(string) map[string]snmpVarBind) []ObservedPowerPort {
	types := walk(snmpOIDEntPhySensorType)
	if len(types) == 0 {
		return nil
	}
	classes := walk(snmpOIDEntPhysicalClass)
	contained := walk(snmpOIDEntPhysicalContainedIn)
	names := walk(snmpOIDEntPhysicalName)
	scale, precision := walk(snmpOIDEntPhySensorScale), walk(snmpOIDEntPhySensorPrecision)
	value, oper := walk(snmpOIDEntPhySensorValue), walk(snmpOIDEntPhySensorOper)

	byPSU := map[string]*ObservedPowerPort{}
	var order []string
	for idx, tb := range types {
		t, _ := tb.Int()
		if t != entSensorWatts && t != entSensorAmperes {
			continue
		}
		parent := strconv.FormatInt(func() int64 { n, _ := bindInt(contained, idx); return n }(), 10)
		psu := idx
		if c, _ := bindInt(classes, idx); c != entClassPowerSupply {
			psu = parent
		}
		if c, _ := bindInt(classes, psu); c != entClassPowerSupply {
			continue
		}
		name := bindText(names, psu)
		if name == "" {
			continue
		}
		v, ok := entitySensorValue(value, scale, precision, oper, idx)
		if !ok || v < 0 {
			continue
		}
		p, seen := byPSU[psu]
		if !seen {
			p = &ObservedPowerPort{Name: name}
			byPSU[psu] = p
			order = append(order, psu)
		}
		if t == entSensorWatts {
			p.MeasuredDraw = intPtr(int(math.Round(v)))
		} else {
			p.MeasuredCurrent = floatPtr(v)
		}
	}
	sort.Slice(order, func(i, j int) bool { return snmpIndexLess(order[i], order[j]) })
	var out []ObservedPowerPort
	for _, k := range order {
		out = append(out, *byPSU[k])
	}
	return out
}

// snmpPowerPurposes says why each PDU column is walked (the SNMP manifest's
// endpoint list, capability_manifest.go).
var snmpPowerPurposes = map[string]string{
	snmpOIDAPCDeviceModule: "APC rack PDU unit of a chain (only the first is read)", snmpOIDAPCDevicePower: "APC rack PDU total load (power port draw, DCIM row 6.2)",
	snmpOIDAPCPhaseModule: "APC phase unit", snmpOIDAPCPhaseNumber: "APC phase number (feed leg)",
	snmpOIDAPCPhaseCurrent: "APC per-phase current", snmpOIDAPCPhasePower: "APC per-phase load",
	snmpOIDAPCSwModule: "APC switched outlet unit", snmpOIDAPCSwName: "APC outlet names", snmpOIDAPCSwNumber: "APC outlet numbers",
	snmpOIDAPCSwState: "APC outlet on / off state", snmpOIDAPCMtModule: "APC metered outlet unit", snmpOIDAPCMtName: "APC metered outlet names",
	snmpOIDAPCMtNumber: "APC metered outlet numbers", snmpOIDAPCMtCurrent: "APC outlet current", snmpOIDAPCMtPower: "APC outlet power",

	snmpOIDRaritanInletLabel: "Raritan inlet labels", snmpOIDRaritanInletName: "Raritan inlet names",
	snmpOIDRaritanInletDigits: "Raritan inlet reading scale", snmpOIDRaritanInletValue: "Raritan inlet current and power",
	snmpOIDRaritanInletPoleDigits: "Raritan inlet pole reading scale", snmpOIDRaritanInletPoleValue: "Raritan per-pole (feed leg) current and power",
	snmpOIDRaritanOutletLabel: "Raritan outlet labels", snmpOIDRaritanOutletName: "Raritan outlet names",
	snmpOIDRaritanOutletDigits: "Raritan outlet reading scale", snmpOIDRaritanOutletSensorState: "Raritan outlet on / off state",
	snmpOIDRaritanOutletSensorValue: "Raritan outlet current and power",

	snmpOIDEatonInputFeedName: "Eaton input names", snmpOIDEatonInputCurType: "Eaton input current kind (phase)",
	snmpOIDEatonInputCurrent: "Eaton input current", snmpOIDEatonInputPowerType: "Eaton input power kind (phase or total)",
	snmpOIDEatonInputWatts: "Eaton input power", snmpOIDEatonInputTotalW: "Eaton input total power",
	snmpOIDEatonOutletName: "Eaton outlet names", snmpOIDEatonOutletCurrent: "Eaton outlet current",
	snmpOIDEatonOutletWatts: "Eaton outlet power", snmpOIDEatonOutletControl: "Eaton outlet on / off state",

	snmpOIDEntPhySensorType: "sensor kind (watts / amperes inside a power supply)", snmpOIDEntPhySensorScale: "sensor scale",
	snmpOIDEntPhySensorPrecision: "sensor precision", snmpOIDEntPhySensorValue: "power supply draw and current",
	snmpOIDEntPhySensorOper: "sensor operational state",
}

// snmpPowerEndpoints lists the PDU columns as manifest endpoints, in OID order.
func snmpPowerEndpoints() []Endpoint {
	cols := make([]string, 0, len(snmpPowerColumns))
	for oid := range snmpPowerColumns {
		cols = append(cols, oid)
	}
	sort.Strings(cols)
	out := make([]Endpoint, 0, len(cols))
	for _, oid := range cols {
		out = append(out, snmpWalkEndpoint(oid, snmpPowerPurposes[oid]))
	}
	return out
}
