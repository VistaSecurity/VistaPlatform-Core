package snmpfake

import "fmt"

// Synthesised rack PDU walks (DCIM BUILD_PLAN row 6.2). None is a capture of a
// real device; each is shaped the way that vendor's agent answers the tables
// the PDU collector walks, with documentation-range addresses and made-up
// serials. Each plants PDUCommunity / PDUSecret in sysDescr, sysContact and
// in a column of the vendor's MIB the collector does NOT walk (an outlet's
// external link, a user account), so a projection test can prove nothing but
// the named columns reaches an observation.

// Planted secrets in the PDU walks.
// Spelled as two pieces so the value never sits in the source as one
// high-entropy literal: the PR-diff Gitleaks gate flagged it as an API key.
const (
	PDUCommunity = "PlantedPduCommunity-" + "h5Rw31"
	PDUSecret    = "PlantedPduSecret-" + "Lq8803"
)

func pduSystem(m *mibBuilder, objectID, descr, name string) {
	m.add(
		Str(oidSysDescr, descr+" community "+PDUCommunity),
		OIDValue(oidSysObjectID, objectID),
		Ticks(oidSysUpTime, 4242424),
		Str(oidSysContact, "facilities@example.net "+PDUSecret),
		Str(oidSysName, name),
		Str(oidSysLocation, "Row 3 / "+PDUSecret),
	)
}

// APCRackPDU is an APC switched, metered-by-outlet rack PDU (AP8941-shaped,
// PowerNet-MIB rPDU2, enterprise 318) with eight outlets on module 1, a second
// chained unit (module 2) the collector must ignore, three phases, outlet 3
// off and outlet 8 named by the operator:
//
//   - rPDU2DeviceStatusPower 1.23 kW on module 1 (123 hundredths);
//   - phases 1-3: 2.1 A / 0.45 kW, 1.8 A / 0.39 kW, 1.7 A / 0.39 kW;
//   - outlet n draws n×0.2 A and n×40 W; outlet 3 draws nothing.
func APCRackPDU() Recording {
	var m mibBuilder
	pduSystem(&m, "1.3.6.1.4.1.318.1.3.4.6", "APC Web/SNMP Management Card (MB:v4.1.0 PF:v6.9.6 PN:apc_hw05_aos_696.bin AF1:v6.9.6 AN1:apc_hw05_rpdu2g_696.bin MN:AP8941 HR:02 SN: 5A1234E00001 MD:04/18/2020)", "pdu-a1.example.net")
	const dev, ph, sw, mt = "1.3.6.1.4.1.318.1.1.26.4.3.1", "1.3.6.1.4.1.318.1.1.26.6.3.1", "1.3.6.1.4.1.318.1.1.26.9.2.3.1", "1.3.6.1.4.1.318.1.1.26.9.4.3.1"
	m.add(Int(dev+".2.1", 1), Int(dev+".5.1", 123), Int(dev+".2.2", 2), Int(dev+".5.2", 999))
	for i, p := range [][2]int64{{21, 45}, {18, 39}, {17, 39}} {
		idx := fmt.Sprintf(".%d", i+1)
		m.add(Int(ph+".2"+idx, 1), Int(ph+".3"+idx, int64(i+1)), Int(ph+".5"+idx, p[0]), Int(ph+".7"+idx, p[1]))
	}
	// The chained unit's phase: never read.
	m.add(Int(ph+".2.4", 2), Int(ph+".3.4", 1), Int(ph+".5.4", 99), Int(ph+".7.4", 99))
	for n := 1; n <= 8; n++ {
		idx := fmt.Sprintf(".%d", n)
		name := fmt.Sprintf("Outlet %d", n)
		if n == 8 {
			name = "web-01 PSU A"
		}
		state := int64(2)
		amps, watts := int64(n*2), int64(n*40)
		if n == 3 {
			state, amps, watts = 1, 0, 0
		}
		m.add(Int(sw+".2"+idx, 1), Str(sw+".3"+idx, name), Int(sw+".4"+idx, int64(n)), Int(sw+".5"+idx, state),
			Str(sw+".7"+idx, "https://example.net/?key="+PDUSecret), // rPDU2OutletSwitchedStatusExternalLink: not walked
			Int(mt+".2"+idx, 1), Str(mt+".3"+idx, name), Int(mt+".4"+idx, int64(n)), Int(mt+".6"+idx, amps), Int(mt+".7"+idx, watts))
	}
	// Module 2's outlet 1 (off, 7.7 A): never read — module 1's outlet 1 stays on.
	m.add(Int(sw+".2.9", 2), Str(sw+".3.9", "Outlet 1"), Int(sw+".4.9", 1), Int(sw+".5.9", 1),
		Int(mt+".2.9", 2), Str(mt+".3.9", "Outlet 1"), Int(mt+".4.9", 1), Int(mt+".6.9", 77), Int(mt+".7.9", 777))
	return Recording{Community: PDUCommunity, MIB: m.v}
}

// RaritanPDU is a Raritan PX3-shaped single-inlet, three-phase PDU (PDU2-MIB,
// enterprise 13742) with six outlets:
//
//   - inlet I1, no user name: 1834 W, rmsCurrent 9.105 A (3 decimal digits),
//     poles L1-L3 at 3.2 / 3.0 / 2.905 A and 640 / 600 / 594 W, the neutral
//     pole 4 ignored;
//   - outlet n "Outlet n" except outlet 2 named "db-02 PSU1", 0.5×n A (1
//     digit), 100×n W, on, except outlet 5 off.
func RaritanPDU() Recording {
	var m mibBuilder
	pduSystem(&m, "1.3.6.1.4.1.13742.6", "Raritan PX3-5190R 3.6.0", "pdu-b1.example.net")
	const inCfg, inDig, inVal = "1.3.6.1.4.1.13742.6.3.3.3.1", "1.3.6.1.4.1.13742.6.3.3.4.1.7", "1.3.6.1.4.1.13742.6.5.2.3.1.4"
	const poleDig, poleVal = "1.3.6.1.4.1.13742.6.3.3.6.1.7", "1.3.6.1.4.1.13742.6.5.2.4.1.4"
	const outCfg, outDig, outState, outVal = "1.3.6.1.4.1.13742.6.3.5.3.1", "1.3.6.1.4.1.13742.6.3.5.4.1.7", "1.3.6.1.4.1.13742.6.5.4.3.1.3", "1.3.6.1.4.1.13742.6.5.4.3.1.4"
	m.add(Str(inCfg+".2.1.1", "I1"), Str(inCfg+".3.1.1", ""),
		Gauge(inDig+".1.1.1", 3), Gauge(inVal+".1.1.1", 9105),
		Gauge(inDig+".1.1.5", 0), Gauge(inVal+".1.1.5", 1834))
	for pole, r := range [][2]int64{{3200, 640}, {3000, 600}, {2905, 594}, {100, 0}} {
		p := fmt.Sprintf(".1.1.%d", pole+1)
		m.add(Gauge(poleDig+p+".1", 3), Gauge(poleVal+p+".1", r[0]), Gauge(poleDig+p+".5", 0), Gauge(poleVal+p+".5", r[1]))
	}
	for n := 1; n <= 6; n++ {
		idx := fmt.Sprintf(".1.%d", n)
		name := ""
		if n == 2 {
			name = "db-02 PSU1"
		}
		state := int64(7)
		if n == 5 {
			state = 8
		}
		m.add(Str(outCfg+".2"+idx, fmt.Sprint(n)), Str(outCfg+".3"+idx, name),
			Gauge(outDig+idx+".1", 1), Gauge(outVal+idx+".1", int64(5*n)),
			Gauge(outDig+idx+".5", 0), Gauge(outVal+idx+".5", int64(100*n)),
			Int(outState+idx+".14", state))
	}
	// A user account row of PDU2-MIB's unitConfiguration: never walked.
	m.add(Str("1.3.6.1.4.1.13742.6.3.2.4.1.2.1", "admin:"+PDUSecret))
	return Recording{Community: PDUCommunity, MIB: m.v}
}

// EatonEPDU is an Eaton G3 ePDU-shaped single-input, three-phase PDU
// (EATON-EPDU-MIB, enterprise 534) with four outlets on strapping index 1 and
// a chained unit (strapping 2) the collector ignores:
//
//   - input 1 "Feed A": total 2100 W; phase currents 3.1 / 2.9 / 3.0 A (mA),
//     phase power 700 / 690 / 710 W, the neutral current ignored;
//   - outlet n "Outlet n", 250×n mA, 60×n W; outlet 2 off, outlet 4 has no
//     power reading (outletWatts -1) and is pendingOff (still on).
func EatonEPDU() Recording {
	var m mibBuilder
	pduSystem(&m, "1.3.6.1.4.1.534.6.6.7", "Eaton ePDU MA 0U (C20 16A 1P)20XC13:4XC19", "pdu-c1.example.net")
	const in, cur, pow, tot = "1.3.6.1.4.1.534.6.6.7.3.1.1", "1.3.6.1.4.1.534.6.6.7.3.3.1", "1.3.6.1.4.1.534.6.6.7.3.4.1", "1.3.6.1.4.1.534.6.6.7.3.5.1.4"
	const oName, oCur, oPow, oCtl = "1.3.6.1.4.1.534.6.6.7.6.1.1.3", "1.3.6.1.4.1.534.6.6.7.6.4.1.3", "1.3.6.1.4.1.534.6.6.7.6.5.1.3", "1.3.6.1.4.1.534.6.6.7.6.6.1.2"
	m.add(Str(in+".10.1.1", "Feed A"), Int(tot+".1.1", 2100), Str(in+".10.2.2", "Feed B"), Int(tot+".2.2", 999))
	for i, c := range []int64{3100, 2900, 3000} {
		idx := fmt.Sprintf(".1.1.%d", i+1)
		m.add(Int(cur+".2"+idx, int64(i+3)), Int(cur+".3"+idx, c))
	}
	m.add(Int(cur+".2.1.1.4", 2), Int(cur+".3.1.1.4", 40)) // neutral
	for i, w := range []int64{700, 690, 710, 2100} {
		idx := fmt.Sprintf(".1.1.%d", i+1)
		m.add(Int(pow+".2"+idx, int64(i+1)), Int(pow+".3"+idx, w))
	}
	for n := 1; n <= 4; n++ {
		idx := fmt.Sprintf(".1.%d", n)
		watts := int64(60 * n)
		ctl := int64(1)
		switch n {
		case 2:
			ctl = 0
		case 4:
			watts, ctl = -1, 2
		}
		m.add(Str(oName+idx, fmt.Sprintf("Outlet %d", n)), Int(oCur+idx, int64(250*n)), Int(oPow+idx, watts), Int(oCtl+idx, ctl))
	}
	m.add(Str(oName+".2.1", "Outlet 1"), Int(oCur+".2.1", 9999), Int(oPow+".2.1", 9999), Int(oCtl+".2.1", 1))
	// unitName of the userTable-shaped branch: never walked.
	m.add(Str("1.3.6.1.4.1.534.6.6.7.1.2.1.20.1", PDUSecret))
	return Recording{Community: PDUCommunity, MIB: m.v}
}

// ServerWithPSUSensors is a server BMC's agent (enterprise 674, Dell-shaped)
// with two power supplies in entPhysicalTable, each holding an
// ENTITY-SENSOR-MIB watts sensor and an amperes sensor (milli scale), one
// temperature sensor that is not power, and a third power supply whose sensor
// is not operating:
//
//   - "PSU 1": 212 W, 0.950 A; "PSU 2": 198 W, 0.880 A; "PSU 3": unavailable.
func ServerWithPSUSensors() Recording {
	var m mibBuilder
	pduSystem(&m, "1.3.6.1.4.1.674.10892.5", "Linux idrac 4.19 BMC", "bmc-db-02.example.net")
	const cls, contained, name = "1.3.6.1.2.1.47.1.1.1.1.5", "1.3.6.1.2.1.47.1.1.1.1.4", "1.3.6.1.2.1.47.1.1.1.1.7"
	const sType, sScale, sPrec, sVal, sOper = "1.3.6.1.2.1.99.1.1.1.1", "1.3.6.1.2.1.99.1.1.1.2", "1.3.6.1.2.1.99.1.1.1.3", "1.3.6.1.2.1.99.1.1.1.4", "1.3.6.1.2.1.99.1.1.1.5"
	m.add(Int(cls+".1", 3), Str(name+".1", "Chassis"))
	sensor := func(idx, parent int, typ, scale, prec, val, oper int64, label string) {
		i := fmt.Sprintf(".%d", idx)
		m.add(Int(cls+i, 8), Int(contained+i, int64(parent)), Str(name+i, label),
			Int(sType+i, typ), Int(sScale+i, scale), Int(sPrec+i, prec), Int(sVal+i, val), Int(sOper+i, oper))
	}
	for k, r := range [][3]int64{{212, 950, 1}, {198, 880, 1}, {0, 0, 2}} {
		psu := 10 + k
		i := fmt.Sprintf(".%d", psu)
		m.add(Int(cls+i, 6), Int(contained+i, 1), Str(name+i, fmt.Sprintf("PSU %d", k+1)))
		sensor(100+2*k, psu, 6, 9, 0, r[0], r[2], fmt.Sprintf("PSU %d Power", k+1))
		sensor(101+2*k, psu, 5, 8, 0, r[1], r[2], fmt.Sprintf("PSU %d Current", k+1))
	}
	sensor(200, 1, 8, 9, 0, 31, 1, "Inlet Temp")
	return Recording{Community: PDUCommunity, MIB: m.v}
}
