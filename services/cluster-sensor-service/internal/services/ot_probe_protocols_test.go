package services

import (
	"reflect"
	"testing"

	shareddisc "github.com/vistasecurity/vistaplatform/shared/discovery"
)

// TestDispatchableOTProtocolsKeepsTheAuditColumnHonest pins "record only what
// was genuinely attempted": discovery_jobs.ot_probe_protocols documents itself
// as "these probes were dispatched", so a protocol that would never be probed
// must not appear in it.
func TestDispatchableOTProtocolsKeepsTheAuditColumnHonest(t *testing.T) {
	if got := dispatchableOTProtocols([]string{"BACnet", "Modbus"}); len(got) != 2 {
		t.Errorf("dispatchableOTProtocols(BACnet, Modbus) = %v, want both — each has a standard port", got)
	}
	// A protocol with no standard port is never probed, so recording it as
	// probed would be the "reported as probed, never probed" lie again.
	if got := dispatchableOTProtocols([]string{"BACnet", "Nonexistent"}); len(got) != 1 || got[0] != "BACnet" {
		t.Errorf("dispatchableOTProtocols(BACnet, Nonexistent) = %v, want [BACnet]", got)
	}
	if got := dispatchableOTProtocols([]string{"Nonexistent"}); got != nil {
		t.Errorf("dispatchableOTProtocols(Nonexistent) = %v, want nil", got)
	}
	if got := dispatchableOTProtocols(nil); got != nil {
		t.Errorf("dispatchableOTProtocols(nil) = %v, want nil", got)
	}
}

// TestOTProbePorts_EachProtocolAtItsStandardPort pins the pairs the legacy
// OT-only request is translated with ( WP5): one standard port per
// protocol, exactly the port the OT target row records.
func TestOTProbePorts_EachProtocolAtItsStandardPort(t *testing.T) {
	got := otProbePorts([]string{"Modbus", "OPC_UA", "EtherNet_IP", "BACnet", "Nonexistent"})
	want := []shareddisc.OTProbePort{{Protocol: "Modbus", Port: 502}, {Protocol: "OPC_UA", Port: 4840},
		{Protocol: "EtherNet_IP", Port: 44818}, {Protocol: "BACnet", Port: 47808}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("otProbePorts = %+v, want %+v", got, want)
	}
	if got := otProbePorts(nil); len(got) != 0 {
		t.Fatalf("otProbePorts(nil) = %+v, want none", got)
	}
}
