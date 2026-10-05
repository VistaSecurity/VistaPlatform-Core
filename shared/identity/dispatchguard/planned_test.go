package dispatchguard

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	shareddisc "github.com/vistasecurity/vistaplatform/shared/discovery"
	"github.com/vistasecurity/vistaplatform/shared/sensordispatch"
)

func planTarget(target string, depth shareddisc.ScanDepth, tcp, udp string) sensordispatch.PlanTargetWork {
	return sensordispatch.PlanTargetWork{PlanTarget: shareddisc.PlanTarget{Target: target, Depth: depth, TCPPorts: tcp, UDPPorts: udp}}
}

func plannedPayload(targets ...sensordispatch.PlanTargetWork) sensordispatch.Payload {
	return sensordispatch.Payload{TenantID: "t", Plan: &sensordispatch.PlanPayload{Version: 1, Attempt: 1, Targets: targets}}
}

func TestProbeScopeOf_LegacyPayloadIsUnchanged(t *testing.T) {
	p := sensordispatch.Payload{Targets: []string{"10.0.0.5"}, Protocols: []string{"TLS"}, Ports: []int{443, 443}}
	got, err := probeScopeOf(p)
	if err != nil {
		t.Fatal(err)
	}
	want := probeScope{Targets: p.Targets, Protocols: p.Protocols, Ports: p.Ports}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("scope = %+v, want the payload as it is %+v", got, want)
	}
}

func TestProbeScopeOf_PlanReadsAddressesAndPortsScanned(t *testing.T) {
	a := planTarget("10.0.0.5", shareddisc.DepthCustom, "443,22", "")
	b := planTarget("10.0.0.6", shareddisc.DepthCustom, "8443", "")
	skipped := planTarget("10.0.0.7", shareddisc.DepthCustom, "443", "")
	skipped.SkipAddresses = []string{"10.0.0.7"}
	got, err := probeScopeOf(plannedPayload(a, b, skipped))
	if err != nil {
		t.Fatal(err)
	}
	want := probeScope{Targets: []string{"10.0.0.5", "10.0.0.6"}, Ports: []int{22, 443, 8443}, Planned: true}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("scope = %+v, want %+v", got, want)
	}
	quick, err := probeScopeOf(plannedPayload(planTarget("10.0.0.5", shareddisc.DepthQuick, shareddisc.QuickPorts().String(), "")))
	if err != nil || len(quick.Ports) != shareddisc.QuickPorts().Len() {
		t.Fatalf("quick depth: scope=%+v err=%v", quick, err)
	}
}

func TestProbeScopeOf_PlanRefusals(t *testing.T) {
	withOT := plannedPayload(planTarget("10.0.0.5", shareddisc.DepthCustom, "502", ""))
	withOT.Plan.OTProbeProtocols = []string{"Modbus"}
	beside := plannedPayload(planTarget("10.0.0.5", shareddisc.DepthCustom, "443", ""))
	beside.Targets = []string{"10.0.0.9"}
	for name, tc := range map[string]struct {
		payload sensordispatch.Payload
		why     string
	}{
		"udp":         {plannedPayload(planTarget("10.0.0.5", shareddisc.DepthCustom, "443", "161")), "UDP"},
		"udp only":    {plannedPayload(planTarget("10.0.0.5", shareddisc.DepthCustom, "", "53")), "UDP"},
		"ot opt-in":   {withOT, "OT probes"},
		"standard":    {plannedPayload(planTarget("10.0.0.5", shareddisc.DepthStandard, "443", "")), "custom or quick"},
		"thorough":    {plannedPayload(planTarget("10.0.0.5", shareddisc.DepthThorough, "1-65535", "")), "custom or quick"},
		"range":       {plannedPayload(planTarget("10.0.0.0/30", shareddisc.DepthCustom, "443", "")), "individual addresses"},
		"dash range":  {plannedPayload(planTarget("10.0.0.1-10.0.0.9", shareddisc.DepthCustom, "443", "")), "individual addresses"},
		"hostname":    {plannedPayload(planTarget("host.example.test", shareddisc.DepthCustom, "443", "")), "individual addresses"},
		"no port":     {plannedPayload(planTarget("10.0.0.5", shareddisc.DepthCustom, "", "")), "no TCP port"},
		"beside plan": {beside, "in the plan"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := probeScopeOf(tc.payload)
			if !errors.Is(err, ErrDenied) || !strings.Contains(err.Error(), tc.why) {
				t.Fatalf("err = %v, want a denial naming %q", err, tc.why)
			}
		})
	}
}
