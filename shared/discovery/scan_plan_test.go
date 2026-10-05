package discovery

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
)

func TestResolveJobRequest_PathAndValidation(t *testing.T) {
	for _, tc := range []struct {
		name    string
		in      JobRequestFields
		plan    bool
		depth   ScanDepth
		tcp     int
		udp     int
		pace    Pace
		runFrom string
		// wantErr is a substring the refusal must contain; "" = accepted.
		wantErr string
	}{
		// Legacy: exactly as before, whatever execution_mode says.
		{name: "legacy protocols/ports", in: JobRequestFields{Protocols: []string{"TLS"}, Ports: []int{443}, ExecutionMode: "cloud"}},
		{name: "legacy OT-only stays legacy", in: JobRequestFields{OTProbeProtocols: []string{"Modbus"}}},
		{name: "legacy ports only (cluster-sensor refuses it, as before)", in: JobRequestFields{Ports: []int{443}}},

		// Every depth.
		{name: "default is standard", in: JobRequestFields{}, plan: true, depth: DepthStandard, tcp: 1364, udp: 11, pace: PaceNormal, runFrom: RunFromAuto},
		{name: "quick", in: JobRequestFields{ScanDepth: "quick"}, plan: true, depth: DepthQuick, tcp: 41, udp: 0, pace: PaceNormal, runFrom: RunFromAuto},
		{name: "standard", in: JobRequestFields{ScanDepth: "Standard"}, plan: true, depth: DepthStandard, tcp: 1364, udp: 11, pace: PaceNormal, runFrom: RunFromAuto},
		{name: "thorough", in: JobRequestFields{ScanDepth: "thorough", Pace: "polite"}, plan: true, depth: DepthThorough, tcp: 65535, udp: 11, pace: PacePolite, runFrom: RunFromAuto},
		{name: "custom ranges", in: JobRequestFields{ScanDepth: "custom", TCPPorts: "22, 80,8000-8100", UDPPorts: "53,161"}, plan: true, depth: DepthCustom, tcp: 103, udp: 2, pace: PaceNormal, runFrom: RunFromAuto},
		{name: "custom UDP only", in: JobRequestFields{ScanDepth: "custom", UDPPorts: "500"}, plan: true, depth: DepthCustom, tcp: 0, udp: 1, pace: PaceNormal, runFrom: RunFromAuto},
		{name: "pace alone selects the plan path", in: JobRequestFields{Pace: "fast"}, plan: true, depth: DepthStandard, tcp: 1364, udp: 11, pace: PaceFast, runFrom: RunFromAuto},
		{name: "OT opt-in rides along", in: JobRequestFields{ScanDepth: "quick", OTProbeProtocols: []string{"Modbus"}}, plan: true, depth: DepthQuick, tcp: 41, pace: PaceNormal, runFrom: RunFromAuto},

		// Run from.
		{name: "run_from platform", in: JobRequestFields{RunFrom: "platform"}, plan: true, depth: DepthStandard, tcp: 1364, udp: 11, pace: PaceNormal, runFrom: RunFromPlatform},
		{name: "run_from sensor", in: JobRequestFields{RunFrom: "sensor", SensorID: "6f1c2b9e-4d3a-4b8e-9c1d-2e3f4a5b6c7d"}, plan: true, depth: DepthStandard, tcp: 1364, udp: 11, pace: PaceNormal, runFrom: RunFromSensor},
		{name: "legacy cloud is platform", in: JobRequestFields{ScanDepth: "quick", ExecutionMode: "cloud"}, plan: true, depth: DepthQuick, tcp: 41, pace: PaceNormal, runFrom: RunFromPlatform},
		{name: "legacy sensors is sensor", in: JobRequestFields{ScanDepth: "quick", ExecutionMode: "sensors", PreferredSensorIDs: []string{"6f1c2b9e-4d3a-4b8e-9c1d-2e3f4a5b6c7d"}}, plan: true, depth: DepthQuick, tcp: 41, pace: PaceNormal, runFrom: RunFromSensor},

		// Refusals, each naming what to fix.
		{name: "depth + protocols conflict", in: JobRequestFields{ScanDepth: "thorough", Protocols: []string{"TLS"}, Ports: []int{443}}, wantErr: "scan_depth cannot be combined with protocols/ports"},
		{name: "run_from + ports conflict", in: JobRequestFields{RunFrom: "platform", Ports: []int{443}}, wantErr: "run_from cannot be combined"},
		{name: "unknown depth", in: JobRequestFields{ScanDepth: "deep"}, wantErr: `scan_depth "deep"`},
		{name: "custom with nothing", in: JobRequestFields{ScanDepth: "custom"}, wantErr: "needs tcp_ports, udp_ports or both"},
		{name: "ports on a preset depth", in: JobRequestFields{ScanDepth: "quick", TCPPorts: "22"}, wantErr: "apply only to scan_depth \"custom\""},
		{name: "ports without a depth", in: JobRequestFields{TCPPorts: "22"}, wantErr: "apply only to scan_depth \"custom\""},
		{name: "bad TCP token named", in: JobRequestFields{ScanDepth: "custom", TCPPorts: "22,http,443"}, wantErr: `tcp_ports: port spec entry "http"`},
		{name: "bad UDP token named", in: JobRequestFields{ScanDepth: "custom", UDPPorts: "53,70000"}, wantErr: `udp_ports: port spec entry "70000"`},
		{name: "reversed range named", in: JobRequestFields{ScanDepth: "custom", TCPPorts: "100-80"}, wantErr: `"100-80"`},
		{name: "bad pace", in: JobRequestFields{Pace: "ludicrous"}, wantErr: "pace: unknown scan pace"},
		{name: "sensor without id", in: JobRequestFields{RunFrom: "sensor"}, wantErr: "needs a sensor_id"},
		{name: "sensor id not a uuid", in: JobRequestFields{RunFrom: "sensor", SensorID: "edge-1"}, wantErr: "is not a UUID"},
		{name: "sensor_id with auto", in: JobRequestFields{SensorID: "6f1c2b9e-4d3a-4b8e-9c1d-2e3f4a5b6c7d"}, wantErr: "only applies to run_from \"sensor\""},
		{name: "run_from and execution_mode", in: JobRequestFields{RunFrom: "platform", ExecutionMode: "auto"}, wantErr: "cannot both be set"},
		{name: "unknown run_from", in: JobRequestFields{RunFrom: "moon"}, wantErr: `run_from "moon"`},
		{name: "preferred ids with run_from", in: JobRequestFields{RunFrom: "sensor", SensorID: "6f1c2b9e-4d3a-4b8e-9c1d-2e3f4a5b6c7d", PreferredSensorIDs: []string{"6f1c2b9e-4d3a-4b8e-9c1d-2e3f4a5b6c7d"}}, wantErr: "preferred_sensor_ids does not apply"},
		{name: "sensors alias needs one id", in: JobRequestFields{ScanDepth: "quick", ExecutionMode: "sensors"}, wantErr: "exactly one preferred_sensor_id"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ResolveJobRequest(tc.in)
			if tc.wantErr != "" {
				var reqErr *ScanRequestError
				if err == nil || !errors.As(err, &reqErr) || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("err = %v, want a *ScanRequestError containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("refused: %v", err)
			}
			if got.Plan != tc.plan {
				t.Fatalf("plan path = %v, want %v", got.Plan, tc.plan)
			}
			if !tc.plan {
				return
			}
			if got.Spec.Depth != tc.depth || got.Spec.TCP.Len() != tc.tcp || got.Spec.UDP.Len() != tc.udp || got.Spec.Pace != tc.pace || got.RunFrom != tc.runFrom {
				t.Fatalf("got depth=%s tcp=%d udp=%d pace=%s run_from=%s; want %s %d %d %s %s",
					got.Spec.Depth, got.Spec.TCP.Len(), got.Spec.UDP.Len(), got.Spec.Pace, got.RunFrom, tc.depth, tc.tcp, tc.udp, tc.pace, tc.runFrom)
			}
		})
	}
}

func mustSpec(t *testing.T, f JobRequestFields) ScanSpec {
	t.Helper()
	shape, err := ResolveJobRequest(f)
	if err != nil || !shape.Plan {
		t.Fatalf("ResolveJobRequest(%+v) = %+v, %v", f, shape, err)
	}
	return shape.Spec
}

// D3: an external target is capped at Standard; internal and registered
// targets get what was asked. Per target, in the same job.
func TestBuildScanPlan_ExternalCapIsPerTarget(t *testing.T) {
	spec := mustSpec(t, JobRequestFields{ScanDepth: "thorough"})
	plan, err := BuildScanPlan(spec, nil, []PlanTargetInput{
		{Target: "10.20.30.0/24", Class: ClassPrivate},
		{Target: "93.184.216.34", Class: ClassExternal},
		{Target: "93.184.217.0/28", Class: ClassRegisteredSegment, SegmentID: "seg-1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	internal, external, registered := plan.Targets[0], plan.Targets[1], plan.Targets[2]
	if internal.Depth != DepthThorough || internal.TCPPortCount != 65535 || internal.UDPPortCount != 11 || internal.Addresses != 256 {
		t.Errorf("private /24 = %+v, want thorough 65535+11 on 256 addresses", internal)
	}
	if internal.EstimatedProbes != 256*(65535+11) {
		t.Errorf("private /24 probes = %d", internal.EstimatedProbes)
	}
	if external.Depth != DepthStandard || external.TCPPortCount != StandardPorts().Len() || external.UDPPortCount != 11 {
		t.Errorf("external host = %+v, want capped to standard", external)
	}
	if registered.Depth != DepthThorough || registered.SegmentID != "seg-1" || registered.TCPPortCount != 65535 {
		t.Errorf("registered segment = %+v, want thorough and its segment id", registered)
	}
	if len(plan.DepthAdjustments) != 1 {
		t.Fatalf("adjustments = %+v, want exactly the external one", plan.DepthAdjustments)
	}
	adj := plan.DepthAdjustments[0]
	if adj.Target != "93.184.216.34" || adj.Requested != DepthThorough || adj.Applied != DepthStandard ||
		!strings.Contains(adj.Reason, "outside your registered networks") || !strings.Contains(adj.Reason, "register the range if it is yours") {
		t.Errorf("adjustment = %+v", adj)
	}
	want := internal.EstimatedProbes + external.EstimatedProbes + registered.EstimatedProbes
	if plan.EstimatedProbes != want {
		t.Errorf("estimated = %d, want %d", plan.EstimatedProbes, want)
	}
}

func TestBuildScanPlan_ExternalQuickAndStandardUnchanged(t *testing.T) {
	for _, depth := range []string{"quick", "standard"} {
		plan, err := BuildScanPlan(mustSpec(t, JobRequestFields{ScanDepth: depth}), nil, []PlanTargetInput{{Target: "93.184.216.34", Class: ClassExternal}})
		if err != nil {
			t.Fatal(err)
		}
		if len(plan.DepthAdjustments) != 0 || plan.Targets[0].Depth != ScanDepth(depth) {
			t.Errorf("%s: %+v", depth, plan)
		}
	}
}

func TestBuildScanPlan_ExternalCustomIsCapped(t *testing.T) {
	spec := mustSpec(t, JobRequestFields{ScanDepth: "custom", TCPPorts: "1-2000", UDPPorts: "53,5000,161,6000-6001"})
	plan, err := BuildScanPlan(spec, nil, []PlanTargetInput{
		{Target: "93.184.216.34", Class: ClassExternal},
		{Target: "10.1.1.1", Class: ClassPrivate},
	})
	if err != nil {
		t.Fatal(err)
	}
	ext, in := plan.Targets[0], plan.Targets[1]
	if ext.TCPPortCount != MaxExternalCustomTCPPorts || ext.TCPPorts != "1-1024" {
		t.Errorf("external custom TCP = %d %q, want the lowest 1024", ext.TCPPortCount, ext.TCPPorts)
	}
	if ext.UDPPorts != "53,161" {
		t.Errorf("external custom UDP = %q, want only the curated ports asked for", ext.UDPPorts)
	}
	if in.TCPPortCount != 2000 || in.UDPPorts != "53,161,5000,6000-6001" {
		t.Errorf("private target was capped: %+v", in)
	}
	if len(plan.DepthAdjustments) != 1 || !strings.Contains(plan.DepthAdjustments[0].Reason, "1024 TCP ports") ||
		!strings.Contains(plan.DepthAdjustments[0].Reason, "UDP 5000,6000-6001 is not") {
		t.Errorf("adjustment = %+v", plan.DepthAdjustments)
	}

	// Within the cap: no adjustment.
	small := mustSpec(t, JobRequestFields{ScanDepth: "custom", TCPPorts: "22,443", UDPPorts: "500"})
	plan, _ = BuildScanPlan(small, nil, []PlanTargetInput{{Target: "93.184.216.34", Class: ClassExternal}})
	if len(plan.DepthAdjustments) != 0 || plan.Targets[0].TCPPorts != "22,443" || plan.Targets[0].UDPPorts != "500" {
		t.Errorf("in-cap custom = %+v", plan)
	}
}

func TestBuildScanPlan_ExplicitURLPortJoinsEveryTarget(t *testing.T) {
	plan, err := BuildScanPlan(mustSpec(t, JobRequestFields{ScanDepth: "quick"}), []int{9999}, []PlanTargetInput{
		{Target: "www.example.com", Class: ClassExternal},
	})
	if err != nil {
		t.Fatal(err)
	}
	tcp, _ := plan.Targets[0].TCPPortSet()
	if !tcp.Contains(9999) || plan.Targets[0].Addresses != 1 || plan.TCPPortCount != QuickPorts().Len()+1 {
		t.Errorf("plan = %+v", plan)
	}
}

// H19: the budget refuses above the limit with the numbers, admits at it.
func TestCheckBudget_BothPolarities(t *testing.T) {
	plan, err := BuildScanPlan(mustSpec(t, JobRequestFields{ScanDepth: "custom", TCPPorts: "1-100"}), nil, []PlanTargetInput{
		{Target: "10.0.0.0/24", Class: ClassPrivate},
		{Target: "10.0.1.1", Class: ClassPrivate},
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.EstimatedProbes != 25700 {
		t.Fatalf("estimated = %d, want 256*100 + 100", plan.EstimatedProbes)
	}
	if err := plan.CheckBudget(25700); err != nil || plan.ProbeLimit != 25700 {
		t.Fatalf("exactly at the limit refused: %v", err)
	}
	err = plan.CheckBudget(25699)
	budget, ok := IsScanBudgetError(err)
	if !ok {
		t.Fatalf("one over the limit: %v", err)
	}
	if budget.Estimated != 25700 || budget.Limit != 25699 || budget.Largest.Target != "10.0.0.0/24" {
		t.Errorf("budget error = %+v", budget)
	}
	for _, want := range []string{"25,700", "25,699", `"10.0.0.0/24"`, "256 address(es) × 100 port(s) = 25,600", "Lower the scan depth"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("message %q lacks %q", err.Error(), want)
		}
	}
}

// The default budget admits what the product is for and refuses the next step
// up — pinned, because changing it is a product decision.
func TestDefaultMaxJobProbes_Pinned(t *testing.T) {
	check := func(name string, depth string, targets []PlanTargetInput, fits bool) {
		t.Helper()
		plan, err := BuildScanPlan(mustSpec(t, JobRequestFields{ScanDepth: depth}), nil, targets)
		if err != nil {
			t.Fatal(err)
		}
		if got := plan.CheckBudget(DefaultMaxJobProbes) == nil; got != fits {
			t.Errorf("%s: %d probes fits=%v, want %v", name, plan.EstimatedProbes, got, fits)
		}
	}
	check("thorough /24", "thorough", []PlanTargetInput{{Target: "10.0.0.0/24", Class: ClassPrivate}}, true)
	var maxJob []PlanTargetInput
	for _, cidr := range []string{"10.0.0.0/20", "10.1.0.0/20", "10.2.0.0/20", "10.3.0.0/20"} {
		maxJob = append(maxJob, PlanTargetInput{Target: cidr, Class: ClassPrivate})
	}
	check("standard on the largest job", "standard", maxJob, true)
	check("thorough /23", "thorough", []PlanTargetInput{{Target: "10.0.0.0/23", Class: ClassPrivate}}, false)
}

func TestMaxJobProbesFromEnv_FailsClosed(t *testing.T) {
	for raw, want := range map[string]uint64{
		"":                     DefaultMaxJobProbes,
		"1000":                 1000,
		" 2000 ":               2000,
		"abc":                  DefaultMaxJobProbes,
		"0":                    DefaultMaxJobProbes,
		"-5":                   DefaultMaxJobProbes,
		"1e9":                  DefaultMaxJobProbes,
		"99999999999999999999": DefaultMaxJobProbes,
		"2147450881":           DefaultMaxJobProbes, // ceiling + 1
		"2147450880":           MaxJobProbesCeiling,
	} {
		t.Setenv(EnvMaxJobProbes, raw)
		if got := MaxJobProbesFromEnv(); got != want {
			t.Errorf("%s=%q → %d, want %d", EnvMaxJobProbes, raw, got, want)
		}
	}
}

func TestGroupDigits(t *testing.T) {
	for n, want := range map[uint64]string{0: "0", 999: "999", 1000: "1,000", 25000000: "25,000,000", 123456: "123,456"} {
		if got := groupDigits(n); got != want {
			t.Errorf("groupDigits(%d) = %q, want %q", n, got, want)
		}
	}
}

// SNI candidates ride a plan target as an optional, bounded list: what the plan
// records is already valid and at most MaxSNICandidates long, and a target with
// none writes no field at all (an executor that predates it sees an unchanged
// document).
func TestBuildScanPlan_SNICandidatesAreSanitizedAndOptional(t *testing.T) {
	spec := mustSpec(t, JobRequestFields{ScanDepth: "quick"})
	plan, err := BuildScanPlan(spec, nil, []PlanTargetInput{
		{Target: "10.20.30.4", Class: ClassPrivate, SNICandidates: []string{
			"Web.Example.Test", "10.0.0.9", "not a name", "b.example.test", "c.example.test", "d.example.test"}},
		{Target: "10.20.30.5", Class: ClassPrivate},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := plan.Targets[0].SNICandidates, []string{"web.example.test", "b.example.test", "c.example.test"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("candidates = %q, want %q", got, want)
	}
	raw, err := json.Marshal(plan.Targets[1])
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "sni_candidates") {
		t.Errorf("a target with no names serialises the field: %s", raw)
	}
}
