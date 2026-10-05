package sensordispatch

import (
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/discovery"
)

const planJobID = "8a2c4e10-9b3d-4f52-8e71-0d6a9c3b1f42"

func samplePlan() *PlanPayload {
	return &PlanPayload{
		Version: PlanPayloadVersion, Attempt: 2, Pace: discovery.PaceNormal, OTProbeProtocols: []string{"Modbus"},
		Targets: []PlanTargetWork{
			{PlanTarget: discovery.PlanTarget{Target: "10.40.0.0/30", Class: discovery.ClassPrivate, TCPPorts: "22,443", UDPPorts: "53"},
				TargetID: "11111111-2222-4333-8444-555555555555", SkipAddresses: []string{"10.40.0.1"}},
			{PlanTarget: discovery.PlanTarget{Target: "app.example.test", Class: discovery.ClassPrivate, TCPPorts: "443"},
				TargetID: "21111111-2222-4333-8444-555555555555", PinnedAddresses: []string{"10.40.1.7", "10.40.1.8"}},
		},
	}
}

// The map a command stores, as the sensor receives it: JSON, so numbers are
// float64 and lists are []interface{}.
func asCommandPayload(t *testing.T, p Payload) map[string]interface{} {
	t.Helper()
	raw, err := json.Marshal(p.ToMap())
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestParsePayload_PlanRoundTrips(t *testing.T) {
	plan := samplePlan()
	got, err := ParsePayload(asCommandPayload(t, Payload{JobID: planJobID, TenantID: "t", Plan: plan}))
	if err != nil {
		t.Fatalf("a plan the platform writes was refused: %v", err)
	}
	if got.Plan == nil || !reflect.DeepEqual(*got.Plan, *plan) {
		t.Fatalf("plan = %+v, want %+v", got.Plan, plan)
	}
	if len(got.Targets) != 0 {
		t.Fatalf("a plan payload carries top-level targets %v", got.Targets)
	}
}

// The silent failure the capability exists to prevent must be impossible even
// if a plan reached a sensor too old to know "plan": such a sensor ignores the
// key, and its strict parser — this one, minus the plan branch — then finds no
// targets and refuses the command as malformed instead of running something
// unrelated with protocols=[].
func TestParsePayload_AnOldSensorRefusesAPlanPayload(t *testing.T) {
	m := asCommandPayload(t, Payload{JobID: planJobID, Plan: samplePlan()})
	delete(m, "plan") // what a sensor that does not know the key sees
	if _, err := ParsePayload(m); !errors.Is(err, ErrMalformedPayload) || !strings.Contains(err.Error(), "targets is empty") {
		t.Fatalf("an old sensor's reading of a plan payload = %v, want a malformed refusal", err)
	}
}

func TestParsePayload_RefusesAMalformedPlan(t *testing.T) {
	for name, mutate := range map[string]func(p *PlanPayload, m map[string]interface{}){
		"unknown version":        func(p *PlanPayload, _ map[string]interface{}) { p.Version = 2 },
		"no attempt":             func(p *PlanPayload, _ map[string]interface{}) { p.Attempt = 0 },
		"bad pace":               func(p *PlanPayload, _ map[string]interface{}) { p.Pace = "ludicrous" },
		"unprobeable OT":         func(p *PlanPayload, _ map[string]interface{}) { p.OTProbeProtocols = []string{"DNP3"} },
		"no targets":             func(p *PlanPayload, _ map[string]interface{}) { p.Targets = nil },
		"target id not a uuid":   func(p *PlanPayload, _ map[string]interface{}) { p.Targets[0].TargetID = "t1" },
		"bad port token":         func(p *PlanPayload, _ map[string]interface{}) { p.Targets[0].TCPPorts = "22,ssh" },
		"no port at all":         func(p *PlanPayload, _ map[string]interface{}) { p.Targets[0].TCPPorts, p.Targets[0].UDPPorts = "", "" },
		"skip not an address":    func(p *PlanPayload, _ map[string]interface{}) { p.Targets[0].SkipAddresses = []string{"host"} },
		"pin not an address":     func(p *PlanPayload, _ map[string]interface{}) { p.Targets[1].PinnedAddresses = []string{"10.0.0.0/24"} },
		"oversize range":         func(p *PlanPayload, _ map[string]interface{}) { p.Targets[0].Target = "10.0.0.0/19" },
		"targets beside a plan":  func(_ *PlanPayload, m map[string]interface{}) { m["targets"] = []interface{}{"10.0.0.1"} },
		"plan is not an object":  func(_ *PlanPayload, m map[string]interface{}) { m["plan"] = "scan everything" },
		"target with empty name": func(p *PlanPayload, _ map[string]interface{}) { p.Targets[0].Target = " " },
	} {
		t.Run(name, func(t *testing.T) {
			p := samplePlan()
			m := map[string]interface{}{}
			mutate(p, m)
			payload := asCommandPayload(t, Payload{JobID: planJobID, Plan: p})
			for k, v := range m {
				payload[k] = v
			}
			if _, err := ParsePayload(payload); !errors.Is(err, ErrMalformedPayload) {
				t.Fatalf("ParsePayload = %v, want ErrMalformedPayload", err)
			}
		})
	}
}

func TestPlanTargetWork_AddressesNeverResolveAndSkipWhatIsAnswered(t *testing.T) {
	p := samplePlan()
	if got := p.Targets[0].Addresses(); !reflect.DeepEqual(got, []string{"10.40.0.0", "10.40.0.2", "10.40.0.3"}) {
		t.Errorf("range addresses = %v", got)
	}
	if got := p.Targets[1].Addresses(); !reflect.DeepEqual(got, []string{"10.40.1.7", "10.40.1.8"}) {
		t.Errorf("hostname addresses = %v, want its pins", got)
	}
	unpinned := PlanTargetWork{PlanTarget: discovery.PlanTarget{Target: "app.example.test"}}
	if got := unpinned.Addresses(); len(got) != 0 {
		t.Errorf("a name with no pins expanded to %v — it must never be resolved", got)
	}
}

func TestUnitResult_RoundTripsAndRefusesWhatTheEngineCannotProduce(t *testing.T) {
	addr := netip.MustParseAddr("10.40.0.2")
	out := discovery.UnitOutput{
		Host: discovery.HostScan{Addr: addr, Liveness: discovery.LivenessUp, LivenessEvidence: "tcp-open:22", PortsRequested: 3, Open: []int{22}, OpenCount: 1, Closed: 1, Filtered: 1},
		TCP:  []discovery.Observation{{Addr: addr, Port: 22, Transport: "tcp", State: "open", Protocol: "SSH", Identified: true}},
	}
	r := NewUnitResult("11111111-2222-4333-8444-555555555555", "10.40.0.2", 2, out)
	raw, _ := json.Marshal(r)
	var back UnitResult
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	got, err := back.Output()
	if err != nil {
		t.Fatalf("Output: %v", err)
	}
	if got.Host.Liveness != discovery.LivenessUp || got.Host.OpenCount != 1 || got.Host.Closed != 1 || len(got.TCP) != 1 || got.TCP[0].Protocol != "SSH" {
		t.Fatalf("round trip = %+v", got)
	}
	if err := (UnitBatch{Units: []UnitResult{back}}).Validate(); err != nil {
		t.Fatalf("a well-formed batch was refused: %v", err)
	}

	for name, mutate := range map[string]func(r *UnitResult){
		"counts do not add up": func(r *UnitResult) { r.Host.PortsRequested = 9 },
		"negative count":       func(r *UnitResult) { r.Host.Closed, r.Host.Filtered = -1, 3 },
		"unknown liveness":     func(r *UnitResult) { r.Host.Liveness = "probably" },
		"another host":         func(r *UnitResult) { r.TCP[0].Addr = netip.MustParseAddr("10.9.9.9") },
		"port 0":               func(r *UnitResult) { r.TCP[0].Port = 0 },
		"not an address":       func(r *UnitResult) { r.Address = "host" },
		"more open than count": func(r *UnitResult) { r.Host.Open = []int{22, 23} },
	} {
		t.Run(name, func(t *testing.T) {
			bad := NewUnitResult("11111111-2222-4333-8444-555555555555", "10.40.0.2", 2, out)
			bad.TCP = append([]discovery.Observation(nil), out.TCP...)
			mutate(&bad)
			if err := (UnitBatch{Units: []UnitResult{bad}}).Validate(); err == nil {
				t.Fatal("refused nothing")
			}
		})
	}
	if err := (UnitBatch{Units: []UnitResult{{TargetID: "x", Address: "10.0.0.1", Attempt: 1}}}).Validate(); err == nil {
		t.Error("a bad target_id was accepted")
	}
	if err := (UnitBatch{Units: []UnitResult{{TargetID: "11111111-2222-4333-8444-555555555555", Address: "10.0.0.1"}}}).Validate(); err == nil {
		t.Error("attempt 0 was accepted")
	}
	if err := (UnitBatch{Units: make([]UnitResult, MaxUnitsPerBatch+1)}).Validate(); err == nil {
		t.Error("an oversize batch was accepted")
	}
}

// The lease is chosen against the sensor's own cadence: many pings, and at
// least five of the slowest heartbeats the platform still calls live.
func TestPlanProgressLease_OutlastsPingsAndHeartbeats(t *testing.T) {
	if PlanProgressLease < 10*PlanProgressInterval {
		t.Errorf("lease %s is under ten pings (%s each)", PlanProgressLease, PlanProgressInterval)
	}
	if PlanProgressLease < LivenessWindow(180) {
		t.Errorf("lease %s is shorter than the liveness window of a 3-minute heartbeat", PlanProgressLease)
	}
	if PlanProgressLease >= ExecutionTimeout {
		t.Errorf("lease %s is not shorter than the fixed timeout it replaces", PlanProgressLease)
	}
}

// A plan target's SNI candidates reach the sensor, and a plan without the field
// (an older platform) still parses: the field is additive, so PlanPayloadVersion
// is unchanged.
func TestParsePayload_SNICandidatesAreCarriedAndOptional(t *testing.T) {
	plan := samplePlan()
	plan.Targets = append(plan.Targets, PlanTargetWork{
		PlanTarget: discovery.PlanTarget{Target: "10.40.2.9", Class: discovery.ClassPrivate, TCPPorts: "443",
			SNICandidates: []string{"web.example.test", "alt.example.test"}},
		TargetID: "31111111-2222-4333-8444-555555555555",
	})
	got, err := ParsePayload(asCommandPayload(t, Payload{JobID: planJobID, TenantID: "t", Plan: plan}))
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"web.example.test", "alt.example.test"}; !reflect.DeepEqual(got.Plan.Targets[2].SNICandidates, want) {
		t.Errorf("candidates = %q, want %q", got.Plan.Targets[2].SNICandidates, want)
	}
	if len(got.Plan.Targets[0].SNICandidates) != 0 {
		t.Errorf("a target with none gained %q", got.Plan.Targets[0].SNICandidates)
	}
}
