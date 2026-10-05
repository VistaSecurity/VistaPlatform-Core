package services

import (
	"reflect"
	"testing"

	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/models"
	shareddisc "github.com/vistasecurity/vistaplatform/shared/discovery"
)

// A stored identity probe answers a request with its request ID when the
// fingerprints match, or when it is the same probe in another request shape
// (a probe dispatched before the WP4 upgrade and retried after it).
// Every other difference is still refused.
func TestStoredIdentityProbe_Answers(t *testing.T) {
	const sensor, obs = "00000000-0000-4000-8000-0000000000a1", "00000000-0000-4000-8000-0000000000b1"
	stored := storedIdentityProbe{fingerprint: "f-legacy", sensors: []string{sensor}, observation: obs,
		targets: []string{"10.0.0.20"}, ports: []int64{22, 443}}
	same := identityProbeRequest{sensor: sensor, observation: obs, targets: []string{"10.0.0.20"}, ports: []int{22, 443}}
	with := func(mut func(*identityProbeRequest)) identityProbeRequest {
		in := same
		mut(&in)
		return in
	}
	cases := []struct {
		name string
		fp   string
		in   identityProbeRequest
		want bool
	}{
		{"same fingerprint", "f-legacy", identityProbeRequest{}, true},
		{"other shape, same probe", "f-planned", same, true},
		{"other targets", "f-planned", with(func(r *identityProbeRequest) { r.targets = []string{"10.0.0.21"} }), false},
		{"other ports", "f-planned", with(func(r *identityProbeRequest) { r.ports = []int{443} }), false},
		{"other sensor", "f-planned", with(func(r *identityProbeRequest) { r.sensor = "00000000-0000-4000-8000-0000000000a2" }), false},
		{"other observation", "f-planned", with(func(r *identityProbeRequest) { r.observation = "x" }), false},
		{"no sensor named", "f-planned", with(func(r *identityProbeRequest) { r.sensor = "" }), false},
		{"no ports", "f-planned", with(func(r *identityProbeRequest) { r.ports = nil }), false},
	}
	for _, tc := range cases {
		s := stored
		if tc.name == "no ports" {
			s.ports = nil
		}
		if got := s.answers(tc.fp, tc.in); got != tc.want {
			t.Errorf("%s: answers = %v, want %v", tc.name, got, tc.want)
		}
	}
	twoSensors := stored
	twoSensors.sensors = []string{sensor, sensor}
	if twoSensors.answers("f-planned", same) {
		t.Error("a job stored for two sensors answered a one-sensor probe")
	}
}

// The incoming probe is read the same way from either request shape.
func TestIncomingIdentityProbe_SameProbeEitherShape(t *testing.T) {
	const sensor = "00000000-0000-4000-8000-0000000000a1"
	opts := map[string]interface{}{"identity_observation_id": "obs"}
	legacy := models.CreateDiscoveryJobRequest{Targets: []string{"10.0.0.20"}, ExecutionMode: "sensors", PreferredSensorIDs: []string{sensor},
		Protocols: []string{"TLS", "SSH"}, Ports: []int{443, 22}, Options: opts}
	planned := models.CreateDiscoveryJobRequest{Targets: []string{"10.0.0.20"}, ExecutionMode: "sensors", PreferredSensorIDs: []string{sensor},
		ScanDepth: "custom", TCPPorts: "443,22", Options: opts}
	ls, err := shareddisc.ResolveJobRequest(jobRequestFields(legacy, false))
	if err != nil {
		t.Fatal(err)
	}
	ps, err := shareddisc.ResolveJobRequest(jobRequestFields(planned, false))
	if err != nil {
		t.Fatal(err)
	}
	a, b := incomingIdentityProbe(ls, legacy), incomingIdentityProbe(ps, planned)
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("legacy %+v != planned %+v", a, b)
	}
}

func legacyRequest() models.CreateDiscoveryJobRequest {
	return models.CreateDiscoveryJobRequest{
		Targets: []string{"10.0.0.5"}, Protocols: []string{"TLS"}, Ports: []int{443, 22},
		ExecutionMode: "async", Options: map[string]interface{}{"active_scan": true},
	}
}

// Every legacy request that names ports is planned: there is no switch and no
// legacy executor to leave it to ( WP5).
func TestTranslateLegacyRequest_PlansThePorts(t *testing.T) {
	req := legacyRequest()
	if !translateLegacyRequest(&req, false, nil) {
		t.Fatal("a protocols × ports request was not translated")
	}
	want := models.CreateDiscoveryJobRequest{
		Targets: []string{"10.0.0.5"}, ScanDepth: "custom", TCPPorts: "443,22", RunFrom: "platform",
		Options: map[string]interface{}{"active_scan": true},
	}
	if !reflect.DeepEqual(req, want) {
		t.Fatalf("translated request = %+v, want %+v", req, want)
	}
}

// An OT-only request becomes a custom plan on exactly its OT ports and keeps
// its opt-in, so the engine probes those protocols there ( WP5). With the
// switch having dropped every probe it is left as it was: CreateJob refuses it
// rather than scan nothing.
func TestTranslateLegacyRequest_OTOnlyPlansItsStandardPorts(t *testing.T) {
	req := models.CreateDiscoveryJobRequest{Targets: []string{"10.0.0.5"}, OTProbeProtocols: []string{"modbus", "BACnet"}}
	if !translateLegacyRequest(&req, false, []string{"Modbus", "BACnet"}) {
		t.Fatal("an OT-only request was not translated")
	}
	want := models.CreateDiscoveryJobRequest{Targets: []string{"10.0.0.5"}, OTProbeProtocols: []string{"modbus", "BACnet"},
		ScanDepth: "custom", TCPPorts: "502", UDPPorts: "47808", RunFrom: "platform"}
	if !reflect.DeepEqual(req, want) {
		t.Fatalf("translated request = %+v, want %+v", req, want)
	}
	shape, err := shareddisc.ResolveJobRequest(jobRequestFields(req, false))
	if err != nil || !shape.Plan {
		t.Fatalf("translated OT request does not resolve to a plan: %+v %v", shape, err)
	}

	off := models.CreateDiscoveryJobRequest{Targets: []string{"10.0.0.5"}, OTProbeProtocols: []string{"Modbus"}}
	if translateLegacyRequest(&off, false, nil) {
		t.Fatal("an OT-only request whose probes were all switched off was translated into a plan")
	}
}
