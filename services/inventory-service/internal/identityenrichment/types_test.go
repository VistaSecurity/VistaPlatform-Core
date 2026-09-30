package identityenrichment

import (
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/autoscan"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

func TestNetworkPlanRequiresScopeAuthorizationAndCollector(t *testing.T) {
	segment, sensor, observer := uuid.New(), uuid.New(), uuid.New()
	scope := Scope{SegmentID: segment, SensorID: sensor, ObserverSensorID: observer, CIDR: netip.MustParsePrefix("192.168.3.0/24"), Reachable: true, DNSCapable: true}
	policy := Policy{Enabled: true, AdmissionMode: "enforce", Scan: autoscan.DefaultPolicy()}
	observation := Observation{Evidence: identity.Observation{Identifiers: []identity.Identifier{{Kind: identity.KindHostname, Value: "test.local", Scope: segment.String()}}}}
	plan, reason := NetworkPlan(observation, policy, scope, nil, nil)
	if reason != "" || plan.Action != "dns" {
		t.Fatalf("DNS plan=%+v %s", plan, reason)
	}
	// D4: the plan dispatches to the EXECUTOR and records the OBSERVER.
	// One field for both is what made a cross-VLAN advert permanently
	// unenrichable, so a plan that loses either half is the bug returning.
	if plan.SensorID != sensor || plan.Executor != "sensor:"+sensor.String() || plan.ObserverSensorID != observer {
		t.Fatalf("plan lost an executor/observer half: %+v", plan)
	}
	cases := []struct {
		name   string
		mutate func(*Scope, *Policy)
		reason string
	}{
		{"enrichment disabled", func(_ *Scope, p *Policy) { p.Enabled = false }, "admission_or_enrichment_paused"},
		{"unknown scope", func(s *Scope, _ *Policy) { s.SegmentID = uuid.Nil }, "network_scope_unresolved"},
		{"no eligible executor", func(s *Scope, _ *Policy) { s.Reachable = false }, ReasonNoEligibleCollector},
		{"no executor selected", func(s *Scope, _ *Policy) { s.SensorID = uuid.Nil }, ReasonNoEligibleCollector},
		{"unreachable observer alone does not block", func(s *Scope, _ *Policy) {
			s.ObserverReachable, s.ObserverReason = false, "collector_has_no_interface_in_target_network"
		}, ""},
		{"old collector", func(s *Scope, _ *Policy) { s.DNSCapable = false }, "collector_upgrade_required_identity_dns_v1"},
		{"sensitive", func(s *Scope, _ *Policy) { s.Sensitive = true }, "sensitive_device_requires_review"},
		{"protocol disabled", func(_ *Scope, p *Policy) { p.Scan.Enabled = false }, "automatic_probes_disabled"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, p := scope, policy
			tc.mutate(&s, &p)
			plan, reason := NetworkPlan(observation, p, s, nil, nil)
			if reason != tc.reason {
				t.Fatalf("reason=%s", reason)
			}
			if plan.ObserverSensorID != observer {
				t.Fatalf("blocked plan lost its observer: %+v", plan)
			}
		})
	}
	policy.ExcludedCIDRs = []string{"192.168.3.2/32"}
	plan, reason = NetworkPlan(observation, policy, scope, []string{"192.168.3.2", "203.0.113.5", "192.168.3.4", "192.168.3.4"}, nil)
	if reason != "" || plan.Action != "probe" || len(plan.Addresses) != 1 || plan.Addresses[0] != "192.168.3.4" {
		t.Fatalf("bounded probe=%+v %s", plan, reason)
	}
}
func TestGenerationIgnoresRepeatedSightingsButIncludesUsefulEvidence(t *testing.T) {
	o := Observation{Evidence: identity.Observation{ObservedAt: time.Now(), Hostname: "Host.local", DisplayName: "Host.local", Admission: identity.AdmissionEvidence{ReceiptID: "first"}, Identifiers: []identity.Identifier{{Kind: identity.KindHostname, Value: "host"}}}}
	first := Generation(o)
	o.Evidence.ObservedAt = o.Evidence.ObservedAt.Add(time.Hour)
	o.Evidence.Admission.ReceiptID = "second"
	o.Evidence.Hostname = "HOST."
	o.Evidence.DisplayName = "host"
	if Generation(o) != first {
		t.Fatal("delivery clock became new work")
	}
	o.Evidence.Identifiers = append(o.Evidence.Identifiers, identity.Identifier{Kind: identity.KindHostname, Value: "host.local", SeenAt: time.Now()})
	if Generation(o) != first {
		t.Fatal("alternate hostname spelling became independent work")
	}
	o.Evidence.Identifiers = append(o.Evidence.Identifiers, identity.Identifier{Kind: identity.KindMACAddress, Value: "00:11:22:33:44:55"})
	if Generation(o) == first {
		t.Fatal("new interface evidence did not become eligible")
	}
}

// A name crossing the tenant-frequency threshold between two sightings, a
// builder's confidence changing, or the engine stamping provenance on an
// identifier is the SAME evidence: the generation must not change, or it
// schedules a redundant probe ( B2). A different value still does.
//
// Mutation checks: stop zeroing Generic, Confidence or Source in Generation →
// the matching case fails.
func TestGenerationIgnoresPerObservationIdentifierAnnotations(t *testing.T) {
	base := func() Observation {
		return Observation{Evidence: identity.Observation{
			Source: identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:a"},
			Identifiers: []identity.Identifier{
				{Kind: identity.KindHostname, Value: "iphone", Scope: "seg-1", Confidence: 1},
				{Kind: identity.KindIPAddress, Value: "192.0.2.5", Scope: "seg-1", Confidence: 1},
			},
		}}
	}
	want := Generation(base())
	for _, tc := range []struct {
		name   string
		mutate func(*identity.Identifier)
	}{
		{"marked generic", func(id *identity.Identifier) { id.Generic = true; id.Confidence = identity.GenericConfidence }},
		{"generic flag alone", func(id *identity.Identifier) { id.Generic = true }},
		{"confidence alone", func(id *identity.Identifier) { id.Confidence = 0.5 }},
		{"engine provenance", func(id *identity.Identifier) {
			id.Source = identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:a", Mode: identity.ModePassive}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o := base()
			tc.mutate(&o.Evidence.Identifiers[0])
			if got := Generation(o); got != want {
				t.Errorf("generation changed on a per-observation annotation: %s != %s", got, want)
			}
		})
	}
	o := base()
	o.Evidence.Identifiers[0].Value = "desk-phone"
	if Generation(o) == want {
		t.Error("a different hostname value did not change the generation")
	}
}

func TestPolicyRequiresExplicitEnrichmentAndEnforcement(t *testing.T) {
	for _, raw := range []string{`{}`, `{"identity_enrichment":{"enabled":true}}`, `{"identity_enrichment":{"enabled":true},"identity_admission":{"mode":"paused"}}`} {
		p, err := ParsePolicy([]byte(raw))
		if err != nil || p.Active() {
			t.Fatalf("policy=%+v err=%v", p, err)
		}
	}
	if _, err := ParsePolicy([]byte(`{"identity_enrichment":{"excluded_cidrs":["bad"]}}`)); err == nil {
		t.Fatal("malformed exclusion silently accepted")
	}
}
