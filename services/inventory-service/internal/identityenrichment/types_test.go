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
	segment, sensor := uuid.New(), uuid.New()
	scope := Scope{SegmentID: segment, SensorID: sensor, CIDR: netip.MustParsePrefix("192.168.3.0/24"), Reachable: true, DNSCapable: true}
	policy := Policy{Enabled: true, AdmissionMode: "enforce", Scan: autoscan.DefaultPolicy()}
	observation := Observation{Evidence: identity.Observation{Identifiers: []identity.Identifier{{Kind: identity.KindHostname, Value: "test.local", Scope: segment.String()}}}}
	if plan, reason := NetworkPlan(observation, policy, scope, nil, nil); reason != "" || plan.Action != "dns" {
		t.Fatalf("DNS plan=%+v %s", plan, reason)
	}
	cases := []struct {
		name   string
		mutate func(*Scope, *Policy)
		reason string
	}{
		{"enrichment disabled", func(_ *Scope, p *Policy) { p.Enabled = false }, "admission_or_enrichment_paused"},
		{"unknown scope", func(s *Scope, _ *Policy) { s.SegmentID = uuid.Nil }, "network_scope_unresolved"},
		{"offline observer", func(s *Scope, _ *Policy) { s.Reachable = false }, "observing_collector_unreachable"},
		{"old collector", func(s *Scope, _ *Policy) { s.DNSCapable = false }, "collector_upgrade_required_identity_dns_v1"},
		{"sensitive", func(s *Scope, _ *Policy) { s.Sensitive = true }, "sensitive_device_requires_review"},
		{"protocol disabled", func(_ *Scope, p *Policy) { p.Scan.Enabled = false }, "automatic_probes_disabled"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, p := scope, policy
			tc.mutate(&s, &p)
			_, reason := NetworkPlan(observation, p, s, nil, nil)
			if reason != tc.reason {
				t.Fatalf("reason=%s", reason)
			}
		})
	}
	policy.ExcludedCIDRs = []string{"192.168.3.2/32"}
	plan, reason := NetworkPlan(observation, policy, scope, []string{"192.168.3.2", "203.0.113.5", "192.168.3.4", "192.168.3.4"}, nil)
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
