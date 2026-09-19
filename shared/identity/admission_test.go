package identity

import (
	"testing"
	"time"
)

func TestAdmissionRequiresEvidenceNotNamesOrConfidence(t *testing.T) {
	base := Observation{TenantID: "tenant", Source: Source{Kind: SourceMeasured, Ref: "sensor:a", Mode: ModePassive}, ObservedAt: time.Now(), Confidence: 1}
	tests := []struct {
		name    string
		ids     []Identifier
		proof   AdmissionEvidence
		scope   string
		dynamic bool
		want    bool
	}{
		{"uuid name", []Identifier{{Kind: KindHostname, Value: "00e73817-b51d-4ab2-a566-486ad75027f2.local"}}, AdmissionEvidence{}, "", false, false},
		{"relayed name and address", []Identifier{{Kind: KindHostname, Value: "printer.local"}, {Kind: KindIPAddress, Value: "192.168.1.2", Scope: "lan"}}, AdmissionEvidence{Direct: true, Relayed: true}, "lan", false, false},
		{"scoped direct unknown device", []Identifier{{Kind: KindIPAddress, Value: "192.168.1.2", Scope: "lan"}}, AdmissionEvidence{Direct: true}, "lan", false, true},
		{"changing address alone", []Identifier{{Kind: KindIPAddress, Value: "192.168.1.2", Scope: "lan"}}, AdmissionEvidence{Direct: true}, "lan", true, false},
		{"bound interface", []Identifier{{Kind: KindIPAddress, Value: "192.168.1.2", Scope: "lan"}, {Kind: KindMACAddress, Value: "02:11:22:33:44:55"}}, AdmissionEvidence{Direct: true}, "lan", true, true},
		{"unscoped interface", []Identifier{{Kind: KindMACAddress, Value: "02:11:22:33:44:55"}}, AdmissionEvidence{Direct: true}, "", false, false},
		{"tenant fallback interface", []Identifier{{Kind: KindMACAddress, Value: "02:11:22:33:44:55"}}, AdmissionEvidence{Direct: true}, ScopeTenantDefault, false, false},
		{"tenant fallback address", []Identifier{{Kind: KindIPAddress, Value: "192.168.1.2", Scope: ScopeTenantDefault}}, AdmissionEvidence{Direct: true}, ScopeTenantDefault, false, false},
		{"authoritative agent without address", []Identifier{{Kind: KindAgentID, Value: "agent-1"}}, AdmissionEvidence{Authoritative: true}, "", false, true},
		{"unverified agent claim", []Identifier{{Kind: KindAgentID, Value: "agent-1"}}, AdmissionEvidence{}, "", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := base
			o.Identifiers = tt.ids
			o.Admission = tt.proof
			o.Network.SegmentID = tt.scope
			o.DynamicScopes = map[string]bool{"lan": tt.dynamic}
			got := AssessAdmission(o)
			if got.Established != tt.want || len(got.Reasons) == 0 {
				t.Fatalf("admission = %+v, want established=%v", got, tt.want)
			}
		})
	}
}

func TestObservationGroupingIsNotCorroboration(t *testing.T) {
	a := Observation{TenantID: "one", Source: Source{Kind: SourceMeasured, Ref: "sensor:a"}, ObservedAt: time.Unix(123, 0), Identifiers: []Identifier{{Kind: KindHostname, Value: "host.local"}, {Kind: KindHostname, Value: "host"}}}
	b := a
	b.Identifiers = []Identifier{{Kind: KindHostname, Value: "host"}}
	if ObservationFingerprint(a) != ObservationFingerprint(b) {
		t.Fatal("alternate spelling inflated observation groups")
	}
	b.Source.Ref = "sensor:b"
	if ObservationFingerprint(a) == ObservationFingerprint(b) {
		t.Fatal("independent sources lost their provenance")
	}
	b = a
	b.ObservedAt = b.ObservedAt.Add(time.Second)
	if ObservationFingerprint(a) != ObservationFingerprint(b) || ObservationReceiptKey(a) == ObservationReceiptKey(b) {
		t.Fatal("sighting and replay are not distinguished")
	}
	a.Admission.ReceiptID = "delivery-1"
	b.Admission.ReceiptID = "delivery-1"
	if ObservationReceiptKey(a) != ObservationReceiptKey(b) {
		t.Fatal("a delivery retry with an intake clock became another sighting")
	}
}
