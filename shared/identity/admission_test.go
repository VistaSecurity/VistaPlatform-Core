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

// TestAdmissionTreatsAPinnedAddressAsStatic: an address whose owner holds it
// pinned binds a direct sighting inside a dynamic scope exactly as an
// address in a static segment does; any other address in that scope still
// does not. obs.pinned is what Engine.Resolve fills from the store.
//
// Mutation check: drop `&& !obs.addressPinned(id)` from AssessAdmission → the
// pinned case is refused with dynamic_address_without_device_binding.
func TestAdmissionTreatsAPinnedAddressAsStatic(t *testing.T) {
	addr := Identifier{Kind: KindIPAddress, Value: "192.0.2.1", Scope: "lan"}
	o := Observation{
		TenantID: "tenant", Source: Source{Kind: SourceMeasured, Ref: "sensor:a"}, ObservedAt: time.Now(), Confidence: 1,
		Identifiers: []Identifier{addr}, Admission: AdmissionEvidence{Direct: true},
		Network: Network{SegmentID: "lan"}, DynamicScopes: map[string]bool{"lan": true},
	}
	if got := AssessAdmission(o); got.Established || got.Reasons[0] != ReasonDynamicAddressWithoutDeviceBinding {
		t.Fatalf("unpinned: admission = %+v, want refused as a dynamic address", got)
	}
	o.pinned = map[string]bool{addr.Key(): true}
	if got := AssessAdmission(o); !got.Established || got.Reasons[0] != "direct_scoped_address" {
		t.Fatalf("pinned: admission = %+v, want established as a direct scoped address", got)
	}
	o.pinned = map[string]bool{Identifier{Kind: KindIPAddress, Value: "192.0.2.9", Scope: "lan"}.Key(): true}
	if got := AssessAdmission(o); got.Established {
		t.Fatalf("a pin on another address established this one: %+v", got)
	}
}

// TestAdmissionTreatsALeaseFreshAddressAsStatic: a lease-fresh address
// (leasefresh.go) establishes exactly as a pinned one does, and only for the
// address it names.
// Mutation: drop addressLeaseFresh from AssessAdmission's dynamic test → the
// fresh address is refused as a dynamic address.
func TestAdmissionTreatsALeaseFreshAddressAsStatic(t *testing.T) {
	addr := Identifier{Kind: KindIPAddress, Value: "192.0.2.1", Scope: "lan"}
	o := Observation{
		TenantID: "tenant", Source: Source{Kind: SourceMeasured, Ref: "sensor:a"}, ObservedAt: time.Now(), Confidence: 1,
		Identifiers: []Identifier{addr}, Admission: AdmissionEvidence{Direct: true},
		Network: Network{SegmentID: "lan"}, DynamicScopes: map[string]bool{"lan": true},
	}
	if got := AssessAdmission(o); got.Established {
		t.Fatalf("not fresh: admission = %+v, want refused as a dynamic address", got)
	}
	o.leaseFresh = map[string]bool{addr.Key(): true}
	if got := AssessAdmission(o); !got.Established || got.Reasons[0] != "direct_scoped_address" {
		t.Fatalf("lease-fresh: admission = %+v, want established as a direct scoped address", got)
	}
	o.leaseFresh = map[string]bool{Identifier{Kind: KindIPAddress, Value: "192.0.2.9", Scope: "lan"}.Key(): true}
	if got := AssessAdmission(o); got.Established {
		t.Fatalf("a fresh lease on another address established this one: %+v", got)
	}
}

// TestObservationFingerprintGroupsByOrigin: a source whose Ref changes every
// run (`interrogation:<job>`) groups by its Origin (the interrogated device),
// so a repeat run is another receipt of the same observation rather than a
// new row per client per run. A source without an Origin fingerprints exactly
// as before the field existed — pinned to the pre-change digests, because a
// changed fingerprint would orphan every stored row on upgrade.
func TestObservationFingerprintGroupsByOrigin(t *testing.T) {
	base := Observation{TenantID: "11111111-1111-1111-1111-111111111111", Source: Source{Kind: SourceMeasured, Ref: "sensor:a", Mode: ModeActive}, Network: Network{SegmentID: "seg-1", Ownership: "internal"}, ObservedAt: time.Unix(123, 0), Identifiers: []Identifier{{Kind: KindMACAddress, Value: "aa:bb:cc:dd:ee:ff"}, {Kind: KindHostname, Value: "host", Scope: "seg-1"}}}
	if got := ObservationFingerprint(base); got != "40289542dafad324e36034455c3669fd34b1e74ba4d9783cc109624847083902" {
		t.Fatalf("sensor fingerprint changed: %s — every stored observation would be orphaned on upgrade", got)
	}
	runA := base
	runA.Source = Source{Kind: SourceMeasured, Ref: "interrogation:4ae89a36-9d88-41b7-a4d8-933c13c79c92", Mode: ModeActive}
	if got := ObservationFingerprint(runA); got != "f1dbe30db4ebb245ac44f6b613c5c4f329a771c99a5fec67b187e6c23db4f203" {
		t.Fatalf("origin-less interrogation fingerprint changed: %s", got)
	}
	runB := runA
	runB.Source.Ref = "interrogation:6f0d263e-6e57-4b45-a4b7-010ec3abffae"
	runB.ObservedAt = runA.ObservedAt.Add(24 * time.Hour)
	if ObservationFingerprint(runA) == ObservationFingerprint(runB) {
		t.Fatal("two runs with no origin must still be separate: the ref is all there is")
	}
	runA.Source.Origin, runB.Source.Origin = "device:4c6eda4a", "device:4c6eda4a"
	if ObservationFingerprint(runA) != ObservationFingerprint(runB) {
		t.Fatal("two runs of the same device must group as one observation")
	}
	if ObservationReceiptKey(runA) == ObservationReceiptKey(runB) {
		t.Fatal("two runs of the same device are two sightings, not a replay")
	}
	other := runB
	other.Source.Origin = "device:ffffffff"
	if ObservationFingerprint(runA) == ObservationFingerprint(other) {
		t.Fatal("two devices reporting the same client must stay separate")
	}
	if ObservationFingerprint(runA) == ObservationFingerprint(base) {
		t.Fatal("an origin must not collide with a sensor's ref")
	}
}
