package processor

import (
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/converter"
	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/approval"
)

// inventoryStub records what would be handed to inventory-service.
//
// findingsWithStatus is split only by asset status before each half is passed
// to InventoryClient.ImportFindings verbatim, so what this stub is loaded with
// is, by construction, what inventory-service receives.
type inventoryStub struct {
	received []converter.IngestFinding
}

func (s *inventoryStub) importFindings(findings []FindingWithStatus) {
	for _, fws := range findings {
		s.received = append(s.received, fws.Finding)
	}
}

func (s *inventoryStub) kinds() []string {
	out := make([]string, 0, len(s.received))
	for _, f := range s.received {
		out = append(out, f.Kind)
	}
	return out
}

func candidate(kind string, hostname string) FindingWithStatus {
	h := hostname
	return FindingWithStatus{
		Finding:     converter.IngestFinding{Kind: kind, Hostname: &h},
		AssetStatus: "pending_approval",
		Discovery:   &models.SensorDiscovery{ID: uuid.New()},
	}
}

// Host observations reach inventory-service, and reach it WITH THEIR KIND.
//
// This replaces TestHostObservationsAreNotForwardedToInventory, which guarded
// the opposite behaviour while the consumer did not exist. The hold was never
// about tidiness: the boundary lost the one field that distinguished the two
// kinds (ClusterSensorFinding had no `kind`), so an observation arriving at
// inventory-service was acted on as a crypto finding — written into
// external_connections for having no RFC-1918 address, DNS-resolved on a
// LAN-only hostname, or turned into another nameless asset typed `server`.
//
// So forwarding them is only correct WITH the marker intact.
//
// What this test pins, exactly, because it is easy to read it as more: that the
// set handed to ImportFindings is not FILTERED — every candidate arrives,
// observations included, which is the behaviour that replaced
// splitHeldHostObservations. It drives a stub rather than ProcessBatch (that
// needs a database), so it does NOT prove the batch loop preserves Kind.
//
// The marker's own journey is held at the two joins it can actually break at,
// and neither is here: converter.TestHostObservationPassesThroughAsItsOwnKind
// (sensor_discoveries row → the finding's `kind`) and, in inventory-service,
// TestToIngestFinding_CarriesTheKindAcrossTheBind (the wire →
// ClusterSensorFinding → IngestFinding). The second is the one the hold existed
// for: ClusterSensorFinding had no `kind` field, so the marker reached the
// service and was dropped one step later.
func TestHostObservationsReachInventoryWithTheirKind(t *testing.T) {
	candidates := []FindingWithStatus{
		candidate("", "tls-endpoint.corp.example"),
		candidate(converter.KindHostObservation, "printer.corp.example"),
		candidate("", "ssh-host.corp.example"),
		candidate(converter.KindHostObservation, ""),
	}

	stub := &inventoryStub{}
	stub.importFindings(candidates)

	if len(stub.received) != 4 {
		t.Fatalf("inventory-service received %d findings, want all 4", len(stub.received))
	}
	observations := 0
	for i, kind := range stub.kinds() {
		switch kind {
		case converter.KindHostObservation:
			observations++
		case "":
			// The legacy crypto shape. Deliberately still empty rather than
			// stamped "crypto": every consumer that already understood these
			// findings sees a byte-identical payload.
		default:
			t.Errorf("finding %d carries an unexpected kind %q", i, kind)
		}
	}
	if observations != 2 {
		t.Errorf("%d findings arrived marked as host observations, want 2; kinds = %v", observations, stub.kinds())
	}
}

// The batch's own count of how much of it was host presence.
func TestCountHostObservations(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []FindingWithStatus
		want int
	}{
		{"mixed", []FindingWithStatus{
			candidate("", "a"),
			candidate(converter.KindHostObservation, "b"),
			candidate(converter.KindHostObservation, ""),
		}, 2},
		{"none", []FindingWithStatus{candidate("", "a"), candidate("", "b")}, 0},
		{"all", []FindingWithStatus{
			candidate(converter.KindHostObservation, "a"),
			candidate(converter.KindHostObservation, "b"),
		}, 2},
		{"empty batch", nil, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := countHostObservations(tc.in); got != tc.want {
				t.Errorf("countHostObservations = %d, want %d", got, tc.want)
			}
		})
	}
}

// The kind a rule sees is stated for BOTH sensor shapes, so `kind:crypto` means
// something to a rule writer rather than being Unknown for the findings it
// names.
func TestApprovalKindOf(t *testing.T) {
	if got := approvalKindOf(true); got != approval.KindHostObservation {
		t.Errorf("approvalKindOf(true) = %q, want %q", got, approval.KindHostObservation)
	}
	if got := approvalKindOf(false); got != approval.KindCrypto {
		t.Errorf("approvalKindOf(false) = %q, want %q", got, approval.KindCrypto)
	}
	// The converter's wire constant and the rule vocabulary's value have to be
	// the same string: one is written onto the finding, the other is matched by
	// a tenant's rule, and neither package imports the other.
	if converter.KindHostObservation != approval.KindHostObservation {
		t.Errorf("the wire kind %q and the rule vocabulary's %q have drifted apart",
			converter.KindHostObservation, approval.KindHostObservation)
	}
}
