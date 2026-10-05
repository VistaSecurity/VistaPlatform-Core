package identity_test

import (
	"context"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/identity/memory"
)

// A person's scan of a named asset (operator_scan.go). The inventory-service
// integration tests drive the whole path, including the server-side checks
// that decide whether a request exists at all; these pin the engine's half on
// the PR gate, where no database runs.

const operatorScanSegment = "dhcp-lan"

func operatorScanEngine(t *testing.T) (*identity.Engine, identity.AssetRef, *memory.Repository) {
	t.Helper()
	e, repo := newEngine(t, identity.Config{DynamicScopes: map[string]bool{operatorScanSegment: true}})
	ref, err := repo.CreateAsset(context.Background(), tenant, identity.NewAsset{
		ClassKey: "server", Hostname: "laptop-7", Status: identity.StatusMonitoring,
		Source:      identity.Source{Kind: identity.SourceDeclared, Ref: "manual"},
		Identifiers: []identity.Identifier{scoped(identity.KindHostname, "laptop-7", operatorScanSegment), id(identity.KindMACAddress, "00:00:5e:00:53:07")},
		FirstSeenAt: observedAt, LastSeenAt: observedAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	return e, ref, repo
}

func scanObservation(ids ...identity.Identifier) identity.Observation {
	o := obs("", append([]identity.Identifier{scoped(identity.KindIPAddress, "192.0.2.7", operatorScanSegment)}, ids...)...)
	o.Source = identity.Source{Kind: identity.SourceMeasured, Ref: "scan:sensor-1", Mode: identity.ModeActive}
	return o
}

func TestOperatorScanRequestLinksTheNamedAsset(t *testing.T) {
	// Without the request, a dynamic address decides nothing and the
	// observation is not the asset's.
	e, ref, _ := operatorScanEngine(t)
	if res := mustResolve(t, e, scanObservation()); res.Asset.ID == ref.ID {
		t.Fatalf("without a request the scan resolved onto %s (%s)", ref.ID, res.Outcome)
	}

	e2, ref2, repo2 := operatorScanEngine(t)
	req := identity.OperatorScanRequest{Asset: ref2, Address: "192.0.2.7", JobID: "job-1"}
	res := mustResolve(t, e2.WithOperatorScanRequest(req), scanObservation())
	if res.Outcome != identity.OutcomeMatched || res.Asset.ID != ref2.ID || res.OperatorScanJob != "job-1" || res.OperatorScanRefused != "" {
		t.Fatalf("resolution %+v, want matched on %s by job-1", res, ref2.ID)
	}
	var found bool
	for _, h := range repo2.HistoryFor(ref2) {
		if h.Changes["decided_by"] == identity.DecidedByOperatorScanRequest && h.Changes["operator_scan_job"] == "job-1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no timeline entry decided_by=%s: %+v", identity.DecidedByOperatorScanRequest, repo2.HistoryFor(ref2))
	}
}

func TestOperatorScanRequestRefusedWhenTheDeviceDisagrees(t *testing.T) {
	e, ref, _ := operatorScanEngine(t)
	req := identity.OperatorScanRequest{Asset: ref, Address: "192.0.2.7", JobID: "job-1"}
	o := scanObservation(id(identity.KindMACAddress, "00:00:5e:00:53:99"))
	o.Admission.Direct = true
	res := mustResolve(t, e.WithOperatorScanRequest(req), o)
	if res.Asset.ID == ref.ID || res.OperatorScanJob != "" {
		t.Fatalf("a scan that met another MAC was attached to the scanned asset: %+v", res)
	}
	if res.OperatorScanRefused == "" {
		t.Fatalf("resolution %+v carries no refusal reason", res)
	}
}

func TestOperatorScanRequestRefusedForAnotherAddress(t *testing.T) {
	e, ref, _ := operatorScanEngine(t)
	req := identity.OperatorScanRequest{Asset: ref, Address: "192.0.2.8", JobID: "job-1"}
	res := mustResolve(t, e.WithOperatorScanRequest(req), scanObservation())
	if res.Asset.ID == ref.ID || res.OperatorScanRefused == "" {
		t.Fatalf("a scan of another address was attached: %+v", res)
	}
}

func TestOperatorScanRequestZeroIsNoRequest(t *testing.T) {
	e, _, _ := operatorScanEngine(t)
	if got := e.WithOperatorScanRequest(identity.OperatorScanRequest{}); got != e {
		t.Fatal("a zero request must return the engine unchanged")
	}
}
