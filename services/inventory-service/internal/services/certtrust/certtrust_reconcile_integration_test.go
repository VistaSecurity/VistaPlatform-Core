package certtrust_test

import (
	"context"
	"sync"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services/certtrust"
)

type recordedJob struct {
	tenant uuid.UUID
	reason string
}

type fakeReconcile struct {
	mu   sync.Mutex
	jobs []recordedJob
}

func (f *fakeReconcile) PublishComplianceReconcile(_ context.Context, tenantID uuid.UUID, reason string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.jobs = append(f.jobs, recordedJob{tenantID, reason})
	return nil
}

func (f *fakeReconcile) take() []recordedJob {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := f.jobs
	f.jobs = nil
	return out
}

// TestIntegration_TrustDecisionPublishesOneReconcile: each decision change
// asks compliance-engine for exactly ONE reconcile of the tenant — not one per
// re-evaluated certificate — with reason certificate_trust_changed; a
// note-only edit asks for none.
func TestIntegration_TrustDecisionPublishesOneReconcile(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	pub := &fakeReconcile{}
	f.store.SetReconcilePublisher(pub)

	root := issue(t, "Example Reconcile Root", true, nil)
	inter := issue(t, "Example Reconcile Issuing CA", true, &root)
	leafA := issue(t, "a.example.test", false, &inter)
	leafB := issue(t, "b.example.test", false, &inter)
	ids := f.ingest(t, leafA.cert, inter.cert, root.cert)
	f.ingest(t, leafB.cert, inter.cert)
	rootID := ids[2]
	pub.take() // ingest is not a decision

	wantOne := func(step string) {
		t.Helper()
		jobs := pub.take()
		if len(jobs) != 1 {
			t.Fatalf("%s: %d reconcile job(s), want exactly 1", step, len(jobs))
		}
		if jobs[0].tenant != f.tenant || jobs[0].reason != certtrust.ReconcileReason {
			t.Errorf("%s: job %+v, want tenant %s reason %s", step, jobs[0], f.tenant, certtrust.ReconcileReason)
		}
	}

	a, err := f.store.CreateAnchor(ctx, f.tenant, certtrust.CreateRequest{CertificateID: &rootID, Decision: certtrust.DecisionTrusted})
	if err != nil {
		t.Fatalf("CreateAnchor: %v", err)
	}
	wantOne("create")

	note := "ticket 42"
	if _, err := f.store.UpdateAnchor(ctx, f.tenant, a.ID, certtrust.UpdateRequest{Note: &note}); err != nil {
		t.Fatalf("UpdateAnchor(note): %v", err)
	}
	if jobs := pub.take(); len(jobs) != 0 {
		t.Errorf("note-only edit published %d reconcile job(s), want 0", len(jobs))
	}

	d := certtrust.DecisionDistrusted
	if _, err := f.store.UpdateAnchor(ctx, f.tenant, a.ID, certtrust.UpdateRequest{Decision: &d}); err != nil {
		t.Fatalf("UpdateAnchor(decision): %v", err)
	}
	wantOne("change decision")

	if err := f.store.DeleteAnchor(ctx, f.tenant, a.ID); err != nil {
		t.Fatalf("DeleteAnchor: %v", err)
	}
	wantOne("delete")

	if _, err := f.store.CreateAnchorFromChain(ctx, f.tenant, certtrust.FromChainRequest{
		ChainPEM: pemOf(leafA.cert, inter.cert, root.cert), Decision: certtrust.DecisionTrusted,
	}); err != nil {
		t.Fatalf("CreateAnchorFromChain: %v", err)
	}
	wantOne("from-chain")
}
