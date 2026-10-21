package jobs

// Change notifications for work with no HTTP request around it: the real
// background passes (RunCableResolverPass, StartIdentityEvidenceWorker) run
// under a context carrying a change notifier, their per-tenant work records a
// change through the real recorder in a tenant transaction, and the event is
// raised once it has committed. Skipped unless TEST_DATABASE_URL is set.
//
// Mutations (each turns a test here red): drop the changenotify.Unit wrapper
// in RunCableResolverPass (call r.ResolveParked(ctx, tenant) directly); the
// same in StartIdentityEvidenceWorker.

import (
	"context"
	"database/sql"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changenotify"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
	"github.com/vistasecurity/vistaplatform/shared/dcim/unresolved"
	"github.com/vistasecurity/vistaplatform/shared/events"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

type jobRaised struct {
	mu  sync.Mutex
	evs []events.AlertRaiseEvent
}

func (r *jobRaised) Raise(ev events.AlertRaiseEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.evs = append(r.evs, ev)
	return nil
}

func (r *jobRaised) take() []events.AlertRaiseEvent {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.evs
	r.evs = nil
	return out
}

// jobChangeFix is a tenant with an Inventory-changes rule that includes
// intake, and a notifier on a background context, as main() sets it up.
type jobChangeFix struct {
	db     *sql.DB
	tenant uuid.UUID
	pub    *jobRaised
	ctx    context.Context
}

func newJobChangeFix(t *testing.T) jobChangeFix {
	t.Helper()
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db)
	testdb.RetryTransient(t, func() error {
		_, err := db.Exec(`
			INSERT INTO tenant_notification_rules (tenant_id, rule_name, alert_source, alert_type, channel_ids, change_filter, enabled)
			VALUES ($1, 'Cable changes', 'inventory-service', 'object_changed', ARRAY[gen_random_uuid()], '{"include_intake": true}'::jsonb, true)`, tenant)
		return err
	})
	pub := &jobRaised{}
	n := changenotify.New(db)
	n.SetPublisher(pub)
	return jobChangeFix{db: db, tenant: tenant, pub: pub, ctx: changenotify.WithNotifier(context.Background(), n)}
}

// proposeCable is what a resolver pass does for a parked neighbour: a cable
// filed in the tenant's own transaction, recorded as LLDP intake.
func (f jobChangeFix) proposeCable(ctx context.Context, tenant uuid.UUID, label string) (uuid.UUID, error) {
	id := uuid.New()
	ctx = changes.WithSource(ctx, changes.IntakeSource("lldp"))
	err := database.WithTenantTx(ctx, f.db, tenant, func(tx *sql.Tx) error {
		return changes.InTx(tx).Record(ctx, changes.Change{
			TenantID: tenant, Kind: dcim.ObjectKindCable, ID: id, Action: changes.ActionCreate,
			Post: map[string]any{"label": label, "status": "planned"},
		})
	})
	return id, err
}

type fakeResolver struct {
	f     jobChangeFix
	cable uuid.UUID
}

func (r *fakeResolver) ResolveParked(ctx context.Context, tenant uuid.UUID) (unresolved.ResolvedCount, error) {
	id, err := r.f.proposeCable(ctx, tenant, "LLDP Gi1/0/1 to Gi0/1")
	r.cable = id
	return unresolved.ResolvedCount{Resolved: 1}, err
}

func TestIntegration_ChangeNotify_CableResolverPassRaisesWhatItFiled(t *testing.T) {
	f := newJobChangeFix(t)
	r := &fakeResolver{f: f}
	tenants := func(context.Context, *sql.DB) ([]uuid.UUID, error) { return []uuid.UUID{f.tenant}, nil }

	RunCableResolverPass(f.ctx, f.db, tenants, r)

	evs := f.pub.take()
	if len(evs) != 1 {
		t.Fatalf("the pass raised %d events, want 1 for the cable it filed", len(evs))
	}
	ev := evs[0]
	if ev.TenantID != f.tenant || ev.SubjectType != string(dcim.ObjectKindCable) || ev.SubjectID == nil || *ev.SubjectID != r.cable ||
		ev.Metadata["source"] != "intake:lldp" || ev.Metadata["link"] != "/inventory/cables/"+r.cable.String() {
		t.Fatalf("event = %+v", ev)
	}
}

type fakeEvidenceSweeper struct {
	f      jobChangeFix
	cancel context.CancelFunc
	cable  uuid.UUID
}

func (s *fakeEvidenceSweeper) SweepIdentityEvidence(ctx context.Context, tenant uuid.UUID) (int, error) {
	if tenant != s.f.tenant {
		return 0, nil // another test's tenant in the shared database
	}
	defer s.cancel() // this tenant swept: the worker returns after its pass
	id, err := s.f.proposeCable(ctx, tenant, "replayed observation")
	s.cable = id
	return 1, err
}

func TestIntegration_ChangeNotify_IdentityEvidencePassRaisesWhatItWrote(t *testing.T) {
	f := newJobChangeFix(t)
	// The worker enumerates tenants from identity_observations; give this
	// tenant one so it is swept.
	testdb.RetryTransient(t, func() error {
		_, err := f.db.Exec(`INSERT INTO identity_observations (tenant_id, fingerprint, source_kind, source_ref, evidence, first_seen_at, last_seen_at)
			VALUES ($1, $2, 'sensor', 'job-test', '{}'::jsonb, now(), now())`, f.tenant, uuid.NewString())
		return err
	})
	// Bounded: a worker that never reached this tenant would otherwise tick
	// for ever.
	ctx, cancel := context.WithTimeout(f.ctx, 90*time.Second)
	defer cancel()
	s := &fakeEvidenceSweeper{f: f, cancel: cancel}

	StartIdentityEvidenceWorker(ctx, f.db, s)

	var mine []events.AlertRaiseEvent
	for _, ev := range f.pub.take() {
		if ev.TenantID == f.tenant {
			mine = append(mine, ev)
		}
	}
	if len(mine) != 1 || mine[0].SubjectID == nil || *mine[0].SubjectID != s.cable {
		t.Fatalf("the sweep raised %+v, want one event for the cable it wrote", mine)
	}
}
