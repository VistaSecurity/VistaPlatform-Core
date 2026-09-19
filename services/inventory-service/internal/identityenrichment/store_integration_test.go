package identityenrichment

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func enrichmentFixture(t *testing.T) (*Store, uuid.UUID, Observation) {
	t.Helper()
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db)
	store := &Store{DB: &database.DB{DB: sqlx.NewDb(db, "postgres")}}
	o := Observation{ID: uuid.New(), State: "unresolved", Fingerprint: uuid.NewString(), LastSeen: time.Now().UTC().Truncate(time.Microsecond).Add(-time.Hour)}
	o.Evidence = identity.Observation{TenantID: tenant.String(), Source: identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:" + uuid.NewString()}, ObservedAt: o.LastSeen, Identifiers: []identity.Identifier{{Kind: identity.KindHostname, Value: "uuid-only.local", Scope: identity.ScopeTenantDefault}}}
	evidence, err := json.Marshal(o.Evidence)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`INSERT INTO identity_observations(tenant_id,id,fingerprint,source_kind,source_ref,evidence,first_seen_at,last_seen_at)
  VALUES($1,$2,$3,'measured',$4,$5,$6,$6)`, tenant, o.ID, o.Fingerprint, o.Evidence.Source.Ref, string(evidence), o.LastSeen)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`INSERT INTO tenant_admin_settings(tenant_id,config) VALUES($1,'{"identity_enrichment":{"enabled":true},"identity_admission":{"mode":"enforce"}}')
 ON CONFLICT(tenant_id) DO UPDATE SET config=EXCLUDED.config`, tenant)
	if err != nil {
		t.Fatal(err)
	}
	return store, tenant, o
}
func TestIntegration_EnrichmentClaimsReplayAndFreshness(t *testing.T) {
	s, tenant, o := enrichmentFixture(t)
	ctx := context.Background()
	plan := Plan{Action: "configured_source", Executor: "configured_sources"}
	const n = 8
	ids := make(chan uuid.UUID, n)
	errs := make(chan error, n)
	var wg sync.WaitGroup
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			j, err := s.Ensure(ctx, tenant, o, plan, time.Now())
			ids <- j.ID
			errs <- err
		}()
	}
	wg.Wait()
	close(ids)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	var id uuid.UUID
	for got := range ids {
		if id != uuid.Nil && got != id {
			t.Fatal("duplicate jobs")
		}
		id = got
	}
	job, err := s.Ensure(ctx, tenant, o, plan, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	claimed, lease, ok, err := s.Claim(ctx, job, now)
	if err != nil || !ok {
		t.Fatalf("claim %v %v", ok, err)
	}
	originalClock := claimed.RequestEvidence.ObservedAt
	newer := o
	newer.Evidence.ObservedAt = newer.Evidence.ObservedAt.Add(time.Minute)
	newer.Evidence.Admission.ReceiptID = "newer-delivery"
	replay, err := s.Ensure(ctx, tenant, newer, plan, now)
	if err != nil {
		t.Fatal(err)
	}
	if replay.ID != job.ID || !replay.RequestEvidence.ObservedAt.Equal(originalClock) || replay.RequestEvidence.Admission.ReceiptID != claimed.RequestEvidence.Admission.ReceiptID {
		t.Fatal("retry changed immutable source request evidence")
	}
	if _, _, ok, err := s.Claim(ctx, job, now); err != nil || ok {
		t.Fatalf("double claim %v %v", ok, err)
	}
	// Crash before acknowledgment: after expiry the same request ID is retried.
	reclaimed, newLease, ok, err := s.Claim(ctx, job, now.Add(3*time.Minute))
	if err != nil || !ok || reclaimed.RequestID != claimed.RequestID {
		t.Fatalf("restart %+v %v %v", reclaimed, ok, err)
	}
	if err := s.Finish(ctx, claimed, lease, Result{State: "completed"}, now); err == nil {
		t.Fatal("stale worker acknowledged new lease")
	}
	if err := s.Finish(ctx, reclaimed, newLease, Result{State: "completed", Reason: "source_complete"}, now.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	refreshed, err := s.Observation(ctx, tenant, o.ID)
	if err != nil {
		t.Fatal(err)
	}
	if refreshed.LastSeen.UnixMicro() != o.LastSeen.UnixMicro() {
		t.Fatal("scheduling fabricated an observation timestamp")
	}
	var count int
	if err := s.DB.QueryRow(`SELECT occurrence_count FROM identity_observations WHERE tenant_id=$1 AND id=$2`, tenant, o.ID).Scan(&count); err != nil || count != 1 {
		t.Fatalf("sightings=%d %v", count, err)
	}
	foreign := testdb.NewTenant(t, s.DB.DB.DB)
	if _, err := s.Observation(ctx, foreign, o.ID); err == nil {
		t.Fatal("cross-tenant observation exposed")
	}
	if _, err := s.Ensure(ctx, foreign, o, plan, time.Now()); err == nil {
		t.Fatal("cross-tenant job accepted")
	}
}

type fakeBackend struct {
	dispatches    int
	reevaluations int
	completePoll  bool
	lastCycle     string
}

func (f *fakeBackend) Dispatch(_ context.Context, j Job, _ Observation) (Result, error) {
	f.dispatches++
	return Result{State: "completed", RemoteID: j.RequestID.String(), Reason: "no_configured_source"}, nil
}
func (f *fakeBackend) Poll(_ context.Context, j Job, _ Observation) (Result, error) {
	if f.completePoll {
		return Result{State: "completed", RemoteID: j.RemoteID}, nil
	}
	panic("unexpected poll")
}
func (f *fakeBackend) Reevaluate(_ context.Context, _ uuid.UUID, o Observation) error {
	f.lastCycle = o.Cycle
	f.reevaluations++
	return nil
}
func TestIntegration_EnrichmentSourceFirstPauseAndReplay(t *testing.T) {
	s, tenant, o := enrichmentFixture(t)
	ctx := context.Background()
	backend := &fakeBackend{}
	now := time.Now().UTC()
	c := &Coordinator{Store: s, Backend: backend, Enabled: true, Now: func() time.Time { return now }}
	if err := c.Sweep(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	if backend.dispatches != 1 || backend.reevaluations != 1 {
		t.Fatalf("source first %+v", backend)
	}
	var state, reason string
	if err := s.DB.QueryRow(`SELECT enrichment_state,enrichment_reason FROM identity_observations WHERE tenant_id=$1 AND id=$2`, tenant, o.ID).Scan(&state, &reason); err != nil {
		t.Fatal(err)
	}
	if state != "blocked" || reason != "network_scope_unresolved" {
		t.Fatalf("state=%s reason=%s", state, reason)
	}
	now = now.Add(20 * time.Minute)
	if err := c.Sweep(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	if backend.dispatches != 1 {
		t.Fatal("repeat evidence dispatched duplicate work")
	}
	if _, err := s.DB.Exec(`UPDATE tenant_admin_settings SET config=jsonb_set(config,'{identity_admission,mode}','"paused"') WHERE tenant_id=$1`, tenant); err != nil {
		t.Fatal(err)
	}
	before := backend.reevaluations
	now = now.Add(time.Hour)
	if err := c.Sweep(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	if backend.reevaluations != before {
		t.Fatal("paused coordinator processed evidence")
	}
	c.Enabled = false
	if _, err := s.DB.Exec(`UPDATE tenant_admin_settings SET config=jsonb_set(config,'{identity_admission,mode}','"enforce"') WHERE tenant_id=$1`, tenant); err != nil {
		t.Fatal(err)
	}
	if err := c.Sweep(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	if backend.reevaluations != before {
		t.Fatal("tenant policy bypassed release gate")
	}
}

func TestIntegration_EnrichmentCyclePersistsAndDoesNotCountReplay(t *testing.T) {
	s, tenant, o := enrichmentFixture(t)
	now := time.Now().UTC()
	o.Cycle = "scheduled-101"
	plan := Plan{Action: "configured_source", Executor: "configured_sources", Cycle: "caller-cannot-override"}
	first, err := s.Ensure(t.Context(), tenant, o, plan, now)
	if err != nil {
		t.Fatal(err)
	}
	if first.Plan.Cycle != o.Cycle {
		t.Fatalf("missing central cycle: %+v", first.Plan)
	}
	replay, err := s.Ensure(t.Context(), tenant, o, plan, now.Add(time.Minute))
	if err != nil || replay.ID != first.ID || replay.Plan.Cycle != o.Cycle {
		t.Fatalf("replay changed cycle: %+v %v", replay, err)
	}
	claimed, lease, ok, err := s.Claim(t.Context(), first, now)
	if err != nil || !ok {
		t.Fatalf("claim %v %v", ok, err)
	}
	if err := s.Finish(t.Context(), claimed, lease, Result{State: "running", RemoteID: first.RequestID.String()}, now); err != nil {
		t.Fatal(err)
	}
	next := o
	next.Cycle = "scheduled-102"
	active, err := s.Ensure(t.Context(), tenant, next, plan, now.Add(time.Hour))
	if err != nil || active.ID != first.ID || active.Plan.Cycle != o.Cycle {
		t.Fatalf("active work assigned to a second cycle: %+v %v", active, err)
	}
	claimed, lease, ok, err = s.Claim(t.Context(), active, now.Add(time.Hour))
	if err != nil || !ok {
		t.Fatalf("claim active %v %v", ok, err)
	}
	if err := s.Finish(t.Context(), claimed, lease, Result{State: "completed", RemoteID: first.RequestID.String()}, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	second, err := s.Ensure(t.Context(), tenant, next, plan, now.Add(2*time.Hour))
	if err != nil || second.ID == first.ID || second.Plan.Cycle != next.Cycle {
		t.Fatalf("new scheduled cycle missing: %+v %v", second, err)
	}
	downstream, err := s.Ensure(t.Context(), tenant, o, Plan{Action: "dns", Executor: "observer"}, now.Add(time.Hour))
	if err != nil || downstream.Plan.Cycle != first.Plan.Cycle {
		t.Fatalf("downstream cohort lost: %+v %v", downstream, err)
	}
}

func TestIntegration_EnrichmentRolloverKeepsSourceCohort(t *testing.T) {
	s, tenant, o := enrichmentFixture(t)
	now := time.Now().UTC()
	o.Cycle = "older-window"
	job, err := s.Ensure(t.Context(), tenant, o, Plan{Action: "configured_source", Executor: "configured_sources"}, now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	claimed, lease, ok, err := s.Claim(t.Context(), job, now.Add(-time.Hour))
	if err != nil || !ok {
		t.Fatalf("claim %v %v", ok, err)
	}
	if err := s.Finish(t.Context(), claimed, lease, Result{State: "running", RemoteID: job.RequestID.String()}, now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	backend := &fakeBackend{completePoll: true}
	coordinator := &Coordinator{Store: s, Backend: backend, Enabled: true, Now: func() time.Time { return now }}
	if err := coordinator.Sweep(t.Context(), tenant); err != nil {
		t.Fatal(err)
	}
	if backend.reevaluations != 1 || backend.lastCycle != o.Cycle {
		t.Fatalf("completed old source attributed to another cycle: %+v", backend)
	}
}
