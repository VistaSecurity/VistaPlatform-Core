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
	now := time.Now().UTC().Truncate(time.Microsecond)
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
	dispatches       int
	reevaluations    int
	materializations int
	completePoll     bool
	lastCycle        string
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
func (f *fakeBackend) Materialize(_ context.Context, _ uuid.UUID, _ Observation) error {
	f.materializations++
	return nil
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
	now := time.Now().UTC().Truncate(time.Microsecond)
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
	now := time.Now().UTC().Truncate(time.Microsecond)
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
	now := time.Now().UTC().Truncate(time.Microsecond)
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

func TestIntegration_EnrichmentScopeExplainsCollectorEligibility(t *testing.T) {
	s, tenant, o := enrichmentFixture(t)
	sensor, segment := uuid.New(), uuid.New()
	o.Evidence.Source.Ref = "sensor:" + sensor.String()
	o.Evidence.Network.SegmentID = segment.String()
	now := time.Now().UTC().Truncate(time.Microsecond)
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO sensors(id,tenant_id,name,platform,version,profile,status,last_heartbeat,network_interfaces,reported_dns_interfaces,reported_capabilities)
 VALUES($1,$2,'Sensor','windows','1.0','datacenter_host','active',$3,ARRAY['pcap-capture-name'],ARRAY['Ethernet'],ARRAY['identity_dns_v1'])`, []any{sensor, tenant, now}},
		{`INSERT INTO network_segments(id,tenant_id,name,segment_type,value,is_active,environment) VALUES($1,$2,'Test network','cidr','192.0.2.0/24',true,'production')`, []any{segment, tenant}},
		{`INSERT INTO agent_addresses(sensor_id,interface_name,address,prefix_length,last_seen_at) VALUES($1,'Ethernet','192.0.2.10',24,$2),($1,'Wi-Fi','198.51.100.10',24,$2)`, []any{sensor, now}},
	} {
		if _, err := s.DB.Exec(q.sql, q.args...); err != nil {
			t.Fatal(err)
		}
	}
	// D4 split this into two answers. `check` asserts BOTH: whether an
	// executor was selected (and so whether the work is blocked), and the
	// observer's own reachability, which is provenance the UI renders and which
	// no longer decides anything on its own.
	check := func(wantExecutor bool, blockReason, observerReason string) {
		t.Helper()
		scope, _, err := s.Scope(context.Background(), tenant, o, now)
		if err != nil {
			t.Fatal(err)
		}
		if scope.Reachable != wantExecutor || (scope.SensorID != uuid.Nil) != wantExecutor || scope.BlockReason != blockReason {
			t.Fatalf("scope=%+v want executor=%v block=%s", scope, wantExecutor, blockReason)
		}
		if scope.ObserverSensorID != sensor || scope.ObserverReason != observerReason || scope.ObserverReachable != (observerReason == "") {
			t.Fatalf("observer=%+v want reason=%s", scope, observerReason)
		}
	}
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := s.DB.Exec(q, args...); err != nil {
			t.Fatal(err)
		}
	}
	// The observer is on the target network and is therefore preferred as its
	// own executor. (Npcap capture name and OS Ethernet name may differ.)
	check(true, "", "")
	exec(`UPDATE network_segments SET value='198.51.100.0/24' WHERE id=$1`, segment)
	// Wi-Fi holds an address in the new segment but is not an authorized DNS
	// interface, so neither the observer nor any executor reaches it.
	check(false, ReasonNoEligibleCollector, "collector_has_no_interface_in_target_network")
	exec(`UPDATE network_segments SET value='192.0.2.0/24' WHERE id=$1`, segment)
	exec(`UPDATE agent_addresses SET prefix_length=NULL WHERE sensor_id=$1`, sensor)
	check(false, ReasonNoEligibleCollector, "collector_has_no_interface_in_target_network")
	exec(`UPDATE agent_addresses SET prefix_length=24,last_seen_at=$2 WHERE sensor_id=$1`, sensor, now.Add(-6*time.Minute))
	check(false, ReasonNoEligibleCollector, "collector_has_no_interface_in_target_network")
	exec(`UPDATE agent_addresses SET last_seen_at=$2 WHERE sensor_id=$1`, sensor, now)
	exec(`UPDATE sensors SET last_heartbeat=$2 WHERE id=$1`, sensor, now.Add(-time.Hour))
	check(false, ReasonNoEligibleCollector, "observing_collector_offline")
	exec(`UPDATE sensors SET last_heartbeat=$2,air_gapped=true WHERE id=$1`, sensor, now)
	check(false, ReasonNoEligibleCollector, "collector_network_checks_disabled")
	// A platform ('system'-tagged) collector's observation is refused outright:
	// no tenant sensor may execute work derived from evidence that collector
	// gathered on behalf of every tenant at once.
	exec(`UPDATE sensors SET air_gapped=false,last_heartbeat=$2,tags=ARRAY['system'] WHERE id=$1`, sensor, now)
	check(false, "platform_collector_not_authorized_for_identity_enrichment", "platform_collector_not_authorized_for_identity_enrichment")
	foreign := testdb.NewTenant(t, s.DB.DB.DB)
	scope, _, err := s.Scope(context.Background(), foreign, o, now)
	if err != nil || scope.Reachable || scope.SensorID != uuid.Nil || scope.ObserverSensorID != sensor || scope.SegmentID != uuid.Nil {
		t.Fatalf("foreign scope=%+v err=%v", scope, err)
	}
}

// dispatchRefusingBackend fails the test if anything is dispatched. The point of
// the authorization recheck is that the collector is never contacted.
type dispatchRefusingBackend struct{ t *testing.T }

func (b dispatchRefusingBackend) Dispatch(_ context.Context, j Job, _ Observation) (Result, error) {
	b.t.Fatalf("work was dispatched to a collector that is no longer authorized: %+v", j.Plan)
	return Result{}, nil
}
func (b dispatchRefusingBackend) Poll(_ context.Context, _ Job, _ Observation) (Result, error) {
	b.t.Fatal("unexpected poll")
	return Result{}, nil
}
func (b dispatchRefusingBackend) Reevaluate(_ context.Context, _ uuid.UUID, _ Observation) error {
	return nil
}
func (b dispatchRefusingBackend) Materialize(_ context.Context, _ uuid.UUID, _ Observation) error {
	return nil
}

// TestIntegration_EnrichmentRechecksExecutorAuthorizationBeforeDispatch pins
// D4's safety property: a plan is authorization at PLAN time, and the
// executor's eligibility is re-derived immediately before the collector is
// contacted.
//
// It matters more now than it did when the executor was always the observer.
// The executor is chosen from a fleet whose eligibility moves on its own —
// a sensor's interface report goes stale after five minutes, a heartbeat
// lapses, an operator air-gaps a host — so the window between planning and
// dispatching is one a normal deployment walks through regularly, not a race a
// reviewer has to contrive.
//
// It lives here rather than beside the rest of the lifecycle tests
// because `Coordinator.advance` is unexported: driving it through `Sweep` from
// another package would need the configured-source stage to complete first,
// which means an HTTP call to device-interrogation-service that a test has no
// business making.
func TestIntegration_EnrichmentRechecksExecutorAuthorizationBeforeDispatch(t *testing.T) {
	s, tenant, o := enrichmentFixture(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	observer, executor, segment := uuid.New(), uuid.New(), uuid.New()

	// The observer is on 192.0.2.0/24; the advertised device is on
	// 198.51.100.0/24, where only the executor has an interface.
	o.Evidence.Source.Ref = "sensor:" + observer.String()
	o.Evidence.Network.SegmentID = segment.String()
	o.Evidence.Identifiers = []identity.Identifier{
		{Kind: identity.KindHostname, Value: "crossvlan-printer", Scope: segment.String()},
		{Kind: identity.KindIPAddress, Value: "198.51.100.7", Scope: segment.String()},
	}
	evidence, err := json.Marshal(o.Evidence)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`UPDATE identity_observations SET evidence=$3,source_ref=$4,network_scope=$5 WHERE tenant_id=$1 AND id=$2`, []any{tenant, o.ID, string(evidence), o.Evidence.Source.Ref, segment.String()}},
		{`INSERT INTO network_segments(id,tenant_id,name,segment_type,value,is_active,environment) VALUES($1,$2,'VLAN B','cidr','198.51.100.0/24',true,'production')`, []any{segment, tenant}},
		{`INSERT INTO sensors(id,tenant_id,name,platform,version,profile,status,last_heartbeat,network_interfaces,reported_capabilities,reported_dns_interfaces) VALUES($1,$2,'observer','linux','1.0','datacenter_host','active',$3,ARRAY['eth0'],ARRAY['identity_dns_v1'],ARRAY['eth0'])`, []any{observer, tenant, now}},
		{`INSERT INTO agent_addresses(sensor_id,interface_name,address,prefix_length,last_seen_at) VALUES($1,'eth0','192.0.2.10',24,$2)`, []any{observer, now}},
		{`INSERT INTO sensors(id,tenant_id,name,platform,version,profile,status,last_heartbeat,network_interfaces,reported_capabilities,reported_dns_interfaces) VALUES($1,$2,'executor','linux','1.0','datacenter_host','active',$3,ARRAY['eth0'],ARRAY['identity_dns_v1'],ARRAY['eth0'])`, []any{executor, tenant, now}},
		{`INSERT INTO agent_addresses(sensor_id,interface_name,address,prefix_length,last_seen_at) VALUES($1,'eth0','198.51.100.9',24,$2)`, []any{executor, now}},
	} {
		if _, err := s.DB.Exec(q.sql, q.args...); err != nil {
			t.Fatal(err)
		}
	}

	scope, excluded, err := s.Scope(ctx, tenant, o, now)
	if err != nil {
		t.Fatal(err)
	}
	if scope.SensorID != executor || scope.ObserverSensorID != observer {
		t.Fatalf("scope=%+v want executor %s observed by %s", scope, executor, observer)
	}
	policy, err := s.Policy(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	plan, reason := NetworkPlan(o, policy, scope, nil, excluded)
	if reason != "" || plan.Action != "probe" {
		t.Fatalf("plan=%+v reason=%s", plan, reason)
	}
	job, err := s.Ensure(ctx, tenant, o, plan, now)
	if err != nil {
		t.Fatal(err)
	}

	// The executor's interface report goes stale between planning and dispatch.
	if _, err := s.DB.Exec(`DELETE FROM agent_addresses WHERE sensor_id=$1`, executor); err != nil {
		t.Fatal(err)
	}
	c := &Coordinator{Store: s, Backend: dispatchRefusingBackend{t: t}, Enabled: true, Now: func() time.Time { return now }}
	advanced, err := c.advance(ctx, job, o, now)
	if err != nil {
		t.Fatal(err)
	}
	if advanced.State != "blocked" || advanced.Reason != "authorization_changed_before_dispatch" {
		t.Fatalf("job=%s/%s, want blocked/authorization_changed_before_dispatch", advanced.State, advanced.Reason)
	}
}
