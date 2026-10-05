package identityenrichment

// The identity-enrichment probe flood seen on a lab deployment, the planner half:
// several observations of one address must share ONE probe through one
// executor, and an executor with no room must be waited for, not failed.
// Driven through Coordinator.Sweep, so the wiring from planning to dispatch is
// what is tested; only the backend (the collector) is fake.
//
// Skips without TEST_DATABASE_URL.

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/autoscan"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// probeBackend completes every configured-source request at once and records
// every probe it is asked to dispatch. Probes report `running` until
// completeProbes is set; busy makes the collector refuse for want of room.
type probeBackend struct {
	mu             sync.Mutex
	probes         map[string]int // address list -> dispatches
	busy           bool
	completeProbes bool
	reevaluated    map[uuid.UUID]int
}

func newProbeBackend() *probeBackend {
	return &probeBackend{probes: map[string]int{}, reevaluated: map[uuid.UUID]int{}}
}

func (b *probeBackend) Dispatch(_ context.Context, j Job, _ Observation) (Result, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if j.Plan.Action != "probe" {
		return Result{State: "completed", RemoteID: j.RequestID.String(), Reason: "no_configured_source"}, nil
	}
	if b.busy {
		return Result{State: "waiting", Reason: ReasonCollectorBusy}, nil
	}
	key, _ := json.Marshal(j.Plan.Addresses)
	b.probes[string(key)]++
	return Result{State: "queued", RemoteID: uuid.NewString()}, nil
}

func (b *probeBackend) Poll(_ context.Context, j Job, _ Observation) (Result, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.completeProbes {
		return Result{State: "completed", RemoteID: j.RemoteID, Reason: "probe_results_ingested"}, nil
	}
	return Result{State: "running", RemoteID: j.RemoteID}, nil
}

func (b *probeBackend) Reevaluate(_ context.Context, _ uuid.UUID, o Observation) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.reevaluated[o.ID]++
	return nil
}

func (b *probeBackend) Materialize(context.Context, uuid.UUID, Observation) error { return nil }

func (b *probeBackend) dispatches() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := 0
	for _, c := range b.probes {
		n += c
	}
	return n
}

// probeFixture is a tenant with one live executor on 198.51.100.0/24 and
// observations of addresses on it, each an independent sighting (its own
// fingerprint and source ref) the way a passive and an active-scan sighting
// of one host are.
type probeFixture struct {
	s        *Store
	tenant   uuid.UUID
	executor uuid.UUID
	segment  uuid.UUID
	now      time.Time
}

func newProbeFixture(t *testing.T) *probeFixture {
	t.Helper()
	s, tenant, o := enrichmentFixture(t)
	// The fixture's own hostname-only observation would plan nothing useful
	// here; take it out of the sweep.
	if _, err := s.DB.Exec(`UPDATE identity_observations SET state='dismissed' WHERE tenant_id=$1 AND id=$2`, tenant, o.ID); err != nil {
		t.Fatal(err)
	}
	// Start just inside a rescan cycle, so the minutes this test steps through
	// stay in one cohort whatever the wall clock says.
	cycle := int64(time.Duration(autoscan.DefaultRescanIntervalHours) * time.Hour / time.Second)
	now := time.Unix(time.Now().Unix()/cycle*cycle, 0).UTC().Add(time.Minute)
	f := &probeFixture{s: s, tenant: tenant, executor: uuid.New(), segment: uuid.New(), now: now}
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO network_segments(id,tenant_id,name,segment_type,value,is_active,environment) VALUES($1,$2,'VLAN 99','cidr','198.51.100.0/24',true,'production')`, []any{f.segment, tenant}},
		{`INSERT INTO sensors(id,tenant_id,name,platform,version,profile,status,last_heartbeat,network_interfaces,reported_capabilities,reported_dns_interfaces) VALUES($1,$2,'branch-sensor','windows','4.3.1','datacenter_host','active',$3,ARRAY['eth0'],ARRAY['identity_dns_v1'],ARRAY['eth0'])`, []any{f.executor, tenant, now}},
		{`INSERT INTO agent_addresses(sensor_id,interface_name,address,prefix_length,last_seen_at) VALUES($1,'eth0','198.51.100.205',24,$2)`, []any{f.executor, now}},
	} {
		if _, err := s.DB.Exec(q.sql, q.args...); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

// observe records one unresolved observation of address, as `ref`
// ("sensor" or "scan") of the executor saw it.
func (f *probeFixture) observe(t *testing.T, ref, address string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	ev := identity.Observation{
		TenantID:    f.tenant.String(),
		Source:      identity.Source{Kind: identity.SourceMeasured, Ref: ref + ":" + f.executor.String()},
		ObservedAt:  f.now.Add(-10 * time.Minute),
		Network:     identity.Network{SegmentID: f.segment.String()},
		Identifiers: []identity.Identifier{{Kind: identity.KindIPAddress, Value: address, Scope: f.segment.String()}},
	}
	raw, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.DB.Exec(`INSERT INTO identity_observations(tenant_id,id,fingerprint,source_kind,source_ref,network_scope,evidence,first_seen_at,last_seen_at)
  VALUES($1,$2,$3,'measured',$4,$5,$6,$7,$7)`, f.tenant, id, uuid.NewString(), ev.Source.Ref, f.segment.String(), string(raw), ev.ObservedAt); err != nil {
		t.Fatal(err)
	}
	return id
}

// alive keeps the executor eligible at the test's clock: a live heartbeat and
// a fresh interface report (Scope requires both within minutes of now).
func (f *probeFixture) alive(t *testing.T, now time.Time) {
	t.Helper()
	if _, err := f.s.DB.Exec(`UPDATE sensors SET last_heartbeat=$2 WHERE id=$1`, f.executor, now); err != nil {
		t.Fatal(err)
	}
	if _, err := f.s.DB.Exec(`UPDATE agent_addresses SET last_seen_at=$2 WHERE sensor_id=$1`, f.executor, now); err != nil {
		t.Fatal(err)
	}
}

func (f *probeFixture) enrichment(t *testing.T, id uuid.UUID) (state, reason string, next time.Time) {
	t.Helper()
	if err := f.s.DB.QueryRow(`SELECT enrichment_state,enrichment_reason,COALESCE(next_attempt_at,'epoch') FROM identity_observations WHERE tenant_id=$1 AND id=$2`, f.tenant, id).Scan(&state, &reason, &next); err != nil {
		t.Fatal(err)
	}
	return
}

func TestIntegration_EnrichmentCoalescesProbesPerExecutorAndAddress(t *testing.T) {
	f := newProbeFixture(t)
	ctx := context.Background()
	// Three sightings of .131 (passive, active scan, and a second passive one
	// from a later delivery) and one of .10 — the shape of the lab flood.
	shared := []uuid.UUID{
		f.observe(t, "sensor", "198.51.100.131"),
		f.observe(t, "scan", "198.51.100.131"),
		f.observe(t, "sensor", "198.51.100.131"),
	}
	other := f.observe(t, "scan", "198.51.100.10")

	backend := newProbeBackend()
	now := f.now
	c := &Coordinator{Store: f.s, Backend: backend, Enabled: true, Now: func() time.Time { return now }}
	if err := c.Sweep(ctx, f.tenant); err != nil {
		t.Fatal(err)
	}
	if got := backend.probes[`["198.51.100.131"]`]; got != 1 {
		t.Fatalf("198.51.100.131 was probed %d times for three observations, want once", got)
	}
	if got := backend.probes[`["198.51.100.10"]`]; got != 1 {
		t.Fatalf("198.51.100.10 was probed %d times, want once — coalescing must not swallow a different address", got)
	}
	coalesced := 0
	for _, id := range shared {
		if _, reason, _ := f.enrichment(t, id); reason == ReasonProbeCoalesced {
			coalesced++
		}
	}
	if coalesced != 2 {
		t.Fatalf("%d of the three .131 observations wait on the shared probe, want 2", coalesced)
	}
	var jobs int
	if err := f.s.DB.QueryRow(`SELECT count(*) FROM identity_enrichment_jobs WHERE tenant_id=$1 AND action='probe'`, f.tenant).Scan(&jobs); err != nil {
		t.Fatal(err)
	}
	if jobs != 2 {
		t.Fatalf("%d probe jobs recorded, want 2 (one per address)", jobs)
	}

	// Every minute while the probe runs, nothing new is dispatched.
	for range 3 {
		now = now.Add(time.Minute)
		f.alive(t, now)
		if err := c.Sweep(ctx, f.tenant); err != nil {
			t.Fatal(err)
		}
	}
	if n := backend.dispatches(); n != 2 {
		t.Fatalf("%d probes dispatched while the first ones ran, want still 2", n)
	}

	// The shared probe completes: every observation of .131 is re-evaluated
	// against what it ingested and completes — without a probe of its own.
	backend.completeProbes = true
	for range 3 {
		now = now.Add(time.Minute)
		f.alive(t, now)
		if err := c.Sweep(ctx, f.tenant); err != nil {
			t.Fatal(err)
		}
	}
	if n := backend.dispatches(); n != 2 {
		t.Fatalf("%d probes dispatched in all, want 2 — a completed shared probe satisfies its followers", n)
	}
	for _, id := range append(shared, other) {
		state, reason, _ := f.enrichment(t, id)
		if state != "completed" || reason != "authorized_probe_completed_identity_requires_corroboration" {
			t.Errorf("observation %s = %s/%s after the shared probe completed, want completed/authorized_probe_completed_identity_requires_corroboration", id, state, reason)
		}
	}
}

// An executor with no room is waited for: the observation reads waiting with
// the busy reason, the next attempt backs off, and nothing is blocked.
func TestIntegration_EnrichmentWaitsForABusyCollector(t *testing.T) {
	f := newProbeFixture(t)
	ctx := context.Background()
	id := f.observe(t, "sensor", "198.51.100.131")
	backend := newProbeBackend()
	backend.busy = true
	now := f.now
	c := &Coordinator{Store: f.s, Backend: backend, Enabled: true, Now: func() time.Time { return now }}

	var previous time.Duration
	for attempt := 1; attempt <= 3; attempt++ {
		if err := c.Sweep(ctx, f.tenant); err != nil {
			t.Fatal(err)
		}
		state, reason, next := f.enrichment(t, id)
		if state != "waiting" || reason != ReasonCollectorBusy {
			t.Fatalf("attempt %d: observation %s/%s, want waiting/%s — a busy collector is back-pressure, not a failure", attempt, state, reason, ReasonCollectorBusy)
		}
		wait := next.Sub(now)
		if wait < previous || wait < time.Minute {
			t.Fatalf("attempt %d: next attempt in %s after %s — busy retries must back off", attempt, wait, previous)
		}
		previous = wait
		now = next
		f.alive(t, now)
	}
	if previous <= time.Minute {
		t.Fatalf("after three busy attempts the retry is still %s apart, want a growing backoff", previous)
	}
	if n := backend.dispatches(); n != 0 {
		t.Fatalf("%d probes dispatched to a busy collector", n)
	}

	// Room again: the same job dispatches.
	backend.busy = false
	if err := c.Sweep(ctx, f.tenant); err != nil {
		t.Fatal(err)
	}
	if n := backend.dispatches(); n != 1 {
		t.Fatalf("%d probes dispatched once the collector had room, want 1", n)
	}
}

// A remote request that ended without running (the sensor refused it for want
// of room) is forgotten: the next dispatch is a NEW request, because the
// remote side replays a request ID it already knows.
func TestIntegration_EnrichmentRedispatchIssuesANewRequest(t *testing.T) {
	f := newProbeFixture(t)
	ctx := context.Background()
	id := f.observe(t, "sensor", "198.51.100.131")
	o, err := f.s.Observation(ctx, f.tenant, id)
	if err != nil {
		t.Fatal(err)
	}
	job, err := f.s.EnsureProbe(ctx, f.tenant, o, Plan{Action: "probe", Executor: "sensor:" + f.executor.String(), SensorID: f.executor, SegmentID: f.segment,
		Addresses: []string{"198.51.100.131"}, Ports: []int{443}, Protocols: []string{"TLS"}}, f.now, f.now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	claimed, lease, ok, err := f.s.Claim(ctx, job, f.now)
	if err != nil || !ok {
		t.Fatalf("claim %v %v", ok, err)
	}
	if err := f.s.Finish(ctx, claimed, lease, Result{State: "queued", RemoteID: "remote-1"}, f.now); err != nil {
		t.Fatal(err)
	}
	later := f.now.Add(2 * time.Minute)
	claimed, lease, ok, err = f.s.Claim(ctx, job, later)
	if err != nil || !ok {
		t.Fatalf("reclaim %v %v", ok, err)
	}
	if err := f.s.Finish(ctx, claimed, lease, Result{State: "waiting", Reason: ReasonCollectorBusy, Redispatch: true}, later); err != nil {
		t.Fatal(err)
	}
	var remote string
	var request uuid.UUID
	var next time.Time
	if err := f.s.DB.QueryRow(`SELECT remote_id,request_id,next_attempt_at FROM identity_enrichment_jobs WHERE tenant_id=$1 AND id=$2`, f.tenant, job.ID).Scan(&remote, &request, &next); err != nil {
		t.Fatal(err)
	}
	if remote != "" || request == job.RequestID {
		t.Fatalf("after a redispatch remote_id=%q request_id unchanged=%v; want the old request forgotten and a new ID", remote, request == job.RequestID)
	}
	if !next.After(later) {
		t.Fatalf("next attempt %s is not after %s", next, later)
	}
	// And the plain polarity: a result without Redispatch keeps both.
	claimed, lease, ok, err = f.s.Claim(ctx, job, next)
	if err != nil || !ok {
		t.Fatalf("claim after backoff %v %v", ok, err)
	}
	if err := f.s.Finish(ctx, claimed, lease, Result{State: "queued", RemoteID: "remote-2"}, next); err != nil {
		t.Fatal(err)
	}
	var again uuid.UUID
	if err := f.s.DB.QueryRow(`SELECT remote_id,request_id FROM identity_enrichment_jobs WHERE tenant_id=$1 AND id=$2`, f.tenant, job.ID).Scan(&remote, &again); err != nil {
		t.Fatal(err)
	}
	if remote != "remote-2" || again != request {
		t.Fatalf("an ordinary result changed the request: remote=%q request changed=%v", remote, again != request)
	}
}
