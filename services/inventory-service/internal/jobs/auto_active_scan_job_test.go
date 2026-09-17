package jobs

// The automatic active-scan sweep's DECISIONS — what it dispatches, what it
// refuses to dispatch, and what it records — driven through a fake store and a
// fake dispatcher so every branch runs without a database or a peer.
//
// The wiring guard at the bottom is the other half. "A fix can compile, pass
// its tests, and still do nothing in production": the worker and its
// first-observation subscriber are two lines in cmd/main.go, and deleting
// either leaves this whole file green while the product quietly stops scanning
// anything unasked.

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/autoscan"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	sharedautoscan "github.com/vistasecurity/vistaplatform/shared/autoscan"
)

type fakeStore struct {
	policy    autoscan.Policy
	policyErr error

	targets     []autoscan.Target
	refusals    map[sharedautoscan.Reason]int
	targetsErr  error
	targetsSeen struct {
		policy   autoscan.Policy
		now      time.Time
		excluded []netip.Prefix
		calls    int
	}

	inFlight    map[string]bool
	inFlightErr error

	recorded []recordedScan
	stateSet []autoscan.State

	stampCalls int
	stampErr   error
}

type recordedScan struct {
	assetIDs []uuid.UUID
	jobID    string
}

func (f *fakeStore) GetPolicy(context.Context, uuid.UUID) (autoscan.Policy, error) {
	return f.policy, f.policyErr
}

func (f *fakeStore) EligibleTargets(_ context.Context, _ uuid.UUID, p autoscan.Policy, now time.Time, excluded []netip.Prefix) ([]autoscan.Target, map[sharedautoscan.Reason]int, error) {
	f.targetsSeen.policy = p
	f.targetsSeen.now = now
	f.targetsSeen.excluded = excluded
	f.targetsSeen.calls++
	return f.targets, f.refusals, f.targetsErr
}

func (f *fakeStore) StampCompletedScans(context.Context, uuid.UUID) (int, error) {
	f.stampCalls++
	if f.stampErr != nil {
		return 0, f.stampErr
	}
	return 0, nil
}

func (f *fakeStore) AddressesWithScanInFlight(context.Context, uuid.UUID) (map[string]bool, error) {
	return f.inFlight, f.inFlightErr
}

func (f *fakeStore) RecordScanned(_ context.Context, _ uuid.UUID, assetIDs []uuid.UUID, jobID string, _ time.Time) error {
	f.recorded = append(f.recorded, recordedScan{assetIDs: assetIDs, jobID: jobID})
	return nil
}

func (f *fakeStore) SetState(_ context.Context, _ uuid.UUID, state autoscan.State) error {
	f.stateSet = append(f.stateSet, state)
	return nil
}

type fakeDispatcher struct {
	jobs []models.CreateDiscoveryJobInput
	err  error
	n    int
}

func (d *fakeDispatcher) CreateJobInternal(_ string, input models.CreateDiscoveryJobInput) (*models.DiscoveryJob, error) {
	if d.err != nil {
		return nil, d.err
	}
	d.jobs = append(d.jobs, input)
	d.n++
	return &models.DiscoveryJob{ID: "job-" + string(rune('a'+d.n-1))}, nil
}

func newJob(store autoScanStore, dispatcher autoScanDispatcher) *AutoActiveScanJob {
	j := NewAutoActiveScanJob(store, dispatcher, nil, nil)
	j.now = func() time.Time { return time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC) }
	return j
}

func targetsAt(addresses ...string) []autoscan.Target {
	out := make([]autoscan.Target, 0, len(addresses))
	for _, a := range addresses {
		out = append(out, autoscan.Target{AssetID: uuid.New(), Address: a})
	}
	return out
}

func TestSweepTenant_DispatchesWhatThePolicyAsksFor(t *testing.T) {
	store := &fakeStore{
		policy:  sharedautoscan.DefaultPolicy(),
		targets: targetsAt("10.0.0.1", "10.0.0.2"),
	}
	d := &fakeDispatcher{}
	newJob(store, d).SweepTenant(context.Background(), uuid.New(), false)

	if len(d.jobs) != 1 {
		t.Fatalf("dispatched %d jobs, want 1", len(d.jobs))
	}
	job := d.jobs[0]
	if len(job.Targets) != 2 {
		t.Errorf("targets = %v, want both addresses", job.Targets)
	}
	// The job must carry the TENANT's protocols and ports, not a second copy of
	// the defaults living in the worker.
	if len(job.Protocols) != len(store.policy.Protocols) || len(job.Ports) != len(store.policy.Ports) {
		t.Errorf("job carries %v/%v, want the policy's %v/%v", job.Protocols, job.Ports, store.policy.Protocols, store.policy.Ports)
	}
	// The origin marker is what every later reader uses to tell a scan nobody
	// asked for from one somebody did — the idempotency gate, the settings
	// page's recent-runs list, and a support engineer with psql.
	if job.Options["origin"] != autoscan.Origin {
		t.Errorf("job options = %v, want origin %q", job.Options, autoscan.Origin)
	}

	if len(store.recorded) != 1 || len(store.recorded[0].assetIDs) != 2 {
		t.Fatalf("recorded = %+v, want one stamp covering both assets", store.recorded)
	}
	if store.recorded[0].jobID != "job-a" {
		t.Errorf("stamped job id = %q, want the dispatched job's", store.recorded[0].jobID)
	}
}

func TestSweepTenant_PolicyGates(t *testing.T) {
	cases := []struct {
		name             string
		policy           autoscan.Policy
		firstObservation bool
		wantJobs         int
	}{
		{
			name:     "off means nothing is scanned",
			policy:   autoscan.Policy{Enabled: false, ScanOnFirstObservation: true, RescanIntervalHours: 24},
			wantJobs: 0,
		},
		{
			name:             "off means nothing is scanned on observation either",
			policy:           autoscan.Policy{Enabled: false, ScanOnFirstObservation: true, RescanIntervalHours: 24},
			firstObservation: true,
			wantJobs:         0,
		},
		{
			// The two halves are independent: a tenant can keep the daily
			// rescan and decline to be scanned the instant something appears.
			name:             "first-observation off still allows the scheduled sweep",
			policy:           autoscan.Policy{Enabled: true, ScanOnFirstObservation: false, RescanIntervalHours: 24, Protocols: []string{"TLS"}, Ports: []int{443}},
			firstObservation: false,
			wantJobs:         1,
		},
		{
			name:             "first-observation off skips the triggered pass",
			policy:           autoscan.Policy{Enabled: true, ScanOnFirstObservation: false, RescanIntervalHours: 24, Protocols: []string{"TLS"}, Ports: []int{443}},
			firstObservation: true,
			wantJobs:         0,
		},
		{
			name:             "everything on scans on observation",
			policy:           sharedautoscan.DefaultPolicy(),
			firstObservation: true,
			wantJobs:         1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := &fakeStore{policy: tc.policy, targets: targetsAt("10.0.0.1")}
			d := &fakeDispatcher{}
			newJob(store, d).SweepTenant(context.Background(), uuid.New(), tc.firstObservation)
			if len(d.jobs) != tc.wantJobs {
				t.Fatalf("dispatched %d jobs, want %d", len(d.jobs), tc.wantJobs)
			}
		})
	}
}

// The interval is the tenant's, and the worker must hand it to the selector
// rather than deciding staleness itself — two opinions about "due" is how the
// page and the sweep come to disagree.
func TestSweepTenant_PassesTheTenantsPolicyToTheSelector(t *testing.T) {
	policy := sharedautoscan.DefaultPolicy()
	policy.RescanIntervalHours = 72
	store := &fakeStore{policy: policy}
	j := newJob(store, &fakeDispatcher{})
	j.SweepTenant(context.Background(), uuid.New(), false)

	if store.targetsSeen.policy.RescanIntervalHours != 72 {
		t.Errorf("the selector was given %d hours, want the tenant's 72", store.targetsSeen.policy.RescanIntervalHours)
	}
	if !store.targetsSeen.now.Equal(j.now()) {
		t.Errorf("the selector was given %v, want the sweep's clock %v", store.targetsSeen.now, j.now())
	}
}

func TestSweepTenant_SkipsAddressesAlreadyBeingScanned(t *testing.T) {
	store := &fakeStore{
		policy:   sharedautoscan.DefaultPolicy(),
		targets:  targetsAt("10.0.0.1", "10.0.0.2"),
		inFlight: map[string]bool{"10.0.0.1": true},
	}
	d := &fakeDispatcher{}
	newJob(store, d).SweepTenant(context.Background(), uuid.New(), false)

	if len(d.jobs) != 1 {
		t.Fatalf("dispatched %d jobs, want 1", len(d.jobs))
	}
	if len(d.jobs[0].Targets) != 1 || d.jobs[0].Targets[0] != "10.0.0.2" {
		t.Errorf("targets = %v, want only 10.0.0.2", d.jobs[0].Targets)
	}
}

// Fail CLOSED. Dispatching without knowing what is already running is how one
// observation becomes the same host probed several times over — which the
// tenant sees in their own logs before we see it in ours.
func TestSweepTenant_SkipsThePassWhenTheIdempotencyGateCannotBeRead(t *testing.T) {
	store := &fakeStore{
		policy:      sharedautoscan.DefaultPolicy(),
		targets:     targetsAt("10.0.0.1"),
		inFlightErr: errors.New("database is down"),
	}
	d := &fakeDispatcher{}
	newJob(store, d).SweepTenant(context.Background(), uuid.New(), false)

	if len(d.jobs) != 0 {
		t.Fatalf("dispatched %d jobs with the idempotency gate unreadable, want 0", len(d.jobs))
	}
	if len(store.recorded) != 0 {
		t.Errorf("stamped %d assets without scanning them", len(store.recorded))
	}
}

// An asset whose scan never left the cluster must stay DUE. Stamping it anyway
// would turn a peer outage into a completed sweep and leave the host unlooked-at
// for a whole interval.
func TestSweepTenant_DoesNotStampAFailedDispatch(t *testing.T) {
	store := &fakeStore{
		policy:  sharedautoscan.DefaultPolicy(),
		targets: targetsAt("10.0.0.1"),
	}
	d := &fakeDispatcher{err: errors.New("cluster-sensor-service is unreachable")}
	newJob(store, d).SweepTenant(context.Background(), uuid.New(), false)

	if len(store.recorded) != 0 {
		t.Fatalf("stamped %d assets after a failed dispatch — they would not be rescanned for a whole interval", len(store.recorded))
	}
}

// "We looked and nothing was due" and "the worker has not run" are different
// answers, and the settings page shows which one it is.
func TestSweepTenant_RecordsAPassThatFoundNothing(t *testing.T) {
	store := &fakeStore{policy: sharedautoscan.DefaultPolicy()}
	newJob(store, &fakeDispatcher{}).SweepTenant(context.Background(), uuid.New(), false)

	if len(store.stateSet) != 1 {
		t.Fatalf("recorded %d passes, want 1", len(store.stateSet))
	}
	s := store.stateSet[0]
	if s.LastSweepAt == nil || s.NextSweepAt == nil {
		t.Fatalf("state = %+v, want both timestamps", s)
	}
	if !s.NextSweepAt.After(*s.LastSweepAt) {
		t.Errorf("next sweep %v is not after the last %v", s.NextSweepAt, s.LastSweepAt)
	}
	if s.LastSweepJobs != 0 || s.LastSweepAssets != 0 {
		t.Errorf("state = %+v, want zeroes", s)
	}
}

func TestSweepTenant_RecordsWhatTheSweepDid(t *testing.T) {
	store := &fakeStore{policy: sharedautoscan.DefaultPolicy(), targets: targetsAt("10.0.0.1", "10.0.0.2", "10.0.0.3")}
	newJob(store, &fakeDispatcher{}).SweepTenant(context.Background(), uuid.New(), false)

	if len(store.stateSet) != 1 {
		t.Fatalf("recorded %d passes, want 1", len(store.stateSet))
	}
	if store.stateSet[0].LastSweepJobs != 1 || store.stateSet[0].LastSweepAssets != 3 {
		t.Errorf("state = %+v, want 1 job / 3 assets", store.stateSet[0])
	}
}

// The refusals are part of the record, on BOTH branches. The one that matters
// most is the pass that dispatched nothing because every host was refused: a
// Tailscale tenant's whole estate is carrier-grade NAT, and without this the
// page says "Automatic scanning: on" over a sweep that will never scan a host.
func TestSweepTenant_RecordsWhyHostsWereNotScanned(t *testing.T) {
	refusals := map[sharedautoscan.Reason]int{
		sharedautoscan.ReasonCarrierGradeNAT: 12,
		sharedautoscan.ReasonPublic:          3,
		sharedautoscan.ReasonLoopback:        0, // a zero is not a refusal; it must not be stored
	}

	t.Run("nothing due", func(t *testing.T) {
		store := &fakeStore{policy: sharedautoscan.DefaultPolicy(), refusals: refusals}
		newJob(store, &fakeDispatcher{}).SweepTenant(context.Background(), uuid.New(), false)
		if len(store.stateSet) != 1 {
			t.Fatalf("recorded %d passes, want 1", len(store.stateSet))
		}
		got := store.stateSet[0].LastSweepRefusals
		if got[sharedautoscan.ReasonCarrierGradeNAT] != 12 || got[sharedautoscan.ReasonPublic] != 3 {
			t.Errorf("refusals = %v, want cgnat=12 public=3", got)
		}
		if _, present := got[sharedautoscan.ReasonLoopback]; present {
			t.Errorf("a zero count was recorded as a refusal: %v", got)
		}
	})

	t.Run("something dispatched", func(t *testing.T) {
		store := &fakeStore{policy: sharedautoscan.DefaultPolicy(), refusals: refusals, targets: targetsAt("10.0.0.1")}
		newJob(store, &fakeDispatcher{}).SweepTenant(context.Background(), uuid.New(), false)
		if len(store.stateSet) != 1 {
			t.Fatalf("recorded %d passes, want 1", len(store.stateSet))
		}
		if got := store.stateSet[0].LastSweepRefusals; got[sharedautoscan.ReasonCarrierGradeNAT] != 12 {
			t.Errorf("refusals = %v, want cgnat=12 alongside the dispatch", got)
		}
	})

	t.Run("no refusals is stored as absent, not as an empty map", func(t *testing.T) {
		store := &fakeStore{policy: sharedautoscan.DefaultPolicy(), refusals: map[sharedautoscan.Reason]int{}}
		newJob(store, &fakeDispatcher{}).SweepTenant(context.Background(), uuid.New(), false)
		if store.stateSet[0].LastSweepRefusals != nil {
			t.Errorf("refusals = %v, want nil", store.stateSet[0].LastSweepRefusals)
		}
	})
}

// Completed automatic scans are stamped onto their endpoints on every pass —
// including a pass for a tenant who has since turned the feature OFF. The job
// completed; the manual coverage list should say so regardless of the switch.
func TestSweepTenant_StampsCompletedScansEvenWhenThePolicyIsOff(t *testing.T) {
	off := sharedautoscan.DefaultPolicy()
	off.Enabled = false
	store := &fakeStore{policy: off}
	newJob(store, &fakeDispatcher{}).SweepTenant(context.Background(), uuid.New(), false)

	if store.stampCalls != 1 {
		t.Fatalf("StampCompletedScans called %d times, want 1 — a scan that completed after the switch went off would never be stamped", store.stampCalls)
	}
}

// The stamp is a record, not a gate: if it fails, the pass still dispatches.
func TestSweepTenant_StampFailureDoesNotStopThePass(t *testing.T) {
	store := &fakeStore{
		policy:   sharedautoscan.DefaultPolicy(),
		targets:  targetsAt("10.0.0.1"),
		stampErr: errors.New("asset_endpoints is locked"),
	}
	d := &fakeDispatcher{}
	newJob(store, d).SweepTenant(context.Background(), uuid.New(), false)

	if d.n != 1 {
		t.Fatalf("dispatched %d jobs, want 1 — a failed stamp must not cancel the sweep", d.n)
	}
}

// A tenant the guard refuses gets no stamp pass either: the guard is the
// "may we touch this tenant at all" question, and it comes first.
func TestSweepTenant_DoesNotStampATenantWeMayNoLongerScan(t *testing.T) {
	store := &fakeStore{policy: sharedautoscan.DefaultPolicy()}
	j := newJob(store, &fakeDispatcher{})
	j.isScannable = func(uuid.UUID) (bool, error) { return false, nil }
	j.SweepTenant(context.Background(), uuid.New(), false)

	if store.stampCalls != 0 {
		t.Fatalf("StampCompletedScans called %d times for a tenant the guard refused", store.stampCalls)
	}
}

func TestSweepTenant_SurvivesAStoreThatCannotAnswer(t *testing.T) {
	for name, store := range map[string]*fakeStore{
		"policy unreadable":  {policyErr: errors.New("boom"), policy: sharedautoscan.DefaultPolicy(), targets: targetsAt("10.0.0.1")},
		"targets unreadable": {policy: sharedautoscan.DefaultPolicy(), targetsErr: errors.New("boom")},
	} {
		t.Run(name, func(t *testing.T) {
			d := &fakeDispatcher{}
			newJob(store, d).SweepTenant(context.Background(), uuid.New(), false)
			if len(d.jobs) != 0 {
				t.Errorf("dispatched %d jobs despite the error", len(d.jobs))
			}
		})
	}
}

func TestSweepAll_VisitsEveryTenant(t *testing.T) {
	store := &fakeStore{policy: sharedautoscan.DefaultPolicy(), targets: targetsAt("10.0.0.1")}
	d := &fakeDispatcher{}
	j := newJob(store, d)
	a, b := uuid.New(), uuid.New()
	j.listTenants = func() ([]uuid.UUID, error) { return []uuid.UUID{a, b}, nil }

	j.SweepAll(context.Background())
	if len(d.jobs) != 2 {
		t.Fatalf("dispatched %d jobs, want one per tenant", len(d.jobs))
	}
}

func TestSweepAll_StopsWhenTheContextIsCancelled(t *testing.T) {
	store := &fakeStore{policy: sharedautoscan.DefaultPolicy(), targets: targetsAt("10.0.0.1")}
	d := &fakeDispatcher{}
	j := newJob(store, d)
	j.listTenants = func() ([]uuid.UUID, error) { return []uuid.UUID{uuid.New(), uuid.New()}, nil }

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	j.SweepAll(ctx)
	if len(d.jobs) != 0 {
		t.Errorf("dispatched %d jobs after cancellation", len(d.jobs))
	}
}

// A burst of observations from one tenant is ONE entry, which is what makes 300
// new hosts a bounded number of jobs rather than 300 passes.
func TestNoteObservation_Coalesces(t *testing.T) {
	j := newJob(&fakeStore{}, &fakeDispatcher{})
	tenant := uuid.New()
	for i := 0; i < 300; i++ {
		j.NoteObservation(tenant)
	}
	j.NoteObservation(uuid.New())

	got := j.takeDirty()
	if len(got) != 2 {
		t.Fatalf("takeDirty returned %d tenants, want 2", len(got))
	}
	// And the set is drained, so a pass that finds nothing new does nothing.
	if again := j.takeDirty(); len(again) != 0 {
		t.Errorf("takeDirty returned %d tenants on a second call, want none", len(again))
	}
}

func TestNoteObservation_IgnoresTheNilTenant(t *testing.T) {
	j := newJob(&fakeStore{}, &fakeDispatcher{})
	j.NoteObservation(uuid.Nil)
	if got := j.takeDirty(); len(got) != 0 {
		t.Errorf("the nil tenant was queued: %v", got)
	}
}

// The kill switch has to stop the worker, not merely make it quieter.
func TestKillSwitch(t *testing.T) {
	t.Setenv(EnvAutoScanEnabled, "false")
	store := &fakeStore{policy: sharedautoscan.DefaultPolicy(), targets: targetsAt("10.0.0.1")}
	d := &fakeDispatcher{}
	j := NewAutoActiveScanJob(store, d, nil, nil)
	j.listTenants = func() ([]uuid.UUID, error) { return []uuid.UUID{uuid.New()}, nil }

	// Start returns immediately rather than blocking on a ticker.
	done := make(chan struct{})
	go func() { j.Start(context.Background()); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return with the kill switch set — the worker is still running")
	}
	if len(d.jobs) != 0 {
		t.Errorf("dispatched %d jobs with the kill switch set", len(d.jobs))
	}
	// And an observation reported while it is off queues nothing.
	j.NoteObservation(uuid.New())
	if got := j.takeDirty(); len(got) != 0 {
		t.Errorf("a disabled worker queued %d tenants", len(got))
	}
}

func TestIntervalsComeFromTheEnvironment(t *testing.T) {
	t.Setenv(EnvAutoScanSweepInterval, "3m")
	t.Setenv(EnvAutoScanTriggerInterval, "5s")
	j := NewAutoActiveScanJob(&fakeStore{}, &fakeDispatcher{}, nil, nil)
	if j.sweepInterval != 3*time.Minute || j.triggerInterval != 5*time.Second {
		t.Fatalf("intervals = %v/%v, want 3m/5s", j.sweepInterval, j.triggerInterval)
	}

	// Nonsense falls back to the default rather than to zero, which would spin
	// a ticker as fast as the scheduler allows.
	t.Setenv(EnvAutoScanSweepInterval, "not-a-duration")
	t.Setenv(EnvAutoScanTriggerInterval, "-5s")
	j = NewAutoActiveScanJob(&fakeStore{}, &fakeDispatcher{}, nil, nil)
	if j.sweepInterval != defaultSweepInterval || j.triggerInterval != defaultTriggerInterval {
		t.Fatalf("intervals = %v/%v, want the defaults %v/%v", j.sweepInterval, j.triggerInterval, defaultSweepInterval, defaultTriggerInterval)
	}
}

// The platform's own addresses reach the selector. Without this the exclusion
// list is computed and thrown away, and the sweep would happily probe the
// cluster it runs in.
func TestSweepTenant_HandsTheExclusionsToTheSelector(t *testing.T) {
	t.Setenv(autoscan.EnvExcludeCIDRs, "10.99.0.0/16")
	store := &fakeStore{policy: sharedautoscan.DefaultPolicy()}
	j := NewAutoActiveScanJob(store, &fakeDispatcher{}, nil, nil)
	j.now = func() time.Time { return time.Now() }
	j.SweepTenant(context.Background(), uuid.New(), false)

	found := false
	for _, p := range store.targetsSeen.excluded {
		if p.String() == "10.99.0.0/16" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the selector was given %v, which does not include the operator's excluded range", store.targetsSeen.excluded)
	}
}

// Scanning is something we DO to a customer's estate, so a cancelled account
// whose sensor is still running must stop being scanned. Both entry points need
// the guard: the scheduled pass goes through the enumerator, the
// first-observation pass acts on whatever the NATS consumer marked and never
// touches it.
func TestSweepTenant_SkipsATenantWeMayNoLongerScan(t *testing.T) {
	for _, firstObservation := range []bool{false, true} {
		name := "scheduled pass"
		if firstObservation {
			name = "first-observation pass"
		}
		t.Run(name, func(t *testing.T) {
			store := &fakeStore{policy: sharedautoscan.DefaultPolicy(), targets: targetsAt("10.0.0.1")}
			d := &fakeDispatcher{}
			j := newJob(store, d)
			var asked uuid.UUID
			j.isScannable = func(id uuid.UUID) (bool, error) { asked = id; return false, nil }

			tenant := uuid.New()
			j.SweepTenant(context.Background(), tenant, firstObservation)

			if asked != tenant {
				t.Errorf("the guard was asked about %s, want %s", asked, tenant)
			}
			if len(d.jobs) != 0 {
				t.Fatalf("dispatched %d jobs for a tenant we may no longer scan", len(d.jobs))
			}
			if len(store.stateSet) != 0 {
				t.Errorf("recorded a sweep for a tenant we may no longer scan")
			}
		})
	}
}

// Fail closed: if we cannot find out whether the relationship is still live, we
// do not scan. The alternative is scanning a cancelled customer's network
// because a query timed out.
func TestSweepTenant_SkipsWhenTheTenantGuardCannotAnswer(t *testing.T) {
	store := &fakeStore{policy: sharedautoscan.DefaultPolicy(), targets: targetsAt("10.0.0.1")}
	d := &fakeDispatcher{}
	j := newJob(store, d)
	j.isScannable = func(uuid.UUID) (bool, error) { return false, errors.New("database is down") }

	j.SweepTenant(context.Background(), uuid.New(), false)
	if len(d.jobs) != 0 {
		t.Fatalf("dispatched %d jobs without knowing whether the tenant may be scanned", len(d.jobs))
	}
}

func TestSweepTenant_ScansATenantTheGuardAllows(t *testing.T) {
	// The other polarity. A guard that refuses everything would pass the two
	// tests above and break the product.
	store := &fakeStore{policy: sharedautoscan.DefaultPolicy(), targets: targetsAt("10.0.0.1")}
	d := &fakeDispatcher{}
	j := newJob(store, d)
	j.isScannable = func(uuid.UUID) (bool, error) { return true, nil }

	j.SweepTenant(context.Background(), uuid.New(), false)
	if len(d.jobs) != 1 {
		t.Fatalf("dispatched %d jobs for a live tenant, want 1", len(d.jobs))
	}
}

// inventory-service runs two replicas under values-ha.yaml and both have the
// same ticker. Without the lock the same tenant's sweep runs twice in parallel:
// both read the same eligible set, both see the same empty in-flight set, and
// both dispatch. The in-flight gate cannot close that — the race is between two
// reads that both happen before either write.
func TestSweepPasses_SkipWhenAnotherReplicaHoldsTheLock(t *testing.T) {
	for _, pass := range []struct {
		name string
		run  func(*AutoActiveScanJob, context.Context)
	}{
		{"scheduled sweep", func(j *AutoActiveScanJob, ctx context.Context) { j.SweepAll(ctx) }},
		{"first-observation pass", func(j *AutoActiveScanJob, ctx context.Context) {
			j.NoteObservation(uuid.New())
			j.SweepObserved(ctx)
		}},
	} {
		t.Run(pass.name, func(t *testing.T) {
			store := &fakeStore{policy: sharedautoscan.DefaultPolicy(), targets: targetsAt("10.0.0.1")}
			d := &fakeDispatcher{}
			j := newJob(store, d)
			j.listTenants = func() ([]uuid.UUID, error) { return []uuid.UUID{uuid.New()}, nil }
			j.tryLock = func(context.Context) (func(), bool, error) { return nil, false, nil }

			pass.run(j, context.Background())
			if len(d.jobs) != 0 {
				t.Fatalf("dispatched %d jobs while another replica held the sweep lock", len(d.jobs))
			}
		})
	}
}

func TestSweepAll_ReleasesTheLockAfterThePass(t *testing.T) {
	store := &fakeStore{policy: sharedautoscan.DefaultPolicy()}
	j := newJob(store, &fakeDispatcher{})
	j.listTenants = func() ([]uuid.UUID, error) { return []uuid.UUID{uuid.New()}, nil }
	released := false
	j.tryLock = func(context.Context) (func(), bool, error) {
		return func() { released = true }, true, nil
	}

	j.SweepAll(context.Background())
	if !released {
		t.Fatal("the sweep lock was not released; the next tick on this pod would find it held forever")
	}
}

// A lock error is not a licence to sweep anyway.
func TestSweepAll_SkipsWhenTheLockCannotBeTaken(t *testing.T) {
	store := &fakeStore{policy: sharedautoscan.DefaultPolicy(), targets: targetsAt("10.0.0.1")}
	d := &fakeDispatcher{}
	j := newJob(store, d)
	j.listTenants = func() ([]uuid.UUID, error) { return []uuid.UUID{uuid.New()}, nil }
	j.tryLock = func(context.Context) (func(), bool, error) { return nil, false, errors.New("no connection") }

	j.SweepAll(context.Background())
	if len(d.jobs) != 0 {
		t.Fatalf("dispatched %d jobs without holding the sweep lock", len(d.jobs))
	}
}

// The source guard. Nothing else in this repository can observe a startup line
// that stopped being executed, and both of these lines are deletable with the
// whole suite staying green.
func TestAutoActiveScan_MainStartsTheWorker(t *testing.T) {
	src, err := os.ReadFile("../../cmd/main.go")
	if err != nil {
		t.Fatalf("reading cmd/main.go: %v", err)
	}
	main := string(src)

	for _, want := range []string{
		// The sweep is constructed and STARTED. Constructing it alone would
		// leave a worker that never ticks.
		// The router is the wiring for tenant-sensor dispatch: pass
		// nil here and every automatic scan silently runs from the platform
		// again, with the settings switch still shown.
		"jobs.NewAutoActiveScanJob(autoScanStore, discoveryService, sensorrouting.NewStore(db), bypassDB)",
		"autoScanJob.Start(ctx)",
		// ...and the first-observation trigger is subscribed to it. Without
		// this the product still rescans on schedule and silently stops doing
		// the "scan it the moment we see it" half.
		"subscribers.NewAutoScanSubscriber(natsClient, autoScanJob)",
		"autoScanSubscriber.Start()",
		// ...and the settings page's endpoints are reachable.
		"handlers.NewAutoScanHandler(autoScanStore)",
		`"/discovery/auto-scan", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionSettingsRead), autoScanHandler.GetAutoScan`,
		`"/discovery/auto-scan", sharedrbac.RequireTenantPermission(rawDB, rbac.PermissionSettingsUpdate), autoScanHandler.UpdateAutoScan`,
	} {
		if !strings.Contains(main, want) {
			t.Errorf("cmd/main.go no longer contains %q — that layer is built and never reached", want)
		}
	}
}

// A kill switch that does not exist in the pod is not a kill switch.
//
// A backend's environment is the shared ConfigMap plus its `extraEnv` list, and
// the worker reads these with os.Getenv — so with no chart entry the variable
// simply does not exist in the pod, os.Getenv returns "", and an unset value
// means ON. The switch would be documented and unreachable, which is the exact
// shape of "a fix that compiles, passes its tests, and does nothing in
// production". Nothing else in the repository can observe that.
func TestAutoActiveScan_TheKillSwitchExistsWhereItIsRead(t *testing.T) {
	read := func(t *testing.T, rel string) string {
		t.Helper()
		b, err := os.ReadFile(rel)
		if err != nil {
			t.Fatalf("reading %s: %v", rel, err)
		}
		return string(b)
	}

	// The names the CODE reads, not literals typed twice.
	wanted := []string{EnvAutoScanEnabled, EnvAutoScanSweepInterval, EnvAutoScanTriggerInterval, autoscan.EnvExcludeCIDRs}

	values := read(t, "../../../../charts/vistaplatform/values.yaml")
	// Scoped to this service's block: the variable existing under SOME backend
	// would satisfy a whole-file search while doing nothing for this pod.
	start := strings.Index(values, "\n  inventory-service:")
	if start < 0 {
		t.Fatal("values.yaml has no inventory-service backend block")
	}
	rest := values[start+1:]
	end := strings.Index(rest, "\n  compliance-engine:")
	if end < 0 {
		t.Fatal("could not find the end of the inventory-service block in values.yaml")
	}
	block := rest[:end]
	for _, name := range wanted {
		if !strings.Contains(block, name) {
			t.Errorf("charts/vistaplatform/values.yaml: %s is missing from backends.inventory-service.extraEnv — it does not exist in the pod, so the code's os.Getenv returns \"\" and the switch is unreachable", name)
		}
	}

	env := read(t, "../../../../env.example")
	for _, name := range wanted {
		if !strings.Contains(env, name) {
			t.Errorf("env.example: %s is undocumented, so a compose operator cannot find it", name)
		}
	}
}
