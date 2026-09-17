package jobs

// Tenant-sensor routing inside the automatic sweep, through a fake
// router: one `sensors` job per observing sensor, platform for the rest, an
// offline observer's targets skipped AND left unstamped, and the whole thing
// off when the tenant's switch is off.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/autoscan"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/sensorrouting"
	sharedautoscan "github.com/vistasecurity/vistaplatform/shared/autoscan"
)

type fakeRouter struct {
	plan  sensorrouting.Plan
	err   error
	calls int
	seen  []string
}

func (r *fakeRouter) Resolve(_ context.Context, _ uuid.UUID, targets []string, _ time.Time) (sensorrouting.Plan, error) {
	r.calls++
	r.seen = append(r.seen, targets...)
	return r.plan, r.err
}

func routedJob(store autoScanStore, dispatcher autoScanDispatcher, router autoScanRouter) *AutoActiveScanJob {
	j := NewAutoActiveScanJob(store, dispatcher, router, nil)
	j.now = func() time.Time { return time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC) }
	return j
}

func liveSensorNamed(name string) sensorrouting.Sensor {
	beat := time.Date(2026, 9, 17, 11, 59, 30, 0, time.UTC)
	return sensorrouting.Sensor{ID: uuid.New(), Name: name, Status: "active", LastHeartbeat: &beat, ReportingInterval: 30}
}

func TestSweepTenant_RoutesToTheObservingSensor(t *testing.T) {
	xps := liveSensorNamed("xps16-sensor")
	targets := targetsAt("10.0.0.1", "10.0.0.2", "10.0.0.3")
	store := &fakeStore{policy: sharedautoscan.DefaultPolicy(), targets: targets}
	d := &fakeDispatcher{}
	router := &fakeRouter{plan: sensorrouting.Plan{
		Groups:   []sensorrouting.Group{{Sensor: xps, Targets: []string{"10.0.0.1", "10.0.0.2"}}},
		Platform: []string{"10.0.0.3"},
	}}
	routedJob(store, d, router).SweepTenant(context.Background(), uuid.New(), false)

	if router.calls != 1 || len(router.seen) != 3 {
		t.Fatalf("router consulted %d time(s) over %v, want once over all three", router.calls, router.seen)
	}
	if len(d.jobs) != 2 {
		t.Fatalf("dispatched %d jobs, want 2 (one sensor, one platform): %+v", len(d.jobs), d.jobs)
	}
	sensorJob, platformJob := d.jobs[0], d.jobs[1]
	if sensorJob.ExecutionMode != "sensors" || len(sensorJob.PreferredSensorIDs) != 1 || sensorJob.PreferredSensorIDs[0] != xps.ID.String() {
		t.Errorf("sensor job = mode %q sensors %v, want sensors/[xps16]", sensorJob.ExecutionMode, sensorJob.PreferredSensorIDs)
	}
	if len(sensorJob.Targets) != 2 || sensorJob.Targets[0] != "10.0.0.1" {
		t.Errorf("sensor job targets = %v", sensorJob.Targets)
	}
	if platformJob.ExecutionMode != "async" || len(platformJob.PreferredSensorIDs) != 0 || len(platformJob.Targets) != 1 || platformJob.Targets[0] != "10.0.0.3" {
		t.Errorf("platform job = %+v", platformJob)
	}
	// Both jobs carry the tenant's policy and the automatic-scan origin.
	for _, job := range d.jobs {
		if job.Options["origin"] != autoscan.Origin || len(job.Protocols) != len(store.policy.Protocols) {
			t.Errorf("job lost its policy/origin: %+v", job)
		}
	}
	// Each asset is stamped by the job that probes ITS address.
	if len(store.recorded) != 2 || len(store.recorded[0].assetIDs) != 2 || store.recorded[0].jobID != "job-a" ||
		len(store.recorded[1].assetIDs) != 1 || store.recorded[1].jobID != "job-b" {
		t.Errorf("stamps = %+v", store.recorded)
	}
	if store.stateSet[0].LastSweepJobs != 2 || store.stateSet[0].LastSweepAssets != 3 {
		t.Errorf("state = %+v, want 2 jobs / 3 assets", store.stateSet[0])
	}
}

// The guard: an offline observing sensor's targets are neither scanned from
// the platform NOR stamped as scanned. Make the router hand them to the
// platform instead (or stamp them here) and this goes red.
func TestSweepTenant_SkipsAndDoesNotStampAnOfflineObserversTargets(t *testing.T) {
	xps := liveSensorNamed("xps16-sensor")
	stale := time.Date(2026, 9, 17, 10, 0, 0, 0, time.UTC)
	xps.LastHeartbeat = &stale
	store := &fakeStore{policy: sharedautoscan.DefaultPolicy(), targets: targetsAt("10.0.0.1", "10.0.0.2")}
	d := &fakeDispatcher{}
	router := &fakeRouter{plan: sensorrouting.Plan{
		Platform: []string{"10.0.0.2"},
		Skipped:  []sensorrouting.Skip{{Target: "10.0.0.1", Sensor: xps, Reason: sensorrouting.ReasonObserverOffline}},
	}}
	routedJob(store, d, router).SweepTenant(context.Background(), uuid.New(), false)

	if len(d.jobs) != 1 || d.jobs[0].ExecutionMode != "async" || len(d.jobs[0].Targets) != 1 || d.jobs[0].Targets[0] != "10.0.0.2" {
		t.Fatalf("jobs = %+v, want only the platform job for 10.0.0.2", d.jobs)
	}
	if len(store.recorded) != 1 || len(store.recorded[0].assetIDs) != 1 {
		t.Fatalf("stamps = %+v, want only 10.0.0.2's asset", store.recorded)
	}
	if store.stateSet[0].LastSweepAssets != 1 {
		t.Errorf("state = %+v, want 1 asset", store.stateSet[0])
	}
}

func TestSweepTenant_SwitchOffScansEverythingFromThePlatform(t *testing.T) {
	policy := sharedautoscan.DefaultPolicy()
	policy.PreferObservingSensor = false
	store := &fakeStore{policy: policy, targets: targetsAt("10.0.0.1", "10.0.0.2")}
	d := &fakeDispatcher{}
	router := &fakeRouter{plan: sensorrouting.Plan{Groups: []sensorrouting.Group{{Sensor: liveSensorNamed("xps16-sensor"), Targets: []string{"10.0.0.1", "10.0.0.2"}}}}}
	routedJob(store, d, router).SweepTenant(context.Background(), uuid.New(), false)

	if router.calls != 0 {
		t.Errorf("router consulted %d time(s) with the switch off", router.calls)
	}
	if len(d.jobs) != 1 || d.jobs[0].ExecutionMode != "async" || len(d.jobs[0].PreferredSensorIDs) != 0 {
		t.Fatalf("jobs = %+v, want one platform job", d.jobs)
	}
}

// A router that cannot answer must not stop the sweep: the platform scans this
// pass, loudly, which is the behaviour every tenant had before routing existed.
func TestSweepTenant_RouterFailureFallsBackToThePlatform(t *testing.T) {
	store := &fakeStore{policy: sharedautoscan.DefaultPolicy(), targets: targetsAt("10.0.0.1")}
	d := &fakeDispatcher{}
	routedJob(store, d, &fakeRouter{err: errors.New("sensors table unreadable")}).SweepTenant(context.Background(), uuid.New(), false)
	if len(d.jobs) != 1 || d.jobs[0].ExecutionMode != "async" {
		t.Fatalf("jobs = %+v, want one platform job", d.jobs)
	}
}

func TestSweepTenant_NoRouterWiredScansFromThePlatform(t *testing.T) {
	store := &fakeStore{policy: sharedautoscan.DefaultPolicy(), targets: targetsAt("10.0.0.1")}
	d := &fakeDispatcher{}
	routedJob(store, d, nil).SweepTenant(context.Background(), uuid.New(), false)
	if len(d.jobs) != 1 || d.jobs[0].ExecutionMode != "async" {
		t.Fatalf("jobs = %+v", d.jobs)
	}
}

// A sensor job that cluster-sensor refuses (the sensor went offline between
// routing and creation) is not stamped, and the platform job beside it still
// goes out.
func TestSweepTenant_ARefusedSensorJobIsNotStampedAndDoesNotBlockThePlatformJob(t *testing.T) {
	xps := liveSensorNamed("xps16-sensor")
	store := &fakeStore{policy: sharedautoscan.DefaultPolicy(), targets: targetsAt("10.0.0.1", "10.0.0.2")}
	d := &refusingDispatcher{refuseMode: "sensors"}
	router := &fakeRouter{plan: sensorrouting.Plan{
		Groups:   []sensorrouting.Group{{Sensor: xps, Targets: []string{"10.0.0.1"}}},
		Platform: []string{"10.0.0.2"},
	}}
	routedJob(store, d, router).SweepTenant(context.Background(), uuid.New(), false)

	if d.accepted != 1 {
		t.Fatalf("accepted %d job(s), want the platform job", d.accepted)
	}
	if len(store.recorded) != 1 || len(store.recorded[0].assetIDs) != 1 {
		t.Fatalf("stamps = %+v, want only the platform job's asset", store.recorded)
	}
}

type refusingDispatcher struct {
	fakeDispatcher
	refuseMode string
	accepted   int
}

func (d *refusingDispatcher) CreateJobInternal(tenantID string, input models.CreateDiscoveryJobInput) (*models.DiscoveryJob, error) {
	if input.ExecutionMode == d.refuseMode {
		return nil, errors.New("409: sensor offline; nothing was scanned")
	}
	d.accepted++
	return d.fakeDispatcher.CreateJobInternal(tenantID, input)
}
