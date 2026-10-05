package jobs

// A dispatch call that errors AFTER cluster-sensor-service created the job
// (the client's 30 s timeout against a slow job creation) must not make the
// next sweep dispatch the same hosts again.
//
// orphanWorld is a tiny stand-in for the two tables that matter: a dispatcher
// that creates the job and still returns an error, and a store whose
// AdoptRecentJobs stamps from the jobs that exist and whose EligibleTargets
// leaves stamped assets out, as the real ones do.

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/autoscan"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	sharedautoscan "github.com/vistasecurity/vistaplatform/shared/autoscan"
)

type createdJob struct {
	id        string
	addresses []string
	at        time.Time
}

type orphanWorld struct {
	*fakeStore
	assets  []autoscan.Target
	stamped map[uuid.UUID]time.Time
	jobs    []createdJob
}

func newOrphanWorld(addresses ...string) *orphanWorld {
	w := &orphanWorld{
		fakeStore: &fakeStore{policy: sharedautoscan.DefaultPolicy()},
		assets:    targetsAt(addresses...),
		stamped:   map[uuid.UUID]time.Time{},
	}
	return w
}

func (w *orphanWorld) EligibleTargets(_ context.Context, _ uuid.UUID, p autoscan.Policy, now time.Time, _ []netip.Prefix) ([]autoscan.Target, map[sharedautoscan.Reason]int, error) {
	cutoff := now.Add(-time.Duration(p.RescanIntervalHours) * time.Hour)
	var due []autoscan.Target
	for _, a := range w.assets {
		if at, ok := w.stamped[a.AssetID]; ok && !at.Before(cutoff) {
			continue
		}
		due = append(due, a)
	}
	return due, nil, nil
}

func (w *orphanWorld) RecordScanned(ctx context.Context, tenant uuid.UUID, ids []uuid.UUID, jobID string, at time.Time) error {
	for _, id := range ids {
		w.stamped[id] = at
	}
	return w.fakeStore.RecordScanned(ctx, tenant, ids, jobID, at)
}

func (w *orphanWorld) AdoptRecentJobs(ctx context.Context, tenant uuid.UUID, since time.Time) (int, error) {
	if _, err := w.fakeStore.AdoptRecentJobs(ctx, tenant, since); err != nil {
		return 0, err
	}
	n := 0
	for _, j := range w.jobs {
		if j.at.Before(since) {
			continue
		}
		for _, a := range w.assets {
			for _, addr := range j.addresses {
				if a.Address != addr {
					continue
				}
				if at, ok := w.stamped[a.AssetID]; ok && !at.Before(j.at) {
					continue
				}
				w.stamped[a.AssetID] = j.at
				n++
			}
		}
	}
	return n, nil
}

// timeoutAfterCreate creates the job, then reports the failure the HTTP
// client saw.
type timeoutAfterCreate struct {
	world *orphanWorld
	now   time.Time
	calls int
}

func (d *timeoutAfterCreate) CreateJobInternal(_ string, in models.CreateDiscoveryJobInput) (*models.DiscoveryJob, error) {
	d.calls++
	d.world.jobs = append(d.world.jobs, createdJob{id: "orphan", addresses: in.Targets, at: d.now})
	return nil, errors.New("context deadline exceeded (Client.Timeout exceeded while awaiting headers)")
}

func TestSweepTenant_ATimedOutDispatchDoesNotRequeueTheEstateNextSweep(t *testing.T) {
	w := newOrphanWorld("10.0.0.1", "10.0.0.2", "10.0.0.3")
	d := &timeoutAfterCreate{world: w, now: time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)}
	job := newJob(w, d)
	tenant := uuid.New()

	job.SweepTenant(context.Background(), tenant, false)
	if d.calls != 1 {
		t.Fatalf("first sweep dispatched %d times, want 1", d.calls)
	}
	if len(w.stamped) != 0 {
		t.Fatalf("setup: the failed dispatch must not have stamped anything itself, got %d stamps", len(w.stamped))
	}

	// Fifteen minutes later: the job exists, the stamp does not.
	job.now = func() time.Time { return time.Date(2026, 9, 17, 12, 15, 0, 0, time.UTC) }
	job.SweepTenant(context.Background(), tenant, false)

	if d.calls != 1 {
		t.Fatalf("second sweep dispatched again (%d calls total): the orphaned job was not adopted, so the whole estate is re-queued every pass", d.calls)
	}
	if len(w.stamped) != 3 {
		t.Fatalf("%d assets stamped after adoption, want 3", len(w.stamped))
	}
}

func TestSweepTenant_AdoptsWithinTheTenantsRescanInterval(t *testing.T) {
	w := newOrphanWorld("10.0.0.1")
	w.policy.RescanIntervalHours = 6
	job := newJob(w, &fakeDispatcher{})
	job.SweepTenant(context.Background(), uuid.New(), false)

	want := job.now().Add(-6 * time.Hour)
	if !w.adoptSince.Equal(want) {
		t.Fatalf("adopt window starts %v, want %v — it must be the tenant's rescan interval", w.adoptSince, want)
	}
}

func TestSweepTenant_AdoptsBeforeSelectingTargets(t *testing.T) {
	// The whole point: the stamp has to exist by the time EligibleTargets
	// runs, so an orphaned job's hosts are never in the due list.
	w := newOrphanWorld("10.0.0.1")
	d := &fakeDispatcher{}
	w.jobs = []createdJob{{id: "orphan", addresses: []string{"10.0.0.1"}, at: time.Date(2026, 9, 17, 11, 50, 0, 0, time.UTC)}}
	newJob(w, d).SweepTenant(context.Background(), uuid.New(), false)
	if d.n != 0 {
		t.Fatalf("dispatched %d jobs for a host an orphaned recent job already covers", d.n)
	}
}

func TestSweepTenant_AdoptFailureDoesNotStopThePass(t *testing.T) {
	store := &fakeStore{
		policy:   sharedautoscan.DefaultPolicy(),
		targets:  targetsAt("10.0.0.1"),
		adoptErr: errors.New("assets is locked"),
	}
	d := &fakeDispatcher{}
	newJob(store, d).SweepTenant(context.Background(), uuid.New(), false)
	if d.n != 1 {
		t.Fatalf("dispatched %d jobs, want 1 — a failed adoption must not cancel the sweep", d.n)
	}
}

func TestSweepTenant_DoesNotAdoptForATenantWeMayNoLongerScan(t *testing.T) {
	store := &fakeStore{policy: sharedautoscan.DefaultPolicy()}
	j := newJob(store, &fakeDispatcher{})
	j.isScannable = func(uuid.UUID) (bool, error) { return false, nil }
	j.SweepTenant(context.Background(), uuid.New(), false)
	if store.adoptCalls != 0 {
		t.Fatalf("AdoptRecentJobs called %d times for a tenant the guard refused", store.adoptCalls)
	}
}
