package services

// Two tenants on one replica ( H33 and WP2 item 9). Tenant A starts a
// long scan; tenant B's scan, delivered after it to the SAME processor, runs
// and finishes while A's is still going — the handler is not held by A — and
// A never has more units in flight than its share, nor the replica more than
// its cap.
//
// Skips without TEST_DATABASE_URL (make test-integration-db).

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_PlanUnits_TwoTenantsShareTheReplica(t *testing.T) {
	f, fake := newUnitFixture(t)
	f.jp.detachPlanJobs = true
	f.jp.units = newUnitScheduler(unitConcurrency{Global: 2, PerTenant: 1})

	// Tenant B: same database, same processor.
	fb := *f
	fb.tenant = testdb.NewTenant(t, f.raw)
	if _, err := f.raw.Exec(`INSERT INTO sensors (id, tenant_id, name, platform, version, profile, status, tags, ip_address, reporting_interval, last_heartbeat)
		VALUES ($1, $2, 'Platform Discovery Sensor', 'platform', '1.0.0', 'discovery', 'active', '{system}', '10.0.0.1', 30, NOW())`, uuid.New(), fb.tenant); err != nil {
		t.Fatal(err)
	}

	// A: four named hosts whose port scans are held until the test lets go.
	release := make(chan struct{})
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	aHosts := []string{"10.183.10.1", "10.183.10.2", "10.183.10.3", "10.183.10.4"}
	held := map[string]bool{}
	for _, h := range aHosts {
		fake.Host(h, nil, nil)
		held[h] = true
	}
	fake.Host("10.183.11.1", nil, nil)
	fake.OnDial = func(ctx context.Context, _ string, ap netip.AddrPort) {
		if held[ap.Addr().String()] {
			select {
			case <-release:
			case <-ctx.Done():
			}
		}
	}

	jobA := f.createPlanJob(t, "20-30", aHosts...)
	jobB := fb.createPlanJob(t, "20-30", "10.183.11.1")
	if err := f.jp.handleDiscoveryJob(jobMessage(t, jobA), &countingLease{}); err != nil {
		t.Fatal(err)
	}
	// The handler returned at once: A runs on its own.
	if err := f.jp.handleDiscoveryJob(jobMessage(t, jobB), &countingLease{}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for f.jobStatus(t, jobB) != "completed" {
		if time.Now().After(deadline) {
			t.Fatalf("tenant B's scan did not finish while tenant A's was held (A %s, B %s)", f.jobStatus(t, jobA), f.jobStatus(t, jobB))
		}
		time.Sleep(50 * time.Millisecond)
	}
	if s := f.jobStatus(t, jobA); s != "running" {
		t.Fatalf("tenant A's job is %s while held, want running", s)
	}
	close(release)
	f.jp.inflight.Wait()
	if s := f.jobStatus(t, jobA); s != "completed" {
		t.Fatalf("tenant A's job = %s after release, want completed", s)
	}
	global, perA := f.jp.units.peaks(f.tenant.String())
	if perA != 1 || global > 2 {
		t.Fatalf("peaks: tenant A held %d slot(s) at once (cap 1), the replica %d (cap 2)", perA, global)
	}
}
