package services

// The cluster's own pod and Service CIDRs (VISTA_PLATFORM_INTERNAL_CIDRS) are
// refused for a scan the in-cluster PLATFORM sensor executes, and only for that:
// to a tenant's own on-premises sensor the same numbers are the customer's
// address space. Both polarities, at both doors — job creation and the per-unit
// authorization at dispatch — against a real Postgres. The test addresses are
// the 10.183.0.0/16 range every fixture here uses, declared as the cluster's
// range for the test's duration.

import (
	"strings"
	"testing"

	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/identity/dispatchguard"
	"github.com/vistasecurity/vistaplatform/shared/sensordispatch"
)

const clusterRange = "10.183.0.0/16"

func TestIntegration_ClusterRanges_RefusedForPlatformSensorScans(t *testing.T) {
	f, _ := newUnitFixture(t)
	t.Setenv("VISTA_PLATFORM_INTERNAL_CIDRS", clusterRange)

	// Creation: a job the platform would run in-cluster is refused.
	_, err := f.svc.CreateJob(f.tenant.String(), f.tenantUser(t), models.CreateDiscoveryJobRequest{
		Targets: []string{"10.183.0.10"}, ScanDepth: "quick", RunFrom: "platform",
	})
	if err == nil {
		t.Fatal("a Platform Sensor scan of the cluster's own range was created")
	}
	if !strings.Contains(err.Error(), "never scans") && !strings.Contains(err.Error(), "refused") && !strings.Contains(err.Error(), "scan") {
		t.Fatalf("refused for the wrong reason: %v", err)
	}

	// Dispatch: a platform job created BEFORE the range was declared (an
	// upgrade, or a segment edit) is re-judged per unit and its unit fails.
	t.Setenv("VISTA_PLATFORM_INTERNAL_CIDRS", "")
	jobID := f.createPlanJob(t, "22", "10.183.0.20")
	t.Setenv("VISTA_PLATFORM_INTERNAL_CIDRS", clusterRange)
	job, _ := f.svc.GetJob(jobID)
	if claimed, err := f.svc.ClaimJob(jobID); err != nil || !claimed {
		t.Fatal(claimed, err)
	}
	run, targets, err := f.jp.newPlanRun(job, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.jp.ensureUnits(job, targets, run.auth); err != nil {
		t.Fatal(err)
	}
	if st := f.unitStatuses(t, jobID); st["10.183.0.20"] != unitFailed {
		t.Fatalf("unit statuses = %v, want the cluster-range address failed by the platform authorizer", st)
	}
}

func TestIntegration_ClusterRanges_StillAllowedForATenantSensor(t *testing.T) {
	f, _ := newUnitFixture(t)
	t.Setenv("VISTA_PLATFORM_INTERNAL_CIDRS", clusterRange)

	// Creation and dispatch of a plan job on a tenant's own sensor.
	sensor := f.liveSensor(t, "branch-onprem")
	if _, err := f.raw.Exec(`UPDATE sensors SET reported_capabilities = $2 WHERE id = $1`, sensor, pq.Array([]string{sensordispatch.ScanPlanCapability})); err != nil {
		t.Fatal(err)
	}
	job, err := f.svc.CreateJob(f.tenant.String(), "system", models.CreateDiscoveryJobRequest{
		Targets: []string{"10.183.0.10"}, ScanDepth: "quick", RunFrom: "sensor", SensorID: sensor.String(),
	})
	if err != nil {
		t.Fatalf("a tenant sensor's scan of its own LAN, which overlaps the cluster ranges, was refused at creation: %v", err)
	}
	full, err := f.svc.GetJob(job.ID)
	if err != nil || full.Plan == nil {
		t.Fatalf("GetJob: %+v %v", full, err)
	}
	if err := f.jp.dispatchToSensor(full); err != nil {
		t.Fatalf("dispatchToSensor: %v", err)
	}
	if status, _, _, errMsg := f.jobRow(t, job.ID); status != sensordispatch.StatusAwaitingSensor {
		t.Fatalf("job = %s / %v, want %s (handed to the tenant sensor)", status, errMsg, sensordispatch.StatusAwaitingSensor)
	}
	if st := f.unitStatuses(t, job.ID); st["10.183.0.10"] == unitFailed {
		t.Fatalf("unit statuses = %v: the tenant sensor's address was failed by the cluster-range rule", st)
	}

	// The authorizer itself, both executors, same address.
	for name, platform := range map[string]bool{"platform sensor": true, "tenant sensor": false} {
		a := &unitAuthorizer{jp: f.jp, tenantID: f.tenant.String(), platformExecutor: platform}
		err := a.authorize("10.183.0.30", dispatchguard.DispatchConsent{})
		if platform && err == nil {
			t.Errorf("%s: the cluster-range address was authorized", name)
		}
		if !platform && err != nil {
			t.Errorf("%s: the same address was refused: %v", name, err)
		}
	}
}
