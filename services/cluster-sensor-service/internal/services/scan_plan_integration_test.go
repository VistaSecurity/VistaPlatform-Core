package services

// Hole H37 against a real Postgres: the Discover wizard's "Cloud —
// platform sensor" option sends execution_mode "cloud", which the job
// processor reads, when STORED, as a cloud-ACCOUNT discovery and hands to
// device-interrogation-service — where it fails with "no integration_id in job
// metadata". On POST /discovery/jobs "cloud" means "run from the platform", so
// it must be stored as the in-cluster mode and run here.
//
// Skips without TEST_DATABASE_URL (make test-integration-db).

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/cluster-sensor-service/internal/models"
	shareddisc "github.com/vistasecurity/vistaplatform/shared/discovery"
	"github.com/vistasecurity/vistaplatform/shared/identity/dispatchguard"
)

func TestIntegration_CreateJob_LegacyCloudIsNotDelegatedToDeviceInterrogation(t *testing.T) {
	f := newDispatchFixture(t)
	// Wizard-shaped: protocols × ports and execution_mode "cloud". Active
	// scanning off so the processor stops after its routing decisions instead
	// of dialling anything.
	job, err := f.svc.CreateJob(f.tenant.String(), "system", models.CreateDiscoveryJobRequest{
		Targets:       []string{"10.184.0.10"},
		ExecutionMode: "cloud",
		Protocols:     []string{"TLS"},
		Ports:         []int{443},
		Options:       map[string]interface{}{"active_scanning": false},
	})
	if err != nil {
		t.Fatalf("CreateJob: %v", err)
	}
	var stored string
	if err := f.db.QueryRow(`SELECT execution_mode FROM discovery_jobs WHERE id = $1`, job.ID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored == "cloud" || stored != platformExecutionMode {
		t.Fatalf("execution_mode stored as %q, want %q (never \"cloud\")", stored, platformExecutionMode)
	}

	loaded, err := f.svc.GetJob(job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.jp.processDiscoveryJob(context.Background(), loaded); err != nil {
		t.Fatalf("processDiscoveryJob: %v — a wizard job must run in-cluster, not be delegated as a cloud-account discovery", err)
	}
	var delegated int
	if err := f.db.QueryRow(`SELECT count(*) FROM device_jobs WHERE parameters->>'discovery_job_id' = $1`, job.ID).Scan(&delegated); err != nil {
		t.Fatal(err)
	}
	if delegated != 0 {
		t.Fatalf("%d device_jobs created for a wizard job", delegated)
	}
}

// The scan-plan path reads the same legacy value as run_from "platform".
func TestIntegration_CreateJob_ScanPlanCloudAliasIsPlatform(t *testing.T) {
	f := newDispatchFixture(t)
	job, err := f.svc.CreateJob(f.tenant.String(), "system", models.CreateDiscoveryJobRequest{
		Targets: []string{"10.184.0.11"}, ExecutionMode: "cloud", ScanDepth: "quick",
	})
	if err != nil {
		t.Fatalf("CreateJob: %v", err)
	}
	if job.ExecutionMode != platformExecutionMode || job.Plan == nil || job.Plan.RunFromRequested != shareddisc.RunFromPlatform || job.Plan.ExecutorResolved != shareddisc.ExecutorPlatform {
		t.Fatalf("job = %+v plan = %+v", job, job.Plan)
	}
}

// The automatic sweep may be a planned job ( WP2), but never a deep one:
// Thorough (every TCP port, plus UDP) is a person's choice. Refused by the
// automatic-scan authorization, and nothing is written.
func TestIntegration_CreateJob_AutomaticScanPlanCannotBeThorough(t *testing.T) {
	f := newDispatchFixture(t)
	before := f.countJobs(t)
	_, err := f.svc.CreateJob(f.tenant.String(), "system", models.CreateDiscoveryJobRequest{
		Targets: []string{"10.184.0.12"}, ScanDepth: "thorough",
		Options: map[string]interface{}{"origin": "auto_scan"},
	})
	if !errors.Is(err, dispatchguard.ErrDenied) || !strings.Contains(err.Error(), "custom or quick") {
		t.Fatalf("err = %v, want the automatic-scan depth refusal", err)
	}
	if after := f.countJobs(t); after != before {
		t.Fatalf("jobs %d → %d: a refused automatic scan wrote a job", before, after)
	}
}

// insertLegacyPlatformJob writes the row an older release created for a
// protocols × ports request run from the platform: no scan plan, one target
// row naming protocols and ports. Nothing in this release creates one.
func (f *dispatchFixture) insertLegacyPlatformJob(t *testing.T, target string) string {
	t.Helper()
	var id string
	if err := f.raw.QueryRow(`INSERT INTO discovery_jobs (tenant_id, execution_mode, status, metadata)
		VALUES ($1, 'async', 'queued', '{"options":{"origin":"manual"}}') RETURNING id`, f.tenant).Scan(&id); err != nil {
		t.Fatalf("insert legacy job: %v", err)
	}
	if _, err := f.raw.Exec(`INSERT INTO discovery_targets (job_id, tenant_id, input, protocols, ports, status)
		VALUES ($1, $2, $3, '{TLS,SSH}', '{443,22}', 'pending')`, id, f.tenant, target); err != nil {
		t.Fatalf("insert legacy target: %v", err)
	}
	return id
}

// TestProcessDiscoveryJob_FailsALegacyPlatformJob: the platform has no
// protocols × ports executor any more ( WP5). A legacy job queued across
// the upgrade must FAIL with a reason a person can act on — through the real
// entry point — and contact nothing; it must not end "completed" having
// scanned nothing. Mutation: delete the errLegacyPlatformJob return in
// processDiscoveryJob and the job completes, turning this red.
func TestIntegration_ProcessDiscoveryJob_FailsALegacyPlatformJob(t *testing.T) {
	f, fake := newUnitFixture(t)
	fake.Host("10.184.0.20", nil, nil)
	jobID := f.insertLegacyPlatformJob(t, "10.184.0.20")

	if err := f.jp.handleDiscoveryJob(jobMessage(t, jobID), &countingLease{}); err != nil {
		t.Fatalf("handleDiscoveryJob: %v", err)
	}
	var status, msg string
	if err := f.raw.QueryRow(`SELECT status, COALESCE(error_message, '') FROM discovery_jobs WHERE id = $1`, jobID).Scan(&status, &msg); err != nil {
		t.Fatal(err)
	}
	if status != "failed" || !strings.Contains(msg, "protocols × ports") || !strings.Contains(msg, "Run the scan again") {
		t.Fatalf("legacy platform job ended %q (%q), want failed with the reason", status, msg)
	}
	if dials := fake.Dials(); len(dials) != 0 {
		t.Fatalf("a legacy job the platform cannot run contacted %v", dials)
	}
	if n := f.findingCount(t, jobID); n != 0 {
		t.Fatalf("%d findings stored for a job that was not run", n)
	}
}

// The legacy request shape is planned at creation ( D2, WP5): there is
// no switch that would leave it to an executor that no longer exists. The
// processor then runs it on the shared engine, not the failure above.
func TestIntegration_CreateJob_LegacyShapeFromThePlatformIsPlanned(t *testing.T) {
	f := newDispatchFixture(t)
	job, err := f.svc.CreateJob(f.tenant.String(), "system", models.CreateDiscoveryJobRequest{
		Targets: []string{"10.184.0.21"}, ExecutionMode: "async", Protocols: []string{"TLS", "SSH"}, Ports: []int{443, 22},
	})
	if err != nil {
		t.Fatalf("CreateJob: %v", err)
	}
	if job.Plan == nil || job.Plan.Depth != shareddisc.DepthCustom || job.Plan.TCPPorts != "22,443" || job.Plan.ExecutorResolved != shareddisc.ExecutorPlatform {
		t.Fatalf("legacy request from the platform: plan = %+v, want custom on 22,443 run from the platform", job.Plan)
	}
}
