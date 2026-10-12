package services

import (
	"context"
	"testing"

	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// HasInterrogationJob is what stops the credential-update kickoff piling a
// second first-run on a device. Pending, running and completed count; failed
// and cancelled do not, and neither does another tenant's device.
func TestIntegration_HasInterrogationJob(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db)
	other := testdb.NewTenant(t, db)
	devices := NewDeviceServiceWithKey(db, testMasterKey)
	queue := NewJobQueueService(db, db, nil)
	ctx := context.Background()
	device, err := devices.CreateDevice(ctx, tenant, models.CreateDeviceRequest{DeviceType: "unifi", Hostname: strptr("history.example.test"), ManagementURL: strptr("https://192.0.2.4")})
	if err != nil {
		t.Fatal(err)
	}
	has := func(tn interface{ String() string }, label string, want bool) {
		t.Helper()
		got, err := queue.HasInterrogationJob(ctx, tenant, device.ID)
		if tn.String() == other.String() {
			got, err = queue.HasInterrogationJob(ctx, other, device.ID)
		}
		if err != nil || got != want {
			t.Fatalf("%s: got %v (err %v), want %v", label, got, err, want)
		}
	}
	has(tenant, "no job", false)
	job, err := queue.CreateJob(ctx, models.CreateDeviceJobRequest{TenantID: tenant, JobType: models.JobTypeDeviceInterrogation, AssetID: &device.ID})
	if err != nil {
		t.Fatal(err)
	}
	has(tenant, "pending", true)
	has(other, "other tenant", false)
	for status, want := range map[string]bool{"failed": false, "cancelled": false, "in_progress": true, "completed": true} {
		if _, err := db.Exec(`UPDATE device_jobs SET status=$2 WHERE id=$1`, job.ID, status); err != nil {
			t.Fatal(err)
		}
		has(tenant, status, want)
	}
}
