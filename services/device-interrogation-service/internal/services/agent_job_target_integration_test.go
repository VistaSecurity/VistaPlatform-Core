package services

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// TestIntegration_GetNextJob_CarriesDeviceAddressToAgent is the end-to-end proof
// for, through real SQL: a device-interrogation job handed to an agent
// must carry the device's address in its parameters.
//
// The in-cluster PlatformAgentWorker re-reads the device row by device_id, so a
// payload of just {device_id, device_type} was sufficient for it and the gap
// went unnoticed. An agent has no database. Both claim the same
// `agent_id IS NULL` queue, so registering a tenant's first agent was enough to
// route a job to the consumer that could not resolve the target — which then
// interrogated whatever an empty address resolved to on its own host.
func TestIntegration_GetNextJob_CarriesDeviceAddressToAgent(t *testing.T) {
	db := testdb.Connect(t)
	tenant := testdb.NewTenant(t, db)
	ctx := context.Background()

	hostname := "gw-" + uuid.New().String()[:8] + ".example.test"
	ip := "192.0.2.1"
	dev, err := NewDeviceService(db).CreateDevice(ctx, tenant, models.CreateDeviceRequest{
		DeviceType: "unifi",
		Hostname:   &hostname,
		IPAddress:  &ip,
	})
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}

	// A job created the way the scheduler creates them: parameters forwarded
	// verbatim, with no address in them.
	jobQueue := NewJobQueueService(db, db, nil)
	job, err := jobQueue.CreateJob(ctx, models.CreateDeviceJobRequest{
		TenantID:   tenant,
		JobType:    models.JobTypeDeviceInterrogation,
		DeviceID:   &dev.ID,
		Parameters: map[string]interface{}{"device_type": "unifi"},
	})
	if err != nil {
		t.Fatalf("CreateJob: %v", err)
	}

	svc := NewAgentService(db, db, nil)

	// GetNextJob takes a Redis lock before reaching this; exercise the
	// enrichment directly, which is the step GetNextJob delegates to.
	handed := job.ToJob()
	if err := svc.enrichJobTarget(ctx, tenant, handed); err != nil {
		t.Fatalf("enrichJobTarget = %v, want nil", err)
	}

	if got, _ := handed.Parameters["hostname"].(string); got != hostname {
		t.Errorf("parameters[hostname] = %q, want %q", got, hostname)
	}
	if got, _ := handed.Parameters["ip_address"].(string); got != ip {
		t.Errorf("parameters[ip_address] = %q, want %q", got, ip)
	}
}

// TestIntegration_GetNextJob_RefusesAddresslessDevice pins the failure mode: a
// device with no usable address must fail the job at dispatch with a clear
// reason, rather than being handed to an agent that will report a misleading
// connection or auth error against its own host.
//
// The devices table's `device_identifier` CHECK requires one of hostname /
// ip_address / management_url to be NOT NULL — but an empty string satisfies
// it, so an addressless device is reachable and this guard is not dead code.
func TestIntegration_GetNextJob_RefusesAddresslessDevice(t *testing.T) {
	db := testdb.Connect(t)
	tenant := testdb.NewTenant(t, db)
	ctx := context.Background()

	blank := ""
	dev, err := NewDeviceService(db).CreateDevice(ctx, tenant, models.CreateDeviceRequest{
		DeviceType: "unifi",
		Hostname:   &blank, // NOT NULL, satisfies the CHECK, reaches nothing
	})
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}

	jobQueue := NewJobQueueService(db, db, nil)
	job, err := jobQueue.CreateJob(ctx, models.CreateDeviceJobRequest{
		TenantID:   tenant,
		JobType:    models.JobTypeDeviceInterrogation,
		DeviceID:   &dev.ID,
		Parameters: map[string]interface{}{"device_type": "unifi"},
	})
	if err != nil {
		t.Fatalf("CreateJob: %v", err)
	}

	svc := NewAgentService(db, db, nil)
	err = svc.enrichJobTarget(ctx, tenant, job.ToJob())
	if !errors.Is(err, ErrJobHasNoTarget) {
		t.Fatalf("enrichJobTarget = %v, want ErrJobHasNoTarget", err)
	}
}

// TestIntegration_GetNextJob_DoesNotLeakAddressAcrossTenants pins the tenant
// constraint on this bypass-role read: the device lookup is scoped to the job's
// own tenant, so it cannot resolve another tenant's device.
func TestIntegration_GetNextJob_DoesNotLeakAddressAcrossTenants(t *testing.T) {
	db := testdb.Connect(t)
	owner := testdb.NewTenant(t, db)
	other := testdb.NewTenant(t, db)
	ctx := context.Background()

	hostname := "secret-" + uuid.New().String()[:8] + ".example.test"
	dev, err := NewDeviceService(db).CreateDevice(ctx, owner, models.CreateDeviceRequest{
		DeviceType: "unifi",
		Hostname:   &hostname,
	})
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}

	job := &models.Job{
		ID:         uuid.New(),
		Type:       string(models.JobTypeDeviceInterrogation),
		DeviceID:   &dev.ID,
		Parameters: map[string]interface{}{"device_type": "unifi"},
	}

	svc := NewAgentService(db, db, nil)
	// Resolving the same device under a DIFFERENT tenant must find nothing.
	err = svc.enrichJobTarget(ctx, other, job)
	if err == nil {
		t.Fatalf("enrichJobTarget across tenants = nil, want an error")
	}
	if got, _ := job.Parameters["hostname"].(string); got != "" {
		t.Errorf("leaked hostname %q across tenants", got)
	}
}
