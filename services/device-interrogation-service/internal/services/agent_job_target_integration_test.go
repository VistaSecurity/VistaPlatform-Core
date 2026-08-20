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

// TestIntegration_GetNextJob_CarriesDeviceTypeToAgent is B-36: the same gap as
// the address, one field over.
//
// A schedule stores an operator-supplied parameter map, and the schedule-create
// UI never sends one — so TriggerSchedule creates jobs with EMPTY parameters.
// The in-cluster worker re-reads the device row and never misses device_type;
// an agent has no database, DeviceJob.ToJob sources device_type exclusively from
// Parameters, and GetNextJob's enrichment restored only the address and
// credentials (the latter putting device_type into the credential map, which the
// agent never reads for dispatch). The agent then refuses the job with
// "device_type not specified in job" — an internal field name the user never
// supplied — and only when the agent wins the `agent_id IS NULL` claim race.
//
// The parameters here are deliberately EMPTY. Every pre-existing agent test
// pre-seeds Parameters{device_type}, which is exactly what masked this.
//
// Mutation check: remove device_type from enrichJobTarget's SELECT/setIfAbsent
// and this fails while the address test above still passes.
func TestIntegration_GetNextJob_CarriesDeviceTypeToAgent(t *testing.T) {
	db := testdb.Connect(t)
	tenant := testdb.NewTenant(t, db)
	ctx := context.Background()

	hostname := "fw-" + uuid.New().String()[:8] + ".example.test"
	dev, err := NewDeviceService(db).CreateDevice(ctx, tenant, models.CreateDeviceRequest{
		DeviceType: "fortinet",
		Hostname:   &hostname,
	})
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}

	jobQueue := NewJobQueueService(db, db, nil)
	job, err := jobQueue.CreateJob(ctx, models.CreateDeviceJobRequest{
		TenantID:   tenant,
		JobType:    models.JobTypeDeviceInterrogation,
		DeviceID:   &dev.ID,
		Parameters: map[string]interface{}{}, // what the scheduler actually sends
	})
	if err != nil {
		t.Fatalf("CreateJob: %v", err)
	}

	handed := job.ToJob()
	if handed.DeviceType != "" {
		t.Fatalf("precondition: ToJob resolved DeviceType = %q from empty parameters", handed.DeviceType)
	}

	svc := NewAgentService(db, db, nil)
	if err := svc.enrichJobTarget(ctx, tenant, handed); err != nil {
		t.Fatalf("enrichJobTarget = %v, want nil", err)
	}

	// The agent reads Job.DeviceType first and falls back to the parameter map;
	// both have to carry it, or one agent version or the other refuses the job.
	if handed.DeviceType != "fortinet" {
		t.Errorf("job.device_type = %q, want fortinet — the agent refuses the job without it", handed.DeviceType)
	}
	if got, _ := handed.Parameters["device_type"].(string); got != "fortinet" {
		t.Errorf("parameters[device_type] = %q, want fortinet", got)
	}
}

// TestIntegration_EnrichJobTarget_KeepsExplicitDeviceType pins the precedence
// rule the other enriched fields already follow: a device_type the job carries
// is the more specific intent and must not be overwritten by the device row.
func TestIntegration_EnrichJobTarget_KeepsExplicitDeviceType(t *testing.T) {
	db := testdb.Connect(t)
	tenant := testdb.NewTenant(t, db)
	ctx := context.Background()

	hostname := "fw-" + uuid.New().String()[:8] + ".example.test"
	dev, err := NewDeviceService(db).CreateDevice(ctx, tenant, models.CreateDeviceRequest{
		DeviceType: "fortinet",
		Hostname:   &hostname,
	})
	if err != nil {
		t.Fatalf("CreateDevice: %v", err)
	}

	jobQueue := NewJobQueueService(db, db, nil)
	job, err := jobQueue.CreateJob(ctx, models.CreateDeviceJobRequest{
		TenantID:   tenant,
		JobType:    models.JobTypeDeviceInterrogation,
		DeviceID:   &dev.ID,
		Parameters: map[string]interface{}{"device_type": "paloalto"},
	})
	if err != nil {
		t.Fatalf("CreateJob: %v", err)
	}

	handed := job.ToJob()
	svc := NewAgentService(db, db, nil)
	if err := svc.enrichJobTarget(ctx, tenant, handed); err != nil {
		t.Fatalf("enrichJobTarget = %v, want nil", err)
	}

	if got, _ := handed.Parameters["device_type"].(string); got != "paloalto" {
		t.Errorf("parameters[device_type] = %q, want the job's own paloalto", got)
	}
	if handed.DeviceType != "paloalto" {
		t.Errorf("job.device_type = %q, want paloalto", handed.DeviceType)
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
