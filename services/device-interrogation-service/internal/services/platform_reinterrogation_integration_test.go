package services

import (
	"context"
	"database/sql"
	"testing"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func boolPtr(b bool) *bool { return &b }

// consentFixture is a monitored, platform-interrogated network controller with
// one completed platform interrogation behind it — the device the planner asks
// for consent about.
type consentFixture struct {
	db      *sql.DB
	tenant  uuid.UUID
	devices *DeviceService
	queue   *JobQueueService
	service *ConfiguredSourceRefresh
	device  models.Device
	lastJob uuid.UUID
	// other and peer are further managed devices, created before admission is
	// enforced (enforce holds a new device's sighting for review).
	other, peer models.Device
}

func newConsentFixture(t *testing.T) consentFixture {
	t.Helper()
	t.Setenv("ENCRYPTION_MASTER_KEY", testMasterKey)
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db)
	if _, err := db.Exec(`INSERT INTO network_segments(id,tenant_id,name,segment_type,value,environment,is_active) VALUES($1,$2,'Consent network','cidr','192.0.2.0/24','production',true)`, uuid.New(), tenant); err != nil {
		t.Fatal(err)
	}
	devices := NewDeviceServiceWithKey(db, testMasterKey)
	device := createMonitoredController(t, db, devices, tenant, "controller.example.test", "https://192.0.2.2")
	other := createMonitoredController(t, db, devices, tenant, "other.example.test", "https://192.0.2.3")
	peer := createMonitoredController(t, db, devices, tenant, "peer.example.test", "https://192.0.2.4")
	queue := NewJobQueueService(db, db, nil)
	last := completedJob(t, db, queue, tenant, device.ID, nil)
	prepare := func(_ context.Context, _ uuid.UUID, id uuid.UUID) (models.CreateDeviceJobRequest, error) {
		d, err := devices.GetDevice(context.Background(), tenant, id)
		if err != nil {
			return models.CreateDeviceJobRequest{}, err
		}
		return models.CreateDeviceJobRequest{TenantID: tenant, JobType: models.JobTypeDeviceInterrogation, AssetID: &d.ID, Parameters: map[string]interface{}{"asset_id": d.ID.String(), "management_url": *d.ManagementURL}}, nil
	}
	enableSourceRefresh(t, db, tenant)
	return consentFixture{db: db, tenant: tenant, devices: devices, queue: queue, service: NewConfiguredSourceRefresh(db, queue, devices, prepare), device: device, lastJob: last, other: other, peer: peer}
}

func createMonitoredController(t *testing.T, db *sql.DB, devices *DeviceService, tenant uuid.UUID, host, url string) models.Device {
	t.Helper()
	d, err := devices.CreateDevice(context.Background(), tenant, models.CreateDeviceRequest{DeviceType: "unifi", Hostname: strptr(host), ManagementURL: strptr(url)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE assets SET asset_status='monitoring' WHERE tenant_id=$1 AND id=$2`, tenant, d.ID); err != nil {
		t.Fatal(err)
	}
	return *d
}

func completedJob(t *testing.T, db *sql.DB, queue *JobQueueService, tenant, asset uuid.UUID, agent *uuid.UUID) uuid.UUID {
	t.Helper()
	job, err := queue.CreateJob(context.Background(), models.CreateDeviceJobRequest{TenantID: tenant, JobType: models.JobTypeDeviceInterrogation, AssetID: &asset, AgentID: agent})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE device_jobs SET status='completed',completed_at=now()-interval '1 minute' WHERE id=$1`, job.ID); err != nil {
		t.Fatal(err)
	}
	return job.ID
}

// blockOnConsent writes the coordinator's side of a consent-blocked
// configured-source refresh the way the live rows look: the enrichment job and
// the observation both blocked `executor_scope_unknown`, due well in the future
// (Store.Finish's backoff).
func blockOnConsent(t *testing.T, db *sql.DB, tenant uuid.UUID, req SourceRefreshRequest) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO identity_enrichment_jobs(tenant_id,observation_id,generation,action,executor_scope,plan,state,reason,attempts,next_attempt_at)
	 VALUES($1,$2,$3,'configured_source','configured_sources','{}','blocked','executor_scope_unknown',7,now()+interval '2 hours')`, tenant, req.ObservationID, uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	// The live receipts were first planned hours earlier; Refresh never re-plans
	// a receipt younger than five minutes, whatever its next_attempt_at says.
	if _, err := db.Exec(`UPDATE identity_source_refreshes SET created_at=now()-interval '1 hour' WHERE tenant_id=$1 AND id=$2`, tenant, req.RequestID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE identity_observations SET enrichment_state='blocked',enrichment_reason='executor_scope_unknown',next_attempt_at=now()+interval '2 hours' WHERE tenant_id=$1 AND id=$2`, tenant, req.ObservationID); err != nil {
		t.Fatal(err)
	}
}

type consentClocks struct{ receipt, job, observation bool }

// dueNow reports which of the three clocks a re-open moves are due.
func dueNow(t *testing.T, db *sql.DB, tenant uuid.UUID, req SourceRefreshRequest) consentClocks {
	t.Helper()
	var c consentClocks
	if err := db.QueryRow(`SELECT
	  (SELECT next_attempt_at<=now() FROM identity_source_refreshes WHERE tenant_id=$1 AND id=$2),
	  (SELECT next_attempt_at<=now() FROM identity_enrichment_jobs WHERE tenant_id=$1 AND observation_id=$3),
	  (SELECT next_attempt_at<=now() FROM identity_observations WHERE tenant_id=$1 AND id=$3)`, tenant, req.RequestID, req.ObservationID).Scan(&c.receipt, &c.job, &c.observation); err != nil {
		t.Fatal(err)
	}
	return c
}

// TestIntegration_PlatformReinterrogationConsent is the live shape: a
// controller the platform interrogated minutes ago, observations linked to it
// from the sensor, and every one of them blocked `executor_scope_unknown`
// because nothing could set the consent. Turning the consent on through the
// device update must (a) satisfy the planner, (b) re-open the blocked rows so
// the next cycle picks them up rather than a backoff of up to two hours later,
// and (c) not touch another device's blocked rows.
//
// Mutations performed, each observed red, then restored:
//   - never call applyPlatformReinterrogation from applyDeviceFields → the
//     consent never lands.
//   - drop the reopenConsentBlockedEnrichment call → the clocks stay in the
//     future ("not re-opened").
//   - write the consent back only when the request names it → the smuggled
//     metadata key grants it, and an unrelated metadata edit withdraws it.
//   - re-open on every consent write, not only off→on → the smuggled-key
//     update re-opens rows.
func TestIntegration_PlatformReinterrogationConsent(t *testing.T) {
	f := newConsentFixture(t)
	ctx := context.Background()

	// Off by default, and the planner refuses.
	if f.device.PlatformReinterrogationAllowed {
		t.Fatal("consent defaulted on")
	}
	req := refreshObservation(t, f.db, f.tenant, "sensor:"+uuid.NewString(), &f.device.ID)
	result, err := f.service.Refresh(ctx, req)
	if err != nil || result.State != "blocked" || result.Reason != reasonExecutorScopeUnknown {
		t.Fatalf("no consent: %+v %v", result, err)
	}
	blockOnConsent(t, f.db, f.tenant, req)

	// Another device's consent-blocked row, which turning THIS device on must leave alone.
	other := f.other
	completedJob(t, f.db, f.queue, f.tenant, other.ID, nil)
	otherReq := refreshObservation(t, f.db, f.tenant, "sensor:"+uuid.NewString(), &other.ID)
	if r, err := f.service.Refresh(ctx, otherReq); err != nil || r.Reason != reasonExecutorScopeUnknown {
		t.Fatalf("other device: %+v %v", r, err)
	}
	blockOnConsent(t, f.db, f.tenant, otherReq)

	// Free-form metadata cannot grant it.
	updated, err := f.devices.UpdateDevice(ctx, f.tenant, f.device.ID, models.UpdateDeviceRequest{Metadata: map[string]interface{}{PlatformReinterrogationKey: platformExecutorValue, "note": "kept"}})
	if err != nil {
		t.Fatal(err)
	}
	if updated.PlatformReinterrogationAllowed || updated.Metadata["note"] != "kept" {
		t.Fatalf("smuggled consent: allowed=%v metadata=%v", updated.PlatformReinterrogationAllowed, updated.Metadata)
	}
	if c := dueNow(t, f.db, f.tenant, req); c.job || c.observation {
		t.Fatalf("a refused grant re-opened rows: %+v", c)
	}

	// The explicit field grants it and re-opens exactly this device's rows —
	// as the application role, under RLS, the way the service runs.
	appDevices := NewDeviceServiceWithKey(testdb.ConnectAsAppRole(t, f.db), testMasterKey)
	updated, err = appDevices.UpdateDevice(ctx, f.tenant, f.device.ID, models.UpdateDeviceRequest{PlatformReinterrogationAllowed: boolPtr(true)})
	if err != nil {
		t.Fatal(err)
	}
	if !updated.PlatformReinterrogationAllowed || updated.Metadata["note"] != "kept" {
		t.Fatalf("grant: allowed=%v metadata=%v", updated.PlatformReinterrogationAllowed, updated.Metadata)
	}
	if c := dueNow(t, f.db, f.tenant, req); c != (consentClocks{true, true, true}) {
		t.Fatalf("blocked rows not re-opened: %+v", c)
	}
	if c := dueNow(t, f.db, f.tenant, otherReq); c.job || c.observation {
		t.Fatalf("another device's rows re-opened: %+v", c)
	}
	var state, reason string
	var attempts int
	if err := f.db.QueryRow(`SELECT state,reason,attempts FROM identity_enrichment_jobs WHERE tenant_id=$1 AND observation_id=$2`, f.tenant, req.ObservationID).Scan(&state, &reason, &attempts); err != nil || state != "blocked" || attempts != 7 {
		t.Fatalf("re-open must move clocks only: %s/%s attempts=%d %v", state, reason, attempts, err)
	}

	// The coordinator's retry (Poll → POST on a blocked job) now plans it.
	result, err = f.service.Refresh(ctx, req)
	if err != nil || result.State != "queued" {
		t.Fatalf("after consent: %+v %v", result, err)
	}
	var executor string
	if err := f.db.QueryRow(`SELECT j.parameters->>'identity_refresh_executor' FROM device_jobs j JOIN identity_source_refreshes r ON r.tenant_id=j.tenant_id AND r.device_job_id=j.id WHERE r.tenant_id=$1 AND r.id=$2`, f.tenant, req.RequestID).Scan(&executor); err != nil || executor != "platform" {
		t.Fatalf("executor %q: %v", executor, err)
	}

	// An unrelated metadata edit keeps it.
	updated, err = f.devices.UpdateDevice(ctx, f.tenant, f.device.ID, models.UpdateDeviceRequest{Metadata: map[string]interface{}{"note": "changed"}})
	if err != nil {
		t.Fatal(err)
	}
	if !updated.PlatformReinterrogationAllowed || updated.Metadata["note"] != "changed" {
		t.Fatalf("metadata edit dropped consent: allowed=%v metadata=%v", updated.PlatformReinterrogationAllowed, updated.Metadata)
	}

	// Withdrawn: the key is gone and the planner refuses again.
	updated, err = f.devices.UpdateDevice(ctx, f.tenant, f.device.ID, models.UpdateDeviceRequest{PlatformReinterrogationAllowed: boolPtr(false)})
	if err != nil {
		t.Fatal(err)
	}
	if updated.PlatformReinterrogationAllowed {
		t.Fatal("withdraw did not stick")
	}
	if _, present := updated.Metadata[PlatformReinterrogationKey]; present || updated.Metadata["note"] != "changed" {
		t.Fatalf("withdraw left %v", updated.Metadata)
	}
	again := refreshObservation(t, f.db, f.tenant, "sensor:"+uuid.NewString(), &f.device.ID)
	if r, err := f.service.Refresh(ctx, again); err != nil || r.Reason != reasonExecutorScopeUnknown {
		t.Fatalf("after withdraw: %+v %v", r, err)
	}
}

// The consent given on Add device lands with the device.
func TestIntegration_PlatformReinterrogationConsent_OnCreate(t *testing.T) {
	t.Setenv("ENCRYPTION_MASTER_KEY", testMasterKey)
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db)
	devices := NewDeviceServiceWithKey(db, testMasterKey)
	d, err := devices.CreateDevice(context.Background(), tenant, models.CreateDeviceRequest{DeviceType: "unifi", Hostname: strptr("created.example.test"), ManagementURL: strptr("https://192.0.2.9"), PlatformReinterrogationAllowed: boolPtr(true), Metadata: map[string]interface{}{"auto_discovered": true}})
	if err != nil {
		t.Fatal(err)
	}
	if !d.PlatformReinterrogationAllowed || d.Metadata["auto_discovered"] != true {
		t.Fatalf("create: allowed=%v metadata=%v", d.PlatformReinterrogationAllowed, d.Metadata)
	}
	plain, err := devices.CreateDevice(context.Background(), tenant, models.CreateDeviceRequest{DeviceType: "unifi", Hostname: strptr("plain.example.test"), ManagementURL: strptr("https://192.0.2.10"), Metadata: map[string]interface{}{PlatformReinterrogationKey: platformExecutorValue}})
	if err != nil {
		t.Fatal(err)
	}
	if plain.PlatformReinterrogationAllowed {
		t.Fatal("create: free-form metadata granted the consent")
	}
}

// InterrogatedByAgent mirrors the planner's question: who ran the device's
// most recent completed job.
func TestIntegration_DeviceInterrogatedByAgent(t *testing.T) {
	f := newConsentFixture(t)
	ctx := context.Background()
	d, err := f.devices.GetDevice(ctx, f.tenant, f.device.ID)
	if err != nil || d.InterrogatedByAgent {
		t.Fatalf("platform-run device reported agent: %+v %v", d, err)
	}
	agent := uuid.New()
	if _, err := f.db.Exec(`INSERT INTO device_agents(id,tenant_id,registration_key,platform,version,profile,status,last_heartbeat) VALUES($1,$2,$3,'linux','1.0.0','full','active',now())`, agent, f.tenant, uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	job := completedJob(t, f.db, f.queue, f.tenant, f.device.ID, &agent)
	if _, err := f.db.Exec(`UPDATE device_jobs SET completed_at=now() WHERE id=$1`, job); err != nil {
		t.Fatal(err)
	}
	list, err := f.devices.ListDevices(ctx, f.tenant)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range list {
		if d.InterrogatedByAgent != (d.ID == f.device.ID) {
			t.Fatalf("device %s interrogated_by_agent=%v", d.ID, d.InterrogatedByAgent)
		}
	}
}

// TestIntegration_SourceRefresh_InterrogationRefNamesDiscoveryJob: a platform
// interrogation writes its observations as `interrogation:<discovery job id>`
// (persistObservations), not the device job id. The planner used to look that
// id up in device_jobs.id only, find nothing, and return early — skipping even
// the linked-asset check — so the observation completed `no_configured_source`
// by accident (56 of 56 interrogation-sourced observations on a live tenant
// resolved only through device_jobs.parameters->>'discovery_job_id').
//
// Mutations performed, each observed red, then restored:
//   - restore the device_jobs.id-only lookup → the unlinked observation
//     completes no_configured_source instead of being recognised as its
//     device's own answer (configured_source_already_reported_this_peer).
//   - restore the early return on an unknown id → the unknown-run observation
//     linked to a managed device completes no_configured_source.
//   - drop the `fromSource && linked.Valid` completion → the linked
//     observation dispatches a pointless re-run.
func TestIntegration_SourceRefresh_InterrogationRefNamesDiscoveryJob(t *testing.T) {
	f := newConsentFixture(t)
	ctx := context.Background()
	if _, err := f.devices.UpdateDevice(ctx, f.tenant, f.device.ID, models.UpdateDeviceRequest{PlatformReinterrogationAllowed: boolPtr(true)}); err != nil {
		t.Fatal(err)
	}
	discovery := uuid.New()
	if err := f.queue.RecordDiscoveryJob(ctx, f.lastJob, discovery); err != nil {
		t.Fatal(err)
	}

	// Unlinked: recognised as the device's own answer, so it is not planned
	// against the device again (a lookup that missed the run would complete
	// no_configured_source instead).
	unlinked := refreshObservation(t, f.db, f.tenant, "interrogation:"+discovery.String(), nil)
	result, err := f.service.Refresh(ctx, unlinked)
	if err != nil || result.State != "completed" || result.Reason != reasonSourceAlreadyReportedPeer {
		t.Fatalf("unlinked platform-run observation: %+v %v", result, err)
	}
	assertNoRefreshJob(t, f.db, f.tenant, unlinked)

	// Linked (a peer the controller reported): the source's own answer.
	peer := f.peer
	for _, ref := range []string{"interrogation:" + discovery.String(), "interrogation:" + f.lastJob.String()} {
		linked := refreshObservation(t, f.db, f.tenant, ref, &peer.ID)
		result, err = f.service.Refresh(ctx, linked)
		if err != nil || result.State != "completed" || result.Reason != reasonSourceProducedObservation {
			t.Fatalf("linked %s: %+v %v", ref, result, err)
		}
		assertNoRefreshJob(t, f.db, f.tenant, linked)
	}

	// An id no run carries no longer skips the linked-asset check.
	unknown := refreshObservation(t, f.db, f.tenant, "interrogation:"+uuid.NewString(), &f.device.ID)
	result, err = f.service.Refresh(ctx, unknown)
	if err != nil || result.State != "queued" {
		t.Fatalf("unknown run linked to a managed device: %+v %v", result, err)
	}
}
