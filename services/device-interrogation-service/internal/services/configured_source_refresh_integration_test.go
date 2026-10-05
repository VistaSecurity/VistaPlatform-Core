package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func refreshObservation(t *testing.T, db *sql.DB, tenant uuid.UUID, source string, asset *uuid.UUID) SourceRefreshRequest {
	t.Helper()
	id := uuid.New()
	obs := identity.Observation{TenantID: tenant.String(), Source: identity.Source{Kind: identity.SourceMeasured, Ref: source}, ObservedAt: time.Now().UTC(), DisplayName: "unresolved.local"}
	raw, err := json.Marshal(obs)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO identity_observations(tenant_id,id,fingerprint,source_kind,source_ref,evidence,asset_id,first_seen_at,last_seen_at) VALUES($1,$2,$3,'measured',$4,$5,$6,now(),now())`, tenant, id, id.String(), source, raw, asset); err != nil {
		t.Fatal(err)
	}
	return SourceRefreshRequest{RequestID: uuid.New(), TenantID: tenant, ObservationID: id, Evidence: obs}
}
func TestIntegration_SourceRefreshAtomicReplayAndCompletion(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db)
	if _, err := db.Exec(`INSERT INTO network_segments(id,tenant_id,name,segment_type,value,environment,is_active) VALUES($1,$2,'Refresh network','cidr','192.0.2.0/24','production',true)`, uuid.New(), tenant); err != nil {
		t.Fatal(err)
	}
	other := testdb.NewTenant(t, db)
	deviceService := NewDeviceServiceWithKey(db, testMasterKey)
	device, err := deviceService.CreateDevice(context.Background(), tenant, models.CreateDeviceRequest{DeviceType: "unifi", Hostname: strptr("controller.example.test"), ManagementURL: strptr("https://192.0.2.2"), PlatformReinterrogationAllowed: boolPtr(true)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE assets SET asset_status='monitoring' WHERE tenant_id=$1`, tenant); err != nil {
		t.Fatal(err)
	}
	queue := NewJobQueueService(db, db, nil)
	previous, err := queue.CreateJob(context.Background(), models.CreateDeviceJobRequest{TenantID: tenant, JobType: models.JobTypeDeviceInterrogation, AssetID: &device.ID})
	if err != nil {
		t.Fatal(err)
	}
	prepare := func(context.Context, uuid.UUID, uuid.UUID) (models.CreateDeviceJobRequest, error) {
		return models.CreateDeviceJobRequest{TenantID: tenant, JobType: models.JobTypeDeviceInterrogation, AssetID: &device.ID, Parameters: map[string]interface{}{"asset_id": device.ID.String(), "management_url": "https://192.0.2.2"}}, nil
	}
	service := NewConfiguredSourceRefresh(db, queue, deviceService, prepare)
	enableSourceRefresh(t, db, tenant)
	// A sensor's sighting linked to the managed controller: the shape a source
	// refresh is for. (An observation the controller's OWN run produced is never
	// planned against it — TestIntegration_SourceRefresh_NoSelfFeedingLoop.)
	if _, err := db.Exec(`UPDATE device_jobs SET status='completed',completed_at=now()-interval '1 day' WHERE id=$1`, previous.ID); err != nil {
		t.Fatal(err)
	}
	req := refreshObservation(t, db, tenant, "sensor:"+uuid.NewString(), &device.ID)
	// A single data connection must work: dedup uses the separate control pool.
	db.SetMaxOpenConns(1)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	for range 3 {
		wg.Go(func() {
			result, err := service.Refresh(ctx, req)
			if err != nil || result.State != "queued" {
				t.Errorf("refresh %+v: %v", result, err)
			}
		})
	}
	wg.Wait()
	var count int
	var child uuid.UUID
	if err := db.QueryRow(`SELECT count(*),min(device_job_id::text)::uuid FROM identity_source_refreshes WHERE tenant_id=$1 AND id=$2`, tenant, req.RequestID).Scan(&count, &child); err != nil || count != 1 {
		t.Fatalf("receipt count %d: %v", count, err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM device_jobs WHERE tenant_id=$1 AND parameters->>'identity_refresh_request_id'=$2`, tenant, req.RequestID.String()).Scan(&count); err != nil || count != 1 {
		t.Fatalf("duplicate dispatch %d: %v", count, err)
	}
	changed := req
	changed.Evidence.DisplayName = "different"
	if _, err := service.Refresh(ctx, changed); !errors.Is(err, ErrRefreshConflict) {
		t.Fatalf("fingerprint conflict: %v", err)
	}
	foreign := req
	foreign.TenantID = other
	foreign.Evidence.TenantID = other.String()
	if _, err := service.Refresh(ctx, foreign); !errors.Is(err, ErrRefreshNotFound) {
		t.Fatalf("cross tenant: %v", err)
	}
	if _, err := service.Status(ctx, other, req.RequestID); !errors.Is(err, ErrRefreshNotFound) {
		t.Fatalf("foreign poll: %v", err)
	}
	if _, err := db.Exec(`UPDATE device_jobs SET status='completed',results='{}' WHERE id=$1`, child); err != nil {
		t.Fatal(err)
	}
	result, err := service.Status(ctx, tenant, req.RequestID)
	if err != nil || result.State != "running" {
		t.Fatalf("premature completion %+v: %v", result, err)
	}
	batch := uuid.New()
	sensor := uuid.New()
	if _, err := db.Exec(`INSERT INTO sensors(id,tenant_id,name,platform,version,profile,status) VALUES($1,$2,'refresh test','linux','test','device_interrogation','active')`, sensor, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO sensor_discoveries(id,sensor_id,tenant_id,batch_id,protocol,dest_ip,port) VALUES($1,$2,$3,$4,'tls','192.0.2.1',443)`, uuid.New(), sensor, tenant, batch.String()); err != nil {
		t.Fatal(err)
	}
	processing, _ := json.Marshal(map[string]interface{}{"processing": map[string]interface{}{"processing_finished_at": time.Now().Format(time.RFC3339), "fully_materialized": true, "discovery_job_id": batch.String()}})
	if _, err := db.Exec(`UPDATE device_jobs SET results=$2 WHERE id=$1`, child, processing); err != nil {
		t.Fatal(err)
	}
	result, err = service.Status(ctx, tenant, req.RequestID)
	if err != nil || result.State != "running" {
		t.Fatalf("raw evidence not ingested %+v: %v", result, err)
	}
	if _, err := db.Exec(`UPDATE sensor_discoveries SET processed_at=now() WHERE tenant_id=$1 AND batch_id=$2`, tenant, batch.String()); err != nil {
		t.Fatal(err)
	}
	result, err = service.Status(ctx, tenant, req.RequestID)
	if err != nil || result.State != "completed" {
		t.Fatalf("completion %+v: %v", result, err)
	}
	// Platform collectors materialize rows before returning an intentionally
	// empty Assets list. Their explicit receipt still waits for processing.
	direct, _ := json.Marshal(map[string]interface{}{"metadata": map[string]interface{}{"identity_refresh_materialized": true}, "processing": map[string]interface{}{"processing_finished_at": time.Now().Format(time.RFC3339), "fully_materialized": false, "discovery_job_id": batch.String()}})
	if _, err := db.Exec(`UPDATE device_jobs SET results=$2 WHERE id=$1`, child, direct); err != nil {
		t.Fatal(err)
	}
	result, err = service.Status(ctx, tenant, req.RequestID)
	if err != nil || result.State != "completed" {
		t.Fatalf("direct platform materialization %+v: %v", result, err)
	}
	if _, err := db.Exec(`UPDATE device_jobs SET results=jsonb_set(results,'{processing,discoveries_failed}','1') WHERE id=$1`, child); err != nil {
		t.Fatal(err)
	}
	result, err = service.Status(ctx, tenant, req.RequestID)
	if err != nil || result.State != "failed" {
		t.Fatalf("direct platform failure hidden %+v: %v", result, err)
	}
	// A failed job does not duplicate active work. Only a terminal job whose
	// backoff elapsed gets a fresh child, preserving the stable logical ID.
	if _, err := db.Exec(`UPDATE device_jobs SET status='failed',completed_at=now() WHERE id=$1`, child); err != nil {
		t.Fatal(err)
	}
	result, err = service.Refresh(ctx, req)
	if err != nil || result.State != "failed" {
		t.Fatalf("backoff %+v: %v", result, err)
	}
	if _, err := db.Exec(`UPDATE device_jobs SET completed_at=now()-interval '10 minutes' WHERE id=$1`, child); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE identity_source_refreshes SET next_attempt_at=now()-interval '1 minute' WHERE tenant_id=$1 AND id=$2`, tenant, req.RequestID); err != nil {
		t.Fatal(err)
	}
	// Past the five-minute reuse window, but the controller was asked less than
	// minSourceRefreshInterval ago: another observation wanting it completes its
	// source stage without asking again, failed run or not.
	sibling := refreshObservation(t, db, tenant, "sensor:"+uuid.NewString(), &device.ID)
	result, err = service.Refresh(ctx, sibling)
	if err != nil || result.State != "completed" || result.Reason != reasonSourceRefreshedRecently {
		t.Fatalf("second observation inside the source interval %+v: %v", result, err)
	}
	assertNoRefreshJob(t, db, tenant, sibling)
	// Once the interval has passed, the failed receipt's retry gets a fresh
	// child under its stable logical ID.
	if _, err := db.Exec(`UPDATE device_jobs SET created_at=now()-$2*interval '1 second'-interval '1 minute' WHERE id=$1`, child, int64(minSourceRefreshInterval/time.Second)); err != nil {
		t.Fatal(err)
	}
	result, err = service.Refresh(ctx, req)
	if err != nil || result.State != "queued" {
		t.Fatalf("retry %+v: %v", result, err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM device_jobs WHERE tenant_id=$1 AND parameters->>'identity_refresh_request_id'=$2`, tenant, req.RequestID.String()).Scan(&count); err != nil || count != 2 {
		t.Fatalf("retry count %d: %v", count, err)
	}
}
func TestIntegration_SourceRefreshNoGuessingAndBlockedCredentials(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db)
	if _, err := db.Exec(`INSERT INTO network_segments(id,tenant_id,name,segment_type,value,environment,is_active) VALUES($1,$2,'Refresh network','cidr','192.0.2.0/24','production',true)`, uuid.New(), tenant); err != nil {
		t.Fatal(err)
	}
	devices := NewDeviceServiceWithKey(db, testMasterKey)
	queue := NewJobQueueService(db, db, nil)
	service := NewConfiguredSourceRefresh(db, queue, devices, func(context.Context, uuid.UUID, uuid.UUID) (models.CreateDeviceJobRequest, error) {
		return models.CreateDeviceJobRequest{}, ErrRefreshCredentialsUnavailable
	})
	req := refreshObservation(t, db, tenant, "sensor:"+uuid.NewString(), nil)
	result, err := service.Refresh(context.Background(), req)
	if err != nil || result.State != "completed" || result.Reason != "no_configured_source" {
		t.Fatalf("weak alias %+v: %v", result, err)
	}
	device, err := devices.CreateDevice(context.Background(), tenant, models.CreateDeviceRequest{DeviceType: "unifi", Hostname: strptr("controller.example.test"), ManagementURL: strptr("https://192.0.2.2"), PlatformReinterrogationAllowed: boolPtr(true)})
	if err != nil {
		t.Fatal(err)
	}
	// A sighting linked to the controller, which has been interrogated before
	// (the executor the planner reuses).
	completedJob(t, db, queue, tenant, device.ID, nil)
	req = refreshObservation(t, db, tenant, "sensor:"+uuid.NewString(), &device.ID)
	result, err = service.Refresh(context.Background(), req)
	if err != nil || result.State != "blocked" || result.Reason != "configured_credentials_unavailable" {
		t.Fatalf("credentials %+v: %v", result, err)
	}
	var count int
	if err := db.QueryRow(`SELECT count(*) FROM device_jobs WHERE tenant_id=$1 AND parameters?'identity_refresh_request_id'`, tenant).Scan(&count); err != nil || count != 0 {
		t.Fatalf("blocked job dispatched: %d %v", count, err)
	}
}
func TestBoundedCloudResourceType(t *testing.T) {
	for _, tc := range []struct{ provider, device, collector string }{{"gcp", "gcp_https_load_balancer", "load_balancer"}, {"gcp", "gcp_kms_crypto_key", "kms"}, {"azure", "azure_keyvault_key", "key_vault"},
		// Every at-rest device type a collector emits maps back onto the
		// collector that lists it (atRestDeviceTypes). These four used to map
		// to nothing, so no bucket or database could ever be refreshed.
		{"aws", "aws_s3_bucket", "s3"}, {"aws", "aws_rds_instance", "rds"}, {"aws", "aws_kms", "kms"},
		{"azure", "azure_storage_account", "storage_account"}, {"azure", "azure_sql_database", "sql_database"},
		{"gcp", "gcp_storage_bucket", "storage"}, {"gcp", "gcp_cloudsql_instance", "cloudsql"}} {
		if got := boundedCloudResourceType(tc.provider, tc.device); got != tc.collector {
			t.Errorf("%s maps to %q, want %q", tc.device, got, tc.collector)
		}
	}

	if boundedCloudResourceType("aws", "aws_alb") != "alb" || boundedCloudResourceType("azure", "azure_application_gateway") != "application_gateway" {
		t.Fatal("known collector missing")
	}
	for _, kind := range []string{"", "all", "aws_ec2", "unknown", "gcp_load_balancer"} {
		if boundedCloudResourceType("aws", kind) != "" {
			t.Fatalf("unsafe collector %q", kind)
		}
	}
}

func TestIntegration_SourceRefreshCloudAndExecutorOwnership(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db)
	if _, err := db.Exec(`INSERT INTO network_segments(id,tenant_id,name,segment_type,value,environment,is_active) VALUES($1,$2,'Refresh network','cidr','192.0.2.0/24','production',true)`, uuid.New(), tenant); err != nil {
		t.Fatal(err)
	}
	other := testdb.NewTenant(t, db)
	devices := NewDeviceServiceWithKey(db, testMasterKey)
	queue := NewJobQueueService(db, db, nil)
	service := NewConfiguredSourceRefresh(db, queue, devices, nil)
	integration := uuid.New()
	if _, err := db.Exec(`INSERT INTO platform_integrations(id,tenant_id,integration_name,integration_type,provider,config,is_active) VALUES($1,$2,'Refresh AWS','aws','cloud','{"region":"us-east-1"}',true)`, integration, tenant); err != nil {
		t.Fatal(err)
	}
	device, err := devices.CreateDevice(context.Background(), tenant, models.CreateDeviceRequest{DeviceType: "aws_alb", Hostname: strptr("lb.example.test"), CredentialID: &integration})
	if err != nil {
		t.Fatal(err)
	}
	enableSourceRefresh(t, db, tenant)
	// A LINKED cloud observation is the provider's own answer: the source stage
	// completes without dispatching the collector that produced it.
	linked := refreshObservation(t, db, tenant, "cloud:aws", &device.ID)
	result, err := service.Refresh(context.Background(), linked)
	if err != nil || result.State != "completed" || result.Reason != reasonSourceProducedObservation {
		t.Fatalf("linked cloud %+v: %v", result, err)
	}
	assertNoRefreshJob(t, db, tenant, linked)
	// Retained provider context identifies the configured integration for an
	// observation that has no asset, without manufacturing one or reading
	// another tenant's credential — and the dispatch is bounded.
	req := retainedCloudRefresh(t, db, devices, tenant, *device)
	result, err = service.Refresh(context.Background(), req)
	if err != nil || result.State != "queued" {
		t.Fatalf("retained cloud %+v: %v", result, err)
	}
	var selected uuid.UUID
	var params []byte
	if err := db.QueryRow(`SELECT j.integration_id,j.parameters FROM device_jobs j JOIN identity_source_refreshes r ON r.tenant_id=j.tenant_id AND r.device_job_id=j.id WHERE r.tenant_id=$1 AND r.id=$2`, tenant, req.RequestID).Scan(&selected, &params); err != nil {
		t.Fatal(err)
	}
	var parameters map[string]interface{}
	if err := json.Unmarshal(params, &parameters); err != nil {
		t.Fatal(err)
	}
	if selected != integration || parameters["source_refresh_only"] != true || len(parameters["resource_types"].([]interface{})) != 1 {
		t.Fatalf("unbounded/wrong source %s %v", selected, parameters)
	}
	// A second retained observation of the same source shares the dispatch.
	retained := retainedCloudRefresh(t, db, devices, tenant, *device)
	result, err = service.Refresh(context.Background(), retained)
	if err != nil || result.State != "queued" {
		t.Fatalf("second retained cloud %+v: %v", result, err)
	}
	var sharedJobs int
	if err := db.QueryRow(`SELECT count(DISTINCT device_job_id) FROM identity_source_refreshes WHERE tenant_id=$1`, tenant).Scan(&sharedJobs); err != nil || sharedJobs != 1 {
		t.Fatalf("same cloud source dispatched repeatedly: %d %v", sharedJobs, err)
	}
	if _, err := db.Exec(`UPDATE platform_integrations SET tenant_id=$2 WHERE id=$1`, integration, other); err != nil {
		t.Fatal(err)
	}
	denied := retainedCloudRefresh(t, db, devices, tenant, *device)
	result, err = service.Refresh(context.Background(), denied)
	if err != nil || result.State != "blocked" {
		t.Fatalf("foreign integration %+v: %v", result, err)
	}
	if _, err := db.Exec(`UPDATE tenant_admin_settings SET config='{}' WHERE tenant_id=$1`, tenant); err != nil {
		t.Fatal(err)
	}
	controller, err := devices.CreateDevice(context.Background(), tenant, models.CreateDeviceRequest{DeviceType: "unifi", Hostname: strptr("controller.example.test"), ManagementURL: strptr("https://192.0.2.2"), PlatformReinterrogationAllowed: boolPtr(true)})
	if err != nil {
		t.Fatal(err)
	}
	agent := uuid.New()
	if _, err := db.Exec(`INSERT INTO device_agents(id,tenant_id,registration_key,platform,version,profile,status,last_heartbeat) VALUES($1,$2,$3,'linux','0.9.9','full','active',now())`, agent, other, uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	// The controller's last run was by that foreign agent; a sighting linked to
	// the controller must not be handed to it.
	completedJob(t, db, queue, tenant, controller.ID, &agent)
	req = refreshObservation(t, db, tenant, "sensor:"+uuid.NewString(), &controller.ID)
	result, err = service.Refresh(context.Background(), req)
	if err != nil || result.State != "blocked" || result.Reason != "executor_unreachable_or_unsuitable" {
		t.Fatalf("foreign executor %+v: %v", result, err)
	}
	// The app role cannot browse another tenant's request (RLS, not just APIs).
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(`SET LOCAL ROLE crypto_app`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`SELECT set_config('app.tenant_id',$1,true)`, other.String()); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := tx.QueryRow(`SELECT count(*) FROM identity_source_refreshes WHERE tenant_id=$1`, tenant).Scan(&count); err != nil || count != 0 {
		t.Fatalf("RLS leaked %d: %v", count, err)
	}
}

func TestIntegration_SourceRefreshTargetPolicy(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db)
	service := NewConfiguredSourceRefresh(db, NewJobQueueService(db, db, nil), NewDeviceServiceWithKey(db, testMasterKey), nil)
	segment := uuid.New()
	if _, err := db.Exec(`INSERT INTO network_segments(id,tenant_id,name,segment_type,value,environment,is_active) VALUES($1,$2,'Policy network','cidr','192.0.2.0/24','production',true)`, segment, tenant); err != nil {
		t.Fatal(err)
	}
	device := models.Device{ID: uuid.New(), TenantID: tenant, DeviceType: "unifi", ClassKey: "network_controller", ManagementURL: strptr("https://192.0.2.2")}
	cases := []struct{ name, config, url, reason string }{
		{"allowed", `{}`, "https://192.0.2.2", ""},
		{"disabled", `{"discovery_auto_scan":{"enabled":false}}`, "https://192.0.2.2", "automatic_probes_disabled"},
		{"excluded", `{"identity_enrichment":{"excluded_cidrs":["192.0.2.2/32"]}}`, "https://192.0.2.2", "target_excluded"},
		{"unresolved name", `{}`, "https://controller.example.test", "configured_target_requires_scoped_address"},
		{"unauthorized network", `{}`, "https://198.51.100.2", "network_scope_unresolved_or_ambiguous"},
		{"unauthorized protocol", `{}`, "http://192.0.2.2", "configured_protocol_not_authorized"},
		{"unauthorized port", `{}`, "https://192.0.2.2:55555", "configured_port_not_authorized"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := db.Exec(`INSERT INTO tenant_admin_settings(tenant_id,config) VALUES($1,$2) ON CONFLICT(tenant_id) DO UPDATE SET config=EXCLUDED.config`, tenant, tc.config); err != nil {
				t.Fatal(err)
			}
			device.ManagementURL = &tc.url
			reason, err := service.authorizeTargetedRefresh(context.Background(), tenant, &device)
			if err != nil || reason != tc.reason {
				t.Fatalf("reason=%s want=%s: %v", reason, tc.reason, err)
			}
		})
	}
	t.Setenv("DISCOVERY_AUTO_SCAN_EXCLUDE_CIDRS", "192.0.2.0/24")
	device.ManagementURL = strptr("https://192.0.2.2")
	reason, err := service.authorizeTargetedRefresh(context.Background(), tenant, &device)
	if err != nil || reason != "platform_target_excluded" {
		t.Fatalf("platform exclusions %s: %v", reason, err)
	}
	t.Setenv("DISCOVERY_AUTO_SCAN_EXCLUDE_CIDRS", "")
	t.Setenv("KUBERNETES_SERVICE_HOST", "192.0.2.2")
	reason, err = service.authorizeTargetedRefresh(context.Background(), tenant, &device)
	if err != nil || reason != "platform_target_excluded" {
		t.Fatalf("platform API exclusion %s: %v", reason, err)
	}
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	if _, err := db.Exec(`UPDATE tenant_admin_settings SET config='{}' WHERE tenant_id=$1;`, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE network_segments SET metadata='{"active_probes_disabled":true}' WHERE id=$1`, segment); err != nil {
		t.Fatal(err)
	}
	device.ManagementURL = strptr("https://192.0.2.2")
	reason, err = service.authorizeTargetedRefresh(context.Background(), tenant, &device)
	if err != nil || reason != "sensitive_network_requires_review" {
		t.Fatalf("sensitive segment %s: %v", reason, err)
	}
}

func TestIntegration_SourceRefreshRechecksPolicyAtClaim(t *testing.T) {
	t.Setenv("ENCRYPTION_MASTER_KEY", testMasterKey)
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db)
	devices := NewDeviceServiceWithKey(db, testMasterKey)
	queue := NewJobQueueService(db, db, nil)
	if _, err := db.Exec(`INSERT INTO network_segments(id,tenant_id,name,segment_type,value,environment,is_active) VALUES($1,$2,'Claim network','cidr','192.0.2.0/24','production',true)`, uuid.New(), tenant); err != nil {
		t.Fatal(err)
	}
	device, err := devices.CreateDevice(context.Background(), tenant, models.CreateDeviceRequest{DeviceType: "unifi", ManagementURL: strptr("https://192.0.2.2"), PlatformReinterrogationAllowed: boolPtr(true)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE assets SET asset_status='monitoring' WHERE tenant_id=$1 AND id=$2`, tenant, device.ID); err != nil {
		t.Fatal(err)
	}
	job := &models.DeviceJob{ID: uuid.New(), TenantID: tenant, JobType: models.JobTypeDeviceInterrogation, AssetID: &device.ID, Parameters: map[string]interface{}{"identity_refresh_request_id": uuid.NewString(), "identity_refresh_executor": "platform", "management_url": "https://192.0.2.2"}}
	receipt := refreshObservation(t, db, tenant, "interrogation:"+uuid.NewString(), nil)
	if _, err := db.Exec(`INSERT INTO identity_source_refreshes(tenant_id,id,observation_id,fingerprint,state,device_job_id) VALUES($1,$2,$3,'claim','queued',$4)`, tenant, receipt.RequestID, receipt.ObservationID, job.ID); err != nil {
		t.Fatal(err)
	}
	if err := queue.validateRefreshClaim(context.Background(), job); err == nil {
		t.Fatal("disabled coordinator allowed queued refresh")
	}
	if _, err := db.Exec(`INSERT INTO tenant_admin_settings(tenant_id,config) VALUES($1,'{"identity_enrichment":{"enabled":true},"identity_admission":{"mode":"enforce"}}') ON CONFLICT(tenant_id) DO UPDATE SET config=EXCLUDED.config`, tenant); err != nil {
		t.Fatal(err)
	}
	if err := queue.validateRefreshClaim(context.Background(), job); err != nil {
		t.Fatalf("approved configured platform: %v", err)
	}
	agent := uuid.New()
	job.AgentID = &agent
	if err := queue.validateRefreshClaim(context.Background(), job); err == nil {
		t.Fatal("platform refresh handed to arbitrary agent")
	}
	job.AgentID = nil
	job.Parameters["management_url"] = "https://198.51.100.1"
	if err := queue.validateRefreshClaim(context.Background(), job); err == nil {
		t.Fatal("changed target accepted")
	}
	job.Parameters["management_url"] = "https://192.0.2.2"
	if _, err := db.Exec(`UPDATE tenant_admin_settings SET config=jsonb_set(config,'{identity_enrichment,excluded_cidrs}','["192.0.2.2/32"]') WHERE tenant_id=$1`, tenant); err != nil {
		t.Fatal(err)
	}
	if err := queue.validateRefreshClaim(context.Background(), job); err == nil {
		t.Fatal("new exclusion ignored at claim")
	}
}

func enableSourceRefresh(t *testing.T, db *sql.DB, tenant uuid.UUID) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO tenant_admin_settings(tenant_id,config) VALUES($1,'{"identity_enrichment":{"enabled":true},"identity_admission":{"mode":"enforce"}}') ON CONFLICT(tenant_id) DO UPDATE SET config=EXCLUDED.config`, tenant); err != nil {
		t.Fatal(err)
	}
}

// retainedCloudRefresh is an UNLINKED cloud observation with the retained
// provider context cloud discovery keeps for an observation that produced no
// asset (retainCloudContext) — the one shape a cloud source refresh is for.
func retainedCloudRefresh(t *testing.T, db *sql.DB, devices *DeviceService, tenant uuid.UUID, device models.Device) SourceRefreshRequest {
	t.Helper()
	req := refreshObservation(t, db, tenant, "cloud:aws", nil)
	raw, err := json.Marshal(retainedCloudContext{Device: device, Observation: req.Evidence})
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := devices.cipher.EncryptValue(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO identity_observation_cloud_contexts(tenant_id,observation_id,receipt_key,context_enc,observed_at) VALUES($1,$2,$3,$4,now())`, tenant, req.ObservationID, "refresh-test-"+req.ObservationID.String(), sealed); err != nil {
		t.Fatal(err)
	}
	return req
}

func assertNoRefreshJob(t *testing.T, db *sql.DB, tenant uuid.UUID, req SourceRefreshRequest) {
	t.Helper()
	var count int
	if err := db.QueryRow(`SELECT count(*) FROM device_jobs WHERE tenant_id=$1 AND parameters->>'identity_refresh_request_id'=$2`, tenant, req.RequestID.String()).Scan(&count); err != nil || count != 0 {
		t.Fatalf("refresh dispatched %d device jobs for %s: %v", count, req.RequestID, err)
	}
}

// TestIntegration_SourceRefresh_CloudDiscoveredAssetCompletes is the reported
// shape, produced by the REAL cloud producer: upsertDeviceAsset records a
// resource as an unmanaged asset (no asset_management, no asset_credentials —
// "nothing found through a cloud API is a managed device") and, because the
// observation produced an asset, keeps no retained cloud context. The
// coordinator then asks for a configured-source refresh of that observation.
//
// It used to end `blocked / cloud_source_not_identified` (23 rows on a live deployment,
// each after 4–5 attempts): the planner looked for the linked asset's
// management row, found none, fell back to the retained context, found none.
// The observation IS the cloud source's answer, so the stage is complete.
//
// Mutations performed, each observed red:
//   - delete the `if linked.Valid` early return in planCloud → blocked /
//     cloud_source_not_identified, the reported case.
//   - drop reasonSourceProducedObservation from Refresh's completed mapping →
//     state "blocked".
func TestIntegration_SourceRefresh_CloudDiscoveredAssetCompletes(t *testing.T) {
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)
	tenant := testdb.NewTenant(t, owner)
	ctx := context.Background()
	appDB := testdb.ConnectAsAppRole(t, owner)
	integration := seedCloudIntegration(t, owner, tenant)
	if _, err := owner.Exec(`UPDATE platform_integrations SET config='{"region":"us-east-1"}', is_active=true WHERE id=$1`, integration); err != nil {
		t.Fatal(err)
	}

	cloud := NewCloudDiscoveryService(appDB, owner, testMasterKey)
	bucket := s3Bucket("enrichment-" + uuid.NewString()[:8])
	bucket.TenantID = tenant
	bucket.CredentialID = &integration
	if err := cloud.upsertDeviceAsset(ctx, &bucket, getStringFromMap(bucket.Metadata, "arn")); err != nil {
		t.Fatalf("upsertDeviceAsset: %v", err)
	}
	asset := bucket.ID

	// The preconditions that made the planner block, read back rather than
	// assumed: unmanaged, and no retained context for its observation.
	if row := managementFor(t, owner, tenant, asset); row.exists {
		t.Fatal("precondition: a cloud-discovered asset has a management row")
	}
	if hasCredentialsRow(t, owner, tenant, asset) {
		t.Fatal("precondition: a cloud-discovered asset has a credentials row")
	}
	var contexts int
	if err := owner.QueryRow(`SELECT count(*) FROM identity_observation_cloud_contexts WHERE tenant_id=$1`, tenant).Scan(&contexts); err != nil || contexts != 0 {
		t.Fatalf("precondition: retained cloud context for an observation that produced an asset: %d %v", contexts, err)
	}

	// The linked `cloud:aws` observation the coordinator schedules for — in
	// production written by inventory-service's intake of the run's discovery
	// rows (findingSource), which this package cannot host, so it is written here
	// in that shape: measured, `cloud:aws`, linked to the asset above.
	enableSourceRefresh(t, owner, tenant)
	req := refreshObservation(t, owner, tenant, "cloud:aws", &asset)
	devices := NewDeviceServiceWithKey(owner, testMasterKey)
	service := NewConfiguredSourceRefresh(owner, NewJobQueueService(owner, owner, nil), devices, nil)

	result, err := service.Refresh(ctx, req)
	if err != nil {
		t.Fatal(err)
	}
	if result.State != "completed" || result.Reason != reasonSourceProducedObservation {
		t.Fatalf("cloud-discovered asset's refresh = %+v, want completed / %s", result, reasonSourceProducedObservation)
	}
	assertNoRefreshJob(t, owner, tenant, req)

	// The durable receipt the coordinator polls says the same, so the row an
	// operator reads is not a blocker.
	status, err := service.Status(ctx, tenant, req.RequestID)
	if err != nil || status.State != "completed" {
		t.Fatalf("receipt %+v: %v", status, err)
	}
}
