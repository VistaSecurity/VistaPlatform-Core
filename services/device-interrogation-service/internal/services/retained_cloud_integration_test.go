package services

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_RetainedCloudReplaysProviderEvidenceAfterApproval(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db)
	other := testdb.NewTenant(t, db)
	ctx := context.Background()
	svc := NewCloudDiscoveryService(db, db, testMasterKey)
	hostname := "cloud-target.example.test"
	target, err := svc.devices.CreateDevice(ctx, tenant, models.CreateDeviceRequest{DeviceType: "aws_alb", Hostname: &hostname})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO sensors(id,tenant_id,name,platform,version,profile,status,tags)
 VALUES($1,$2,'Cloud replay','linux','test','device_interrogation','active',ARRAY['system'])`, uuid.New(), tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO tenant_admin_settings(tenant_id,config) VALUES($1,'{"identity_admission":{"mode":"paused"}}') ON CONFLICT(tenant_id) DO UPDATE SET config=EXCLUDED.config`, tenant); err != nil {
		t.Fatal(err)
	}
	svc.devices.identityEng, err = identity.New(identity.Config{Repo: svc.devices.identityRepo, AdmissionEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	seen := time.Now().UTC().Add(-4 * time.Hour).Truncate(time.Microsecond)
	arn := "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/held/123"
	device := models.Device{ID: uuid.New(), TenantID: tenant, DeviceType: "aws_alb", Vendor: stringPtr("AWS"), Hostname: stringPtr("cloud-held.example.test"), CreatedAt: seen,
		Metadata: models.JSONB{"arn": arn, "region": "us-east-1", "crypto_configs": []map[string]interface{}{{"protocol": "TLS", "protocol_version": "TLS 1.3", "port": 443, "cipher_suite": "TLS_AES_256_GCM_SHA384"}}}}
	run := &cloudRunEvidence{}
	runCtx := context.WithValue(ctx, cloudRunKey{}, run)
	var retained *identity.RetainedObservation
	for range 2 {
		err = svc.upsertDeviceAsset(runCtx, &device, arn)
		if !errors.As(err, &retained) {
			t.Fatalf("want retained cloud evidence: %v", err)
		}
	}
	if run.summary.ObservationsRetained != 2 || run.summary.AssetsCreated != 0 || run.summary.RejectedInputs != 0 {
		t.Fatalf("retained outcome counted as failure/asset: %+v", run.summary)
	}
	var count int
	var sealed, evidence string
	if err := db.QueryRow(`SELECT count(*) FROM identity_observation_cloud_contexts WHERE tenant_id=$1`, tenant).Scan(&count); err != nil || count != 1 {
		t.Fatalf("retained receipt replay count=%d: %v", count, err)
	}
	if err := db.QueryRow(`SELECT p.context_enc,o.evidence::text FROM identity_observation_cloud_contexts p JOIN identity_observations o ON o.tenant_id=p.tenant_id AND o.id=p.observation_id WHERE p.tenant_id=$1`, tenant).Scan(&sealed, &evidence); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(sealed, "enc:v1:") || strings.Contains(sealed, "TLS_AES") || strings.Contains(evidence, "crypto_configs") {
		t.Fatal("cloud payload escaped encrypted storage")
	}
	if _, err := db.Exec(`UPDATE identity_observations SET state='linked',asset_id=$3 WHERE tenant_id=$1 AND id=$2`, tenant, retained.Result.ObservationID, target.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE tenant_admin_settings SET config='{"identity_admission":{"mode":"enforce"}}' WHERE tenant_id=$1`, tenant); err != nil {
		t.Fatal(err)
	}
	if err := svc.ReplayRetainedCloudContext(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM sensor_discoveries WHERE tenant_id=$1`, tenant).Scan(&count); err != nil || count != 0 {
		t.Fatalf("pending cloud evidence published: %d %v", count, err)
	}
	if _, err := db.Exec(`UPDATE assets SET asset_status='monitoring' WHERE tenant_id=$1 AND id=$2`, tenant, target.ID); err != nil {
		t.Fatal(err)
	}
	var before time.Time
	if err := db.QueryRow(`SELECT last_seen_at FROM assets WHERE tenant_id=$1 AND id=$2`, tenant, target.ID).Scan(&before); err != nil {
		t.Fatal(err)
	}
	restarted := NewCloudDiscoveryService(db, db, testMasterKey)
	// A downstream write failure rolls back both projection and acknowledgement.
	function := "fail_cloud_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := db.Exec(fmt.Sprintf(`CREATE FUNCTION %s() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.tenant_id='%s'::uuid THEN RAISE EXCEPTION 'injected cloud write failure'; END IF; RETURN NEW; END $$;
 CREATE TRIGGER %s BEFORE INSERT ON sensor_discoveries_partitioned FOR EACH ROW EXECUTE FUNCTION %s()`, function, tenant, function, function)); err != nil {
		t.Fatal(err)
	}
	cleanup := func() {
		_, _ = db.Exec(fmt.Sprintf("DROP TRIGGER IF EXISTS %s ON sensor_discoveries_partitioned; DROP FUNCTION IF EXISTS %s()", function, function))
	}
	t.Cleanup(cleanup)
	if err := restarted.ReplayRetainedCloudContext(ctx, tenant); err == nil {
		t.Fatal("downstream persistence failure was acknowledged")
	}
	if err := db.QueryRow(`SELECT count(*) FROM identity_observation_cloud_contexts WHERE tenant_id=$1 AND materialized_at IS NOT NULL`, tenant).Scan(&count); err != nil || count != 0 {
		t.Fatalf("failed cloud receipt acknowledged: %d %v", count, err)
	}
	cleanup()
	if _, err := db.Exec(`UPDATE identity_observation_cloud_contexts SET next_attempt_at=now() WHERE tenant_id=$1`, tenant); err != nil {
		t.Fatal(err)
	}
	app := testdb.ConnectAsAppRole(t, db)
	if err := shareddatabase.WithTenantTx(ctx, app, other, func(tx *sql.Tx) error {
		return tx.QueryRow(`SELECT count(*) FROM identity_observation_cloud_contexts WHERE tenant_id=$1`, tenant).Scan(&count)
	}); err != nil || count != 0 {
		t.Fatalf("cross-tenant cloud payload exposed: %d %v", count, err)
	}
	if err := restarted.ReplayRetainedCloudContext(ctx, other); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := restarted.ReplayRetainedCloudContext(ctx, tenant); err != nil {
			t.Fatal(err)
		}
	}
	var observed, after time.Time
	var cipher string
	if err := db.QueryRow(`SELECT timestamp,metadata->>'cipher_suite' FROM sensor_discoveries WHERE tenant_id=$1`, tenant).Scan(&observed, &cipher); err != nil {
		t.Fatal(err)
	}
	if !observed.Equal(seen) || cipher != "TLS_AES_256_GCM_SHA384" {
		t.Fatalf("cloud replay lost source clock or crypto: %s %s", observed, cipher)
	}
	if err := db.QueryRow(`SELECT count(*) FROM sensor_discoveries WHERE tenant_id=$1`, tenant).Scan(&count); err != nil || count != 1 {
		t.Fatalf("duplicate downstream evidence: %d %v", count, err)
	}
	if err := db.QueryRow(`SELECT last_seen_at FROM assets WHERE tenant_id=$1 AND id=$2`, tenant, target.ID).Scan(&after); err != nil || !after.Equal(before) {
		t.Fatalf("replay refreshed identity timestamp: %s %s %v", before, after, err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM identity_observation_cloud_contexts WHERE tenant_id=$1 AND materialized_at IS NOT NULL`, tenant).Scan(&count); err != nil || count != 1 {
		t.Fatalf("receipt not acknowledged exactly once: %d %v", count, err)
	}
}

func TestIntegration_RetainedCloudEnumerationPreservesFactsAndDeclaredAttributes(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db)
	ctx := context.Background()
	integration := seedCloudIntegration(t, db, tenant)
	svc := NewCloudDiscoveryService(db, db, testMasterKey)
	target, err := svc.devices.CreateDevice(ctx, tenant, models.CreateDeviceRequest{DeviceType: DeviceTypeAWSEC2Instance, Hostname: stringPtr("declared-target.example.test")})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE assets SET attributes='{"region":"operator-region"}' WHERE tenant_id=$1 AND id=$2`, tenant, target.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO tenant_admin_settings(tenant_id,config) VALUES($1,'{"identity_admission":{"mode":"paused"}}') ON CONFLICT(tenant_id) DO UPDATE SET config=EXCLUDED.config`, tenant); err != nil {
		t.Fatal(err)
	}
	svc.devices.identityEng, err = identity.New(identity.Config{Repo: svc.devices.identityRepo, AdmissionEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	plan := awsEnumerationPlanForTest(t)
	resource := plan.Instances[0]
	resource.ParentID = "arn:aws:ec2:us-east-1:123456789012:subnet/future-parent"
	resource.Attributes["region"] = "observed-region"
	_, err = svc.recordCloudResource(ctx, tenant, integration, "AWS", resource)
	var retained *identity.RetainedObservation
	if !errors.As(err, &retained) {
		t.Fatalf("enumeration not retained: %v", err)
	}
	var seen time.Time
	if err := db.QueryRow(`SELECT observed_at FROM identity_observation_cloud_contexts WHERE tenant_id=$1`, tenant).Scan(&seen); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE identity_observations SET state='linked',asset_id=$3 WHERE tenant_id=$1 AND id=$2`, tenant, retained.Result.ObservationID, target.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE assets SET asset_status='monitoring' WHERE tenant_id=$1 AND id=$2`, tenant, target.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE tenant_admin_settings SET config='{"identity_admission":{"mode":"enforce"}}' WHERE tenant_id=$1`, tenant); err != nil {
		t.Fatal(err)
	}
	restarted := NewCloudDiscoveryService(db, db, testMasterKey)
	if err := restarted.ReplayRetainedCloudContext(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	var pending int
	if err := db.QueryRow(`SELECT count(*) FROM identity_observation_cloud_contexts WHERE tenant_id=$1 AND materialized_at IS NULL AND last_error='cloud parent identity unresolved'`, tenant).Scan(&pending); err != nil || pending != 1 {
		t.Fatalf("unresolved parent evidence lost: %d %v", pending, err)
	}
	if _, err := db.Exec(`UPDATE tenant_admin_settings SET config='{"identity_admission":{"mode":"disabled"}}' WHERE tenant_id=$1`, tenant); err != nil {
		t.Fatal(err)
	}
	parent, err := svc.devices.CreateDevice(ctx, tenant, models.CreateDeviceRequest{DeviceType: DeviceTypeAWSSubnet, Hostname: stringPtr("parent.example.test"), Metadata: map[string]interface{}{"cloud_resource_id": resource.ParentID}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE tenant_admin_settings SET config='{"identity_admission":{"mode":"enforce"}}' WHERE tenant_id=$1`, tenant); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE identity_observation_cloud_contexts SET next_attempt_at=now() WHERE tenant_id=$1`, tenant); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := restarted.ReplayRetainedCloudContext(ctx, tenant); err != nil {
			t.Fatal(err)
		}
	}
	var edges int
	if err := db.QueryRow(`SELECT count(*) FROM asset_relationships WHERE tenant_id=$1 AND from_asset_id=$2 AND to_asset_id=$3 AND type='contains'`, tenant, parent.ID, target.ID).Scan(&edges); err != nil || edges != 1 {
		t.Fatalf("retained containment lost: %d %v", edges, err)
	}
	var region string
	if err := db.QueryRow(`SELECT attributes->>'region' FROM assets WHERE tenant_id=$1 AND id=$2`, tenant, target.ID).Scan(&region); err != nil || region != "operator-region" {
		t.Fatalf("replay replaced declared region: %s %v", region, err)
	}
	var factsCount int
	var latest time.Time
	if err := db.QueryRow(`SELECT count(*),max(observed_at) FROM asset_facts WHERE tenant_id=$1 AND asset_id=$2 AND source_ref='cloud:aws'`, tenant, target.ID).Scan(&factsCount, &latest); err != nil {
		t.Fatal(err)
	}
	if factsCount == 0 || !latest.Equal(seen) {
		t.Fatalf("facts missing or source clock changed: %d %s want %s", factsCount, latest, seen)
	}
	var discoveries int
	if err := db.QueryRow(`SELECT count(*) FROM sensor_discoveries WHERE tenant_id=$1`, tenant).Scan(&discoveries); err != nil || discoveries != 0 {
		t.Fatalf("enumeration fabricated endpoint evidence: %d %v", discoveries, err)
	}
}
