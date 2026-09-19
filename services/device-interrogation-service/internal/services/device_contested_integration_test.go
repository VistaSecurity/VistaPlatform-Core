package services

// The contested-identity outcome, and the thing that made it a lie: the merge
// proposal the operator is told to read must still be there when they look.
//
// The engine writes the proposal INSIDE the resolve transaction. Returning an
// error from the RunInTx closure rolled that transaction back — so the proposal
// was erased by the very act of reporting it, and the operator went to Approvals
// and found nothing. Only a real transaction can show this: in a fake, the
// rollback is not modelled and the test passes either way.
//
// Skips without TEST_DATABASE_URL.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_RetainedDeviceManagementEncryptedAndReplayedAfterApproval(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db)
	other := testdb.NewTenant(t, db)
	ctx := context.Background()
	svc := NewDeviceService(db)
	// Seed an existing unmanaged target using the unchanged disabled behavior.
	targetName := "retained-target.example.test"
	target, err := svc.CreateDevice(ctx, tenant, models.CreateDeviceRequest{DeviceType: "f5", Hostname: &targetName})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`DELETE FROM asset_management WHERE tenant_id=$1 AND asset_id=$2`, tenant, target.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO tenant_admin_settings(tenant_id,config) VALUES($1,'{"identity_admission":{"mode":"enforce"}}') ON CONFLICT(tenant_id) DO UPDATE SET config=EXCLUDED.config`, tenant); err != nil {
		t.Fatal(err)
	}
	svc.identityEng, err = identity.New(identity.Config{Repo: svc.identityRepo, AdmissionEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	name, url, password := "retained-device.example.test", "https://retained-device.example.test", "test-device-secret-for-encrypted-retention"
	_, err = svc.CreateDevice(ctx, tenant, models.CreateDeviceRequest{DeviceType: "f5", Hostname: &name, ManagementURL: &url, Password: &password, Metadata: map[string]interface{}{"nested_secret": password}})
	var retained *identity.RetainedObservation
	if !errors.As(err, &retained) || retained.Result.ObservationID == "" || retained.Result.AssetID != "" {
		t.Fatalf("want retained result without asset: %v", err)
	}
	var sealed, evidence string
	if err = db.QueryRow(`SELECT m.context_enc,o.evidence::text FROM identity_observation_management m JOIN identity_observations o ON o.id=m.observation_id AND o.tenant_id=m.tenant_id WHERE m.tenant_id=$1 AND m.observation_id=$2`, tenant, retained.Result.ObservationID).Scan(&sealed, &evidence); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(sealed, "enc:v1:") || strings.Contains(sealed, password) || strings.Contains(evidence, password) {
		t.Fatal("credential escaped encrypted context")
	}
	if _, err = db.Exec(`UPDATE identity_observations SET state='linked',asset_id=$3 WHERE tenant_id=$1 AND id=$2`, tenant, retained.Result.ObservationID, target.ID); err != nil {
		t.Fatal(err)
	}
	if err = svc.ReplayRetainedManagement(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	var count int
	if err = db.QueryRow(`SELECT count(*) FROM asset_management WHERE tenant_id=$1 AND asset_id=$2`, tenant, target.ID).Scan(&count); err != nil || count != 0 {
		t.Fatalf("unapproved context materialized: count=%d err=%v", count, err)
	}
	if _, err = db.Exec(`UPDATE assets SET asset_status='monitoring' WHERE tenant_id=$1 AND id=$2`, tenant, target.ID); err != nil {
		t.Fatal(err)
	}
	var seenBefore, seenAfter time.Time
	if err = db.QueryRow(`SELECT last_seen_at FROM assets WHERE tenant_id=$1 AND id=$2`, tenant, target.ID).Scan(&seenBefore); err != nil {
		t.Fatal(err)
	}
	if err = svc.ReplayRetainedManagement(ctx, other); err != nil {
		t.Fatal(err)
	}
	// A new service instance models a restart after ingestion committed.
	restarted := NewDeviceService(db)
	for range 2 {
		if err = restarted.ReplayRetainedManagement(ctx, tenant); err != nil {
			t.Fatal(err)
		}
	}
	var storedURL, storedPassword string
	if err = db.QueryRow(`SELECT m.management_url,c.password_enc FROM asset_management m JOIN asset_credentials c ON c.tenant_id=m.tenant_id AND c.asset_id=m.asset_id WHERE m.tenant_id=$1 AND m.asset_id=$2`, tenant, target.ID).Scan(&storedURL, &storedPassword); err != nil {
		t.Fatal(err)
	}
	decrypted, err := restarted.cipher.DecryptValue(storedPassword)
	if err != nil || decrypted != password || storedURL != url || storedPassword == password {
		t.Fatal("encrypted management did not replay correctly")
	}
	// Another observation linked to an already-managed asset must not replace
	// its populated configuration or credentials.
	otherName, replacementURL := "another-retained-device.example.test", "https://replacement.example.test"
	_, err = svc.CreateDevice(ctx, tenant, models.CreateDeviceRequest{DeviceType: "f5", Hostname: &otherName, ManagementURL: &replacementURL})
	var second *identity.RetainedObservation
	if !errors.As(err, &second) {
		t.Fatalf("second retained context: %v", err)
	}
	if _, err = db.Exec(`UPDATE identity_observations SET state='linked',asset_id=$3 WHERE tenant_id=$1 AND id=$2`, tenant, second.Result.ObservationID, target.ID); err != nil {
		t.Fatal(err)
	}
	if err = restarted.ReplayRetainedManagement(ctx, tenant); err != nil {
		t.Fatal(err)
	}
	if err = db.QueryRow(`SELECT management_url FROM asset_management WHERE tenant_id=$1 AND asset_id=$2`, tenant, target.ID).Scan(&storedURL); err != nil || storedURL != url {
		t.Fatalf("populated management was overwritten: %q %v", storedURL, err)
	}
	if err = db.QueryRow(`SELECT last_seen_at FROM assets WHERE tenant_id=$1 AND id=$2`, tenant, target.ID).Scan(&seenAfter); err != nil || !seenBefore.Equal(seenAfter) {
		t.Fatalf("configuration replay changed observation freshness: %v", err)
	}
	if err = db.QueryRow(`SELECT count(*) FROM identity_observation_management WHERE tenant_id=$1 AND materialized_at IS NOT NULL`, tenant).Scan(&count); err != nil || count != 1 {
		t.Fatalf("replay was not recorded exactly once: %d %v", count, err)
	}
}

func TestIntegration_PausedCloudResourceRetainsManagement(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db)
	cloud := NewCloudDiscoveryService(db, db, "test-retained-cloud-master-key")
	if _, err := cloud.devices.identityEngine(); err != nil {
		t.Fatal(err)
	}
	var err error
	cloud.devices.identityEng, err = identity.New(identity.Config{Repo: cloud.devices.identityRepo, AdmissionEnabled: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`INSERT INTO tenant_admin_settings(tenant_id,config) VALUES($1,'{"identity_admission":{"mode":"paused"}}') ON CONFLICT(tenant_id) DO UPDATE SET config=EXCLUDED.config`, tenant); err != nil {
		t.Fatal(err)
	}
	vendor := "AWS"
	device := models.Device{ID: uuid.New(), TenantID: tenant, DeviceType: "aws_alb", Vendor: &vendor}
	err = cloud.upsertDeviceAsset(context.Background(), &device, "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/retained/123")
	var retained *identity.RetainedObservation
	if !errors.As(err, &retained) || retained.Result.ObservationID == "" {
		t.Fatalf("cloud did not expose retained outcome: %v", err)
	}
	var count int
	if err = db.QueryRow(`SELECT count(*) FROM identity_observation_management WHERE tenant_id=$1`, tenant).Scan(&count); err != nil || count != 1 {
		t.Fatalf("cloud context not retained: %d %v", count, err)
	}
}

// TestIntegration_CreateDevice_Contested_LeavesTheProposal: two devices, then a
// third whose only identifier is already taken. The create is refused — and the
// proposal survives the refusal.
func TestIntegration_CreateDevice_Contested_LeavesTheProposal(t *testing.T) {
	db := testdb.Connect(t)
	tenant := testdb.NewTenant(t, db)
	ctx := context.Background()
	svc := NewDeviceService(db)

	// Two assets, each already owning ONE of the identifiers the third device
	// will carry: the cross-kind conflict where every identifier is spoken for.
	// Nothing can be created (an asset with no identifier could never be matched
	// again), so the engine writes a proposal and returns a zero ref.
	serial := "SN-CONTESTED-DEVICE"
	bySerial := "switch-a.example.test"
	if _, err := svc.CreateDevice(ctx, tenant, models.CreateDeviceRequest{
		DeviceType: "cisco_ios", Hostname: &bySerial, SerialNumber: &serial,
	}); err != nil {
		t.Fatalf("create the serial's owner: %v", err)
	}
	byName := "switch-b.example.test"
	if _, err := svc.CreateDevice(ctx, tenant, models.CreateDeviceRequest{
		DeviceType: "cisco_ios", Hostname: &byName,
	}); err != nil {
		t.Fatalf("create the name's owner: %v", err)
	}

	_, err := svc.CreateDevice(ctx, tenant, models.CreateDeviceRequest{
		DeviceType: "cisco_ios", Hostname: &byName, SerialNumber: &serial,
	})
	if err == nil {
		t.Fatal("a device whose every identifier is taken must not be created")
	}
	if !errors.Is(err, ErrDeviceIdentityContested) {
		t.Fatalf("err = %v, want the contested sentinel", err)
	}
	var contested *DeviceIdentityContestedError
	if !errors.As(err, &contested) {
		t.Fatalf("err = %T, want *DeviceIdentityContestedError", err)
	}
	if contested.ProposalID == "" {
		t.Fatal("the contested error must name the proposal it sends the operator to read")
	}

	// THE POINT: the proposal is still in the database. It was written inside
	// the transaction the refusal used to roll back.
	var live int
	if err := db.QueryRow(`
		SELECT count(*) FROM asset_history
		WHERE tenant_id = $1 AND id = $2 AND action = $3
		  AND changes_json->>'kind' = 'merge_proposal'`,
		tenant, contested.ProposalID, string(identity.ActionMergeProposed)).Scan(&live); err != nil {
		t.Fatalf("look for the proposal: %v", err)
	}
	if live != 1 {
		t.Errorf("merge proposal %s is not in the database (%d rows); the refusal erased what it told the operator to review",
			contested.ProposalID, live)
	}
}

// TestIntegration_UpsertCloudResource_Contested_LeavesTheProposal is the cloud
// twin. Same defect, same shape, a different intake path — and one the operator
// never drives by hand, so a rolled-back proposal there would simply never be
// seen at all.
func TestIntegration_UpsertCloudResource_Contested_LeavesTheProposal(t *testing.T) {
	db := testdb.Connect(t)
	tenant := testdb.NewTenant(t, db)
	ctx := context.Background()
	devices := NewDeviceService(db)
	cloud := &CloudDiscoveryService{devices: devices}

	const arn = "arn:aws:elasticloadbalancing:us-east-1:1:loadbalancer/app/contested/1"
	arnOwner := "lb-first.example.test"
	if _, err := devices.CreateDevice(ctx, tenant, models.CreateDeviceRequest{
		DeviceType: "aws_alb", Hostname: &arnOwner,
		Metadata: map[string]interface{}{"arn": arn},
	}); err != nil {
		t.Fatalf("create the asset that owns the ARN: %v", err)
	}
	nameOwner := "lb-second.example.test"
	if _, err := devices.CreateDevice(ctx, tenant, models.CreateDeviceRequest{
		DeviceType: "aws_alb", Hostname: &nameOwner,
	}); err != nil {
		t.Fatalf("create the asset that owns the name: %v", err)
	}

	// A cloud resource carrying the ARN of one and the name of the other: every
	// identifier is spoken for, so nothing can be created.
	device := models.Device{TenantID: tenant, DeviceType: "aws_alb", Hostname: &nameOwner}
	err := cloud.upsertDeviceAsset(ctx, &device, arn)
	if err == nil {
		t.Fatal("a cloud resource whose every identifier is taken must not be created")
	}
	var contested *DeviceIdentityContestedError
	if !errors.As(err, &contested) {
		t.Fatalf("err = %v (%T), want *DeviceIdentityContestedError", err, err)
	}
	if contested.ProposalID == "" {
		t.Fatal("the contested error must name the proposal")
	}

	var live int
	if err := db.QueryRow(`
		SELECT count(*) FROM asset_history
		WHERE tenant_id = $1 AND id = $2 AND action = $3
		  AND changes_json->>'kind' = 'merge_proposal'`,
		tenant, contested.ProposalID, string(identity.ActionMergeProposed)).Scan(&live); err != nil {
		t.Fatalf("look for the proposal: %v", err)
	}
	if live != 1 {
		t.Errorf("merge proposal %s is not in the database (%d rows); the cloud path erased it on the way out",
			contested.ProposalID, live)
	}
}
