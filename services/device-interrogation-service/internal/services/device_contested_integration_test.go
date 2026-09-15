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
	"testing"

	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

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
