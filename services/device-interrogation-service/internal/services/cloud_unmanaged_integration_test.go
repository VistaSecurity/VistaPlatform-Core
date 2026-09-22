package services

// Nothing discovered through a cloud API is a managed device — and the device
// an operator adds by hand still is.
//
// The Devices page lists API-accessible interfaces the platform pulls inventory
// FROM. Cloud discovery used to write an `asset_management` row (plus an
// `asset_credentials` row holding only the integration id) for every resource it
// enumerated, stamped `connection_status = 'connected'`. On the demo host that
// put seven subnets and two VPCs on the page claiming a connection nothing ever
// made, with every per-row action greyed out because the page already knew a
// cloud-discovered row is not interrogable. An EC2 instance fails the same test
// for a different reason: an instance is onboarded through the DEVICE AGENT, so
// a management row minted by enumeration describes an onboarding that did not
// happen.
//
// The other half matters just as much and is the reason the suppression is
// scoped to the cloud code path rather than to applyDeviceFields or to the
// client-settable `discovery_method` string: a cloud-hosted appliance — a Palo
// Alto or FortiGate running as an instance — must still be addable deliberately,
// with credentials, and interrogable.
//
// These are WIRING tests. They drive recordEnumeration, upsertDeviceAsset and
// CreateDevice — the same entry points a cloud_discovery job and the Devices
// form take — and assert on the rows in Postgres.
//
// Skips unless TEST_DATABASE_URL is set (run `make test-integration-db`).

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// managementRow is what asset_management holds for one asset, or nothing.
type managementRow struct {
	exists           bool
	connectionStatus string
	managementURL    sql.NullString
}

func managementFor(t *testing.T, db *sql.DB, tenantID, assetID uuid.UUID) managementRow {
	t.Helper()
	var row managementRow
	err := db.QueryRow(
		`SELECT connection_status, management_url FROM asset_management WHERE tenant_id = $1 AND asset_id = $2`,
		tenantID, assetID).Scan(&row.connectionStatus, &row.managementURL)
	if err == sql.ErrNoRows {
		return managementRow{}
	}
	if err != nil {
		t.Fatalf("read asset_management for %s: %v", assetID, err)
	}
	row.exists = true
	return row
}

func hasCredentialsRow(t *testing.T, db *sql.DB, tenantID, assetID uuid.UUID) bool {
	t.Helper()
	var exists bool
	if err := db.QueryRow(
		`SELECT EXISTS(SELECT 1 FROM asset_credentials WHERE tenant_id = $1 AND asset_id = $2)`,
		tenantID, assetID).Scan(&exists); err != nil {
		t.Fatalf("read asset_credentials for %s: %v", assetID, err)
	}
	return exists
}

// TestIntegration_CloudDiscovery_NothingDiscoveredIsManaged drives the two
// shapes of cloud discovery through the one funnel they share.
//
// Mutation checks, all run and all observed red:
//   - flip `Unmanaged: true` to false in upsertDeviceAssetWith (or delete the
//     `if !in.Unmanaged` in applyDeviceFields) → every asset here grows a
//     management row and a credentials row.
//   - restore `ConnectionStatus: "connected"` in recordCloudResource → the
//     reported status assertion below fails.
//   - delete the cloudIntegrationIDKey block in upsertDeviceAssetWith → the
//     provenance assertion fails.
func TestIntegration_CloudDiscovery_NothingDiscoveredIsManaged(t *testing.T) {
	owner := testdb.Connect(t)
	tenantID := testdb.NewTenant(t, owner)
	ctx := context.Background()

	appDB := testdb.ConnectAsAppRole(t, owner)
	integrationID := seedCloudIntegration(t, owner, tenantID)

	svc := NewCloudDiscoveryService(appDB, owner, testMasterKey)
	plan := awsEnumerationPlanForTest(t)

	reported, _, err := svc.recordEnumeration(ctx, tenantID, integrationID, "production", plan)
	if err != nil {
		t.Fatalf("recordEnumeration: %v", err)
	}

	// The status the run REPORTS, which is what the job result and the API
	// response carry now that no asset_management row is written to hold it.
	// "connected" would be a claim about a connection nothing made; the provider
	// API was read.
	if len(reported) != 3 {
		t.Fatalf("recordEnumeration reported %d devices, want 3", len(reported))
	}
	for _, d := range reported {
		if d.ConnectionStatus != "discovered" {
			t.Errorf("%s reports connection_status %q, want \"discovered\" — the cloud API was read, nothing was connected to",
				d.DeviceType, d.ConnectionStatus)
		}
	}

	// A NON-enumeration collector through the same funnel, so the assertion
	// covers the load balancers / gateways / buckets / key stores too and not
	// just the three types cloud_enumeration.go emits.
	albARN := "arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/unmanaged/" + uuid.New().String()[:8]
	alb := models.Device{
		ID:               uuid.New(),
		TenantID:         tenantID,
		DeviceType:       "aws_alb",
		Vendor:           stringPtr("AWS"),
		Hostname:         stringPtr("unmanaged-alb.example.test"),
		DiscoveryMethod:  "cloud_api",
		CredentialID:     &integrationID,
		ConnectionStatus: "discovered",
		Metadata:         models.JSONB{"arn": albARN, "region": "us-east-1"},
	}
	if err := svc.upsertDeviceAsset(ctx, &alb, albARN); err != nil {
		t.Fatalf("upsertDeviceAsset(alb): %v", err)
	}

	subjects := []struct {
		id    uuid.UUID
		label string
	}{
		{assetIDForCloudResource(t, owner, tenantID, plan.Networks[0].ResourceID), "vpc"},
		{assetIDForCloudResource(t, owner, tenantID, plan.Subnets[0].ResourceID), "subnet"},
		{assetIDForCloudResource(t, owner, tenantID, plan.Instances[0].ResourceID), "ec2 instance"},
		{assetIDForCloudResource(t, owner, tenantID, albARN), "load balancer"},
	}

	// --- no management row, and no credentials row either ---------------------
	for _, tc := range subjects {
		if row := managementFor(t, owner, tenantID, tc.id); row.exists {
			t.Errorf("%s has an asset_management row (connection_status=%q); nothing found through a cloud API is a managed device",
				tc.label, row.connectionStatus)
		}
		if hasCredentialsRow(t, owner, tenantID, tc.id) {
			t.Errorf("%s has an asset_credentials row; it is unreachable without management and held only the integration id", tc.label)
		}
	}

	// --- the integration id survives as provenance ---------------------------
	//
	// It used to live in asset_credentials.credential_id, which is the row just
	// asserted absent. Losing the fact would be a silent regression: nothing else
	// records WHICH integration read a resource.
	for _, tc := range subjects {
		var integration sql.NullString
		if err := owner.QueryRow(
			`SELECT metadata->'device_metadata'->>'cloud_integration_id' FROM assets WHERE tenant_id = $1 AND id = $2`,
			tenantID, tc.id).Scan(&integration); err != nil {
			t.Fatalf("%s metadata: %v", tc.label, err)
		}
		if !integration.Valid || integration.String != integrationID.String() {
			t.Errorf("%s cloud_integration_id = %q (valid=%v), want %s", tc.label, integration.String, integration.Valid, integrationID)
		}
	}

	// --- the INVENTORY is untouched ------------------------------------------
	//
	// Suppressing management must not suppress the asset. If this half regresses
	// the cloud inventory simply vanishes, which is a worse bug than the one
	// being fixed.
	for _, tc := range []struct {
		id        uuid.UUID
		wantClass string
		label     string
	}{
		{subjects[0].id, "virtual_network", "vpc"},
		{subjects[1].id, "subnet", "subnet"},
		{subjects[2].id, "compute_instance", "ec2 instance"},
	} {
		var classKey, discoveryMethod string
		if err := owner.QueryRow(`
			SELECT class_key, coalesce(metadata->>'device_discovery_method', '')
			FROM assets WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL`,
			tenantID, tc.id).Scan(&classKey, &discoveryMethod); err != nil {
			t.Fatalf("%s asset row: %v", tc.label, err)
		}
		if classKey != tc.wantClass {
			t.Errorf("%s class_key = %q, want %q", tc.label, classKey, tc.wantClass)
		}
		// The POST-MIGRATIONS cleanup in schema.sql selects on exactly this key,
		// so it is pinned here rather than inferred from reading applyDeviceFields.
		if discoveryMethod != "cloud_api" {
			t.Errorf("%s device_discovery_method = %q, want \"cloud_api\" — the schema.sql cleanup keys on it", tc.label, discoveryMethod)
		}
		var factCount int
		if err := owner.QueryRow(
			`SELECT count(*) FROM asset_facts WHERE tenant_id = $1 AND asset_id = $2`,
			tenantID, tc.id).Scan(&factCount); err != nil {
			t.Fatalf("%s fact count: %v", tc.label, err)
		}
		if factCount == 0 {
			t.Errorf("%s carries no facts; only the management and credentials rows were meant to go", tc.label)
		}
	}

	// Containment survives: vpc→subnet and subnet→instance.
	var edges int
	if err := owner.QueryRow(
		`SELECT count(*) FROM asset_relationships WHERE tenant_id = $1 AND type = 'contains'`,
		tenantID).Scan(&edges); err != nil {
		t.Fatalf("edge count: %v", err)
	}
	if edges != 2 {
		t.Errorf("%d contains edges, want 2 — suppressing management must not suppress containment", edges)
	}
}

// TestIntegration_ManualCloudApplianceKeepsManagement is the other half of the
// rule, and the owner's explicit requirement: "a firewall in the cloud should be
// something that can be added."
//
// Cloud discovery suppresses management. An operator adding the same kind of box
// by hand must not be caught by that — they are stating that this IS an
// API-accessible interface they want inventory pulled from, which is exactly
// what the Devices page is for.
//
// Mutation check: move the suppression from the cloud funnel down into
// applyDeviceFields (`if !in.Unmanaged` → `if false`), or key it on
// `fields.DiscoveryMethod == "cloud_api"` and give the request that method, and
// this fails — CreateDevice's GetDevice read-back cannot even find the device,
// because ListDevices is the inner join on asset_management.
func TestIntegration_ManualCloudApplianceKeepsManagement(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db)
	ctx := context.Background()

	svc := NewDeviceService(db)

	url := "https://cloud-fw.example.test"
	password := "a-real-appliance-secret-the-operator-typed"
	device, err := svc.CreateDevice(ctx, tenant, models.CreateDeviceRequest{
		DeviceType:    "palo_alto", // a firewall, running in the cloud
		Hostname:      stringPtr("cloud-fw.example.test"),
		ManagementURL: &url,
		Username:      stringPtr("admin"),
		Password:      &password,
	})
	if err != nil {
		t.Fatalf("adding a cloud-hosted appliance by hand failed: %v", err)
	}

	// It is ON the Devices page — GetDevice succeeding is that statement, since
	// the query is the inner join on asset_management.
	if _, err := svc.GetDevice(ctx, tenant, device.ID); err != nil {
		t.Fatalf("the appliance is not on the Devices page: %v", err)
	}

	mgmt := managementFor(t, db, tenant, device.ID)
	if !mgmt.exists {
		t.Fatal("a hand-added cloud appliance got no asset_management row; the cloud-path suppression has leaked into CreateDevice")
	}
	if !mgmt.managementURL.Valid || mgmt.managementURL.String != url {
		t.Errorf("management_url = %q (valid=%v), want %q", mgmt.managementURL.String, mgmt.managementURL.Valid, url)
	}

	// And it is interrogable: the credential the operator typed is stored,
	// encrypted.
	var username, encrypted string
	if err := db.QueryRow(
		`SELECT coalesce(username,''), coalesce(password_enc,'') FROM asset_credentials WHERE tenant_id = $1 AND asset_id = $2`,
		tenant, device.ID).Scan(&username, &encrypted); err != nil {
		t.Fatalf("the appliance's credentials were not stored: %v", err)
	}
	if username != "admin" || encrypted == "" || encrypted == password {
		t.Fatalf("credentials stored wrong: username=%q encrypted=%v plaintext=%v", username, encrypted != "", encrypted == password)
	}
}

// TestIntegration_CloudDiscovery_SuppressionSurvivesReplay covers the SECOND way
// a management row can be born.
//
// The contested path does not write management inline — it seals the same
// deviceFieldUpdate into identity_observation_management, and
// ReplayRetainedManagement materializes it later, once the merge is approved. A
// guard that covered only the inline write would be reopened by that replay,
// silently, weeks after the discovery run.
//
// The subject is an EC2 INSTANCE rather than a subnet, so the test would still
// fail if someone narrowed the rule back to network structure.
//
// Mutation check: remove the `if !fields.Unmanaged` condition from
// ReplayRetainedManagement and this fails while the tests above still pass —
// which is exactly the hole it exists to close.
func TestIntegration_CloudDiscovery_SuppressionSurvivesReplay(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenant := testdb.NewTenant(t, db)
	ctx := context.Background()

	integration := seedCloudIntegration(t, db, tenant)
	svc := NewCloudDiscoveryService(db, db, testMasterKey)

	// An already-approved asset with NO management row — the exact state
	// ReplayRetainedManagement selects for. Created through the device path and
	// then stripped, the way the contested tests next door do it.
	target, err := svc.devices.CreateDevice(ctx, tenant, models.CreateDeviceRequest{
		DeviceType: DeviceTypeAWSEC2Instance,
		Hostname:   stringPtr("replay-instance.example.test"),
	})
	if err != nil {
		t.Fatalf("seed target: %v", err)
	}
	if _, err := db.Exec(`DELETE FROM asset_management WHERE tenant_id=$1 AND asset_id=$2`, tenant, target.ID); err != nil {
		t.Fatalf("strip management: %v", err)
	}

	// Admission on and paused makes the next observation retained rather than
	// applied, which is what routes it through retainManagement.
	if _, err := db.Exec(`INSERT INTO tenant_admin_settings(tenant_id,config)
	 VALUES($1,'{"identity_admission":{"mode":"paused"}}')
	 ON CONFLICT(tenant_id) DO UPDATE SET config=EXCLUDED.config`, tenant); err != nil {
		t.Fatalf("set admission mode: %v", err)
	}
	svc.devices.identityEng, err = identity.New(identity.Config{Repo: svc.devices.identityRepo, AdmissionEnabled: true})
	if err != nil {
		t.Fatalf("rebuild identity engine: %v", err)
	}

	plan := awsEnumerationPlanForTest(t)
	instance := plan.Instances[0]
	instance.ParentID = ""
	_, err = svc.recordCloudResource(ctx, tenant, integration, "AWS", instance)
	var retained *identity.RetainedObservation
	if !errors.As(err, &retained) {
		t.Fatalf("instance observation was not retained: %v", err)
	}

	// Approve it: link the observation to the target and put the asset in
	// monitoring, which is what makes replay pick it up.
	if _, err := db.Exec(`UPDATE identity_observations SET state='linked',asset_id=$3 WHERE tenant_id=$1 AND id=$2`,
		tenant, retained.Result.ObservationID, target.ID); err != nil {
		t.Fatalf("link observation: %v", err)
	}
	if _, err := db.Exec(`UPDATE assets SET asset_status='monitoring' WHERE tenant_id=$1 AND id=$2`, tenant, target.ID); err != nil {
		t.Fatalf("approve asset: %v", err)
	}
	// Replay refuses to run at all while admission is paused, so unpause it —
	// otherwise the test proves nothing about the guard and merely observes the
	// replay declining to start.
	if _, err := db.Exec(`UPDATE tenant_admin_settings SET config='{"identity_admission":{"mode":"enforce"}}' WHERE tenant_id=$1`, tenant); err != nil {
		t.Fatalf("resume admission: %v", err)
	}

	if err := svc.devices.ReplayRetainedManagement(ctx, tenant); err != nil {
		t.Fatalf("ReplayRetainedManagement: %v", err)
	}

	if row := managementFor(t, db, tenant, target.ID); row.exists {
		t.Errorf("replay materialized an asset_management row for a cloud-discovered instance (connection_status=%q)", row.connectionStatus)
	}

	// The replay must still CONSUME the retained row. Skipping the management
	// write without marking it materialized would leave it re-selected forever.
	var materialized sql.NullTime
	if err := db.QueryRow(
		`SELECT materialized_at FROM identity_observation_management WHERE tenant_id = $1 AND observation_id = $2`,
		tenant, retained.Result.ObservationID).Scan(&materialized); err != nil {
		t.Fatalf("read retained management: %v", err)
	}
	if !materialized.Valid {
		t.Error("retained management row was left unmaterialized; it will be re-selected on every replay pass")
	}
}
