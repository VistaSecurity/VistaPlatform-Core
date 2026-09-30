package services

// Cloud at-rest resources under ENFORCE identity admission (integrations
// review W6).
//
// What went wrong. Object storage, managed databases and key stores reach
// inventory ONLY as findings: their collectors write sensor_discoveries rows and
// never record the resource through the identification engine themselves (the
// load balancers, distributions and enumerated compute do, and were fine). A
// finding carrying a bucket name and its ARN has no device or address binding,
// and nothing marked it authoritative, so a tenant in enforce mode parked every
// one of them in Discovery → Observations as
// `unresolved / no_device_or_address_binding` with no asset. In the default
// (disabled) mode the engine never asks the admission question, which is why
// TestIntegration_CloudFindingOnMonitoringAsset_ReportsMonitoring stayed green
// over the gap.
//
// The fix admits a cloud-API finding as authoritative, keyed on the provider's
// resource id, when — and only when — the row was written under the tenant's
// platform-managed device-interrogation sensor (cloudCollectorAuthoritative).
//
// Mutations that prove these tests (both run; see the PR):
//
//	delete `obs.Admission.Authoritative = cloudAuthoritative` (the pre-fix code)
//	    → BecomesAssetOnce (all three), ParkedObservation, and both enforce legs
//	      of TestIntegration_CloudFindingOnMonitoringAsset_ReportsMonitoring go red
//	cloudCollectorAuthoritative returns true instead of the platform-sensor
//	answer (any sensor's cloud-shaped row counts)
//	    → OnlyThePlatformCollectorIsAuthoritative goes red (tenant-sensor leg)
//	AssessAdmission accepts a bare hostname/FQDN
//	    → OnlyThePlatformCollectorIsAuthoritative goes red (all three legs)
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// enforceIdentityAdmission puts the tenant in the admission mode the gap was
// found in.
func enforceIdentityAdmission(t *testing.T, raw *sql.DB, tenant uuid.UUID) {
	t.Helper()
	if _, err := raw.Exec(`INSERT INTO tenant_admin_settings(tenant_id,config)
		VALUES($1,'{"identity_admission":{"mode":"enforce"}}')
		ON CONFLICT(tenant_id) DO UPDATE SET config=EXCLUDED.config`, tenant); err != nil {
		t.Fatalf("enable enforce admission: %v", err)
	}
	// Enforce mode checks the tenant's asset allowance on every create; a bare
	// test tenant has none, which would park everything as
	// `asset_allowance_exhausted` and make every assertion here about billing.
	if _, err := raw.Exec(`INSERT INTO tenant_entitlements(tenant_id,item_id,override_value,reason)
		SELECT $1,id,'{"quantity":10}'::jsonb,'cloud enforce admission regression' FROM billable_items WHERE key='max_assets'`, tenant); err != nil {
		t.Fatalf("grant asset allowance: %v", err)
	}
}

// platformInterrogationSensor is the sensor the cloud collector writes its
// sensor_discoveries rows under — created for every tenant by the
// create_system_sensors_on_tenant_create trigger.
func platformInterrogationSensor(t *testing.T, raw *sql.DB, tenant uuid.UUID) string {
	t.Helper()
	var id string
	if err := raw.QueryRow(`SELECT id::text FROM sensors WHERE tenant_id=$1 AND profile='device_interrogation'
		AND platform_managed AND deleted_at IS NULL ORDER BY created_at, id LIMIT 1`, tenant).Scan(&id); err != nil {
		t.Fatalf("the tenant has no platform device-interrogation sensor: %v", err)
	}
	return id
}

// tenantSensor registers an ordinary tenant sensor. It deliberately claims the
// device_interrogation profile and the platform's name — a tenant can set both —
// so the only thing distinguishing it from the collector is platform_managed.
func tenantSensor(t *testing.T, raw *sql.DB, tenant uuid.UUID) string {
	t.Helper()
	id := uuid.New()
	if _, err := raw.Exec(`INSERT INTO sensors(id,tenant_id,name,platform,version,profile,status,tags)
		VALUES($1,$2,'Platform Device Interrogation Agent','linux','1.0','device_interrogation','active',ARRAY[]::text[])`,
		id, tenant); err != nil {
		t.Fatalf("register tenant sensor: %v", err)
	}
	return id.String()
}

// fromSensor stamps what discovery-processor stamps on every finding it
// converts: the sensor the row was written under, the row's id (the receipt)
// and when it was seen. Enforce mode refuses an observation without a time.
func fromSensor(f IngestFinding, sensorID string, seen time.Time) IngestFinding {
	raw := make(map[string]interface{}, len(f.RawData)+3)
	for k, v := range f.RawData {
		raw[k] = v
	}
	raw["discovery_id"] = uuid.NewString()
	raw["observed_at"] = seen.UTC().Format(time.RFC3339Nano)
	f.RawData = raw
	if sensorID != "" {
		s := sensorID
		f.SourceSensorID = &s
	} else {
		f.SourceSensorID = nil
	}
	return f
}

// cloudRDSFinding is the RDS at-rest shape writeSensorDiscoveriesTx emits: the
// instance identifier as hostname (it does not resolve, so the placeholder
// address), no port, no protocol, and the ARN.
func cloudRDSFinding(instance, integrationID string) IngestFinding {
	host, ip, port := instance, "0.0.0.0", 0
	return IngestFinding{
		Hostname:  &host,
		IPAddress: &ip,
		Port:      &port,
		AssetType: "server",
		RawData: map[string]interface{}{
			"source":           "cloud_discovery",
			"discovery_method": "cloud_api",
			"integration_id":   integrationID,
			"cloud_provider":   "aws",
			"cloud_region":     "us-east-1",
			"device_type":      "aws_rds_instance",
			"resource_type":    "rds_instance",
			"arn":              "arn:aws:rds:us-east-1:123456789012:db:" + instance,
			"at_rest":          true,
			"encrypted":        true,
			"encryption_type":  "aws-kms",
			"algorithm":        "AES-256",
		},
	}
}

// cloudKeyStoreFinding is the KMS shape: the key's alias as hostname and the key
// ARN, no address at all.
func cloudKeyStoreFinding(alias, keyID, integrationID string) IngestFinding {
	host := alias
	return IngestFinding{
		Hostname:  &host,
		AssetType: "service",
		RawData: map[string]interface{}{
			"source":           "cloud_discovery",
			"discovery_method": "cloud_api",
			"integration_id":   integrationID,
			"cloud_provider":   "aws",
			"cloud_region":     "us-east-1",
			"device_type":      "aws_kms",
			"at_rest":          true,
			"arn":              "arn:aws:kms:us-east-1:123456789012:key/" + keyID,
		},
	}
}

// assetsOwningResourceID lists the live assets carrying a cloud_resource_id.
func assetsOwningResourceID(t *testing.T, raw *sql.DB, tenant uuid.UUID, rid string) []uuid.UUID {
	t.Helper()
	rows, err := raw.Query(`SELECT DISTINCT a.id FROM asset_identifiers i JOIN assets a ON a.tenant_id=i.tenant_id AND a.id=i.asset_id
		WHERE i.tenant_id=$1 AND i.kind='cloud_resource_id' AND i.value=$2 AND a.deleted_at IS NULL`, tenant, rid)
	if err != nil {
		t.Fatalf("read resource-id owners: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var out []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		out = append(out, id)
	}
	return out
}

type storedObservation struct {
	State   string
	AssetID *uuid.UUID
	Reasons []string
}

// observationsFor returns every identity_observations row whose evidence names
// the value — the sighting as the Observations page shows it.
func observationsFor(t *testing.T, raw *sql.DB, tenant uuid.UUID, value string) []storedObservation {
	t.Helper()
	rows, err := raw.Query(`SELECT state, asset_id, admission_reasons FROM identity_observations
		WHERE tenant_id=$1 AND evidence::text LIKE '%' || $2 || '%' ORDER BY first_seen_at`, tenant, value)
	if err != nil {
		t.Fatalf("read observations: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var out []storedObservation
	for rows.Next() {
		var o storedObservation
		var reasons pq.StringArray
		if err := rows.Scan(&o.State, &o.AssetID, &reasons); err != nil {
			t.Fatal(err)
		}
		o.Reasons = []string(reasons)
		out = append(out, o)
	}
	return out
}

func TestIntegration_CloudAtRestFinding_EnforceAdmission_BecomesAssetOnce(t *testing.T) {
	integrationID := uuid.NewString()
	cases := []struct {
		name    string
		finding IngestFinding
		class   string
	}{
		{"S3 bucket", cloudBucketFinding("enforce-bucket-123456789012", integrationID), "object_storage"},
		{"RDS instance", cloudRDSFinding("enforce-orders-db", integrationID), "managed_database"},
		{"KMS key", cloudKeyStoreFinding("alias/enforce-app", "00000000-0000-4000-8000-00000000e001", integrationID), "key_store"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := testdb.Connect(t)
			testdb.ApplySchemaAndSeed(t, raw)
			db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
			tenant := testdb.NewTenant(t, raw)
			enforceIdentityAdmission(t, raw, tenant)
			svc := newCloudRoutingAssetService(db)
			collector := platformInterrogationSensor(t, raw, tenant)
			rid := identity.CloudResourceIDFromMetadata(tc.finding.RawData)
			first := time.Now().UTC().Add(-time.Hour)

			report, err := svc.IngestFindingsReport(tenant, []IngestFinding{fromSensor(tc.finding, collector, first)}, identity.StatusPendingApproval)
			if err != nil {
				t.Fatalf("first ingest: %v", err)
			}
			owners := assetsOwningResourceID(t, raw, tenant, rid)
			if len(owners) != 1 {
				t.Fatalf("%d assets own %s after the first run, want 1 — a cloud API listing a resource is the "+
					"authoritative source for it, and enforce mode parked it instead (observations: %+v)",
					len(owners), rid, observationsFor(t, raw, tenant, rid))
			}
			asset := owners[0]
			if len(report.Results) != 1 || report.Results[0].AssetID != asset.String() {
				t.Fatalf("report results = %+v, want one naming asset %s", report.Results, asset)
			}

			var class, identityStatus string
			if err := raw.QueryRow(`SELECT class_key, identity_status FROM assets WHERE tenant_id=$1 AND id=$2`,
				tenant, asset).Scan(&class, &identityStatus); err != nil {
				t.Fatalf("read asset: %v", err)
			}
			if class != tc.class {
				t.Errorf("class = %q, want %q", class, tc.class)
			}
			if identityStatus != string(identity.IdentityEstablished) {
				t.Errorf("identity_status = %q, want %q — the admission is what established it", identityStatus, identity.IdentityEstablished)
			}

			obs := observationsFor(t, raw, tenant, rid)
			if len(obs) != 1 || obs[0].State != "linked" || obs[0].AssetID == nil || *obs[0].AssetID != asset {
				t.Fatalf("observations = %+v, want one `linked` to %s", obs, asset)
			}

			// The next run of the same discovery: a new receipt, a later time,
			// the same resource. It must MATCH on the resource id.
			second, err := svc.IngestFindingsReport(tenant, []IngestFinding{fromSensor(tc.finding, collector, first.Add(30*time.Minute))}, identity.StatusPendingApproval)
			if err != nil {
				t.Fatalf("second ingest: %v", err)
			}
			if len(second.Results) != 1 || second.Results[0].AssetID != asset.String() || second.Results[0].Outcome != string(identity.OutcomeMatched) {
				t.Fatalf("second run results = %+v, want one `matched` to %s", second.Results, asset)
			}
			if owners := assetsOwningResourceID(t, raw, tenant, rid); len(owners) != 1 {
				t.Fatalf("%d assets own %s after the second run, want 1 — rediscovery made a duplicate", len(owners), rid)
			}
			var live int
			if err := raw.QueryRow(`SELECT count(*) FROM assets WHERE tenant_id=$1 AND deleted_at IS NULL`, tenant).Scan(&live); err != nil {
				t.Fatal(err)
			}
			if live != 1 {
				t.Fatalf("%d live assets, want 1", live)
			}
		})
	}
}

// The other direction: the admission is decided by who WROTE the row and by
// the provider's resource id, never by a name. Every one of these must be
// parked exactly as before.
func TestIntegration_CloudShapedFinding_EnforceAdmission_OnlyThePlatformCollectorIsAuthoritative(t *testing.T) {
	cases := []struct {
		name    string
		value   string // what the observation's evidence names
		finding func(t *testing.T, raw *sql.DB, tenant uuid.UUID) IngestFinding
	}{
		{
			// A tenant sensor passively saw a name and nothing else. The domain
			// segment keeps it on the managed-asset path (a name with no address
			// is otherwise routed to external_connections and never reaches
			// admission at all), so this is the engine's own answer.
			name:  "name-only passive sensor observation",
			value: "shadow-store.corp.example.test",
			finding: func(t *testing.T, raw *sql.DB, tenant uuid.UUID) IngestFinding {
				if _, err := raw.Exec(`INSERT INTO network_segments(id,tenant_id,name,segment_type,value,environment)
					VALUES($1,$2,'Corp names','domain','corp.example.test','production')`, uuid.New(), tenant); err != nil {
					t.Fatalf("register domain segment: %v", err)
				}
				host := "shadow-store.corp.example.test"
				return fromSensor(IngestFinding{
					Hostname:  &host,
					AssetType: "server",
					RawData:   map[string]interface{}{"source": "sensor_discovery"},
				}, tenantSensor(t, raw, tenant), time.Now())
			},
		},
		{
			// The metadata envelope is sensor-controlled: a tenant sensor can
			// write discovery_method=cloud_api and an ARN into it. That is a
			// claim, not a cloud API's answer.
			name:  "cloud-shaped row from a tenant sensor",
			value: "arn:aws:s3:::forged-bucket-123456789012",
			finding: func(t *testing.T, raw *sql.DB, tenant uuid.UUID) IngestFinding {
				return fromSensor(cloudBucketFinding("forged-bucket-123456789012", uuid.NewString()), tenantSensor(t, raw, tenant), time.Now())
			},
		},
		{
			// The collector's own row, but with no provider resource id: only a
			// name is left, and a name does not establish an asset whoever
			// reports it. The admission is keyed on the resource id.
			name:  "platform collector row without a resource id",
			value: "unkeyed-bucket-123456789012",
			finding: func(t *testing.T, raw *sql.DB, tenant uuid.UUID) IngestFinding {
				f := cloudBucketFinding("unkeyed-bucket-123456789012", uuid.NewString())
				delete(f.RawData, "arn")
				return fromSensor(f, platformInterrogationSensor(t, raw, tenant), time.Now())
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := testdb.Connect(t)
			testdb.ApplySchemaAndSeed(t, raw)
			db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
			tenant := testdb.NewTenant(t, raw)
			enforceIdentityAdmission(t, raw, tenant)
			svc := newCloudRoutingAssetService(db)

			report, err := svc.IngestFindingsReport(tenant, []IngestFinding{tc.finding(t, raw, tenant)}, identity.StatusPendingApproval)
			if err != nil {
				t.Fatalf("ingest: %v", err)
			}
			var live int
			if err := raw.QueryRow(`SELECT count(*) FROM assets WHERE tenant_id=$1 AND deleted_at IS NULL`, tenant).Scan(&live); err != nil {
				t.Fatal(err)
			}
			if live != 0 {
				t.Fatalf("%d assets created, want 0 — only the platform collector's listing keyed on a provider "+
					"resource id may establish an asset here (results %+v)",
					live, report.Results)
			}
			obs := observationsFor(t, raw, tenant, tc.value)
			if len(obs) != 1 {
				t.Fatalf("%d observations name %q, want 1 — the evidence must reach admission and be retained", len(obs), tc.value)
			}
			if obs[0].State != "unresolved" || obs[0].AssetID != nil {
				t.Fatalf("observation = %+v, want `unresolved` with no asset", obs[0])
			}
			if !strings.Contains(strings.Join(obs[0].Reasons, ","), "no_device_or_address_binding") {
				t.Errorf("admission reasons = %v, want no_device_or_address_binding", obs[0].Reasons)
			}
		})
	}
}

// What happens to sightings enforce mode parked BEFORE this fix: the next run
// of the discovery produces the same observation (a cloud finding's fingerprint
// does not include the sensor), so it lands on the SAME evidence row, which the
// now-established resolution links. The parked run's retained payload is then
// materialized by the identity-evidence sweep once the asset is approved. No
// data migration is needed.
func TestIntegration_CloudAtRestFinding_ParkedObservationMaterializesOnRediscovery(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	enforceIdentityAdmission(t, raw, tenant)
	svc := newCloudRoutingAssetService(db)

	bucket := cloudBucketFinding("parked-bucket-123456789012", uuid.NewString())
	rid := identity.CloudResourceIDFromMetadata(bucket.RawData)
	earlier := time.Now().UTC().Add(-2 * time.Hour)

	// The pre-fix sighting: identical evidence that was not admitted. Written
	// here without the collector's sensor, which is exactly the observation the
	// old code built for the real row.
	if _, err := svc.IngestFindingsReport(tenant, []IngestFinding{fromSensor(bucket, "", earlier)}, identity.StatusPendingApproval); err != nil {
		t.Fatalf("parked ingest: %v", err)
	}
	parked := observationsFor(t, raw, tenant, rid)
	if len(parked) != 1 || parked[0].State != "unresolved" || parked[0].AssetID != nil {
		t.Fatalf("fixture: observations = %+v, want one parked `unresolved` row", parked)
	}
	if owners := assetsOwningResourceID(t, raw, tenant, rid); len(owners) != 0 {
		t.Fatalf("fixture: %d assets already own %s — the parked state was not reproduced", len(owners), rid)
	}

	// The next discovery run, after the fix.
	if _, err := svc.IngestFindingsReport(tenant, []IngestFinding{fromSensor(bucket, platformInterrogationSensor(t, raw, tenant), earlier.Add(time.Hour))}, identity.StatusPendingApproval); err != nil {
		t.Fatalf("rediscovery ingest: %v", err)
	}
	owners := assetsOwningResourceID(t, raw, tenant, rid)
	if len(owners) != 1 {
		t.Fatalf("%d assets own %s after rediscovery, want 1", len(owners), rid)
	}
	asset := owners[0]
	after := observationsFor(t, raw, tenant, rid)
	if len(after) != 1 || after[0].State != "linked" || after[0].AssetID == nil || *after[0].AssetID != asset {
		t.Fatalf("observations after rediscovery = %+v, want the SAME single row, now `linked` to %s", after, asset)
	}

	// Both runs' payloads are retained on that row; approval lets the sweep
	// materialize them.
	if err := svc.ApproveAssets(tenant, []uuid.UUID{asset}, uuid.New()); err != nil {
		t.Fatalf("approve: %v", err)
	}
	if _, err := svc.SweepIdentityEvidence(t.Context(), tenant); err != nil {
		t.Fatalf("sweep: %v", err)
	}
	var pending, done int
	if err := raw.QueryRow(`SELECT count(*) FILTER (WHERE materialized_at IS NULL), count(*) FILTER (WHERE materialized_at IS NOT NULL)
		FROM identity_observation_payloads WHERE tenant_id=$1`, tenant).Scan(&pending, &done); err != nil {
		t.Fatal(err)
	}
	if pending != 0 || done != 2 {
		t.Fatalf("retained payloads: %d pending, %d materialized — want 0 and 2 (the parked run's and the rediscovery's)", pending, done)
	}
}
