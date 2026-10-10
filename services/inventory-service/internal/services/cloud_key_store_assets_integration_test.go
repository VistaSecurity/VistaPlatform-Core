package services

// WP6 F13, decision D3 as amended: POST /keys/cloud is the one path a
// cloud KMS key takes into inventory, and it lands BOTH halves — the `keys`
// row (Inventory → Keys) and the key's Key Store asset. The discovery queue
// carries no KMS rows.
//
// These drive the REAL handler (handlers.CloudKeyHandler is wired over the
// same AssetService methods; the route-level wiring is pinned in
// handlers/cloud_key_handler_test.go) through the REAL services against
// Postgres.
//
// Mutations (each run, then restored — see the PR):
//
//	RecordCloudKeyStores returning before IngestFindingsReport
//	    → FiveKeysYieldFiveRowsAndFiveKeyStores (0 key_store assets) and
//	      ApprovalFollowsTheTenantsRules
//	kmsKeyStoreResourceMetadata without the AWS `arn` key
//	    → FiveKeysYieldFiveRowsAndFiveKeyStores and
//	      ApprovalFollowsTheTenantsRules (no AWS Key Store: without the
//	      resource id the collector's listing is not admitted)
//	approval status forced to pending_approval
//	    → ApprovalFollowsTheTenantsRules (the rule-covered key is pending)
//
// Skips without TEST_DATABASE_URL (make test-integration-db).

import (
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func kmsKeyStoreFixture(t *testing.T) (*AssetService, *sql.DB, uuid.UUID) {
	t.Helper()
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	return newCloudRoutingAssetService(db), raw, testdb.NewTenant(t, raw)
}

// kmsFiveKeys is one cloud run's keys across the three providers, in the
// shape device-interrogation's cloudKeyRecordsFrom publishes.
func kmsFiveKeys() []CloudKeyRecord {
	created := time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)
	var out []CloudKeyRecord
	for _, id := range []string{
		"00000000-0000-4000-8000-0000000000a1",
		"00000000-0000-4000-8000-0000000000a2",
		"00000000-0000-4000-8000-0000000000a3",
	} {
		out = append(out, CloudKeyRecord{
			Provider: "aws", KeyID: id, KeyARN: "arn:aws:kms:us-east-1:111122223333:key/" + id,
			KeySpec: "SYMMETRIC_DEFAULT", KeyUsage: "ENCRYPT_DECRYPT", KeyState: "Enabled", KeyManager: "CUSTOMER",
			Origin: "AWS_KMS", Region: "us-east-1", AccountID: "111122223333", CreationDate: &created,
		})
	}
	out = append(out,
		CloudKeyRecord{
			Provider: "gcp", KeyID: "projects/p/locations/global/keyRings/r/cryptoKeys/k",
			KeyARN:  "projects/p/locations/global/keyRings/r/cryptoKeys/k",
			KeySpec: "SYMMETRIC_DEFAULT", KeyUsage: "ENCRYPT_DECRYPT", KeyState: "ENABLED",
			Region: "global", AccountID: "p", CreationDate: &created,
		},
		CloudKeyRecord{
			Provider: "azure", KeyID: "https://v.vault.azure.net/keys/k1",
			KeyARN:  "/subscriptions/s/resourceGroups/g/providers/Microsoft.KeyVault/vaults/v/keys/k1",
			KeySpec: "RSA_2048", KeyUsage: "SIGN_VERIFY", KeyState: "Enabled",
			Region: "eastus", AccountID: "s", CreationDate: &created,
		},
	)
	return out
}

// kmsIngest is the handler's body: the key rows, then their assets.
func kmsIngest(t *testing.T, svc *AssetService, tenant uuid.UUID, records []CloudKeyRecord) {
	t.Helper()
	if _, err := svc.UpsertCloudKeys(tenant, records); err != nil {
		t.Fatalf("UpsertCloudKeys: %v", err)
	}
	if _, err := svc.RecordCloudKeyStores(tenant, records); err != nil {
		t.Fatalf("RecordCloudKeyStores: %v", err)
	}
}

type kmsKeyStoreAsset struct {
	ID     uuid.UUID
	Name   string
	Status string
}

// kmsKeyStoreAssets maps each Key Store asset's cloud resource id to the asset.
func kmsKeyStoreAssets(t *testing.T, raw *sql.DB, tenant uuid.UUID) map[string][]kmsKeyStoreAsset {
	t.Helper()
	rows, err := raw.Query(`
		SELECT a.id, COALESCE(a.hostname, ''), a.asset_status::text, COALESCE(i.value, '')
		  FROM assets a
		  LEFT JOIN asset_identifiers i
		    ON i.asset_id = a.id AND i.tenant_id = a.tenant_id AND i.kind = 'cloud_resource_id'
		 WHERE a.tenant_id = $1 AND a.class_key = 'key_store' AND a.deleted_at IS NULL`, tenant)
	if err != nil {
		t.Fatalf("read key store assets: %v", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string][]kmsKeyStoreAsset{}
	for rows.Next() {
		var a kmsKeyStoreAsset
		var rid string
		if err := rows.Scan(&a.ID, &a.Name, &a.Status, &rid); err != nil {
			t.Fatalf("scan: %v", err)
		}
		out[rid] = append(out[rid], a)
	}
	return out
}

func kmsCount(t *testing.T, raw *sql.DB, q string, args ...any) int {
	t.Helper()
	var n int
	if err := raw.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	return n
}

func TestIntegration_KMSCloudKeys_FiveKeysYieldFiveRowsAndFiveKeyStores(t *testing.T) {
	svc, raw, tenant := kmsKeyStoreFixture(t)
	keys := kmsFiveKeys()

	for run := 1; run <= 2; run++ {
		kmsIngest(t, svc, tenant, keys)

		if n := kmsCount(t, raw, `SELECT count(*) FROM keys WHERE tenant_id=$1`, tenant); n != 5 {
			t.Fatalf("run %d: %d key rows, want 5", run, n)
		}
		stores := kmsKeyStoreAssets(t, raw, tenant)
		total := 0
		for _, as := range stores {
			total += len(as)
		}
		if total != 5 {
			t.Fatalf("run %d: %d Key Store assets %v, want 5 — one per key, and a second run must MATCH them", run, total, stores)
		}
		for _, k := range keys {
			as := stores[k.KeyARN]
			if len(as) != 1 {
				t.Errorf("run %d: key %s has %d Key Store assets keyed on its resource id, want 1", run, k.KeyARN, len(as))
				continue
			}
			if want := kmsKeyStoreName(k); as[0].Name != want {
				t.Errorf("run %d: key %s asset named %q, want the collector's %q", run, k.KeyARN, as[0].Name, want)
			}
			if eps := kmsCount(t, raw, `SELECT count(*) FROM asset_endpoints WHERE tenant_id=$1 AND asset_id=$2`, tenant, as[0].ID); eps != 0 {
				t.Errorf("run %d: key store %s has %d endpoints, want 0 — a key has no socket", run, k.KeyARN, eps)
			}
		}
		if n := kmsCount(t, raw, `SELECT count(*) FROM sensor_discoveries WHERE tenant_id=$1`, tenant); n != 0 {
			t.Errorf("run %d: %d sensor_discoveries rows, want 0 — the queue carries no KMS rows", run, n)
		}
	}

	// The AWS key lands in its region's cloud segment, as the queue put it.
	var seg sql.NullString
	if err := raw.QueryRow(`
		SELECT s.value FROM assets a JOIN network_segments s ON s.id = a.network_segment_id
		 WHERE a.tenant_id=$1 AND a.class_key='key_store' AND a.hostname=$2`, tenant, keys[0].KeyID).Scan(&seg); err != nil {
		t.Fatalf("read the AWS key store's segment: %v", err)
	}
	if seg.String == "" {
		t.Errorf("the AWS key store has no cloud segment")
	}
}

// An asset the discovery queue created before this change is the SAME asset:
// the key ingest resolves to it rather than minting a second Key Store.
func TestIntegration_KMSCloudKeys_MatchesAKeyStoreTheQueueCreated(t *testing.T) {
	svc, raw, tenant := kmsKeyStoreFixture(t)
	key := kmsFiveKeys()[0]

	sensor, err := svc.kmsPlatformCollectorSensor(tenant)
	if err != nil {
		t.Fatal(err)
	}
	// The finding discovery-processor used to hand IngestFindings for this key
	// (TestIntegration_KMSKeyFinding_IsAKeyStoreNotAnApplication's shape, under
	// the platform collector's sensor), in its own words — not built by the
	// code under test.
	name := key.KeyID
	addr, port, sid := "0.0.0.0", 0, sensor.String()
	old := IngestFinding{
		Hostname: &name, IPAddress: &addr, Port: &port, AssetType: "service", SourceSensorID: &sid,
		RawData: map[string]interface{}{
			"source": "cloud_discovery", "discovery_method": "cloud_api", "sensor_id": sid,
			"cloud_provider": "aws", "cloud_region": "us-east-1", "device_type": "aws_kms",
			"at_rest": true, "arn": key.KeyARN, "key_id": key.KeyID, "region": "us-east-1",
		},
	}
	if _, err := svc.IngestFindings(tenant, []IngestFinding{old}, "monitoring"); err != nil {
		t.Fatalf("old-path IngestFindings: %v", err)
	}
	before := kmsKeyStoreAssets(t, raw, tenant)[key.KeyARN]
	if len(before) != 1 {
		t.Fatalf("the old path created %d Key Store assets, want 1", len(before))
	}

	kmsIngest(t, svc, tenant, []CloudKeyRecord{key})

	after := kmsKeyStoreAssets(t, raw, tenant)
	if len(after[key.KeyARN]) != 1 || after[key.KeyARN][0].ID != before[0].ID {
		t.Fatalf("after the key ingest: %v, want the queue's asset %s and no other", after, before[0].ID)
	}
	if after[key.KeyARN][0].Status != "monitoring" {
		t.Errorf("the matched asset is %s, want it left monitoring", after[key.KeyARN][0].Status)
	}
	if n := kmsCount(t, raw, `SELECT count(*) FROM assets WHERE tenant_id=$1 AND class_key='key_store' AND deleted_at IS NULL`, tenant); n != 1 {
		t.Errorf("%d Key Store assets, want 1", n)
	}
}

// Approval is the tenant's rules over the same projection the processor
// evaluated: a rule on the AWS region's cloud segment approves the AWS key;
// keys with no region (Azure, GCP) had no segment then and have none now, so
// they wait in Approvals.
func TestIntegration_KMSCloudKeys_ApprovalFollowsTheTenantsRules(t *testing.T) {
	svc, raw, tenant := kmsKeyStoreFixture(t)
	keys := kmsFiveKeys()

	seg, err := svc.networkSegmentService.FindOrCreateCloudSegment(tenant, "aws", "us-east-1", "", "production")
	if err != nil {
		t.Fatalf("cloud segment: %v", err)
	}
	if _, err := raw.Exec(`INSERT INTO discovery_auto_approval_rules (tenant_id, name, query, is_active)
		VALUES ($1, 'aws us-east-1', $2, true)`,
		tenant, segmentApprovalQuery([]string{models.AutoApproveSourceCloud}, seg.NetworkType, seg.ID.String())); err != nil {
		t.Fatalf("insert rule: %v", err)
	}

	kmsIngest(t, svc, tenant, []CloudKeyRecord{keys[0], keys[3], keys[4]})

	stores := kmsKeyStoreAssets(t, raw, tenant)
	for arn, want := range map[string]string{
		keys[0].KeyARN: "monitoring",
		keys[3].KeyARN: "pending_approval",
		keys[4].KeyARN: "pending_approval",
	} {
		if len(stores[arn]) != 1 || stores[arn][0].Status != want {
			t.Errorf("%s: %v, want one asset %s", arn, stores[arn], want)
		}
	}
}
