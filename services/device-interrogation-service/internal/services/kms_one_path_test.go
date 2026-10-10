package services

// F13 / decision D3: a cloud KMS key takes ONE path into inventory — the
// key inventory, over POST /keys/cloud, which also creates the key's Key Store
// asset (inventory-service's RecordCloudKeyStores, tested there).
//
// It used to take three: that publish, a `kms_keys` row nobody user-facing
// reads, and an at-rest sensor_discoveries row that sent every key round the
// whole discovery queue to reach its endpoint-less `key_store` asset. These tests drive the real collector tail (landKMSKeys) and the real
// writer (WriteSensorDiscoveries); only the provider listing and the
// inventory-service peer are faked.
//
// Mutations (each run, then restored — see the PR):
//
//	becomesDiscoveryRow without `&& !keyInventoryDeviceTypes[...]`
//	    → TestBecomesDiscoveryRow and
//	      TestIntegration_CloudKMSKeysTakeOnePathIntoInventory (key rows appear
//	      in sensor_discoveries)
//	landKMSKeys without the PublishKMSKeyFindings call
//	    → TestIntegration_CloudKMSKeysTakeOnePathIntoInventory (0 keys published)

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/device-interrogation-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// Both polarities of the predicate the writer uses. The key stores are out;
// the at-rest resources that ARE assets (buckets, databases) and the endpoints
// stay in; enumerated compute stays out as before.
func TestBecomesDiscoveryRow(t *testing.T) {
	for _, dt := range []string{"aws_kms", "azure_keyvault_key", "gcp_kms_crypto_key"} {
		if becomesDiscoveryRow(dt) {
			t.Errorf("%s becomes a sensor_discoveries row: a cloud key's one path is the key inventory (#2374 D3)", dt)
		}
	}
	for _, dt := range []string{
		"aws_s3_bucket", "aws_rds_instance", "azure_storage_account", "azure_sql_database",
		"gcp_storage_bucket", "gcp_cloudsql_instance",
		"aws_alb", "aws_cloudfront", "aws_api_gateway", "azure_application_gateway", "gcp_https_load_balancer",
	} {
		if !becomesDiscoveryRow(dt) {
			t.Errorf("%s no longer becomes a discovery row — it is an asset whose crypto posture only the queue materializes", dt)
		}
	}
	for dt := range inventoryOnlyDeviceTypes {
		if becomesDiscoveryRow(dt) {
			t.Errorf("enumerated %s becomes a discovery row", dt)
		}
	}
}

func TestKMSKeyDevicesKeepEachProvidersShape(t *testing.T) {
	tenant := uuid.New()
	f := awsManagedFinding()
	for provider, want := range map[string]string{"aws": "aws_kms", "azure": "azure_keyvault_key", "gcp": "gcp_kms_crypto_key"} {
		devices := kmsKeyDevices(tenant, provider, []KMSKeyFinding{f, f})
		if len(devices) != 2 {
			t.Fatalf("%s: %d devices for 2 keys", provider, len(devices))
		}
		for _, d := range devices {
			if d.DeviceType != want || d.TenantID != tenant || d.DiscoveryMethod != "cloud_api" {
				t.Errorf("%s: device %+v", provider, d)
			}
			if !keyInventoryDeviceTypes[d.DeviceType] {
				t.Errorf("%s: %s is not in keyInventoryDeviceTypes, so the writer would queue it", provider, d.DeviceType)
			}
		}
	}
	if devices := kmsKeyDevices(tenant, "oracle", []KMSKeyFinding{f}); len(devices) != 0 {
		t.Errorf("unknown provider produced %d devices", len(devices))
	}
}

// A collector with no key-inventory client fails the collection rather than
// dropping the keys silently.
func TestPublishKMSKeyFindingsWithoutAPublisherIsAnError(t *testing.T) {
	svc := &KMSDiscoveryService{}
	if err := svc.PublishKMSKeyFindings(context.Background(), uuid.New(), uuid.New(), "aws", []KMSKeyFinding{awsManagedFinding()}); err == nil {
		t.Fatal("keys with nowhere to go returned nil")
	}
	if err := svc.PublishKMSKeyFindings(context.Background(), uuid.New(), uuid.New(), "aws", nil); err != nil {
		t.Fatalf("no keys is not a failure: %v", err)
	}
}

// keyInventoryRecorder is inventory-service's cloud-key intake, counting keys.
type keyInventoryRecorder struct {
	mu   sync.Mutex
	keys []CloudKeyRecord
}

func (r *keyInventoryRecorder) server(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != cloudKeyIngestPath {
			http.NotFound(w, req)
			return
		}
		raw, _ := io.ReadAll(req.Body)
		var body cloudKeyIngestRequest
		if err := json.Unmarshal(raw, &body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		r.mu.Lock()
		r.keys = append(r.keys, body.Keys...)
		r.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(cloudKeyIngestResponse{Written: len(body.Keys)})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestIntegration_CloudKMSKeysTakeOnePathIntoInventory(t *testing.T) {
	owner := testdb.Connect(t)
	tenant := testdb.NewTenant(t, owner)
	appDB := testdb.ConnectAsAppRole(t, owner)
	ctx := context.Background()
	integration := seedCloudIntegration(t, owner, tenant)

	inventory := &keyInventoryRecorder{}
	srv := inventory.server(t)
	cloud := NewCloudDiscoveryService(appDB, owner, testMasterKey)
	kms := NewKMSDiscoveryService(appDB, owner, testMasterKey)
	kms.SetCloudKeyPublisher(NewInventoryCloudKeyPublisher(srv.URL, nil))

	// N keys across the three providers, in each collector's finding shape.
	awsKeys := make([]KMSKeyFinding, 3)
	for i := range awsKeys {
		id := uuid.NewString()
		awsKeys[i] = awsManagedFinding()
		awsKeys[i].KeyID = id
		awsKeys[i].KeyARN = "arn:aws:kms:us-east-1:111122223333:key/" + id
		awsKeys[i].AliasNames = nil
	}
	gcpKey := KMSKeyFinding{
		KeyID: "projects/p/locations/global/keyRings/r/cryptoKeys/k", KeyARN: "projects/p/locations/global/keyRings/r/cryptoKeys/k",
		KeyState: "ENABLED", KeyUsage: "ENCRYPT_DECRYPT", KeySpec: "SYMMETRIC_DEFAULT", Region: "global", AccountID: "p",
		CreationDate: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
	}
	azureKey := KMSKeyFinding{
		KeyID: "https://v.vault.azure.net/keys/k1", KeyARN: "/subscriptions/s/resourceGroups/g/providers/Microsoft.KeyVault/vaults/v/keys/k1",
		KeyState: "Enabled", KeyUsage: "SIGN_VERIFY", KeySpec: "RSA_2048", Region: "eastus", AccountID: "s",
		CreationDate: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
	}

	var devices []models.Device
	for _, run := range []struct {
		provider string
		findings []KMSKeyFinding
	}{{"aws", awsKeys}, {"gcp", []KMSKeyFinding{gcpKey}}, {"azure", []KMSKeyFinding{azureKey}}} {
		found, err := cloud.landKMSKeys(ctx, kms, tenant, integration, run.provider, run.findings)
		if err != nil {
			t.Fatalf("%s: landKMSKeys: %v", run.provider, err)
		}
		if len(found) != len(run.findings) {
			t.Fatalf("%s: %d devices for %d keys — the job result must still count the keys", run.provider, len(found), len(run.findings))
		}
		devices = append(devices, found...)
	}
	const n = 5

	// Path one, the only one: N keys reached the key inventory.
	inventory.mu.Lock()
	published := len(inventory.keys)
	inventory.mu.Unlock()
	if published != n {
		t.Fatalf("key inventory received %d keys, want %d", published, n)
	}

	// The same run's genuine at-rest asset still reaches the queue beside them.
	bucket := s3Bucket("example-audit-logs")
	batch := uuid.NewString()
	inserted, err := cloud.WriteSensorDiscoveries(ctx, tenant, batch, integration, "aws", append(devices, bucket))
	if err != nil {
		t.Fatalf("WriteSensorDiscoveries: %v", err)
	}

	rows := cloudRowsInBatch(t, owner, tenant, batch)
	var keyRows []string
	for name, r := range rows {
		if dt, _ := r.Meta["device_type"].(string); keyInventoryDeviceTypes[dt] || strings.Contains(dt, "kms") || strings.Contains(dt, "keyvault") {
			keyRows = append(keyRows, name+" ("+dt+")")
		}
	}
	if len(keyRows) != 0 {
		t.Errorf("%d KMS key(s) were written to sensor_discoveries: %v — a cloud key's one path is the key inventory (#2374 D3)", len(keyRows), keyRows)
	}
	if _, ok := rows["example-audit-logs"]; !ok || inserted != 1 || len(rows) != 1 {
		t.Errorf("inserted %d row(s) %v, want exactly the bucket: an at-rest resource that IS an asset keeps its discovery row", inserted, rows)
	}

	// Path two is gone too.
	var kmsRows int
	if err := owner.QueryRow(`SELECT count(*) FROM kms_keys WHERE tenant_id = $1`, tenant).Scan(&kmsRows); err != nil {
		t.Fatalf("count kms_keys: %v", err)
	}
	if kmsRows != 0 {
		t.Errorf("kms_keys has %d rows, want 0", kmsRows)
	}
}
