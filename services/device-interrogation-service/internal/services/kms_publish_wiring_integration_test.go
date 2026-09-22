package services

// WIRING proof: storing KMS findings must also PUBLISH them to the key
// inventory, over the real HTTP client, with the real signed request.
//
// This is deliberately not a test of PublishCloudKeys in isolation. The repo
// has been burned twice by a correct helper whose CALL SITE was the hole (
//), and this is the same shape: `kms_keys` gets written either way, so a
// missing publish looks exactly like a successful discovery and the key is
// simply never seen. Delete the s.publishToKeyInventory(...) line in
// StoreKMSKeyFindings and TestIntegration_StoreKMSKeyFindings_PublishesToKeyInventory
// fails — no request arrives.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/serviceauth"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// newKMSPublishFixture returns a KMS discovery service wired to a real Postgres
// (so the kms_keys write is genuine) plus the tenant and integration ids.
func newKMSPublishFixture(t *testing.T) (*KMSDiscoveryService, uuid.UUID, uuid.UUID) {
	t.Helper()
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	tenant := testdb.NewTenant(t, raw)

	integration := uuid.New()
	if _, err := raw.Exec(`
		INSERT INTO platform_integrations (id, integration_type, integration_name, provider, tenant_id)
		VALUES ($1, 'aws', 'kms-publish-test', 'cloud', $2)`, integration, tenant); err != nil {
		t.Fatalf("insert integration: %v", err)
	}

	// The constructor's env-derived publisher is replaced below; masterKey is
	// unused on this path (no credential decryption — the findings are given).
	svc := NewKMSDiscoveryService(raw, raw, "")
	return svc, tenant, integration
}

func awsManagedFinding() KMSKeyFinding {
	return KMSKeyFinding{
		KeyID:        "11111111-2222-3333-4444-555555555555",
		KeyARN:       "arn:aws:kms:us-east-1:111122223333:key/11111111-2222-3333-4444-555555555555",
		KeyState:     "Enabled",
		KeyUsage:     "ENCRYPT_DECRYPT",
		KeySpec:      "SYMMETRIC_DEFAULT",
		KeyManager:   "AWS",
		Origin:       "AWS_KMS",
		CreationDate: time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC),
		AliasNames:   []string{"alias/aws/s3"},
		Region:       "us-east-1",
		AccountID:    "111122223333",
		Enabled:      true,
	}
}

func TestIntegration_StoreKMSKeyFindings_PublishesToKeyInventory(t *testing.T) {
	svc, tenant, integration := newKMSPublishFixture(t)

	type received struct {
		path     string
		tenant   string
		signed   bool
		body     cloudKeyIngestRequest
		gotCalls int
	}
	var got received

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.gotCalls++
		got.path = r.URL.Path
		got.tenant = r.Header.Get(serviceauth.HeaderTenantID)
		// The internal route refuses anything that is not an internal service
		// call, so a request without this marker would 403 in production. The
		// HMAC signature itself rides alongside it whenever INTERNAL_AUTH_SECRET
		// is set (serviceauth.SignRequestFromEnv); the marker is the part that
		// is present in every configuration, so it is what this asserts.
		got.signed = r.Header.Get(serviceauth.HeaderServiceCall) == "true"
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &got.body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"written":1}`))
	}))
	defer srv.Close()

	svc.SetCloudKeyPublisher(NewInventoryCloudKeyPublisher(srv.URL, nil))

	findings := []KMSKeyFinding{awsManagedFinding()}
	if err := svc.StoreKMSKeyFindings(context.Background(), tenant, integration, "aws", findings); err != nil {
		t.Fatalf("StoreKMSKeyFindings: %v", err)
	}

	if got.gotCalls != 1 {
		t.Fatalf("key inventory received %d calls, want 1 — storing a KMS key must also publish it", got.gotCalls)
	}
	if got.path != cloudKeyIngestPath {
		t.Errorf("published to %q, want %q", got.path, cloudKeyIngestPath)
	}
	if got.tenant != tenant.String() {
		t.Errorf("tenant header = %q, want %q", got.tenant, tenant)
	}
	if !got.signed {
		t.Errorf("request carried no %s marker — the internal route would answer 403", serviceauth.HeaderServiceCall)
	}
	if len(got.body.Keys) != 1 {
		t.Fatalf("published %d keys, want 1", len(got.body.Keys))
	}
	k := got.body.Keys[0]
	if k.KeyManager != "AWS" {
		t.Errorf("published key_manager = %q, want AWS — custody must survive the hop", k.KeyManager)
	}
	if k.Provider != "aws" || k.IntegrationID != integration.String() {
		t.Errorf("published provider/integration = %q/%q, want aws/%s", k.Provider, k.IntegrationID, integration)
	}
	if k.KeyARN != findings[0].KeyARN {
		t.Errorf("published key_arn = %q, want %q", k.KeyARN, findings[0].KeyARN)
	}

	// The parallel table is still written — retiring it is a separate decision,
	// and double-writing is what keeps the experimental endpoint working.
	var n int
	if err := svc.db.QueryRow(`SELECT count(*) FROM kms_keys WHERE tenant_id = $1`, tenant).Scan(&n); err != nil {
		t.Fatalf("count kms_keys: %v", err)
	}
	if n != 1 {
		t.Errorf("kms_keys has %d rows, want 1 — the existing write must not regress", n)
	}
}

// An inventory that is down must not lose the discovery: kms_keys is still
// written and StoreKMSKeyFindings still succeeds.
func TestIntegration_StoreKMSKeyFindings_SurvivesInventoryOutage(t *testing.T) {
	svc, tenant, integration := newKMSPublishFixture(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"error":"boom"}`, http.StatusInternalServerError)
	}))
	defer srv.Close()
	svc.SetCloudKeyPublisher(NewInventoryCloudKeyPublisher(srv.URL, nil))

	if err := svc.StoreKMSKeyFindings(context.Background(), tenant, integration, "aws", []KMSKeyFinding{awsManagedFinding()}); err != nil {
		t.Fatalf("a failed publish must not fail the discovery: %v", err)
	}
	var n int
	if err := svc.db.QueryRow(`SELECT count(*) FROM kms_keys WHERE tenant_id = $1`, tenant).Scan(&n); err != nil {
		t.Fatalf("count kms_keys: %v", err)
	}
	if n != 1 {
		t.Errorf("kms_keys has %d rows, want 1", n)
	}
}
