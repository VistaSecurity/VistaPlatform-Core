package handlers

// Contract test for the admin-service artifact-storage-config surface
// (ADR-0001 /). It is called INLINE by the admin-ui
// (storage-configuration component), not via a service-layer client, so it was
// missed by the original sweep.
//
// storage_config.go landed a repo extraction (storageStore) so the real
// handlers run over an in-memory stub. Uses the shared contract harness
// (loadSpec / doRequest / apiBase) from contract_harness_test.go.
//
// The admin billing invoices/credits half of this file moved to
// ee/billingapi/admin_invoices_contract_test.go with the billing carve.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/storage"
)

// --- stubs ------------------------------------------------------------------

type stubStorageStore struct {
	raw             []byte
	rawErr          error
	upsertErr       error
	integrations    []IntegrationSummary
	integrationsErr error
	exists          bool
	existsErr       error
	status          string
	statusErr       error
	creds           *storage.AWSCredentials
	credsErr        error
}

func (s *stubStorageStore) GetArtifactStorageConfigRaw(context.Context) ([]byte, error) {
	return s.raw, s.rawErr
}
func (s *stubStorageStore) UpsertArtifactStorageConfig(context.Context, []byte, uuid.UUID) error {
	return s.upsertErr
}
func (s *stubStorageStore) ListAWSIntegrations(context.Context) ([]IntegrationSummary, error) {
	return s.integrations, s.integrationsErr
}
func (s *stubStorageStore) IntegrationExists(context.Context, uuid.UUID) (bool, error) {
	return s.exists, s.existsErr
}
func (s *stubStorageStore) GetIntegrationStatus(context.Context, uuid.UUID) (string, error) {
	return s.status, s.statusErr
}
func (s *stubStorageStore) ResolveAWSCredentials(context.Context, uuid.UUID) (*storage.AWSCredentials, error) {
	if s.credsErr != nil {
		return nil, s.credsErr
	}
	if s.creds != nil {
		return s.creds, nil
	}
	return &storage.AWSCredentials{AccessKeyID: "AKIAEXAMPLE", SecretAccessKey: "secret", Region: "us-east-1"}, nil
}

// withStubProbe swaps the S3 reachability probe for the duration of a test.
func withStubProbe(t *testing.T, err error) {
	t.Helper()
	prev := probeBucket
	probeBucket = func(context.Context, *storage.AWSCredentials, string) error { return err }
	t.Cleanup(func() { probeBucket = prev })
}

func storageEngine(ss storageStore, withUser bool) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	g := r.Group(apiBase)
	if withUser {
		g.Use(func(c *gin.Context) { c.Set("userID", uuid.NewString()); c.Next() })
	}
	g.GET("/admin/storage/config", getStorageConfigWithStore(ss))
	g.PUT("/admin/storage/config", updateStorageConfigWithStore(ss))
	g.POST("/admin/storage/test", testStorageConnectionWithStore(ss))
	return r
}

func sampleIntegration() IntegrationSummary {
	region := "us-east-1"
	return IntegrationSummary{ID: uuid.New(), IntegrationName: "prod-s3", Provider: "aws", Status: "connected", Region: &region}
}

// a storage config JSON with one enabled artifact type + a default integration,
// so /test resolves an integration id + bucket.
func testStorageConfigJSON() []byte {
	return []byte(`{"default_integration_id":"` + uuid.New().String() + `","default_bucket":"prod-bucket","artifact_types":{"tenant_branding":{"enabled":true}}}`)
}

const testStorageBody = `{"artifact_type":"tenant_branding"}`

// --- storage config: GET ----------------------------------------------------

func TestContract_GetStorageConfig_200(t *testing.T) {
	sv := loadSpec(t)
	// ErrNoRows → DefaultStorageConfig; integrations present.
	eng := storageEngine(&stubStorageStore{rawErr: sql.ErrNoRows, integrations: []IntegrationSummary{sampleIntegration()}}, true)
	w := doRequest(eng, http.MethodGet, apiBase+"/admin/storage/config", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "StorageConfigResponse", w.Body.Bytes())
}

func TestContract_GetStorageConfig_200_noIntegrations(t *testing.T) {
	sv := loadSpec(t)
	eng := storageEngine(&stubStorageStore{rawErr: sql.ErrNoRows, integrations: nil}, true)
	w := doRequest(eng, http.MethodGet, apiBase+"/admin/storage/config", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "StorageConfigResponse", w.Body.Bytes())
}

func TestContract_GetStorageConfig_500(t *testing.T) {
	sv := loadSpec(t)
	eng := storageEngine(&stubStorageStore{rawErr: context.DeadlineExceeded}, true)
	w := doRequest(eng, http.MethodGet, apiBase+"/admin/storage/config", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- storage config: PUT ----------------------------------------------------

func TestContract_UpdateStorageConfig_200(t *testing.T) {
	sv := loadSpec(t)
	eng := storageEngine(&stubStorageStore{}, true)
	w := doRequest(eng, http.MethodPut, apiBase+"/admin/storage/config", strings.NewReader(`{"default_bucket":"b"}`))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "StorageConfigUpdateResponse", w.Body.Bytes())
}

func TestContract_UpdateStorageConfig_400(t *testing.T) {
	sv := loadSpec(t)
	eng := storageEngine(&stubStorageStore{}, true)
	w := doRequest(eng, http.MethodPut, apiBase+"/admin/storage/config", strings.NewReader(`{bad`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_UpdateStorageConfig_401(t *testing.T) {
	sv := loadSpec(t)
	eng := storageEngine(&stubStorageStore{}, false)
	w := doRequest(eng, http.MethodPut, apiBase+"/admin/storage/config", strings.NewReader(`{"default_bucket":"b"}`))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_UpdateStorageConfig_500(t *testing.T) {
	sv := loadSpec(t)
	eng := storageEngine(&stubStorageStore{upsertErr: context.DeadlineExceeded}, true)
	w := doRequest(eng, http.MethodPut, apiBase+"/admin/storage/config", strings.NewReader(`{"default_bucket":"b"}`))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- storage test -----------------------------------------------------------

func TestContract_TestStorageConnection_200(t *testing.T) {
	sv := loadSpec(t)
	withStubProbe(t, nil)
	eng := storageEngine(&stubStorageStore{raw: testStorageConfigJSON(), status: "connected"}, true)
	w := doRequest(eng, http.MethodPost, apiBase+"/admin/storage/test", strings.NewReader(testStorageBody))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "StorageTestResponse", w.Body.Bytes())
}

// Integration not connected → still 200, success=false.
func TestContract_TestStorageConnection_200_notConnected(t *testing.T) {
	sv := loadSpec(t)
	eng := storageEngine(&stubStorageStore{raw: testStorageConfigJSON(), status: "pending"}, true)
	w := doRequest(eng, http.MethodPost, apiBase+"/admin/storage/test", strings.NewReader(testStorageBody))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "StorageTestResponse", w.Body.Bytes())
}

// No config persisted → 400.
func TestContract_TestStorageConnection_400_notConfigured(t *testing.T) {
	sv := loadSpec(t)
	eng := storageEngine(&stubStorageStore{rawErr: sql.ErrNoRows}, true)
	w := doRequest(eng, http.MethodPost, apiBase+"/admin/storage/test", strings.NewReader(testStorageBody))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_TestStorageConnection_400_badBody(t *testing.T) {
	sv := loadSpec(t)
	eng := storageEngine(&stubStorageStore{}, true)
	w := doRequest(eng, http.MethodPost, apiBase+"/admin/storage/test", strings.NewReader(`{}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- storage test: the check must be able to FAIL ----------------------------
//
// These three pin the B-53 fix. Before it, TestStorageConnection read nothing
// but platform_integrations.status and answered "Storage configuration appears
// valid" — a check that could not fail for any credential or bucket problem,
// which is the only class of problem the button exists to surface.

// Credentials that cannot be decrypted → 200 with success=false, not success=true.
func TestContract_TestStorageConnection_200_credentialsUnresolvable(t *testing.T) {
	sv := loadSpec(t)
	withStubProbe(t, nil) // probe would pass; the credential step must still fail the test
	eng := storageEngine(&stubStorageStore{
		raw:      testStorageConfigJSON(),
		status:   "connected",
		credsErr: errors.New("failed to decrypt secret access key"),
	}, true)
	w := doRequest(eng, http.MethodPost, apiBase+"/admin/storage/test", strings.NewReader(testStorageBody))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "StorageTestResponse", w.Body.Bytes())
	if decodeSuccess(t, w.Body.Bytes()) {
		t.Fatalf("success = true with undecryptable credentials; the test-connection check cannot fail. body=%s", w.Body.String())
	}
}

// Bucket unreachable (bad keys / wrong region / missing bucket / no permission)
// → 200 with success=false.
func TestContract_TestStorageConnection_200_bucketUnreachable(t *testing.T) {
	sv := loadSpec(t)
	withStubProbe(t, errors.New("s3 HeadBucket failed: AccessDenied"))
	eng := storageEngine(&stubStorageStore{raw: testStorageConfigJSON(), status: "connected"}, true)
	w := doRequest(eng, http.MethodPost, apiBase+"/admin/storage/test", strings.NewReader(testStorageBody))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "StorageTestResponse", w.Body.Bytes())
	if decodeSuccess(t, w.Body.Bytes()) {
		t.Fatalf("success = true against an unreachable bucket. body=%s", w.Body.String())
	}
}

// success=true is reported only when credentials resolved AND the bucket answered.
func TestContract_TestStorageConnection_200_successRequiresReachableBucket(t *testing.T) {
	withStubProbe(t, nil)
	eng := storageEngine(&stubStorageStore{raw: testStorageConfigJSON(), status: "connected"}, true)
	w := doRequest(eng, http.MethodPost, apiBase+"/admin/storage/test", strings.NewReader(testStorageBody))
	if !decodeSuccess(t, w.Body.Bytes()) {
		t.Fatalf("success = false on a fully working configuration. body=%s", w.Body.String())
	}
}

func decodeSuccess(t *testing.T, body []byte) bool {
	t.Helper()
	var parsed struct {
		Success bool `json:"success"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("decode response: %v (body=%s)", err, body)
	}
	return parsed.Success
}
