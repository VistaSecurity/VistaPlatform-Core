package handlers

// Contract test for the cloud-integrations full-CRUD surface. Extends the
// device-interrogation-service spec-first contract (ADR-0001) and reuses the
// shared harness (loadSpec / assertConforms / do / strPtr / aUUID / base /
// deviceTestTenant) from the jobs + devices + schedules contract tests — only
// the integration stub + engine + cases live here.
//
// IntegrationHandlers used to query *sql.DB inline; this slice landed a
// behaviour-preserving refactor first (the SQL moved verbatim into
// integrationRepository behind the integrationStore interface; the credential
// encrypt/decrypt/mask logic stayed in the handler). So the real handlers now
// run over httptest with an in-memory stub — no database.

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

const testEncryptionKey = "test-encryption-master-key-for-contract-tests"

// --- stub integrationStore -------------------------------------------------

type stubIntegrationStore struct {
	list       []CloudIntegration
	listErr    error
	get        *CloudIntegration
	getErr     error
	createErr  error
	updFound   bool
	updType    string
	updConfig  string
	delRows    int64
	testFound  bool
	testType   string
	testConfig string
}

func (s *stubIntegrationStore) List(context.Context, uuid.UUID, string) ([]CloudIntegration, error) {
	return s.list, s.listErr
}
func (s *stubIntegrationStore) Get(context.Context, uuid.UUID, uuid.UUID) (*CloudIntegration, error) {
	return s.get, s.getErr
}
func (s *stubIntegrationStore) Create(context.Context, CreateIntegrationParams) error {
	return s.createErr
}
func (s *stubIntegrationStore) GetConfigForUpdate(context.Context, uuid.UUID, uuid.UUID) (string, string, bool, error) {
	return s.updConfig, s.updType, s.updFound, nil
}
func (s *stubIntegrationStore) GetConfigForTest(context.Context, uuid.UUID, uuid.UUID) (string, string, bool, error) {
	return s.testConfig, s.testType, s.testFound, nil
}
func (s *stubIntegrationStore) Update(context.Context, uuid.UUID, uuid.UUID, map[string]interface{}) (int64, error) {
	return 1, nil
}
func (s *stubIntegrationStore) Delete(context.Context, uuid.UUID, uuid.UUID) (int64, error) {
	return s.delRows, nil
}
func (s *stubIntegrationStore) UpdateTestStatus(context.Context, uuid.UUID, uuid.UUID, string, *string) error {
	return nil
}

func newIntegrationEngine(store *stubIntegrationStore) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group("/api/v1/device-interrogation-service")
	grp.Use(func(c *gin.Context) {
		c.Set("tenantID", deviceTestTenant)
		c.Next()
	})
	h := &IntegrationHandlers{store: store, encryptionKey: testEncryptionKey}
	grp.GET("/integrations", h.ListIntegrations)
	grp.POST("/integrations", h.CreateIntegration)
	grp.GET("/integrations/:id", h.GetIntegration)
	grp.PUT("/integrations/:id", h.UpdateIntegration)
	grp.DELETE("/integrations/:id", h.DeleteIntegration)
	grp.POST("/integrations/:id/test", h.TestConnection)
	return r
}

func sampleIntegration() CloudIntegration {
	now := time.Now().UTC()
	return CloudIntegration{
		ID:              uuid.New(),
		TenantID:        deviceTestTenant,
		IntegrationType: "aws",
		IntegrationName: "prod AWS",
		Provider:        "cloud",
		Config:          map[string]interface{}{"access_key_id": "AKIAEXAMPLE", "secret_access_key": "supersecretvalue"},
		AccountID:       strPtr("123456789012"),
		Region:          strPtr("us-east-1"),
		Tags:            []string{"prod"},
		IsEnabled:       true,
		Status:          "configured",
		CreatedAt:       now,
		UpdatedAt:       now,
	}
}

// minimalIntegration leaves the omitempty fields unset and config nil (→ null).
func minimalIntegration() CloudIntegration {
	now := time.Now().UTC()
	return CloudIntegration{
		ID:              uuid.New(),
		TenantID:        deviceTestTenant,
		IntegrationType: "gcp",
		IntegrationName: "gcp project",
		Provider:        "cloud",
		IsEnabled:       false,
		Status:          "pending",
		CreatedAt:       now,
		UpdatedAt:       now,
	}
}

const validIntegrationBody = `{"integration_type":"aws","integration_name":"prod","provider":"cloud","config":{"access_key_id":"AKIA","secret_access_key":"x"}}`

// --- the contract tests ----------------------------------------------------

func TestContract_ListIntegrations_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newIntegrationEngine(&stubIntegrationStore{list: []CloudIntegration{sampleIntegration(), minimalIntegration()}})
	w := do(eng, http.MethodGet, base+"/integrations", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "IntegrationListResponse", w.Body.Bytes())
}

func TestContract_CreateIntegration_201(t *testing.T) {
	sv := loadSpec(t)
	eng := newIntegrationEngine(&stubIntegrationStore{})
	w := do(eng, http.MethodPost, base+"/integrations", strings.NewReader(validIntegrationBody))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "IntegrationResponse", w.Body.Bytes())
}

func TestContract_CreateIntegration_400(t *testing.T) {
	sv := loadSpec(t)
	eng := newIntegrationEngine(&stubIntegrationStore{})
	w := do(eng, http.MethodPost, base+"/integrations", strings.NewReader(`{"integration_name":"x"}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GetIntegration_200(t *testing.T) {
	sv := loadSpec(t)
	integ := sampleIntegration()
	eng := newIntegrationEngine(&stubIntegrationStore{get: &integ})
	w := do(eng, http.MethodGet, base+"/integrations/"+aUUID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "IntegrationResponse", w.Body.Bytes())
}

func TestContract_GetIntegration_400_badID(t *testing.T) {
	sv := loadSpec(t)
	eng := newIntegrationEngine(&stubIntegrationStore{})
	w := do(eng, http.MethodGet, base+"/integrations/not-a-uuid", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_GetIntegration_404(t *testing.T) {
	sv := loadSpec(t)
	eng := newIntegrationEngine(&stubIntegrationStore{get: nil})
	w := do(eng, http.MethodGet, base+"/integrations/"+aUUID, nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_UpdateIntegration_200(t *testing.T) {
	sv := loadSpec(t)
	// found=true so ownership passes; no config in body so no encryption path.
	eng := newIntegrationEngine(&stubIntegrationStore{updFound: true, updType: "aws", updConfig: "{}"})
	w := do(eng, http.MethodPut, base+"/integrations/"+aUUID, strings.NewReader(`{"integration_name":"renamed"}`))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "MessageResponse", w.Body.Bytes())
}

func TestContract_UpdateIntegration_404(t *testing.T) {
	sv := loadSpec(t)
	eng := newIntegrationEngine(&stubIntegrationStore{updFound: false})
	w := do(eng, http.MethodPut, base+"/integrations/"+aUUID, strings.NewReader(`{"integration_name":"renamed"}`))
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_DeleteIntegration_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newIntegrationEngine(&stubIntegrationStore{delRows: 1})
	w := do(eng, http.MethodDelete, base+"/integrations/"+aUUID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "MessageResponse", w.Body.Bytes())
}

func TestContract_DeleteIntegration_404(t *testing.T) {
	sv := loadSpec(t)
	eng := newIntegrationEngine(&stubIntegrationStore{delRows: 0})
	w := do(eng, http.MethodDelete, base+"/integrations/"+aUUID, nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// TestConnection on a (no-longer-supported) network device type returns a
// clean success=false result with no live network call.
func TestContract_TestConnection_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newIntegrationEngine(&stubIntegrationStore{testFound: true, testType: "f5", testConfig: "{}"})
	w := do(eng, http.MethodPost, base+"/integrations/"+aUUID+"/test", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "TestConnectionResult", w.Body.Bytes())
}

func TestContract_TestConnection_404(t *testing.T) {
	sv := loadSpec(t)
	eng := newIntegrationEngine(&stubIntegrationStore{testFound: false})
	w := do(eng, http.MethodPost, base+"/integrations/"+aUUID+"/test", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_Integration_DriftIsCaught(t *testing.T) {
	sv := loadSpec(t)
	sch, err := sv.compiler.Compile(specBaseURI + "#/components/schemas/CloudIntegration")
	if err != nil {
		t.Fatalf("compile CloudIntegration: %v", err)
	}
	bad, err := jsonschema.UnmarshalJSON(strings.NewReader(
		`{"id":"` + aUUID + `","surprise_field":true}`))
	if err != nil {
		t.Fatalf("unmarshal bad body: %v", err)
	}
	if err := sch.Validate(bad); err == nil {
		t.Fatal("expected validation to FAIL for a drifted CloudIntegration, but it passed — the guardrail is not actually checking")
	}
}
