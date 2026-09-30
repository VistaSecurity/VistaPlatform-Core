package handlers

// Contract test for the internal CI export routes (platform ADR-0002 D4, M3):
// the REAL handlers, behind the REAL signed-call gate, over a stub service,
// every response body validated against the `ci-export` schemas in
// api/openapi/inventory-service.openapi.yaml — the shapes the Enterprise integration service's
// CMDB push decodes.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
)

type stubCIExporter struct {
	gotTenant uuid.UUID
	gotAfter  uuid.UUID
	gotLimit  int
	gotQuery  services.CIExportAssetQuery
	queryErr  error
}

func (s *stubCIExporter) ExportItems(_ context.Context, tenant, after uuid.UUID, limit int) ([]services.CIExportItem, error) {
	s.gotTenant, s.gotAfter, s.gotLimit = tenant, after, limit
	score := 91
	now := time.Now().UTC()
	return []services.CIExportItem{
		{ID: uuid.New(), Category: "infrastructure_asset", CMDBCIType: "cmdb_ci_server", DisplayName: "web-01",
			RiskScore: &score, RiskLevel: "Critical", DiscoveredAt: now, LastVerifiedAt: now},
		{ID: uuid.New(), Category: "certificate", CMDBCIType: "cmdb_ci_certificate", DisplayName: "web-01.example.test",
			Description: "Certificate: web-01.example.test", DiscoveredAt: now, LastVerifiedAt: now},
	}, nil
}

func (s *stubCIExporter) ExportAssets(_ context.Context, tenant uuid.UUID, q services.CIExportAssetQuery) ([]services.CIExportAsset, error) {
	s.gotTenant, s.gotQuery = tenant, q
	if s.queryErr != nil {
		return nil, s.queryErr
	}
	v := "TLS"
	ks := 2048
	return []services.CIExportAsset{
		{ID: q.AssetIDs[0], Fields: map[string]string{"hostname": "web-01", "class_key": "server"},
			Facts:         map[string]any{"os.name": "Ubuntu"},
			CryptoPosture: &services.CIExportPosture{RiskLevel: "High", Configurations: []services.CIExportCrypto{{Protocol: "TLS", ProtocolVersion: &v, KeySize: &ks}}},
			Identifiers:   []string{"SRV0001"}},
		{ID: uuid.New(), Retired: true},
	}, nil
}

func (s *stubCIExporter) ExportRelationships(_ context.Context, tenant, after uuid.UUID, limit int) ([]services.CIExportRelationship, error) {
	s.gotTenant, s.gotAfter, s.gotLimit = tenant, after, limit
	return []services.CIExportRelationship{{ID: uuid.New(), FromAssetID: uuid.New(), ToAssetID: uuid.New(), Type: "runs_on"}}, nil
}

func ciExportContractEngine(stub *stubCIExporter) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	internal := r.Group("/api/v1")
	internal.Use(RequireSignedServiceCall(sourceContractSecret))
	RegisterCIExportRoutes(internal, newCIExportHandlerWith(stub))
	return r
}

func TestContract_CIExport_Responses(t *testing.T) {
	sv := loadSpec(t)
	stub := &stubCIExporter{}
	e := ciExportContractEngine(stub)
	tenant := uuid.New()
	after := uuid.New()
	const base = "/api/v1/inventory-service/internal/ci-export"
	asset := uuid.New()

	for _, tc := range []struct {
		method, path, body, schema string
	}{
		{http.MethodGet, base + "/items?after=" + after.String() + "&limit=2", ``, "CIExportItemsResponse"},
		{http.MethodPost, base + "/assets", `{"asset_ids":["` + asset.String() + `"],"include":{"fields":true,"fact_keys":["os.name"],"crypto_posture":true,"identifier":{"kind":"cmdb_sys_id","scope":"p"}}}`, "CIExportAssetsResponse"},
		{http.MethodGet, base + "/relationships?limit=1", ``, "CIExportRelationshipsResponse"},
	} {
		w := httptest.NewRecorder()
		e.ServeHTTP(w, signedSourceCall(tc.method, tc.path, tc.body, tenant))
		if w.Code != http.StatusOK {
			t.Fatalf("%s %s = %d: %s", tc.method, tc.path, w.Code, w.Body.String())
		}
		sv.assertConforms(t, tc.schema, w.Body.Bytes())
		if stub.gotTenant != tenant {
			t.Errorf("%s %s acted for tenant %s, want the signed %s", tc.method, tc.path, stub.gotTenant, tenant)
		}
	}
	// The detail query reached the service as asked.
	q := stub.gotQuery
	if !q.Fields || !q.CryptoPosture || len(q.FactKeys) != 1 || q.IdentifierKind != "cmdb_sys_id" || q.IdentifierScope != "p" || q.AssetIDs[0] != asset {
		t.Errorf("detail query = %+v", q)
	}
}

// A full page says there may be more; a short one says there is not.
func TestContract_CIExport_PagesSayWhetherThereIsMore(t *testing.T) {
	e := ciExportContractEngine(&stubCIExporter{})
	for _, tc := range []struct {
		path string
		more bool
	}{
		{"/items?limit=2", true},
		{"/items?limit=3", false},
		{"/relationships?limit=1", true},
		{"/relationships?limit=2", false},
	} {
		w := httptest.NewRecorder()
		e.ServeHTTP(w, signedSourceCall(http.MethodGet, "/api/v1/inventory-service/internal/ci-export"+tc.path, "", uuid.New()))
		want := `"more":false`
		if tc.more {
			want = `"more":true`
		}
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), want) {
			t.Errorf("GET %s = %d %s, want %s", tc.path, w.Code, w.Body.String(), want)
		}
	}
}

func TestContract_CIExport_RefusesBadRequests(t *testing.T) {
	stub := &stubCIExporter{}
	e := ciExportContractEngine(stub)
	tooMany := `{"asset_ids":[`
	for i := 0; i <= services.MaxCIExportAssets; i++ {
		if i > 0 {
			tooMany += ","
		}
		tooMany += `"` + uuid.NewString() + `"`
	}
	tooMany += `]}`
	for _, tc := range []struct{ method, path, body string }{
		{http.MethodGet, "/items?after=not-a-uuid", ""},
		{http.MethodGet, "/items?limit=0", ""},
		{http.MethodGet, "/relationships?limit=5001", ""},
		{http.MethodPost, "/assets", `{"asset_ids":[]}`},
		{http.MethodPost, "/assets", tooMany},
		{http.MethodPost, "/assets", `{"asset_ids":["` + uuid.NewString() + `"],"include":{"identifier":{"kind":"","scope":"p"}}}`},
	} {
		w := httptest.NewRecorder()
		e.ServeHTTP(w, signedSourceCall(tc.method, "/api/v1/inventory-service/internal/ci-export"+tc.path, tc.body, uuid.New()))
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s %s = %d, want 400", tc.method, tc.path, w.Code)
		}
	}
	if stub.gotTenant != uuid.Nil {
		t.Error("the service ran for a request that should have been refused")
	}

	// A query the service refuses as asked (an unexportable identifier kind,
	// an unknown fact key) is the caller's 400, not a 500.
	stub.queryErr = &services.ErrCIExportQuery{Message: `identifier kind "serial_number" cannot be exported`}
	w := httptest.NewRecorder()
	e.ServeHTTP(w, signedSourceCall(http.MethodPost, "/api/v1/inventory-service/internal/ci-export/assets",
		`{"asset_ids":["`+uuid.NewString()+`"],"include":{"identifier":{"kind":"serial_number","scope":"p"}}}`, uuid.New()))
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "cannot be exported") {
		t.Errorf("a refused query = %d %s, want 400 naming why", w.Code, w.Body.String())
	}
}
