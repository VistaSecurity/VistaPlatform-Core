package handlers

// Contract test for the internal source-import routes (platform ADR-0002 D3):
// the REAL handlers, behind the REAL signed-call gate, over a stub service,
// with every response body validated against the `source-imports` schemas in
// api/openapi/inventory-service.openapi.yaml. The connector on the other side
// decodes exactly these shapes.

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/serviceauth"
)

const sourceContractSecret = "source-import-contract-secret-0123456789"

type stubSourceImporter struct {
	admissionErr error
	gotTenant    uuid.UUID
	gotSource    identity.Source
}

func (s *stubSourceImporter) UpsertSegments(_ context.Context, tenant uuid.UUID, items []services.SourceSegment) ([]services.SourceSegmentResult, error) {
	s.gotTenant = tenant
	out := make([]services.SourceSegmentResult, 0, len(items))
	for i, it := range items {
		switch i % 3 {
		case 0:
			out = append(out, services.SourceSegmentResult{CIDR: it.CIDR, Outcome: services.SourceSegmentCreated})
		case 1:
			out = append(out, services.SourceSegmentResult{CIDR: it.CIDR, Outcome: services.SourceSegmentMatched})
		default:
			out = append(out, services.SourceSegmentResult{CIDR: it.CIDR, Outcome: services.SourceSegmentError, Error: "boom"})
		}
	}
	return out, nil
}

func (s *stubSourceImporter) Admission(_ context.Context, tenant uuid.UUID, _ int) (services.SourceAdmission, error) {
	s.gotTenant = tenant
	if s.admissionErr != nil {
		return services.SourceAdmission{}, s.admissionErr
	}
	return services.SourceAdmission{Allowed: false, Message: "over the plan's asset limit"}, nil
}

func (s *stubSourceImporter) ResolveAssets(_ context.Context, tenant uuid.UUID, source identity.Source, items []services.SourceAssetItem) []services.SourceAssetResult {
	s.gotTenant, s.gotSource = tenant, source
	id := uuid.New()
	out := []services.SourceAssetResult{
		{Outcome: "created", AssetID: &id},
		{Outcome: services.SourceOutcomeRetained, ObservationID: uuid.NewString(), Proposed: true},
		{Outcome: services.SourceOutcomeError, Error: "no usable identifier"},
	}
	return out[:len(items)]
}

func (s *stubSourceImporter) ClassKeyExists(_ context.Context, tenant uuid.UUID, _ string) (bool, error) {
	s.gotTenant = tenant
	return true, nil
}

func (s *stubSourceImporter) HardwareAssets(_ context.Context, tenant uuid.UUID, _ uuid.UUID, limit int) ([]services.SourceHardwareAsset, error) {
	s.gotTenant = tenant
	return []services.SourceHardwareAsset{{ID: uuid.New(), ClassKey: "switch", AssetStatus: "monitoring", Serial: "SN1"}}, nil
}

func (s *stubSourceImporter) AttachLinks(_ context.Context, tenant uuid.UUID, source identity.Source, items []services.SourceLink) ([]services.SourceItemResult, error) {
	s.gotTenant, s.gotSource = tenant, source
	out := []services.SourceItemResult{
		{Outcome: services.SourceItemRecorded},
		{Outcome: services.SourceItemNotFound},
		{Outcome: services.SourceOutcomeError, Error: "not a source link"},
	}
	return out[:len(items)], nil
}

func (s *stubSourceImporter) RecordPresence(_ context.Context, tenant uuid.UUID, source identity.Source, _ string, items []services.SourcePresence) ([]services.SourceItemResult, error) {
	s.gotTenant, s.gotSource = tenant, source
	out := make([]services.SourceItemResult, 0, len(items))
	for range items {
		out = append(out, services.SourceItemResult{Outcome: services.SourceItemRecorded})
	}
	return out, nil
}

func (s *stubSourceImporter) RecordRun(_ context.Context, tenant uuid.UUID, source identity.Source, _ uuid.UUID, items []services.SourceRunItem) ([]services.SourceItemResult, error) {
	s.gotTenant, s.gotSource = tenant, source
	out := []services.SourceItemResult{
		{Outcome: services.SourceItemRecorded},
		{Outcome: services.SourceItemNotFound},
		{Outcome: services.SourceOutcomeError, Error: "action \"deleted\" is not created or updated"},
	}
	return out[:len(items)], nil
}

func (s *stubSourceImporter) ArchiveRunAssets(_ context.Context, tenant uuid.UUID, source identity.Source, _ uuid.UUID, _ uuid.UUID, _ string, ids []uuid.UUID) ([]services.SourceUndoResult, error) {
	s.gotTenant, s.gotSource = tenant, source
	out := make([]services.SourceUndoResult, 0, len(ids))
	outcomes := []services.SourceUndoResult{
		{Outcome: services.SourceUndoArchived},
		{Outcome: services.SourceUndoKept, Reason: "also reported by sensor:abc"},
		{Outcome: services.SourceUndoAlreadyArchived},
		{Outcome: services.SourceItemNotFound},
	}
	for i, id := range ids {
		r := outcomes[i%len(outcomes)]
		r.AssetID = id
		out = append(out, r)
	}
	return out, nil
}

func (s *stubSourceImporter) SetScanConsent(_ context.Context, tenant uuid.UUID, source identity.Source, allow bool, _ uuid.UUID) (services.SourceScanConsent, error) {
	s.gotTenant, s.gotSource = tenant, source
	return services.SourceScanConsent{SourceRef: source.Ref, AllowActiveScan: allow}, nil
}

func sourceContractEngine(stub *stubSourceImporter) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	internal := r.Group("/api/v1")
	internal.Use(RequireSignedServiceCall(sourceContractSecret))
	RegisterSourceImportRoutes(internal, newSourceImportHandlerWith(stub))
	return r
}

func signedSourceCall(method, path, body string, tenant uuid.UUID) *http.Request {
	req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(serviceauth.HeaderTenantID, tenant.String())
	serviceauth.NewSigner(sourceContractSecret).SignRequest(req)
	return req
}

func TestContract_SourceImport_Responses(t *testing.T) {
	sv := loadSpec(t)
	stub := &stubSourceImporter{}
	e := sourceContractEngine(stub)
	tenant := uuid.New()
	const base = "/api/v1/inventory-service/internal/sources"

	for _, tc := range []struct {
		method, path, body, schema string
		want                       int
	}{
		{http.MethodPost, base + "/segments", `{"segments":[{"cidr":"192.0.2.0/24","source_ref":"a"},{"cidr":"198.51.100.0/24","source_ref":"b"},{"cidr":"203.0.113.0/24","source_ref":"c"}]}`, "SourceSegmentsResponse", http.StatusOK},
		{http.MethodPost, base + "/assets/admission", `{"count":3}`, "SourceAdmissionResponse", http.StatusOK},
		{http.MethodPost, base + "/assets", `{"source":{"kind":"imported","ref":"netbox:x"},"assets":[{"class_key":"switch"},{"class_key":"switch"},{"class_key":"switch"}]}`, "SourceAssetsResponse", http.StatusOK},
		{http.MethodGet, base + "/asset-classes/switch", ``, "SourceClassExistsResponse", http.StatusOK},
		{http.MethodGet, base + "/hardware-assets?limit=10", ``, "SourceHardwareAssetsResponse", http.StatusOK},
		{http.MethodPost, base + "/assets/presence", `{"source":{"kind":"imported","ref":"cmdb:p"},"platform":"servicenow","items":[{"asset_id":"` + uuid.NewString() + `","presence":"absent","reason":"retired in ServiceNow"}]}`, "SourceItemResultsResponse", http.StatusOK},
		{http.MethodPost, base + "/assets/runs", `{"source":{"kind":"imported","ref":"cmdb:p"},"run_id":"` + uuid.NewString() + `","items":[{"asset_id":"` + uuid.NewString() + `","action":"created"},{"asset_id":"` + uuid.NewString() + `","action":"updated"},{"asset_id":"` + uuid.NewString() + `","action":"deleted"}]}`, "SourceItemResultsResponse", http.StatusOK},
		{http.MethodPut, "/api/v1/inventory-service/internal/sources/scan-consent", `{"source":{"kind":"imported","ref":"cmdb:p"},"allow_active_scan":true,"actor_user_id":"` + uuid.NewString() + `"}`, "SourceScanConsent", http.StatusOK},
		{http.MethodPost, base + "/assets/archive", `{"source":{"kind":"imported","ref":"cmdb:p"},"run_id":"` + uuid.NewString() + `","actor_user_id":"` + uuid.NewString() + `","reason":"undo","asset_ids":["` + uuid.NewString() + `","` + uuid.NewString() + `","` + uuid.NewString() + `","` + uuid.NewString() + `"]}`, "SourceUndoResponse", http.StatusOK},
		{http.MethodPost, base + "/assets/links", `{"source":{"kind":"imported","ref":"netbox:x"},"links":[{"asset_id":"` + uuid.NewString() + `","kind":"cmdb_sys_id","value":"SRV1","scope":"p"},{"asset_id":"` + uuid.NewString() + `","kind":"cmdb_sys_id","value":"SRV2","scope":"p"},{"asset_id":"` + uuid.NewString() + `","kind":"serial_number","value":"x","scope":"p"}]}`, "SourceItemResultsResponse", http.StatusOK},
	} {
		w := httptest.NewRecorder()
		e.ServeHTTP(w, signedSourceCall(tc.method, tc.path, tc.body, tenant))
		if w.Code != tc.want {
			t.Fatalf("%s %s = %d, want %d: %s", tc.method, tc.path, w.Code, tc.want, w.Body.String())
		}
		sv.assertConforms(t, tc.schema, w.Body.Bytes())
		// The tenant the handler acted for is the one the signed header named.
		if stub.gotTenant != tenant {
			t.Errorf("%s %s acted for tenant %s, want the signed %s", tc.method, tc.path, stub.gotTenant, tenant)
		}
	}
	if stub.gotSource.Kind != identity.SourceImported || stub.gotSource.Ref != "netbox:x" {
		t.Errorf("source passed through as %+v", stub.gotSource)
	}
}

// An admission check that cannot be answered is a 500 naming its stage —
// never a 200 "allowed".
func TestContract_SourceImport_AdmissionErrorNamesItsStage(t *testing.T) {
	sv := loadSpec(t)
	for _, tc := range []struct {
		err   error
		stage string
	}{
		{fmt.Errorf("%w: resolver down", services.ErrAssetLimit), "limit"},
		{fmt.Errorf("%w: engine down", services.ErrAdmissionPolicy), "policy"},
	} {
		e := sourceContractEngine(&stubSourceImporter{admissionErr: tc.err})
		w := httptest.NewRecorder()
		e.ServeHTTP(w, signedSourceCall(http.MethodPost, "/api/v1/inventory-service/internal/sources/assets/admission", `{"count":1}`, uuid.New()))
		if w.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500", w.Code)
		}
		sv.assertConforms(t, "SourceAdmissionError", w.Body.Bytes())
		if !bytes.Contains(w.Body.Bytes(), []byte(`"stage":"`+tc.stage+`"`)) {
			t.Errorf("body %s does not name stage %q", w.Body.String(), tc.stage)
		}
	}
}

// Only `imported` is a source a connector may claim; a batch outside the
// bounds is refused before the service runs.
func TestContract_SourceImport_RefusesBadRequests(t *testing.T) {
	stub := &stubSourceImporter{}
	e := sourceContractEngine(stub)
	var big bytes.Buffer
	big.WriteString(`{"segments":[`)
	for i := 0; i <= services.MaxSourceBatch; i++ {
		if i > 0 {
			big.WriteString(",")
		}
		big.WriteString(`{"cidr":"10.0.0.0/24","source_ref":"r"}`)
	}
	big.WriteString(`]}`)
	for _, tc := range []struct{ path, body string }{
		{"/assets", `{"source":{"kind":"measured","ref":"sensor:x"},"assets":[{"class_key":"switch"}]}`},
		{"/assets", `{"source":{"kind":"imported","ref":""},"assets":[{"class_key":"switch"}]}`},
		{"/assets", `{"source":{"kind":"imported","ref":"netbox:x"},"assets":[]}`},
		{"/segments", big.String()},
		{"/assets/admission", `{"count":-1}`},
		{"/assets/links", `{"source":{"kind":"declared","ref":"cmdb:p"},"links":[{"asset_id":"` + uuid.NewString() + `","kind":"cmdb_sys_id","value":"v","scope":"p"}]}`},
		{"/assets/links", `{"source":{"kind":"imported","ref":"cmdb:p"},"links":[]}`},
		{"/assets/presence", `{"source":{"kind":"measured","ref":"cmdb:p"},"items":[{"asset_id":"` + uuid.NewString() + `","presence":"absent"}]}`},
		{"/assets/presence", `{"source":{"kind":"imported","ref":"cmdb:p"},"items":[]}`},
		{"/assets/runs", `{"source":{"kind":"imported","ref":"cmdb:p"},"items":[{"asset_id":"` + uuid.NewString() + `","action":"created"}]}`},
		{"/assets/runs", `{"source":{"kind":"measured","ref":"cmdb:p"},"run_id":"` + uuid.NewString() + `","items":[{"asset_id":"` + uuid.NewString() + `","action":"created"}]}`},
		{"/assets/archive", `{"source":{"kind":"imported","ref":"cmdb:p"},"asset_ids":["` + uuid.NewString() + `"]}`},
		{"/assets/archive", `{"source":{"kind":"imported","ref":"cmdb:p"},"run_id":"` + uuid.NewString() + `","asset_ids":[]}`},
		{"/scan-consent", `{"source":{"kind":"imported","ref":"cmdb:p"}}`},
		{"/scan-consent", `{"source":{"kind":"measured","ref":"sensor:x"},"allow_active_scan":true}`},
		{"/assets/archive", `{"source":{"kind":"declared","ref":"cmdb:p"},"run_id":"` + uuid.NewString() + `","asset_ids":["` + uuid.NewString() + `"]}`},
	} {
		w := httptest.NewRecorder()
		method := http.MethodPost
		if tc.path == "/scan-consent" {
			method = http.MethodPut
		}
		e.ServeHTTP(w, signedSourceCall(method, "/api/v1/inventory-service/internal/sources"+tc.path, tc.body, uuid.New()))
		if w.Code != http.StatusBadRequest {
			t.Errorf("POST %s %.60s… = %d, want 400", tc.path, tc.body, w.Code)
		}
	}
	if stub.gotTenant != uuid.Nil {
		t.Error("the service ran for a request that should have been refused")
	}
}
