package handlers

// Contract test for the network-segments HTTP surface (CMDB network segments).
// Extends the inventory-service spec-first contract (ADR-0001) and reuses the
// shared harness (loadSpec / assertConforms / do / strPtr / aUUID) from
// asset_contract_test.go — only the segment stub + engine + cases live here.
//
// NetworkSegmentHandler was made testable by depending on the
// networkSegmentService interface (the concrete *services.NetworkSegmentService
// still satisfies it), so these tests drive the real handlers with an in-memory
// stub — no database.

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
)

// --- stub networkSegmentService --------------------------------------------

type stubNetworkSegmentService struct {
	list    []models.NetworkSegment
	total   int
	listErr error
	byID    *models.NetworkSegment
	byIDErr error
	// write surface
	createResult *models.NetworkSegment
	createErr    error
	updateResult *models.NetworkSegment
	updateErr    error
	updateInput  models.NetworkSegmentInput // what the handler handed to Update
	deleteErr    error
	// cloud classification (B-49)
	cloudSegment    *models.NetworkSegment
	cloudSegmentErr error
}

func (s *stubNetworkSegmentService) List(uuid.UUID, models.NetworkSegmentFilters) ([]models.NetworkSegment, int, error) {
	return s.list, s.total, s.listErr
}
func (s *stubNetworkSegmentService) GetByID(uuid.UUID, uuid.UUID) (*models.NetworkSegment, error) {
	return s.byID, s.byIDErr
}
func (s *stubNetworkSegmentService) Create(uuid.UUID, models.NetworkSegmentInput) (*models.NetworkSegment, error) {
	return s.createResult, s.createErr
}
func (s *stubNetworkSegmentService) BulkCreate(_ uuid.UUID, inputs []models.NetworkSegmentInput) *models.BulkImportResult {
	res := models.NewBulkImportResult(len(inputs))
	for i := range inputs {
		res.Add(i, models.BulkRowCreated, nil, "")
	}
	return res
}
func (s *stubNetworkSegmentService) Update(_ uuid.UUID, _ uuid.UUID, in models.NetworkSegmentInput) (*models.NetworkSegment, error) {
	s.updateInput = in
	return s.updateResult, s.updateErr
}
func (s *stubNetworkSegmentService) Delete(uuid.UUID, uuid.UUID) error                  { return s.deleteErr }
func (s *stubNetworkSegmentService) ManageAutoApprovalRules(uuid.UUID, uuid.UUID) error { return nil }
func (s *stubNetworkSegmentService) GetSegmentForIP(uuid.UUID, *string, *string) (*models.NetworkSegment, error) {
	return nil, nil
}
func (s *stubNetworkSegmentService) ClassifyAsset(uuid.UUID, *string, *string, []string) (string, error) {
	return "", nil
}
func (s *stubNetworkSegmentService) FindOrCreateCloudSegment(uuid.UUID, string, string, string, string) (*models.NetworkSegment, error) {
	return s.cloudSegment, s.cloudSegmentErr
}
func (s *stubNetworkSegmentService) ReclassifyAllAssets(uuid.UUID) (int, error)      { return 0, nil }
func (s *stubNetworkSegmentService) MigrateFromNetworkSpaces(uuid.UUID) (int, error) { return 0, nil }

func newSegmentEngine(svc *stubNetworkSegmentService) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group("/api/v2/inventory-service")
	grp.Use(func(c *gin.Context) {
		c.Set("tenantID", uuid.New())
		c.Next()
	})
	h := &NetworkSegmentHandler{segmentService: svc}
	grp.GET("/network-segments", h.GetNetworkSegments)
	grp.POST("/network-segments", h.CreateNetworkSegment)
	grp.GET("/network-segments/:id", h.GetNetworkSegment)
	grp.PUT("/network-segments/:id", h.UpdateNetworkSegment)
	grp.DELETE("/network-segments/:id", h.DeleteNetworkSegment)
	return r
}

func sampleSegment() models.NetworkSegment {
	now := time.Now().UTC()
	return models.NetworkSegment{
		ID:                     uuid.New(),
		TenantID:               uuid.New(),
		Name:                   "prod-vpc-east",
		SegmentType:            "cloud_vpc",
		Value:                  "10.0.0.0/16",
		NetworkType:            "cloud",
		Environment:            "production",
		LocationID:             uuidPtr(uuid.New()),
		BusinessUnit:           strPtr("platform"),
		OwnerEmail:             strPtr("ops@example.com"),
		IsActive:               true,
		AutoApproveDiscoveries: false,
		Tags:                   models.JSONB{"team": "infra"},
		Metadata:               models.JSONB{"region": "us-east-1"},
		CreatedAt:              now,
		UpdatedAt:              now,
	}
}

// minimalSegment leaves omitempty fields unset and the nullable maps nil.
func minimalSegment() models.NetworkSegment {
	now := time.Now().UTC()
	return models.NetworkSegment{
		ID:          uuid.New(),
		TenantID:    uuid.New(),
		Name:        "lab-range",
		SegmentType: "ip_range",
		Value:       "192.168.1.1-192.168.1.254",
		NetworkType: "private",
		Environment: "test",
		// LocationID intentionally nil — exercises the optional/nullable location path.
		IsActive:  true,
		CreatedAt: now,
		UpdatedAt: now,
	}
}

func uuidPtr(u uuid.UUID) *uuid.UUID { return &u }

const nsBase = "/api/v2/inventory-service"

// --- the contract tests ----------------------------------------------------

func TestContract_ListNetworkSegments_200(t *testing.T) {
	sv := loadSpec(t)
	eng := newSegmentEngine(&stubNetworkSegmentService{list: []models.NetworkSegment{sampleSegment(), minimalSegment()}, total: 2})
	w := do(eng, http.MethodGet, nsBase+"/network-segments", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "NetworkSegmentListResponse", w.Body.Bytes())
}

func TestContract_GetNetworkSegment_200(t *testing.T) {
	sv := loadSpec(t)
	seg := sampleSegment()
	eng := newSegmentEngine(&stubNetworkSegmentService{byID: &seg})
	w := do(eng, http.MethodGet, nsBase+"/network-segments/"+aUUID, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "NetworkSegment", w.Body.Bytes())
}

func TestContract_GetNetworkSegment_400_badID(t *testing.T) {
	sv := loadSpec(t)
	eng := newSegmentEngine(&stubNetworkSegmentService{})
	w := do(eng, http.MethodGet, nsBase+"/network-segments/not-a-uuid", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// A nil segment (no error) maps to 404.
func TestContract_GetNetworkSegment_404(t *testing.T) {
	sv := loadSpec(t)
	eng := newSegmentEngine(&stubNetworkSegmentService{byID: nil})
	w := do(eng, http.MethodGet, nsBase+"/network-segments/"+aUUID, nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_NetworkSegment_DriftIsCaught(t *testing.T) {
	sv := loadSpec(t)
	sch, err := sv.compiler.Compile(specBaseURI + "#/components/schemas/NetworkSegment")
	if err != nil {
		t.Fatalf("compile NetworkSegment: %v", err)
	}
	bad, err := jsonschema.UnmarshalJSON(strings.NewReader(
		`{"id":"` + aUUID + `","surprise_field":true}`))
	if err != nil {
		t.Fatalf("unmarshal bad body: %v", err)
	}
	if err := sch.Validate(bad); err == nil {
		t.Fatal("expected validation to FAIL for a drifted NetworkSegment, but it passed — the guardrail is not actually checking")
	}
}

// --- write surface: create / update / delete -------------------------

const validSegmentBody = `{"name":"prod-vpc","segment_type":"cloud_vpc","value":"10.0.0.0/16","network_type":"cloud","environment":"production"}`

func TestContract_CreateNetworkSegment_201(t *testing.T) {
	sv := loadSpec(t)
	seg := sampleSegment()
	eng := newSegmentEngine(&stubNetworkSegmentService{createResult: &seg})
	w := do(eng, http.MethodPost, nsBase+"/network-segments", strings.NewReader(validSegmentBody))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "NetworkSegment", w.Body.Bytes())
}

func TestContract_CreateNetworkSegment_400_badBody(t *testing.T) {
	sv := loadSpec(t)
	eng := newSegmentEngine(&stubNetworkSegmentService{})
	w := do(eng, http.MethodPost, nsBase+"/network-segments", strings.NewReader(`{`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// An unknown location_id surfaces as 400 "Invalid request".
func TestContract_CreateNetworkSegment_400_unknownLocation(t *testing.T) {
	sv := loadSpec(t)
	eng := newSegmentEngine(&stubNetworkSegmentService{createErr: errors.New("location not found")})
	w := do(eng, http.MethodPost, nsBase+"/network-segments", strings.NewReader(validSegmentBody))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_CreateNetworkSegment_500(t *testing.T) {
	sv := loadSpec(t)
	eng := newSegmentEngine(&stubNetworkSegmentService{createErr: io.EOF})
	w := do(eng, http.MethodPost, nsBase+"/network-segments", strings.NewReader(validSegmentBody))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_UpdateNetworkSegment_200(t *testing.T) {
	sv := loadSpec(t)
	seg := sampleSegment()
	eng := newSegmentEngine(&stubNetworkSegmentService{updateResult: &seg})
	w := do(eng, http.MethodPut, nsBase+"/network-segments/"+aUUID, strings.NewReader(validSegmentBody))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "NetworkSegment", w.Body.Bytes())
}

func TestContract_UpdateNetworkSegment_400_badID(t *testing.T) {
	sv := loadSpec(t)
	eng := newSegmentEngine(&stubNetworkSegmentService{})
	w := do(eng, http.MethodPut, nsBase+"/network-segments/not-a-uuid", strings.NewReader(validSegmentBody))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_UpdateNetworkSegment_404(t *testing.T) {
	sv := loadSpec(t)
	eng := newSegmentEngine(&stubNetworkSegmentService{updateErr: errors.New("network segment not found")})
	w := do(eng, http.MethodPut, nsBase+"/network-segments/"+aUUID, strings.NewReader(validSegmentBody))
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_DeleteNetworkSegment_204(t *testing.T) {
	eng := newSegmentEngine(&stubNetworkSegmentService{})
	w := do(eng, http.MethodDelete, nsBase+"/network-segments/"+aUUID, nil)
	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, want 204; body=%s", w.Code, w.Body.String())
	}
	if w.Body.Len() != 0 {
		t.Fatalf("expected empty body on 204, got: %s", w.Body.String())
	}
}

func TestContract_DeleteNetworkSegment_400_badID(t *testing.T) {
	sv := loadSpec(t)
	eng := newSegmentEngine(&stubNetworkSegmentService{})
	w := do(eng, http.MethodDelete, nsBase+"/network-segments/not-a-uuid", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_DeleteNetworkSegment_404(t *testing.T) {
	sv := loadSpec(t)
	eng := newSegmentEngine(&stubNetworkSegmentService{deleteErr: sql.ErrNoRows})
	w := do(eng, http.MethodDelete, nsBase+"/network-segments/"+aUUID, nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- DHCP posture ( Phase 1a) ------------------------------------------

// The response carries the effective posture and whose statement it is, and both
// are null — not false, not absent — for a segment nobody has spoken for.
func TestContract_NetworkSegment_ExposesDHCPPosture(t *testing.T) {
	sv := loadSpec(t)
	yes, src, name := true, "measured", "edge-router"
	measured := sampleSegment()
	measured.Dynamic, measured.DynamicSource, measured.DynamicSourceName = &yes, &src, &name
	silent := minimalSegment()

	for label, seg := range map[string]models.NetworkSegment{"measured": measured, "unknown": silent} {
		s := seg
		w := do(newSegmentEngine(&stubNetworkSegmentService{byID: &s}), http.MethodGet, nsBase+"/network-segments/"+aUUID, nil)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: status = %d, want 200; body=%s", label, w.Code, w.Body.String())
		}
		sv.assertConforms(t, "NetworkSegment", w.Body.Bytes())
		var got map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if _, has := got["dynamic"]; !has {
			t.Fatalf("%s: dynamic is absent from the response; unknown must be an explicit null", label)
		}
		if _, has := got["dynamic_source"]; !has {
			t.Fatalf("%s: dynamic_source is absent from the response", label)
		}
	}
	w := do(newSegmentEngine(&stubNetworkSegmentService{byID: &measured}), http.MethodGet, nsBase+"/network-segments/"+aUUID, nil)
	if !strings.Contains(w.Body.String(), `"dynamic":true`) || !strings.Contains(w.Body.String(), `"dynamic_source":"measured"`) {
		t.Fatalf("posture not serialised: %s", w.Body.String())
	}
}

// PUT `dhcp` is three-valued and the handler must tell the three apart:
// absent keeps, true/false sets, null clears. A *bool decodes absent and null
// to the same nil, which is how "keep" and "clear" would silently swap.
func TestContract_UpdateNetworkSegment_DHCPIsThreeValued(t *testing.T) {
	sv := loadSpec(t)
	const head = `{"name":"lan","segment_type":"cidr","value":"192.0.2.0/24","network_type":"private","environment":"production"`
	for _, c := range []struct {
		name, body string
		set        bool
		val        *bool
	}{
		{"absent keeps", head + `}`, false, nil},
		{"true sets", head + `,"dhcp":true}`, true, boolP(true)},
		{"false sets", head + `,"dhcp":false}`, true, boolP(false)},
		{"null clears", head + `,"dhcp":null}`, true, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			// The body is a valid NetworkSegmentInput per the spec...
			sv.assertConforms(t, "NetworkSegmentInput", []byte(c.body))
			// ...and reaches the service as the state it names.
			seg := sampleSegment()
			stub := &stubNetworkSegmentService{updateResult: &seg}
			w := do(newSegmentEngine(stub), http.MethodPut, nsBase+"/network-segments/"+aUUID, strings.NewReader(c.body))
			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
			}
			got := stub.updateInput.DHCP
			if got.Set != c.set || (got.Value == nil) != (c.val == nil) || (got.Value != nil && *got.Value != *c.val) {
				t.Fatalf("service saw dhcp = {Set:%v Value:%v}, want {Set:%v Value:%v}", got.Set, got.Value, c.set, c.val)
			}
		})
	}
}

// A dhcp that is not a boolean is refused at the door, by the spec and by the
// handler, with the message the form shows.
func TestContract_UpdateNetworkSegment_DHCPMustBeABoolean(t *testing.T) {
	sv := loadSpec(t)
	bad := `{"name":"lan","segment_type":"cidr","value":"192.0.2.0/24","network_type":"private","environment":"production","dhcp":"yes"}`
	sch, err := sv.compiler.Compile(specBaseURI + "#/components/schemas/NetworkSegmentInput")
	if err != nil {
		t.Fatal(err)
	}
	inst, err := jsonschema.UnmarshalJSON(strings.NewReader(bad))
	if err != nil {
		t.Fatal(err)
	}
	if err := sch.Validate(inst); err == nil {
		t.Fatal("the spec accepted dhcp:\"yes\" — the guardrail is not checking the field")
	}
	w := do(newSegmentEngine(&stubNetworkSegmentService{}), http.MethodPut, nsBase+"/network-segments/"+aUUID, strings.NewReader(bad))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// A DHCP answer on a segment type that cannot hold a lease is a field error the
// person at the form can act on, not a 500.
func TestContract_UpdateNetworkSegment_400_dhcpNotApplicable(t *testing.T) {
	sv := loadSpec(t)
	eng := newSegmentEngine(&stubNetworkSegmentService{updateErr: fmt.Errorf("%w: %q is neither", services.ErrDHCPNotApplicable, "domain")})
	w := do(eng, http.MethodPut, nsBase+"/network-segments/"+aUUID, strings.NewReader(validSegmentBody))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func boolP(b bool) *bool { return &b }
