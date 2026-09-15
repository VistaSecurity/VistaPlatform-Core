package handlers

// The contract between the measurement REGISTRY and the catalogue endpoint the
// rule builder reads (workstream 3.6).
//
// Two directions, and both have bitten this codebase in other places:
//
//   - every registered measurement type must be OFFERED. A type the extractor
//     implements but the rule builder never lists is a capability with no
//     consumer — the orphan-layer failure the feature framework exists to stop.
//   - nothing else may be offered. A row left in `measurement_types` by an
//     older release is a measurement type the extractor no longer serves, and a
//     control authored against it evaluates to nothing forever: a check that
//     cannot fail, which is worse than no check.
//
// It runs against a seeded database rather than a fake, because the thing being
// asserted IS that the seed and the registry agree.
//
// Skips without TEST_DATABASE_URL (shared/testdb); `make test-integration-db`.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func measurementCatalogRouter(t *testing.T) *gin.Engine {
	t.Helper()
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := sqlx.NewDb(raw, "postgres")

	gin.SetMode(gin.TestMode)
	r := gin.New()
	h := NewMeasurementHandlers(db)
	// The REAL routes, as cmd/main.go registers them. Driving the handler
	// function directly would pass with the routes deleted.
	r.GET("/measurement-types", h.ListMeasurementTypes)
	r.GET("/measurement-types/:code", h.GetMeasurementType)
	return r
}

func TestIntegration_MeasurementCatalog_OffersExactlyTheRegistry(t *testing.T) {
	r := measurementCatalogRouter(t)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/measurement-types", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}

	var body struct {
		MeasurementTypes []models.MeasurementType `json:"measurement_types"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}

	got := make([]string, 0, len(body.MeasurementTypes))
	for _, mt := range body.MeasurementTypes {
		got = append(got, mt.Code)
		if mt.ID.String() == "00000000-0000-0000-0000-000000000000" {
			t.Errorf("%s: no id — the rule builder posts this id as measurement_type_id and "+
				"control_measurements has a foreign key on it", mt.Code)
		}
	}
	want := services.MeasurementTypeCodes()
	sort.Strings(got)

	if len(got) != len(want) {
		t.Errorf("offered %d measurement types, registry declares %d\noffered:  %v\nregistry: %v",
			len(got), len(want), got, want)
	}
	inRegistry := map[string]bool{}
	for _, code := range want {
		inRegistry[code] = true
	}
	offered := map[string]bool{}
	for _, code := range got {
		offered[code] = true
		if !inRegistry[code] {
			t.Errorf("offered %q, which the registry does not declare — a rule authored against it "+
				"would evaluate to nothing, forever and silently", code)
		}
	}
	for _, code := range want {
		if !offered[code] {
			t.Errorf("registry declares %q but the catalogue does not offer it — either the seed "+
				"did not run, or a measurement type shipped with no way to author a rule for it", code)
		}
	}
}

// TestIntegration_MeasurementCatalog_ServesTheRegistrysMeaning pins the OTHER
// half: the rows carry the registry's data type, rule types and value sets, not
// whatever an older release happened to seed into the table. The rule builder
// validates a predicate against exactly these fields.
func TestIntegration_MeasurementCatalog_ServesTheRegistrysMeaning(t *testing.T) {
	r := measurementCatalogRouter(t)

	for _, def := range services.MeasurementTypes() {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/measurement-types/"+def.Code, nil))
		if w.Code != http.StatusOK {
			t.Errorf("%s: status = %d, want 200", def.Code, w.Code)
			continue
		}
		var body struct {
			MeasurementType models.MeasurementType `json:"measurement_type"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Errorf("%s: decode: %v", def.Code, err)
			continue
		}
		mt := body.MeasurementType
		if mt.DataType != def.DataType {
			t.Errorf("%s: data_type = %q, want %q", def.Code, mt.DataType, def.DataType)
		}
		if len(mt.AllowedRuleTypes) != len(def.AllowedRuleTypes) {
			t.Errorf("%s: allowed_rule_types = %v, want %v", def.Code, mt.AllowedRuleTypes, def.AllowedRuleTypes)
		}
		if len(mt.EnumValues) != len(def.EnumValues) {
			t.Errorf("%s: enum_values = %v, want %v", def.Code, mt.EnumValues, def.EnumValues)
		}
		if mt.Name != def.Name {
			t.Errorf("%s: name = %q, want %q", def.Code, mt.Name, def.Name)
		}
	}
}

func TestIntegration_MeasurementCatalog_UnknownCodeIs404(t *testing.T) {
	r := measurementCatalogRouter(t)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/measurement-types/not_a_measurement", nil))
	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want 404", w.Code)
	}
}
