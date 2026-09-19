package handlers

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
)

func TestContract_IdentityObservationEvidence(t *testing.T) {
	spec := loadSpec(t)
	b, err := json.Marshal(services.IdentitySummary{Legacy: 2, Unresolved: 3})
	if err != nil {
		t.Fatal(err)
	}
	spec.assertConforms(t, "IdentitySummary", b)
	b, err = json.Marshal(services.IdentityObservation{ID: uuid.New(), SourceKind: "measured", SourceRef: "sensor:test",
		Evidence:         json.RawMessage(`{"identifiers":[{"kind":"hostname","value":"anonymous.local"}]}`),
		AdmissionReasons: []string{"no_device_or_address_binding"}, State: "unresolved", FirstSeenAt: time.Now(), LastSeenAt: time.Now(), OccurrenceCount: 1, EnrichmentState: "waiting"})
	if err != nil {
		t.Fatal(err)
	}
	spec.assertConforms(t, "IdentityObservation", b)
}

func TestIdentityObservationFiltersRejectInvalidInput(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.Use(func(c *gin.Context) { c.Set("tenantID", uuid.New()); c.Next() })
	handler := NewIdentityObservationHandler(nil)
	engine.GET("/observations", handler.List)
	for _, q := range []string{"page=0", "page_size=101", "state=unknown", "asset_id=not-a-uuid"} {
		t.Run(q, func(t *testing.T) {
			w := do(engine, http.MethodGet, "/observations?"+q, nil)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
		})
	}
}
