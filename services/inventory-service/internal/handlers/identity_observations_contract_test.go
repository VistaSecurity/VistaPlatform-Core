package handlers

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
)

func TestContract_IdentityObservationEvidence(t *testing.T) {
	spec := loadSpec(t)
	b, err := json.Marshal(services.IdentitySummary{Legacy: 2, Unresolved: 3, AdmissionMode: "disabled"})
	if err != nil {
		t.Fatal(err)
	}
	spec.assertConforms(t, "IdentitySummary", b)
	network := "Office LAN"
	b, err = json.Marshal(services.IdentityObservation{ID: uuid.New(), SourceKind: "measured", SourceRef: "sensor:test",
		Evidence:         json.RawMessage(`{"identifiers":[{"kind":"hostname","value":"anonymous.local"}]}`),
		AdmissionReasons: []string{"no_device_or_address_binding"}, State: "unresolved", FirstSeenAt: time.Now(), LastSeenAt: time.Now(), OccurrenceCount: 1, EnrichmentState: "waiting",
		NetworkName: &network, SourceName: "Sensor", Needs: services.NeedsLikelyNoise, SuggestedAction: services.SuggestDismiss,
		ExplanationCode: services.ExplainNameOnly, SuggestedReason: "Dismissed from Observations: A device seen as anonymous.local.",
		Summary: []services.ObservationIdentifierSummary{{Kind: "hostname", Label: "Hostname", Value: "anonymous.local"}}})
	if err != nil {
		t.Fatal(err)
	}
	spec.assertConforms(t, "IdentityObservation", b)
	// A link suggestion carries the owner it points at.
	b, err = json.Marshal(services.IdentityObservation{ID: uuid.New(), SourceKind: "measured", SourceRef: "sensor:test",
		Evidence:         json.RawMessage(`{"identifiers":[{"kind":"ip_address","value":"192.0.2.10"}]}`),
		AdmissionReasons: []string{"dynamic_address_without_device_binding"}, State: "unresolved", FirstSeenAt: time.Now(), LastSeenAt: time.Now(), OccurrenceCount: 1, EnrichmentState: "waiting",
		SourceName: "Sensor", Needs: services.NeedsLinkExisting, SuggestedAction: services.SuggestLink,
		ExplanationCode: services.ExplainOwnedByAsset, SuggestedReason: "Linked from Observations: A device seen at 192.0.2.10 — already belongs to dream-router.",
		Summary:   []services.ObservationIdentifierSummary{},
		LinkAsset: &services.ObservationOwner{ID: uuid.New(), Name: "dream-router", Linkable: true}})
	if err != nil {
		t.Fatal(err)
	}
	spec.assertConforms(t, "IdentityObservation", b)
}

// Every needs value, suggested action and explanation code the Go side can
// produce is in the spec's enums — a new code added in Go alone would reach
// the UI as a value its generated types say cannot exist.
func TestContract_ObservationReviewVocabulary(t *testing.T) {
	spec := loadSpec(t)
	for _, needs := range services.ObservationNeedsValues {
		b, _ := json.Marshal(needs)
		spec.assertConforms(t, "ObservationNeeds", b)
	}
	b, err := json.Marshal(services.ObservationNeedsCounts{ReadyToConfirm: 1, LinkExisting: 1, NeedsReview: 1, All: 3})
	if err != nil {
		t.Fatal(err)
	}
	spec.assertConforms(t, "ObservationNeedsCounts", b)
	b, err = json.Marshal(BulkObservationResponse{BatchID: uuid.New(), Results: []BulkObservationResult{
		{ID: uuid.New(), Outcome: "ok", Status: http.StatusOK, Message: "Confirmed", AssetID: uuid.NewString()},
		{ID: uuid.New(), Outcome: "failed", Status: http.StatusUnprocessableEntity, Code: "not_ready_to_confirm", Message: services.ErrObservationNotReady.Error()},
	}})
	if err != nil {
		t.Fatal(err)
	}
	spec.assertConforms(t, "BulkObservationDecisionResult", b)
	for _, err := range []error{services.ErrObservationNotFound, services.ErrObservationProvisionalMerge, services.ErrObservationChanged,
		services.ErrObservationAllowance, services.ErrObservationNotReady, errors.New("anything else")} {
		status, code, message := observationErrorResponse(err)
		b, _ := json.Marshal(BulkObservationResponse{BatchID: uuid.New(), Results: []BulkObservationResult{{ID: uuid.New(), Outcome: "failed", Status: status, Code: code, Message: message}}})
		spec.assertConforms(t, "BulkObservationDecisionResult", b)
	}
}

func TestBulkObservationRejectsInvalidRequests(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.Use(func(c *gin.Context) { c.Set("tenantID", uuid.New()); c.Set("userID", uuid.New()); c.Next() })
	engine.POST("/bulk", NewIdentityObservationHandler(nil).Bulk)
	id := `"` + uuid.NewString() + `"`
	for name, body := range map[string]string{
		"no ids":       `{"action":"confirm","ids":[],"reason":"r"}`,
		"relink":       `{"action":"relink","ids":[` + id + `],"reason":"r"}`,
		"blank reason": `{"action":"dismiss","ids":[` + id + `],"reason":"   "}`,
		"bad uuid":     `{"action":"dismiss","ids":["nope"],"reason":"r"}`,
		"missing ids":  `{"action":"dismiss","reason":"r"}`,
		"201 ids":      `{"action":"dismiss","ids":[` + strings.TrimSuffix(strings.Repeat(id+",", 201), ",") + `],"reason":"r"}`,
		"long name":    `{"action":"confirm","ids":[` + id + `],"reason":"r","name":"` + strings.Repeat("n", 256) + `"}`,
		"not json":     `action=confirm`,
	} {
		t.Run(name, func(t *testing.T) {
			w := do(engine, http.MethodPost, "/bulk", strings.NewReader(body))
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
		})
	}
}

func TestIdentityObservationFiltersRejectInvalidInput(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	engine.Use(func(c *gin.Context) { c.Set("tenantID", uuid.New()); c.Next() })
	handler := NewIdentityObservationHandler(nil)
	engine.GET("/observations", handler.List)
	for _, q := range []string{"page=0", "page_size=101", "state=unknown", "asset_id=not-a-uuid",
		"needs=bogus", "needs=ready_to_confirm,bogus", "needs=ready_to_confirm&needs=bogus", "network_scope=tenant",
		"sort=random", "q=" + strings.Repeat("x", 201), "source=" + strings.Repeat("s", 256)} {
		t.Run(q, func(t *testing.T) {
			w := do(engine, http.MethodGet, "/observations?"+q, nil)
			if w.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
		})
	}
}
