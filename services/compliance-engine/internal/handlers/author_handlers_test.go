package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
)

// Core's answer to "can this deployment draft controls from a standard?".
//
// It is the answer the majority of deployments serve, and the one both
// authoring UIs ask before deciding whether to render the button.
func TestAuthorAvailability_CoreSaysEditionRatherThanJustNo(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	// The zero value is what cmd/main.go passes when the edition hook is nil.
	r.GET("/availability", NewAuthorHandlers(models.AuthorAvailability{}).GetAvailability)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/availability", nil))

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	var got models.AuthorAvailability
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Available {
		t.Fatal("Core has no generative author and must not report one")
	}
	// "No" without "why" sends an operator who configured a provider looking in
	// the wrong place. The two nos have different fixes.
	if got.Reason != models.AuthorReasonEdition {
		t.Fatalf("Reason = %q, want %q", got.Reason, models.AuthorReasonEdition)
	}
}

// A constructor that filled in a reason must not also fill in availability, and
// an explicitly available seam must keep its provider name.
func TestAuthorAvailability_PassesAnEnterpriseAnswerThrough(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/availability", NewAuthorHandlers(models.AuthorAvailability{
		Available: true, Provider: "anthropic",
	}).GetAvailability)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/availability", nil))

	var got models.AuthorAvailability
	_ = json.Unmarshal(w.Body.Bytes(), &got)
	if !got.Available || got.Provider != "anthropic" {
		t.Fatalf("got %+v", got)
	}
	if got.Reason != "" {
		t.Fatalf("Reason = %q, want empty when available", got.Reason)
	}
}

// The admin GET route tree, exactly as cmd/main.go builds it, plus the new
// availability route.
//
// This is a startup test wearing a routing test's clothes. gin PANICS at
// REGISTRATION time on a wildcard conflict, so `/frameworks/draft-controls/...`
// sitting beside `/frameworks/:id` is not a 404 risk — it is a
// compliance-engine that cannot start. The pattern is already proven in this
// group by `/frameworks/versions/:versionId`, and this pins it rather than
// leaving it to be discovered by a pod that crashloops.
//
// The route list is duplicated from main.go because main.go builds it inline
// and there is nothing to import. It only has to stay complete enough to
// contain every SIBLING of the new route, which is what a conflict needs.
func TestAdminGetTree_AcceptsTheDraftingAvailabilityRoute(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	admin := r.Group("/api/v1/compliance-engine/admin")

	echo := func(c *gin.Context) { c.String(http.StatusOK, c.FullPath()) }

	admin.GET("/alerts", echo)
	admin.GET("/frameworks", echo)
	admin.GET("/frameworks/:id", echo)
	admin.GET("/frameworks/:id/versions", echo)
	admin.GET("/frameworks/versions/:versionId", echo)
	admin.GET("/controls/:id/measurements", echo)
	admin.GET("/templates", echo)
	admin.GET("/templates/:id", echo)
	admin.GET("/tenants/:tenantId/subscriptions", echo)
	// The one this test exists for.
	admin.GET("/frameworks/draft-controls/availability", echo)

	cases := map[string]string{
		"/api/v1/compliance-engine/admin/frameworks/draft-controls/availability": "/api/v1/compliance-engine/admin/frameworks/draft-controls/availability",
		// The param sibling must still resolve — a static child that swallowed
		// it would break every framework read on the catalog page.
		"/api/v1/compliance-engine/admin/frameworks/11111111-1111-1111-1111-111111111111":          "/api/v1/compliance-engine/admin/frameworks/:id",
		"/api/v1/compliance-engine/admin/frameworks/versions/22222222-2222-2222-2222-222222222222": "/api/v1/compliance-engine/admin/frameworks/versions/:versionId",
	}
	for path, want := range cases {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, path, nil))
		if got := w.Body.String(); got != want {
			t.Errorf("GET %s routed to %q, want %q", path, got, want)
		}
	}
}
