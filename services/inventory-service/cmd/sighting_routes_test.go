package main

// The internal sightings route (platform ADR-0003 D3 step 2) admits a signed
// service call and NOTHING else. Like source_import_routes_test.go, these drive
// mountSightingRoutes — the function main() calls — on a gin engine that also
// carries a user group, so the WIRING is pinned: deleting the gate, or
// re-homing the route onto the user group, turns them red.

import (
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/handlers"
	"github.com/vistasecurity/vistaplatform/shared/serviceauth"
)

const sightingsPath = "/api/v1/inventory-service/internal/sightings"

func sightingEngine(t *testing.T, secret string) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	users := r.Group("/api/v1")
	users.Use(func(c *gin.Context) {
		if !strings.HasPrefix(c.GetHeader("Authorization"), "Bearer ") {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		c.Next()
	})
	users.GET("/inventory-service/assets", func(c *gin.Context) { c.Status(http.StatusOK) })
	mountSightingRoutes(r, handlers.NewSightingHandler(nil), secret)
	return r
}

func TestSightingRoute_RefusesEverythingButASignedCall(t *testing.T) {
	e := sightingEngine(t, sourceTestSecret)
	cases := map[string]func(*http.Request){
		"no credentials":             func(*http.Request) {},
		"a tenant token":             func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+tenantToken(t)) },
		"an unsigned internal flag":  func(r *http.Request) { r.Header.Set(serviceauth.HeaderServiceCall, "true") },
		"another secret's signature": func(r *http.Request) { serviceauth.NewSigner("some-other-secret-0123456789abcdef").SignRequest(r) },
		"a tenant swapped after signing": func(r *http.Request) {
			serviceauth.NewSigner(sourceTestSecret).SignRequest(r)
			r.Header.Set(serviceauth.HeaderTenantID, uuid.NewString())
		},
	}
	for name, mutate := range cases {
		req := sourceRequest(http.MethodPost, sightingsPath, []byte(`{"sightings":[]}`))
		req.Header.Set(serviceauth.HeaderTenantID, uuid.NewString())
		mutate(req)
		if w := serve(e, req); w.Code != http.StatusUnauthorized {
			t.Errorf("%s = %d, want 401", name, w.Code)
		}
	}
}

// The positive polarity: a signed call naming a tenant reaches the handler,
// which refuses the empty batch with its own 400.
func TestSightingRoute_AdmitsASignedServiceCall(t *testing.T) {
	e := sightingEngine(t, sourceTestSecret)
	req := sourceRequest(http.MethodPost, sightingsPath, []byte(`{"sightings":[]}`))
	req.Header.Set(serviceauth.HeaderTenantID, uuid.NewString())
	serviceauth.NewSigner(sourceTestSecret).SignRequest(req)
	w := serve(e, req)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "between 1 and") {
		t.Fatalf("a signed call = %d %s, want the handler's own 400", w.Code, w.Body.String())
	}
}

func TestSightingRoute_FailsClosedWithoutASecret(t *testing.T) {
	e := sightingEngine(t, "")
	req := sourceRequest(http.MethodPost, sightingsPath, []byte(`{"sightings":[]}`))
	req.Header.Set(serviceauth.HeaderTenantID, uuid.NewString())
	serviceauth.NewSigner("anything-at-all-0123456789").SignRequest(req)
	if w := serve(e, req); w.Code != http.StatusUnauthorized {
		t.Errorf("with no INTERNAL_AUTH_SECRET a signed call = %d, want 401", w.Code)
	}
}

// The gateway-links route rides the same gate: only a signed call
// reaches its handler, which refuses a body with no asset with its own 400.
func TestGatewayLinksRoute_RefusesEverythingButASignedCall(t *testing.T) {
	e := sightingEngine(t, sourceTestSecret)
	const path = "/api/v1/inventory-service/internal/gateway-links"
	for name, mutate := range map[string]func(*http.Request){
		"no credentials":             func(*http.Request) {},
		"a tenant token":             func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+tenantToken(t)) },
		"an unsigned internal flag":  func(r *http.Request) { r.Header.Set(serviceauth.HeaderServiceCall, "true") },
		"another secret's signature": func(r *http.Request) { serviceauth.NewSigner("some-other-secret-0123456789abcdef").SignRequest(r) },
	} {
		req := sourceRequest(http.MethodPost, path, []byte(`{}`))
		req.Header.Set(serviceauth.HeaderTenantID, uuid.NewString())
		mutate(req)
		if w := serve(e, req); w.Code != http.StatusUnauthorized {
			t.Errorf("%s = %d, want 401", name, w.Code)
		}
	}
	req := sourceRequest(http.MethodPost, path, []byte(`{}`))
	req.Header.Set(serviceauth.HeaderTenantID, uuid.NewString())
	serviceauth.NewSigner(sourceTestSecret).SignRequest(req)
	if w := serve(e, req); w.Code != http.StatusBadRequest {
		t.Errorf("a signed call with no asset = %d %s, want the handler's own 400", w.Code, w.Body.String())
	}
}

// main() must mount the route through the helper and never name it directly.
func TestMainMountsSightingRouteOnlyThroughTheGate(t *testing.T) {
	body, err := os.ReadFile(filepath.Join(".", "main.go"))
	if err != nil {
		t.Fatal(err)
	}
	src := string(body)
	if !regexp.MustCompile(`(?m)^\s*mountSightingRoutes\(r,`).MatchString(src) {
		t.Error("main.go does not call mountSightingRoutes(r, …); the internal sightings route is not served")
	}
	if strings.Contains(src, "/internal/sightings") {
		t.Error("main.go names /internal/sightings directly; it must be mounted only by mountSightingRoutes, behind the signed-call gate")
	}
}
