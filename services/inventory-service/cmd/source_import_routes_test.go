package main

// The internal source-import routes (platform ADR-0002 D3) admit a signed
// service call and NOTHING else.
//
// These drive mountSourceImportRoutes — the function main() calls — on a real
// gin engine that also carries a JWT-gated /api/v1 group, the arrangement
// main() builds. So what is pinned is the wiring: the routes live on their own
// group, behind RequireSignedServiceCall, and a user token has no path to them.
// A helper-only test would stay green if main() mounted the handlers on the
// user group instead.
//
// The handler is built over a nil service: every request these tests send is
// refused before a handler runs, except the signed ones, which stop at request
// validation (an empty batch is a 400). That is deliberate — reaching the
// handler at all is the assertion.

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/handlers"
	"github.com/vistasecurity/vistaplatform/shared/serviceauth"
)

const (
	sourceTestSecret = "source-import-routes-test-secret-0123456789"
	sourceTestJWT    = "source-import-routes-test-jwt-0123456789abcdef"
)

// sourceEngine is main()'s arrangement in miniature: a JWT-gated user group
// with a route of its own, and the internal source routes mounted by the real
// helper.
func sourceEngine(t *testing.T) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	r := gin.New()
	// A user group like main()'s, with a stand-in auth that admits any
	// bearer token — so a 401 on the internal routes cannot come from a token
	// that failed to verify, only from the route not accepting user tokens.
	users := r.Group("/api/v1")
	users.Use(func(c *gin.Context) {
		if !strings.HasPrefix(c.GetHeader("Authorization"), "Bearer ") {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		c.Next()
	})
	users.GET("/inventory-service/assets", func(c *gin.Context) { c.Status(http.StatusOK) })

	mountSourceImportRoutes(r, handlers.NewSourceImportHandler(nil), sourceTestSecret)
	return r
}

func tenantToken(t *testing.T) string {
	t.Helper()
	tok, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": uuid.NewString(), "tenant_id": uuid.NewString(), "type": "access",
	}).SignedString([]byte(sourceTestJWT))
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

var sourceRoutes = []struct{ method, path string }{
	{http.MethodPost, "/api/v1/inventory-service/internal/sources/segments"},
	{http.MethodPost, "/api/v1/inventory-service/internal/sources/assets/admission"},
	{http.MethodPost, "/api/v1/inventory-service/internal/sources/assets"},
	{http.MethodGet, "/api/v1/inventory-service/internal/sources/asset-classes/switch"},
	{http.MethodGet, "/api/v1/inventory-service/internal/sources/hardware-assets"},
}

func sourceRequest(method, path string, body []byte) *http.Request {
	if body == nil && method == http.MethodPost {
		body = []byte(`{}`)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	return req
}

func serve(e *gin.Engine, req *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	e.ServeHTTP(w, req)
	return w
}

func TestSourceImportRoutes_RefuseATenantToken(t *testing.T) {
	e := sourceEngine(t)
	// The stand-in user auth admits this token on the user group…
	req := httptest.NewRequest(http.MethodGet, "/api/v1/inventory-service/assets", nil)
	req.Header.Set("Authorization", "Bearer "+tenantToken(t))
	if w := serve(e, req); w.Code != http.StatusOK {
		t.Fatalf("control: the user route answered %d to a bearer token, want 200", w.Code)
	}
	// …and the internal routes refuse it.
	for _, rt := range sourceRoutes {
		req := sourceRequest(rt.method, rt.path, nil)
		req.Header.Set("Authorization", "Bearer "+tenantToken(t))
		req.Header.Set(serviceauth.HeaderTenantID, uuid.NewString())
		if w := serve(e, req); w.Code != http.StatusUnauthorized {
			t.Errorf("%s %s with a tenant token = %d, want 401", rt.method, rt.path, w.Code)
		}
	}
}

func TestSourceImportRoutes_RefuseAnUnsignedInternalHeader(t *testing.T) {
	e := sourceEngine(t)
	for _, rt := range sourceRoutes {
		req := sourceRequest(rt.method, rt.path, nil)
		// The legacy spoofable header on its own is not a service call.
		req.Header.Set(serviceauth.HeaderServiceCall, "true")
		req.Header.Set(serviceauth.HeaderTenantID, uuid.NewString())
		if w := serve(e, req); w.Code != http.StatusUnauthorized {
			t.Errorf("%s %s with X-Internal-Call but no signature = %d, want 401", rt.method, rt.path, w.Code)
		}
	}
}

func TestSourceImportRoutes_RefuseASignatureFromAnotherSecret(t *testing.T) {
	e := sourceEngine(t)
	for _, rt := range sourceRoutes {
		req := sourceRequest(rt.method, rt.path, nil)
		req.Header.Set(serviceauth.HeaderTenantID, uuid.NewString())
		serviceauth.NewSigner("some-other-secret-0123456789abcdef").SignRequest(req)
		if w := serve(e, req); w.Code != http.StatusUnauthorized {
			t.Errorf("%s %s signed with the wrong secret = %d, want 401", rt.method, rt.path, w.Code)
		}
	}
}

// The tenant is part of the signature. Re-pointing a signed request at another
// tenant after it was signed must fail — that is what makes "tenant A's run
// cannot write tenant B" a property of the transport, not of the caller's care.
func TestSourceImportRoutes_RefuseATenantSwappedAfterSigning(t *testing.T) {
	e := sourceEngine(t)
	for _, rt := range sourceRoutes {
		req := sourceRequest(rt.method, rt.path, nil)
		req.Header.Set(serviceauth.HeaderTenantID, uuid.NewString())
		serviceauth.NewSigner(sourceTestSecret).SignRequest(req)
		req.Header.Set(serviceauth.HeaderTenantID, uuid.NewString())
		if w := serve(e, req); w.Code != http.StatusUnauthorized {
			t.Errorf("%s %s with the tenant swapped after signing = %d, want 401", rt.method, rt.path, w.Code)
		}
	}
}

func TestSourceImportRoutes_RequireANamedTenant(t *testing.T) {
	e := sourceEngine(t)
	for _, tenant := range []string{"", uuid.Nil.String(), "not-a-uuid"} {
		req := sourceRequest(http.MethodPost, "/api/v1/inventory-service/internal/sources/segments", nil)
		if tenant != "" {
			req.Header.Set(serviceauth.HeaderTenantID, tenant)
		}
		serviceauth.NewSigner(sourceTestSecret).SignRequest(req)
		if w := serve(e, req); w.Code != http.StatusBadRequest {
			t.Errorf("a signed call naming tenant %q = %d, want 400", tenant, w.Code)
		}
	}
}

// The positive polarity: a correctly signed call naming a tenant reaches the
// handler (which then refuses the empty batch with its own 400).
func TestSourceImportRoutes_AdmitASignedServiceCall(t *testing.T) {
	e := sourceEngine(t)
	for _, path := range []string{
		"/api/v1/inventory-service/internal/sources/segments",
		"/api/v1/inventory-service/internal/sources/assets",
	} {
		req := sourceRequest(http.MethodPost, path, []byte(`{}`))
		req.Header.Set(serviceauth.HeaderTenantID, uuid.NewString())
		serviceauth.NewSigner(sourceTestSecret).SignRequest(req)
		w := serve(e, req)
		if w.Code != http.StatusBadRequest {
			t.Errorf("a signed call to %s = %d (%s), want the handler's own 400", path, w.Code, w.Body.String())
		}
		if !strings.Contains(w.Body.String(), "between 1 and") && !strings.Contains(w.Body.String(), "source must be") {
			t.Errorf("a signed call to %s did not reach the handler: %s", path, w.Body.String())
		}
	}
}

// With no secret configured the gate fails CLOSED.
func TestSourceImportRoutes_FailClosedWithoutASecret(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	mountSourceImportRoutes(r, handlers.NewSourceImportHandler(nil), "")
	req := sourceRequest(http.MethodPost, "/api/v1/inventory-service/internal/sources/segments", nil)
	req.Header.Set(serviceauth.HeaderTenantID, uuid.NewString())
	serviceauth.NewSigner("anything-at-all-0123456789").SignRequest(req)
	if w := serve(r, req); w.Code != http.StatusUnauthorized {
		t.Errorf("with no INTERNAL_AUTH_SECRET a signed call = %d, want 401", w.Code)
	}
}

// main() must mount them through the helper, and must not also register any
// of them on a user-token group. Read from the source, as admin_plane_test.go
// does for the other gates main() owns.
func TestMainMountsSourceImportRoutesOnlyThroughTheGate(t *testing.T) {
	body, err := os.ReadFile(filepath.Join(".", "main.go"))
	if err != nil {
		t.Fatal(err)
	}
	src := string(body)
	if !regexp.MustCompile(`(?m)^\s*mountSourceImportRoutes\(r,`).MatchString(src) {
		t.Error("main.go does not call mountSourceImportRoutes(r, …); the internal source routes are not served")
	}
	if strings.Contains(src, "/internal/sources/") {
		t.Error("main.go names an /internal/sources/ path directly; it must be mounted only by mountSourceImportRoutes, behind the signed-call gate")
	}
}
