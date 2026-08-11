package middleware

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type stubFeatureChecker struct {
	allowed bool
	err     error
	asked   []string
}

func (s *stubFeatureChecker) CheckFeatureAccess(_ uuid.UUID, feature string) (bool, error) {
	s.asked = append(s.asked, feature)
	return s.allowed, s.err
}

func engine(svc featureChecker, feature string, withTenant bool) *gin.Engine {
	var tenantValue any
	if withTenant {
		tenantValue = uuid.New().String()
	}
	return engineWithTenantValue(svc, feature, tenantValue)
}

func engineWithTenantValue(svc featureChecker, feature string, tenantValue any) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		if tenantValue != nil {
			c.Set("tenantID", tenantValue)
		}
		c.Next()
	})
	r.GET("/x", requireFeatureWithChecker(svc, feature), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	return r
}

func do(r *gin.Engine) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/x", nil))
	return w
}

func TestRequireFeature_AllowsEntitledTenant(t *testing.T) {
	svc := &stubFeatureChecker{allowed: true}
	if got := do(engine(svc, "cmdb_sync", true)).Code; got != http.StatusOK {
		t.Fatalf("status = %d, want 200", got)
	}
	if len(svc.asked) != 1 || svc.asked[0] != "cmdb_sync" {
		t.Fatalf("checked %v, want [cmdb_sync]", svc.asked)
	}
}

func TestRequireFeature_AllowsUUIDTenantContext(t *testing.T) {
	svc := &stubFeatureChecker{allowed: true}
	if got := do(engineWithTenantValue(svc, "cmdb_sync", uuid.New())).Code; got != http.StatusOK {
		t.Fatalf("status = %d, want 200", got)
	}
	if len(svc.asked) != 1 || svc.asked[0] != "cmdb_sync" {
		t.Fatalf("checked %v, want [cmdb_sync]", svc.asked)
	}
}

// 402, not 403: the caller IS authenticated and authorized. Returning 403 would
// send an operator to debug RBAC, which would waste their time.
func TestRequireFeature_UnentitledIs402NotForbidden(t *testing.T) {
	w := do(engine(&stubFeatureChecker{allowed: false}, "cmdb_sync", true))
	if w.Code != http.StatusPaymentRequired {
		t.Fatalf("status = %d, want 402; body=%s", w.Code, w.Body.String())
	}
	// The response names the feature so a client can render a specific upsell
	// rather than a generic "upgrade" message.
	if body := w.Body.String(); !contains(body, "cmdb_sync") {
		t.Fatalf("response does not name the feature: %s", body)
	}
}

// Fails CLOSED. Every current caller guards a write or an external-system call,
// so an ambiguous lookup must not be treated as permission.
func TestRequireFeature_LookupErrorDenies(t *testing.T) {
	w := do(engine(&stubFeatureChecker{err: errors.New("db down")}, "cmdb_sync", true))
	if w.Code == http.StatusOK {
		t.Fatal("entitlement lookup error allowed the request through — this gate must fail closed")
	}
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
}

func TestRequireFeature_NoTenantIs401(t *testing.T) {
	svc := &stubFeatureChecker{allowed: true}
	if got := do(engine(svc, "cmdb_sync", false)).Code; got != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", got)
	}
	if len(svc.asked) != 0 {
		t.Fatal("entitlement was checked without a tenant in context")
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (haystack == needle ||
		len(needle) == 0 ||
		indexOf(haystack, needle) >= 0)
}

func indexOf(h, n string) int {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return i
		}
	}
	return -1
}
