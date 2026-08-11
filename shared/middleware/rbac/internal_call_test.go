package rbac

import (
	"database/sql"
	"database/sql/driver"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/vistasecurity/vistaplatform/shared/middleware"
)

// fakeDriver is a no-op database/sql driver. It lets us construct a non-nil
// *sql.DB without a real database. Any attempt to actually query fails — which
// is exactly what we want: these tests assert the internal-call bypass returns
// BEFORE the middleware ever touches the database.
type fakeDriver struct{}

func (fakeDriver) Open(string) (driver.Conn, error) {
	return nil, errors.New("fakeDriver: no connections")
}

func init() {
	sql.Register("rbac_fake_driver", fakeDriver{})
	gin.SetMode(gin.TestMode)
}

func fakeDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("rbac_fake_driver", "")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	return db
}

// markInternal mimics what RequireJWTAuth does for an HMAC-verified internal
// service call: sets isInternalCall=true and the non-UUID "system" userID sentinel.
func markInternal(c *gin.Context) {
	c.Set(middleware.CtxKeyIsInternalCall, true)
	c.Set(middleware.CtxKeyUserID, middleware.InternalUserIDSentinel)
	c.Next()
}

func runWith(handlers ...gin.HandlerFunc) *httptest.ResponseRecorder {
	r := gin.New()
	chain := append(handlers, func(c *gin.Context) { c.String(http.StatusOK, "reached") })
	r.GET("/x", chain...)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.ServeHTTP(w, req)
	return w
}

func TestRequireTenantPermission_InternalCallBypass(t *testing.T) {
	db := fakeDB(t)
	w := runWith(markInternal, RequireTenantPermission(db, "assets.create"))
	if w.Code != http.StatusOK || w.Body.String() != "reached" {
		t.Fatalf("internal call should bypass per-user RBAC and reach the handler; got %d %q", w.Code, w.Body.String())
	}
}

func TestRequirePlatformPermission_InternalCallBypass(t *testing.T) {
	db := fakeDB(t)
	w := runWith(markInternal, RequirePlatformPermission(db, "platform.analytics"))
	if w.Code != http.StatusOK || w.Body.String() != "reached" {
		t.Fatalf("internal call should bypass platform RBAC; got %d %q", w.Code, w.Body.String())
	}
}

func TestRequireAnyPlatformPermission_InternalCallBypass(t *testing.T) {
	db := fakeDB(t)
	w := runWith(markInternal, RequireAnyPlatformPermission(db, "platform.analytics", "platform.health"))
	if w.Code != http.StatusOK || w.Body.String() != "reached" {
		t.Fatalf("internal call should bypass platform RBAC; got %d %q", w.Code, w.Body.String())
	}
}

// Without the internal-call flag, the "system" sentinel must NOT slip through:
// it is not a valid UUID, so RequireTenantPermission rejects it with 401 before
// any DB access. This guards the bypass from being widened accidentally.
func TestRequireTenantPermission_NonInternalSystemSentinelRejected(t *testing.T) {
	db := fakeDB(t)
	setCtx := func(c *gin.Context) {
		c.Set(middleware.CtxKeyUserID, middleware.InternalUserIDSentinel) // "system", no isInternalCall
		c.Set(middleware.CtxKeyTenantID, "11111111-1111-1111-1111-111111111111")
		c.Next()
	}
	w := runWith(setCtx, RequireTenantPermission(db, "assets.create"))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("non-internal call with 'system' userID must be rejected 401, got %d %q", w.Code, w.Body.String())
	}
}
