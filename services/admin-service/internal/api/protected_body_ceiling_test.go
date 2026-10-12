package api

// The authenticated /admin routes read request bodies too, and only the
// anonymous /auth group was bounded. protectedBodyCeiling is group middleware
// ahead of authentication, so it is driven through the REAL router: deleting
// its Use line in setupRouter fails these tests.

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	_ "github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/admin-service/internal/config"
)

func TestProtectedRoutes_RefuseAnOversizeBody(t *testing.T) {
	db, err := sql.Open("postgres", "postgres://nobody@127.0.0.1:1/none?sslmode=disable&connect_timeout=1")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	router := NewServerWithConnections(&config.Config{Environment: "test"}, db, db, EditionHooks{}).Router()

	send := func(method, path string, size int) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(`{"x":"`+strings.Repeat("a", size)+`"}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}
	const twoMiB = 2 << 20

	for _, route := range []struct{ method, path string }{
		{http.MethodPut, "/api/v1/admin-service/admin/settings"},
		{http.MethodPost, "/api/v1/admin-service/admin/integrations"},
		{http.MethodPost, "/api/v1/admin-service/admin/auth/logout"},
	} {
		if w := send(route.method, route.path, twoMiB); w.Code != http.StatusRequestEntityTooLarge {
			t.Errorf("%s %s with a 2 MiB body: status %d, want 413; body %s", route.method, route.path, w.Code, w.Body.String())
		}
		// A small body is not refused as too large (it reaches the auth gate: 401).
		if w := send(route.method, route.path, 10); w.Code == http.StatusRequestEntityTooLarge {
			t.Errorf("%s %s: a tiny body was refused as too large", route.method, route.path)
		}
	}

	// The two upload routes keep their own, larger, explicit bounds: a 2 MiB
	// body is not refused by the ceiling (the handlers enforce their own caps
	// after authentication).
	for _, route := range []struct{ method, path string }{
		{http.MethodPost, "/api/v1/admin-service/admin/branding/upload"},
		{http.MethodPost, "/api/v1/admin-service/admin/catalogs/import-bundle"},
	} {
		if w := send(route.method, route.path, twoMiB); w.Code == http.StatusRequestEntityTooLarge {
			t.Errorf("%s %s: the upload route got the small default ceiling", route.method, route.path)
		}
	}
	// ...but the branding route is still bounded (5 MiB + envelope).
	if w := send(http.MethodPost, "/api/v1/admin-service/admin/branding/upload", 6<<20); w.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("branding upload with a 6 MiB body: status %d, want 413", w.Code)
	}
}
