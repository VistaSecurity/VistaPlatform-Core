package handlers

import (
	"database/sql"
	"database/sql/driver"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/rbac"

	sharedrbac "github.com/vistasecurity/vistaplatform/shared/middleware/rbac"
)

// The tenant integrations list returns third-party credential configuration
// (SIEM / CMDB / ITSM endpoints and their auth blocks). Before this gate, all
// three routes that reach IntegrationsHandler.List carried nothing but
// JWTMiddleware, so any authenticated member of the tenant — viewer,
// billing_admin, a read-only personal access token — could enumerate them.
//
// Two assertions, because either one alone is satisfiable while the hole is
// open: that the middleware really refuses a caller without settings.read, and
// that cmd/main.go actually installs it on every route reaching List.

// --- a database/sql driver that answers user_has_permission() with a fixed bool.
// Written rather than mocked so this test adds no dependency to the module.

type permDriver struct{ grant bool }

type permConn struct{ grant bool }

type permStmt struct{ grant bool }

type permRows struct {
	grant bool
	done  bool
}

func (d permDriver) Open(string) (driver.Conn, error) { return permConn(d), nil }

func (c permConn) Prepare(string) (driver.Stmt, error) { return permStmt(c), nil }
func (c permConn) Close() error                        { return nil }
func (c permConn) Begin() (driver.Tx, error)           { return nil, driver.ErrSkip }

func (s permStmt) Close() error  { return nil }
func (s permStmt) NumInput() int { return -1 }
func (s permStmt) Exec([]driver.Value) (driver.Result, error) {
	return nil, driver.ErrSkip
}
func (s permStmt) Query([]driver.Value) (driver.Rows, error) {
	return &permRows{grant: s.grant}, nil
}

func (r *permRows) Columns() []string { return []string{"user_has_permission"} }
func (r *permRows) Close() error      { return nil }
func (r *permRows) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done = true
	dest[0] = r.grant
	return nil
}

var registerPermDrivers sync.Once

func permissionDB(t *testing.T, grant bool) *sql.DB {
	t.Helper()
	registerPermDrivers.Do(func() {
		sql.Register("permgrant", permDriver{grant: true})
		sql.Register("permdeny", permDriver{grant: false})
	})
	name := "permdeny"
	if grant {
		name = "permgrant"
	}
	db, err := sql.Open(name, "")
	if err != nil {
		t.Fatalf("sql.Open(%s): %v", name, err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// TestIntegrationsList_RequiresSettingsRead proves the gate refuses a caller
// whose role does not carry settings.read, and that the handler behind it is
// never entered.
func TestIntegrationsList_RequiresSettingsRead(t *testing.T) {
	gin.SetMode(gin.TestMode)

	for _, tc := range []struct {
		name       string
		grant      bool
		wantStatus int
		wantCalled bool
	}{
		{name: "without settings.read", grant: false, wantStatus: http.StatusForbidden, wantCalled: false},
		{name: "with settings.read", grant: true, wantStatus: http.StatusOK, wantCalled: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			r := gin.New()
			r.Use(func(c *gin.Context) {
				c.Set("userID", uuid.New())
				c.Set("tenantID", uuid.New())
			})
			r.GET("/api/v1/inventory-service/integrations",
				sharedrbac.RequireTenantPermission(permissionDB(t, tc.grant), rbac.PermissionSettingsRead),
				func(c *gin.Context) {
					called = true
					c.JSON(http.StatusOK, gin.H{"integrations": []any{}})
				})

			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/api/v1/inventory-service/integrations", nil)
			r.ServeHTTP(w, req)

			if w.Code != tc.wantStatus {
				t.Fatalf("status = %d, want %d (body %s)", w.Code, tc.wantStatus, w.Body.String())
			}
			if called != tc.wantCalled {
				t.Fatalf("handler called = %v, want %v", called, tc.wantCalled)
			}
			if !tc.grant && !strings.Contains(w.Body.String(), rbac.PermissionSettingsRead) {
				t.Fatalf("403 body should name the required permission, got %s", w.Body.String())
			}
		})
	}
}

// TestIntegrationsListRoutesAreGated pins the wiring. The middleware test above
// stays green if someone drops the gate from a route, so read the routing table
// itself: every registration whose handler is integrationsHandler.List must
// carry RequireTenantPermission(..., rbac.PermissionSettingsRead).
func TestIntegrationsListRoutesAreGated(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "cmd", "main.go"))
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}

	listRoute := regexp.MustCompile(`(?m)^.*\.GET\("([^"]*integrations)",\s*(.*)integrationsHandler\.List\).*$`)
	matches := listRoute.FindAllStringSubmatch(string(src), -1)
	if len(matches) != 3 {
		t.Fatalf("expected 3 integrations List routes (v1 prefixed, v1 direct, v2), found %d: %v", len(matches), matches)
	}
	for _, m := range matches {
		if !strings.Contains(m[2], "RequireTenantPermission(rawDB, rbac.PermissionSettingsRead)") {
			t.Errorf("GET %s reaches integrationsHandler.List without a settings.read gate: %s", m[1], strings.TrimSpace(m[0]))
		}
	}
}
