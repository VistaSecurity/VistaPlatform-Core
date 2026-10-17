package rbac

import (
	"database/sql"
	"database/sql/driver"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/rbac"
)

// BUILD_PLAN row 0.6: drives the real RequireTenantPermission middleware with
// the DCIM constants. The fake pool answers user_has_permission() from a role
// table that mirrors the seeded matrix (standards/permissions.yaml; the matrix
// itself is pinned by scripts/audit-dcim-permissions.test.mjs). A role holding
// dcim.read but not dcim.manage must read (200) and be refused a write (403).

var dcimGrants = map[string]map[string]bool{
	"viewer":       {rbac.PermissionDcimRead: true},
	"tenant_admin": {rbac.PermissionDcimRead: true, rbac.PermissionDcimManage: true},
}

type dcimDriver struct{ role string }

func (d dcimDriver) Open(string) (driver.Conn, error) { return dcimConn(d), nil }

type dcimConn dcimDriver

func (c dcimConn) Prepare(string) (driver.Stmt, error) { return dcimStmt(c), nil }
func (c dcimConn) Close() error                        { return nil }
func (c dcimConn) Begin() (driver.Tx, error)           { return nil, driver.ErrSkip }

type dcimStmt dcimDriver

func (s dcimStmt) Close() error  { return nil }
func (s dcimStmt) NumInput() int { return -1 }
func (s dcimStmt) Exec([]driver.Value) (driver.Result, error) {
	return nil, driver.ErrSkip
}
func (s dcimStmt) Query(args []driver.Value) (driver.Rows, error) {
	perm, _ := args[2].(string)
	return &dcimRows{grant: dcimGrants[s.role][perm]}, nil
}

type dcimRows struct {
	grant bool
	done  bool
}

func (r *dcimRows) Columns() []string { return []string{"user_has_permission"} }
func (r *dcimRows) Close() error      { return nil }
func (r *dcimRows) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done = true
	dest[0] = r.grant
	return nil
}

var dcimDriverSeq atomic.Int64
var dcimRegMu sync.Mutex

func dcimPool(t *testing.T, role string) *sql.DB {
	t.Helper()
	dcimRegMu.Lock()
	name := "dcim-perm-" + role + "-" + string(rune('a'+dcimDriverSeq.Add(1)))
	sql.Register(name, dcimDriver{role: role})
	dcimRegMu.Unlock()
	db, err := sql.Open(name, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func dcimRouter(db *sql.DB) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("userID", uuid.New())
		c.Set("tenantID", uuid.New())
	})
	g := r.Group("/api/v2/inventory-service/dcim")
	g.GET("/racks", RequireTenantPermission(db, rbac.PermissionDcimRead), func(c *gin.Context) { c.Status(http.StatusOK) })
	g.POST("/racks", RequireTenantPermission(db, rbac.PermissionDcimManage), func(c *gin.Context) { c.Status(http.StatusCreated) })
	return r
}

func TestRequireTenantPermission_DCIM(t *testing.T) {
	cases := []struct {
		role, method string
		want         int
	}{
		{"viewer", http.MethodGet, http.StatusOK},
		{"viewer", http.MethodPost, http.StatusForbidden},
		{"tenant_admin", http.MethodGet, http.StatusOK},
		{"tenant_admin", http.MethodPost, http.StatusCreated},
	}
	for _, tc := range cases {
		t.Run(tc.role+"_"+tc.method, func(t *testing.T) {
			r := dcimRouter(dcimPool(t, tc.role))
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest(tc.method, "/api/v2/inventory-service/dcim/racks", nil))
			if w.Code != tc.want {
				t.Fatalf("%s %s: got %d, want %d (%s)", tc.role, tc.method, w.Code, tc.want, w.Body.String())
			}
		})
	}
}
