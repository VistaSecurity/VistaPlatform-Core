package main

// The interface routes' permission gates, through the REAL mount function
// main() calls and the REAL RequireTenantPermission middleware. The pool is a
// fake driver answering user_has_permission() from a grant table. A role with
// dcim.read reads and is refused every write; a role with neither is refused
// the reads too; dcim.manage writes.
//
// Mutation: drop `read` from a GET → the no-grant role reaches the stub; drop
// `manage` from any write → the read-only role reaches the stub.

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/handlers"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/rbac"
)

type ifaceGrantDriver struct{ grants map[string]bool }

func (d ifaceGrantDriver) Open(string) (driver.Conn, error) { return ifaceGrantConn(d), nil }

type ifaceGrantConn ifaceGrantDriver

func (c ifaceGrantConn) Prepare(string) (driver.Stmt, error) { return ifaceGrantStmt(c), nil }
func (c ifaceGrantConn) Close() error                        { return nil }
func (c ifaceGrantConn) Begin() (driver.Tx, error)           { return nil, driver.ErrSkip }

type ifaceGrantStmt ifaceGrantDriver

func (s ifaceGrantStmt) Close() error                               { return nil }
func (s ifaceGrantStmt) NumInput() int                              { return -1 }
func (s ifaceGrantStmt) Exec([]driver.Value) (driver.Result, error) { return nil, driver.ErrSkip }
func (s ifaceGrantStmt) Query(args []driver.Value) (driver.Rows, error) {
	perm, _ := args[len(args)-1].(string)
	return &ifaceGrantRows{grant: s.grants[perm]}, nil
}

type ifaceGrantRows struct{ grant, done bool }

func (r *ifaceGrantRows) Columns() []string { return []string{"user_has_permission"} }
func (r *ifaceGrantRows) Close() error      { return nil }
func (r *ifaceGrantRows) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done = true
	dest[0] = r.grant
	return nil
}

var (
	ifaceGrantSeq atomic.Int64
	ifaceGrantMu  sync.Mutex
)

func ifaceGrantPool(t *testing.T, perms ...string) *sql.DB {
	t.Helper()
	g := map[string]bool{}
	for _, p := range perms {
		g[p] = true
	}
	ifaceGrantMu.Lock()
	name := "dcim-iface-grants-" + uuid.NewString() + string(rune('a'+ifaceGrantSeq.Add(1)%26))
	sql.Register(name, ifaceGrantDriver{grants: g})
	ifaceGrantMu.Unlock()
	db, err := sql.Open(name, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

type ifaceStubStore struct{ calls int }

func (s *ifaceStubStore) List(context.Context, uuid.UUID, services.InterfaceFilter) ([]services.Interface, int, error) {
	s.calls++
	return []services.Interface{}, 0, nil
}
func (s *ifaceStubStore) Get(context.Context, uuid.UUID, uuid.UUID) (services.Interface, error) {
	s.calls++
	return services.Interface{}, nil
}
func (s *ifaceStubStore) Create(context.Context, uuid.UUID, uuid.UUID, services.InterfaceInput) (services.Interface, error) {
	s.calls++
	return services.Interface{}, nil
}
func (s *ifaceStubStore) BulkCreate(context.Context, uuid.UUID, uuid.UUID, []services.InterfaceInput) ([]services.Interface, error) {
	s.calls++
	return []services.Interface{}, nil
}
func (s *ifaceStubStore) Patch(context.Context, uuid.UUID, uuid.UUID, map[string]json.RawMessage) (services.Interface, error) {
	s.calls++
	return services.Interface{}, nil
}
func (s *ifaceStubStore) Delete(context.Context, uuid.UUID, uuid.UUID) error {
	s.calls++
	return nil
}

func TestDcimInterfaceRoutes_PermissionGates(t *testing.T) {
	gin.SetMode(gin.TestMode)
	id := uuid.NewString()
	routes := []struct {
		method, path, body string
		write              bool
		ok                 int
	}{
		{http.MethodGet, "/api/v2/inventory-service/dcim/interfaces", "", false, http.StatusOK},
		{http.MethodGet, "/api/v2/inventory-service/dcim/interfaces/" + id, "", false, http.StatusOK},
		{http.MethodGet, "/api/v2/inventory-service/dcim/assets/" + id + "/interfaces", "", false, http.StatusOK},
		{http.MethodPost, "/api/v2/inventory-service/dcim/interfaces", `{"asset_id":"` + id + `","name":"eth0","type":"1000base-t"}`, true, http.StatusCreated},
		{http.MethodPost, "/api/v2/inventory-service/dcim/interfaces/bulk", `{"interfaces":[{"name":"eth0"}]}`, true, http.StatusCreated},
		{http.MethodPatch, "/api/v2/inventory-service/dcim/interfaces/" + id, `{"description":"x"}`, true, http.StatusOK},
		{http.MethodDelete, "/api/v2/inventory-service/dcim/interfaces/" + id, "", true, http.StatusNoContent},
	}
	roles := map[string][]string{
		"none":   nil,
		"reader": {rbac.PermissionDcimRead},
		"admin":  {rbac.PermissionDcimRead, rbac.PermissionDcimManage},
	}
	for role, perms := range roles {
		for _, rt := range routes {
			t.Run(role+" "+rt.method+" "+rt.path, func(t *testing.T) {
				store := &ifaceStubStore{}
				r := gin.New()
				r.Use(func(c *gin.Context) {
					c.Set("userID", uuid.New())
					c.Set("tenantID", uuid.New())
				})
				mountDcimInterfaceRoutes(r.Group("/api/v2"), ifaceGrantPool(t, perms...), handlers.NewInterfaceHandler(store))
				w := httptest.NewRecorder()
				r.ServeHTTP(w, httptest.NewRequest(rt.method, rt.path, strings.NewReader(rt.body)))

				allowed := role == "admin" || (role == "reader" && !rt.write)
				if allowed {
					if w.Code != rt.ok || store.calls != 1 {
						t.Fatalf("want %d and the store reached, got %d (calls=%d) %s", rt.ok, w.Code, store.calls, w.Body.String())
					}
					return
				}
				if w.Code != http.StatusForbidden || store.calls != 0 {
					t.Fatalf("want 403 and the store untouched, got %d (calls=%d)", w.Code, store.calls)
				}
			})
		}
	}
}

// main.go must mount the routes through mountDcimInterfaceRoutes, the function
// the gate test above drives.
func TestDcimInterfaceRoutes_MountedByMain(t *testing.T) {
	raw, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "mountDcimInterfaceRoutes(apiv2, rawDB,") {
		t.Fatal("main.go does not mount the interface routes through mountDcimInterfaceRoutes")
	}
	if strings.Contains(string(raw), `"/inventory-service/dcim/interfaces`) {
		t.Fatal("main.go registers an interface route directly, outside the gated mount function")
	}
}
