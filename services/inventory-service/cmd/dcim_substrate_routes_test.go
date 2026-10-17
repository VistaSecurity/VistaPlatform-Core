package main

// The DCIM substrate routes' permission gates, through the REAL mount function
// main() calls and the REAL RequireTenantPermission middleware. The pool is a
// fake driver answering user_has_permission() from a grant table, so the test
// needs no database. A role with dcim.read reads and is refused every write; a
// role with neither is refused the reads too.
//
// Mutation: drop `read` from the /changes registration → the no-grant role
// gets 200 and this fails; drop `manage` from any write → the read-only role
// reaches the stub and this fails.

import (
	"context"
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
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/handlers"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
	"github.com/vistasecurity/vistaplatform/shared/dcim/journal"
	"github.com/vistasecurity/vistaplatform/shared/dcim/tags"
	"github.com/vistasecurity/vistaplatform/shared/rbac"
)

type grantDriver struct{ grants map[string]bool }

func (d grantDriver) Open(string) (driver.Conn, error) { return grantConn(d), nil }

type grantConn grantDriver

func (c grantConn) Prepare(string) (driver.Stmt, error) { return grantStmt(c), nil }
func (c grantConn) Close() error                        { return nil }
func (c grantConn) Begin() (driver.Tx, error)           { return nil, driver.ErrSkip }

type grantStmt grantDriver

func (s grantStmt) Close() error                               { return nil }
func (s grantStmt) NumInput() int                              { return -1 }
func (s grantStmt) Exec([]driver.Value) (driver.Result, error) { return nil, driver.ErrSkip }
func (s grantStmt) Query(args []driver.Value) (driver.Rows, error) {
	perm, _ := args[len(args)-1].(string)
	return &grantRows{grant: s.grants[perm]}, nil
}

type grantRows struct {
	grant bool
	done  bool
}

func (r *grantRows) Columns() []string { return []string{"user_has_permission"} }
func (r *grantRows) Close() error      { return nil }
func (r *grantRows) Next(dest []driver.Value) error {
	if r.done {
		return io.EOF
	}
	r.done = true
	dest[0] = r.grant
	return nil
}

var (
	grantSeq atomic.Int64
	grantMu  sync.Mutex
)

func grantPool(t *testing.T, perms ...string) *sql.DB {
	t.Helper()
	g := map[string]bool{}
	for _, p := range perms {
		g[p] = true
	}
	grantMu.Lock()
	name := "dcim-substrate-grants-" + uuid.NewString() + string(rune('a'+grantSeq.Add(1)%26))
	sql.Register(name, grantDriver{grants: g})
	grantMu.Unlock()
	db, err := sql.Open(name, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// stubSubstrate answers every call successfully and records whether a call
// reached it and what actor the context carried.
type stubSubstrate struct {
	calls    int
	sawActor bool
}

func (s *stubSubstrate) note(ctx context.Context) {
	s.calls++
	_, s.sawActor = changes.ActorFrom(ctx)
}
func (s *stubSubstrate) ListChanges(ctx context.Context, _ changes.Filter) ([]changes.ObjectChange, int, error) {
	s.note(ctx)
	return []changes.ObjectChange{}, 0, nil
}
func (s *stubSubstrate) GetChange(ctx context.Context, _, id uuid.UUID) (changes.ObjectChange, error) {
	s.note(ctx)
	return changes.ObjectChange{ID: id, ObjectKind: dcim.ObjectKindAsset, Action: changes.ActionCreate, ChangedFields: []string{}}, nil
}
func (s *stubSubstrate) ListJournal(ctx context.Context, _ uuid.UUID, _ dcim.ObjectKind, _ uuid.UUID, _, _ int) ([]journal.Entry, int, error) {
	s.note(ctx)
	return []journal.Entry{}, 0, nil
}
func (s *stubSubstrate) AddJournal(ctx context.Context, _ uuid.UUID, k dcim.ObjectKind, id uuid.UUID, ek journal.Kind, c string) (journal.Entry, error) {
	s.note(ctx)
	return journal.Entry{ID: uuid.New(), ObjectKind: k, ObjectID: id, Kind: journal.KindInfo, Comments: c}, nil
}
func (s *stubSubstrate) ObjectTags(ctx context.Context, _ uuid.UUID, _ dcim.ObjectKind, _ uuid.UUID) ([]tags.Tag, error) {
	s.note(ctx)
	return []tags.Tag{}, nil
}
func (s *stubSubstrate) SetObjectTags(ctx context.Context, _ uuid.UUID, _ dcim.ObjectKind, _ uuid.UUID, _ []uuid.UUID) ([]tags.Tag, error) {
	s.note(ctx)
	return []tags.Tag{}, nil
}
func (s *stubSubstrate) ListTags(ctx context.Context, _ uuid.UUID) ([]tags.Tag, error) {
	s.note(ctx)
	return []tags.Tag{}, nil
}
func (s *stubSubstrate) CreateTag(ctx context.Context, _ uuid.UUID, in tags.Input) (tags.Tag, error) {
	s.note(ctx)
	return tags.Tag{ID: uuid.New(), Name: in.Name, Slug: "x", ObjectKinds: []dcim.ObjectKind{}}, nil
}
func (s *stubSubstrate) UpdateTag(ctx context.Context, _, id uuid.UUID, _ services.TagPatch) (tags.Tag, error) {
	s.note(ctx)
	return tags.Tag{ID: id, Name: "x", Slug: "x", ObjectKinds: []dcim.ObjectKind{}}, nil
}
func (s *stubSubstrate) DeleteTag(ctx context.Context, _, _ uuid.UUID) error {
	s.note(ctx)
	return nil
}

func substrateRouter(t *testing.T, store *stubSubstrate, perms ...string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	v2 := r.Group("/api/v2")
	v2.Use(func(c *gin.Context) {
		c.Set("userID", uuid.New())
		c.Set("tenantID", uuid.New())
		c.Set("email", "op@example.test")
	})
	mountDcimSubstrateRoutes(v2, grantPool(t, perms...), handlers.NewDcimSubstrateHandler(store))
	return r
}

type substrateRoute struct {
	method, path, body string
	write              bool
	want               int
}

var substrateRoutes = func() []substrateRoute {
	obj := "/api/v2/inventory-service/dcim/objects/asset/" + uuid.NewString()
	tag := "/api/v2/inventory-service/dcim/tags/" + uuid.NewString()
	return []substrateRoute{
		{http.MethodGet, "/api/v2/inventory-service/dcim/changes", "", false, http.StatusOK},
		{http.MethodGet, "/api/v2/inventory-service/dcim/changes/" + uuid.NewString(), "", false, http.StatusOK},
		{http.MethodGet, obj + "/journal", "", false, http.StatusOK},
		{http.MethodPost, obj + "/journal", `{"comments":"x"}`, true, http.StatusCreated},
		{http.MethodGet, obj + "/tags", "", false, http.StatusOK},
		{http.MethodPut, obj + "/tags", `{"tag_ids":[]}`, true, http.StatusOK},
		{http.MethodGet, "/api/v2/inventory-service/dcim/tags", "", false, http.StatusOK},
		{http.MethodPost, "/api/v2/inventory-service/dcim/tags", `{"name":"x"}`, true, http.StatusCreated},
		{http.MethodPatch, tag, `{"name":"y"}`, true, http.StatusOK},
		{http.MethodDelete, tag, "", true, http.StatusNoContent},
	}
}()

func serveSubstrate(r http.Handler, rt substrateRoute) *httptest.ResponseRecorder {
	var body io.Reader
	if rt.body != "" {
		body = strings.NewReader(rt.body)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(rt.method, rt.path, body))
	return w
}

func TestDcimSubstrateRoutes_Gates(t *testing.T) {
	for _, rt := range substrateRoutes {
		name := rt.method + " " + rt.path
		t.Run("no grant/"+name, func(t *testing.T) {
			store := &stubSubstrate{}
			w := serveSubstrate(substrateRouter(t, store), rt)
			if w.Code != http.StatusForbidden || store.calls != 0 {
				t.Fatalf("no dcim grant: status %d, store calls %d — want 403 and nothing reached", w.Code, store.calls)
			}
		})
		t.Run("dcim.read/"+name, func(t *testing.T) {
			store := &stubSubstrate{}
			w := serveSubstrate(substrateRouter(t, store, rbac.PermissionDcimRead), rt)
			if rt.write {
				if w.Code != http.StatusForbidden || store.calls != 0 {
					t.Fatalf("read-only role on a write: status %d, store calls %d — want 403", w.Code, store.calls)
				}
				return
			}
			if w.Code != rt.want {
				t.Fatalf("read with dcim.read: status %d, want %d (%s)", w.Code, rt.want, w.Body.String())
			}
		})
		t.Run("dcim.manage/"+name, func(t *testing.T) {
			store := &stubSubstrate{}
			w := serveSubstrate(substrateRouter(t, store, rbac.PermissionDcimRead, rbac.PermissionDcimManage), rt)
			if w.Code != rt.want {
				t.Fatalf("status %d, want %d (%s)", w.Code, rt.want, w.Body.String())
			}
			// The group's changes.Middleware put the actor on the context the
			// service layer records changes under.
			if !store.sawActor {
				t.Fatal("the store's context carried no actor — changes.Middleware is not mounted")
			}
		})
	}
}

// main() must mount the substrate on the JWT-authenticated v2 group. The gate
// test above drives mountDcimSubstrateRoutes directly, so without this a
// deleted call in main.go would leave every test green and the routes 404.
func TestDcimSubstrateRoutes_MountedByMain(t *testing.T) {
	raw, err := os.ReadFile(filepath.Clean(mainPath))
	if err != nil {
		t.Fatalf("read %s: %v", mainPath, err)
	}
	if !regexp.MustCompile(`(?m)^\s*mountDcimSubstrateRoutes\(apiv2, rawDB, `).Match(raw) {
		t.Fatal("main.go does not call mountDcimSubstrateRoutes(apiv2, rawDB, …): the DCIM substrate routes are not served")
	}
}
