package main

// Contacts and image attachments' permission gates (DCIM row 2.8), through the
// REAL mount function main() calls and the REAL RequireTenantPermission
// middleware. Every route: no grant → 403 and nothing reaches the store;
// dcim.read → reads succeed, writes 403; dcim.manage → writes reach the store
// with an actor on the context; ipam.manage opens nothing here.
//
// Mutation: drop `read`/`manage` from any registration in
// dcim_contact_routes.go → a subtest fails.

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/handlers"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/services"
	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
	"github.com/vistasecurity/vistaplatform/shared/rbac"
)

type stubContacts struct {
	calls    int
	sawActor bool
}

func (s *stubContacts) note(ctx context.Context) {
	s.calls++
	_, s.sawActor = changes.ActorFrom(ctx)
}

func (s *stubContacts) List(ctx context.Context, _ uuid.UUID, _ string, _ services.IPAMListParams) ([]json.RawMessage, int, error) {
	s.note(ctx)
	return []json.RawMessage{}, 0, nil
}
func (s *stubContacts) Get(ctx context.Context, _ uuid.UUID, _ string, _ uuid.UUID) (json.RawMessage, error) {
	s.note(ctx)
	return json.RawMessage(`{}`), nil
}
func (s *stubContacts) Create(ctx context.Context, _ uuid.UUID, _ string, _ []byte) (json.RawMessage, error) {
	s.note(ctx)
	return json.RawMessage(`{}`), nil
}
func (s *stubContacts) Update(ctx context.Context, _ uuid.UUID, _ string, _ uuid.UUID, _ []byte) (json.RawMessage, error) {
	s.note(ctx)
	return json.RawMessage(`{}`), nil
}
func (s *stubContacts) Delete(ctx context.Context, _ uuid.UUID, _ string, _ uuid.UUID) error {
	s.note(ctx)
	return nil
}
func (s *stubContacts) ListForObject(ctx context.Context, _ uuid.UUID, _ dcim.ObjectKind, _ uuid.UUID, _ services.IPAMListParams) ([]json.RawMessage, int, error) {
	s.note(ctx)
	return []json.RawMessage{}, 0, nil
}
func (s *stubContacts) AssignToObject(ctx context.Context, _ uuid.UUID, _ dcim.ObjectKind, _ uuid.UUID, _ []byte) (json.RawMessage, error) {
	s.note(ctx)
	return json.RawMessage(`{}`), nil
}

// stubImages shares the counter with stubContacts so one "calls" tells whether
// anything reached a store.
type stubImages struct{ c *stubContacts }

func (s stubImages) ListForObject(ctx context.Context, _ uuid.UUID, _ dcim.ObjectKind, _ uuid.UUID, _ services.IPAMListParams) ([]json.RawMessage, int, error) {
	s.c.note(ctx)
	return []json.RawMessage{}, 0, nil
}
func (s stubImages) List(ctx context.Context, _ uuid.UUID, _ services.IPAMListParams) ([]json.RawMessage, int, error) {
	s.c.note(ctx)
	return []json.RawMessage{}, 0, nil
}
func (s stubImages) Get(ctx context.Context, _, _ uuid.UUID) (json.RawMessage, error) {
	s.c.note(ctx)
	return json.RawMessage(`{}`), nil
}
func (s stubImages) Upload(ctx context.Context, _ uuid.UUID, _ services.ImageUpload) (json.RawMessage, error) {
	s.c.note(ctx)
	return json.RawMessage(`{}`), nil
}
func (s stubImages) Delete(ctx context.Context, _, _ uuid.UUID) error {
	s.c.note(ctx)
	return nil
}
func (s stubImages) Download(ctx context.Context, _, _ uuid.UUID) (io.ReadCloser, string, string, error) {
	s.c.note(ctx)
	return io.NopCloser(strings.NewReader("x")), "image/png", "a.png", nil
}

func contactRouter(t *testing.T, store *stubContacts, perms ...string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	v2 := r.Group("/api/v2")
	v2.Use(func(c *gin.Context) {
		c.Set("userID", uuid.New())
		c.Set("tenantID", uuid.New())
		c.Set("email", "op@example.test")
	})
	mountDcimContactRoutes(v2, grantPool(t, perms...), handlers.NewContactHandler(store), handlers.NewImageHandler(stubImages{store}))
	return r
}

type contactRoute struct {
	method, path, body, ctype string
	write                     bool
	want                      int
}

func multipartBody(t *testing.T) (string, string) {
	var b bytes.Buffer
	w := multipart.NewWriter(&b)
	fw, err := w.CreateFormFile("file", "a.png")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fw.Write([]byte("x"))
	_ = w.Close()
	return b.String(), w.FormDataContentType()
}

func contactRoutes(t *testing.T) []contactRoute {
	base := "/api/v2/inventory-service/dcim"
	var out []contactRoute
	for _, r := range services.ContactRoutes() {
		list, one := base+"/"+r, base+"/"+r+"/"+uuid.NewString()
		out = append(out,
			contactRoute{http.MethodGet, list, "", "", false, http.StatusOK},
			contactRoute{http.MethodGet, one, "", "", false, http.StatusOK},
			contactRoute{http.MethodPost, list, `{}`, "", true, http.StatusCreated},
			contactRoute{http.MethodPatch, one, `{}`, "", true, http.StatusOK},
			contactRoute{http.MethodDelete, one, "", "", true, http.StatusNoContent},
		)
	}
	obj := base + "/objects/site/" + uuid.NewString()
	mp, ct := multipartBody(t)
	img := base + "/images/" + uuid.NewString()
	out = append(out,
		contactRoute{http.MethodGet, obj + "/contacts", "", "", false, http.StatusOK},
		contactRoute{http.MethodPost, obj + "/contacts", `{}`, "", true, http.StatusCreated},
		contactRoute{http.MethodGet, obj + "/images", "", "", false, http.StatusOK},
		contactRoute{http.MethodPost, obj + "/images", mp, ct, true, http.StatusCreated},
		contactRoute{http.MethodGet, base + "/images", "", "", false, http.StatusOK},
		contactRoute{http.MethodGet, img, "", "", false, http.StatusOK},
		contactRoute{http.MethodGet, img + "/download", "", "", false, http.StatusOK},
		contactRoute{http.MethodDelete, img, "", "", true, http.StatusNoContent},
	)
	return out
}

func serveContact(r http.Handler, rt contactRoute) *httptest.ResponseRecorder {
	var body io.Reader
	if rt.body != "" {
		body = strings.NewReader(rt.body)
	}
	w := httptest.NewRecorder()
	req := httptest.NewRequest(rt.method, rt.path, body)
	if rt.ctype != "" {
		req.Header.Set("Content-Type", rt.ctype)
	}
	r.ServeHTTP(w, req)
	return w
}

func TestDcimContactRoutes_Gates(t *testing.T) {
	routes := contactRoutes(t)
	if want := 3*5 + 8; len(routes) != want {
		t.Fatalf("expected %d contact/image routes, got %d", want, len(routes))
	}
	for _, rt := range routes {
		name := rt.method + " " + rt.path
		t.Run("no grant/"+name, func(t *testing.T) {
			store := &stubContacts{}
			w := serveContact(contactRouter(t, store), rt)
			if w.Code != http.StatusForbidden || store.calls != 0 {
				t.Fatalf("no dcim grant: status %d, store calls %d — want 403 and nothing reached", w.Code, store.calls)
			}
		})
		t.Run("dcim.read/"+name, func(t *testing.T) {
			store := &stubContacts{}
			w := serveContact(contactRouter(t, store, rbac.PermissionDcimRead), rt)
			if rt.write {
				if w.Code != http.StatusForbidden || store.calls != 0 {
					t.Fatalf("read-only role on a write: status %d, store calls %d — want 403", w.Code, store.calls)
				}
				return
			}
			if w.Code != rt.want || store.calls != 1 {
				t.Fatalf("read with dcim.read: status %d (calls %d), want %d (%s)", w.Code, store.calls, rt.want, w.Body.String())
			}
		})
		t.Run("dcim.manage/"+name, func(t *testing.T) {
			store := &stubContacts{}
			w := serveContact(contactRouter(t, store, rbac.PermissionDcimRead, rbac.PermissionDcimManage), rt)
			if w.Code != rt.want || store.calls != 1 {
				t.Fatalf("status %d (calls %d), want %d (%s)", w.Code, store.calls, rt.want, w.Body.String())
			}
			if !store.sawActor {
				t.Fatal("the store's context carried no actor — changes.Middleware is not mounted")
			}
		})
		t.Run("ipam.manage/"+name, func(t *testing.T) {
			store := &stubContacts{}
			w := serveContact(contactRouter(t, store, rbac.PermissionIpamRead, rbac.PermissionIpamManage), rt)
			if w.Code != http.StatusForbidden {
				t.Fatalf("ipam permissions opened a contact route: status %d", w.Code)
			}
		})
	}
}

func TestDcimContactRoutes_MountedByMain(t *testing.T) {
	raw, err := os.ReadFile(filepath.Clean(mainPath))
	if err != nil {
		t.Fatalf("read %s: %v", mainPath, err)
	}
	if !regexp.MustCompile(`(?m)^\s*mountDcimContactRoutes\(apiv2, rawDB,`).Match(raw) {
		t.Fatal("main.go does not call mountDcimContactRoutes(apiv2, rawDB, …): the contact and image routes are not served")
	}
	if strings.Contains(string(raw), `"/inventory-service/dcim/contacts`) || strings.Contains(string(raw), `"/inventory-service/dcim/images`) {
		t.Fatal("main.go registers a contact/image route directly, outside the gated mount function")
	}
}
