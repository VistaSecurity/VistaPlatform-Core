package rbac

// HTTP-level tests for the tenant role CRUD handlers: every typed service
// refusal must map to a distinguishable status + machine-readable `code`, so the
// UI can react (lock a checkbox, open a reassignment picker) instead of showing
// a generic failure.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// errRBACStore returns a fixed error from every write, so the handler's error
// mapping is what's under test.
type errRBACStore struct {
	stubRBACStore
	err error
}

func (s errRBACStore) UpdateRolePermissions(_, _, _ uuid.UUID, _ []uuid.UUID) error { return s.err }
func (s errRBACStore) CreateTenantRole(_, _ uuid.UUID, _ CreateRoleRequest) (*Role, error) {
	return nil, s.err
}
func (s errRBACStore) DeleteTenantRole(_, _ uuid.UUID, _ *uuid.UUID) (*DeleteRoleResult, error) {
	return nil, s.err
}
func (s errRBACStore) GetPermissionMatrix(_, _, _ uuid.UUID) (*PermissionMatrix, error) {
	return nil, s.err
}

func newWriteCtx(t *testing.T, tenant string, params gin.Params, method, body string) (*gin.Context, *httptest.ResponseRecorder) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(method, "/", strings.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Set("tenantID", tenant)
	c.Set("userID", uuid.NewString())
	c.Params = params
	return c, w
}

func decodeCode(t *testing.T, w *httptest.ResponseRecorder) string {
	t.Helper()
	var payload struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatalf("body is not JSON: %s", w.Body.String())
	}
	return payload.Code
}

// System roles are read-only on ALL THREE write verbs. The reconciliation DO
// block in scripts/database/seed.sql re-asserts their grants on every helm
// upgrade, so a 200 here would be a lie.
func TestHandlers_SystemRoleRejectedOnEveryWriteVerb(t *testing.T) {
	tenant := uuid.NewString()
	roleID := uuid.NewString()
	h := NewRBACHandlersWithStore(errRBACStore{err: ErrSystemRoleImmutable})

	cases := []struct {
		name   string
		run    func(*gin.Context)
		method string
		body   string
		params gin.Params
	}{
		{
			"UpdateRolePermissions", h.UpdateRolePermissions, http.MethodPut,
			`{"permission_ids":[]}`,
			gin.Params{{Key: "tenantId", Value: tenant}, {Key: "roleId", Value: roleID}},
		},
		{
			// Rename: creating over a system role's name is the only "rename"
			// route into a built-in, and it is refused the same way.
			"CreateTenantRole", h.CreateTenantRole, http.MethodPost,
			`{"display_name":"Viewer"}`,
			gin.Params{{Key: "tenantId", Value: tenant}},
		},
		{
			"DeleteTenantRole", h.DeleteTenantRole, http.MethodDelete, "",
			gin.Params{{Key: "tenantId", Value: tenant}, {Key: "roleId", Value: roleID}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, w := newWriteCtx(t, tenant, tc.params, tc.method, tc.body)
			tc.run(c)
			if w.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want 403; body=%s", w.Code, w.Body.String())
			}
			if got := decodeCode(t, w); got != "system_role_immutable" {
				t.Fatalf("code = %q, want system_role_immutable", got)
			}
		})
	}
}

func TestHandlers_EscalationRefusalIs403WithNames(t *testing.T) {
	tenant := uuid.NewString()
	h := NewRBACHandlersWithStore(errRBACStore{err: &ErrPermissionNotHeld{Names: []string{"billing.update"}}})
	c, w := newWriteCtx(t, tenant,
		gin.Params{{Key: "tenantId", Value: tenant}, {Key: "roleId", Value: uuid.NewString()}},
		http.MethodPut, `{"permission_ids":["`+uuid.NewString()+`"]}`)
	h.UpdateRolePermissions(c)

	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", w.Code, w.Body.String())
	}
	var payload struct {
		Code    string   `json:"code"`
		Missing []string `json:"missing_permissions"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Code != "permission_not_held" || len(payload.Missing) != 1 || payload.Missing[0] != "billing.update" {
		t.Fatalf("unexpected payload: %s", w.Body.String())
	}
}

func TestHandlers_UnknownPermissionIs400(t *testing.T) {
	tenant := uuid.NewString()
	h := NewRBACHandlersWithStore(errRBACStore{err: &ErrUnknownPermissions{IDs: []uuid.UUID{uuid.New()}}})
	c, w := newWriteCtx(t, tenant,
		gin.Params{{Key: "tenantId", Value: tenant}, {Key: "roleId", Value: uuid.NewString()}},
		http.MethodPut, `{"permission_ids":["`+uuid.NewString()+`"]}`)
	h.UpdateRolePermissions(c)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	if got := decodeCode(t, w); got != "unknown_permissions" {
		t.Fatalf("code = %q, want unknown_permissions", got)
	}
}

// A blocked delete carries the holder count so the UI can name the impact and
// offer a reassignment target.
func TestHandlers_DeleteBlockedReportsHolderCount(t *testing.T) {
	tenant := uuid.NewString()
	h := NewRBACHandlersWithStore(errRBACStore{err: &ErrRoleInUse{UserCount: 4}})
	c, w := newWriteCtx(t, tenant,
		gin.Params{{Key: "tenantId", Value: tenant}, {Key: "roleId", Value: uuid.NewString()}},
		http.MethodDelete, "")
	h.DeleteTenantRole(c)

	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", w.Code, w.Body.String())
	}
	var payload struct {
		Code      string `json:"code"`
		UserCount int    `json:"user_count"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Code != "role_in_use" || payload.UserCount != 4 {
		t.Fatalf("unexpected payload: %s", w.Body.String())
	}
}

func TestHandlers_CrossTenantRoleIs404(t *testing.T) {
	tenant := uuid.NewString()
	h := NewRBACHandlersWithStore(errRBACStore{err: ErrRoleNotInTenant})
	c, w := newWriteCtx(t, tenant,
		gin.Params{{Key: "tenantId", Value: tenant}, {Key: "roleId", Value: uuid.NewString()}},
		http.MethodGet, "")
	h.GetPermissionMatrix(c)

	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	if got := decodeCode(t, w); got != "role_not_found" {
		t.Fatalf("code = %q, want role_not_found", got)
	}
}

func TestHandlers_DeleteRejectsMalformedReassignTo(t *testing.T) {
	tenant := uuid.NewString()
	h := NewRBACHandlersWithStore(stubRBACStore{})
	c, w := newWriteCtx(t, tenant,
		gin.Params{{Key: "tenantId", Value: tenant}, {Key: "roleId", Value: uuid.NewString()}},
		http.MethodDelete, "")
	c.Request = httptest.NewRequest(http.MethodDelete, "/?reassign_to=not-a-uuid", nil)
	h.DeleteTenantRole(c)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
}

func TestHandlers_CreateReturns201WithRole(t *testing.T) {
	tenant := uuid.NewString()
	h := NewRBACHandlersWithStore(stubRBACStore{})
	c, w := newWriteCtx(t, tenant, gin.Params{{Key: "tenantId", Value: tenant}},
		http.MethodPost, `{"display_name":"Auditors"}`)
	h.CreateTenantRole(c)

	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", w.Code, w.Body.String())
	}
	var payload struct {
		Role map[string]interface{} `json:"role"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Role == nil {
		t.Fatalf("expected a `role` envelope; got %s", w.Body.String())
	}
}

// display_name is required — a body without it must not reach the service.
func TestHandlers_CreateRequiresDisplayName(t *testing.T) {
	tenant := uuid.NewString()
	h := NewRBACHandlersWithStore(stubRBACStore{})
	c, w := newWriteCtx(t, tenant, gin.Params{{Key: "tenantId", Value: tenant}},
		http.MethodPost, `{"name":"auditors"}`)
	h.CreateTenantRole(c)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
}
