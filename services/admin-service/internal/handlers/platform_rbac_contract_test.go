package handlers

// Contract test for the platform RBAC HTTP surface (admin-ui Roles &
// Permissions page): /admin/roles CRUD + /admin/permissions reads +
// /admin/user/permissions.
//
// These handlers were free functions taking *sql.DB and running SQL inline;
// this slice landed a behaviour-preserving repo extraction first (the queries
// moved verbatim into platformRBACRepository behind the platformRBACStore
// interface — see platform_rbac_repository.go), plus a one-method
// userPermissionProvider interface for the current-user endpoint. So the real
// gin handlers run over httptest with in-memory stubs — no database, no RBAC
// service — and their bodies are asserted against
// api/openapi/admin-service.openapi.yaml.
//
// The spec-loading + assertConforms + doRequest harness and the apiBase
// const are shared with tenant_billing_contract_test.go (same package, same
// spec file) and reused here rather than redefined.

import (
	"database/sql"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/vistasecurity/vistaplatform/shared/models"
)

// --- in-memory stubs --------------------------------------------------------

type stubPlatformRBACStore struct {
	roles        []platformRoleRow
	rolesErr     error
	role         platformRoleRow
	roleErr      error
	permNames    []string
	permNamesErr error
	createID     string
	createErr    error
	updateErr    error
	isSystem     bool
	isSystemErr  error
	deleteErr    error
	setPermsErr  error
	perms        []models.PlatformPermission
	permsErr     error
	perm         models.PlatformPermission
	permErr      error
}

func (s *stubPlatformRBACStore) ListRoles() ([]platformRoleRow, error) { return s.roles, s.rolesErr }
func (s *stubPlatformRBACStore) GetRole(string) (platformRoleRow, error) {
	return s.role, s.roleErr
}
func (s *stubPlatformRBACStore) RolePermissionNames(string) ([]string, error) {
	return s.permNames, s.permNamesErr
}
func (s *stubPlatformRBACStore) CreateRole(string, string, string) (string, time.Time, time.Time, error) {
	now := time.Now().UTC()
	return s.createID, now, now, s.createErr
}
func (s *stubPlatformRBACStore) UpdateRoleFields(string, *string, *string) error { return s.updateErr }
func (s *stubPlatformRBACStore) RoleIsSystem(string) (bool, error)               { return s.isSystem, s.isSystemErr }
func (s *stubPlatformRBACStore) DeleteRole(string) error                         { return s.deleteErr }
func (s *stubPlatformRBACStore) SetRolePermissions(string, []string) error {
	return s.setPermsErr
}
func (s *stubPlatformRBACStore) ListPermissions() ([]models.PlatformPermission, error) {
	return s.perms, s.permsErr
}
func (s *stubPlatformRBACStore) GetPermission(string) (models.PlatformPermission, error) {
	return s.perm, s.permErr
}

type stubUserPermissionProvider struct {
	perms []*models.PlatformPermission
	err   error
}

func (s *stubUserPermissionProvider) GetPlatformUserPermissions(uuid.UUID) ([]*models.PlatformPermission, error) {
	return s.perms, s.err
}

// --- engine helpers ---------------------------------------------------------

func rbacEngine(store platformRBACStore, prov userPermissionProvider, withUser bool) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group(apiBase)
	if withUser {
		grp.Use(func(c *gin.Context) {
			c.Set("userID", uuid.New().String())
			c.Next()
		})
	}
	grp.GET("/admin/roles", ListPlatformRoles(store))
	grp.GET("/admin/roles/:id", GetPlatformRole(store))
	grp.POST("/admin/roles", CreatePlatformRole(store))
	grp.PUT("/admin/roles/:id", UpdatePlatformRole(store))
	grp.PUT("/admin/roles/:id/permissions", SetPlatformRolePermissions(store))
	grp.DELETE("/admin/roles/:id", DeletePlatformRole(store))
	grp.GET("/admin/permissions", ListPlatformPermissions(store))
	grp.GET("/admin/permissions/:id", GetPlatformPermission(store))
	grp.GET("/admin/user/permissions", GetCurrentUserPermissions(prov))
	return r
}

// --- sample data ------------------------------------------------------------

func samplePlatformRole() platformRoleRow {
	now := time.Now().UTC()
	return platformRoleRow{
		PlatformRole: models.PlatformRole{
			ID:           uuid.New(),
			Name:         "platform_admin",
			DisplayName:  "Platform Admin",
			Description:  "Full platform access",
			IsSystemRole: true,
			CreatedAt:    now,
			UpdatedAt:    now,
		},
		UserCount: 3,
	}
}

func samplePlatformPermission() models.PlatformPermission {
	return models.PlatformPermission{
		ID:          uuid.New(),
		Name:        "platform_users.manage",
		Resource:    "platform_users",
		Action:      "manage",
		Description: "Manage platform users",
		CreatedAt:   time.Now().UTC(),
		// UpdatedAt left zero → serializes as 0001-01-01T00:00:00Z.
	}
}

// --- roles ------------------------------------------------------------------

func TestContract_ListPlatformRoles_200(t *testing.T) {
	sv := loadSpec(t)
	eng := rbacEngine(&stubPlatformRBACStore{
		roles:     []platformRoleRow{samplePlatformRole()},
		permNames: []string{"platform_users.manage", "platform_roles.read"},
	}, nil, false)
	w := doRequest(eng, http.MethodGet, apiBase+"/admin/roles", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "RoleListResponse", w.Body.Bytes())
}

// No roles → nil slice → `{"roles": null}`.
func TestContract_ListPlatformRoles_200_empty(t *testing.T) {
	sv := loadSpec(t)
	eng := rbacEngine(&stubPlatformRBACStore{roles: nil}, nil, false)
	w := doRequest(eng, http.MethodGet, apiBase+"/admin/roles", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "RoleListResponse", w.Body.Bytes())
}

func TestContract_GetPlatformRole_200(t *testing.T) {
	sv := loadSpec(t)
	eng := rbacEngine(&stubPlatformRBACStore{
		role:      samplePlatformRole(),
		permNames: []string{"platform_users.read"},
	}, nil, false)
	w := doRequest(eng, http.MethodGet, apiBase+"/admin/roles/role_1", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "RoleDetailResponse", w.Body.Bytes())
}

func TestContract_GetPlatformRole_404(t *testing.T) {
	sv := loadSpec(t)
	eng := rbacEngine(&stubPlatformRBACStore{roleErr: sql.ErrNoRows}, nil, false)
	w := doRequest(eng, http.MethodGet, apiBase+"/admin/roles/missing", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_CreatePlatformRole_201(t *testing.T) {
	sv := loadSpec(t)
	eng := rbacEngine(&stubPlatformRBACStore{createID: uuid.New().String()}, nil, false)
	w := doRequest(eng, http.MethodPost, apiBase+"/admin/roles",
		strings.NewReader(`{"name":"auditor","display_name":"Auditor","description":"read-only"}`))
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "CreateRoleResponse", w.Body.Bytes())
}

// Missing required fields → binding error → 400.
func TestContract_CreatePlatformRole_400(t *testing.T) {
	sv := loadSpec(t)
	eng := rbacEngine(&stubPlatformRBACStore{}, nil, false)
	w := doRequest(eng, http.MethodPost, apiBase+"/admin/roles", strings.NewReader(`{}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_UpdatePlatformRole_200(t *testing.T) {
	sv := loadSpec(t)
	eng := rbacEngine(&stubPlatformRBACStore{}, nil, false)
	w := doRequest(eng, http.MethodPut, apiBase+"/admin/roles/role_1",
		strings.NewReader(`{"display_name":"Renamed"}`))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "MessageResponse", w.Body.Bytes())
}

// Empty body (no fields) → 400 "No fields to update".
func TestContract_UpdatePlatformRole_400(t *testing.T) {
	sv := loadSpec(t)
	eng := rbacEngine(&stubPlatformRBACStore{}, nil, false)
	w := doRequest(eng, http.MethodPut, apiBase+"/admin/roles/role_1", strings.NewReader(`{}`))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_DeletePlatformRole_200(t *testing.T) {
	sv := loadSpec(t)
	eng := rbacEngine(&stubPlatformRBACStore{isSystem: false}, nil, false)
	w := doRequest(eng, http.MethodDelete, apiBase+"/admin/roles/role_1", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "MessageResponse", w.Body.Bytes())
}

// System roles cannot be deleted → 400.
func TestContract_DeletePlatformRole_400_system(t *testing.T) {
	sv := loadSpec(t)
	eng := rbacEngine(&stubPlatformRBACStore{isSystem: true}, nil, false)
	w := doRequest(eng, http.MethodDelete, apiBase+"/admin/roles/role_1", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// Missing role (system-role check errors) → 404.
func TestContract_DeletePlatformRole_404(t *testing.T) {
	sv := loadSpec(t)
	eng := rbacEngine(&stubPlatformRBACStore{isSystemErr: sql.ErrNoRows}, nil, false)
	w := doRequest(eng, http.MethodDelete, apiBase+"/admin/roles/missing", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- set role permissions ---------------------------------------------------

func TestContract_SetPlatformRolePermissions_200(t *testing.T) {
	sv := loadSpec(t)
	eng := rbacEngine(&stubPlatformRBACStore{isSystem: false}, nil, false)
	w := doRequest(eng, http.MethodPut, apiBase+"/admin/roles/role_1/permissions",
		strings.NewReader(`{"permission_ids":["`+uuid.New().String()+`","`+uuid.New().String()+`"]}`))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "SetRolePermissionsResponse", w.Body.Bytes())
}

// Empty array clears all permissions → still 200.
func TestContract_SetPlatformRolePermissions_200_empty(t *testing.T) {
	sv := loadSpec(t)
	eng := rbacEngine(&stubPlatformRBACStore{isSystem: false}, nil, false)
	w := doRequest(eng, http.MethodPut, apiBase+"/admin/roles/role_1/permissions",
		strings.NewReader(`{"permission_ids":[]}`))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "SetRolePermissionsResponse", w.Body.Bytes())
}

// System roles are immutable → 403.
func TestContract_SetPlatformRolePermissions_403_system(t *testing.T) {
	sv := loadSpec(t)
	eng := rbacEngine(&stubPlatformRBACStore{isSystem: true}, nil, false)
	w := doRequest(eng, http.MethodPut, apiBase+"/admin/roles/role_1/permissions",
		strings.NewReader(`{"permission_ids":["`+uuid.New().String()+`"]}`))
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// Missing role (system-role check errors) → 404.
func TestContract_SetPlatformRolePermissions_404(t *testing.T) {
	sv := loadSpec(t)
	eng := rbacEngine(&stubPlatformRBACStore{isSystemErr: sql.ErrNoRows}, nil, false)
	w := doRequest(eng, http.MethodPut, apiBase+"/admin/roles/missing/permissions",
		strings.NewReader(`{"permission_ids":[]}`))
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- permissions ------------------------------------------------------------

func TestContract_ListPlatformPermissions_200(t *testing.T) {
	sv := loadSpec(t)
	eng := rbacEngine(&stubPlatformRBACStore{
		perms: []models.PlatformPermission{samplePlatformPermission()},
	}, nil, false)
	w := doRequest(eng, http.MethodGet, apiBase+"/admin/permissions", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "PermissionListResponse", w.Body.Bytes())
}

// No permissions → nil slice → `{"permissions": null}`.
func TestContract_ListPlatformPermissions_200_empty(t *testing.T) {
	sv := loadSpec(t)
	eng := rbacEngine(&stubPlatformRBACStore{perms: nil}, nil, false)
	w := doRequest(eng, http.MethodGet, apiBase+"/admin/permissions", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "PermissionListResponse", w.Body.Bytes())
}

func TestContract_GetPlatformPermission_200(t *testing.T) {
	sv := loadSpec(t)
	eng := rbacEngine(&stubPlatformRBACStore{perm: samplePlatformPermission()}, nil, false)
	w := doRequest(eng, http.MethodGet, apiBase+"/admin/permissions/perm_1", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "PermissionDetailResponse", w.Body.Bytes())
}

func TestContract_GetPlatformPermission_404(t *testing.T) {
	sv := loadSpec(t)
	eng := rbacEngine(&stubPlatformRBACStore{permErr: sql.ErrNoRows}, nil, false)
	w := doRequest(eng, http.MethodGet, apiBase+"/admin/permissions/missing", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- current user permissions -----------------------------------------------

func TestContract_GetCurrentUserPermissions_200(t *testing.T) {
	sv := loadSpec(t)
	p := samplePlatformPermission()
	eng := rbacEngine(&stubPlatformRBACStore{}, &stubUserPermissionProvider{
		perms: []*models.PlatformPermission{&p},
	}, true)
	w := doRequest(eng, http.MethodGet, apiBase+"/admin/user/permissions", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "PermissionListResponse", w.Body.Bytes())
}

// No userID in context → 401.
func TestContract_GetCurrentUserPermissions_401(t *testing.T) {
	sv := loadSpec(t)
	eng := rbacEngine(&stubPlatformRBACStore{}, &stubUserPermissionProvider{}, false)
	w := doRequest(eng, http.MethodGet, apiBase+"/admin/user/permissions", nil)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- drift guards -----------------------------------------------------------

func TestContract_Role_DriftIsCaught(t *testing.T) {
	sv := loadSpec(t)
	sch, err := sv.compiler.Compile(specBaseURI + "#/components/schemas/Role")
	if err != nil {
		t.Fatalf("compile Role: %v", err)
	}
	bad, err := jsonschema.UnmarshalJSON(strings.NewReader(`{"id":"x","surprise_field":true}`))
	if err != nil {
		t.Fatalf("unmarshal bad body: %v", err)
	}
	if err := sch.Validate(bad); err == nil {
		t.Fatal("expected validation to FAIL for a drifted Role, but it passed — the guardrail is not actually checking")
	}
}

func TestContract_Permission_DriftIsCaught(t *testing.T) {
	sv := loadSpec(t)
	sch, err := sv.compiler.Compile(specBaseURI + "#/components/schemas/Permission")
	if err != nil {
		t.Fatalf("compile Permission: %v", err)
	}
	bad, err := jsonschema.UnmarshalJSON(strings.NewReader(`{"id":"x","surprise_field":true}`))
	if err != nil {
		t.Fatalf("unmarshal bad body: %v", err)
	}
	if err := sch.Validate(bad); err == nil {
		t.Fatal("expected validation to FAIL for a drifted Permission, but it passed — the guardrail is not actually checking")
	}
}
