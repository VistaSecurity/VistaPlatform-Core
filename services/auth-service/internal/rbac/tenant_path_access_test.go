package rbac

// Unit tests for the cross-tenant guard on the RBAC read handlers.
// These drive the handlers with an in-memory rbacStore stub (no DB) via the
// test-only NewRBACHandlersWithStore constructor, and assert that a caller whose
// token tenant differs from the :tenantId path param is rejected with 403 — the
// same protection AssignRole / RemoveRole already enforce.

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// stubRBACStore returns canned data; the read handlers under test only need
// GetTenantRoles / GetUserRoles / GetUserPermissions to succeed so we can prove
// the guard runs BEFORE the service call (a leak would 200 with data).
type stubRBACStore struct{}

func (stubRBACStore) GetUserPermissions(_, _ uuid.UUID) ([]Permission, error) {
	return []Permission{{Name: "compliance.read"}}, nil
}
func (stubRBACStore) GetTenantRoles(_ uuid.UUID) ([]Role, error) {
	return []Role{{Name: "viewer"}}, nil
}
func (stubRBACStore) GetTenantPermissions(_ uuid.UUID) ([]Permission, error) { return nil, nil }
func (stubRBACStore) GetUserRoles(_, _ uuid.UUID) ([]Role, error) {
	return []Role{{Name: "viewer"}}, nil
}
func (stubRBACStore) AssignUserRole(_, _, _, _ uuid.UUID) error { return nil }
func (stubRBACStore) RemoveUserRole(_, _, _ uuid.UUID) error    { return nil }
func (stubRBACStore) GetPermissionMatrix(_, _, _ uuid.UUID) (*PermissionMatrix, error) {
	return &PermissionMatrix{}, nil
}
func (stubRBACStore) UpdateRolePermissions(_, _, _ uuid.UUID, _ []uuid.UUID) error { return nil }
func (stubRBACStore) CreateTenantRole(_, _ uuid.UUID, _ CreateRoleRequest) (*Role, error) {
	return &Role{}, nil
}
func (stubRBACStore) DeleteTenantRole(_, _ uuid.UUID, _ *uuid.UUID) (*DeleteRoleResult, error) {
	return &DeleteRoleResult{}, nil
}
func (stubRBACStore) CheckPermission(_, _ uuid.UUID, _ string) (bool, error) { return true, nil }

// newCtx builds a gin context whose token tenant is `tokenTenant` (as
// RequireAuth would set it) and whose path params are provided.
func newCtx(tokenTenant string, params gin.Params) (*gin.Context, *httptest.ResponseRecorder) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	if tokenTenant != "" {
		c.Set("tenantID", tokenTenant)
	}
	// The role write/matrix handlers also read the acting user id (for the
	// escalation guard), so RequireAuth's other context key is modelled too.
	c.Set("userID", uuid.NewString())
	c.Params = params
	return c, w
}

func TestRBACReadHandlers_RejectCrossTenant(t *testing.T) {
	h := NewRBACHandlersWithStore(stubRBACStore{})
	callerTenant := uuid.NewString()
	otherTenant := uuid.NewString()
	otherUser := uuid.NewString()

	cases := []struct {
		name   string
		run    func(*gin.Context)
		params gin.Params
	}{
		{"GetTenantRoles", h.GetTenantRoles, gin.Params{{Key: "tenantId", Value: otherTenant}}},
		{"GetUserRoles", h.GetUserRoles, gin.Params{{Key: "tenantId", Value: otherTenant}, {Key: "userId", Value: otherUser}}},
		{"GetUserPermissions", h.GetUserPermissions, gin.Params{{Key: "tenantId", Value: otherTenant}, {Key: "userId", Value: otherUser}}},
		//: a cross-tenant roleId is rejected by the path guard before any
		// service call (the guard runs ahead of the body parse for the PUT).
		{"GetPermissionMatrix", h.GetPermissionMatrix, gin.Params{{Key: "tenantId", Value: otherTenant}, {Key: "roleId", Value: uuid.NewString()}}},
		{"UpdateRolePermissions", h.UpdateRolePermissions, gin.Params{{Key: "tenantId", Value: otherTenant}, {Key: "roleId", Value: uuid.NewString()}}},
		{"CreateTenantRole", h.CreateTenantRole, gin.Params{{Key: "tenantId", Value: otherTenant}}},
		{"DeleteTenantRole", h.DeleteTenantRole, gin.Params{{Key: "tenantId", Value: otherTenant}, {Key: "roleId", Value: uuid.NewString()}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, w := newCtx(callerTenant, tc.params)
			tc.run(c)
			if w.Code != http.StatusForbidden {
				t.Fatalf("%s: cross-tenant request returned %d, want 403; body=%s", tc.name, w.Code, w.Body.String())
			}
		})
	}
}

func TestRBACReadHandlers_AllowSameTenant(t *testing.T) {
	h := NewRBACHandlersWithStore(stubRBACStore{})
	tenant := uuid.NewString()
	user := uuid.NewString()

	cases := []struct {
		name   string
		run    func(*gin.Context)
		params gin.Params
	}{
		{"GetTenantRoles", h.GetTenantRoles, gin.Params{{Key: "tenantId", Value: tenant}}},
		{"GetUserRoles", h.GetUserRoles, gin.Params{{Key: "tenantId", Value: tenant}, {Key: "userId", Value: user}}},
		{"GetUserPermissions", h.GetUserPermissions, gin.Params{{Key: "tenantId", Value: tenant}, {Key: "userId", Value: user}}},
		//: same-tenant matrix read passes the guard (the stub returns nil).
		{"GetPermissionMatrix", h.GetPermissionMatrix, gin.Params{{Key: "tenantId", Value: tenant}, {Key: "roleId", Value: uuid.NewString()}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, w := newCtx(tenant, tc.params)
			tc.run(c)
			if w.Code != http.StatusOK {
				t.Fatalf("%s: same-tenant request returned %d, want 200; body=%s", tc.name, w.Code, w.Body.String())
			}
		})
	}
}

func TestRBACReadHandlers_RejectMissingToken(t *testing.T) {
	h := NewRBACHandlersWithStore(stubRBACStore{})
	// No token tenant set (as if RequireAuth were bypassed) → must not 200.
	c, w := newCtx("", gin.Params{{Key: "tenantId", Value: uuid.NewString()}})
	h.GetTenantRoles(c)
	if w.Code != http.StatusForbidden {
		t.Fatalf("missing-token request returned %d, want 403; body=%s", w.Code, w.Body.String())
	}
}
