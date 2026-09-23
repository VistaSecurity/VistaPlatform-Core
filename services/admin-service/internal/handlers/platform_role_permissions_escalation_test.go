package handlers

// platform_roles.manage must not be a way around platform_roles.assign
// (authorizeRolePermissionEdit in roles.go). Each denial asserts the permission
// set was not written; the real-router half is
// internal/api/platform_role_permissions_integration_test.go.

import (
	"net/http"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const editedRoleID = "6b000000-0000-4000-8000-0000000000e1"

// rbacEngineAs is rbacEngine with a fixed caller (or none, for "").
func rbacEngineAs(store platformRBACStore, callerID string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group(apiBase)
	grp.Use(func(c *gin.Context) {
		if callerID != "" {
			c.Set("userID", callerID)
		}
		c.Next()
	})
	grp.POST("/admin/roles", CreatePlatformRole(store))
	grp.PUT("/admin/roles/:id", UpdatePlatformRole(store))
	grp.DELETE("/admin/roles/:id", DeletePlatformRole(store))
	grp.PUT("/admin/roles/:id/permissions", SetPlatformRolePermissions(store))
	return r
}

func putRolePerms(s *stubPlatformRBACStore, callerID, roleID string) (int, string) {
	w := doRequest(rbacEngineAs(s, callerID), http.MethodPut, apiBase+"/admin/roles/"+roleID+"/permissions",
		strings.NewReader(`{"permission_ids":["`+uuid.NewString()+`"]}`))
	return w.Code, w.Body.String()
}

func expectPermsNotWritten(t *testing.T, s *stubPlatformRBACStore) {
	t.Helper()
	if s.setPermsCalled {
		t.Fatal("a denied permission edit still wrote the role's permissions")
	}
}

func TestRolePerms_403_AddPermissionCallerLacks(t *testing.T) {
	s := &stubPlatformRBACStore{missingNew: []string{"platform.override"}}
	code, body := putRolePerms(s, stubCallerID, editedRoleID)
	expect(t, "grant an unheld permission", code, body, http.StatusForbidden)
	requireMissingPermissions(t, body)
	expectPermsNotWritten(t, s)
}

// Editing your own role is refused even when every permission is one you hold:
// it is how a caller would keep a grant after someone else narrows the role.
func TestRolePerms_403_OwnRole(t *testing.T) {
	s := &stubPlatformRBACStore{callerRoleID: editedRoleID}
	code, body := putRolePerms(s, stubCallerID, strings.ToUpper(editedRoleID))
	expect(t, "edit own role", code, body, http.StatusForbidden)
	expectPermsNotWritten(t, s)
}

// A lesser operator does not strip a role that outranks them.
func TestRolePerms_403_RoleOutranksCaller(t *testing.T) {
	s := &stubPlatformRBACStore{missingCurrent: []string{"platform_users.delete"}}
	code, body := putRolePerms(s, stubCallerID, editedRoleID)
	expect(t, "edit a role that outranks the caller", code, body, http.StatusForbidden)
	requireMissingPermissions(t, body)
	expectPermsNotWritten(t, s)
}

func TestRolePerms_401_NoCaller(t *testing.T) {
	s := &stubPlatformRBACStore{}
	code, body := putRolePerms(s, "", editedRoleID)
	expect(t, "edit without a caller", code, body, http.StatusUnauthorized)
	expectPermsNotWritten(t, s)
}

// The other polarity: a role that does not outrank the caller, set to
// permissions the caller holds, by someone whose role it is not.
func TestRolePerms_200_WithinCallerPermissions(t *testing.T) {
	s := &stubPlatformRBACStore{callerRoleID: uuid.NewString()}
	code, body := putRolePerms(s, stubCallerID, editedRoleID)
	expect(t, "edit within permissions", code, body, http.StatusOK)
	if !s.setPermsCalled {
		t.Fatal("the permitted edit was not written")
	}
}

// Create has no permission path: a body carrying permission_ids creates an
// empty role and never writes permissions. If create ever learns to accept
// permissions, this test is the reminder that it needs the same guard.
func TestRolePerms_CreateNeverWritesPermissions(t *testing.T) {
	s := &stubPlatformRBACStore{createID: uuid.NewString(), missingNew: []string{"platform.override"}}
	w := doRequest(rbacEngineAs(s, stubCallerID), http.MethodPost, apiBase+"/admin/roles",
		strings.NewReader(`{"name":"sneaky","display_name":"Sneaky","permission_ids":["`+uuid.NewString()+`"]}`))
	expect(t, "create role", w.Code, w.Body.String(), http.StatusCreated)
	if s.createCalls != 1 {
		t.Fatalf("CreateRole calls = %d, want 1", s.createCalls)
	}
	expectPermsNotWritten(t, s)
}
