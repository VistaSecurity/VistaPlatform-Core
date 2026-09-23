package handlers

// Privilege-escalation guard for platform_users.role_id (security-staff-1).
//
// Every route that writes a platform user's role — create, invite, update — is
// driven through its REAL handler here, over the same stub store the contract
// tests use, with the store's role-assignment seams set to deny. Each denial
// test also asserts that nothing was written, so deleting the
// authorizeRoleAssignment call from any one handler turns that handler's tests
// red (the fix was mutation-tested that way; see the PR).
//
// The DB-backed half — the real admin-service router, the real
// platform_user_has_permission() and the real seeded roles — is
// internal/api/platform_role_assignment_integration_test.go.

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
)

var (
	roleSuperAdmin    = uuid.MustParse("5a000000-0000-4000-8000-000000000001")
	rolePlatformAdmin = uuid.MustParse("5a000000-0000-4000-8000-000000000002")
	roleSupport       = uuid.MustParse("5a000000-0000-4000-8000-000000000003")
	targetUserID      = "7a000000-0000-4000-8000-0000000000aa"
)

func roleRef(id uuid.UUID, name string) platformUserRoleRef {
	rid := id
	return platformUserRoleRef{RoleID: &rid, RoleName: name}
}

// escalationStore models a platform_admin-shaped caller acting on a
// support_agent-shaped target. Tests switch individual seams to deny.
func escalationStore() *stubPlatformUserStore {
	return &stubPlatformUserStore{
		roleExists: true,
		createID:   uuid.NewString(),
		roleRefs: map[string]platformUserRoleRef{
			stubCallerID: roleRef(rolePlatformAdmin, "platform_admin"),
			targetUserID: roleRef(roleSupport, "support_agent"),
		},
		roleNames: map[uuid.UUID]string{
			roleSuperAdmin:    "super_admin",
			rolePlatformAdmin: "platform_admin",
			roleSupport:       "support_agent",
		},
		// A platform_admin does not hold what super_admin grants.
		missingByRole: map[string][]string{
			roleSuperAdmin.String(): {"platform_roles.assign", "platform_roles.manage", "platform_users.delete"},
		},
	}
}

func putRole(t *testing.T, store *stubPlatformUserStore, userID string, roleID uuid.UUID) (int, map[string]any) {
	t.Helper()
	eng := platformUserEngine(store, stubPasswordHasher{}, "")
	w := doRequest(eng, http.MethodPut, platformUserBase+"/"+userID,
		strings.NewReader(`{"first_name":"Renamed","role_id":"`+roleID.String()+`"}`))
	return w.Code, decodeBody(t, w.Body.Bytes())
}

func decodeBody(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal %q: %v", string(b), err)
	}
	return m
}

func expectNothingUpdated(t *testing.T, s *stubPlatformUserStore) {
	t.Helper()
	if s.updated != nil {
		t.Fatalf("a denied role change still wrote the user: %+v", *s.updated)
	}
}

// --- update: PUT /admin/users/:id ------------------------------------------

// The reported exploit: platform_users.manage alone was enough to set role_id.
func TestRoleAssign_Update_403_WithoutPlatformRolesAssign(t *testing.T) {
	s := escalationStore()
	s.denyAssign = true
	code, body := putRole(t, s, targetUserID, rolePlatformAdmin)
	if code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%v", code, body)
	}
	if body["required_permission"] != "platform_roles.assign" {
		t.Errorf("403 must name platform_roles.assign; body=%v", body)
	}
	expectNothingUpdated(t, s)
}

// The self-promotion variant of the exploit — also refused by the assign gate.
func TestRoleAssign_Update_403_SelfPromotionWithoutAssign(t *testing.T) {
	s := escalationStore()
	s.denyAssign = true
	code, body := putRole(t, s, stubCallerID, roleSuperAdmin)
	if code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%v", code, body)
	}
	expectNothingUpdated(t, s)
}

func TestRoleAssign_Update_403_TargetRoleBroaderThanCaller(t *testing.T) {
	s := escalationStore() // assign granted; super_admin is broader
	code, body := putRole(t, s, targetUserID, roleSuperAdmin)
	if code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%v", code, body)
	}
	missing, _ := body["missing_permissions"].([]any)
	if len(missing) == 0 {
		t.Errorf("403 must list the permissions the caller lacks; body=%v", body)
	}
	expectNothingUpdated(t, s)
}

// A lesser operator must not be able to demote (lock out) someone who outranks
// them, even to a role they could otherwise grant.
func TestRoleAssign_Update_403_CurrentRoleBroaderThanCaller(t *testing.T) {
	s := escalationStore()
	s.roleRefs[targetUserID] = roleRef(roleSuperAdmin, "super_admin")
	code, body := putRole(t, s, targetUserID, roleSupport)
	if code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%v", code, body)
	}
	expectNothingUpdated(t, s)
}

// Holding assign and a narrower role is not enough to change your OWN role.
func TestRoleAssign_Update_403_SelfChange(t *testing.T) {
	s := escalationStore()
	code, body := putRole(t, s, stubCallerID, roleSupport)
	if code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%v", code, body)
	}
	expectNothingUpdated(t, s)
}

// The other polarity of every check above: a caller holding assign, granting
// a role within their own permissions, to someone else, succeeds.
func TestRoleAssign_Update_200_WithinCallerPermissions(t *testing.T) {
	s := escalationStore()
	code, body := putRole(t, s, targetUserID, rolePlatformAdmin)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%v", code, body)
	}
	if s.updated == nil || s.updated.RoleID == nil || *s.updated.RoleID != rolePlatformAdmin {
		t.Fatalf("role was not written: %+v", s.updated)
	}
}

func TestRoleAssign_Update_200_SuperAdmin(t *testing.T) {
	s := escalationStore()
	s.roleRefs[stubCallerID] = roleRef(roleSuperAdmin, "super_admin")
	s.missingByRole = nil // super_admin holds every permission
	code, body := putRole(t, s, targetUserID, roleSuperAdmin)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%v", code, body)
	}
}

// super_admin may step down while another active super_admin remains...
func TestRoleAssign_Update_200_SuperAdminSelfDemotionWithAnotherSuperAdmin(t *testing.T) {
	s := escalationStore()
	s.roleRefs[stubCallerID] = roleRef(roleSuperAdmin, "super_admin")
	s.missingByRole = nil
	s.otherSuperAdmins = 1
	code, body := putRole(t, s, stubCallerID, rolePlatformAdmin)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%v", code, body)
	}
}

// ...but never as the last one.
func TestRoleAssign_Update_409_LastSuperAdminSelfDemotion(t *testing.T) {
	s := escalationStore()
	s.roleRefs[stubCallerID] = roleRef(roleSuperAdmin, "super_admin")
	s.missingByRole = nil
	s.otherSuperAdmins = 0
	code, body := putRole(t, s, stubCallerID, rolePlatformAdmin)
	if code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%v", code, body)
	}
	expectNothingUpdated(t, s)
}

// The Edit form always re-sends role_id. Re-sending the user's EXISTING role is
// not a role change, so a profile edit by an operator without assign still
// works — without this, the fix would break every name edit.
func TestRoleAssign_Update_200_UnchangedRoleNeedsNoAssign(t *testing.T) {
	s := escalationStore()
	s.denyAssign = true
	code, body := putRole(t, s, targetUserID, roleSupport)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%v", code, body)
	}
}

func TestRoleAssign_Update_200_NoRoleFieldNeedsNoAssign(t *testing.T) {
	s := escalationStore()
	s.denyAssign = true
	eng := platformUserEngine(s, stubPasswordHasher{}, "")
	w := doRequest(eng, http.MethodPut, platformUserBase+"/"+targetUserID, strings.NewReader(`{"first_name":"Renamed"}`))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
}

func TestRoleAssign_Update_404_UnknownTargetWithRole(t *testing.T) {
	s := escalationStore()
	code, body := putRole(t, s, uuid.NewString(), roleSupport)
	if code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%v", code, body)
	}
	expectNothingUpdated(t, s)
}

// --- create: POST /admin/users ---------------------------------------------

func postCreate(t *testing.T, s *stubPlatformUserStore, roleID uuid.UUID) (int, map[string]any) {
	t.Helper()
	eng := platformUserEngine(s, stubPasswordHasher{}, "")
	body := `{"email":"new@vistaplatform.local","password":"` + strongPassword() + `","first_name":"New","last_name":"Admin","role_id":"` + roleID.String() + `"}`
	w := doRequest(eng, http.MethodPost, platformUserBase, strings.NewReader(body))
	return w.Code, decodeBody(t, w.Body.Bytes())
}

func TestRoleAssign_Create_403_WithoutPlatformRolesAssign(t *testing.T) {
	s := escalationStore()
	s.denyAssign = true
	code, body := postCreate(t, s, roleSupport)
	if code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%v", code, body)
	}
	if s.created {
		t.Fatal("a denied create still inserted the user")
	}
}

func TestRoleAssign_Create_403_RoleBroaderThanCaller(t *testing.T) {
	s := escalationStore()
	code, body := postCreate(t, s, roleSuperAdmin)
	if code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%v", code, body)
	}
	if s.created {
		t.Fatal("a denied create still inserted the user")
	}
}

func TestRoleAssign_Create_201_WithinCallerPermissions(t *testing.T) {
	s := escalationStore()
	code, body := postCreate(t, s, roleSupport)
	if code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%v", code, body)
	}
}

// --- invite: POST /admin/users/invite ---------------------------------------

func postInvite(t *testing.T, s *stubPlatformUserStore, roleID uuid.UUID) (int, map[string]any) {
	t.Helper()
	eng := platformUserEmailEngine(s, stubPasswordHasher{}, emailSends(), stubBrandingProvider{}, stubCallerID)
	body := `{"email":"invitee@vistaplatform.local","first_name":"Inv","last_name":"Itee","role_id":"` + roleID.String() + `"}`
	w := doRequest(eng, http.MethodPost, inviteBase, strings.NewReader(body))
	return w.Code, decodeBody(t, w.Body.Bytes())
}

func TestRoleAssign_Invite_403_WithoutPlatformRolesAssign(t *testing.T) {
	s := escalationStore()
	s.denyAssign = true
	code, body := postInvite(t, s, roleSupport)
	if code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%v", code, body)
	}
	if s.created {
		t.Fatal("a denied invite still inserted the user")
	}
}

func TestRoleAssign_Invite_403_RoleBroaderThanCaller(t *testing.T) {
	s := escalationStore()
	code, body := postInvite(t, s, roleSuperAdmin)
	if code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403; body=%v", code, body)
	}
	if s.created {
		t.Fatal("a denied invite still inserted the user")
	}
}

func TestRoleAssign_Invite_201_WithinCallerPermissions(t *testing.T) {
	s := escalationStore()
	code, body := postInvite(t, s, roleSupport)
	if code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body=%v", code, body)
	}
}

// An unidentified caller cannot be authorized to grant anything.
func TestRoleAssign_Invite_401_NoCaller(t *testing.T) {
	s := escalationStore()
	eng := platformUserEmailEngine(s, stubPasswordHasher{}, emailSends(), stubBrandingProvider{}, "")
	w := doRequest(eng, http.MethodPost, inviteBase, strings.NewReader(validInviteBody()))
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401; body=%s", w.Code, w.Body.String())
	}
	if s.created {
		t.Fatal("an unauthenticated invite inserted the user")
	}
}

// --- audit -------------------------------------------------------------------

// A role change is recorded as its own event carrying both the old and the new
// role, read back from the store rather than echoed from the request.
func TestRoleAssign_Update_AuditsOldAndNewRole(t *testing.T) {
	ch := captureAudit(t)
	s := escalationStore()
	code, body := putRole(t, s, targetUserID, rolePlatformAdmin)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%v", code, body)
	}

	var roleEvent map[string]interface{}
	for i := 0; i < 2 && roleEvent == nil; i++ {
		ev := awaitAudit(t, ch)
		if ev["event_type"] == "platform_user.role_changed" {
			roleEvent = ev
		}
	}
	if roleEvent == nil {
		t.Fatal("no platform_user.role_changed event was recorded for a role change")
	}
	meta, _ := roleEvent["metadata"].(map[string]interface{})
	want := map[string]string{
		"old_role_id":   roleSupport.String(),
		"old_role_name": "support_agent",
		"new_role_id":   rolePlatformAdmin.String(),
		"new_role_name": "platform_admin",
	}
	for k, v := range want {
		if meta[k] != v {
			t.Errorf("metadata[%q] = %v, want %q (metadata=%v)", k, meta[k], v, meta)
		}
	}
	if roleEvent["resource_id"] != targetUserID {
		t.Errorf("resource_id = %v, want the target user %s", roleEvent["resource_id"], targetUserID)
	}
}

// A profile edit that re-sends the same role is not a role change and must not
// be recorded as one.
func TestRoleAssign_Update_UnchangedRoleIsNotAuditedAsRoleChange(t *testing.T) {
	ch := captureAudit(t)
	s := escalationStore()
	if code, body := putRole(t, s, targetUserID, roleSupport); code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%v", code, body)
	}
	if ev := awaitAudit(t, ch); ev["event_type"] != "platform_user.updated" {
		t.Fatalf("first event = %v, want platform_user.updated", ev["event_type"])
	}
	expectNoAudit(t, ch)
}

// --- which permission, and what is written -----------------------------------

// The gate must ask for platform_roles.assign specifically. The stub denies only
// that literal name, and this test pins the name the handler asked for, so
// swapping the constant for any other permission (platform_users.manage, which
// the route already requires, is the tempting one) fails here in the PR gate
// rather than only in the nightly router test.
func TestRoleAssign_ChecksPlatformRolesAssign(t *testing.T) {
	cases := map[string]func(*stubPlatformUserStore) (int, map[string]any){
		"update": func(s *stubPlatformUserStore) (int, map[string]any) {
			return putRole(t, s, targetUserID, rolePlatformAdmin)
		},
		"create": func(s *stubPlatformUserStore) (int, map[string]any) { return postCreate(t, s, roleSupport) },
		"invite": func(s *stubPlatformUserStore) (int, map[string]any) { return postInvite(t, s, roleSupport) },
	}
	for name, run := range cases {
		t.Run(name, func(t *testing.T) {
			s := escalationStore()
			if code, body := run(s); code >= 300 {
				t.Fatalf("status = %d, want success; body=%v", code, body)
			}
			if len(s.permChecks) != 1 || s.permChecks[0] != "platform_roles.assign" {
				t.Fatalf("permission checks = %v, want exactly [platform_roles.assign]", s.permChecks)
			}
		})
	}
}

// An unchanged role_id is not written back (TOCTOU): if another operator
// changed this user's role after the handler read it, re-sending the stale
// value would revert their change without any role authority.
func TestRoleAssign_Update_UnchangedRoleIsNotWritten(t *testing.T) {
	s := escalationStore()
	s.denyAssign = true
	code, body := putRole(t, s, targetUserID, roleSupport)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%v", code, body)
	}
	if s.updated == nil {
		t.Fatal("the name change was not written")
	}
	if s.updated.RoleID != nil {
		t.Fatalf("an unchanged role was written back: %v", *s.updated.RoleID)
	}
	if s.updated.FirstName == nil || *s.updated.FirstName != "Renamed" {
		t.Fatalf("first_name not written: %+v", *s.updated)
	}
}

// A body carrying only the current role is a no-op, not a 400 and not a write.
func TestRoleAssign_Update_OnlyUnchangedRoleIsANoOp(t *testing.T) {
	s := escalationStore()
	eng := platformUserEngine(s, stubPasswordHasher{}, "")
	w := doRequest(eng, http.MethodPut, platformUserBase+"/"+targetUserID,
		strings.NewReader(`{"role_id":"`+roleSupport.String()+`"}`))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	expectNothingUpdated(t, s)
}
