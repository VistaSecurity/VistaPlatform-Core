package handlers

// Second-round hardening of the platform-authorization guards (PR review):
//
//  1. SetPlatformRolePermissions: every permission id is parsed, canonicalized
//     and de-duplicated BEFORE the escalation check, and the check and the
//     write receive the identical slice — so no spelling of an id (upper case,
//     braces, no hyphens) can be written while slipping past the check.
//  3. Writes to an existing platform user are conditional on the role the
//     rank check saw: a user re-roled between check and write is not written
//     (409).
//  4. PUT and DELETE /admin/roles/:id carry the rank rule, and a system role's
//     display name is a super_admin's to change.
//
// The real-Postgres halves are internal/api/platform_authz_hardening_integration_test.go
// (router) and platform_user_toctou_integration_test.go (repository).

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// --- 1. permission-id canonicalization ---------------------------------------

func putRolePermsBody(s *stubPlatformRBACStore, roleID, body string) (int, string) {
	w := doRequest(rbacEngineAs(s, stubCallerID), http.MethodPut, apiBase+"/admin/roles/"+roleID+"/permissions",
		strings.NewReader(body))
	return w.Code, w.Body.String()
}

func TestRolePerms_CheckAndWriteSeeTheSameCanonicalIDs(t *testing.T) {
	id := uuid.MustParse("3c1f0000-aaaa-4bbb-8ccc-00000000dd01")
	other := uuid.MustParse("3c1f0000-aaaa-4bbb-8ccc-00000000dd02")
	s := &stubPlatformRBACStore{}
	body := `{"permission_ids":["` + strings.ToUpper(id.String()) + `","{` + id.String() + `}","` +
		strings.ReplaceAll(id.String(), "-", "") + `","` + other.String() + `"]}`
	code, resp := putRolePermsBody(s, editedRoleID, body)
	expect(t, "canonicalized edit", code, resp, http.StatusOK)

	want := []string{id.String(), other.String()}
	if strings.Join(s.checkedIDs, ",") != strings.Join(want, ",") {
		t.Fatalf("the escalation check saw %v, want %v", s.checkedIDs, want)
	}
	if strings.Join(s.setPermsIDs, ",") != strings.Join(want, ",") {
		t.Fatalf("the write received %v, want %v", s.setPermsIDs, want)
	}
}

// An upper-case id of a permission the caller lacks: the check must be asked
// about it (in canonical form), so its refusal reaches the caller.
func TestRolePerms_403_UpperCaseUnheldPermission(t *testing.T) {
	s := &stubPlatformRBACStore{missingNew: []string{"platform.override"}}
	id := uuid.NewString()
	code, body := putRolePermsBody(s, editedRoleID, `{"permission_ids":["`+strings.ToUpper(id)+`"]}`)
	expect(t, "upper-case unheld permission", code, body, http.StatusForbidden)
	requireMissingPermissions(t, body)
	if len(s.checkedIDs) != 1 || s.checkedIDs[0] != id {
		t.Fatalf("the check saw %v, want [%s]", s.checkedIDs, id)
	}
	expectPermsNotWritten(t, s)
}

func TestRolePerms_400_UnparsablePermissionID(t *testing.T) {
	for _, bad := range []string{"not-a-uuid", "", "platform.override", "' OR 1=1 --"} {
		s := &stubPlatformRBACStore{}
		code, body := putRolePermsBody(s, editedRoleID, `{"permission_ids":["`+uuid.NewString()+`","`+bad+`"]}`)
		expect(t, "garbage id "+bad, code, body, http.StatusBadRequest)
		expectPermsNotWritten(t, s)
		if s.checkedIDs != nil {
			t.Fatalf("garbage id %q still reached the escalation check", bad)
		}
	}
}

func TestRolePerms_400_UnparsableRoleID(t *testing.T) {
	s := &stubPlatformRBACStore{}
	code, body := putRolePermsBody(s, "not-a-uuid", `{"permission_ids":[]}`)
	expect(t, "garbage role id", code, body, http.StatusBadRequest)
	expectPermsNotWritten(t, s)
}

func TestCanonicalUUIDs(t *testing.T) {
	id := "3c1f0000-aaaa-4bbb-8ccc-00000000dd01"
	got, err := canonicalUUIDs([]string{strings.ToUpper(id), "{" + id + "}", "urn:uuid:" + id})
	if err != nil || len(got) != 1 || got[0] != id {
		t.Fatalf("canonicalUUIDs = %v, %v; want [%s]", got, err, id)
	}
	if got, err := canonicalUUIDs(nil); err != nil || got == nil || len(got) != 0 {
		t.Fatalf("canonicalUUIDs(nil) = %#v, %v; want an empty non-nil slice", got, err)
	}
	if _, err := canonicalUUIDs([]string{id, "nope"}); err == nil {
		t.Fatal("an unparsable id must fail the whole list")
	}
}

// --- 3. writes conditional on the role the check saw -------------------------

// promoteTargetAfterCheck makes the target a super_admin right after the
// handler's rank check read its role — a concurrent operator's promotion.
func promoteTargetAfterCheck(s *stubPlatformUserStore, target string) {
	s.onRoleRead = func() { s.roleRefs[target] = roleRef(roleSuperAdmin, "super_admin") }
}

func expectCheckedRolePassed(t *testing.T, s *stubPlatformUserStore) {
	t.Helper()
	if len(s.expectedRoles) != 1 || s.expectedRoles[0] == nil || *s.expectedRoles[0] != roleSupport {
		t.Fatalf("the write was conditioned on %v, want exactly the checked role %s", s.expectedRoles, roleSupport)
	}
}

func TestTOCTOU_Deactivate_409WhenPromotedAfterCheck(t *testing.T) {
	s := rankStore()
	promoteTargetAfterCheck(s, targetUserID)
	code, body := putUser(s, targetUserID, `{"is_active":false}`)
	expect(t, "deactivate a user promoted after the check", code, body, http.StatusConflict)
	expectNothingUpdated(t, s)
	expectCheckedRolePassed(t, s)
}

func TestTOCTOU_RoleChange_409WhenPromotedAfterCheck(t *testing.T) {
	s := rankStore()
	promoteTargetAfterCheck(s, targetUserID)
	code, body := putUser(s, targetUserID, `{"role_id":"`+rolePlatformAdmin.String()+`"}`)
	expect(t, "re-role a user promoted after the check", code, body, http.StatusConflict)
	expectNothingUpdated(t, s)
	expectCheckedRolePassed(t, s)
}

func TestTOCTOU_SetPassword_409WhenPromotedAfterCheck(t *testing.T) {
	s := rankStore()
	promoteTargetAfterCheck(s, targetUserID)
	code, body := setPassword(s, targetUserID)
	expect(t, "set-password on a user promoted after the check", code, body, http.StatusConflict)
	if s.passwordSet {
		t.Fatal("the password was written although the target changed")
	}
	expectCheckedRolePassed(t, s)
}

func TestTOCTOU_SendReset_409WhenPromotedAfterCheck(t *testing.T) {
	s := rankStore()
	s.userFound = true
	s.user = samplePlatformUser()
	promoteTargetAfterCheck(s, targetUserID)
	code, body := sendReset(s, targetUserID)
	expect(t, "send-reset to a user promoted after the check", code, body, http.StatusConflict)
	if s.resetStored || strings.Contains(body, "reset_link") {
		t.Fatal("a reset token was stored although the target changed")
	}
	expectCheckedRolePassed(t, s)
}

func TestTOCTOU_Delete_409WhenPromotedAfterCheck(t *testing.T) {
	s := rankStore()
	promoteTargetAfterCheck(s, targetUserID)
	w := doRequest(platformUserEngine(s, stubPasswordHasher{}, ""), http.MethodDelete, platformUserBase+"/"+targetUserID, nil)
	expect(t, "delete a user promoted after the check", w.Code, w.Body.String(), http.StatusConflict)
	if s.deleted {
		t.Fatal("the user was deleted although they changed")
	}
	expectCheckedRolePassed(t, s)
}

// The other polarity: nothing changes in between, the checked role is passed
// and the write goes through.
func TestTOCTOU_UnchangedTargetIsWritten(t *testing.T) {
	s := rankStore()
	code, body := putUser(s, targetUserID, `{"is_active":false}`)
	expect(t, "deactivate an unchanged user", code, body, http.StatusOK)
	if s.updated == nil {
		t.Fatal("the permitted deactivation was not written")
	}
	expectCheckedRolePassed(t, s)
}

// A roleless target is conditioned on "still roleless" (nil), not skipped.
func TestTOCTOU_RolelessTargetConditionedOnNoRole(t *testing.T) {
	s := rankStore()
	roleless := uuid.NewString()
	s.roleRefs[roleless] = platformUserRoleRef{}
	s.onRoleRead = func() { s.roleRefs[roleless] = roleRef(roleSuperAdmin, "super_admin") }
	code, body := setPassword(s, roleless)
	expect(t, "set-password on a roleless user promoted after the check", code, body, http.StatusConflict)
	if s.passwordSet || len(s.expectedRoles) != 1 || s.expectedRoles[0] != nil {
		t.Fatalf("roleless target: passwordSet=%v expectedRoles=%v", s.passwordSet, s.expectedRoles)
	}
}

// --- 4. rank rule on role rename / delete ------------------------------------

func roleReq(s *stubPlatformRBACStore, method, roleID, body string) (int, string) {
	var r io.Reader
	if body != "" {
		r = strings.NewReader(body)
	}
	w := doRequest(rbacEngineAs(s, stubCallerID), method, apiBase+"/admin/roles/"+roleID, r)
	return w.Code, w.Body.String()
}

func TestRoleUpdate_403_RoleOutranksCaller(t *testing.T) {
	s := &stubPlatformRBACStore{missingCurrent: []string{"platform.override"}}
	code, body := roleReq(s, http.MethodPut, editedRoleID, `{"description":"mine now"}`)
	expect(t, "edit a role that outranks the caller", code, body, http.StatusForbidden)
	requireMissingPermissions(t, body)
	if s.updateCalled {
		t.Fatal("a denied role edit was still written")
	}
}

func TestRoleUpdate_SystemRoleDisplayName(t *testing.T) {
	sys := samplePlatformRole() // is_system_role: true, display_name "Platform Admin"
	cases := []struct {
		name, callerRole, body string
		want                   int
	}{
		{"non-super renames a system role", "platform_admin", `{"display_name":"Super Administrator"}`, http.StatusForbidden},
		{"non-super re-sends the current name with a new description", "platform_admin", `{"display_name":"Platform Admin","description":"x"}`, http.StatusOK},
		{"non-super edits only the description", "platform_admin", `{"description":"x"}`, http.StatusOK},
		{"super_admin renames a system role", "super_admin", `{"display_name":"Operators"}`, http.StatusOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &stubPlatformRBACStore{role: sys, callerRoleID: uuid.NewString(), callerRoleName: tc.callerRole}
			code, body := roleReq(s, http.MethodPut, editedRoleID, tc.body)
			expect(t, tc.name, code, body, tc.want)
			if (tc.want == http.StatusOK) != s.updateCalled {
				t.Fatalf("updateCalled = %v for status %d", s.updateCalled, code)
			}
		})
	}
}

// A custom role's display name is not reserved: rank is the only rule.
func TestRoleUpdate_200_CustomRoleRename(t *testing.T) {
	s := &stubPlatformRBACStore{callerRoleName: "platform_admin"}
	code, body := roleReq(s, http.MethodPut, editedRoleID, `{"display_name":"Renamed"}`)
	expect(t, "rename a custom role", code, body, http.StatusOK)
}

func TestRoleUpdate_400_UnparsableRoleID(t *testing.T) {
	s := &stubPlatformRBACStore{}
	code, body := roleReq(s, http.MethodPut, "role_1", `{"description":"x"}`)
	expect(t, "garbage role id", code, body, http.StatusBadRequest)
	if s.updateCalled {
		t.Fatal("a rejected edit was written")
	}
}

func TestRoleDelete_403_RoleOutranksCaller(t *testing.T) {
	s := &stubPlatformRBACStore{missingCurrent: []string{"platform.override"}}
	code, body := roleReq(s, http.MethodDelete, editedRoleID, "")
	expect(t, "delete a role that outranks the caller", code, body, http.StatusForbidden)
	requireMissingPermissions(t, body)
	if s.deleteCalled {
		t.Fatal("a denied delete still deleted the role")
	}
}

func TestRoleDelete_200_WithinRank(t *testing.T) {
	s := &stubPlatformRBACStore{}
	code, body := roleReq(s, http.MethodDelete, editedRoleID, "")
	expect(t, "delete a role within rank", code, body, http.StatusOK)
	if !s.deleteCalled {
		t.Fatal("the permitted delete was not written")
	}
}

func TestRoleDelete_401_NoCaller(t *testing.T) {
	s := &stubPlatformRBACStore{}
	w := doRequest(rbacEngineAs(s, ""), http.MethodDelete, apiBase+"/admin/roles/"+editedRoleID, nil)
	expect(t, "delete without a caller", w.Code, w.Body.String(), http.StatusUnauthorized)
	if s.deleteCalled {
		t.Fatal("an unauthenticated delete was written")
	}
}
