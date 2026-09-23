package handlers

// Target rank (platform_role_assignment.go, rule 5), self-protection (rule 6)
// and the last-super-admin 409 on every mutation of an existing platform user
// that is NOT a role change: profile edit, activate/deactivate, set-password,
// send-password-reset, delete.
//
// Each denial asserts that nothing was written, so deleting the
// authorizeActOnPlatformUser call from any one handler turns that handler's
// tests red. The real-router + real-Postgres half is
// internal/api/platform_role_assignment_integration_test.go.

import (
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// superTargetID is a super_admin the platform_admin-shaped caller of
// escalationStore does not outrank.
const superTargetID = "7a000000-0000-4000-8000-0000000000bb"

func rankStore() *stubPlatformUserStore {
	s := escalationStore()
	s.roleRefs[superTargetID] = roleRef(roleSuperAdmin, "super_admin")
	s.otherSuperAdmins = 1
	return s
}

func expect(t *testing.T, what string, code int, body string, want int) {
	t.Helper()
	if code != want {
		t.Fatalf("%s: status = %d, want %d; body=%s", what, code, want, body)
	}
}

func requireMissingPermissions(t *testing.T, body string) {
	t.Helper()
	m := decodeBody(t, []byte(body))
	if missing, _ := m["missing_permissions"].([]any); len(missing) == 0 {
		t.Fatalf("403 must list missing_permissions; body=%s", body)
	}
}

// --- set-password -----------------------------------------------------------

func setPassword(s *stubPlatformUserStore, id string) (int, string) {
	eng := platformUserEngine(s, stubPasswordHasher{}, "")
	w := doRequest(eng, http.MethodPut, platformUserBase+"/"+id+"/set-password",
		strings.NewReader(`{"new_password":"`+strongPassword()+`"}`))
	return w.Code, w.Body.String()
}

// The finding: platform_admin → super_admin set-password was an account
// takeover of the super administrator.
func TestTargetRank_SetPassword_403_OnSuperior(t *testing.T) {
	s := rankStore()
	code, body := setPassword(s, superTargetID)
	expect(t, "set-password on a super_admin", code, body, http.StatusForbidden)
	requireMissingPermissions(t, body)
	if s.passwordSet {
		t.Fatal("a denied set-password still wrote the password")
	}
}

func TestTargetRank_SetPassword_200_WithinRank(t *testing.T) {
	s := rankStore()
	code, body := setPassword(s, targetUserID)
	expect(t, "set-password within rank", code, body, http.StatusOK)
	if !s.passwordSet {
		t.Fatal("the permitted set-password was not written")
	}
}

func TestTargetRank_SetPassword_404_UnknownTarget(t *testing.T) {
	s := rankStore()
	code, body := setPassword(s, uuid.NewString())
	expect(t, "set-password on an unknown user", code, body, http.StatusNotFound)
	if s.passwordSet {
		t.Fatal("set-password on an unknown user wrote something")
	}
}

// A user with no role holds no permissions, so anyone outranks them.
func TestTargetRank_SetPassword_200_RolelessTarget(t *testing.T) {
	s := rankStore()
	roleless := uuid.NewString()
	s.roleRefs[roleless] = platformUserRoleRef{}
	code, body := setPassword(s, roleless)
	expect(t, "set-password on a roleless user", code, body, http.StatusOK)
}

// --- send-password-reset -----------------------------------------------------

func sendReset(s *stubPlatformUserStore, id string) (int, string) {
	eng := platformUserEmailEngine(s, stubPasswordHasher{}, emailSends(), stubBrandingProvider{}, stubCallerID)
	w := doRequest(eng, http.MethodPost, sendResetPath(id), nil)
	return w.Code, w.Body.String()
}

func TestTargetRank_SendReset_403_OnSuperior(t *testing.T) {
	s := rankStore()
	s.userFound = true
	s.user = samplePlatformUser()
	code, body := sendReset(s, superTargetID)
	expect(t, "send-reset to a super_admin", code, body, http.StatusForbidden)
	requireMissingPermissions(t, body)
	if s.resetStored {
		t.Fatal("a denied send-reset still stored a reset token")
	}
}

func TestTargetRank_SendReset_200_WithinRank(t *testing.T) {
	s := rankStore()
	s.userFound = true
	s.user = samplePlatformUser()
	code, body := sendReset(s, targetUserID)
	expect(t, "send-reset within rank", code, body, http.StatusOK)
	if !s.resetStored {
		t.Fatal("the permitted send-reset stored no token")
	}
}

// --- update (non-role fields) -----------------------------------------------

func putUser(s *stubPlatformUserStore, id, body string) (int, string) {
	eng := platformUserEngine(s, stubPasswordHasher{}, "")
	w := doRequest(eng, http.MethodPut, platformUserBase+"/"+id, strings.NewReader(body))
	return w.Code, w.Body.String()
}

func TestTargetRank_Deactivate_403_OnSuperior(t *testing.T) {
	s := rankStore()
	code, body := putUser(s, superTargetID, `{"is_active":false}`)
	expect(t, "deactivate a super_admin", code, body, http.StatusForbidden)
	requireMissingPermissions(t, body)
	expectNothingUpdated(t, s)
}

// Every mutation, not only the dangerous ones: a lesser operator does not edit
// a superior's profile either.
func TestTargetRank_ProfileEdit_403_OnSuperior(t *testing.T) {
	s := rankStore()
	code, body := putUser(s, superTargetID, `{"first_name":"Renamed"}`)
	expect(t, "rename a super_admin", code, body, http.StatusForbidden)
	expectNothingUpdated(t, s)
}

func TestTargetRank_Deactivate_200_WithinRank(t *testing.T) {
	s := rankStore()
	code, body := putUser(s, targetUserID, `{"is_active":false}`)
	expect(t, "deactivate within rank", code, body, http.StatusOK)
	if s.updated == nil || s.updated.IsActive == nil || *s.updated.IsActive {
		t.Fatalf("deactivation not written: %+v", s.updated)
	}
}

func TestTargetRank_Update_404_UnknownTarget(t *testing.T) {
	s := rankStore()
	code, body := putUser(s, uuid.NewString(), `{"first_name":"Renamed"}`)
	expect(t, "update an unknown user", code, body, http.StatusNotFound)
	expectNothingUpdated(t, s)
}

func TestSelf_Deactivate_403(t *testing.T) {
	s := rankStore()
	code, body := putUser(s, stubCallerID, `{"is_active":false}`)
	expect(t, "self-deactivation", code, body, http.StatusForbidden)
	expectNothingUpdated(t, s)
}

// Refusing self-DEactivation must not block editing your own name.
func TestSelf_ProfileEdit_200(t *testing.T) {
	s := rankStore()
	code, body := putUser(s, stubCallerID, `{"first_name":"Me","is_active":true}`)
	expect(t, "self profile edit", code, body, http.StatusOK)
}

// The last active super_admin cannot be deactivated even by a caller who
// outranks them (here: holds everything a super_admin does).
func TestLastSuperAdmin_Deactivate_409(t *testing.T) {
	s := rankStore()
	s.missingByRole = nil
	s.otherSuperAdmins = 0
	code, body := putUser(s, superTargetID, `{"is_active":false}`)
	expect(t, "deactivate the last super_admin", code, body, http.StatusConflict)
	expectNothingUpdated(t, s)
}

func TestLastSuperAdmin_Deactivate_200_WhenAnotherRemains(t *testing.T) {
	s := rankStore()
	s.missingByRole = nil
	code, body := putUser(s, superTargetID, `{"is_active":false}`)
	expect(t, "deactivate a super_admin while another remains", code, body, http.StatusOK)
}

// --- delete -----------------------------------------------------------------

func deleteUser(s *stubPlatformUserStore, id string) (int, string) {
	eng := platformUserEngine(s, stubPasswordHasher{}, "")
	w := doRequest(eng, http.MethodDelete, platformUserBase+"/"+id, nil)
	return w.Code, w.Body.String()
}

func TestTargetRank_Delete_403_OnSuperior(t *testing.T) {
	s := rankStore()
	code, body := deleteUser(s, superTargetID)
	expect(t, "delete a super_admin", code, body, http.StatusForbidden)
	requireMissingPermissions(t, body)
	if s.deleted {
		t.Fatal("a denied delete still deleted the user")
	}
}

func TestTargetRank_Delete_200_WithinRank(t *testing.T) {
	s := rankStore()
	code, body := deleteUser(s, targetUserID)
	expect(t, "delete within rank", code, body, http.StatusOK)
	if !s.deleted {
		t.Fatal("the permitted delete was not written")
	}
}

func TestTargetRank_Delete_404_UnknownTarget(t *testing.T) {
	s := rankStore()
	code, body := deleteUser(s, uuid.NewString())
	expect(t, "delete an unknown user", code, body, http.StatusNotFound)
}

func TestSelf_Delete_403(t *testing.T) {
	s := rankStore()
	code, body := deleteUser(s, stubCallerID)
	expect(t, "self-deletion", code, body, http.StatusForbidden)
	if s.deleted {
		t.Fatal("a self-deletion was written")
	}
}

func TestLastSuperAdmin_Delete_409(t *testing.T) {
	s := rankStore()
	s.missingByRole = nil
	s.otherSuperAdmins = 0
	code, body := deleteUser(s, superTargetID)
	expect(t, "delete the last super_admin", code, body, http.StatusConflict)
	if s.deleted {
		t.Fatal("the last super_admin was deleted")
	}
}

// An unidentified caller cannot be granted rank over anyone.
func TestTargetRank_401_NoCaller(t *testing.T) {
	s := rankStore()
	eng := platformUserEmailEngine(s, stubPasswordHasher{}, emailSends(), stubBrandingProvider{}, "")
	w := doRequest(eng, http.MethodPost, sendResetPath(targetUserID), nil)
	expect(t, "send-reset without a caller", w.Code, w.Body.String(), http.StatusUnauthorized)
	if s.resetStored {
		t.Fatal("an unauthenticated send-reset stored a token")
	}
}
