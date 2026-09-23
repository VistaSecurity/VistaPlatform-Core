package handlers

// Contract test for the platform-authorization refusals (security-staff-1 and
// its follow-ups): every 403 and 409 the role-assignment, target-rank,
// self-protection, last-super-admin and role-permission guards return is
// validated against the schema the OpenAPI spec DECLARES for that operation
// and status — not against a schema name chosen here. So a guard that starts
// returning a new field, or an operation whose spec forgets the status, fails
// in the PR gate.
//
// The 403 schema (PlatformPermissionDenied) is closed (additionalProperties:
// false), which is what makes this a contract rather than "any object with an
// error string": the TypeScript client is generated from it.

import (
	"bytes"
	"database/sql"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/santhosh-tekuri/jsonschema/v6"
	"gopkg.in/yaml.v3"
)

// declaredResponseSchema returns the JSON pointer (into the spec resource) of
// the application/json schema the spec declares for method+path+status,
// following a $ref to #/components/responses/*.
func declaredResponseSchema(t *testing.T, path, method, status string) string {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	raw, err := os.ReadFile(filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "..",
		"api", "openapi", "admin-service.openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var spec map[string]any
	if err := yaml.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}
	esc := func(s string) string { return strings.ReplaceAll(strings.ReplaceAll(s, "~", "~0"), "/", "~1") }

	paths, _ := spec["paths"].(map[string]any)
	op, _ := paths[path].(map[string]any)[strings.ToLower(method)].(map[string]any)
	if op == nil {
		t.Fatalf("spec has no %s %s", method, path)
	}
	resp, _ := op["responses"].(map[string]any)[status].(map[string]any)
	if resp == nil {
		t.Fatalf("spec does not declare %s for %s %s", status, method, path)
	}
	if ref, ok := resp["$ref"].(string); ok {
		name := strings.TrimPrefix(ref, "#/components/responses/")
		return "#/components/responses/" + esc(name) + "/content/application~1json/schema"
	}
	return "#/paths/" + esc(path) + "/" + strings.ToLower(method) + "/responses/" + status + "/content/application~1json/schema"
}

func assertDeclaredResponse(t *testing.T, sv *specValidator, path, method string, status int, body []byte) {
	t.Helper()
	ptr := declaredResponseSchema(t, path, method, strconv.Itoa(status))
	sch, err := sv.compiler.Compile(specBaseURI + ptr)
	if err != nil {
		t.Fatalf("compile %s: %v", ptr, err)
	}
	inst, err := jsonschema.UnmarshalJSON(bytes.NewReader(body))
	if err != nil {
		t.Fatalf("unmarshal body: %v; body=%s", err, body)
	}
	if err := sch.Validate(inst); err != nil {
		t.Fatalf("%s %s %d violates the declared schema:\n%v\n--- body ---\n%s", method, path, status, err, body)
	}
}

const (
	specUsers       = "/admin/users"
	specUsersInvite = "/admin/users/invite"
	specUser        = "/admin/users/{id}"
	specUserSetPw   = "/admin/users/{id}/set-password"
	specUserReset   = "/admin/users/{id}/send-password-reset"
	specRolePerms   = "/admin/roles/{id}/permissions"
	specRole        = "/admin/roles/{id}"
)

func TestContract_PlatformAuthz_403_409(t *testing.T) {
	sv := loadSpec(t)

	type result struct {
		code int
		body []byte
	}
	users := func(s *stubPlatformUserStore, method, path, body string) result {
		eng := platformUserEngine(s, stubPasswordHasher{}, "")
		var r io.Reader
		if body != "" {
			r = strings.NewReader(body)
		}
		w := doRequest(eng, method, platformUserBase+path, r)
		return result{w.Code, w.Body.Bytes()}
	}

	cases := []struct {
		name     string
		specPath string
		method   string
		want     int
		run      func() result
	}{
		{"update: no platform_roles.assign", specUser, http.MethodPut, 403, func() result {
			s := escalationStore()
			s.denyAssign = true
			return users(s, http.MethodPut, "/"+targetUserID, `{"role_id":"`+rolePlatformAdmin.String()+`"}`)
		}},
		{"update: granted role broader than caller", specUser, http.MethodPut, 403, func() result {
			return users(escalationStore(), http.MethodPut, "/"+targetUserID, `{"role_id":"`+roleSuperAdmin.String()+`"}`)
		}},
		{"update: own role", specUser, http.MethodPut, 403, func() result {
			return users(escalationStore(), http.MethodPut, "/"+stubCallerID, `{"role_id":"`+roleSupport.String()+`"}`)
		}},
		{"update: target outranks caller", specUser, http.MethodPut, 403, func() result {
			return users(rankStore(), http.MethodPut, "/"+superTargetID, `{"first_name":"X"}`)
		}},
		{"update: self-deactivation", specUser, http.MethodPut, 403, func() result {
			return users(rankStore(), http.MethodPut, "/"+stubCallerID, `{"is_active":false}`)
		}},
		{"update: last super_admin", specUser, http.MethodPut, 409, func() result {
			s := rankStore()
			s.missingByRole, s.otherSuperAdmins = nil, 0
			return users(s, http.MethodPut, "/"+superTargetID, `{"is_active":false}`)
		}},
		{"create: no platform_roles.assign", specUsers, http.MethodPost, 403, func() result {
			s := escalationStore()
			s.denyAssign = true
			return users(s, http.MethodPost, "", `{"email":"n@example.test","password":"`+strongPassword()+`","first_name":"N","last_name":"U","role_id":"`+roleSupport.String()+`"}`)
		}},
		{"create: role broader than caller", specUsers, http.MethodPost, 403, func() result {
			return users(escalationStore(), http.MethodPost, "", `{"email":"n@example.test","password":"`+strongPassword()+`","first_name":"N","last_name":"U","role_id":"`+roleSuperAdmin.String()+`"}`)
		}},
		{"invite: role broader than caller", specUsersInvite, http.MethodPost, 403, func() result {
			w := doRequest(platformUserEmailEngine(escalationStore(), stubPasswordHasher{}, emailSends(), stubBrandingProvider{}, stubCallerID),
				http.MethodPost, inviteBase, strings.NewReader(`{"email":"i@example.test","first_name":"I","last_name":"U","role_id":"`+roleSuperAdmin.String()+`"}`))
			return result{w.Code, w.Body.Bytes()}
		}},
		{"set-password: target outranks caller", specUserSetPw, http.MethodPut, 403, func() result {
			return users(rankStore(), http.MethodPut, "/"+superTargetID+"/set-password", `{"new_password":"`+strongPassword()+`"}`)
		}},
		{"send-reset: target outranks caller", specUserReset, http.MethodPost, 403, func() result {
			s := rankStore()
			s.userFound = true
			w := doRequest(platformUserEmailEngine(s, stubPasswordHasher{}, emailSends(), stubBrandingProvider{}, stubCallerID),
				http.MethodPost, sendResetPath(superTargetID), nil)
			return result{w.Code, w.Body.Bytes()}
		}},
		{"delete: target outranks caller", specUser, http.MethodDelete, 403, func() result {
			return users(rankStore(), http.MethodDelete, "/"+superTargetID, "")
		}},
		{"delete: self", specUser, http.MethodDelete, 403, func() result {
			return users(rankStore(), http.MethodDelete, "/"+stubCallerID, "")
		}},
		{"delete: unknown user", specUser, http.MethodDelete, 404, func() result {
			return users(rankStore(), http.MethodDelete, "/"+uuid.NewString(), "")
		}},
		{"delete: last super_admin", specUser, http.MethodDelete, 409, func() result {
			s := rankStore()
			s.missingByRole, s.otherSuperAdmins = nil, 0
			return users(s, http.MethodDelete, "/"+superTargetID, "")
		}},
		{"role permissions: unheld permission", specRolePerms, http.MethodPut, 403, func() result {
			c, b := putRolePerms(&stubPlatformRBACStore{missingNew: []string{"platform.override"}}, stubCallerID, editedRoleID)
			return result{c, []byte(b)}
		}},
		{"role permissions: own role", specRolePerms, http.MethodPut, 403, func() result {
			c, b := putRolePerms(&stubPlatformRBACStore{callerRoleID: editedRoleID}, stubCallerID, editedRoleID)
			return result{c, []byte(b)}
		}},
		{"role permissions: role outranks caller", specRolePerms, http.MethodPut, 403, func() result {
			c, b := putRolePerms(&stubPlatformRBACStore{missingCurrent: []string{"platform_users.delete"}}, stubCallerID, editedRoleID)
			return result{c, []byte(b)}
		}},
		{"update: target changed after the check", specUser, http.MethodPut, 409, func() result {
			s := rankStore()
			promoteTargetAfterCheck(s, targetUserID)
			return users(s, http.MethodPut, "/"+targetUserID, `{"is_active":false}`)
		}},
		{"set-password: target changed after the check", specUserSetPw, http.MethodPut, 409, func() result {
			s := rankStore()
			promoteTargetAfterCheck(s, targetUserID)
			return users(s, http.MethodPut, "/"+targetUserID+"/set-password", `{"new_password":"`+strongPassword()+`"}`)
		}},
		{"send-reset: target changed after the check", specUserReset, http.MethodPost, 409, func() result {
			s := rankStore()
			s.userFound = true
			promoteTargetAfterCheck(s, targetUserID)
			w := doRequest(platformUserEmailEngine(s, stubPasswordHasher{}, emailSends(), stubBrandingProvider{}, stubCallerID),
				http.MethodPost, sendResetPath(targetUserID), nil)
			return result{w.Code, w.Body.Bytes()}
		}},
		{"delete: target changed after the check", specUser, http.MethodDelete, 409, func() result {
			s := rankStore()
			promoteTargetAfterCheck(s, targetUserID)
			return users(s, http.MethodDelete, "/"+targetUserID, "")
		}},
		{"role permissions: non-uuid permission id", specRolePerms, http.MethodPut, 400, func() result {
			c, b := putRolePermsBody(&stubPlatformRBACStore{}, editedRoleID, `{"permission_ids":["nope"]}`)
			return result{c, []byte(b)}
		}},
		{"role update: role outranks caller", specRole, http.MethodPut, 403, func() result {
			c, b := roleReq(&stubPlatformRBACStore{missingCurrent: []string{"platform.override"}}, http.MethodPut, editedRoleID, `{"description":"x"}`)
			return result{c, []byte(b)}
		}},
		{"role update: system role renamed by a non-super_admin", specRole, http.MethodPut, 403, func() result {
			c, b := roleReq(&stubPlatformRBACStore{role: samplePlatformRole(), callerRoleName: "platform_admin"}, http.MethodPut, editedRoleID, `{"display_name":"Renamed"}`)
			return result{c, []byte(b)}
		}},
		{"role update: unknown role", specRole, http.MethodPut, 404, func() result {
			c, b := roleReq(&stubPlatformRBACStore{roleErr: sql.ErrNoRows}, http.MethodPut, editedRoleID, `{"description":"x"}`)
			return result{c, []byte(b)}
		}},
		{"role delete: role outranks caller", specRole, http.MethodDelete, 403, func() result {
			c, b := roleReq(&stubPlatformRBACStore{missingCurrent: []string{"platform.override"}}, http.MethodDelete, editedRoleID, "")
			return result{c, []byte(b)}
		}},
		{"role permissions: system role", specRolePerms, http.MethodPut, 403, func() result {
			c, b := putRolePerms(&stubPlatformRBACStore{isSystem: true}, stubCallerID, editedRoleID)
			return result{c, []byte(b)}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := tc.run()
			if r.code != tc.want {
				t.Fatalf("status = %d, want %d; body=%s", r.code, tc.want, r.body)
			}
			assertDeclaredResponse(t, sv, tc.specPath, tc.method, r.code, r.body)
		})
	}
}

// The 403 schema is closed: a guard that adds an undeclared field fails the
// contract (so the generated client cannot silently fall behind), and one that
// drops `error` does too. Both polarities, against the real declared schema.
func TestContract_PlatformPermissionDenied_IsClosed(t *testing.T) {
	sv := loadSpec(t)
	ptr := declaredResponseSchema(t, specUser, http.MethodPut, "403")
	sch, err := sv.compiler.Compile(specBaseURI + ptr)
	if err != nil {
		t.Fatal(err)
	}
	for body, ok := range map[string]bool{
		`{"error":"x","missing_permissions":["a"]}`: true,
		`{"error":"x","required_permission":"a"}`:   true,
		`{"error":"x"}`:                          true,
		`{"error":"x","missing_permissions":[]}`: false,
		`{"error":"x","extra":1}`:                false,
		`{"missing_permissions":["a"]}`:          false,
	} {
		inst, err := jsonschema.UnmarshalJSON(strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		if got := sch.Validate(inst) == nil; got != ok {
			t.Errorf("%s: valid = %v, want %v", body, got, ok)
		}
	}
}
