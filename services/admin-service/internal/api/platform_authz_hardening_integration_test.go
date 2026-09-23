package api

// Second-round hardening of the platform-authorization guards, through the
// REAL router and a real Postgres:
//
//   - PUT /admin/roles/:id/permissions: the escalation check used to match
//     permission ids as exact lower-case text while the write let Postgres cast
//     them to uuid, so an UPPER-CASE (or braced, or hyphen-less) id of a
//     permission the caller lacked skipped the check and was written. Every
//     spelling must now be refused, and a non-UUID id is a 400.
//   - PUT and DELETE /admin/roles/:id carry the rank rule; only a super_admin
//     renames a system role.
//
// Needs TEST_DATABASE_URL (skips otherwise). Fixture rows are this test's own.

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/google/uuid"
)

func TestIntegration_PlatformRolePermissions_IDSpellings_RealRouter(t *testing.T) {
	f := newRolePermsFixture(t)
	override := f.permID["platform.override"].String() // the manager does NOT hold it
	held := f.permID["tenants.read"].String()          // the manager holds it

	put := func(ids ...string) (int, string) {
		quoted := make([]string, len(ids))
		for i, id := range ids {
			quoted[i] = `"` + id + `"`
		}
		return f.doAdmin(f.manager, http.MethodPut, "/roles/"+f.editable.String()+"/permissions",
			`{"permission_ids":[`+strings.Join(quoted, ",")+`]}`)
	}
	unchanged := func(t *testing.T) {
		t.Helper()
		if got := f.permsOf(f.editable); !sameSet(got, []string{"platform_users.read"}) {
			t.Fatalf("the refused edit still changed the role: %v", got)
		}
	}

	// The reported bypass, and the other spellings Postgres accepts for a uuid.
	for name, id := range map[string]string{
		"upper case":      strings.ToUpper(override),
		"braced":          "{" + override + "}",
		"no hyphens":      strings.ReplaceAll(override, "-", ""),
		"mixed case":      strings.ToUpper(override[:18]) + override[18:],
		"urn":             "urn:uuid:" + override,
		"canonical (ctl)": override,
	} {
		t.Run("unheld permission, "+name, func(t *testing.T) {
			code, body := put(f.permID["platform_users.read"].String(), id)
			expectStatus(t, name, code, body, http.StatusForbidden)
			if !strings.Contains(body, "platform.override") {
				t.Errorf("403 should name platform.override; body=%s", body)
			}
			unchanged(t)
		})
	}

	t.Run("mixed-case duplicate of an unheld permission", func(t *testing.T) {
		code, body := put(override, strings.ToUpper(override), "{"+strings.ToUpper(override)+"}")
		expectStatus(t, "duplicate unheld", code, body, http.StatusForbidden)
		unchanged(t)
	})

	for name, id := range map[string]string{
		"not a uuid":      "not-a-uuid",
		"permission name": "platform.override",
		"empty":           "",
		"sql":             "' OR 1=1 --",
	} {
		t.Run("garbage id, "+name, func(t *testing.T) {
			code, body := put(f.permID["platform_users.read"].String(), id)
			expectStatus(t, name, code, body, http.StatusBadRequest)
			unchanged(t)
		})
	}

	// The permitted polarity: a mixed-case duplicate of a HELD permission is
	// one grant, written once (it used to fail the insert's primary key).
	t.Run("mixed-case duplicate of a held permission is written once", func(t *testing.T) {
		code, body := put(f.permID["platform_users.read"].String(), held, strings.ToUpper(held))
		expectStatus(t, "duplicate held", code, body, http.StatusOK)
		if got := f.permsOf(f.editable); !sameSet(got, []string{"platform_users.read", "tenants.read"}) {
			t.Fatalf("the permitted edit wrote %v", got)
		}
		var resp struct {
			PermissionIDs []string `json:"permission_ids"`
		}
		if err := json.Unmarshal([]byte(body), &resp); err != nil {
			t.Fatal(err)
		}
		if len(resp.PermissionIDs) != 2 {
			t.Fatalf("response permission_ids = %v, want the 2 canonical ids", resp.PermissionIDs)
		}
	})

	t.Run("own role through an upper-case path", func(t *testing.T) {
		before := f.permsOf(f.roles["manager"])
		code, body := f.doAdmin(f.manager, http.MethodPut,
			"/roles/"+strings.ToUpper(f.roles["manager"].String())+"/permissions",
			`{"permission_ids":["`+f.permID["platform_users.read"].String()+`"]}`)
		expectStatus(t, "own role, upper-case id", code, body, http.StatusForbidden)
		if got := f.permsOf(f.roles["manager"]); !sameSet(got, before) {
			t.Fatalf("the refused edit still changed the caller's role: %v", got)
		}
	})

	t.Run("garbage role id", func(t *testing.T) {
		code, body := f.doAdmin(f.manager, http.MethodPut, "/roles/not-a-uuid/permissions", `{"permission_ids":[]}`)
		expectStatus(t, "garbage role id", code, body, http.StatusBadRequest)
	})
}

func TestIntegration_PlatformRoleRenameDelete_Rank_RealRouter(t *testing.T) {
	f := newRolePermsFixture(t)

	var sysRole uuid.UUID
	if err := f.db.QueryRow(`
		INSERT INTO platform_roles (name, display_name, description, is_system_role)
		VALUES ($1, 'System (test)', 'system-role fixture', true) RETURNING id`,
		"test_system_"+f.suffix).Scan(&sysRole); err != nil {
		t.Fatalf("create system fixture role: %v", err)
	}
	t.Cleanup(func() { _, _ = f.db.Exec(`DELETE FROM platform_roles WHERE id = $1`, sysRole) })
	if _, err := f.db.Exec(`
		INSERT INTO platform_role_permissions (role_id, permission_id)
		SELECT $1::uuid, id FROM platform_permissions WHERE name = 'platform_users.read'`, sysRole); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = f.db.Exec(`DELETE FROM platform_role_permissions WHERE role_id = $1`, sysRole) })

	roleCol := func(id uuid.UUID, col string) string {
		t.Helper()
		var v string
		if err := f.db.QueryRow(`SELECT `+col+` FROM platform_roles WHERE id = $1`, id).Scan(&v); err != nil { //nolint:gosec // test-only column literal
			t.Fatalf("read role %s: %v", col, err)
		}
		return v
	}
	exists := func(id uuid.UUID) bool {
		var n int
		_ = f.db.QueryRow(`SELECT COUNT(*) FROM platform_roles WHERE id = $1`, id).Scan(&n)
		return n == 1
	}

	t.Run("cannot rename or re-describe a role that outranks the caller", func(t *testing.T) {
		code, body := f.doAdmin(f.manager, http.MethodPut, "/roles/"+f.wide.String(), `{"display_name":"Harmless"}`)
		expectStatus(t, "rename a wider role", code, body, http.StatusForbidden)
		if !strings.Contains(body, "platform.override") {
			t.Errorf("403 should name platform.override; body=%s", body)
		}
		code, body = f.doAdmin(f.manager, http.MethodPut, "/roles/"+f.wide.String(), `{"description":"read only"}`)
		expectStatus(t, "re-describe a wider role", code, body, http.StatusForbidden)
		if roleCol(f.wide, "display_name") != "wide (test)" || roleCol(f.wide, "description") != "role-permissions integration fixture" {
			t.Fatal("a refused edit still changed the wider role")
		}
	})

	t.Run("cannot delete a role that outranks the caller", func(t *testing.T) {
		code, body := f.doAdmin(f.manager, http.MethodDelete, "/roles/"+f.wide.String(), "")
		expectStatus(t, "delete a wider role", code, body, http.StatusForbidden)
		if !exists(f.wide) {
			t.Fatal("a refused delete still removed the role")
		}
	})

	t.Run("can rename a role it outranks", func(t *testing.T) {
		code, body := f.doAdmin(f.manager, http.MethodPut, "/roles/"+f.editable.String(), `{"display_name":"Editable renamed"}`)
		expectStatus(t, "rename within rank", code, body, http.StatusOK)
		if roleCol(f.editable, "display_name") != "Editable renamed" {
			t.Fatal("the permitted rename was not written")
		}
	})

	t.Run("only a super_admin renames a system role", func(t *testing.T) {
		code, body := f.doAdmin(f.manager, http.MethodPut, "/roles/"+sysRole.String(), `{"display_name":"Super Administrator"}`)
		expectStatus(t, "non-super renames a system role", code, body, http.StatusForbidden)
		if roleCol(sysRole, "display_name") != "System (test)" {
			t.Fatal("a refused system-role rename was still written")
		}
		// Re-sending the current name alongside a description is not a rename.
		code, body = f.doAdmin(f.manager, http.MethodPut, "/roles/"+sysRole.String(),
			`{"display_name":"System (test)","description":"clarified"}`)
		expectStatus(t, "non-super re-describes a system role", code, body, http.StatusOK)
		code, body = f.doAdmin(f.superA, http.MethodPut, "/roles/"+sysRole.String(), `{"display_name":"System renamed"}`)
		expectStatus(t, "super_admin renames a system role", code, body, http.StatusOK)
		if roleCol(sysRole, "display_name") != "System renamed" {
			t.Fatal("the permitted system-role rename was not written")
		}
	})

	t.Run("system roles are never deleted", func(t *testing.T) {
		code, body := f.doAdmin(f.superA, http.MethodDelete, "/roles/"+sysRole.String(), "")
		expectStatus(t, "delete a system role", code, body, http.StatusBadRequest)
	})

	t.Run("super_admin is unrestricted on custom roles", func(t *testing.T) {
		code, body := f.doAdmin(f.superA, http.MethodPut, "/roles/"+f.wide.String(), `{"description":"super edit"}`)
		expectStatus(t, "super_admin re-describes a wider role", code, body, http.StatusOK)
		code, body = f.doAdmin(f.superA, http.MethodDelete, "/roles/"+f.wide.String(), "")
		expectStatus(t, "super_admin deletes a wider role", code, body, http.StatusOK)
		if exists(f.wide) {
			t.Fatal("the permitted delete did not remove the role")
		}
	})

	t.Run("unknown and garbage role ids", func(t *testing.T) {
		code, body := f.doAdmin(f.manager, http.MethodPut, "/roles/"+uuid.NewString(), `{"description":"x"}`)
		expectStatus(t, "unknown role", code, body, http.StatusNotFound)
		code, body = f.doAdmin(f.manager, http.MethodDelete, "/roles/not-a-uuid", "")
		expectStatus(t, "garbage role id", code, body, http.StatusBadRequest)
	})
}
