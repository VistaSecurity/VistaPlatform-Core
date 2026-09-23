package api

// platform_roles.manage must not be a way around platform_roles.assign,
// through the REAL router and the real platform_user_has_permission():
// PUT /admin/roles/:id/permissions refuses permissions the caller does not
// hold, edits of the caller's own role, and edits of a role that outranks the
// caller; POST /admin/roles never grants permissions at all.
//
// Fixture rows are this test's own and removed at cleanup.

import (
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

type rolePermsFixture struct {
	*roleAssignFixture
	manager  uuid.UUID            // platform_admin's permissions + platform_roles.manage
	permID   map[string]uuid.UUID // permission name → id
	editable uuid.UUID            // a custom role the manager outranks
	wide     uuid.UUID            // a custom role holding platform.override, which the manager lacks
}

func newRolePermsFixture(t *testing.T) *rolePermsFixture {
	t.Helper()
	f := &rolePermsFixture{roleAssignFixture: newRoleAssignFixture(t), permID: map[string]uuid.UUID{}}
	db := f.db

	rows, err := db.Query(`SELECT name, id FROM platform_permissions`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var name string
		var id uuid.UUID
		if err := rows.Scan(&name, &id); err != nil {
			t.Fatal(err)
		}
		f.permID[name] = id
	}
	_ = rows.Close()

	role := func(label string, perms ...string) uuid.UUID {
		var id uuid.UUID
		if err := db.QueryRow(`
			INSERT INTO platform_roles (name, display_name, description, is_system_role)
			VALUES ($1, $2, 'role-permissions integration fixture', false) RETURNING id`,
			"test_"+label+"_"+f.suffix, label+" (test)").Scan(&id); err != nil {
			t.Fatalf("create role %s: %v", label, err)
		}
		t.Cleanup(func() {
			_, _ = db.Exec(`DELETE FROM platform_role_permissions WHERE role_id = $1`, id)
			_, _ = db.Exec(`DELETE FROM platform_roles WHERE id = $1`, id)
		})
		if _, err := db.Exec(`
			INSERT INTO platform_role_permissions (role_id, permission_id)
			SELECT $1::uuid, id FROM platform_permissions WHERE name = ANY($2)`, id, pq.Array(perms)); err != nil {
			t.Fatalf("grant role %s: %v", label, err)
		}
		f.roles[label] = id
		return id
	}

	var paPerms []string
	prow, err := db.Query(`
		SELECT pp.name FROM platform_role_permissions prp
		JOIN platform_permissions pp ON pp.id = prp.permission_id
		WHERE prp.role_id = $1`, f.roles["platform_admin"])
	if err != nil {
		t.Fatal(err)
	}
	for prow.Next() {
		var n string
		_ = prow.Scan(&n)
		paPerms = append(paPerms, n)
	}
	_ = prow.Close()

	role("manager", append(paPerms, "platform_roles.manage")...)
	f.editable = role("editable", "platform_users.read")
	f.wide = role("wide", "platform_users.read", "platform.override")
	// Cleanups run last-registered-first: the base fixture's user cleanup runs
	// AFTER these role cleanups, so the manager is removed here, before its
	// role, or the role's DELETE would hit the users' role_id foreign key.
	f.manager = f.user("manager", "manager")
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM platform_users WHERE id = $1`, f.manager) })
	return f
}

func (f *rolePermsFixture) setPerms(caller, roleID uuid.UUID, perms ...string) (int, string) {
	f.t.Helper()
	ids := make([]string, 0, len(perms))
	for _, p := range perms {
		id, ok := f.permID[p]
		if !ok {
			f.t.Fatalf("unknown permission %s", p)
		}
		ids = append(ids, `"`+id.String()+`"`)
	}
	return f.doAdmin(caller, http.MethodPut, "/roles/"+roleID.String()+"/permissions",
		`{"permission_ids":[`+strings.Join(ids, ",")+`]}`)
}

func (f *rolePermsFixture) permsOf(roleID uuid.UUID) []string {
	f.t.Helper()
	rows, err := f.db.Query(`
		SELECT pp.name FROM platform_role_permissions prp
		JOIN platform_permissions pp ON pp.id = prp.permission_id
		WHERE prp.role_id = $1 ORDER BY pp.name`, roleID)
	if err != nil {
		f.t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var n string
		_ = rows.Scan(&n)
		out = append(out, n)
	}
	return out
}

func sameSet(a, b []string) bool {
	a, b = append([]string(nil), a...), append([]string(nil), b...)
	sort.Strings(a)
	sort.Strings(b)
	return strings.Join(a, ",") == strings.Join(b, ",")
}

func TestIntegration_PlatformRolePermissions_RealRouter(t *testing.T) {
	f := newRolePermsFixture(t)

	t.Run("cannot add a permission the caller does not hold", func(t *testing.T) {
		code, body := f.setPerms(f.manager, f.editable, "platform_users.read", "platform_users.delete")
		expectStatus(t, "grant unheld permission", code, body, http.StatusForbidden)
		if !strings.Contains(body, "platform_users.delete") {
			t.Errorf("403 should name the unheld permission; body=%s", body)
		}
		if got := f.permsOf(f.editable); !sameSet(got, []string{"platform_users.read"}) {
			t.Fatalf("the denied edit still changed the role: %v", got)
		}
	})

	t.Run("cannot edit its own role", func(t *testing.T) {
		before := f.permsOf(f.roles["manager"])
		// Only permissions it already holds — the refusal is about whose role it is.
		code, body := f.setPerms(f.manager, f.roles["manager"], "platform_users.read")
		expectStatus(t, "edit own role", code, body, http.StatusForbidden)
		if got := f.permsOf(f.roles["manager"]); !sameSet(got, before) {
			t.Fatalf("the denied edit still changed the caller's role: %v", got)
		}
	})

	t.Run("cannot edit a role that outranks it, even to remove", func(t *testing.T) {
		code, body := f.setPerms(f.manager, f.wide, "platform_users.read")
		expectStatus(t, "strip a wider role", code, body, http.StatusForbidden)
		if got := f.permsOf(f.wide); !sameSet(got, []string{"platform.override", "platform_users.read"}) {
			t.Fatalf("the denied edit still changed the wider role: %v", got)
		}
	})

	t.Run("can set a role it outranks to permissions it holds", func(t *testing.T) {
		code, body := f.setPerms(f.manager, f.editable, "platform_users.read", "tenants.read")
		expectStatus(t, "edit within permissions", code, body, http.StatusOK)
		if got := f.permsOf(f.editable); !sameSet(got, []string{"platform_users.read", "tenants.read"}) {
			t.Fatalf("the permitted edit was not written: %v", got)
		}
	})

	t.Run("super_admin is unrestricted", func(t *testing.T) {
		code, body := f.setPerms(f.superA, f.editable, "platform_users.read", "platform.override")
		expectStatus(t, "super_admin grant", code, body, http.StatusOK)
	})

	t.Run("create never grants permissions", func(t *testing.T) {
		name := "test_created_" + f.suffix
		code, body := f.doAdmin(f.manager, http.MethodPost, "/roles",
			`{"name":"`+name+`","display_name":"Created (test)","permission_ids":["`+f.permID["platform.override"].String()+`"]}`)
		expectStatus(t, "create role", code, body, http.StatusCreated)
		var resp struct {
			RoleID uuid.UUID `json:"role_id"`
		}
		if err := json.Unmarshal([]byte(body), &resp); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _, _ = f.db.Exec(`DELETE FROM platform_roles WHERE id = $1`, resp.RoleID) })
		if got := f.permsOf(resp.RoleID); len(got) != 0 {
			t.Fatalf("a created role carries permissions: %v", got)
		}
	})
}
