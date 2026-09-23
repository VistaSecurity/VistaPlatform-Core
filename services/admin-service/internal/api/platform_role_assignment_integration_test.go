package api

// Privilege-escalation guard for platform_users.role_id (security-staff-1),
// driven through the REAL admin-service router against a real Postgres.
//
// The handler-level tests (internal/handlers/platform_role_assignment_test.go)
// run in the PR gate over a stub store. This file is the half a stub cannot
// prove: that server.go routes these requests to handlers that enforce the
// rule, that the real platform_user_has_permission() and the real subset query
// agree with it, and that the SEEDED roles behave as documented (owner
// decision: platform admins may assign every platform role except
// super_admin) — a stock platform_admin holds platform_users.manage AND
// platform_roles.assign (so it can create, invite and re-role staff), it is a
// SUPERSET of support_agent (so it can grant Support Agent and manage its
// holders), and super_admin is strictly broader than platform_admin (so a
// platform_admin can never grant it nor act on its holders).
//
// Needs TEST_DATABASE_URL (skips otherwise); `make test-integration-db` runs it.
// Fixture rows are this test's own (random emails, throwaway roles) and are
// removed at cleanup; no seeded row is modified.

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/admin-service/internal/config"
	"github.com/vistasecurity/vistaplatform/shared/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

const roleAssignJWTSecret = "role-assign-integration-secret-not-a-real-key"

type roleAssignFixture struct {
	t      *testing.T
	db     *sql.DB
	srv    *Server
	audits chan map[string]interface{}
	suffix string // makes this run's fixture emails unique

	roles map[string]uuid.UUID // seeded role name → id, plus the fixture roles "pa_assign", "pa_no_assign" and "narrow"

	platformAdmin uuid.UUID // stock platform_admin (holds platform_roles.assign since the seed grants it)
	noAssign      uuid.UUID // platform_admin's permissions MINUS platform_roles.assign
	assigner      uuid.UUID // platform_admin's permissions + platform_users.delete
	support       uuid.UUID // stock support_agent
	superA        uuid.UUID
	superB        uuid.UUID
	target        uuid.UUID // holds the fixture role "narrow"
	victim        uuid.UUID // "narrow" too; the one the delete subtest removes
}

func newRoleAssignFixture(t *testing.T) *roleAssignFixture {
	t.Helper()
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)

	f := &roleAssignFixture{t: t, db: db, roles: map[string]uuid.UUID{}}

	for _, name := range []string{"super_admin", "platform_admin", "support_agent"} {
		var id uuid.UUID
		if err := db.QueryRow(`SELECT id FROM platform_roles WHERE name = $1`, name).Scan(&id); err != nil {
			t.Fatalf("seeded role %s: %v", name, err)
		}
		f.roles[name] = id
	}

	// The seed is what these tests are about; pin its shape so a seed change
	// that invalidates a premise fails loudly instead of passing.
	if has := f.roleHas("platform_admin", "platform_users.manage"); !has {
		t.Fatal("premise: seeded platform_admin no longer holds platform_users.manage")
	}
	// The owner-facing default: stock platform admins manage staff again. The
	// subset rule, not the absence of this grant, is what stops escalation.
	if has := f.roleHas("platform_admin", "platform_roles.assign"); !has {
		t.Fatal("seed: platform_admin must hold platform_roles.assign (scripts/database/seed.sql)")
	}
	// Owner decision: platform_admin assigns every role except super_admin, so
	// the seed keeps it a superset of support_agent...
	if missing := f.roleMinus("support_agent", "platform_admin"); len(missing) != 0 {
		t.Fatalf("seed: platform_admin must hold every support_agent permission; lacks %v (scripts/database/seed.sql)", missing)
	}
	// ...and strictly narrower than super_admin.
	if len(f.roleMinus("super_admin", "platform_admin")) == 0 {
		t.Fatal("premise: super_admin must hold something platform_admin does not")
	}

	suffix := strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	f.suffix = suffix
	var paAssign uuid.UUID
	if err := db.QueryRow(`
		INSERT INTO platform_roles (name, display_name, description, is_system_role)
		VALUES ($1, 'PA + assign (test)', 'role-assignment integration fixture', false)
		RETURNING id`, "test_pa_assign_"+suffix).Scan(&paAssign); err != nil {
		t.Fatalf("create fixture role: %v", err)
	}
	f.roles["pa_assign"] = paAssign
	if _, err := db.Exec(`
		INSERT INTO platform_role_permissions (role_id, permission_id)
		SELECT $1::uuid, prp.permission_id FROM platform_role_permissions prp WHERE prp.role_id = $2::uuid
		UNION
		SELECT $1::uuid, id FROM platform_permissions
		WHERE name IN ('platform_roles.assign', 'platform_users.delete')`,
		paAssign, f.roles["platform_admin"]); err != nil {
		t.Fatalf("grant fixture role: %v", err)
	}

	// platform_admin minus platform_roles.assign: an operator who may edit staff
	// but not grant roles — what a stock platform_admin was before the seed
	// granted assign, and what an owner who revokes it gets.
	var paNoAssign uuid.UUID
	if err := db.QueryRow(`
		INSERT INTO platform_roles (name, display_name, description, is_system_role)
		VALUES ($1, 'PA - assign (test)', 'role-assignment integration fixture', false)
		RETURNING id`, "test_pa_no_assign_"+suffix).Scan(&paNoAssign); err != nil {
		t.Fatalf("create fixture role: %v", err)
	}
	f.roles["pa_no_assign"] = paNoAssign
	if _, err := db.Exec(`
		INSERT INTO platform_role_permissions (role_id, permission_id)
		SELECT $1::uuid, prp.permission_id
		FROM platform_role_permissions prp JOIN platform_permissions pp ON pp.id = prp.permission_id
		WHERE prp.role_id = $2::uuid AND pp.name <> 'platform_roles.assign'`,
		paNoAssign, f.roles["platform_admin"]); err != nil {
		t.Fatalf("grant fixture role: %v", err)
	}

	// A deliberately narrow role, so tests have a target every caller outranks.
	var narrow uuid.UUID
	if err := db.QueryRow(`
		INSERT INTO platform_roles (name, display_name, description, is_system_role)
		VALUES ($1, 'Narrow (test)', 'role-assignment integration fixture', false)
		RETURNING id`, "test_narrow_"+suffix).Scan(&narrow); err != nil {
		t.Fatalf("create narrow fixture role: %v", err)
	}
	f.roles["narrow"] = narrow
	if _, err := db.Exec(`
		INSERT INTO platform_role_permissions (role_id, permission_id)
		SELECT $1::uuid, id FROM platform_permissions WHERE name = 'platform_users.read'`, narrow); err != nil {
		t.Fatalf("grant narrow fixture role: %v", err)
	}

	f.platformAdmin = f.user("pa", "platform_admin")
	f.noAssign = f.user("noassign", "pa_no_assign")
	f.assigner = f.user("assigner", "pa_assign")
	f.support = f.user("support", "support_agent")
	f.superA = f.user("supera", "super_admin")
	f.superB = f.user("superb", "super_admin")
	f.target = f.user("target", "narrow")
	f.victim = f.user("victim", "narrow")

	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM platform_users WHERE email LIKE $1`, "%-"+suffix+"@role-assign.example.test")
		for _, id := range []uuid.UUID{paAssign, paNoAssign, narrow} {
			_, _ = db.Exec(`DELETE FROM platform_role_permissions WHERE role_id = $1`, id)
			_, _ = db.Exec(`DELETE FROM platform_roles WHERE id = $1`, id)
		}
	})

	// Point the platform audit emitter at a capture server BEFORE the server is
	// built — NewServerWithConnections wires it from the environment.
	f.audits = make(chan map[string]interface{}, 32)
	auditSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		select {
		case f.audits <- body:
		default:
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"` + uuid.NewString() + `"}`))
	}))
	t.Cleanup(auditSrv.Close)
	t.Setenv("AUDIT_SERVICE_URL", auditSrv.URL)
	t.Setenv("AUDIT_LOGGING_ENABLED", "true")

	f.srv = NewServerWithConnections(
		&config.Config{Environment: "test", JWTSecret: roleAssignJWTSecret},
		db, db, EditionHooks{},
	)
	return f
}

func (f *roleAssignFixture) user(label, role string) uuid.UUID {
	f.t.Helper()
	var id uuid.UUID
	if err := f.db.QueryRow(`
		INSERT INTO platform_users (email, password_hash, first_name, last_name, role_id, is_active)
		VALUES ($1, 'not-a-real-hash', 'Role', 'Assign', $2, true)
		RETURNING id`, label+"-"+f.suffix+"@role-assign.example.test", f.roles[role]).Scan(&id); err != nil {
		f.t.Fatalf("create %s user: %v", label, err)
	}
	return id
}

func (f *roleAssignFixture) roleHas(role, perm string) bool {
	f.t.Helper()
	var has bool
	if err := f.db.QueryRow(`
		SELECT EXISTS (
			SELECT 1 FROM platform_role_permissions prp
			JOIN platform_permissions pp ON pp.id = prp.permission_id
			JOIN platform_roles pr ON pr.id = prp.role_id
			WHERE pr.name = $1 AND pp.name = $2)`, role, perm).Scan(&has); err != nil {
		f.t.Fatalf("roleHas: %v", err)
	}
	return has
}

// roleMinus lists the permissions role a holds that role b does not.
func (f *roleAssignFixture) roleMinus(a, b string) []string {
	f.t.Helper()
	rows, err := f.db.Query(`
		SELECT pp.name FROM platform_role_permissions prp
		JOIN platform_permissions pp ON pp.id = prp.permission_id
		JOIN platform_roles pr ON pr.id = prp.role_id
		WHERE pr.name = $1
		EXCEPT
		SELECT pp.name FROM platform_role_permissions prp
		JOIN platform_permissions pp ON pp.id = prp.permission_id
		JOIN platform_roles pr ON pr.id = prp.role_id
		WHERE pr.name = $2
		ORDER BY 1`, a, b)
	if err != nil {
		f.t.Fatalf("roleMinus: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			f.t.Fatalf("roleMinus: %v", err)
		}
		out = append(out, n)
	}
	return out
}

func (f *roleAssignFixture) roleOf(user uuid.UUID) uuid.UUID {
	f.t.Helper()
	var id uuid.UUID
	if err := f.db.QueryRow(`SELECT role_id FROM platform_users WHERE id = $1`, user).Scan(&id); err != nil {
		f.t.Fatalf("roleOf: %v", err)
	}
	return id
}

func (f *roleAssignFixture) token(user uuid.UUID) string {
	f.t.Helper()
	claims := models.JWTClaims{
		UserID: user,
		Email:  "operator@example.test",
		// Deliberately a lie: authorization must come from the database, not
		// from the role name the token carries.
		Role: "super_admin",
		Type: "access",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(roleAssignJWTSecret))
	if err != nil {
		f.t.Fatalf("sign token: %v", err)
	}
	return signed
}

func (f *roleAssignFixture) do(caller uuid.UUID, method, path, body string) (int, string) {
	f.t.Helper()
	return f.doAdmin(caller, method, "/users"+path, body)
}

// doAdmin sends a request to /api/v1/admin-service/admin<path> as caller.
func (f *roleAssignFixture) doAdmin(caller uuid.UUID, method, path, body string) (int, string) {
	f.t.Helper()
	req := httptest.NewRequest(method, "/api/v1/admin-service/admin"+path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+f.token(caller))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	f.srv.Router().ServeHTTP(w, req)
	return w.Code, w.Body.String()
}

func (f *roleAssignFixture) setRole(caller, target uuid.UUID, role string) (int, string) {
	f.t.Helper()
	return f.do(caller, http.MethodPut, "/"+target.String(),
		`{"first_name":"Role","role_id":"`+f.roles[role].String()+`"}`)
}

func (f *roleAssignFixture) newUserBody(label, role string) string {
	return `{"email":"` + label + "-" + f.suffix + `@role-assign.example.test","password":"Str0ng!Passw0rd#2026","first_name":"New","last_name":"User","role_id":"` + f.roles[role].String() + `"}`
}

func (f *roleAssignFixture) emailExists(label string) bool {
	f.t.Helper()
	var n int
	if err := f.db.QueryRow(`SELECT COUNT(*) FROM platform_users WHERE email = $1`,
		label+"-"+f.suffix+"@role-assign.example.test").Scan(&n); err != nil {
		f.t.Fatalf("emailExists: %v", err)
	}
	return n > 0
}

func expectStatus(t *testing.T, what string, got int, body string, want int) {
	t.Helper()
	if got != want {
		t.Fatalf("%s: status = %d, want %d; body=%s", what, got, want, body)
	}
}

func TestIntegration_PlatformRoleAssignment_RealRouter(t *testing.T) {
	f := newRoleAssignFixture(t)

	// The reported exploit, against the stock role that now holds assign.
	t.Run("stock platform_admin cannot make itself super_admin", func(t *testing.T) {
		code, body := f.setRole(f.platformAdmin, f.platformAdmin, "super_admin")
		expectStatus(t, "self-promotion", code, body, http.StatusForbidden)
		if f.roleOf(f.platformAdmin) != f.roles["platform_admin"] {
			t.Fatal("the denied request still changed the caller's role")
		}
	})

	t.Run("stock platform_admin cannot make anyone super_admin", func(t *testing.T) {
		code, body := f.setRole(f.platformAdmin, f.target, "super_admin")
		expectStatus(t, "grant super_admin", code, body, http.StatusForbidden)
		if !strings.Contains(body, "missing_permissions") {
			t.Errorf("403 should list missing_permissions; body=%s", body)
		}
		if f.roleOf(f.target) != f.roles["narrow"] {
			t.Fatal("the denied request still changed the target's role")
		}
	})

	// Owner decision: every role except super_admin. support_agent is within
	// platform_admin's permissions, so a stock platform_admin grants it...
	t.Run("stock platform_admin can grant support_agent", func(t *testing.T) {
		code, body := f.setRole(f.platformAdmin, f.target, "support_agent")
		expectStatus(t, "grant support_agent", code, body, http.StatusOK)
		if f.roleOf(f.target) != f.roles["support_agent"] {
			t.Fatal("the permitted grant was not written")
		}
		code, body = f.setRole(f.platformAdmin, f.target, "narrow")
		expectStatus(t, "restore the target", code, body, http.StatusOK)

		code, body = f.do(f.platformAdmin, http.MethodPost, "/invite", f.newUserBody("i-support", "support_agent"))
		expectStatus(t, "invite as support_agent", code, body, http.StatusCreated)
		code, body = f.do(f.platformAdmin, http.MethodPost, "", f.newUserBody("c-support", "support_agent"))
		expectStatus(t, "create as support_agent", code, body, http.StatusCreated)
	})

	// ...and, by the target-rank rule, manages an existing support agent.
	t.Run("stock platform_admin can manage a support_agent", func(t *testing.T) {
		code, body := f.do(f.platformAdmin, http.MethodPut, "/"+f.support.String()+"/set-password",
			`{"new_password":"Str0ng!Passw0rd#2026"}`)
		expectStatus(t, "set a support_agent's password", code, body, http.StatusOK)
		code, body = f.do(f.platformAdmin, http.MethodPut, "/"+f.support.String(), `{"is_active":false}`)
		expectStatus(t, "deactivate a support_agent", code, body, http.StatusOK)
		code, body = f.do(f.platformAdmin, http.MethodPut, "/"+f.support.String(), `{"is_active":true}`)
		expectStatus(t, "reactivate a support_agent", code, body, http.StatusOK)
		code, body = f.setRole(f.platformAdmin, f.support, "narrow")
		expectStatus(t, "re-role a support_agent", code, body, http.StatusOK)
		code, body = f.setRole(f.platformAdmin, f.support, "support_agent")
		expectStatus(t, "restore the support_agent", code, body, http.StatusOK)
	})

	// ...but still never super_admin, in any of the ways a role is granted.
	t.Run("stock platform_admin still cannot grant super_admin anywhere", func(t *testing.T) {
		code, body := f.setRole(f.platformAdmin, f.support, "super_admin")
		expectStatus(t, "promote a support_agent to super_admin", code, body, http.StatusForbidden)
		if f.roleOf(f.support) != f.roles["support_agent"] {
			t.Fatal("the denied promotion was still written")
		}
		code, body = f.do(f.platformAdmin, http.MethodPost, "/invite", f.newUserBody("i-super", "super_admin"))
		expectStatus(t, "invite as super_admin", code, body, http.StatusForbidden)
		code, body = f.do(f.platformAdmin, http.MethodPost, "", f.newUserBody("c-super", "super_admin"))
		expectStatus(t, "create as super_admin", code, body, http.StatusForbidden)
		if f.emailExists("i-super") || f.emailExists("c-super") {
			t.Fatal("a denied super_admin create/invite still inserted the user")
		}
	})

	// support_agent is NOT a superset of platform_admin: a support agent holds
	// neither platform_roles.assign nor rank over a platform_admin.
	t.Run("support_agent cannot act on a platform_admin", func(t *testing.T) {
		code, body := f.do(f.support, http.MethodPut, "/"+f.platformAdmin.String(), `{"is_active":false}`)
		if code != http.StatusForbidden {
			t.Fatalf("support_agent deactivating a platform_admin: status = %d, want 403; body=%s", code, body)
		}
	})

	t.Run("without platform_roles.assign nobody's role changes", func(t *testing.T) {
		code, body := f.setRole(f.noAssign, f.target, "pa_no_assign")
		expectStatus(t, "role change without assign", code, body, http.StatusForbidden)
		if !strings.Contains(body, "platform_roles.assign") {
			t.Errorf("403 should name platform_roles.assign; body=%s", body)
		}
		if f.roleOf(f.target) != f.roles["narrow"] {
			t.Fatal("the denied request still changed the target's role")
		}
	})

	t.Run("without platform_roles.assign a profile can still be edited", func(t *testing.T) {
		// The Edit form re-sends the user's current role.
		code, body := f.setRole(f.noAssign, f.target, "narrow")
		expectStatus(t, "profile edit", code, body, http.StatusOK)
	})

	t.Run("stock platform_admin can grant platform_admin", func(t *testing.T) {
		code, body := f.setRole(f.platformAdmin, f.victim, "platform_admin")
		expectStatus(t, "grant platform_admin", code, body, http.StatusOK)
		if f.roleOf(f.victim) != f.roles["platform_admin"] {
			t.Fatal("the permitted role change was not written")
		}
		code, body = f.setRole(f.platformAdmin, f.victim, "narrow")
		expectStatus(t, "re-role a peer platform_admin", code, body, http.StatusOK)
	})

	t.Run("assign holder cannot grant a broader role", func(t *testing.T) {
		code, body := f.setRole(f.assigner, f.target, "super_admin")
		expectStatus(t, "broader grant", code, body, http.StatusForbidden)
		if !strings.Contains(body, "missing_permissions") {
			t.Errorf("403 should list missing_permissions; body=%s", body)
		}
		if f.roleOf(f.target) != f.roles["narrow"] {
			t.Fatal("the denied request still changed the target's role")
		}
	})

	t.Run("assign holder cannot demote a super_admin", func(t *testing.T) {
		code, body := f.setRole(f.assigner, f.superB, "narrow")
		expectStatus(t, "demote superior", code, body, http.StatusForbidden)
		if f.roleOf(f.superB) != f.roles["super_admin"] {
			t.Fatal("the denied request still demoted the super_admin")
		}
	})

	t.Run("assign holder cannot change its own role", func(t *testing.T) {
		code, body := f.setRole(f.assigner, f.assigner, "narrow")
		expectStatus(t, "self change", code, body, http.StatusForbidden)
	})

	t.Run("assign holder can grant a role within its permissions, and it is audited", func(t *testing.T) {
		drain(f.audits)
		code, body := f.setRole(f.assigner, f.target, "platform_admin")
		expectStatus(t, "subset grant", code, body, http.StatusOK)
		if f.roleOf(f.target) != f.roles["platform_admin"] {
			t.Fatal("the permitted role change was not written")
		}
		ev := awaitEvent(t, f.audits, "platform_user.role_changed")
		meta, _ := ev["metadata"].(map[string]interface{})
		if meta["old_role_name"] != "test_narrow_"+f.suffix || meta["new_role_name"] != "platform_admin" {
			t.Errorf("role_changed metadata = %v, want narrow → platform_admin", meta)
		}
		if meta["old_role_id"] != f.roles["narrow"].String() || meta["new_role_id"] != f.roles["platform_admin"].String() {
			t.Errorf("role_changed metadata ids = %v", meta)
		}
		if ev["user_id"] != f.assigner.String() {
			t.Errorf("role_changed actor = %v, want %s", ev["user_id"], f.assigner)
		}
	})

	t.Run("super_admin can grant super_admin", func(t *testing.T) {
		code, body := f.setRole(f.superA, f.target, "super_admin")
		expectStatus(t, "super grant", code, body, http.StatusOK)
		if f.roleOf(f.target) != f.roles["super_admin"] {
			t.Fatal("the permitted role change was not written")
		}
	})

	t.Run("create and invite follow the same rules", func(t *testing.T) {
		code, body := f.do(f.noAssign, http.MethodPost, "", f.newUserBody("c1", "narrow"))
		expectStatus(t, "create without assign", code, body, http.StatusForbidden)
		if f.emailExists("c1") {
			t.Fatal("a denied create still inserted the user")
		}

		code, body = f.do(f.noAssign, http.MethodPost, "/invite", f.newUserBody("i1", "narrow"))
		expectStatus(t, "invite without assign", code, body, http.StatusForbidden)
		if f.emailExists("i1") {
			t.Fatal("a denied invite still inserted the user")
		}

		code, body = f.do(f.platformAdmin, http.MethodPost, "", f.newUserBody("c2", "super_admin"))
		expectStatus(t, "create broader role", code, body, http.StatusForbidden)
		code, body = f.do(f.platformAdmin, http.MethodPost, "/invite", f.newUserBody("i2", "super_admin"))
		expectStatus(t, "invite broader role", code, body, http.StatusForbidden)
		if f.emailExists("c2") || f.emailExists("i2") {
			t.Fatal("a denied create/invite still inserted the user")
		}

		// The owner-facing default: a stock platform_admin adds staff again.
		code, body = f.do(f.platformAdmin, http.MethodPost, "", f.newUserBody("c3", "narrow"))
		expectStatus(t, "stock platform_admin create", code, body, http.StatusCreated)
		code, body = f.do(f.platformAdmin, http.MethodPost, "/invite", f.newUserBody("i4", "platform_admin"))
		expectStatus(t, "stock platform_admin invite", code, body, http.StatusCreated)
		code, body = f.do(f.superA, http.MethodPost, "/invite", f.newUserBody("i3", "super_admin"))
		expectStatus(t, "super_admin invite", code, body, http.StatusCreated)
	})

	t.Run("super_admin may step down while another remains", func(t *testing.T) {
		code, body := f.setRole(f.superA, f.superA, "platform_admin")
		expectStatus(t, "super self-demotion", code, body, http.StatusOK)
	})
}

// Target rank (rule 5) and self-protection (rule 6) on every mutation that is
// not a role change, through the real router: set-password, send-password-
// reset, deactivate, delete.
func TestIntegration_PlatformUserTargetRank_RealRouter(t *testing.T) {
	f := newRoleAssignFixture(t)

	t.Run("platform_admin cannot set a super_admin's password", func(t *testing.T) {
		before := f.column(f.superB, "password_hash")
		code, body := f.do(f.platformAdmin, http.MethodPut, "/"+f.superB.String()+"/set-password",
			`{"new_password":"Str0ng!Passw0rd#2026"}`)
		expectStatus(t, "set-password on a super_admin", code, body, http.StatusForbidden)
		if !strings.Contains(body, "missing_permissions") {
			t.Errorf("403 should list missing_permissions; body=%s", body)
		}
		if f.column(f.superB, "password_hash") != before {
			t.Fatal("the denied set-password still changed the super_admin's password")
		}
	})

	t.Run("platform_admin cannot send a super_admin a reset link", func(t *testing.T) {
		code, body := f.do(f.platformAdmin, http.MethodPost, "/"+f.superB.String()+"/send-password-reset", "")
		expectStatus(t, "send-reset to a super_admin", code, body, http.StatusForbidden)
		if strings.Contains(body, "reset_link") || f.column(f.superB, "password_reset_token") != "" {
			t.Fatal("the denied send-reset still minted a reset token")
		}
	})

	t.Run("platform_admin cannot deactivate a super_admin", func(t *testing.T) {
		code, body := f.do(f.platformAdmin, http.MethodPut, "/"+f.superB.String(), `{"is_active":false}`)
		expectStatus(t, "deactivate a super_admin", code, body, http.StatusForbidden)
		if f.column(f.superB, "is_active") != "true" {
			t.Fatal("the denied deactivation still deactivated the super_admin")
		}
	})

	t.Run("platform_admin can manage a user it outranks", func(t *testing.T) {
		code, body := f.do(f.platformAdmin, http.MethodPut, "/"+f.target.String()+"/set-password",
			`{"new_password":"Str0ng!Passw0rd#2026"}`)
		expectStatus(t, "set-password within rank", code, body, http.StatusOK)
		code, body = f.do(f.platformAdmin, http.MethodPut, "/"+f.target.String(), `{"is_active":false}`)
		expectStatus(t, "deactivate within rank", code, body, http.StatusOK)
		code, body = f.do(f.platformAdmin, http.MethodPut, "/"+f.target.String(), `{"is_active":true}`)
		expectStatus(t, "reactivate within rank", code, body, http.StatusOK)
	})

	t.Run("delete needs rank over the target", func(t *testing.T) {
		code, body := f.do(f.assigner, http.MethodDelete, "/"+f.superB.String(), "")
		expectStatus(t, "delete a super_admin", code, body, http.StatusForbidden)
		if f.column(f.superB, "deleted_at") != "" {
			t.Fatal("the denied delete still deleted the super_admin")
		}
		code, body = f.do(f.assigner, http.MethodDelete, "/"+f.victim.String(), "")
		expectStatus(t, "delete within rank", code, body, http.StatusOK)
		if f.column(f.victim, "deleted_at") == "" {
			t.Fatal("the permitted delete was not written")
		}
	})

	t.Run("nobody deactivates or deletes themselves", func(t *testing.T) {
		code, body := f.do(f.superA, http.MethodPut, "/"+f.superA.String(), `{"is_active":false}`)
		expectStatus(t, "self-deactivation", code, body, http.StatusForbidden)
		code, body = f.do(f.superA, http.MethodDelete, "/"+f.superA.String(), "")
		expectStatus(t, "self-deletion", code, body, http.StatusForbidden)
		if f.column(f.superA, "is_active") != "true" || f.column(f.superA, "deleted_at") != "" {
			t.Fatal("a refused self-deactivation/deletion still changed the row")
		}
	})
}

// column reads one platform_users column as text ("" for NULL).
func (f *roleAssignFixture) column(user uuid.UUID, col string) string {
	f.t.Helper()
	var v sql.NullString
	// col is always a literal from this file, never input.
	if err := f.db.QueryRow(`SELECT `+col+`::text FROM platform_users WHERE id = $1`, user).Scan(&v); err != nil { //nolint:gosec // test-only column literal
		f.t.Fatalf("read %s: %v", col, err)
	}
	return v.String
}

func drain(ch chan map[string]interface{}) {
	for {
		select {
		case <-ch:
		default:
			return
		}
	}
}

func awaitEvent(t *testing.T, ch chan map[string]interface{}, eventType string) map[string]interface{} {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case ev := <-ch:
			if ev["event_type"] == eventType {
				return ev
			}
		case <-deadline:
			t.Fatalf("no %s audit event was recorded", eventType)
			return nil
		}
	}
}
