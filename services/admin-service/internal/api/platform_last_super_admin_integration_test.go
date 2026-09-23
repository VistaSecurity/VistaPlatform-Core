package api

// The last-active-super_admin invariant, through the REAL router against a
// real Postgres — including the race it exists to close.
//
// "Last" cannot be staged in the shared integration database: the seed's own
// super_admin is active there, and deactivating a seeded row would pollute every
// other test binary running against it. So this file builds a SCRATCH database
// (schema + seed applied fresh), dropped at the end, where it may deactivate the
// seeded super_admins freely.
//
// The race test is deterministic rather than a goroutine storm: an open
// transaction holds super_admin B's row mid-deactivation while super_admin A
// asks to step down. A guard that merely COUNTS sees B as still active (the
// deactivation is uncommitted), lets A through, and the platform ends with no
// super_admin once B's transaction commits. The real guard locks the active
// super_admin rows, so A's request waits on B's row and re-reads it after the
// commit. Both polarities are asserted: commit → 409, rollback → 200.
//
// Needs TEST_DATABASE_URL and a role allowed to CREATE DATABASE (skips
// otherwise); `make test-integration-db` runs it.

import (
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/admin-service/internal/config"
	shareddatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// scratchPlatformDB creates an empty database next to TEST_DATABASE_URL's,
// applies schema.sql + seed.sql to it, and drops it at test end.
func scratchPlatformDB(t *testing.T) *sql.DB {
	t.Helper()
	admin := testdb.Connect(t)
	name := "admin_last_super_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:10]
	if _, err := admin.Exec(fmt.Sprintf(`CREATE DATABASE %q`, name)); err != nil {
		t.Skipf("cannot create a scratch database (%v) — this test needs CREATEDB", err)
	}
	t.Cleanup(func() { _, _ = admin.Exec(fmt.Sprintf(`DROP DATABASE IF EXISTS %q WITH (FORCE)`, name)) })

	u, err := url.Parse(os.Getenv(testdb.URLEnv))
	if err != nil {
		t.Fatalf("parse %s: %v", testdb.URLEnv, err)
	}
	u.Path = "/" + name
	db, err := sql.Open("postgres", u.String())
	if err != nil {
		t.Fatalf("open scratch database: %v", err)
	}
	if err := shareddatabase.RegisterSessionPool(db, "postgres", u.String()); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	// Registered after the DROP above, so it runs first: close the pools, then drop.
	t.Cleanup(func() { _ = shareddatabase.CloseWithSessionPool(db) })
	testdb.ApplySchemaAndSeed(t, db)
	return db
}

type lastSuperFixture struct {
	*roleAssignFixture
	omni uuid.UUID // holds every permission super_admin holds, under another role name
}

func newLastSuperFixture(t *testing.T) *lastSuperFixture {
	t.Helper()
	db := scratchPlatformDB(t)
	t.Setenv("AUDIT_LOGGING_ENABLED", "false")

	f := &roleAssignFixture{t: t, db: db, roles: map[string]uuid.UUID{},
		suffix: strings.ReplaceAll(uuid.NewString(), "-", "")[:12]}
	for _, name := range []string{"super_admin", "platform_admin"} {
		var id uuid.UUID
		if err := db.QueryRow(`SELECT id FROM platform_roles WHERE name = $1`, name).Scan(&id); err != nil {
			t.Fatalf("seeded role %s: %v", name, err)
		}
		f.roles[name] = id
	}

	// Scratch database only: take every seeded super_admin out of the active set
	// so this test's own superA is the last one.
	if _, err := db.Exec(`UPDATE platform_users SET is_active = false WHERE role_id = $1`, f.roles["super_admin"]); err != nil {
		t.Fatalf("deactivate seeded super_admins: %v", err)
	}

	// "omni": a custom role carrying all of super_admin's permissions. It
	// outranks a super_admin (rule 5 passes) without BEING one, so the only
	// thing that can stop it removing the last super_admin is the store guard.
	var omni uuid.UUID
	if err := db.QueryRow(`
		INSERT INTO platform_roles (name, display_name, description, is_system_role)
		VALUES ('test_omni', 'Omni (test)', 'last-super-admin fixture', false) RETURNING id`).Scan(&omni); err != nil {
		t.Fatalf("create omni role: %v", err)
	}
	f.roles["omni"] = omni
	if _, err := db.Exec(`
		INSERT INTO platform_role_permissions (role_id, permission_id)
		SELECT $1::uuid, permission_id FROM platform_role_permissions WHERE role_id = $2`,
		omni, f.roles["super_admin"]); err != nil {
		t.Fatalf("grant omni role: %v", err)
	}

	f.superA = f.user("supera", "super_admin")
	f.superB = f.user("superb", "super_admin")
	// B starts inactive: A is the last active super_admin.
	if _, err := db.Exec(`UPDATE platform_users SET is_active = false WHERE id = $1`, f.superB); err != nil {
		t.Fatal(err)
	}
	lf := &lastSuperFixture{roleAssignFixture: f, omni: f.user("omni", "omni")}

	f.srv = NewServerWithConnections(
		&config.Config{Environment: "test", JWTSecret: roleAssignJWTSecret},
		db, db, EditionHooks{},
	)
	return lf
}

func (f *lastSuperFixture) activeSuperAdmins() int {
	f.t.Helper()
	var n int
	if err := f.db.QueryRow(`
		SELECT COUNT(*) FROM platform_users
		WHERE role_id = $1 AND is_active AND deleted_at IS NULL`, f.roles["super_admin"]).Scan(&n); err != nil {
		f.t.Fatalf("count active super_admins: %v", err)
	}
	return n
}

func TestIntegration_PlatformUsers_LastSuperAdmin(t *testing.T) {
	f := newLastSuperFixture(t)
	if n := f.activeSuperAdmins(); n != 1 {
		t.Fatalf("premise: want exactly one active super_admin, have %d", n)
	}

	t.Run("cannot be deactivated", func(t *testing.T) {
		code, body := f.do(f.omni, http.MethodPut, "/"+f.superA.String(), `{"is_active":false}`)
		expectStatus(t, "deactivate the last super_admin", code, body, http.StatusConflict)
	})
	t.Run("cannot be deleted", func(t *testing.T) {
		code, body := f.do(f.omni, http.MethodDelete, "/"+f.superA.String(), "")
		expectStatus(t, "delete the last super_admin", code, body, http.StatusConflict)
	})
	t.Run("cannot be re-roled by someone else", func(t *testing.T) {
		code, body := f.setRole(f.omni, f.superA, "platform_admin")
		expectStatus(t, "re-role the last super_admin", code, body, http.StatusConflict)
	})
	t.Run("cannot step down", func(t *testing.T) {
		code, body := f.setRole(f.superA, f.superA, "platform_admin")
		expectStatus(t, "last super_admin self-demotion", code, body, http.StatusConflict)
	})
	if n := f.activeSuperAdmins(); n != 1 {
		t.Fatalf("a refused request still removed the last super_admin (active = %d)", n)
	}

	// The other polarity: with a second active super_admin, the same requests
	// are allowed — the guard is about the LAST one, not about super_admins.
	t.Run("can be deactivated while another remains", func(t *testing.T) {
		if _, err := f.db.Exec(`UPDATE platform_users SET is_active = true WHERE id = $1`, f.superB); err != nil {
			t.Fatal(err)
		}
		code, body := f.do(f.omni, http.MethodPut, "/"+f.superB.String(), `{"is_active":false}`)
		expectStatus(t, "deactivate a non-last super_admin", code, body, http.StatusOK)
	})
}

// raceStepDown holds super_admin B's row mid-deactivation in an open
// transaction, sends super_admin A's step-down request, proves the request is
// WAITING on that row, then ends the transaction with finish.
func (f *lastSuperFixture) raceStepDown(t *testing.T, finish func(*sql.Tx) error) (int, string) {
	t.Helper()
	if _, err := f.db.Exec(`UPDATE platform_users SET is_active = true, role_id = $2 WHERE id = ANY($1)`,
		"{"+f.superA.String()+","+f.superB.String()+"}", f.roles["super_admin"]); err != nil {
		t.Fatal(err)
	}
	if n := f.activeSuperAdmins(); n != 2 {
		t.Fatalf("premise: want two active super_admins, have %d", n)
	}

	tx, err := f.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tx.Rollback() })
	if _, err := tx.Exec(`UPDATE platform_users SET is_active = false WHERE id = $1`, f.superB); err != nil {
		t.Fatal(err)
	}

	type result struct {
		code int
		body string
	}
	done := make(chan result, 1)
	go func() {
		req := httptest.NewRequest(http.MethodPut, "/api/v1/admin-service/admin/users/"+f.superA.String(),
			strings.NewReader(`{"role_id":"`+f.roles["platform_admin"].String()+`"}`))
		req.Header.Set("Authorization", "Bearer "+f.token(f.superA))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		f.srv.Router().ServeHTTP(w, req)
		done <- result{w.Code, w.Body.String()}
	}()

	select {
	case r := <-done:
		t.Fatalf("the step-down did not wait for the concurrent deactivation of the other super_admin "+
			"(status %d, body %s) — the last-super-admin guard is a count, not a lock", r.code, r.body)
	case <-time.After(750 * time.Millisecond):
	}

	if err := finish(tx); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-done:
		return r.code, r.body
	case <-time.After(10 * time.Second):
		t.Fatal("the step-down never completed after the concurrent transaction ended")
		return 0, ""
	}
}

func TestIntegration_PlatformUsers_LastSuperAdmin_Race(t *testing.T) {
	f := newLastSuperFixture(t)

	t.Run("concurrent deactivation commits: step-down refused", func(t *testing.T) {
		code, body := f.raceStepDown(t, (*sql.Tx).Commit)
		expectStatus(t, "step-down racing the other super_admin's deactivation", code, body, http.StatusConflict)
		if n := f.activeSuperAdmins(); n != 1 {
			t.Fatalf("active super_admins = %d after the race, want 1", n)
		}
		if f.roleOf(f.superA) != f.roles["super_admin"] {
			t.Fatal("the refused step-down still changed A's role")
		}
	})

	t.Run("concurrent deactivation rolls back: step-down allowed", func(t *testing.T) {
		code, body := f.raceStepDown(t, (*sql.Tx).Rollback)
		expectStatus(t, "step-down after the other deactivation rolled back", code, body, http.StatusOK)
		if f.roleOf(f.superA) != f.roles["platform_admin"] {
			t.Fatal("the permitted step-down was not written")
		}
		if n := f.activeSuperAdmins(); n != 1 {
			t.Fatalf("active super_admins = %d, want 1 (B)", n)
		}
	})
}
