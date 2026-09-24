package testdb

import (
	"database/sql"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// Platform (operator) identity fixtures, for tests that drive a platform
// permission gate against the real platform_user_has_permission().
//
// Rows are the calling test's own and are removed at cleanup: users first,
// then roles (t.Cleanup runs last-registered-first, and a user created after
// its role therefore goes first, before the role's foreign key would object).

// SeededPlatformRole returns the id of a seeded platform role by name, failing
// the test if the seed does not carry it.
func SeededPlatformRole(t *testing.T, db *sql.DB, name string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	if err := db.QueryRow(`SELECT id FROM platform_roles WHERE name = $1`, name).Scan(&id); err != nil {
		t.Fatalf("testdb: seeded platform role %q: %v", name, err)
	}
	return id
}

// NewPlatformRole creates a custom (non-system) platform role holding exactly
// perms. Every name must exist in platform_permissions: a misspelt permission
// would otherwise grant nothing and leave a "role WITH the permission" test
// quietly exercising a role without it.
func NewPlatformRole(t *testing.T, db *sql.DB, perms ...string) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	name := "test_role_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	if err := db.QueryRow(`
		INSERT INTO platform_roles (name, display_name, description, is_system_role)
		VALUES ($1, $1, 'testdb platform fixture', false) RETURNING id`, name).Scan(&id); err != nil {
		t.Fatalf("testdb: create platform role: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM platform_role_permissions WHERE role_id = $1`, id)
		_, _ = db.Exec(`DELETE FROM platform_roles WHERE id = $1`, id)
	})
	if len(perms) == 0 {
		return id
	}
	res, err := db.Exec(`
		INSERT INTO platform_role_permissions (role_id, permission_id)
		SELECT $1::uuid, id FROM platform_permissions WHERE name = ANY($2)`, id, pq.Array(perms))
	if err != nil {
		t.Fatalf("testdb: grant platform role: %v", err)
	}
	if n, _ := res.RowsAffected(); n != int64(len(perms)) {
		t.Fatalf("testdb: granted %d of %d permissions %v — a name is not in platform_permissions", n, len(perms), perms)
	}
	return id
}

// NewPlatformUser creates an active platform user holding roleID.
func NewPlatformUser(t *testing.T, db *sql.DB, roleID uuid.UUID) uuid.UUID {
	t.Helper()
	var id uuid.UUID
	email := "platform-fixture-" + uuid.NewString()[:8] + "@example.test"
	if err := db.QueryRow(`
		INSERT INTO platform_users (email, password_hash, first_name, last_name, role_id, is_active)
		VALUES ($1, 'not-a-real-hash', 'Platform', 'Fixture', $2, true)
		RETURNING id`, email, roleID).Scan(&id); err != nil {
		t.Fatalf("testdb: create platform user: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM platform_users WHERE id = $1`, id) })
	return id
}
