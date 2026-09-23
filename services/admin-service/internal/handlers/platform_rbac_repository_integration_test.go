package handlers

// platformRBACRepository.PermissionsNotHeldBy compares permission ids as uuid,
// not as text. The handler canonicalizes ids before calling it, so through the
// router this is defence in depth; it is pinned here on its own so the query
// cannot quietly go back to "pp.id::text = ANY($2)" — the exact-string match
// that let an upper-case id of an unheld permission pass the check while the
// write (which casts to uuid) still stored it. Skips without TEST_DATABASE_URL.

import (
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_PlatformRBACRepository_PermissionsNotHeldBy_ComparesAsUUID(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	repo := &platformRBACRepository{db: db}

	var platformAdminRole uuid.UUID
	if err := db.QueryRow(`SELECT id FROM platform_roles WHERE name = 'platform_admin'`).Scan(&platformAdminRole); err != nil {
		t.Fatal(err)
	}
	var caller uuid.UUID
	if err := db.QueryRow(`
		INSERT INTO platform_users (email, password_hash, first_name, last_name, role_id, is_active)
		VALUES ($1, 'not-a-real-hash', 'Rbac', 'Repo', $2, true) RETURNING id`,
		"rbac-repo-"+uuid.NewString()[:12]+"@rbac-repo.example.test", platformAdminRole).Scan(&caller); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM platform_users WHERE id = $1`, caller) })

	var override string // platform_admin does not hold platform.override
	if err := db.QueryRow(`SELECT id::text FROM platform_permissions WHERE name = 'platform.override'`).Scan(&override); err != nil {
		t.Fatal(err)
	}

	for name, id := range map[string]string{
		"canonical":  override,
		"upper case": strings.ToUpper(override),
		"braced":     "{" + override + "}",
		"no hyphens": strings.ReplaceAll(override, "-", ""),
	} {
		t.Run(name, func(t *testing.T) {
			missing, err := repo.PermissionsNotHeldBy(caller.String(), []string{id})
			if err != nil {
				t.Fatalf("PermissionsNotHeldBy: %v", err)
			}
			if len(missing) != 1 || missing[0] != "platform.override" {
				t.Fatalf("PermissionsNotHeldBy(%s) = %v, want [platform.override]", id, missing)
			}
		})
	}
}
