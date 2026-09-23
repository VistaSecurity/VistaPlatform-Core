package handlers

// A platform_users row with no role. The schema declares role_id NOT NULL, so
// the shared test database cannot hold one; this test builds a throwaway
// database with just the two tables the repository touches and role_id left
// nullable — the shape of a row written outside the constraint — and checks
// what the platform does with it (skips without TEST_DATABASE_URL):
//
//   - list and get return "role_id": null, never the zero UUID (which the
//     console could not tell from a real id), and
//   - a conditional write whose check saw "no role" matches a still-roleless
//     row (role_id IS NOT DISTINCT FROM NULL — a plain "=" never would) and
//     does not match one that has since been given a role.
//
// The scratch database is dropped at cleanup.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func rolelessScratchDB(t *testing.T) *sql.DB {
	t.Helper()
	admin := testdb.Connect(t) // skips without TEST_DATABASE_URL
	name := "roleless_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:16]
	if _, err := admin.Exec(`CREATE DATABASE ` + name); err != nil { //nolint:gosec // generated identifier
		t.Fatalf("create scratch database: %v", err)
	}
	u, err := url.Parse(os.Getenv("TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + name
	db, err := sql.Open("postgres", u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = db.Close()
		_, _ = admin.Exec(`DROP DATABASE IF EXISTS ` + name + ` WITH (FORCE)`) //nolint:gosec // generated identifier
	})
	if _, err := db.Exec(`
		CREATE TABLE platform_roles (
			id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
			name text NOT NULL UNIQUE,
			display_name text NOT NULL DEFAULT ''
		);
		CREATE TABLE platform_users (
			id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
			email text NOT NULL,
			password_hash text,
			first_name text NOT NULL DEFAULT '',
			last_name text NOT NULL DEFAULT '',
			role_id uuid REFERENCES platform_roles(id), -- nullable on purpose
			is_active boolean NOT NULL DEFAULT true,
			email_verified boolean NOT NULL DEFAULT false,
			force_password_change boolean NOT NULL DEFAULT false,
			password_changed_at timestamptz,
			password_reset_token text,
			password_reset_expires timestamptz,
			last_login_at timestamptz,
			invitation_accepted_at timestamptz,
			invited_by uuid,
			deleted_at timestamptz,
			created_at timestamptz NOT NULL DEFAULT now(),
			updated_at timestamptz NOT NULL DEFAULT now()
		);`); err != nil {
		t.Fatalf("create scratch tables: %v", err)
	}
	return db
}

func TestIntegration_RolelessPlatformUser_ReadAsNullAndConditionalWrites(t *testing.T) {
	db := rolelessScratchDB(t)
	repo := &platformUserRepository{db: db}
	ctx := context.Background()

	var roleID, withRole, roleless uuid.UUID
	if err := db.QueryRow(`INSERT INTO platform_roles (name, display_name) VALUES ('narrow', 'Narrow') RETURNING id`).Scan(&roleID); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`INSERT INTO platform_users (email, role_id) VALUES ('with@example.test', $1) RETURNING id`, roleID).Scan(&withRole); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`INSERT INTO platform_users (email, role_id) VALUES ('none@example.test', NULL) RETURNING id`).Scan(&roleless); err != nil {
		t.Fatal(err)
	}

	t.Run("get and list return role_id null, not the zero UUID", func(t *testing.T) {
		u, found, err := repo.GetPlatformUser(ctx, roleless.String())
		if err != nil || !found {
			t.Fatalf("get: found=%v err=%v", found, err)
		}
		b, _ := json.Marshal(u)
		if !strings.Contains(string(b), `"role_id":null`) {
			t.Fatalf("get: %s, want role_id null", b)
		}
		users, _, err := repo.ListPlatformUsers(ctx, platformUserListFilters{PageSize: 10})
		if err != nil {
			t.Fatal(err)
		}
		seen := 0
		for _, u := range users {
			b, _ := json.Marshal(u)
			switch u.ID {
			case roleless:
				seen++
				if u.RoleID != nil || !strings.Contains(string(b), `"role_id":null`) {
					t.Fatalf("list: roleless user = %s, want role_id null", b)
				}
			case withRole:
				seen++
				if u.RoleID == nil || *u.RoleID != roleID {
					t.Fatalf("list: user with a role = %s", b)
				}
			}
		}
		if seen != 2 {
			t.Fatalf("list returned %d of the 2 fixture users", seen)
		}
		ref, found, err := repo.PlatformUserRole(ctx, roleless.String())
		if err != nil || !found || ref.RoleID != nil {
			t.Fatalf("PlatformUserRole(roleless) = %+v, %v, %v; want a nil RoleID", ref, found, err)
		}
	})

	t.Run("a write conditioned on no role matches only a still-roleless row", func(t *testing.T) {
		if err := repo.UpdatePlatformUserPassword(ctx, roleless.String(), nil, "new-hash", false); err != nil {
			t.Fatalf("still roleless: err = %v, want nil (NULL must match NULL)", err)
		}
		if err := repo.StorePasswordResetToken(ctx, roleless.String(), &roleID, "t", time.Now().Add(time.Hour)); !errors.Is(err, errPlatformUserChanged) {
			t.Fatalf("expected a role, row has none: err = %v, want errPlatformUserChanged", err)
		}
		// Someone gives the user a role after a check that saw none.
		if _, err := db.Exec(`UPDATE platform_users SET role_id = $1 WHERE id = $2`, roleID, roleless); err != nil {
			t.Fatal(err)
		}
		no := false
		if err := repo.UpdatePlatformUser(ctx, roleless.String(), nil, platformUserUpdateFields{IsActive: &no}); !errors.Is(err, errPlatformUserChanged) {
			t.Fatalf("given a role since the check: err = %v, want errPlatformUserChanged", err)
		}
		var active bool
		if err := db.QueryRow(`SELECT is_active FROM platform_users WHERE id = $1`, roleless).Scan(&active); err != nil || !active {
			t.Fatalf("the refused deactivation was written (active=%v, err=%v)", active, err)
		}
	})
}
