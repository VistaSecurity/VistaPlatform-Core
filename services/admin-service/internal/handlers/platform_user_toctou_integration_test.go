package handlers

// Writes to an existing platform user are conditional on the role the rank
// check saw (platform_role_assignment.go). Against a real Postgres (skips
// without TEST_DATABASE_URL):
//
//   - the REPOSITORY: each conditional write matches nothing, writes nothing
//     and returns errPlatformUserChanged when the expected role is stale (the
//     NULL-role cases are in platform_user_roleless_integration_test.go: the
//     real schema cannot hold a roleless row);
//   - the HANDLERS over the real repository: a concurrent promotion is
//     simulated by re-roling the target to super_admin right after the
//     handler's rank check read its role. Every mutation must answer 409 and
//     leave the row untouched.
//
// Fixture rows are this test's own (random emails, throwaway role) and are
// removed at cleanup; no seeded row is modified.

import (
	"context"
	"database/sql"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

type toctouFixture struct {
	t        *testing.T
	db       *sql.DB
	repo     *platformUserRepository
	suffix   string
	narrow   uuid.UUID
	super    uuid.UUID
	platform uuid.UUID
	caller   uuid.UUID // a stock platform_admin
}

func newTOCTOUFixture(t *testing.T) *toctouFixture {
	t.Helper()
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	f := &toctouFixture{t: t, db: db, repo: &platformUserRepository{db: db},
		suffix: strings.ReplaceAll(uuid.NewString(), "-", "")[:12]}

	for name, dst := range map[string]*uuid.UUID{"super_admin": &f.super, "platform_admin": &f.platform} {
		if err := db.QueryRow(`SELECT id FROM platform_roles WHERE name = $1`, name).Scan(dst); err != nil {
			t.Fatalf("seeded role %s: %v", name, err)
		}
	}
	if err := db.QueryRow(`
		INSERT INTO platform_roles (name, display_name, description, is_system_role)
		VALUES ($1, 'Narrow (toctou test)', 'toctou fixture', false) RETURNING id`,
		"test_toctou_narrow_"+f.suffix).Scan(&f.narrow); err != nil {
		t.Fatalf("create narrow role: %v", err)
	}
	if _, err := db.Exec(`
		INSERT INTO platform_role_permissions (role_id, permission_id)
		SELECT $1::uuid, id FROM platform_permissions WHERE name = 'platform_users.read'`, f.narrow); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM platform_users WHERE email LIKE $1`, "%-"+f.suffix+"@toctou.example.test")
		_, _ = db.Exec(`DELETE FROM platform_roles WHERE id = $1`, f.narrow)
	})
	f.caller = f.user("caller", &f.platform)
	return f
}

func (f *toctouFixture) user(label string, role *uuid.UUID) uuid.UUID {
	f.t.Helper()
	var id uuid.UUID
	if err := f.db.QueryRow(`
		INSERT INTO platform_users (email, password_hash, first_name, last_name, role_id, is_active)
		VALUES ($1, 'original-hash', 'Toc', 'Tou', $2, true) RETURNING id`,
		label+"-"+uuid.NewString()[:8]+"-"+f.suffix+"@toctou.example.test", role).Scan(&id); err != nil {
		f.t.Fatalf("create %s: %v", label, err)
	}
	return id
}

// row returns the columns a conditional write could change, as one string.
func (f *toctouFixture) row(id uuid.UUID) string {
	f.t.Helper()
	var s string
	if err := f.db.QueryRow(`
		SELECT concat_ws('|', password_hash, is_active::text, COALESCE(role_id::text, 'NULL'),
		                 COALESCE(password_reset_token, 'NULL'), COALESCE(deleted_at::text, 'NULL'), first_name)
		FROM platform_users WHERE id = $1`, id).Scan(&s); err != nil {
		f.t.Fatalf("read row: %v", err)
	}
	return s
}

func TestIntegration_PlatformUserWrites_ConditionalOnCheckedRole_Repository(t *testing.T) {
	f := newTOCTOUFixture(t)
	ctx := context.Background()
	no := false
	name := "Changed"

	writes := map[string]func(id string, expected *uuid.UUID) error{
		"update": func(id string, expected *uuid.UUID) error {
			return f.repo.UpdatePlatformUser(ctx, id, expected, platformUserUpdateFields{FirstName: &name})
		},
		"deactivate": func(id string, expected *uuid.UUID) error {
			return f.repo.UpdatePlatformUser(ctx, id, expected, platformUserUpdateFields{IsActive: &no})
		},
		"role change": func(id string, expected *uuid.UUID) error {
			return f.repo.UpdatePlatformUser(ctx, id, expected, platformUserUpdateFields{RoleID: &f.platform})
		},
		"set-password": func(id string, expected *uuid.UUID) error {
			return f.repo.UpdatePlatformUserPassword(ctx, id, expected, "new-hash", false)
		},
		"reset token": func(id string, expected *uuid.UUID) error {
			return f.repo.StorePasswordResetToken(ctx, id, expected, "token-hash", time.Now().Add(time.Hour))
		},
		"delete": func(id string, expected *uuid.UUID) error {
			return f.repo.DeletePlatformUser(ctx, id, expected)
		},
	}
	for op, write := range writes {
		t.Run(op, func(t *testing.T) {
			// Stale: the check saw "narrow", the user now holds super_admin.
			target := f.user("stale", &f.super)
			before := f.row(target)
			if err := write(target.String(), &f.narrow); !errors.Is(err, errPlatformUserChanged) {
				t.Fatalf("stale expected role: err = %v, want errPlatformUserChanged", err)
			}
			if f.row(target) != before {
				t.Fatal("a write conditioned on a stale role still changed the row")
			}

			// Stale the other way: the check saw no role, the user has one.
			if err := write(target.String(), nil); !errors.Is(err, errPlatformUserChanged) {
				t.Fatalf("expected no role, user has one: err = %v, want errPlatformUserChanged", err)
			}
			if f.row(target) != before {
				t.Fatal("a write conditioned on no role still changed a user who has one")
			}

			// Unknown / deleted user: nothing matches either.
			if err := write(uuid.NewString(), &f.narrow); !errors.Is(err, errPlatformUserChanged) {
				t.Fatalf("unknown user: err = %v, want errPlatformUserChanged", err)
			}

			// Current: the role the check saw is still held — written.
			current := f.user("current", &f.narrow)
			before = f.row(current)
			if err := write(current.String(), &f.narrow); err != nil {
				t.Fatalf("current expected role: err = %v, want nil", err)
			}
			if f.row(current) == before {
				t.Fatal("the current-role write was not written")
			}
		})
	}
}

// promotingStore is the real repository, except that right after the FIRST
// read of the target's role — the handler's rank check — it re-roles the
// target to super_admin, as a concurrent operator would.
type promotingStore struct {
	*platformUserRepository
	db      *sql.DB
	target  uuid.UUID
	super   uuid.UUID
	pending bool
}

func (p *promotingStore) PlatformUserRole(ctx context.Context, userID string) (platformUserRoleRef, bool, error) {
	ref, found, err := p.platformUserRepository.PlatformUserRole(ctx, userID)
	if p.pending && userID == p.target.String() {
		p.pending = false
		if _, uerr := p.db.ExecContext(ctx, `UPDATE platform_users SET role_id = $1 WHERE id = $2`, p.super, p.target); uerr != nil {
			return ref, found, uerr
		}
	}
	return ref, found, err
}

func TestIntegration_PlatformUserMutations_409WhenPromotedAfterCheck(t *testing.T) {
	f := newTOCTOUFixture(t)
	gin.SetMode(gin.TestMode)

	cases := []struct {
		name, method, path, body string
	}{
		{"deactivate", http.MethodPut, "", `{"is_active":false}`},
		{"profile edit", http.MethodPut, "", `{"first_name":"Changed"}`},
		{"role change", http.MethodPut, "", `{"role_id":"__NARROW_ALT__"}`},
		{"set-password", http.MethodPut, "/set-password", `{"new_password":"Str0ng!Passw0rd#2026"}`},
		{"send-password-reset", http.MethodPost, "/send-password-reset", ``},
		{"delete", http.MethodDelete, "", ``},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			target := f.user("target", &f.narrow)
			store := &promotingStore{platformUserRepository: f.repo, db: f.db, target: target, super: f.super, pending: true}

			r := gin.New()
			grp := r.Group("/users")
			grp.Use(func(c *gin.Context) { c.Set("userID", f.caller.String()); c.Next() })
			grp.PUT("/:id", updatePlatformUserWithStore(store))
			grp.DELETE("/:id", deletePlatformUserWithStore(store))
			grp.PUT("/:id/set-password", adminSetPasswordWithStore(store, stubPasswordHasher{}))
			grp.POST("/:id/send-password-reset", adminSendPasswordResetWithDeps(store, emailSends(), stubBrandingProvider{}))

			body := strings.ReplaceAll(tc.body, "__NARROW_ALT__", f.platform.String())
			req := httptest.NewRequest(tc.method, "/users/"+target.String()+tc.path, strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			// What the row looks like once the concurrent promotion lands:
			// the request must leave exactly that.
			before := strings.Replace(f.row(target), f.narrow.String(), f.super.String(), 1)
			r.ServeHTTP(w, req)

			// 409 for THIS reason — not, say, the last-super-admin guard.
			if w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "changed by someone else") {
				t.Fatalf("status = %d, want 409 (user changed); body=%s", w.Code, w.Body.String())
			}
			if store.pending {
				t.Fatal("the simulated promotion never ran — the test proves nothing")
			}
			if got := f.row(target); got != before {
				t.Fatalf("the refused request still wrote the promoted user:\n got %s\nwant %s", got, before)
			}
		})
	}

	// The other polarity through the same wiring: no promotion, the write lands.
	t.Run("unchanged target is written", func(t *testing.T) {
		target := f.user("target", &f.narrow)
		store := &promotingStore{platformUserRepository: f.repo, db: f.db, target: target, super: f.super, pending: false}
		r := gin.New()
		r.PUT("/users/:id", func(c *gin.Context) { c.Set("userID", f.caller.String()); c.Next() }, updatePlatformUserWithStore(store))
		req := httptest.NewRequest(http.MethodPut, "/users/"+target.String(), strings.NewReader(`{"is_active":false}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
		}
		if !strings.Contains(f.row(target), "|false|") {
			t.Fatalf("the permitted deactivation was not written: %s", f.row(target))
		}
	})
}
