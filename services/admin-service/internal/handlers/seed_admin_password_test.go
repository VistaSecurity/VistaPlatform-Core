package handlers

// Guards the seeded platform-admin password against drift.
//
// The scripts that print login instructions (prod-smoke.sh, deploy-smoke.sh,
// deploy-ec2-smoke.sh, seed-smoke-platform-admins.sh) used to each hardcode the
// password. When seed.sql moved to 'PlatformAdm!n2026' the copies stayed on
// 'Password123!' — prod-smoke.sh's admin login 401'd and the printed
// instructions could not work. They now all source
// scripts/lib/seed-credentials.sh; this test proves that file's value is the
// password that actually opens the seeded accounts, by verifying it against the
// real Argon2id hashes in seed.sql. A comment-to-comment grep would not — it
// would happily agree with itself while both were wrong.

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	passwordsvc "github.com/vistasecurity/vistaplatform/shared/security/password"
)

// repoRoot walks up from the test's working directory to the repo root.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for i := 0; i < 10; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.work")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Skip("repo root (go.work) not found; skipping seed-credential drift guard")
	return ""
}

// seedAdminPasswordFromLib reads SEED_ADMIN_PASSWORD out of
// scripts/lib/seed-credentials.sh — the single source of truth the shell
// scripts source.
func seedAdminPasswordFromLib(t *testing.T, root string) string {
	t.Helper()
	path := filepath.Join(root, "scripts", "lib", "seed-credentials.sh")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	re := regexp.MustCompile(`(?m)^SEED_ADMIN_PASSWORD='([^']*)'`)
	m := re.FindSubmatch(data)
	if m == nil {
		t.Fatalf("SEED_ADMIN_PASSWORD not found in %s", path)
	}
	return string(m[1])
}

// seededAdminHashes pulls every Argon2id hash that seed.sql inserts into
// platform_users. Both seeded admins must open on the same published password.
func seededAdminHashes(t *testing.T, root string) []string {
	t.Helper()
	path := filepath.Join(root, "scripts", "database", "seed.sql")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	// Only the platform_users INSERTs — seed.sql also seeds tenant users with a
	// different password, and pulling those in would make this test unsatisfiable.
	body := string(data)
	re := regexp.MustCompile(`'(\$argon2id\$[^']+)'`)

	var hashes []string
	for _, stmt := range strings.Split(body, ";") {
		if !strings.Contains(stmt, "INSERT INTO platform_users") {
			continue
		}
		for _, m := range re.FindAllStringSubmatch(stmt, -1) {
			hashes = append(hashes, m[1])
		}
	}
	return hashes
}

func TestSeedAdminPasswordMatchesSeededHash(t *testing.T) {
	root := repoRoot(t)
	want := seedAdminPasswordFromLib(t, root)

	hashes := seededAdminHashes(t, root)
	if len(hashes) == 0 {
		t.Fatal("no Argon2id hashes found in seed.sql platform_users INSERTs")
	}

	svc := passwordsvc.NewPasswordService()
	for i, h := range hashes {
		ok, err := svc.VerifyPassword(want, h)
		if err != nil {
			t.Fatalf("hash %d: verify error: %v", i, err)
		}
		if !ok {
			t.Fatalf("hash %d in seed.sql does not verify against SEED_ADMIN_PASSWORD (%q) "+
				"from scripts/lib/seed-credentials.sh.\n"+
				"Either seed.sql's password changed and the lib file was not updated, or vice "+
				"versa. Any script printing login instructions is now telling users something "+
				"that yields a 401.", i, want)
		}
	}
}

// The seeded admins are deliberately flagged force_password_change, which
// means the published password only buys a change-password-only session. Scripts
// that need a working admin session must rotate first. This pins the flag so a
// future seed edit that silently drops it is noticed — prod-smoke.sh's rotation
// step would become dead code and the security property would be gone.
func TestSeedAdminsForcePasswordChange(t *testing.T) {
	root := repoRoot(t)
	path := filepath.Join(root, "scripts", "database", "seed.sql")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	var checked int
	for _, stmt := range strings.Split(string(data), ";") {
		if !strings.Contains(stmt, "INSERT INTO platform_users") {
			continue
		}
		if !strings.Contains(stmt, "force_password_change") {
			t.Errorf("a platform_users INSERT in seed.sql does not set force_password_change; "+
				"the seeded admin would get a full session on a published password:\n%s",
				strings.TrimSpace(stmt))
			continue
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("no platform_users INSERT statements found in seed.sql")
	}
}
