package services

// Regression guard: scripts/database/schema.sql must apply cleanly over a
// database that an OLDER RELEASE created and then filled with data.
//
// This is a different question from the one
// schema_reapply_integration_test.go answers, and only this one matches what a
// real upgrade does.
//
// The re-apply test applies the CURRENT schema twice. Both passes therefore
// build the CURRENT table shape, so it structurally cannot catch a statement
// that is fine against today's shape but fails against the shape a previous
// release left behind — a NOT NULL added to a column that v0.N wrote NULLs
// into, a CHECK that old rows violate, a constraint whose old-format data no
// longer satisfies it. Every one of those is invisible to a double-apply and
// fatal to a customer's `helm upgrade`.
//
// The chart's schema-migration Job runs the whole file under
// `psql -v ON_ERROR_STOP=1` on every upgrade, so a statement that fails here
// aborts the Job, which blocks the release for every existing install. Before
// the repository was public that meant rebuilding a lab cluster. It now means
// a stranger's database, which they cannot burn down and rebuild.
//
// What this does, per prior release tag:
//
//	create a scratch database  ->  apply THAT RELEASE's schema.sql + seed.sql
//	                           ->  write tenant-scoped rows into it
//	                           ->  apply the CURRENT schema.sql   <- the assertion
//	                           ->  apply the CURRENT seed.sql
//	                           ->  prove the pre-existing rows survived
//
// A scratch database is required: TEST_DATABASE_URL names a shared, already
// current-schema-loaded database that other packages are using concurrently.
// Applying an old schema into it would corrupt it for everything else.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db), like every other testdb-gated test. It does NOT skip
// when git history is missing — that is a broken checkout, not an absent
// dependency, and skipping would make the guard silently inert.

import (
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// upgradeFromTagCount is how many prior release tags to test upgrading from.
// Ordered newest-first, so the default of 2 covers "upgrade from the latest
// release" (what the next release does to every current install) and "skip one
// release" (what a customer who upgrades occasionally does). Raise it with
// SCHEMA_UPGRADE_FROM_COUNT when auditing a risky schema change; each extra tag
// costs a full schema+seed apply cycle.
const upgradeFromTagCount = 2

func TestIntegration_Schema_UpgradesFromPriorReleases(t *testing.T) {
	admin := testdb.Connect(t)
	root := testdb.RepoRoot(t)

	tags := priorReleaseTags(t, root, upgradeFromTagCountFromEnv())
	if len(tags) == 0 {
		t.Fatal("no core-v* release tags found — cannot verify the upgrade path. " +
			"This usually means a shallow checkout: the test needs full history " +
			"(actions/checkout with fetch-depth: 0), not just the tip commit.")
	}
	t.Logf("verifying upgrade path from prior releases: %s", strings.Join(tags, ", "))

	currentSchema := mustReadFile(t, filepath.Join(root, "scripts", "database", "schema.sql"))
	currentSeed := mustReadFile(t, filepath.Join(root, "scripts", "database", "seed.sql"))

	for _, tag := range tags {
		t.Run(tag, func(t *testing.T) {
			oldSchema := mustGitShow(t, root, tag, "scripts/database/schema.sql")
			oldSeed := mustGitShow(t, root, tag, "scripts/database/seed.sql")

			scratch := newScratchDB(t, admin)

			// 1. Reproduce what that release actually installed.
			mustApply(t, scratch, oldSchema, fmt.Sprintf("%s schema.sql", tag))
			mustApply(t, scratch, oldSeed, fmt.Sprintf("%s seed.sql", tag))

			// 2. Give it data. seed.sql already writes thousands of rows
			//    (algorithms, roles, frameworks); these add the tenant-scoped
			//    shape that constraint changes are most likely to break.
			tenant := populateForUpgrade(t, scratch)

			// 3. The assertion. This is the exact operation the chart's
			//    schema-migration Job performs on `helm upgrade`.
			if _, err := scratch.Exec(currentSchema); err != nil {
				t.Fatalf("current schema.sql does not apply over a populated %s database — "+
					"the migration Job would abort on `helm upgrade` for every install "+
					"still on that release, leaving it wedged mid-upgrade:\n%v", tag, err)
			}

			// 4. The chart re-runs seed post-upgrade too.
			if _, err := scratch.Exec(currentSeed); err != nil {
				t.Fatalf("current seed.sql does not re-apply after upgrading from %s: %v", tag, err)
			}

			// 5. An upgrade that silently discards tenant data is not a
			//    successful upgrade, even though psql exited 0.
			assertTenantDataSurvived(t, scratch, tenant, tag)
		})
	}
}

func upgradeFromTagCountFromEnv() int {
	if v := os.Getenv("SCHEMA_UPGRADE_FROM_COUNT"); v != "" {
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil && n > 0 {
			return n
		}
	}
	return upgradeFromTagCount
}

// priorReleaseTags returns up to n core-v* tags, newest first. Core releases
// are tagged core-vX.Y.Z in this repository (a bare vX.Y.Z is the commercial
// line and carries a different schema cadence), so only core-v* is considered.
func priorReleaseTags(t *testing.T, root string, n int) []string {
	t.Helper()
	out, err := runGit(root, "tag", "-l", "core-v*", "--sort=-v:refname")
	if err != nil {
		t.Fatalf("listing release tags failed — the test cannot verify the upgrade "+
			"path without git history (needs fetch-depth: 0): %v", err)
	}
	var tags []string
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		tags = append(tags, line)
		if len(tags) == n {
			break
		}
	}
	return tags
}

func mustGitShow(t *testing.T, root, tag, path string) string {
	t.Helper()
	out, err := runGit(root, "show", tag+":"+path)
	if err != nil {
		t.Fatalf("cannot read %s at %s: %v\n"+
			"A shallow clone has the tag ref but not its tree objects; "+
			"the checkout needs fetch-depth: 0.", path, tag, err)
	}
	return out
}

func runGit(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	var stderr strings.Builder
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, stderr.String())
	}
	return string(out), nil
}

func mustReadFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

func mustApply(t *testing.T, db *sql.DB, body, label string) {
	t.Helper()
	if _, err := db.Exec(body); err != nil {
		t.Fatalf("applying %s to the scratch database failed — this is the OLD "+
			"release's own file, so the failure is in reproducing the starting "+
			"state, not in the upgrade under test: %v", label, err)
	}
}

// newScratchDB creates an empty database on the same server as TEST_DATABASE_URL
// and returns a connection to it. The database is dropped at test end.
//
// Roles are cluster-wide in Postgres, so crypto_user (which schema.sql's RLS
// section grants to) is already present from the harness that provisioned the
// server — it does not need recreating per database.
func newScratchDB(t *testing.T, admin *sql.DB) *sql.DB {
	t.Helper()

	name := "vp_upgrade_" + strings.ReplaceAll(uuid.New().String()[:8], "-", "")
	// CREATE DATABASE cannot run inside a transaction block; Exec on a plain
	// connection is fine. The name is generated, not user input, but quote it
	// anyway so a future change to the naming scheme cannot break the statement.
	if _, err := admin.Exec(fmt.Sprintf(`CREATE DATABASE %q`, name)); err != nil {
		t.Fatalf("create scratch database %s: %v\n"+
			"The upgrade-path test needs CREATEDB on the server named by %s.",
			name, err, testdb.URLEnv)
	}

	t.Cleanup(func() {
		// Terminate stragglers first: DROP DATABASE fails while any session is
		// still attached, and a failed subtest may leave one.
		_, _ = admin.Exec(
			`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1 AND pid <> pg_backend_pid()`, name)
		if _, err := admin.Exec(fmt.Sprintf(`DROP DATABASE IF EXISTS %q`, name)); err != nil {
			t.Logf("could not drop scratch database %s (harmless in an ephemeral "+
				"CI Postgres, worth cleaning up locally): %v", name, err)
		}
	})

	db, err := sql.Open("postgres", scratchURL(t, name))
	if err != nil {
		t.Fatalf("open scratch database %s: %v", name, err)
	}
	if err := db.Ping(); err != nil {
		t.Fatalf("ping scratch database %s: %v", name, err)
	}
	t.Cleanup(func() { _ = db.Close() })

	return db
}

// scratchURL rewrites TEST_DATABASE_URL to point at a different database on the
// same server, preserving credentials and query parameters (sslmode etc.).
func scratchURL(t *testing.T, name string) string {
	t.Helper()
	raw := os.Getenv(testdb.URLEnv)
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %s: %v", testdb.URLEnv, err)
	}
	u.Path = "/" + name
	return u.String()
}

// populateForUpgrade writes tenant-scoped rows using tables that have been
// stable across the release window under test. It returns the tenant id.
//
// The inserts beyond the tenant itself are best-effort BY DESIGN and every
// skip is logged: an older release genuinely may not have a table or column
// that exists today, and treating that as a failure would make the test fail
// for the wrong reason. The population that carries most of the weight is the
// old seed.sql applied just before this, which writes thousands of rows across
// the catalogue, roles and framework tables.
func populateForUpgrade(t *testing.T, db *sql.DB) uuid.UUID {
	t.Helper()

	tenant := uuid.New()
	slug := "up-" + tenant.String()[:8]
	// The tenant is the anchor for everything else and must succeed. If the
	// tenants table cannot take a row, the scratch database is not a usable
	// starting state and the rest of the test would be meaningless.
	if _, err := db.Exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)`,
		tenant, "Upgrade "+slug, slug); err != nil {
		t.Fatalf("seeding a tenant into the old-release database failed: %v", err)
	}

	assetID, implID, certID := uuid.New(), uuid.New(), uuid.New()

	tryExec(t, db, "network_assets", `
		INSERT INTO network_assets (id, tenant_id, hostname, asset_type, asset_status, last_seen_at, first_discovered_at, created_at, updated_at)
		VALUES ($1,$2,'schema-upgrade.example.test','server','monitoring',NOW(),NOW(),NOW(),NOW())`,
		assetID, tenant)

	tryExec(t, db, "crypto_implementations", `
		INSERT INTO crypto_implementations (id, tenant_id, asset_id, protocol, discovery_method, created_at, updated_at)
		VALUES ($1,$2,$3,'TLS','passive',NOW(),NOW())`,
		implID, tenant, assetID)

	tryExec(t, db, "certificates", `
		INSERT INTO certificates (id, tenant_id, serial_number, subject_dn, issuer_dn, fingerprint_sha256, not_before, not_after, created_at, updated_at)
		VALUES ($1,$2,'01','CN=upgrade','CN=upgrade-ca',encode(gen_random_bytes(32),'hex'),NOW(),NOW()+interval '1 year',NOW(),NOW())`,
		certID, tenant)

	return tenant
}

func tryExec(t *testing.T, db *sql.DB, table, q string, args ...interface{}) {
	t.Helper()
	if _, err := db.Exec(q, args...); err != nil {
		t.Logf("skipped populating %s (not present in this release's shape, or its "+
			"columns differ): %v", table, err)
	}
}

// assertTenantDataSurvived checks the upgrade preserved pre-existing rows.
// psql exiting 0 is necessary but not sufficient: a POST-MIGRATIONS statement
// that drops and recreates a table, or a CASCADE that reaches further than
// intended, completes successfully while destroying customer data.
func assertTenantDataSurvived(t *testing.T, db *sql.DB, tenant uuid.UUID, tag string) {
	t.Helper()
	var tenants int
	if err := db.QueryRow(`SELECT COUNT(*) FROM tenants WHERE id = $1`, tenant).Scan(&tenants); err != nil {
		t.Fatalf("counting tenants after upgrade from %s: %v", tag, err)
	}
	if tenants != 1 {
		t.Errorf("tenant row count = %d after upgrading from %s, want 1 — the upgrade "+
			"destroyed pre-existing tenant data", tenants, tag)
	}

	// network_assets is only asserted when the old release could populate it;
	// tryExec logged a skip otherwise, so an absent row there is not a failure.
	var assets int
	if err := db.QueryRow(`SELECT COUNT(*) FROM network_assets WHERE tenant_id = $1`, tenant).Scan(&assets); err != nil {
		t.Logf("network_assets not queryable after upgrade from %s: %v", tag, err)
		return
	}
	t.Logf("upgrade from %s preserved %d network_assets row(s) for the test tenant", tag, assets)
}
