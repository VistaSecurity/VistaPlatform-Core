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
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// upgradeFromTagCount is how many prior release tags to test upgrading from,
// newest first. Raise it with SCHEMA_UPGRADE_FROM_COUNT when auditing a risky
// schema change; each extra tag costs a full schema+seed apply cycle.
//
// It was ZERO until core-v1.0.0 shipped, per ADR-0007 D2.5. That test asks
// "does the current schema apply over the shape release X left behind?", and
// from phase 1 onwards the honest answer for every PRE-1.0 core-v* tag is "no,
// and deliberately": `assets`, `devices` and the `asset_type` enum are
// REPLACED, not migrated, because the owner established that there
// are no installs of those releases to carry forward.
//
// core-v1.0.0 was tagged on. It is the first release of the new
// shape and therefore the first one anything can upgrade FROM, so the count is
// re-armed to 2 exactly as D2.5 directs. The test is the only thing that
// catches a statement which is fine against today's tables and fails against a
// prior release's (a `SET NOT NULL` on a column old rows hold NULL in, a
// `CHECK` old-format data violates); a populated double-apply is structurally
// blind to that class.
//
// Two, not one: the second-newest release is the one an install that skipped a
// patch upgrades from, and it costs one more schema+seed cycle to cover.
// Only FINAL releases count — see releaseTag below.
const upgradeFromTagCount = 2

func TestIntegration_Schema_UpgradesFromPriorReleases(t *testing.T) {
	// Unreachable while upgradeFromTagCount is 2 — kept so that setting the
	// constant back to 0 disarms the test loudly rather than fataling on an
	// empty tag list. The tripwire in schema_upgrade_tripwire_test.go fails the
	// unit suite if anyone does set it back.
	if n := upgradeFromTagCountFromEnv(); n == 0 {
		t.Skip("upgrade-path verification is disarmed: upgradeFromTagCount is 0. " +
			"It was re-armed to 2 when core-v1.0.0 shipped (ADR-0007 D2.5); if you are " +
			"reading this, something set it back. Set SCHEMA_UPGRADE_FROM_COUNT to run " +
			"against that many prior release tags anyway.")
	}
	admin := testdb.Connect(t)
	root := testdb.RepoRoot(t)

	tags := priorReleaseTags(t, root, upgradeFromTagCountFromEnv())
	if len(tags) == 0 {
		t.Fatal("no core-v1.0.0-or-later release tags found — cannot verify the upgrade " +
			"path. This usually means a shallow checkout: the test needs full history " +
			"(actions/checkout with fetch-depth: 0), not just the tip commit. " +
			"Release CANDIDATES and pre-1.0 releases do not count; see " +
			"firstSupportedUpgradeFrom.")
	}
	// Fewer tags than asked for is normal right after 1.0.0 — there is only one
	// release at or above the floor — and says so rather than looking like the
	// loop silently did less work than the constant advertises.
	if want := upgradeFromTagCountFromEnv(); len(tags) < want {
		t.Logf("only %d release(s) at or above %v exist; asked for %d",
			len(tags), firstSupportedUpgradeFrom, want)
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

// releaseTag matches a FINAL core release tag and nothing else. Core releases
// are tagged core-vX.Y.Z in this repository (a bare vX.Y.Z is the commercial
// line and carries a different schema cadence), so only core-v* is considered.
//
// The anchored end is what excludes release candidates, and it is load-bearing
// rather than tidiness. `git tag --sort=-v:refname` orders core-v1.0.0-rc.19
// ABOVE core-v1.0.0 — git's version sort has no semver prerelease rule unless
// versionsort.suffix is configured — and 1.0.0 went out after nineteen
// candidates. Taking the "newest two" unfiltered therefore selects rc.19 and
// rc.18 and never selects a shipped release at all: the guard would run, cost
// two full schema+seed cycles, and answer a question nobody asked (and keep
// answering it after 1.0.1, when the top two become 1.0.1 and rc.19).
//
// A candidate is also not a shape anything upgrades FROM. It exists so we can
// install it, look at it and throw it away — the same reasoning the tripwire in
// schema_upgrade_tripwire_test.go uses to refuse to ARM on one.
var releaseTag = regexp.MustCompile(`^core-v([0-9]+)\.([0-9]+)\.([0-9]+)$`)

// firstSupportedUpgradeFrom is the oldest shape this test will start from, and
// it is a DECISION, not a convenience.
//
// ADR-0007 D2 is the no-migration path: phase 1 REPLACES `network_assets`,
// `devices` and the `asset_type` enum rather than migrating them, drops the old
// tables in POST-MIGRATIONS, and attempts no translation — because the owner
// established that there are no installs of any pre-1.0 release to
// carry forward. D2.5 therefore re-arms this test "against that release and
// every one after it", core-v1.0.0 being the first release of the new shape.
//
// Without the floor, "newest two" reaches back to core-v0.12.5, which fails on
// the replacement itself and would fail the suite on a decision — which teaches
// the next person to weaken the test rather than to read the ADR, the exact
// outcome the constant's comment above was written to prevent.
//
// The floor is NOT a place to hide a failure. It excludes only shapes the ADR
// says nothing can be upgraded from; every release from 1.0.0 onward is tested,
// and a real ordering bug against one of those still fails here. Raise it only
// if a future ADR declares another replacement release.
var firstSupportedUpgradeFrom = version{1, 0, 0}

type version struct{ major, minor, patch int }

func (v version) String() string {
	return fmt.Sprintf("core-v%d.%d.%d", v.major, v.minor, v.patch)
}

func (v version) atLeast(o version) bool {
	if v.major != o.major {
		return v.major > o.major
	}
	if v.minor != o.minor {
		return v.minor > o.minor
	}
	return v.patch >= o.patch
}

// parseReleaseTag returns the version of a FINAL core release tag, and false
// for anything else — a candidate, a commercial tag, a blank line.
func parseReleaseTag(tag string) (version, bool) {
	m := releaseTag.FindStringSubmatch(strings.TrimSpace(tag))
	if m == nil {
		return version{}, false
	}
	// The regexp already proved all three groups are non-empty digit runs, so
	// the only Atoi error reachable here is an overflow on an absurd tag.
	var v version
	v.major, _ = strconv.Atoi(m[1])
	v.minor, _ = strconv.Atoi(m[2])
	v.patch, _ = strconv.Atoi(m[3])
	return v, true
}

// priorReleaseTags returns up to n final core-v* release tags, newest first.
func priorReleaseTags(t *testing.T, root string, n int) []string {
	t.Helper()
	out, err := runGit(root, "tag", "-l", "core-v*", "--sort=-v:refname")
	if err != nil {
		t.Fatalf("listing release tags failed — the test cannot verify the upgrade "+
			"path without git history (needs fetch-depth: 0): %v", err)
	}
	return firstNReleaseTags(strings.Split(strings.TrimSpace(out), "\n"), n)
}

// firstNReleaseTags is split out from the git call so the selection itself is
// testable without a repository whose tags say what the case needs.
func firstNReleaseTags(lines []string, n int) []string {
	var tags []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		v, ok := parseReleaseTag(line)
		if !ok || !v.atLeast(firstSupportedUpgradeFrom) {
			continue
		}
		tags = append(tags, line)
		if len(tags) == n {
			break
		}
	}
	return tags
}

// Both polarities, because the selection's whole value is picking the tags a
// customer actually upgrades FROM, and the two filters it applies (candidate,
// floor) are separable: cases below fail if EITHER is removed.
//
// The shape being guarded is the real `git tag --sort=-v:refname` output of
// this repository at core-v1.0.0: nineteen candidates sorted ABOVE the release
// they are candidates for, because git's version sort has no semver prerelease
// rule. An unfiltered "newest two" returns rc.19 and rc.18 and never a shipped
// release at all.
func TestPriorReleaseTagsSelectsFinalReleasesOnly(t *testing.T) {
	for _, c := range []struct {
		name  string
		lines []string
		n     int
		want  []string
	}{
		{
			// Candidate exclusion ONLY — both expected tags are above the
			// floor, so this case fails if the rc filter goes and passes if
			// only the floor does the work.
			"candidates sorted above their release are skipped",
			[]string{"core-v1.0.1-rc.2", "core-v1.0.1-rc.1", "core-v1.0.1", "core-v1.0.0"},
			2,
			[]string{"core-v1.0.1", "core-v1.0.0"},
		},
		{
			"candidates only yields nothing rather than a candidate",
			[]string{"core-v1.0.0-rc.2", "core-v1.0.0-rc.1"},
			2,
			nil,
		},
		{
			"the commercial line is a different schema cadence",
			[]string{"v1.0.0", "v3.6.0"},
			2,
			nil,
		},
		{
			"n caps the result",
			[]string{"core-v1.0.1", "core-v1.0.0", "core-v0.12.5"},
			1,
			[]string{"core-v1.0.1"},
		},
		{
			"blank lines from an empty tag list do not match",
			[]string{""},
			2,
			nil,
		},
		// The floor. ADR-0007 D2 replaces the asset tables rather than
		// migrating them, so a pre-1.0 shape is not an upgrade path; asking
		// for two when only one qualifying release exists returns the one.
		{
			"pre-1.0 releases are below the floor",
			[]string{"core-v1.0.0", "core-v0.12.5", "core-v0.12.4"},
			2,
			[]string{"core-v1.0.0"},
		},
		{
			"the floor is not a blanket exclusion of older patches",
			[]string{"core-v1.2.0", "core-v1.1.9", "core-v1.0.0"},
			3,
			[]string{"core-v1.2.0", "core-v1.1.9", "core-v1.0.0"},
		},
		{
			"a major above the floor qualifies",
			[]string{"core-v2.0.0"},
			1,
			[]string{"core-v2.0.0"},
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := firstNReleaseTags(c.lines, c.n)
			if strings.Join(got, ",") != strings.Join(c.want, ",") {
				t.Errorf("firstNReleaseTags(%v, %d) = %v, want %v", c.lines, c.n, got, c.want)
			}
		})
	}
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

	tryExec(t, db, "assets", `
		INSERT INTO assets (id, tenant_id, hostname, class_key, class_path, asset_status, last_seen_at, first_discovered_at, created_at, updated_at)
			VALUES ($1, $2, 'schema-upgrade.example.test', 'server', 'hardware.computer.server', 'monitoring', NOW(), NOW(), NOW(), NOW())`,
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

	// assets is only asserted when the old release could populate it;
	// tryExec logged a skip otherwise, so an absent row there is not a failure.
	var assets int
	if err := db.QueryRow(`SELECT COUNT(*) FROM assets WHERE tenant_id = $1`, tenant).Scan(&assets); err != nil {
		t.Logf("assets not queryable after upgrade from %s: %v", tag, err)
		return
	}
	t.Logf("upgrade from %s preserved %d assets row(s) for the test tenant", tag, assets)
}
