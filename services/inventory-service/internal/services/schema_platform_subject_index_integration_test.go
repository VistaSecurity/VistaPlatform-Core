package services

// Regression guard: uq_user_auth_methods_platform_subject must never abort a
// `helm upgrade`.
//
// The index (one social link per (auth_type, IdP subject)) arrived after
// installs existed, and those installs can already hold the duplicates it
// forbids: sign-up used to ignore deleted accounts, so a deleted account's link
// and a live account's link could share a subject. A bare CREATE UNIQUE INDEX
// fails on that data ("could not create unique index ... is duplicated"), and
// the chart's schema-migration Job runs the whole file under ON_ERROR_STOP=1, so
// that one statement wedged every such install mid-upgrade.
//
// schema.sql now releases contended subjects from deleted accounts first, and
// builds the index inside a DO block that skips it (with a WARNING) when two
// LIVE accounts still share a subject. Each case below stages the data a
// pre-index install can hold on a scratch database with the index dropped,
// applies the CURRENT schema.sql exactly as the Job does, then applies it a
// second time — the Job re-runs the file on every upgrade.
//
// Mutation-tested: deleting the pre-clean UPDATE turns the deleted+live case
// red (index not created); replacing the DO block with the bare CREATE turns
// the two-live case red (the apply itself fails).

import (
	"database/sql"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

const platformSubjectIndex = "uq_user_auth_methods_platform_subject"

// subjectIndexDB is a scratch database whose schema.sql applies are observed:
// every WARNING the server raises during an apply is captured.
type subjectIndexDB struct {
	t      *testing.T
	owner  *sql.DB // the scratch database, as its owner
	hooked *sql.DB // the same database, with a notice handler
	tenant uuid.UUID
	schema string

	mu       sync.Mutex
	warnings []string
}

func newSubjectIndexDB(t *testing.T) *subjectIndexDB {
	t.Helper()
	owner := testdb.ScratchDatabase(t)

	var name string
	if err := owner.QueryRow(`SELECT current_database()`).Scan(&name); err != nil {
		t.Fatalf("current_database: %v", err)
	}
	d := &subjectIndexDB{t: t, owner: owner}
	base, err := pq.NewConnector(scratchURL(t, name))
	if err != nil {
		t.Fatalf("connector for scratch database %s: %v", name, err)
	}
	d.hooked = sql.OpenDB(pq.ConnectorWithNoticeHandler(base, func(n *pq.Error) {
		if n.Severity == "WARNING" {
			d.mu.Lock()
			d.warnings = append(d.warnings, n.Message)
			d.mu.Unlock()
		}
	}))
	d.hooked.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = d.hooked.Close() })

	d.schema = mustReadFile(t, filepath.Join(testdb.RepoRoot(t), "scripts", "database", "schema.sql"))

	// The state every install from before the index is in.
	if _, err := owner.Exec(`DROP INDEX public.` + platformSubjectIndex); err != nil {
		t.Fatalf("drop %s to reproduce a pre-index install: %v", platformSubjectIndex, err)
	}
	// The whole database is dropped at test end, so the tenant needs no
	// cleanup of its own (testdb.NewTenant's would trip over the tenant-SSO
	// provider's non-cascading FK and log noise).
	d.tenant = uuid.New()
	if _, err := owner.Exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $3)`,
		d.tenant, "Subject index "+d.tenant.String()[:8], "subject-index-"+d.tenant.String()[:8]); err != nil {
		t.Fatalf("create tenant: %v", err)
	}
	return d
}

// link creates a tenant user (deleted or live) with one auth method, and
// returns the auth method's id.
func (d *subjectIndexDB) link(label, authType, subject string, deleted bool, ssoProvider *uuid.UUID) uuid.UUID {
	d.t.Helper()
	userID, methodID := uuid.New(), uuid.New()
	var deletedAt interface{}
	if deleted {
		deletedAt = time.Now()
	}
	email := label + "-" + userID.String()[:8] + "@subject-index.example.test"
	if _, err := d.owner.Exec(`
		INSERT INTO users (id, tenant_id, email, first_name, last_name, is_active, email_verified, deleted_at)
		VALUES ($1, $2, $3, 'Subject', 'Index', true, true, $4)`, userID, d.tenant, email, deletedAt); err != nil {
		d.t.Fatalf("%s: create user: %v", label, err)
	}
	var ext interface{}
	if subject != "" {
		ext = subject
	}
	if _, err := d.owner.Exec(`
		INSERT INTO user_auth_methods (id, user_id, auth_type, sso_provider_id, external_user_id, external_email, is_primary)
		VALUES ($1, $2, $3, $4, $5, $6, true)`, methodID, userID, authType, ssoProvider, ext, email); err != nil {
		d.t.Fatalf("%s: create auth method: %v", label, err)
	}
	return methodID
}

// tenantSSOProvider creates a tenant's own SSO provider, whose links are
// outside the index (sso_provider_id IS NOT NULL).
func (d *subjectIndexDB) tenantSSOProvider() uuid.UUID {
	d.t.Helper()
	var id uuid.UUID
	if err := d.owner.QueryRow(`
		INSERT INTO sso_providers (tenant_id, provider_type, provider_name)
		VALUES ($1, 'google', 'Tenant Google') RETURNING id`, d.tenant).Scan(&id); err != nil {
		d.t.Fatalf("insert tenant SSO provider: %v", err)
	}
	return id
}

// apply runs the CURRENT schema.sql once, as the migration Job does, and
// returns the WARNINGs it raised. Only the cross-binary races every schema
// applier in the suite tolerates are retried; a real failure fails the test.
func (d *subjectIndexDB) apply(pass string) []string {
	d.t.Helper()
	const attempts = 3
	for i := 1; ; i++ {
		d.mu.Lock()
		d.warnings = nil
		d.mu.Unlock()
		_, err := d.hooked.Exec(d.schema)
		if err == nil {
			break
		}
		if !testdb.IsTransientRace(err) || i == attempts {
			d.t.Fatalf("%s: schema.sql does not apply over this data — the migration Job would abort "+
				"`helm upgrade` here and leave the install wedged mid-upgrade:\n%v", pass, err)
		}
		d.t.Logf("%s: transient cross-binary race (attempt %d/%d), retrying: %v", pass, i, attempts, err)
		time.Sleep(200 * time.Millisecond)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	var mine []string
	for _, w := range d.warnings {
		if strings.Contains(w, platformSubjectIndex) {
			mine = append(mine, w)
		}
	}
	return mine
}

func (d *subjectIndexDB) indexExists() bool {
	d.t.Helper()
	var exists bool
	if err := d.owner.QueryRow(`SELECT to_regclass('public.` + platformSubjectIndex + `') IS NOT NULL`).Scan(&exists); err != nil {
		d.t.Fatalf("look up %s: %v", platformSubjectIndex, err)
	}
	return exists
}

func (d *subjectIndexDB) subject(methodID uuid.UUID) sql.NullString {
	d.t.Helper()
	var s sql.NullString
	if err := d.owner.QueryRow(`SELECT external_user_id FROM user_auth_methods WHERE id = $1`, methodID).Scan(&s); err != nil {
		d.t.Fatalf("read subject of %s: %v", methodID, err)
	}
	return s
}

// expectSubject asserts a link still (want != "") or no longer (want == "")
// claims a subject.
func (d *subjectIndexDB) expectSubject(pass, label string, methodID uuid.UUID, want string) {
	d.t.Helper()
	got := d.subject(methodID)
	if want == "" {
		if got.Valid {
			d.t.Errorf("%s: %s still claims %q; want it released (NULL)", pass, label, got.String)
		}
		return
	}
	if !got.Valid || got.String != want {
		d.t.Errorf("%s: %s claims %v; want %q untouched", pass, label, got, want)
	}
}

// bothPasses runs the apply twice — the first upgrade, and every later one —
// and runs check after each.
func (d *subjectIndexDB) bothPasses(check func(pass string, warnings []string)) {
	d.t.Helper()
	for _, pass := range []string{"first apply", "second apply"} {
		check(pass, d.apply(pass))
	}
}

func TestIntegration_Schema_PlatformSubjectIndex_ReleasesDeletedHolders(t *testing.T) {
	d := newSubjectIndexDB(t)
	sub := "subject-" + uuid.NewString()

	// (a) The reported case: a deleted account and a live one on one subject.
	gone := d.link("gone", "google", sub, true, nil)
	live := d.link("live", "google", sub, false, nil)
	// Two deleted accounts on one subject collide in the index too.
	twin := "twin-" + uuid.NewString()
	goneA := d.link("gone-a", "google", twin, true, nil)
	goneB := d.link("gone-b", "google", twin, true, nil)
	// Witnesses the release must NOT touch: an uncontended deleted link (it
	// keeps its subject, as at runtime, until someone reclaims it), and a
	// deleted account's link at ANOTHER provider type and a deleted TENANT-SSO
	// link on the same subject string, both outside the contended key.
	lone := "lone-" + uuid.NewString()
	goneLone := d.link("gone-lone", "google", lone, true, nil)
	goneMicrosoft := d.link("gone-microsoft", "microsoft", sub, true, nil)
	provider := d.tenantSSOProvider()
	goneTenantSSO := d.link("gone-tenant-sso", "google", sub, true, &provider)

	d.bothPasses(func(pass string, warnings []string) {
		if !d.indexExists() {
			t.Fatalf("%s: %s was not created; the deleted holders were not released (warnings: %v)", pass, platformSubjectIndex, warnings)
		}
		if len(warnings) != 0 {
			t.Errorf("%s: unexpected warnings %v", pass, warnings)
		}
		d.expectSubject(pass, "the deleted account's link", gone, "")
		d.expectSubject(pass, "the live account's link", live, sub)
		d.expectSubject(pass, "deleted twin A", goneA, "")
		d.expectSubject(pass, "deleted twin B", goneB, "")
		d.expectSubject(pass, "an uncontended deleted link", goneLone, lone)
		d.expectSubject(pass, "a deleted microsoft link on the same subject string", goneMicrosoft, sub)
		d.expectSubject(pass, "a deleted tenant-SSO link on the same subject", goneTenantSSO, sub)
	})
}

func TestIntegration_Schema_PlatformSubjectIndex_TwoLiveAccountsSkipIndex(t *testing.T) {
	d := newSubjectIndexDB(t)
	sub := "subject-" + uuid.NewString()

	// (b) Two LIVE accounts on one subject: only a race or a hand edit gets
	// here, and the migration must not pick a winner — nor abort.
	a := d.link("live-a", "google", sub, false, nil)
	b := d.link("live-b", "google", sub, false, nil)

	d.bothPasses(func(pass string, warnings []string) {
		if d.indexExists() {
			t.Fatalf("%s: %s exists over two live accounts on one subject", pass, platformSubjectIndex)
		}
		if len(warnings) != 1 || !strings.Contains(warnings[0], "NOT created: 1 social sign-in") ||
			!strings.Contains(warnings[0], "operator") {
			t.Errorf("%s: warnings = %v; want one naming the index, the conflict count (1) and the operator step", pass, warnings)
		}
		d.expectSubject(pass, "live account A", a, sub)
		d.expectSubject(pass, "live account B", b, sub)
	})

	// Once an operator resolves the conflict, the next apply builds the index.
	if _, err := d.owner.Exec(`UPDATE user_auth_methods SET external_user_id = NULL WHERE id = $1`, b); err != nil {
		t.Fatal(err)
	}
	if w := d.apply("apply after resolution"); len(w) != 0 || !d.indexExists() {
		t.Fatalf("after resolving the conflict: index exists = %v, warnings = %v; want it created silently", d.indexExists(), w)
	}
}

func TestIntegration_Schema_PlatformSubjectIndex_CleanDataCreatesIndex(t *testing.T) {
	d := newSubjectIndexDB(t)

	// (c) Nothing collides on the index key. Rows outside the key may repeat:
	// legacy links with no subject (NULL and ''), and one subject held by two
	// live accounts through a tenant's own SSO provider.
	one := "one-" + uuid.NewString()
	live := d.link("live", "google", one, false, nil)
	d.link("legacy-null-a", "google", "", false, nil)
	d.link("legacy-null-b", "google", "", false, nil)
	emptyA := d.link("legacy-empty-a", "google", "placeholder-a-"+uuid.NewString(), false, nil)
	emptyB := d.link("legacy-empty-b", "google", "placeholder-b-"+uuid.NewString(), false, nil)
	if _, err := d.owner.Exec(`UPDATE user_auth_methods SET external_user_id = '' WHERE id IN ($1, $2)`, emptyA, emptyB); err != nil {
		t.Fatal(err)
	}
	provider := d.tenantSSOProvider()
	shared := "tenant-sso-" + uuid.NewString()
	ssoA := d.link("tenant-sso-a", "google", shared, false, &provider)
	ssoB := d.link("tenant-sso-b", "google", shared, false, &provider)

	d.bothPasses(func(pass string, warnings []string) {
		if !d.indexExists() {
			t.Fatalf("%s: %s was not created over clean data (warnings: %v)", pass, platformSubjectIndex, warnings)
		}
		if len(warnings) != 0 {
			t.Errorf("%s: unexpected warnings %v", pass, warnings)
		}
		d.expectSubject(pass, "the live link", live, one)
		d.expectSubject(pass, "tenant-SSO link A", ssoA, shared)
		d.expectSubject(pass, "tenant-SSO link B", ssoB, shared)
	})
}
