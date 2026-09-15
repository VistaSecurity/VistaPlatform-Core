package services

// The org-wide Findings list, across producers.
//
// ListFindings carried `complianceProducerScope` from the one-table move
// (workstream 3.1) until the `eol` and `vulnerability` producers shipped
// (3.3/3.4 part 2). At that point Risk & Compliance → Findings would have been
// the ONE surface in the product that silently omitted them: the asset page's
// Findings tab, the query language's `finding:(…)` and the `has_findings` facet
// all showed them, and a triage page that quietly lists a subset is the failure
// shape this repository keeps re-finding.
//
// What these tests pin, and why a unit test cannot:
//
//  1. a non-compliance finding APPEARS on the list, with no framework activated
//     — the licence gate asks about a CONTROL and these rows have none;
//  2. the per-producer counts and the list describe the SAME set;
//  3. the `producer` filter narrows to exactly one producer;
//  4. a `software_install` subject resolves to the HOST it is installed on, so
//     the row has a hostname to render and an asset id to link at;
//  5. control_id scans through a NullUUID — a NULL in a `uuid.UUID` is a scan
//     error, and the handler reports a scan error as a 500.
//
// Every one of those lives in one SQL statement. They skip unless
// TEST_DATABASE_URL is set; `make test-integration-db` runs them.

import (
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	sharedfindings "github.com/vistasecurity/vistaplatform/shared/findings"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// insertAsset writes one asset and returns its id.
func insertAsset(t *testing.T, db *sqlx.DB, tenant uuid.UUID, hostname string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO assets (id, tenant_id, hostname, display_name, asset_status, class_key, class_path, environment)
		VALUES ($1, $2, $3, $3, 'monitoring', 'server', 'server', 'production')`, id, tenant, hostname); err != nil {
		t.Fatalf("insert asset: %v", err)
	}
	return id
}

// insertInstall writes a software product and an install of it on assetID.
func insertInstall(t *testing.T, db *sqlx.DB, tenant, assetID uuid.UUID, name, version string) uuid.UUID {
	t.Helper()
	productID, installID := uuid.New(), uuid.New()
	if _, err := db.Exec(`
		INSERT INTO software_products (id, tenant_id, name, version)
		VALUES ($1, $2, $3, $4)`, productID, tenant, name, version); err != nil {
		t.Fatalf("insert software_product: %v", err)
	}
	if _, err := db.Exec(`
		INSERT INTO software_installs (id, tenant_id, asset_id, product_id, status)
		VALUES ($1, $2, $3, $4, 'active')`, installID, tenant, assetID, productID); err != nil {
		t.Fatalf("insert software_install: %v", err)
	}
	return installID
}

// insertFindingRow writes one finding straight to the table — no producer
// package, because this is a test of the READ and building it through a writer
// would couple it to that writer's rules.
func insertFindingRow(t *testing.T, db *sqlx.DB, tenant uuid.UUID, producerKey, kind, subjectType string, subjectID uuid.UUID, severity string, score int, summary string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO findings (id, tenant_id, producer, kind, subject_type, subject_id,
		                      control_id, severity, score, summary, evidence,
		                      detection_state, workflow_status)
		VALUES ($1, $2, $3, $4, $5, $6, NULL, $7, $8, $9, '{}'::jsonb, 'ACTIVE', 'NEW')`,
		id, tenant, producerKey, kind, subjectType, subjectID, severity, score, summary); err != nil {
		t.Fatalf("insert finding (%s/%s): %v", producerKey, kind, err)
	}
	return id
}

func TestIntegration_ListFindings_ReturnsEveryProducer(t *testing.T) {
	svc, db, tenant := newFindingsServiceIT(t)

	asset := insertAsset(t, db, tenant, "web-01.example.com")
	install := insertInstall(t, db, tenant, asset, "openssl", "1.1.1")

	eolID := insertFindingRow(t, db, tenant, "eol", "software_end_of_life",
		"software_install", install, "medium", 50, "openssl 1.1.1 is end of life")
	vulnID := insertFindingRow(t, db, tenant, "vulnerability", "known_vulnerability",
		"software_install", install, "critical", 98, "openssl 1.1.1 is affected by CVE-2026-1000")
	osID := insertFindingRow(t, db, tenant, "eol", "os_end_of_life",
		"asset", asset, "high", 70, "web-01 runs an end-of-life operating system")

	// NO framework is activated for this tenant. That is the point: the
	// licence gate asks whether a finding's CONTROL belongs to an activated
	// framework, and these rows have no control. Applied unconditionally it
	// would hide all three behind a subscription nobody needs to buy.
	got, total, err := svc.ListFindings(tenant, FindingListFilters{}, 1, 50)
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	if total != 3 {
		t.Fatalf("total = %d, want 3 — the org-wide list is scoped to one producer again", total)
	}
	byID := map[uuid.UUID]int{}
	for i, f := range got {
		byID[f.ID] = i
	}
	for _, want := range []uuid.UUID{eolID, vulnID, osID} {
		if _, ok := byID[want]; !ok {
			t.Errorf("finding %s is missing from the list", want)
		}
	}

	// control_id came back through a NullUUID rather than blowing up the scan.
	for _, f := range got {
		if f.ControlID != uuid.Nil {
			t.Errorf("%s/%s carries control_id %s; only the compliance producer may have one", f.Producer, f.Kind, f.ControlID)
		}
	}

	// A software_install subject resolves to its HOST — the row needs a
	// hostname to render and an asset id to link at, and the subject id names a
	// package row that has no asset page.
	eol := got[byID[eolID]]
	if eol.Asset == nil {
		t.Fatalf("the software_install finding resolved to no asset; the row would render a bare uuid")
	}
	if eol.Asset.ID != asset {
		t.Errorf("joined asset id = %s, want the HOST %s (not the install %s)", eol.Asset.ID, asset, install)
	}
	if eol.Asset.Hostname == nil || *eol.Asset.Hostname != "web-01.example.com" {
		t.Errorf("joined hostname = %v, want web-01.example.com", eol.Asset.Hostname)
	}
}

func TestIntegration_ListFindings_ProducerFilterAndCountsAgree(t *testing.T) {
	svc, db, tenant := newFindingsServiceIT(t)

	asset := insertAsset(t, db, tenant, "db-01.example.com")
	install := insertInstall(t, db, tenant, asset, "postgresql", "12.0")
	insertFindingRow(t, db, tenant, "eol", "software_end_of_life", "software_install", install, "medium", 50, "postgresql 12 is end of life")
	insertFindingRow(t, db, tenant, "eol", "os_end_of_life", "asset", asset, "high", 70, "db-01 runs an end-of-life operating system")
	insertFindingRow(t, db, tenant, "vulnerability", "known_vulnerability", "software_install", install, "critical", 98, "postgresql 12 is affected by CVE-2026-2000")

	counts, err := svc.CountFindingsByProducer(tenant, FindingListFilters{})
	if err != nil {
		t.Fatalf("CountFindingsByProducer: %v", err)
	}
	if counts["eol"] != 2 || counts["vulnerability"] != 1 {
		t.Fatalf("counts = %v, want eol:2 vulnerability:1", counts)
	}
	if _, present := counts["compliance"]; present {
		t.Errorf("counts name a producer with no findings: %v", counts)
	}

	// The filtered list has to match the count the facet showed. They are built
	// from one WHERE for exactly this reason — the `has_findings` facet was
	// withdrawn in Gate 1 because a number and the list it led to were two
	// hand-written expressions over two tables.
	for producerKey, want := range map[string]int{"eol": 2, "vulnerability": 1} {
		rows, total, err := svc.ListFindings(tenant, FindingListFilters{Producer: producerKey}, 1, 50)
		if err != nil {
			t.Fatalf("ListFindings(%s): %v", producerKey, err)
		}
		if total != want || len(rows) != want {
			t.Errorf("producer=%s: list has %d rows (total %d) but the facet said %d", producerKey, len(rows), total, want)
		}
		for _, f := range rows {
			if f.Producer != producerKey {
				t.Errorf("producer=%s filter returned a %s finding", producerKey, f.Producer)
			}
		}
	}

	// The counts do NOT narrow by producer: every facet has to show its own
	// number while one of them is active, or each chip reports only itself.
	filteredCounts, err := svc.CountFindingsByProducer(tenant, FindingListFilters{Producer: "eol"})
	if err != nil {
		t.Fatalf("CountFindingsByProducer(eol): %v", err)
	}
	if filteredCounts["vulnerability"] != 1 {
		t.Errorf("with the eol facet active the vulnerability count is %d, want 1 — the other facets went blank", filteredCounts["vulnerability"])
	}
}

// A compliance finding whose framework the tenant has NOT activated stays
// hidden. The widening removed the gate from non-compliance rows only; removing
// it outright would leak every published framework's findings into the page.
func TestIntegration_ListFindings_UnactivatedComplianceFindingStaysHidden(t *testing.T) {
	svc, db, tenant := newFindingsServiceIT(t)

	asset := insertAsset(t, db, tenant, "app-01.example.com")
	insertFindingRow(t, db, tenant, "eol", "os_end_of_life", "asset", asset, "high", 70, "app-01 runs an end-of-life operating system")

	// A compliance finding pointing at a control that belongs to no framework
	// this tenant activated.
	id := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO findings (id, tenant_id, producer, kind, subject_type, subject_id,
		                      control_id, severity, score, summary, evidence,
		                      detection_state, workflow_status)
		VALUES ($1, $2, 'compliance', 'control_noncompliant', 'asset', $3, $4,
		        'high', 0, 'unactivated framework control failed', '{}'::jsonb, 'ACTIVE', 'NEW')`,
		id, tenant, asset, uuid.New()); err != nil {
		t.Fatalf("insert compliance finding: %v", err)
	}

	got, total, err := svc.ListFindings(tenant, FindingListFilters{}, 1, 50)
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	if total != 1 {
		t.Fatalf("total = %d, want 1 (the eol finding only) — the framework activation gate stopped applying to compliance rows", total)
	}
	if got[0].Producer != "eol" {
		t.Errorf("listed %s/%s, want the eol finding", got[0].Producer, got[0].Kind)
	}
	if counts, err := svc.CountFindingsByProducer(tenant, FindingListFilters{}); err != nil {
		t.Fatalf("CountFindingsByProducer: %v", err)
	} else if counts["compliance"] != 0 {
		t.Errorf("the facet counts %d unactivated compliance findings the list does not show", counts["compliance"])
	}
}

var _ = testdb.NewTenant

// The subject filter — the SQL half (workstream 3.8).
//
// The software surfaces render "3 vulnerabilities" and "End of life" from a
// per-install rollup and link to this list narrowed to that install. If the
// filter did not reach the WHERE, the link would open the whole tenant's
// findings stream while claiming to show one package's — and the handler test
// cannot see that, because it stubs the service.
//
// The second half of the test is the one that matters: it asserts the filter
// narrows to the ONE install rather than merely returning something, by putting
// a second install with its own findings beside it.
func TestIntegration_ListFindings_SubjectFilterNarrowsToOneInstall(t *testing.T) {
	svc, db, tenant := newFindingsServiceIT(t)

	asset := insertAsset(t, db, tenant, "app-01.example.com")
	openssl := insertInstall(t, db, tenant, asset, "openssl", "1.1.1")
	zlib := insertInstall(t, db, tenant, asset, "zlib", "1.2.11")

	opensslEOL := insertFindingRow(t, db, tenant, "eol", "software_end_of_life",
		"software_install", openssl, "medium", 50, "openssl 1.1.1 is end of life")
	opensslVuln := insertFindingRow(t, db, tenant, "vulnerability", "known_vulnerability",
		"software_install", openssl, "critical", 98, "openssl 1.1.1 is affected by CVE-2026-1000")
	insertFindingRow(t, db, tenant, "vulnerability", "known_vulnerability",
		"software_install", zlib, "high", 78, "zlib 1.2.11 is affected by CVE-2026-2000")
	insertFindingRow(t, db, tenant, "eol", "os_end_of_life",
		"asset", asset, "high", 70, "app-01 runs an end-of-life operating system")

	got, total, err := svc.ListFindings(tenant, FindingListFilters{
		SubjectType: "software_install", SubjectID: &openssl,
	}, 1, 50)
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	if total != 2 {
		t.Fatalf("total = %d, want 2 — the filter selected %d rows, so the link and the number it was clicked from disagree", total, total)
	}
	seen := map[uuid.UUID]bool{}
	for _, f := range got {
		seen[f.ID] = true
		if f.SubjectID != openssl {
			t.Errorf("finding %s has subject %s, want only %s", f.ID, f.SubjectID, openssl)
		}
	}
	if !seen[opensslEOL] || !seen[opensslVuln] {
		t.Errorf("the filtered list is missing one of this install's own findings: %v", seen)
	}

	// The counts are built from the SAME WHERE, so they have to narrow too —
	// otherwise the producer chips on a subject-filtered page would count the
	// whole tenant.
	counts, err := svc.CountFindingsByProducer(tenant, FindingListFilters{
		SubjectType: "software_install", SubjectID: &openssl,
	})
	if err != nil {
		t.Fatalf("CountFindingsByProducer: %v", err)
	}
	if counts["eol"] != 1 || counts["vulnerability"] != 1 {
		t.Errorf("counts = %v, want eol:1 vulnerability:1 for this install alone", counts)
	}
}

// The other polarity, and the one that would have shipped quietly: with the
// filter OFF the list must still be the whole tenant's. A WHERE that always
// applied — `subject_id = $n` with a zero uuid, say — would empty every
// unfiltered page in the product.
func TestIntegration_ListFindings_NoSubjectFilterIsEveryFinding(t *testing.T) {
	svc, db, tenant := newFindingsServiceIT(t)

	asset := insertAsset(t, db, tenant, "app-02.example.com")
	install := insertInstall(t, db, tenant, asset, "nginx", "1.18.0")
	insertFindingRow(t, db, tenant, "eol", "software_end_of_life", "software_install", install, "medium", 50, "nginx 1.18 is end of life")
	insertFindingRow(t, db, tenant, "eol", "os_end_of_life", "asset", asset, "high", 70, "app-02 runs an end-of-life operating system")

	_, total, err := svc.ListFindings(tenant, FindingListFilters{}, 1, 50)
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	if total != 2 {
		t.Fatalf("total = %d, want 2 — an unasked-for subject filter is being applied", total)
	}
}

// A subject type with no id (and vice versa) must not narrow. The handler
// refuses that combination before it gets here, but the service is called from
// the MCP tools and from jobs too, and a half-filter that silently matched
// every uuid of that type would be a different answer from the one asked for.
func TestIntegration_ListFindings_HalfSubjectFilterIsIgnored(t *testing.T) {
	svc, db, tenant := newFindingsServiceIT(t)

	asset := insertAsset(t, db, tenant, "app-03.example.com")
	install := insertInstall(t, db, tenant, asset, "curl", "7.68.0")
	insertFindingRow(t, db, tenant, "eol", "software_end_of_life", "software_install", install, "medium", 50, "curl 7.68 is end of life")
	insertFindingRow(t, db, tenant, "eol", "os_end_of_life", "asset", asset, "high", 70, "app-03 runs an end-of-life operating system")

	_, total, err := svc.ListFindings(tenant, FindingListFilters{SubjectType: "software_install"}, 1, 50)
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	if total != 2 {
		t.Errorf("total = %d, want 2 — a subject TYPE with no id narrowed the list", total)
	}

	_, total, err = svc.ListFindings(tenant, FindingListFilters{SubjectID: &install}, 1, 50)
	if err != nil {
		t.Fatalf("ListFindings: %v", err)
	}
	if total != 2 {
		t.Errorf("total = %d, want 2 — a subject ID with no type narrowed the list", total)
	}
}

// The Dashboard's "Critical findings" tile counts EVERY producer.
//
// /findings/statistics carries two severity rollups over the one findings
// table: severity_counts (the compliance producer — failed controls on
// activated frameworks) and all_producer_severity_counts (everything). The tile
// read the first while labelling itself "across all assets", so a tenant whose
// only Criticals were end-of-life or vulnerability findings read "0 critical
// findings" on the Dashboard and saw them on Risk & Compliance → Findings: the
// H-2 divergence, one producer after it was first closed.
//
// A unit test cannot reach this — the two rollups differ only in a WHERE
// clause, and what makes them differ is rows of other producers existing.
//
// Both directions, and the third thing that is easy to lose while widening a
// scope: the framework LICENCE gate still applies to compliance rows in the
// all-producer rollup. Widening "every producer" into "every framework too"
// would put an unactivated framework's Criticals back on the Dashboard, which
// is the bug licensedFindingScopeSQL was written for.
func TestIntegration_GetFindingStatistics_CountsEveryProducer(t *testing.T) {
	svc, db, tenant := newFindingsServiceIT(t)

	// One compliance Critical on an ACTIVATED framework — in both rollups.
	_, newLicensedControl := seedPublishedFramework(t, db, tenant, "stats-all-lic", true)
	licControl, licAsset := newLicensedControl("Critical"), uuid.New()
	licFinding := activeViolation(licControl, licAsset)
	licFinding.Severity = "Critical"
	mustUpsert(t, svc, tenant, licControl, licAsset, licFinding, "ACTIVE")

	// One compliance Critical on a framework the tenant has NOT activated — in
	// neither rollup.
	_, newUnlicensedControl := seedPublishedFramework(t, db, tenant, "stats-all-unlic", false)
	unlicControl, unlicAsset := newUnlicensedControl("Critical"), uuid.New()
	unlicFinding := activeViolation(unlicControl, unlicAsset)
	unlicFinding.Severity = "Critical"
	mustUpsert(t, svc, tenant, unlicControl, unlicAsset, unlicFinding, "ACTIVE")

	// Two non-compliance Criticals and one non-compliance High. No framework is
	// activated for these and none can be: they have no control at all.
	asset := insertAsset(t, db, tenant, "web-02.example.com")
	install := insertInstall(t, db, tenant, asset, "openssl", "1.1.1")
	insertFindingRow(t, db, tenant, "vulnerability", "known_vulnerability",
		"software_install", install, "critical", 98, "openssl 1.1.1 is affected by CVE-2026-1000")
	insertFindingRow(t, db, tenant, "eol", "os_end_of_life",
		"asset", asset, "critical", 95, "web-02 runs an end-of-life operating system")
	insertFindingRow(t, db, tenant, "eol", "software_end_of_life",
		"software_install", install, "high", 70, "openssl 1.1.1 is end of life")

	stats, err := svc.GetFindingStatistics(tenant)
	if err != nil {
		t.Fatalf("GetFindingStatistics: %v", err)
	}

	if stats.SeverityCounts.Critical != 1 {
		t.Errorf("severity_counts.critical = %d, want 1 — this rollup is the COMPLIANCE producer on "+
			"activated frameworks only, and the surfaces that are about framework compliance read it",
			stats.SeverityCounts.Critical)
	}
	if stats.AllProducerSeverityCounts.Critical != 3 {
		t.Errorf("all_producer_severity_counts.critical = %d, want 3 (1 compliance + 1 vulnerability + "+
			"1 eol) — the Dashboard tile reads this, and a tenant whose Criticals are end-of-life "+
			"findings must not read 0 there while the Findings page lists them",
			stats.AllProducerSeverityCounts.Critical)
	}
	if stats.AllProducerSeverityCounts.High != 1 {
		t.Errorf("all_producer_severity_counts.high = %d, want 1", stats.AllProducerSeverityCounts.High)
	}
	if stats.SeverityCounts.High != 0 {
		t.Errorf("severity_counts.high = %d, want 0 — an eol finding is not a failed framework control",
			stats.SeverityCounts.High)
	}
}

// The all-producer rollup, read as the SERVICE reads it — through the RLS app
// role, not the owner pool.
//
// Every other test in this file (and in findings_integration_test.go) drives
// the service on testdb.Connect, which is the database OWNER: RLS does not
// apply to it, so those tests prove the WHERE clause and nothing about the role
// production runs under. That distinction matters for this rollup specifically,
// because its scope is not one table. licensedFindingScopeSQL reaches into
// platform_framework_controls, tenant_framework_licenses, tenant_framework_controls
// and tenant_frameworks from inside an EXISTS, and every one of those carries a
// policy of its own. A policy that hides a licence row from the app role does
// not error — the EXISTS simply goes false, the compliance finding drops out of
// the count, and the Dashboard reads LOW. Silently, and only in production,
// because the owner-pool test still passes.
//
// So: same fixture as the rollup test above, read twice — once as owner, once
// as the app role — and the two must agree.
func TestIntegration_GetFindingStatistics_AgreesUnderTheRLSAppRole(t *testing.T) {
	owner := testdb.Connect(t) // skips if TEST_DATABASE_URL unset
	testdb.ApplySchemaAndSeed(t, owner)
	ownerDB := sqlx.NewDb(owner, "postgres")
	tenant := testdb.NewTenant(t, owner)
	ownerSvc := &FindingsService{db: ownerDB}

	// One compliance Critical on an ACTIVATED framework. This is the row the
	// licence EXISTS has to be able to resolve as the app role.
	_, newLicensedControl := seedPublishedFramework(t, ownerDB, tenant, "stats-rls-lic", true)
	licControl, licAsset := newLicensedControl("Critical"), uuid.New()
	licFinding := activeViolation(licControl, licAsset)
	licFinding.Severity = "Critical"
	mustUpsert(t, ownerSvc, tenant, licControl, licAsset, licFinding, "ACTIVE")

	// One compliance Critical on a framework the tenant has NOT activated. In
	// neither rollup, under either role — the gate must not be relaxed by the
	// app role either.
	_, newUnlicensedControl := seedPublishedFramework(t, ownerDB, tenant, "stats-rls-unlic", false)
	unlicControl, unlicAsset := newUnlicensedControl("Critical"), uuid.New()
	unlicFinding := activeViolation(unlicControl, unlicAsset)
	unlicFinding.Severity = "Critical"
	mustUpsert(t, ownerSvc, tenant, unlicControl, unlicAsset, unlicFinding, "ACTIVE")

	asset := insertAsset(t, ownerDB, tenant, "web-03.example.com")
	install := insertInstall(t, ownerDB, tenant, asset, "openssl", "1.1.1")
	insertFindingRow(t, ownerDB, tenant, "vulnerability", "known_vulnerability",
		"software_install", install, "critical", 98, "openssl 1.1.1 is affected by CVE-2026-1000")
	insertFindingRow(t, ownerDB, tenant, "eol", "os_end_of_life",
		"asset", asset, "critical", 95, "web-03 runs an end-of-life operating system")

	// A SECOND tenant's Critical, written by the owner. Nothing the first
	// tenant reads may include it — under RLS or under the explicit
	// cf.tenant_id predicate, whichever gets there first.
	other := testdb.NewTenant(t, owner)
	otherAsset := insertAsset(t, ownerDB, other, "not-yours.example.com")
	insertFindingRow(t, ownerDB, other, "eol", "os_end_of_life",
		"asset", otherAsset, "critical", 95, "another tenant's end-of-life host")

	app := testdb.ConnectAsAppRole(t, owner)
	appSvc := &FindingsService{db: sqlx.NewDb(app, "postgres")}

	appStats, err := appSvc.GetFindingStatistics(tenant)
	if err != nil {
		t.Fatalf("GetFindingStatistics as %s: %v", testdb.RLSAppRole, err)
	}
	ownerStats, err := ownerSvc.GetFindingStatistics(tenant)
	if err != nil {
		t.Fatalf("GetFindingStatistics as owner: %v", err)
	}

	if appStats.AllProducerSeverityCounts.Critical != 3 {
		t.Errorf("as %s, all_producer_severity_counts.critical = %d, want 3 "+
			"(1 compliance on an activated framework + 1 vulnerability + 1 eol). "+
			"The owner pool is not the role the service runs as; a policy on any table the "+
			"licence EXISTS reaches turns that EXISTS false instead of raising, which reads "+
			"as a clean Dashboard.", testdb.RLSAppRole, appStats.AllProducerSeverityCounts.Critical)
	}
	if appStats.AllProducerSeverityCounts != ownerStats.AllProducerSeverityCounts {
		t.Errorf("all_producer_severity_counts differ by connecting role: %s=%+v owner=%+v",
			testdb.RLSAppRole, appStats.AllProducerSeverityCounts, ownerStats.AllProducerSeverityCounts)
	}
	if appStats.SeverityCounts.Critical != 1 {
		t.Errorf("as %s, severity_counts.critical = %d, want 1 — the compliance rollup's licence "+
			"gate must resolve the same way under the app role", testdb.RLSAppRole, appStats.SeverityCounts.Critical)
	}
}

// EVERY producer the registry defines, enumerated from the registry.
//
// The tile says "all producers". The two tests above name three of them by
// hand, which proves the count is not compliance-only and proves nothing about
// the four they do not name — and a hand-written list is exactly how "all"
// quietly becomes "the ones someone remembered". `standards/findings-registry.yaml`
// is the list; this reads it.
//
// It passes today because the scope is a DENYLIST: findingListWhere exempts
// every row that is not (producer = 'compliance' AND kind = 'control_noncompliant')
// from the framework licence gate, rather than admitting an allowlist of
// producers. That polarity is the whole of why the Dashboard will count the
// configuration and drift producers on the day they start writing, with nobody
// remembering to come back here. Rewrite it as an allowlist — the shape that
// misclassified eleven catalogue algorithms when PQC readiness was written that
// way round — and this test is what fails.
func TestIntegration_GetFindingStatistics_CountsEveryRegisteredProducer(t *testing.T) {
	svc, db, tenant := newFindingsServiceIT(t)

	// One Critical for each NON-compliance producer, on that producer's first
	// registered kind and a subject type that kind allows. Compliance is seeded
	// separately below because its row needs a control on an activated
	// framework — which is the licence gate, not an exemption from this rule.
	var wanted int
	for _, p := range sharedfindings.Producers {
		if p.Key == sharedfindings.ProducerCompliance {
			continue
		}
		kind, subjectType, ok := firstRegisteredKind(p.Key)
		if !ok {
			t.Fatalf("registry producer %q has no kinds; the registry generator or this guard is wrong", p.Key)
		}
		if err := sharedfindings.Validate(p.Key, kind, subjectType); err != nil {
			t.Fatalf("guard built an unwritable finding for %q: %v", p.Key, err)
		}
		insertFindingRow(t, db, tenant, p.Key, kind, subjectType, uuid.New(), "critical", 95,
			"registry sweep: "+p.Key+"/"+kind)
		wanted++
	}

	// And the compliance producer, on an ACTIVATED framework — so "every
	// producer" is proven to include the one the licence gate applies to,
	// rather than passing because compliance was left out.
	_, newLicensedControl := seedPublishedFramework(t, db, tenant, "stats-every-producer", true)
	control, asset := newLicensedControl("Critical"), uuid.New()
	f := activeViolation(control, asset)
	f.Severity = "Critical"
	mustUpsert(t, svc, tenant, control, asset, f, "ACTIVE")
	wanted++

	stats, err := svc.GetFindingStatistics(tenant)
	if err != nil {
		t.Fatalf("GetFindingStatistics: %v", err)
	}
	if stats.AllProducerSeverityCounts.Critical != wanted {
		t.Errorf("all_producer_severity_counts.critical = %d, want %d — one Critical per producer in "+
			"standards/findings-registry.yaml (%d producers). The Dashboard tile labelled \"all producers\" "+
			"reads this number, so a producer missing from it is a Critical the tenant is not shown.",
			stats.AllProducerSeverityCounts.Critical, wanted, len(sharedfindings.Producers))
	}
	// And the compliance-scoped rollup must NOT have moved: it is the one
	// number on this response that is still about framework compliance.
	if stats.SeverityCounts.Critical != 1 {
		t.Errorf("severity_counts.critical = %d, want 1 — six other producers' Criticals leaked into the "+
			"compliance rollup", stats.SeverityCounts.Critical)
	}
}

// firstRegisteredKind returns a producer's first registered kind and a subject
// type that kind allows, in registry order.
func firstRegisteredKind(producer string) (kind, subjectType string, ok bool) {
	for _, k := range sharedfindings.All {
		if k.Producer == producer && len(k.SubjectTypes) > 0 {
			return k.Key, k.SubjectTypes[0], true
		}
	}
	return "", "", false
}
