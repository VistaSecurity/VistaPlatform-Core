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
