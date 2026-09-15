package services

// The software EOL / vulnerability rollup, against a real Postgres
// (workstream 3.8).
//
// Every assertion here is about what the SQL does, and none of them is reachable
// from a unit test: the LATERAL joins, the three-valued ladders, the JSONB reads
// that must not abort the query, and the product-level aggregation.
//
// The one that matters most is the LAST one. `none_known` and `not_assessed` are
// the pair the whole column exists to keep apart — a product with neither a PURL
// nor a CPE was never checked, and rendering that as "0 vulnerabilities" is the
// same collapse a risk score of 0 with an empty `risk_assessed_by` would be.
//
// Skips without TEST_DATABASE_URL (`make test-integration-db`).

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	sharedfindings "github.com/vistasecurity/vistaplatform/shared/findings"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// writeFinding inserts one finding straight into the table.
//
// Deliberately not through `shared/findings/producer`: this is a test of the
// READ, and building the row through the writer would couple it to that
// writer's rules rather than to the column shapes the query depends on.
func writeFinding(
	t *testing.T, svc *SBOMIngestService, tenant uuid.UUID,
	producerKey, kind string, subject uuid.UUID,
	severity string, score int, evidence string,
) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := svc.db.Exec(`
		INSERT INTO findings (id, tenant_id, producer, kind, subject_type, subject_id,
		                      severity, score, summary, evidence, detection_state, workflow_status)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'test finding', $9::jsonb, 'ACTIVE', 'NEW')`,
		id, tenant, producerKey, kind, sharedfindings.SubjectSoftwareInstall, subject,
		severity, score, evidence); err != nil {
		t.Fatalf("insert finding %s/%s: %v", producerKey, kind, err)
	}
	return id
}

// installByName picks one row of an asset's software list.
func installByName(t *testing.T, rows []SoftwareInstallRow, name string) SoftwareInstallRow {
	t.Helper()
	for _, r := range rows {
		if r.Name == name {
			return r
		}
	}
	t.Fatalf("no install named %q in %d rows", name, len(rows))
	return SoftwareInstallRow{}
}

func TestIntegration_SoftwareRollup_ThreeValuedOnBothAxes(t *testing.T) {
	svc, _, tenant := newSBOMFixture(t)
	asset := hostAsset(t, svc.assets, tenant, "rollup.example.test")

	// openssl carries a purl AND a cpe: the producer had something to match on.
	// in-house-shim carries neither, which is what the producer skips.
	ingest(t, svc, tenant, asset, cycloneDX(t, "",
		comp("openssl", map[string]any{
			"version": "1.1.1",
			"purl":    "pkg:generic/openssl@1.1.1",
			"cpe":     "cpe:2.3:a:openssl:openssl:1.1.1:*:*:*:*:*:*:*",
		}),
		comp("zlib", map[string]any{"version": "1.3.1", "purl": "pkg:generic/zlib@1.3.1"}),
		comp("in-house-shim", map[string]any{"version": "0.1.0"}),
	))

	rows, _, err := svc.ListAssetSoftware(context.Background(), tenant, asset, "", "", "", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	openssl := installByName(t, rows, "openssl")
	zlib := installByName(t, rows, "zlib")
	shim := installByName(t, rows, "in-house-shim")

	// --- before any producer has written anything ---------------------------
	//
	// zlib has a purl and no finding: the producer could have checked it, so
	// `none_known`. The shim has no machine identifier at all, so
	// `not_assessed`. These two are the ones that must not be the same value.
	if zlib.VulnerabilityState != SoftwareVulnNoneKnown {
		t.Errorf("zlib (has a purl, no finding) = %q, want %q", zlib.VulnerabilityState, SoftwareVulnNoneKnown)
	}
	if shim.VulnerabilityState != SoftwareVulnNotAssessed {
		t.Errorf("in-house-shim (no purl, no cpe) = %q, want %q — "+
			"a product nothing could match on is not a product with no vulnerabilities",
			shim.VulnerabilityState, SoftwareVulnNotAssessed)
	}
	if openssl.EOLState != SoftwareEOLNotAssessed {
		t.Errorf("openssl eol_state = %q with no finding, want %q", openssl.EOLState, SoftwareEOLNotAssessed)
	}
	for _, r := range rows {
		if r.WorstCVSS != nil {
			t.Errorf("%s carries worst_cvss %v with no vulnerability finding; NULL and 0.0 are different answers", r.Name, *r.WorstCVSS)
		}
		if r.VulnerabilityCount != 0 {
			t.Errorf("%s carries %d CVEs with no finding", r.Name, r.VulnerabilityCount)
		}
	}

	// --- now the producers write --------------------------------------------
	eolID := writeFinding(t, svc, tenant, sharedfindings.ProducerEOL, sharedfindings.KindSoftwareEndOfLife,
		openssl.InstallID, "medium", 50,
		`{"eol_date":"2023-09-11","days_remaining":-731,"catalogue_id":"`+uuid.New().String()+`"}`)
	vulnID := writeFinding(t, svc, tenant, sharedfindings.ProducerVulnerability, sharedfindings.KindKnownVulnerability,
		openssl.InstallID, "critical", 98,
		`{"cve_count":12,"worst_cvss_scored":true,"cves":[{"cve_id":"CVE-2026-1000"}]}`)

	rows, _, err = svc.ListAssetSoftware(context.Background(), tenant, asset, "", "", "", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 {
		t.Fatalf("%d rows after writing findings, want 3 — a LATERAL that matched twice would duplicate the install", len(rows))
	}
	openssl = installByName(t, rows, "openssl")

	if openssl.EOLState != SoftwareEOLEndOfLife {
		t.Errorf("eol_state = %q, want %q", openssl.EOLState, SoftwareEOLEndOfLife)
	}
	if openssl.EOLDate == nil || *openssl.EOLDate != "2023-09-11" {
		t.Errorf("eol_date = %v, want 2023-09-11", openssl.EOLDate)
	}
	if openssl.EOLDaysRemaining == nil || *openssl.EOLDaysRemaining != -731 {
		t.Errorf("eol_days_remaining = %v, want -731", openssl.EOLDaysRemaining)
	}
	if openssl.EOLSeverity == nil || *openssl.EOLSeverity != "medium" {
		t.Errorf("eol_severity = %v, want medium", openssl.EOLSeverity)
	}
	if openssl.EOLFindingID == nil || *openssl.EOLFindingID != eolID {
		t.Errorf("eol_finding_id = %v, want %s — without it the cell cannot link at the finding", openssl.EOLFindingID, eolID)
	}
	if openssl.VulnerabilityState != SoftwareVulnVulnerable {
		t.Errorf("vulnerability_state = %q, want %q", openssl.VulnerabilityState, SoftwareVulnVulnerable)
	}
	if openssl.VulnerabilityCount != 12 {
		t.Errorf("vulnerability_count = %d, want 12", openssl.VulnerabilityCount)
	}
	if openssl.WorstCVSS == nil || *openssl.WorstCVSS != 9.8 {
		t.Errorf("worst_cvss = %v, want 9.8 (score 98 is CVSS x10)", openssl.WorstCVSS)
	}
	if openssl.VulnFindingID == nil || *openssl.VulnFindingID != vulnID {
		t.Errorf("vulnerability_finding_id = %v, want %s", openssl.VulnFindingID, vulnID)
	}
	// The other two rows must be untouched: a join that ignored subject_id
	// would smear one install's finding across every row of the list.
	if installByName(t, rows, "zlib").VulnerabilityState != SoftwareVulnNoneKnown {
		t.Error("zlib picked up openssl's finding; the LATERAL is not keyed on subject_id")
	}
}

// A CVE the catalogue never scored must arrive as NULL, not 0.0.
//
// The producer says so explicitly — it writes `worst_cvss_scored: false` beside
// a score of 0 — and 0.0 on screen reads as "harmless" for something nobody has
// graded. This is the jq `//` mistake in a different notation.
func TestIntegration_SoftwareRollup_UnscoredCVEIsNullNotZero(t *testing.T) {
	svc, _, tenant := newSBOMFixture(t)
	asset := hostAsset(t, svc.assets, tenant, "unscored.example.test")
	ingest(t, svc, tenant, asset, cycloneDX(t, "",
		comp("libfoo", map[string]any{"version": "1.0.0", "purl": "pkg:generic/libfoo@1.0.0"}),
	))
	rows, _, err := svc.ListAssetSoftware(context.Background(), tenant, asset, "", "", "", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	writeFinding(t, svc, tenant, sharedfindings.ProducerVulnerability, sharedfindings.KindKnownVulnerability,
		rows[0].InstallID, "info", 0,
		`{"cve_count":1,"worst_cvss_scored":false,"cves":[{"cve_id":"CVE-2026-9999","cvss_scored":false}]}`)

	rows, _, err = svc.ListAssetSoftware(context.Background(), tenant, asset, "", "", "", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	r := rows[0]
	if r.VulnerabilityState != SoftwareVulnVulnerable {
		t.Errorf("state = %q; an ungraded CVE is still a CVE", r.VulnerabilityState)
	}
	if r.WorstCVSS != nil {
		t.Errorf("worst_cvss = %v, want nil — the catalogue graded nothing, and 0.0 reads as harmless", *r.WorstCVSS)
	}
	if r.VulnerabilityCount != 1 {
		t.Errorf("vulnerability_count = %d, want 1", r.VulnerabilityCount)
	}
}

// A RESOLVED or INACTIVE finding must not show. "Open" is both halves —
// still detected AND nobody has closed it — and using only one of them is how a
// column comes to report a problem somebody already fixed.
func TestIntegration_SoftwareRollup_ClosedFindingsDoNotShow(t *testing.T) {
	svc, _, tenant := newSBOMFixture(t)
	asset := hostAsset(t, svc.assets, tenant, "closed.example.test")
	ingest(t, svc, tenant, asset, cycloneDX(t, "",
		comp("libbar", map[string]any{"version": "2.0.0", "purl": "pkg:generic/libbar@2.0.0"}),
	))
	rows, _, err := svc.ListAssetSoftware(context.Background(), tenant, asset, "", "", "", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	install := rows[0].InstallID

	id := writeFinding(t, svc, tenant, sharedfindings.ProducerVulnerability, sharedfindings.KindKnownVulnerability,
		install, "high", 78, `{"cve_count":3,"worst_cvss_scored":true}`)

	// Still open: it shows.
	rows, _, _ = svc.ListAssetSoftware(context.Background(), tenant, asset, "", "", "", 50, 0)
	if rows[0].VulnerabilityState != SoftwareVulnVulnerable {
		t.Fatalf("state = %q before closing, want vulnerable — the rest of this test proves nothing otherwise", rows[0].VulnerabilityState)
	}

	for _, closed := range []struct{ col, val string }{
		{"workflow_status", "RESOLVED"},
		{"workflow_status", "SUPPRESSED"},
		{"detection_state", "INACTIVE"},
	} {
		if _, err := svc.db.Exec(
			`UPDATE findings SET workflow_status = 'NEW', detection_state = 'ACTIVE' WHERE id = $1`, id); err != nil {
			t.Fatal(err)
		}
		if _, err := svc.db.Exec(
			`UPDATE findings SET `+closed.col+` = $1 WHERE id = $2`, closed.val, id); err != nil {
			t.Fatal(err)
		}
		rows, _, err = svc.ListAssetSoftware(context.Background(), tenant, asset, "", "", "", 50, 0)
		if err != nil {
			t.Fatal(err)
		}
		if rows[0].VulnerabilityState == SoftwareVulnVulnerable {
			t.Errorf("%s=%s still reads as vulnerable; the column would report a problem somebody closed",
				closed.col, closed.val)
		}
		if rows[0].VulnerabilityState != SoftwareVulnNoneKnown {
			t.Errorf("%s=%s reads %q, want %q — the product still has a purl, so it was checkable",
				closed.col, closed.val, rows[0].VulnerabilityState, SoftwareVulnNoneKnown)
		}

		// The CATALOGUE rollup too. It is a different join — a plain one over
		// every install of the tenant rather than the per-row LATERAL — and
		// asserting only the asset tab leaves the Inventory → Software lens
		// free to keep reporting a problem somebody closed. Two joins, one
		// question, and they have to answer it the same way.
		products, _, perr := svc.ListProducts(context.Background(), tenant, "", "", 50, 0)
		if perr != nil {
			t.Fatal(perr)
		}
		if len(products) != 1 {
			t.Fatalf("%d products, want 1", len(products))
		}
		if products[0].VulnerableInstallCount != 0 || products[0].VulnerabilityState == SoftwareVulnVulnerable {
			t.Errorf("catalogue row with %s=%s reads %q on %d installs; the lens would report a closed finding",
				closed.col, closed.val, products[0].VulnerabilityState, products[0].VulnerableInstallCount)
		}
	}
}

// Malformed evidence must leave a blank cell, not 500 the page.
//
// `evidence` is JSONB with no schema, by design. A plain `::int` cast on a
// string value aborts the whole statement, so one bad document would take the
// Software tab down for every row on the asset.
func TestIntegration_SoftwareRollup_MalformedEvidenceDoesNotBreakTheQuery(t *testing.T) {
	svc, _, tenant := newSBOMFixture(t)
	asset := hostAsset(t, svc.assets, tenant, "malformed.example.test")
	ingest(t, svc, tenant, asset, cycloneDX(t, "",
		comp("libbaz", map[string]any{"version": "3.0.0", "purl": "pkg:generic/libbaz@3.0.0"}),
	))
	rows, _, err := svc.ListAssetSoftware(context.Background(), tenant, asset, "", "", "", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	writeFinding(t, svc, tenant, sharedfindings.ProducerVulnerability, sharedfindings.KindKnownVulnerability,
		rows[0].InstallID, "high", 75,
		`{"cve_count":"many","worst_cvss_scored":true}`)
	writeFinding(t, svc, tenant, sharedfindings.ProducerEOL, sharedfindings.KindSoftwareEndOfLife,
		rows[0].InstallID, "medium", 50,
		`{"eol_date":"2024-01-01","days_remaining":"ages ago"}`)

	rows, _, err = svc.ListAssetSoftware(context.Background(), tenant, asset, "", "", "", 50, 0)
	if err != nil {
		t.Fatalf("a malformed evidence document broke the list query: %v", err)
	}
	if rows[0].VulnerabilityCount != 0 {
		t.Errorf("vulnerability_count = %d from a non-numeric value, want 0", rows[0].VulnerabilityCount)
	}
	if rows[0].EOLDaysRemaining != nil {
		t.Errorf("eol_days_remaining = %v from a non-numeric value, want nil", *rows[0].EOLDaysRemaining)
	}
	// The state is still readable — the finding exists, only one field of its
	// evidence was unreadable.
	if rows[0].EOLState != SoftwareEOLEndOfLife {
		t.Errorf("eol_state = %q; a bad `days_remaining` must not lose the finding", rows[0].EOLState)
	}
}

// The catalogue's own rollup: per PRODUCT, across active installs.
func TestIntegration_SoftwareRollup_ProductCatalogueAggregates(t *testing.T) {
	svc, _, tenant := newSBOMFixture(t)
	a1 := hostAsset(t, svc.assets, tenant, "cat-1.example.test")
	a2 := hostAsset(t, svc.assets, tenant, "cat-2.example.test")

	doc := cycloneDX(t, "",
		comp("openssl", map[string]any{"version": "1.1.1", "purl": "pkg:generic/openssl@1.1.1"}),
		comp("in-house-shim", map[string]any{"version": "0.1.0"}),
	)
	ingest(t, svc, tenant, a1, doc)
	ingest(t, svc, tenant, a2, doc)

	// Both installs of openssl get a vulnerability finding; only one gets EOL.
	installs1, _, err := svc.ListAssetSoftware(context.Background(), tenant, a1, "openssl", "", "", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	installs2, _, err := svc.ListAssetSoftware(context.Background(), tenant, a2, "openssl", "", "", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	writeFinding(t, svc, tenant, sharedfindings.ProducerVulnerability, sharedfindings.KindKnownVulnerability,
		installs1[0].InstallID, "critical", 98, `{"cve_count":12,"worst_cvss_scored":true}`)
	writeFinding(t, svc, tenant, sharedfindings.ProducerVulnerability, sharedfindings.KindKnownVulnerability,
		installs2[0].InstallID, "high", 75, `{"cve_count":4,"worst_cvss_scored":true}`)
	writeFinding(t, svc, tenant, sharedfindings.ProducerEOL, sharedfindings.KindSoftwareEndOfLife,
		installs1[0].InstallID, "medium", 50, `{"eol_date":"2023-09-11","days_remaining":-731}`)

	products, total, err := svc.ListProducts(context.Background(), tenant, "", "", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 {
		t.Fatalf("%d products, want 2 — the LATERAL joins multiplied the catalogue", total)
	}
	var openssl, shim SoftwareProductRow
	for _, p := range products {
		switch p.Name {
		case "openssl":
			openssl = p
		case "in-house-shim":
			shim = p
		}
	}
	if openssl.InstallCount != 2 || openssl.AssetCount != 2 {
		t.Errorf("openssl install/asset count = %d/%d, want 2/2 — the join changed the counts that were already right",
			openssl.InstallCount, openssl.AssetCount)
	}
	if openssl.VulnerabilityState != SoftwareVulnVulnerable || openssl.VulnerableInstallCount != 2 {
		t.Errorf("openssl vuln = %q on %d installs, want vulnerable on 2",
			openssl.VulnerabilityState, openssl.VulnerableInstallCount)
	}
	if openssl.WorstCVSS == nil || *openssl.WorstCVSS != 9.8 {
		t.Errorf("openssl worst_cvss = %v, want 9.8 (the WORST across installs, not the last one seen)", openssl.WorstCVSS)
	}
	if openssl.VulnerabilityCount != 12 {
		t.Errorf("openssl cve count = %d, want 12", openssl.VulnerabilityCount)
	}
	if openssl.EOLState != SoftwareEOLEndOfLife || openssl.EOLInstallCount != 1 {
		t.Errorf("openssl eol = %q on %d installs, want end_of_life on 1", openssl.EOLState, openssl.EOLInstallCount)
	}
	if openssl.EOLDate == nil || *openssl.EOLDate != "2023-09-11" {
		t.Errorf("openssl eol_date = %v, want 2023-09-11", openssl.EOLDate)
	}
	// And the third value survives the aggregation.
	if shim.VulnerabilityState != SoftwareVulnNotAssessed {
		t.Errorf("in-house-shim = %q, want %q — no purl, no cpe, never checked",
			shim.VulnerabilityState, SoftwareVulnNotAssessed)
	}
	if shim.VulnerableInstallCount != 0 || shim.WorstCVSS != nil {
		t.Errorf("in-house-shim reports %d vulnerable installs / cvss %v, want 0 / nil",
			shim.VulnerableInstallCount, shim.WorstCVSS)
	}
}

// The catalogue aggregate joins `findings` plainly rather than through a
// LATERAL with `LIMIT 1`, because a LATERAL is evaluated once per install and
// the aggregate folds every install the tenant has (702ms against 101ms on a
// 60,000-install tenant). Nothing in the query itself then stops a second
// matching finding from doubling an install inside the counts — so the clamp
// has to come from the DATABASE.
//
// It does: `findings_open_subject_uniq` is UNIQUE on
// (tenant_id, producer, kind, subject_type, subject_id, control_id) with NULLS
// NOT DISTINCT over every non-ARCHIVED row, and `control_id` is NULL for every
// producer but `compliance`. This asserts that constraint directly, because the
// join's correctness now rests on it: weaken or drop the index and this fails,
// pointing at softwareFindingAggregateJoin rather than leaving a silently
// inflated `eol_install_count` to be noticed on a customer's screen.
func TestIntegration_SoftwareRollup_OneOpenFindingPerSubjectIsEnforced(t *testing.T) {
	svc, _, tenant := newSBOMFixture(t)
	asset := hostAsset(t, svc.assets, tenant, "uniq.example.test")
	ingest(t, svc, tenant, asset, cycloneDX(t, "",
		comp("openssl", map[string]any{"version": "1.1.1", "purl": "pkg:generic/openssl@1.1.1"}),
	))
	rows, _, err := svc.ListAssetSoftware(context.Background(), tenant, asset, "", "", "", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	install := rows[0].InstallID

	writeFinding(t, svc, tenant, sharedfindings.ProducerVulnerability, sharedfindings.KindKnownVulnerability,
		install, "critical", 98, `{"cve_count":12,"worst_cvss_scored":true}`)

	// A SECOND open finding for the same (producer, kind, subject) must be
	// refused by the index.
	_, err = svc.db.Exec(`
		INSERT INTO findings (id, tenant_id, producer, kind, subject_type, subject_id,
		                      severity, score, summary, evidence, detection_state, workflow_status)
		VALUES ($1, $2, $3, $4, $5, $6, 'high', 70, 'duplicate', '{}'::jsonb, 'ACTIVE', 'NEW')`,
		uuid.New(), tenant, sharedfindings.ProducerVulnerability, sharedfindings.KindKnownVulnerability,
		sharedfindings.SubjectSoftwareInstall, install)
	if err == nil {
		t.Fatal("a second OPEN vulnerability finding for the same install was accepted; " +
			"findings_open_subject_uniq no longer clamps the aggregate join to one row per install, " +
			"so eol_install_count / vulnerable_install_count can now over-count silently")
	}

	// And the counts are what one finding says, not two.
	products, _, err := svc.ListProducts(context.Background(), tenant, "", "", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(products) != 1 {
		t.Fatalf("%d products, want 1", len(products))
	}
	if products[0].InstallCount != 1 || products[0].VulnerableInstallCount != 1 {
		t.Errorf("install/vulnerable counts = %d/%d, want 1/1 — the plain join multiplied the install",
			products[0].InstallCount, products[0].VulnerableInstallCount)
	}
}

// A finding belonging to ANOTHER tenant must not reach this one's rollup.
//
// The list runs inside WithTenantTx so RLS is the boundary, but the LATERAL
// also names `tenant_id` explicitly — and a join that dropped that predicate
// would still pass every test above, because they all use one tenant.
func TestIntegration_SoftwareRollup_IsTenantScoped(t *testing.T) {
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)
	db := &database.DB{DB: sqlx.NewDb(owner, "postgres")}
	assets := &AssetService{db: db}
	svc := NewSBOMIngestService(db, assets)
	tenantA, tenantB := testdb.NewTenant(t, owner), testdb.NewTenant(t, owner)

	assetA := hostAsset(t, assets, tenantA, "iso-a.example.test")
	ingest(t, svc, tenantA, assetA, cycloneDX(t, "",
		comp("libiso", map[string]any{"version": "1.0.0", "purl": "pkg:generic/libiso@1.0.0"}),
	))
	rowsA, _, err := svc.ListAssetSoftware(context.Background(), tenantA, assetA, "", "", "", 50, 0)
	if err != nil {
		t.Fatal(err)
	}

	// Tenant B writes a finding naming tenant A's install id. Impossible
	// through the producer; the point is that the READ refuses it anyway.
	writeFinding(t, svc, tenantB, sharedfindings.ProducerVulnerability, sharedfindings.KindKnownVulnerability,
		rowsA[0].InstallID, "critical", 98, `{"cve_count":9,"worst_cvss_scored":true}`)

	rowsA, _, err = svc.ListAssetSoftware(context.Background(), tenantA, assetA, "", "", "", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if rowsA[0].VulnerabilityState != SoftwareVulnNoneKnown {
		t.Errorf("tenant A's row reads %q from tenant B's finding", rowsA[0].VulnerabilityState)
	}

	// And the CATALOGUE rollup, which joins `findings` differently (a plain
	// join over the tenant's whole install set rather than a per-row LATERAL)
	// and therefore needs its own `tenant_id` predicate asserted. Checking only
	// the asset tab left the Inventory → Software lens free to read another
	// tenant's findings — a cross-tenant leak nothing above would have caught.
	productsA, _, err := svc.ListProducts(context.Background(), tenantA, "", "", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(productsA) != 1 {
		t.Fatalf("%d products for tenant A, want 1", len(productsA))
	}
	if productsA[0].VulnerabilityState != SoftwareVulnNoneKnown || productsA[0].VulnerableInstallCount != 0 {
		t.Errorf("tenant A's catalogue row reads %q on %d vulnerable installs, from tenant B's finding",
			productsA[0].VulnerabilityState, productsA[0].VulnerableInstallCount)
	}
}
