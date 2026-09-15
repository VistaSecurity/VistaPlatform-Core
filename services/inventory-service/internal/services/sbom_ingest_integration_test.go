package services

// SBOM ingestion against a real Postgres (workstream 2.6b).
//
// These are the assertions no unit test can make, because every one of them is
// about what the DATABASE does with what the writer sent: the NULL-not-''
// contract that decides whether two purl-less products are one row or two, the
// re-upload sweep, the CPE fold, and RLS.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/facts"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func newSBOMFixture(t *testing.T) (*SBOMIngestService, *database.DB, uuid.UUID) {
	t.Helper()
	assets, db, tenant := newIdentityFixture(t)
	return NewSBOMIngestService(db, assets), db, tenant
}

// cycloneDX builds a minimal 1.6 document. Written as a Go literal rather than
// a fixture file because each test varies one thing, and a directory of
// near-identical JSON files is how the variation stops being visible.
func cycloneDX(t *testing.T, subject string, components ...map[string]any) string {
	t.Helper()
	doc := map[string]any{
		"bomFormat":    "CycloneDX",
		"specVersion":  "1.6",
		"serialNumber": "urn:uuid:" + uuid.New().String(),
		"version":      1,
		"components":   components,
	}
	if subject != "" {
		doc["metadata"] = map[string]any{
			"component": map[string]any{
				"type": "application", "name": subject, "version": "1.0.0", "bom-ref": "subject",
			},
		}
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func comp(name string, extra map[string]any) map[string]any {
	c := map[string]any{"type": "library", "name": name, "bom-ref": "ref-" + name}
	for k, v := range extra {
		c[k] = v
	}
	return c
}

// hostAsset creates a plain server to hang software off.
func hostAsset(t *testing.T, svc *AssetService, tenant uuid.UUID, hostname string) uuid.UUID {
	t.Helper()
	name := hostname
	asset, err := svc.CreateAsset(tenant, models.AssetInput{
		ClassKey: string(assetclass.KeyServer),
		Hostname: &hostname,
		// DisplayName is cosmetic for a server; the hostname carries identity.
		DisplayName: &name,
	})
	if err != nil {
		t.Fatalf("creating the host asset: %v", err)
	}
	return asset.ID
}

func ingest(t *testing.T, svc *SBOMIngestService, tenant, asset uuid.UUID, body string) *SBOMIngestResult {
	t.Helper()
	res, err := svc.Ingest(context.Background(), tenant, asset, uuid.Nil, "test.cdx.json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	return res
}

// THE writer test. software.Product.Identity gives two purl-less products with
// different names two distinct keys; the database only agrees if the writer
// stored NULL rather than the empty string. With the empty string both rows key
// on that one value and the second collides with the first — and nothing on the
// Go side can see it happen.
func TestIntegration_SBOM_PurlLessProductsAreDistinctRows(t *testing.T) {
	svc, db, tenant := newSBOMFixture(t)
	asset := hostAsset(t, svc.assets, tenant, "null-rule.example.test")

	body := cycloneDX(t, "",
		comp("left-pad", map[string]any{"version": "1.3.0"}),
		comp("right-pad", map[string]any{"version": "1.0.0"}),
		comp("no-version-at-all", nil),
	)
	res := ingest(t, svc, tenant, asset, body)

	if res.ProductsCreated != 3 {
		t.Fatalf("products_created = %d, want 3 — two purl-less products with different names are TWO rows, and "+
			"an unversioned one is a third. A writer that stored '' for the absent purl would have collapsed them.",
			res.ProductsCreated)
	}

	var nulls int
	if err := db.QueryRow(`
		SELECT count(*) FROM software_products
		 WHERE tenant_id = $1 AND purl IS NULL AND cpe IS NULL`, tenant).Scan(&nulls); err != nil {
		t.Fatal(err)
	}
	if nulls != 3 {
		t.Fatalf("%d rows have NULL purl AND NULL cpe, want 3", nulls)
	}
	var empties int
	if err := db.QueryRow(`
		SELECT count(*) FROM software_products
		 WHERE tenant_id = $1 AND (purl = '' OR cpe = '' OR version = '' OR vendor = '' OR license_id = '')`,
		tenant).Scan(&empties); err != nil {
		t.Fatal(err)
	}
	if empties != 0 {
		t.Fatalf("%d rows store '' where the value was absent. '' is a VALUE coalesce takes and NULL is one it "+
			"skips: every purl-less product in the tenant would key on ''.", empties)
	}
}

// The unversioned product is one row however many times it is seen — the other
// half of the same coalesce. Without the INNER coalesce on version the key
// would be NULL, and NULLs do not conflict in Postgres, so every re-observation
// would insert again.
func TestIntegration_SBOM_UnversionedProductIsOneRowAcrossUploads(t *testing.T) {
	svc, db, tenant := newSBOMFixture(t)
	asset := hostAsset(t, svc.assets, tenant, "unversioned.example.test")

	for i := 0; i < 3; i++ {
		ingest(t, svc, tenant, asset, cycloneDX(t, "", comp("mystery-lib", nil)))
	}

	var products, installs int
	if err := db.QueryRow(`SELECT count(*) FROM software_products WHERE tenant_id = $1`, tenant).Scan(&products); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM software_installs WHERE tenant_id = $1`, tenant).Scan(&installs); err != nil {
		t.Fatal(err)
	}
	if products != 1 || installs != 1 {
		t.Fatalf("%d products / %d installs after three uploads of one unversioned component, want 1 / 1",
			products, installs)
	}
}

// A re-upload refreshes what is still there and marks what is gone `removed` —
// never deletes it, so first_seen_at survives and the row can come back.
func TestIntegration_SBOM_ReuploadMarksAbsentInstallsRemoved(t *testing.T) {
	svc, db, tenant := newSBOMFixture(t)
	asset := hostAsset(t, svc.assets, tenant, "reupload.example.test")

	first := ingest(t, svc, tenant, asset, cycloneDX(t, "",
		comp("keep-me", map[string]any{"version": "1.0.0"}),
		comp("drop-me", map[string]any{"version": "2.0.0"}),
	))
	if first.InstallsCreated != 2 || first.InstallsRemoved != 0 {
		t.Fatalf("first upload: created=%d removed=%d, want 2/0", first.InstallsCreated, first.InstallsRemoved)
	}

	var firstSeen string
	if err := db.QueryRow(`
		SELECT i.first_seen_at::text FROM software_installs i
		  JOIN software_products p ON p.id = i.product_id
		 WHERE i.tenant_id = $1 AND p.name = 'keep-me'`, tenant).Scan(&firstSeen); err != nil {
		t.Fatal(err)
	}

	second := ingest(t, svc, tenant, asset, cycloneDX(t, "",
		comp("keep-me", map[string]any{"version": "1.0.0"}),
		comp("new-one", map[string]any{"version": "3.0.0"}),
	))
	if second.InstallsUpdated != 1 || second.InstallsCreated != 1 || second.InstallsRemoved != 1 {
		t.Fatalf("second upload: created=%d updated=%d removed=%d, want 1/1/1",
			second.InstallsCreated, second.InstallsUpdated, second.InstallsRemoved)
	}

	statuses := map[string]string{}
	rows, err := db.Query(`
		SELECT p.name, i.status FROM software_installs i
		  JOIN software_products p ON p.id = i.product_id
		 WHERE i.tenant_id = $1`, tenant)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var name, status string
		if err := rows.Scan(&name, &status); err != nil {
			t.Fatal(err)
		}
		statuses[name] = status
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"keep-me": "active", "drop-me": "removed", "new-one": "active"}
	for name, wantStatus := range want {
		if statuses[name] != wantStatus {
			t.Errorf("%s: status = %q, want %q", name, statuses[name], wantStatus)
		}
	}
	if len(statuses) != 3 {
		t.Errorf("%d install rows, want 3 — a removed install is marked, never deleted", len(statuses))
	}

	// first_seen_at is the whole reason `removed` is not a delete.
	var stillFirstSeen string
	if err := db.QueryRow(`
		SELECT i.first_seen_at::text FROM software_installs i
		  JOIN software_products p ON p.id = i.product_id
		 WHERE i.tenant_id = $1 AND p.name = 'keep-me'`, tenant).Scan(&stillFirstSeen); err != nil {
		t.Fatal(err)
	}
	if stillFirstSeen != firstSeen {
		t.Errorf("first_seen_at moved on re-observation: %s → %s", firstSeen, stillFirstSeen)
	}

	// A third upload that lists drop-me again makes it active: the row was
	// marked, not destroyed.
	ingest(t, svc, tenant, asset, cycloneDX(t, "", comp("drop-me", map[string]any{"version": "2.0.0"})))
	var back string
	if err := db.QueryRow(`
		SELECT i.status FROM software_installs i
		  JOIN software_products p ON p.id = i.product_id
		 WHERE i.tenant_id = $1 AND p.name = 'drop-me'`, tenant).Scan(&back); err != nil {
		t.Fatal(err)
	}
	if back != "active" {
		t.Errorf("a product listed again is %q, want active", back)
	}
}

// CPE 2.3 §5.3.2 makes attribute values case-insensitive and NVD publishes them
// lowercase, so two spellings are one product line and must be one catalogue
// row — and one vulnerability match rather than a hit on only one of them.
func TestIntegration_SBOM_CPEIsCaseFoldedAtWrite(t *testing.T) {
	svc, db, tenant := newSBOMFixture(t)
	assetA := hostAsset(t, svc.assets, tenant, "cpe-a.example.test")
	assetB := hostAsset(t, svc.assets, tenant, "cpe-b.example.test")

	ingest(t, svc, tenant, assetA, cycloneDX(t, "", comp("openssl", map[string]any{
		"version": "3.0.13", "cpe": "cpe:2.3:a:OpenSSL:OpenSSL:3.0.13:*:*:*:*:*:*:*",
	})))
	ingest(t, svc, tenant, assetB, cycloneDX(t, "", comp("openssl", map[string]any{
		"version": "3.0.13", "cpe": "cpe:2.3:a:openssl:openssl:3.0.13:*:*:*:*:*:*:*",
	})))

	var rowsWithCPE int
	if err := db.QueryRow(`
		SELECT count(*) FROM software_products WHERE tenant_id = $1 AND cpe IS NOT NULL`, tenant).Scan(&rowsWithCPE); err != nil {
		t.Fatal(err)
	}
	if rowsWithCPE != 1 {
		t.Fatalf("%d catalogue rows for one CPE spelled two ways, want 1", rowsWithCPE)
	}
	var stored string
	if err := db.QueryRow(`
		SELECT cpe FROM software_products WHERE tenant_id = $1 AND cpe IS NOT NULL`, tenant).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored != strings.ToLower(stored) {
		t.Fatalf("stored CPE %q is not lowercase", stored)
	}
	// One product, two assets.
	var installs int
	if err := db.QueryRow(`
		SELECT count(*) FROM software_installs i
		  JOIN software_products p ON p.id = i.product_id
		 WHERE i.tenant_id = $1 AND p.cpe IS NOT NULL`, tenant).Scan(&installs); err != nil {
		t.Fatal(err)
	}
	if installs != 2 {
		t.Fatalf("%d installs of the one product, want 2", installs)
	}
}

// POST /sbom with no target asset: the subject becomes an application asset,
// pending approval, identified by a scoped `name` — and a second upload MATCHES
// it rather than minting another.
func TestIntegration_SBOM_SubjectCreatesAPendingApplicationAsset(t *testing.T) {
	svc, db, tenant := newSBOMFixture(t)

	body := cycloneDX(t, "billing-api", comp("openssl", map[string]any{"version": "3.0.13"}))
	res, err := svc.Ingest(context.Background(), tenant, uuid.Nil, uuid.Nil, "billing.cdx.json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}
	if !res.AssetCreated {
		t.Fatal("asset_created = false on the first upload")
	}
	if res.AssetStatus != identity.StatusPendingApproval {
		t.Fatalf("asset_status = %q, want %q — an API upload is DECLARED provenance and still pending; "+
			"declared is not approved", res.AssetStatus, identity.StatusPendingApproval)
	}

	assetID := uuid.MustParse(res.AssetID)
	var classKey, classSourceKind, classSourceRef, status string
	if err := db.QueryRow(`
		SELECT class_key, class_source_kind, coalesce(class_source_ref, ''), asset_status
		  FROM assets WHERE tenant_id = $1 AND id = $2`, tenant, assetID).
		Scan(&classKey, &classSourceKind, &classSourceRef, &status); err != nil {
		t.Fatal(err)
	}
	if classKey != string(assetclass.KeyApplication) {
		t.Errorf("class_key = %q, want application", classKey)
	}
	if classSourceKind != string(identity.SourceDeclared) {
		t.Errorf("class_source_kind = %q, want declared", classSourceKind)
	}
	if !strings.HasPrefix(classSourceRef, "sbom:") {
		t.Errorf("class_source_ref = %q, want an `sbom:` producer — the Approvals facet groups on it", classSourceRef)
	}
	if status != identity.StatusPendingApproval {
		t.Errorf("asset_status = %q, want %q", status, identity.StatusPendingApproval)
	}

	// The identifier: a `name` scoped by the class key, carrying the subject's
	// software identity and NO host.
	var kind, value, scope string
	if err := db.QueryRow(`
		SELECT kind, value, coalesce(scope, '') FROM asset_identifiers
		 WHERE tenant_id = $1 AND asset_id = $2`, tenant, assetID).Scan(&kind, &value, &scope); err != nil {
		t.Fatal(err)
	}
	if identity.Kind(kind) != identity.KindName {
		t.Errorf("identifier kind = %q, want name", kind)
	}
	if scope != string(assetclass.KeyApplication) {
		t.Errorf("identifier scope = %q, want the class key — a name identifies within a CLASS, not a segment", scope)
	}
	if !strings.HasPrefix(value, sbomSubjectIdentityPrefix) {
		t.Errorf("identifier value = %q, want the %q namespace so it can never collide with a host-parented "+
			"application key", value, sbomSubjectIdentityPrefix)
	}

	// A second upload of the same artefact matches rather than creating.
	second, err := svc.Ingest(context.Background(), tenant, uuid.Nil, uuid.Nil, "billing.cdx.json",
		strings.NewReader(cycloneDX(t, "billing-api", comp("openssl", map[string]any{"version": "3.0.14"}))))
	if err != nil {
		t.Fatalf("second ingest: %v", err)
	}
	if second.AssetCreated {
		t.Error("the second upload created another asset; the subject identity did not match")
	}
	if second.AssetID != res.AssetID {
		t.Errorf("second upload landed on %s, want %s", second.AssetID, res.AssetID)
	}

	var assets int
	if err := db.QueryRow(`
		SELECT count(*) FROM assets WHERE tenant_id = $1 AND class_key = $2 AND deleted_at IS NULL`,
		tenant, string(assetclass.KeyApplication)).Scan(&assets); err != nil {
		t.Fatal(err)
	}
	if assets != 1 {
		t.Fatalf("%d application assets after two uploads of one artefact, want 1", assets)
	}
	// And no merge proposal. A proposal per re-upload is the signature of an
	// identifier the class may not vote on: it is how the old application path
	// produced ninety-six a day, each naming the asset it already was.
	// Proposals are recorded as `merge_proposed` rows in asset_history, so that
	// is where this is counted.
	var proposals int
	if err := db.QueryRow(`
		SELECT count(*) FROM asset_history WHERE tenant_id = $1 AND action = $2`,
		tenant, string(identity.ActionMergeProposed)).Scan(&proposals); err != nil {
		t.Fatal(err)
	}
	if proposals != 0 {
		t.Fatalf("%d merge proposals from re-uploading one document; the subject is not being matched", proposals)
	}
}

// The history writer LOGS a failed insert rather than returning it, so an action
// the CHECK constraint does not carry is rejected IN SILENCE — the row is simply
// never written and nothing upstream notices. `sbom_imported` found exactly
// that: the constraint's ADD block fires only when there is NO constraint, so it
// was a no-op on every database that already had one.
//
// This is the guard. It compares the DEPLOYED check against the Go vocabulary
// rather than against a second hand-written list, so a new HistoryAction with no
// schema edit fails here instead of vanishing at runtime.
func TestIntegration_SBOM_HistoryActionCheckCoversEveryGoAction(t *testing.T) {
	_, db, _ := newSBOMFixture(t)

	var def string
	if err := db.QueryRow(`
		SELECT pg_get_constraintdef(oid) FROM pg_constraint
		 WHERE conname = 'asset_history_action_check'
		   AND conrelid = to_regclass('public.asset_history')`).Scan(&def); err != nil {
		t.Fatalf("reading asset_history_action_check: %v", err)
	}
	for _, action := range identity.AllHistoryActions() {
		if !strings.Contains(def, "'"+string(action)+"'") {
			t.Errorf("asset_history_action_check does not permit %q. recordAssetHistory logs rather than fails, "+
				"so every %s row would be dropped without a word. Widen the constraint in schema.sql.", action, action)
		}
	}
}

// The subject is ALSO a product on its own asset. An application created from a
// document whose Software tab then said nothing would read as "no software
// found", which is the three-valued dishonesty this codebase keeps paying for.
func TestIntegration_SBOM_SubjectIsAlsoAProductOnItsAsset(t *testing.T) {
	svc, db, tenant := newSBOMFixture(t)

	body := cycloneDX(t, "billing-api", comp("openssl", map[string]any{"version": "3.0.13"}))
	res, err := svc.Ingest(context.Background(), tenant, uuid.Nil, uuid.Nil, "billing.cdx.json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}

	var names []string
	rows, err := db.Query(`
		SELECT p.name FROM software_installs i
		  JOIN software_products p ON p.id = i.product_id
		 WHERE i.tenant_id = $1 AND i.asset_id = $2 ORDER BY p.name`, tenant, uuid.MustParse(res.AssetID))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		names = append(names, n)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(names) != 2 || names[0] != "billing-api" || names[1] != "openssl" {
		t.Fatalf("installs = %v, want [billing-api openssl] — the subject belongs on its own asset", names)
	}
}

// A library subject is refused, and refused BEFORE anything is written: a
// partial write here would leave a catalogue row for a document we rejected.
func TestIntegration_SBOM_LibrarySubjectIsRefusedAndWritesNothing(t *testing.T) {
	svc, db, tenant := newSBOMFixture(t)

	doc := map[string]any{
		"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
		"metadata":   map[string]any{"component": map[string]any{"type": "library", "name": "left-pad", "version": "1.3.0"}},
		"components": []map[string]any{comp("openssl", map[string]any{"version": "3.0.13"})},
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.Ingest(context.Background(), tenant, uuid.Nil, uuid.Nil, "lib.cdx.json", strings.NewReader(string(b)))
	if err == nil {
		t.Fatal("a library subject was accepted; a library is a component of an asset, not an asset")
	}

	for _, table := range []string{"assets", "software_products", "software_installs"} {
		var n int
		if err := db.QueryRow(`SELECT count(*) FROM ` + table + ` WHERE tenant_id = '` + tenant.String() + `'`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Errorf("%s has %d rows after a refused upload, want 0", table, n)
		}
	}
}

// sw.package_count is a COVERAGE fact — "was software enumerated here at all" —
// and it must move with the active install set rather than with the document's
// component count.
func TestIntegration_SBOM_RefreshesThePackageCountFact(t *testing.T) {
	svc, db, tenant := newSBOMFixture(t)
	asset := hostAsset(t, svc.assets, tenant, "facts.example.test")

	ingest(t, svc, tenant, asset, cycloneDX(t, "",
		comp("a", map[string]any{"version": "1"}),
		comp("b", map[string]any{"version": "1"}),
		comp("c", map[string]any{"version": "1", "scope": "excluded"}),
	))

	readCount := func() int {
		t.Helper()
		var raw []byte
		if err := db.QueryRow(`
			SELECT value FROM asset_facts
			 WHERE tenant_id = $1 AND asset_id = $2 AND key = $3 AND source_ref = $4`,
			tenant, asset, facts.KeySWPackageCount, sbomFactSourceRef).Scan(&raw); err != nil {
			t.Fatalf("reading %s: %v", facts.KeySWPackageCount, err)
		}
		var n int
		if err := json.Unmarshal(raw, &n); err != nil {
			t.Fatalf("the fact is not an integer: %s", raw)
		}
		return n
	}

	if got := readCount(); got != 2 {
		t.Fatalf("%s = %d, want 2 — an EXCLUDED component is not installed", facts.KeySWPackageCount, got)
	}

	// A second upload listing one of them leaves one active.
	ingest(t, svc, tenant, asset, cycloneDX(t, "", comp("a", map[string]any{"version": "1"})))
	if got := readCount(); got != 1 {
		t.Fatalf("%s = %d after the second upload, want 1", facts.KeySWPackageCount, got)
	}

	// One row for this source, not one per upload: the unique key is
	// (tenant, asset, key, source_ref), and keying on the upload id would leave
	// a stale row behind every time claiming a count that was true once.
	var factRows int
	if err := db.QueryRow(`
		SELECT count(*) FROM asset_facts WHERE tenant_id = $1 AND asset_id = $2 AND key = $3`,
		tenant, asset, facts.KeySWPackageCount).Scan(&factRows); err != nil {
		t.Fatal(err)
	}
	if factRows != 1 {
		t.Fatalf("%d %s rows after two uploads, want 1", factRows, facts.KeySWPackageCount)
	}
}

// One history row per UPLOAD, carrying the counts and the parser's warnings —
// not one per install, which would bury every other thing the timeline records.
func TestIntegration_SBOM_WritesOneHistoryRowWithTheCounts(t *testing.T) {
	svc, db, tenant := newSBOMFixture(t)
	asset := hostAsset(t, svc.assets, tenant, "history.example.test")

	ingest(t, svc, tenant, asset, cycloneDX(t, "",
		comp("a", map[string]any{"version": "1"}),
		comp("b", map[string]any{"version": "2"}),
	))

	var source string
	var changes []byte
	if err := db.QueryRow(`
		SELECT source, changes_json FROM asset_history
		 WHERE tenant_id = $1 AND asset_id = $2 AND action = $3`,
		tenant, asset, string(identity.ActionSBOMImported)).Scan(&source, &changes); err != nil {
		t.Fatalf("reading the %s history row: %v", identity.ActionSBOMImported, err)
	}
	if !strings.HasPrefix(source, "sbom:") {
		t.Errorf("history source = %q, want the `sbom:` producer", source)
	}
	var payload map[string]any
	if err := json.Unmarshal(changes, &payload); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"component_count", "products_created", "installs_created", "installs_removed", "warnings"} {
		if _, ok := payload[key]; !ok {
			t.Errorf("changes_json has no %q; six months later the timeline is the only place that answers "+
				"\"why does this asset list 412 of my 480 components\"", key)
		}
	}
	if payload["source_kind"] != string(identity.SourceImported) {
		t.Errorf("source_kind = %v, want imported — a document is a claim, not a measurement", payload["source_kind"])
	}
}

// RLS, through the app role the services actually run as. The owner role in the
// other tests BYPASSES policies, so a query that leaks across tenants would
// pass every one of them.
func TestIntegration_SBOM_RLSIsolatesTenants(t *testing.T) {
	owner := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, owner)
	tenantA := testdb.NewTenant(t, owner)
	tenantB := testdb.NewTenant(t, owner)

	appRole := testdb.ConnectAsAppRole(t, owner)
	db := &database.DB{DB: sqlx.NewDb(appRole, "postgres")}
	assets := &AssetService{db: db}
	svc := NewSBOMIngestService(db, assets)

	assetA := hostAsset(t, assets, tenantA, "rls-a.example.test")
	ingest(t, svc, tenantA, assetA, cycloneDX(t, "", comp("tenant-a-only", map[string]any{"version": "1.0.0"})))

	// Tenant B sees none of it, through the same code path.
	rows, total, err := svc.ListProducts(context.Background(), tenantB, "", "", 50, 0)
	if err != nil {
		t.Fatalf("listing tenant B's catalogue: %v", err)
	}
	if total != 0 || len(rows) != 0 {
		t.Fatalf("tenant B sees %d of tenant A's products (total %d)", len(rows), total)
	}

	// And asking for tenant A's asset by id as tenant B returns nothing rather
	// than tenant A's software.
	installs, installTotal, err := svc.ListAssetSoftware(context.Background(), tenantB, assetA, "", "", "", 50, 0)
	if err != nil {
		t.Fatalf("listing tenant A's asset as tenant B: %v", err)
	}
	if installTotal != 0 || len(installs) != 0 {
		t.Fatalf("tenant B read %d installs off tenant A's asset", len(installs))
	}

	// The forward polarity: tenant A does see its own. A test that only checks
	// the negative passes just as well against a query that returns nothing to
	// anybody.
	own, ownTotal, err := svc.ListProducts(context.Background(), tenantA, "", "", 50, 0)
	if err != nil {
		t.Fatalf("listing tenant A's catalogue: %v", err)
	}
	if ownTotal != 1 || len(own) != 1 || own[0].Name != "tenant-a-only" {
		t.Fatalf("tenant A sees %d of its own products (total %d)", len(own), ownTotal)
	}
	if own[0].InstallCount != 1 || own[0].AssetCount != 1 {
		t.Fatalf("install/asset counts = %d/%d, want 1/1", own[0].InstallCount, own[0].AssetCount)
	}
}

// The reads: search, status filter and paging, over a real join.
func TestIntegration_SBOM_ListAssetSoftware(t *testing.T) {
	svc, _, tenant := newSBOMFixture(t)
	asset := hostAsset(t, svc.assets, tenant, "reads.example.test")

	ingest(t, svc, tenant, asset, cycloneDX(t, "",
		comp("openssl", map[string]any{"version": "3.0.13", "publisher": "OpenSSL Project"}),
		comp("zlib", map[string]any{"version": "1.3.1"}),
		comp("gone-next-time", map[string]any{"version": "0.1.0"}),
	))
	ingest(t, svc, tenant, asset, cycloneDX(t, "",
		comp("openssl", map[string]any{"version": "3.0.13"}),
		comp("zlib", map[string]any{"version": "1.3.1"}),
	))

	all, total, err := svc.ListAssetSoftware(context.Background(), tenant, asset, "", "", "", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != 3 || len(all) != 3 {
		t.Fatalf("%d rows (total %d), want 3 — a removed install is included by default, because it is evidence",
			len(all), total)
	}

	active, activeTotal, err := svc.ListAssetSoftware(context.Background(), tenant, asset, "", "active", "", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if activeTotal != 2 || len(active) != 2 {
		t.Fatalf("%d active rows (total %d), want 2", len(active), activeTotal)
	}

	found, foundTotal, err := svc.ListAssetSoftware(context.Background(), tenant, asset, "OPENssl", "", "", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if foundTotal != 1 || len(found) != 1 || found[0].Name != "openssl" {
		t.Fatalf("case-insensitive search returned %d rows (total %d)", len(found), foundTotal)
	}

	// Paging: total describes the whole match, not the page.
	page, pageTotal, err := svc.ListAssetSoftware(context.Background(), tenant, asset, "", "", "name", 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(page) != 1 || pageTotal != 3 {
		t.Fatalf("page = %d rows, total = %d; want 1 and 3", len(page), pageTotal)
	}

	if _, _, err := svc.ListAssetSoftware(context.Background(), tenant, asset, "", "", "nonsense", 50, 0); err == nil {
		t.Error("an unknown sort must be refused rather than silently defaulted")
	}
}

// An empty list is a real answer, not a 404 and not an error. The asset exists
// and nobody has enumerated software on it.
func TestIntegration_SBOM_AssetWithNoSoftwareReturnsAnEmptyList(t *testing.T) {
	svc, _, tenant := newSBOMFixture(t)
	asset := hostAsset(t, svc.assets, tenant, "empty.example.test")

	rows, total, err := svc.ListAssetSoftware(context.Background(), tenant, asset, "", "", "", 50, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rows == nil {
		t.Error("rows is nil; the handler must serialise [] rather than null")
	}
	if len(rows) != 0 || total != 0 {
		t.Errorf("%d rows (total %d), want none", len(rows), total)
	}
}

// Uploading against an asset this tenant does not have is a 404, not a create.
func TestIntegration_SBOM_UnknownAssetIsNotFound(t *testing.T) {
	svc, _, tenant := newSBOMFixture(t)
	_, err := svc.Ingest(context.Background(), tenant, uuid.New(), uuid.Nil, "x.json",
		strings.NewReader(cycloneDX(t, "", comp("a", map[string]any{"version": "1"}))))
	if err == nil {
		t.Fatal("uploading against an unknown asset succeeded")
	}
	if !strings.Contains(err.Error(), "asset not found") {
		t.Fatalf("want ErrSBOMAssetNotFound, got %v", err)
	}
}

// An SPDX document goes through the same writer, and its subject — which IS one
// of its packages — is written once.
func TestIntegration_SBOM_SPDXSubjectIsNotWrittenTwice(t *testing.T) {
	svc, db, tenant := newSBOMFixture(t)
	asset := hostAsset(t, svc.assets, tenant, "spdx.example.test")

	doc := map[string]any{
		"spdxVersion":       "SPDX-2.3",
		"SPDXID":            "SPDXRef-DOCUMENT",
		"name":              "billing",
		"documentNamespace": "https://example.test/spdx/" + uuid.New().String(),
		"packages": []map[string]any{
			{"SPDXID": "SPDXRef-Package-billing", "name": "billing", "versionInfo": "2.1.0", "primaryPackagePurpose": "APPLICATION"},
			{"SPDXID": "SPDXRef-Package-zlib", "name": "zlib", "versionInfo": "1.3.1", "primaryPackagePurpose": "LIBRARY"},
		},
		"relationships": []map[string]any{
			{"spdxElementId": "SPDXRef-DOCUMENT", "relatedSpdxElement": "SPDXRef-Package-billing", "relationshipType": "DESCRIBES"},
		},
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	res := ingest(t, svc, tenant, asset, string(b))
	if res.Format != "spdx" {
		t.Fatalf("format = %q, want spdx — detected from the document, not the filename", res.Format)
	}

	var billing int
	if err := db.QueryRow(`
		SELECT count(*) FROM software_products WHERE tenant_id = $1 AND name = 'billing'`, tenant).Scan(&billing); err != nil {
		t.Fatal(err)
	}
	if billing != 1 {
		t.Fatalf("%d catalogue rows for the SPDX subject, want 1 — in SPDX the subject IS one of the packages", billing)
	}
}

// The dependency graph is dropped, and SAID to be dropped. A user who exported
// one deserves to be told it was not kept rather than to discover it later.
func TestIntegration_SBOM_DependencyEdgesAreCountedAndNotStored(t *testing.T) {
	svc, db, tenant := newSBOMFixture(t)
	asset := hostAsset(t, svc.assets, tenant, "deps.example.test")

	doc := map[string]any{
		"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
		"components": []map[string]any{
			comp("app", map[string]any{"version": "1.0.0", "type": "application"}),
			comp("zlib", map[string]any{"version": "1.3.1"}),
		},
		"dependencies": []map[string]any{
			{"ref": "ref-app", "dependsOn": []string{"ref-zlib"}},
		},
	}
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	res := ingest(t, svc, tenant, asset, string(b))
	if res.DependencyEdgesIgnored != 1 {
		t.Fatalf("dependency_edges_ignored = %d, want 1", res.DependencyEdgesIgnored)
	}

	var edges int
	if err := db.QueryRow(`SELECT count(*) FROM asset_relationships WHERE tenant_id = $1`, tenant).Scan(&edges); err != nil {
		t.Fatal(err)
	}
	if edges != 0 {
		t.Fatalf("%d asset_relationships rows; component-to-component edges are not asset edges", edges)
	}
}

// A search term means itself, `%` and `_` included.
//
// The term is a bound parameter, so nothing here is an injection. What is at
// stake is whether the search answers the question asked: LIKE reads `%` as
// "anything" and `_` as "any one character", and both occur in the strings this
// search exists to find. A purl percent-encodes what a namespace may not carry
// literally, so the canonical form of the npm package `@angular/core` is
// `pkg:npm/%40angular/core` — and an unescaped search for that asks for
// "anything, then 40angular", which is every product in the tenant whose purl
// happens to contain those characters. `_` is as common in a package name as
// `-`.
//
// Mutating likePattern back to a bare "%"+lower(term)+"%" makes every assertion
// below fail.
func TestIntegration_SBOM_SearchTreatsLikeWildcardsLiterally(t *testing.T) {
	svc, _, tenant := newSBOMFixture(t)
	asset := hostAsset(t, svc.assets, tenant, "wildcards.example.test")

	ingest(t, svc, tenant, asset, cycloneDX(t, "",
		comp("core", map[string]any{
			"version": "17.0.0",
			"purl":    "pkg:npm/%40angular/core@17.0.0",
		}),
		comp("log4j_core", map[string]any{"version": "2.14.0"}),
		comp("log4jXcore", map[string]any{"version": "2.14.0"}),
		comp("decoy", map[string]any{"version": "1.0.0"}),
	))

	// `_` is a single-character wildcard. Unescaped, this term also matches
	// log4jXcore.
	rows, total, err := svc.ListAssetSoftware(context.Background(), tenant, asset, "log4j_core", "", "", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(rows) != 1 || rows[0].Name != "log4j_core" {
		names := make([]string, 0, len(rows))
		for _, r := range rows {
			names = append(names, r.Name)
		}
		t.Errorf("searching %q returned %v (total %d), want just log4j_core — `_` is a LIKE wildcard",
			"log4j_core", names, total)
	}

	// `%` is an any-length wildcard. Unescaped, this term matches every row
	// whose purl or name contains "40angular" — and, on a tenant with more
	// products, plenty that do not.
	rows, total, err = svc.ListAssetSoftware(context.Background(), tenant, asset, "pkg:npm/%40angular", "", "", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(rows) != 1 || rows[0].Name != "core" {
		t.Errorf("searching a percent-encoded purl returned %d rows (total %d), want the one product that has it",
			len(rows), total)
	}

	// A bare `%` is the degenerate form: unescaped it selects everything.
	// Escaped it selects the one row that carries a literal percent sign — the
	// percent-encoded purl — which is what the user asked for.
	rows, total, err = svc.ListAssetSoftware(context.Background(), tenant, asset, "%", "", "", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if total != 1 || len(rows) != 1 || rows[0].Name != "core" {
		t.Errorf("searching %q matched %d rows (total %d), want only the percent-encoded purl — unescaped it selects the whole list",
			"%", len(rows), total)
	}

	// The catalogue read shares the rule, and would share the bug.
	products, ptotal, err := svc.ListProducts(context.Background(), tenant, "log4j_core", "", 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if ptotal != 1 || len(products) != 1 || products[0].Name != "log4j_core" {
		t.Errorf("the catalogue search returned %d rows (total %d), want just log4j_core", len(products), ptotal)
	}
}

// Paging is a PARTITION: every row appears on exactly one page.
//
// It is one only when the ordering is total, and these orderings tie by
// construction. One upload writes now() into every row it touches inside one
// transaction, so every install on this asset shares `last_seen_at` to the
// microsecond — `last_seen` is a single tie across the whole list, which is the
// worst case, not a corner. Without a unique tiebreaker Postgres may return a
// tied row on two pages and another on none, and may choose differently between
// two executions of the same statement.
//
// Removing `i.id ASC` from softwareSortColumns makes this fail.
func TestIntegration_SBOM_PagingIsAPartitionUnderTies(t *testing.T) {
	svc, _, tenant := newSBOMFixture(t)
	asset := hostAsset(t, svc.assets, tenant, "paging.example.test")

	// Nine products that tie on EVERY ordering key the endpoint offers: one
	// name, one version, one vendor, and one transaction's timestamps. They are
	// nine rows and not one because each carries its own purl, which is the
	// identity rule working as intended.
	comps := make([]map[string]any, 0, 9)
	for i := 0; i < 9; i++ {
		comps = append(comps, map[string]any{
			"type": "library", "name": "tied", "version": "1.0.0",
			"bom-ref":   fmt.Sprintf("ref-%d", i),
			"publisher": "Same Vendor",
			"purl":      fmt.Sprintf("pkg:generic/tied@1.0.0?build=%d", i),
		})
	}
	ingest(t, svc, tenant, asset, cycloneDX(t, "", comps...))

	for _, sortKey := range []string{"name", "version", "vendor", "last_seen", "first_seen"} {
		seen := map[uuid.UUID]int{}
		for offset := 0; offset < 9; offset += 2 {
			page, total, err := svc.ListAssetSoftware(context.Background(), tenant, asset, "", "", sortKey, 2, offset)
			if err != nil {
				t.Fatalf("sort %q offset %d: %v", sortKey, offset, err)
			}
			if total != 9 {
				t.Fatalf("sort %q: total = %d, want 9", sortKey, total)
			}
			for _, r := range page {
				seen[r.InstallID]++
			}
		}
		if len(seen) != 9 {
			t.Errorf("sort %q: paging returned %d distinct installs of 9 — the ordering is not total, so a page boundary drops rows",
				sortKey, len(seen))
		}
		for id, n := range seen {
			if n != 1 {
				t.Errorf("sort %q: install %s appeared on %d pages — the ordering is not total", sortKey, id, n)
			}
		}
	}

	// The catalogue read pages over the same kind of tie: nine products with
	// one name, one version, one vendor and one install each, so `installs`
	// ties across all nine.
	catSeen := map[uuid.UUID]int{}
	for offset := 0; offset < 9; offset += 2 {
		page, total, err := svc.ListProducts(context.Background(), tenant, "tied", "installs", 2, offset)
		if err != nil {
			t.Fatalf("catalogue offset %d: %v", offset, err)
		}
		if total != 9 {
			t.Fatalf("catalogue total = %d, want 9", total)
		}
		for _, p := range page {
			catSeen[p.ProductID]++
		}
	}
	if len(catSeen) != 9 {
		t.Errorf("the catalogue paged to %d distinct products of 9 — `installs` ties across every equal count", len(catSeen))
	}
}
