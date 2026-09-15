package services

// The asset read surface, and the places where two answers to one question had
// drifted apart.
//
// Every assertion here is an AGREEMENT: a count beside a list must describe the
// list, a summary tile must agree with the facet rail it links to, and a filter
// the list honours must be honoured by the count of the same thing. Each of
// these was a pair of hand-written queries with different opinions.
//
// Skips without TEST_DATABASE_URL.

import (
	"testing"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/findings"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// TestIntegration_HasFindingsFacet_AgreesWithQuery is gate 1 A1, closed by
// workstream 3.1.
//
// The facet was WITHDRAWN because it counted `compliance_findings` by
// `asset_id` while the rail's click wrote a `finding:(…)` term, which the query
// language resolves over `findings` and over the asset's DESCENDANTS as well.
// Two tables, two subject vocabularies, one question — the rail's number
// described a different set from the list it led to. (It was also broken
// outright: it filtered a `status` column the old table did not have, so every
// request errored and the client rendered the failure as "no assets have
// findings" — a broken count that read as good news.)
//
// It is back, and this test is the reason it is allowed back: the facet and the
// list are driven off ONE predicate. The facet compiles findings.OpenQuery
// through the same translator the list compiles, so this asserts what the
// product promises — click the number, get exactly those rows.
//
// The fixture is deliberately not all-asset-subjects. Most findings in this
// product are on a certificate or a crypto configuration, and an asset-only
// reading of "has findings" is the specific wrong answer the descendant
// resolution exists to prevent, so one of the three assets here is findable
// ONLY through its crypto configuration.
func TestIntegration_HasFindingsFacet_AgreesWithQuery(t *testing.T) {
	svc, db, tenant := newIdentityFixture(t)

	withAssetFinding := seedAsset(t, db, tenant, "finding-on-host.example.test", "server", "hardware.computer.server", "production", 0, 1)
	withConfigFinding := seedAsset(t, db, tenant, "finding-on-config.example.test", "server", "hardware.computer.server", "production", 0, 1)
	resolvedOnly := seedAsset(t, db, tenant, "finding-resolved.example.test", "server", "hardware.computer.server", "production", 0, 1)
	clean := seedAsset(t, db, tenant, "no-findings.example.test", "server", "hardware.computer.server", "production", 0, 1)

	seedFinding := func(subjectType string, subjectID uuid.UUID, detection, workflow string) {
		t.Helper()
		if _, err := db.Exec(`
			INSERT INTO findings (id, tenant_id, producer, kind, subject_type, subject_id,
			                      severity, score, summary, detection_state, workflow_status)
			VALUES ($1,$2,'eol','os_end_of_life',$3,$4,'high',70,'fixture',$5,$6)`,
			uuid.New(), tenant, subjectType, subjectID, detection, workflow); err != nil {
			t.Fatalf("seed %s finding: %v", subjectType, err)
		}
	}

	seedFinding("asset", withAssetFinding, "ACTIVE", "NEW")

	// A crypto configuration hanging off the second asset's endpoint — the
	// descendant path.
	var endpointID uuid.UUID
	if err := db.QueryRow(`SELECT id FROM asset_endpoints WHERE tenant_id=$1 AND asset_id=$2 LIMIT 1`,
		tenant, withConfigFinding).Scan(&endpointID); err != nil {
		t.Fatalf("read endpoint: %v", err)
	}
	configID := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO crypto_implementations (id, tenant_id, asset_id, endpoint_id, protocol, discovery_method, created_at, updated_at)
		VALUES ($1,$2,$3,$4,'TLS','passive',NOW(),NOW())`,
		configID, tenant, withConfigFinding, endpointID); err != nil {
		t.Fatalf("insert configuration: %v", err)
	}
	seedFinding("crypto_configuration", configID, "ACTIVE", "NEW")

	// Closed by a human: still ACTIVE detection, but RESOLVED workflow. Counting
	// it would report work somebody already did as outstanding; counting only
	// detection_state is the half-definition that does exactly that.
	seedFinding("asset", resolvedOnly, "ACTIVE", "RESOLVED")
	_ = clean

	buckets, err := svc.GetAssetFacets(tenant, models.AssetFilters{}, "has_findings", 50)
	if err != nil {
		t.Fatalf("has_findings facet: %v", err)
	}
	facet := map[string]int{}
	for _, b := range buckets {
		facet[b.Key] = b.Count
	}
	if facet["true"] != 2 {
		t.Errorf("has_findings=true counted %d assets, want 2 (one via the asset, one via its "+
			"crypto configuration); a RESOLVED finding is not open and a clean asset has none", facet["true"])
	}
	if facet["false"] != 2 {
		t.Errorf("has_findings=false counted %d assets, want 2", facet["false"])
	}

	// THE agreement: the list the click leads to must be exactly the set the
	// number counted. Both sides run findings.OpenQuery — the facet compiles it
	// internally, the list receives it as `?query=` — so a divergence here means
	// the two stopped being one predicate.
	listed, total, err := svc.GetAssets(tenant, models.AssetFilters{
		Query: findings.OpenQuery, PageSize: 50, Page: 1,
	})
	if err != nil {
		t.Fatalf("list with the open-findings query: %v", err)
	}
	if total != facet["true"] || len(listed) != facet["true"] {
		t.Fatalf("the rail says %d assets have open findings and the list it links to returns %d "+
			"(%d rows) — the count and the click are describing different sets again",
			facet["true"], total, len(listed))
	}
	got := map[uuid.UUID]bool{}
	for _, a := range listed {
		got[a.ID] = true
	}
	for _, want := range []uuid.UUID{withAssetFinding, withConfigFinding} {
		if !got[want] {
			t.Errorf("asset %s has an open finding and is missing from the list", want)
		}
	}
	for _, notWanted := range []uuid.UUID{resolvedOnly, clean} {
		if got[notWanted] {
			t.Errorf("asset %s has no OPEN finding and is in the list", notWanted)
		}
	}

	// The level is published, so a rail built from AssetFacetLevels() offers it.
	advertised := false
	for _, level := range AssetFacetLevels() {
		if level == "has_findings" {
			advertised = true
		}
	}
	if !advertised {
		t.Error("AssetFacetLevels() does not advertise has_findings; the UI and the OpenAPI enum " +
			"are both built from it, so the control would not appear")
	}

	// The other polarity: the neighbouring facets still answer. A restore that
	// broke one of them would be the withdrawal's bug reversed.
	for _, level := range []string{"class", "risk", "has_endpoints", "environment"} {
		if _, err := svc.GetAssetFacets(tenant, models.AssetFilters{}, level, 50); err != nil {
			t.Errorf("the %s facet broke: %v", level, err)
		}
	}
}

// TestIntegration_RiskSummary_SeparatesNotAssessedFromClean is gate 1 A3.
//
// `unknown_risk` counted every asset in the Informational band with NO coverage
// guard, so an asset nobody had ever scored and an asset scored clean were one
// number — the three-valued flattening this platform has made sixty times, in
// the summary the dashboard hero reads. The risk FACET has always split them,
// which is exactly why the tile and the rail disagreed.
func TestIntegration_RiskSummary_SeparatesNotAssessedFromClean(t *testing.T) {
	svc, db, tenant := newIdentityFixture(t)

	mk := func(host string) uuid.UUID {
		t.Helper()
		a, err := svc.CreateAsset(tenant, models.AssetInput{
			ClassKey: assetclass.KeyServer, Hostname: ptr(host),
		})
		if err != nil {
			t.Fatalf("create %s: %v", host, err)
		}
		if err := svc.ApproveAssets(tenant, []uuid.UUID{a.ID}, uuid.Nil); err != nil {
			t.Fatalf("approve %s: %v", host, err)
		}
		return a.ID
	}
	neverScored := mk("never-scored.example.test")
	scoredClean := mk("scored-clean.example.test")
	scoredHigh := mk("scored-high.example.test")

	// Assessed and clean: score 0 WITH a producer.
	if _, err := db.Exec(
		`UPDATE assets SET risk_score = 0, risk_assessed_by = ARRAY['crypto'] WHERE tenant_id=$1 AND id=$2`,
		tenant, scoredClean); err != nil {
		t.Fatalf("mark assessed-clean: %v", err)
	}
	if _, err := db.Exec(
		`UPDATE assets SET risk_score = 80, risk_assessed_by = ARRAY['crypto'] WHERE tenant_id=$1 AND id=$2`,
		tenant, scoredHigh); err != nil {
		t.Fatalf("mark high: %v", err)
	}
	_ = neverScored // left with an empty risk_assessed_by, which is the point

	summary, err := svc.GetRiskSummary(tenant)
	if err != nil {
		t.Fatalf("risk summary: %v", err)
	}
	if summary.UnknownRisk != 1 {
		t.Errorf("unknown_risk = %d, want 1 — only the asset nobody has scored", summary.UnknownRisk)
	}
	if summary.Informational != 1 {
		t.Errorf("informational = %d, want 1 — the asset scored 0 by a producer is ASSESSED, and clean",
			summary.Informational)
	}
	if summary.HighRisk != 1 {
		t.Errorf("high_risk = %d, want 1", summary.HighRisk)
	}

	// And the tile agrees with the rail it links to, which is the whole point.
	buckets, err := svc.GetAssetFacets(tenant, models.AssetFilters{}, "risk", 50)
	if err != nil {
		t.Fatalf("risk facets: %v", err)
	}
	facet := map[string]int{}
	for _, b := range buckets {
		facet[b.Key] = b.Count
	}
	if facet["not_assessed"] != summary.UnknownRisk {
		t.Errorf("the risk facet says %d not-assessed and the summary says %d; the tile and the rail "+
			"must not disagree about who has been looked at",
			facet["not_assessed"], summary.UnknownRisk)
	}
	if facet["informational"] != summary.Informational {
		t.Errorf("the risk facet says %d informational and the summary says %d",
			facet["informational"], summary.Informational)
	}
}

// TestIntegration_RecentCount_HonoursDiscoverySource is gate 1 A2. The handler
// binds `discovery_source`, the list applies it, the facets apply it — and this
// count did not, so "N new from the sensor" was N new from ANYWHERE, and the
// dashboard tile disagreed with the list it linked to.
func TestIntegration_RecentCount_HonoursDiscoverySource(t *testing.T) {
	svc, db, tenant := newIdentityFixture(t)

	mk := func(host, source string) {
		t.Helper()
		a, err := svc.CreateAsset(tenant, models.AssetInput{
			ClassKey: assetclass.KeyServer, Hostname: ptr(host),
		})
		if err != nil {
			t.Fatalf("create %s: %v", host, err)
		}
		if err := svc.ApproveAssets(tenant, []uuid.UUID{a.ID}, uuid.Nil); err != nil {
			t.Fatalf("approve %s: %v", host, err)
		}
		if _, err := db.Exec(`
			UPDATE assets SET metadata = COALESCE(metadata,'{}'::jsonb) || jsonb_build_object('discovery_source', $3::text)
			WHERE tenant_id=$1 AND id=$2`, tenant, a.ID, source); err != nil {
			t.Fatalf("set discovery_source: %v", err)
		}
	}
	mk("from-sensor-1.example.test", "sensor")
	mk("from-sensor-2.example.test", "sensor")
	mk("from-cloud.example.test", "cloud")

	all, err := svc.GetRecentAssetsCount(tenant, 7, models.AssetFilters{})
	if err != nil {
		t.Fatalf("recent count: %v", err)
	}
	if all != 3 {
		t.Fatalf("unfiltered recent count = %d, want 3", all)
	}

	filtered, err := svc.GetRecentAssetsCount(tenant, 7,
		models.AssetFilters{DiscoverySource: []string{"sensor"}})
	if err != nil {
		t.Fatalf("filtered recent count: %v", err)
	}
	if filtered != 2 {
		t.Errorf("recent count with discovery_source=sensor = %d, want 2 — the filter was bound and ignored",
			filtered)
	}

	// And it agrees with the LIST over the same filter, which is the question
	// the tile is answering.
	listed, total, err := svc.GetAssets(tenant, models.AssetFilters{
		DiscoverySource: []string{"sensor"}, PageSize: 50, Page: 1,
	})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if total != filtered || len(listed) != filtered {
		t.Errorf("the list says %d (%d rows) and the recent count says %d for one filter",
			total, len(listed), filtered)
	}
}

// TestIntegration_MergeAccept_RecomputesBothRollups is gate 1 A4.
//
// A merge moves every crypto configuration from the source to the survivor, and
// INGEST was the only caller of the risk recompute — so the survivor kept the
// rollup it had before it absorbed them. A clean asset that had just inherited a
// weak configuration went on reading risk 0 in the list, in the facets and on
// the dashboard until something happened to re-ingest it.
func TestIntegration_MergeAccept_RecomputesBothRollups(t *testing.T) {
	svc, db, tenant := newIdentityFixture(t)
	merge := NewMergeProposalService(svc.db)

	survivor := seedAsset(t, svc.db, tenant, "rollup-keep.example.test", "server", "hardware.computer.server", "production", 40, 1)
	observation := seedAsset(t, svc.db, tenant, "rollup-merge.example.test", "server", "hardware.computer.server", "production", 60, 1)
	proposal := openProposal(t, svc.db, tenant, observation, survivor)
	actor := seedReviewer(t, svc, tenant)

	// The observation carries the weak configuration and the finding the crypto
	// producer raised on it; the survivor carries nothing.
	//
	// Since workstream 3.2 the rollup reads findings, not configurations
	// (ADR-0005 D4), so the finding is what has to move with the configuration.
	// Coverage moves too: the producer examined the very subjects the survivor
	// now owns, and a survivor scored by an inherited finding with an empty
	// risk_assessed_by reads as "not assessed" in the facet rail.
	configID := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO crypto_implementations (id, tenant_id, asset_id, protocol, discovery_method, risk_score, created_at, updated_at)
		VALUES ($1,$2,$3,'TLS','passive',85,NOW(),NOW())`,
		configID, tenant, observation); err != nil {
		t.Fatalf("insert configuration: %v", err)
	}
	if _, err := db.Exec(`
		INSERT INTO findings (id, tenant_id, producer, kind, subject_type, subject_id,
		                      severity, score, summary, detection_state, workflow_status)
		VALUES ($1,$2,'crypto','weak_configuration','crypto_configuration',$3,
		        'high',85,'seeded by the merge rollup test','ACTIVE','NEW')`,
		uuid.New(), tenant, configID); err != nil {
		t.Fatalf("insert finding: %v", err)
	}
	if _, err := db.Exec(`
		INSERT INTO producer_assessments (tenant_id, asset_id, producer) VALUES ($1,$2,'crypto')
		ON CONFLICT DO NOTHING`, tenant, observation); err != nil {
		t.Fatalf("insert coverage: %v", err)
	}
	for _, id := range []uuid.UUID{survivor, observation} {
		if _, err := db.Exec(
			`UPDATE assets SET risk_score = 0, risk_assessed_by = ARRAY[]::text[] WHERE tenant_id=$1 AND id=$2`,
			tenant, id); err != nil {
			t.Fatalf("reset rollup: %v", err)
		}
	}

	if _, err := merge.Accept(t.Context(), tenant, proposal, survivor, actor); err != nil {
		t.Fatalf("accept: %v", err)
	}

	var survivorScore, mergedScore int
	if err := db.QueryRow(`SELECT risk_score FROM assets WHERE tenant_id=$1 AND id=$2`,
		tenant, survivor).Scan(&survivorScore); err != nil {
		t.Fatalf("read survivor: %v", err)
	}
	if err := db.QueryRow(`SELECT risk_score FROM assets WHERE tenant_id=$1 AND id=$2`,
		tenant, observation).Scan(&mergedScore); err != nil {
		t.Fatalf("read merged: %v", err)
	}
	if survivorScore != 85 {
		t.Errorf("survivor risk_score = %d after absorbing an 85-scoring configuration, want 85 — "+
			"the list, the facets and the dashboard all read this rollup", survivorScore)
	}
	if mergedScore != 0 {
		t.Errorf("merged-away asset risk_score = %d, want 0 — it no longer owns the configuration", mergedScore)
	}

	// And the coverage claim moved with the children.
	var assessedBy pq.StringArray
	if err := db.QueryRow(`SELECT risk_assessed_by FROM assets WHERE tenant_id=$1 AND id=$2`,
		tenant, survivor).Scan(&assessedBy); err != nil {
		t.Fatalf("read survivor coverage: %v", err)
	}
	if len(assessedBy) != 1 || assessedBy[0] != "crypto" {
		t.Errorf("survivor risk_assessed_by = %v after inheriting an assessed asset's subjects, want "+
			"[crypto] — a score with an empty coverage array is read as NOT ASSESSED by the facet rail, "+
			"which would drop the survivor out of every risk band counter", assessedBy)
	}
}

// TestIntegration_MergeAccept_RefusesAnArchivedSurvivor is the other half of A4.
// A candidate archived by an EARLIER decision is a tombstone; merging into one
// buries the observation behind a pointer to somewhere else, and the reviewer
// may well be looking at a page rendered before that decision was made.
func TestIntegration_MergeAccept_RefusesAnArchivedSurvivor(t *testing.T) {
	svc, db, tenant := newIdentityFixture(t)
	merge := NewMergeProposalService(svc.db)

	survivor := seedAsset(t, svc.db, tenant, "tombstone.example.test", "server", "hardware.computer.server", "production", 40, 1)
	observation := seedAsset(t, svc.db, tenant, "live-obs.example.test", "server", "hardware.computer.server", "production", 60, 1)
	proposal := openProposal(t, svc.db, tenant, observation, survivor)
	actor := seedReviewer(t, svc, tenant)

	if _, err := db.Exec(
		`UPDATE assets SET asset_status = 'archived' WHERE tenant_id=$1 AND id=$2`, tenant, survivor); err != nil {
		t.Fatalf("archive the survivor: %v", err)
	}

	_, err := merge.Accept(t.Context(), tenant, proposal, survivor, actor)
	if err == nil {
		t.Fatal("merging into an archived candidate was accepted")
	}
	if err.Error() != ErrMergeSurvivorArchived.Error() {
		t.Errorf("err = %v, want ErrMergeSurvivorArchived", err)
	}

	// And nothing moved.
	var status string
	if err := db.QueryRow(`SELECT asset_status FROM assets WHERE tenant_id=$1 AND id=$2`,
		tenant, observation).Scan(&status); err != nil {
		t.Fatalf("re-read observation: %v", err)
	}
	if status == identity.StatusArchived {
		t.Error("the refused merge archived the observation anyway")
	}
}

// TestIntegration_StaleList_HonoursTheQuery is gate 1 A5. The stale list was a
// SECOND hand-written WHERE builder that ignored `?query=` entirely, so a saved
// view or a facet click carried over from Inventory silently selected the whole
// stale set.
func TestIntegration_StaleList_HonoursTheQuery(t *testing.T) {
	svc, db, tenant := newIdentityFixture(t)
	lifecycle := NewAssetLifecycleService(svc.db)

	mk := func(host, env string) {
		t.Helper()
		a, err := svc.CreateAsset(tenant, models.AssetInput{
			ClassKey: assetclass.KeyServer, Hostname: ptr(host), Environment: ptr(env),
		})
		if err != nil {
			t.Fatalf("create %s: %v", host, err)
		}
		if _, err := db.Exec(
			`UPDATE assets SET stale_status = 'stale' WHERE tenant_id=$1 AND id=$2`, tenant, a.ID); err != nil {
			t.Fatalf("mark stale: %v", err)
		}
	}
	mk("stale-prod-1.example.test", "production")
	mk("stale-prod-2.example.test", "production")
	mk("stale-dev.example.test", "development")

	all, total, err := lifecycle.GetStaleAssets(tenant, models.StaleAssetFilters{})
	if err != nil {
		t.Fatalf("stale list: %v", err)
	}
	if total != 3 || len(all) != 3 {
		t.Fatalf("unfiltered stale list = %d rows / total %d, want 3", len(all), total)
	}

	filtered, filteredTotal, err := lifecycle.GetStaleAssets(tenant,
		models.StaleAssetFilters{Query: "environment:production"})
	if err != nil {
		t.Fatalf("stale list with a query: %v", err)
	}
	if filteredTotal != 2 || len(filtered) != 2 {
		t.Errorf("stale list with `environment:production` = %d rows / total %d, want 2 — "+
			"the query was accepted and ignored", len(filtered), filteredTotal)
	}

	// And an invalid query is the CALLER's error, with diagnostics — not a
	// silent full list.
	if _, _, err := lifecycle.GetStaleAssets(tenant,
		models.StaleAssetFilters{Query: "environment:"}); err == nil {
		t.Error("an unparseable query on the stale list was accepted")
	}
}
