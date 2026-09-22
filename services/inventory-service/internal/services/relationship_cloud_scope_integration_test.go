package services

// The neighbourhood's cloud scoping attributes ( slice D).
//
// `cloud_account` and `cloud_region` reach the map from `asset_facts`, and
// nothing about that read can be checked without a real database: which
// producer's row wins when two wrote the same key, whether an expired fact is
// still answered, and — the one that matters most — whether an asset with no
// fact comes back with "" or with nothing. The map draws a grouping node per
// distinct region, so "" would put every un-scoped asset under one box labelled
// with nothing.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"context"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/facts"
	"github.com/vistasecurity/vistaplatform/shared/relationships"
)

// seedFact writes one asset_facts row directly, so a test can set the
// provenance and the observation time the API would not produce.
func seedFact(t *testing.T, db *database.DB, tenant, asset uuid.UUID, key, value, sourceRef string, confidence float64, observedAt string) {
	t.Helper()
	if _, err := db.Exec(`
		INSERT INTO asset_facts (id, tenant_id, asset_id, key, value, source_kind, source_ref,
		                         confidence, observed_at, created_at, updated_at)
		VALUES ($1,$2,$3,$4,to_jsonb($5::text),'measured',$6,$7,$8::timestamptz,NOW(),NOW())`,
		uuid.New(), tenant, asset, key, value, sourceRef, confidence, observedAt); err != nil {
		t.Fatalf("insert fact %s: %v", key, err)
	}
}

func TestIntegration_Neighbourhood_CarriesCloudScope(t *testing.T) {
	svc, db, tenant := relFixture(t)
	ctx := context.Background()

	vpc := seedRelAsset(t, db, tenant, "scope-vpc.example.test", "monitoring")
	bucket := seedRelAsset(t, db, tenant, "scope-bucket.example.test", "monitoring")
	printer := seedRelAsset(t, db, tenant, "scope-printer.example.test", "monitoring")
	seedEdge(t, db, tenant, vpc, bucket, relationships.Contains, SourceKindMeasured, EdgeStatusActive)
	seedEdge(t, db, tenant, vpc, printer, relationships.ConnectsTo, SourceKindMeasured, EdgeStatusActive)

	seedFact(t, db, tenant, vpc, facts.KeyCloudAccountID, "123456789012", "cloud:aws", 1, "2026-09-20T00:00:00Z")
	seedFact(t, db, tenant, vpc, facts.KeyCloudRegion, "us-east-1", "cloud:aws", 1, "2026-09-20T00:00:00Z")
	seedFact(t, db, tenant, bucket, facts.KeyCloudRegion, "us-east-1", "cloud:aws", 1, "2026-09-20T00:00:00Z")
	// The printer gets neither. It is the case the map must NOT invent a place
	// for.

	g, err := svc.Neighbourhood(ctx, tenant, vpc, 1, false)
	if err != nil {
		t.Fatalf("Neighbourhood: %v", err)
	}
	byID := map[uuid.UUID]NeighbourhoodNode{}
	for _, n := range g.Nodes {
		byID[n.AssetID] = n
	}
	if len(byID) != 3 {
		t.Fatalf("nodes = %d, want 3", len(byID))
	}

	if got := byID[vpc]; got.CloudAccount != "123456789012" || got.CloudRegion != "us-east-1" {
		t.Errorf("vpc scope = %q/%q, want 123456789012/us-east-1", got.CloudAccount, got.CloudRegion)
	}
	// A region with no account is a real and ordinary state — an S3 bucket ARN
	// names no account — and must survive as exactly that rather than being
	// dropped for being half-known.
	if got := byID[bucket]; got.CloudRegion != "us-east-1" || got.CloudAccount != "" {
		t.Errorf("bucket scope = %q/%q, want ''/us-east-1", got.CloudAccount, got.CloudRegion)
	}
	if got := byID[printer]; got.CloudAccount != "" || got.CloudRegion != "" {
		t.Errorf("a non-cloud asset was given a scope: %q/%q", got.CloudAccount, got.CloudRegion)
	}
}

func TestIntegration_Neighbourhood_CloudScopePicksTheBestFact(t *testing.T) {
	svc, db, tenant := relFixture(t)
	ctx := context.Background()

	asset := seedRelAsset(t, db, tenant, "scope-multi.example.test", "monitoring")
	peer := seedRelAsset(t, db, tenant, "scope-peer.example.test", "monitoring")
	seedEdge(t, db, tenant, asset, peer, relationships.ConnectsTo, SourceKindMeasured, EdgeStatusActive)

	// Two producers wrote `cloud.region` for the same asset. The unique index is
	// on (tenant, asset, key, source_ref), so both rows exist and one of them
	// has to win deterministically — otherwise the same asset lands in a
	// different region box on every page load.
	seedFact(t, db, tenant, asset, facts.KeyCloudRegion, "eu-west-1", "import:spreadsheet", 0.4, "2026-09-21T00:00:00Z")
	seedFact(t, db, tenant, asset, facts.KeyCloudRegion, "us-east-1", "cloud:aws", 1, "2026-09-20T00:00:00Z")

	g, err := svc.Neighbourhood(ctx, tenant, asset, 1, false)
	if err != nil {
		t.Fatalf("Neighbourhood: %v", err)
	}
	for _, n := range g.Nodes {
		if n.AssetID != asset {
			continue
		}
		// Confidence first, THEN recency: a more recent guess must not displace
		// the collector that read the provider's own API.
		if n.CloudRegion != "us-east-1" {
			t.Errorf("cloud_region = %q, want the higher-confidence us-east-1", n.CloudRegion)
		}
		return
	}
	t.Fatal("the asset was not in its own neighbourhood")
}

func TestIntegration_Neighbourhood_CloudScopeIgnoresAnExpiredFact(t *testing.T) {
	svc, db, tenant := relFixture(t)
	ctx := context.Background()

	asset := seedRelAsset(t, db, tenant, "scope-expired.example.test", "monitoring")
	peer := seedRelAsset(t, db, tenant, "scope-expired-peer.example.test", "monitoring")
	seedEdge(t, db, tenant, asset, peer, relationships.ConnectsTo, SourceKindMeasured, EdgeStatusActive)

	if _, err := db.Exec(`
		INSERT INTO asset_facts (id, tenant_id, asset_id, key, value, source_kind, source_ref,
		                         confidence, observed_at, expires_at, created_at, updated_at)
		VALUES ($1,$2,$3,$4,to_jsonb('us-east-1'::text),'measured','cloud:aws',1,
		        NOW() - interval '30 days', NOW() - interval '1 day', NOW(), NOW())`,
		uuid.New(), tenant, asset, facts.KeyCloudRegion); err != nil {
		t.Fatalf("insert expired fact: %v", err)
	}

	g, err := svc.Neighbourhood(ctx, tenant, asset, 1, false)
	if err != nil {
		t.Fatalf("Neighbourhood: %v", err)
	}
	for _, n := range g.Nodes {
		if n.AssetID == asset && n.CloudRegion != "" {
			t.Errorf("an expired fact placed the asset in %q; a lapsed statement is not a current one", n.CloudRegion)
		}
	}
}
