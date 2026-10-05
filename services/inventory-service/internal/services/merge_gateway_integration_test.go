package services

// A merge re-points the segment → gateway link ( slice B, spec §2): the
// network a merged-away device was the gateway of is routed by the survivor,
// and its candidacies on other networks follow it. Skips without
// TEST_DATABASE_URL.

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_MergeProposal_RepointsSegmentGateways(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	ctx := context.Background()

	survivor := seedAsset(t, db, tenant, "gw-keep.example.test", "router", "hardware.network.router", "production", 0, 0)
	observation := seedAsset(t, db, tenant, "gw-dup.example.test", "router", "hardware.network.router", "production", 0, 0)
	bystander := seedAsset(t, db, tenant, "gw-other.example.test", "router", "hardware.network.router", "production", 0, 0)
	at := time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC)

	candidate := func(id uuid.UUID, addr string) map[string]any {
		return map[string]any{id.String(): map[string]any{"address": addr, "source_ref": "interrogation:fixture", "observed_at": at.Format(time.RFC3339Nano)}}
	}
	segment := func(cidr string, gateway uuid.UUID, addr string, cands map[string]any) uuid.UUID {
		t.Helper()
		meta, _ := json.Marshal(map[string]any{"gateway_candidates": cands})
		var id uuid.UUID
		if err := db.QueryRow(`INSERT INTO network_segments(tenant_id,name,segment_type,value,environment,gateway_asset_id,gateway_address,gateway_source_ref,gateway_observed_at,metadata)
			VALUES($1,$2,'cidr',$2,'production',$3,$4::inet,'interrogation:fixture',$5,$6::jsonb) RETURNING id`,
			tenant, cidr, gateway, addr, at, meta).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	// 1. The merged-away device routes this network.
	routed := segment("192.0.2.0/24", observation, "192.0.2.1", map[string]any{})
	// 2. Someone else routes this one; the merged-away device is a candidate.
	contested := segment("198.51.100.0/24", bystander, "198.51.100.1", candidate(observation, "198.51.100.2"))
	// 3. The merged-away device routes it and the survivor is its candidate.
	both := segment("203.0.113.0/24", observation, "203.0.113.1", candidate(survivor, "203.0.113.2"))

	svc := NewMergeProposalService(db)
	proposal := openProposal(t, db, tenant, observation, survivor)
	if _, err := svc.Accept(ctx, tenant, proposal, survivor, seedUser(t, db, tenant)); err != nil {
		t.Fatalf("accept: %v", err)
	}

	read := func(id uuid.UUID) (uuid.UUID, map[string]any) {
		t.Helper()
		var gw uuid.UUID
		var raw []byte
		if err := db.QueryRow(`SELECT gateway_asset_id, coalesce(metadata->'gateway_candidates','{}'::jsonb) FROM network_segments WHERE id=$1`, id).Scan(&gw, &raw); err != nil {
			t.Fatal(err)
		}
		var c map[string]any
		_ = json.Unmarshal(raw, &c)
		return gw, c
	}
	if gw, _ := read(routed); gw != survivor {
		t.Errorf("the merged-away device's network is routed by %s, want the survivor %s", gw, survivor)
	}
	gw, c := read(contested)
	if gw != bystander {
		t.Errorf("a merge moved another device's link: %s", gw)
	}
	if _, stale := c[observation.String()]; stale || c[survivor.String()] == nil {
		t.Errorf("candidates after the merge = %v, want the survivor in the merged-away device's place", c)
	}
	gw, c = read(both)
	if gw != survivor || len(c) != 0 {
		t.Errorf("network the survivor was a candidate for = gateway %s, candidates %v; want the survivor and none", gw, c)
	}
}
