package services

// A merge re-points the prefix → gateway link ( slice B, spec §2; DCIM
// row 1.6): the network a merged-away device was the gateway of is routed by
// the survivor, and another device's link is untouched. Skips without
// TEST_DATABASE_URL.
//
// Mutation: drop {"prefixes", "gateway_asset_id"} from the merge's re-point
// list and the routed network is left on the merged-away device.

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_MergeProposal_RepointsPrefixGateways(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	ctx := context.Background()

	survivor := seedAsset(t, db, tenant, "gw-keep.example.test", "router", "hardware.network.router", "production", 0, 0)
	observation := seedAsset(t, db, tenant, "gw-dup.example.test", "router", "hardware.network.router", "production", 0, 0)
	bystander := seedAsset(t, db, tenant, "gw-other.example.test", "router", "hardware.network.router", "production", 0, 0)
	at := time.Date(2026, 10, 3, 9, 0, 0, 0, time.UTC)

	prefix := func(cidr string, gateway uuid.UUID) uuid.UUID {
		t.Helper()
		var id uuid.UUID
		if err := db.QueryRow(`INSERT INTO prefixes(tenant_id,description,prefix,environment,gateway_asset_id,gateway_source_ref,gateway_observed_at,source_kind,status)
			VALUES($1,$2::text,$2::text::cidr,'production',$3,'interrogation:fixture',$4,'declared','active') RETURNING id`,
			tenant, cidr, gateway, at).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	routed := prefix("192.0.2.0/24", observation)
	other := prefix("198.51.100.0/24", bystander)

	svc := NewMergeProposalService(db)
	proposal := openProposal(t, db, tenant, observation, survivor)
	if _, err := svc.Accept(ctx, tenant, proposal, survivor, seedUser(t, db, tenant)); err != nil {
		t.Fatalf("accept: %v", err)
	}

	read := func(id uuid.UUID) uuid.UUID {
		t.Helper()
		var gw uuid.UUID
		if err := db.QueryRow(`SELECT gateway_asset_id FROM prefixes WHERE id=$1`, id).Scan(&gw); err != nil {
			t.Fatal(err)
		}
		return gw
	}
	if gw := read(routed); gw != survivor {
		t.Errorf("the merged-away device's network is routed by %s, want the survivor %s", gw, survivor)
	}
	if gw := read(other); gw != bystander {
		t.Errorf("a merge moved another device's link: %s", gw)
	}
}
