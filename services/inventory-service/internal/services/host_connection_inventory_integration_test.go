package services

// DB-backed acceptance for the managed half of host connection routing. The
// discovery processor supplies pending_approval while a private peer is in no
// registered network, then monitoring after an auto-approving segment covers
// it. Inventory must match and promote the original asset rather than create a
// second host or leave the first one stuck in Approvals.

import (
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/identity/identifiersql"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_HostConnection_PendingPrivatePeerPromotesAfterNetworkRegistration(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	assets := NewAssetService(db)

	address, port := "10.77.0.15", 8443
	finding := IngestFinding{
		IPAddress: &address, Port: &port, Protocol: "tcp", AssetType: "server",
		RawData: map[string]interface{}{
			"source": "sensor_discovery", "source_ip": "10.1.2.3",
			"discovery_method": "host_inventory", "discovery_type": "host_connection",
		},
	}
	if _, err := assets.IngestFindingsReport(tenant, []IngestFinding{finding}, identity.StatusPendingApproval); err != nil {
		t.Fatalf("initial pending ingest: %v", err)
	}

	var assetID uuid.UUID
	var status string
	if err := raw.QueryRow(`SELECT id,asset_status FROM assets WHERE tenant_id=$1 AND primary_address=$2::inet AND deleted_at IS NULL`, tenant, address).Scan(&assetID, &status); err != nil {
		t.Fatal(err)
	}
	if status != identity.StatusPendingApproval {
		t.Fatalf("unregistered private peer landed %q, want pending approval", status)
	}
	var priorScope string
	if err := raw.QueryRow(`SELECT scope FROM (`+identifiersql.All+`) ident_rows WHERE tenant_id=$1 AND asset_id=$2 AND kind='ip_address'`, tenant, assetID).Scan(&priorScope); err != nil {
		t.Fatalf("read initial address identity: %v", err)
	}
	t.Logf("initial address identity scope: %s", priorScope)

	// Declaring the prefix with auto-approve writes its rule (the prefix's own
	// write, prefix_approval_rules.go).
	prefix := declarePrefix(t, raw, tenant, map[string]any{
		"prefix": "10.77.0.0/24", "description": "newly registered host peers",
		"network_type": "private", "environment": "production", "auto_approve_discoveries": true,
	})

	report, err := assets.IngestFindingsReport(tenant, []IngestFinding{finding}, identity.StatusMonitoring)
	if err != nil {
		t.Fatalf("post-registration ingest: %v", err)
	}
	if len(report.EffectiveStatus) != 1 || report.EffectiveStatus[0] != identity.StatusMonitoring {
		t.Fatalf("effective status = %v, want monitoring", report.EffectiveStatus)
	}
	var gotID uuid.UUID
	var gotSegment *uuid.UUID
	if err := raw.QueryRow(`SELECT id,asset_status,prefix_id FROM assets WHERE tenant_id=$1 AND primary_address=$2::inet AND deleted_at IS NULL`, tenant, address).Scan(&gotID, &status, &gotSegment); err != nil {
		t.Fatal(err)
	}
	if gotID != assetID || status != identity.StatusMonitoring || gotSegment == nil || *gotSegment != prefix {
		t.Fatalf("asset after registration = id %s status %s prefix %v; want same id %s, monitoring, prefix %s", gotID, status, gotSegment, assetID, prefix)
	}
	var count int
	if err := raw.QueryRow(`SELECT count(*) FROM assets WHERE tenant_id=$1 AND primary_address=$2::inet AND deleted_at IS NULL`, tenant, address).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("network registration produced %d assets for one peer", count)
	}
}
