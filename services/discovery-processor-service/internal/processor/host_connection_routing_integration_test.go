package processor

// This drives host-inventory connection rows through the real batch processor
// against inventory's import (routeInventoryStandIn, the real handler's
// response shape). Since WP3 every row takes the one door — the import —
// and inventory decides ownership, approval and external_connections; the test
// asserts what crossed that wire and how each row was settled from the
// answer.

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/converter"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_HostConnectionsUseOwnershipApprovalAndSourceAssetRouting(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := sqlx.NewDb(raw, "postgres")
	tenant := testdb.NewTenant(t, raw)
	ruleID, sourceAssetID := uuid.New(), uuid.New()

	inv := newRouteInventoryStandIn(t)
	// 10.40.0.15 is in a registered segment whose rule auto-approves it.
	inv.ownership["10.40.0.15"] = "internal"
	inv.rules["10.40.0.15"] = ruleID
	processor := NewBatchProcessor(db, converter.NewSensorDiscoveryConverter(), inv.client(t), nil)

	batchID, sensorID := uuid.New().String(), uuid.New()
	for _, peer := range []struct {
		ip   string
		port int
	}{{"8.8.8.8", 443}, {"10.40.0.15", 8443}, {"10.50.0.15", 9443}} {
		metadata, _ := json.Marshal(map[string]any{
			"discovery_method": "host_inventory", "discovery_type": "host_connection",
			"source_asset_id": sourceAssetID.String(), "source_agent_id": uuid.New().String(),
		})
		if _, err := raw.Exec(`INSERT INTO sensor_discoveries
			(id,sensor_id,tenant_id,batch_id,protocol,dest_ip,port,confidence,metadata,source_ip,timestamp,created_at)
			VALUES($1,$2,$3,$4,'tcp',$5::inet,$6,1,$7::jsonb,'10.1.2.3'::inet,now(),now())`,
			uuid.New(), sensorID, tenant, batchID, peer.ip, peer.port, metadata); err != nil {
			t.Fatal(err)
		}
	}

	if err := processor.ProcessBatch(batchID, tenant); err != nil {
		t.Fatalf("ProcessBatch: %v", err)
	}
	inv.assertOnlyImports(t)

	imported := inv.allImported()
	if len(imported) != 3 {
		t.Fatalf("imported %d findings, want all 3 — the public one included", len(imported))
	}
	for _, finding := range imported {
		if finding.RawData["source_asset_id"] != sourceAssetID.String() {
			t.Errorf("source_asset_id lost on the way to inventory: %#v", finding.RawData)
		}
		if finding.RawData["source_ip"] != "10.1.2.3" {
			t.Errorf("source_ip lost on the way to inventory: %#v", finding.RawData)
		}
	}
	routed := inv.routedFindings()
	if len(routed) != 1 || routed[0].IPAddress == nil || *routed[0].IPAddress != "8.8.8.8" {
		t.Fatalf("routed = %#v, want the public connection alone", routed)
	}

	rows, err := raw.Query(`SELECT host(dest_ip),approval_status,auto_approval_rule_id FROM sensor_discoveries
		WHERE tenant_id=$1 AND batch_id=$2 ORDER BY host(dest_ip)`, tenant, batchID)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	want := map[string]struct {
		status string
		rule   *uuid.UUID
	}{
		// routed: evidence recorded elsewhere, no approval decision will
		// follow (applyIngestOutcome).
		"8.8.8.8":    {"observed", nil},
		"10.40.0.15": {"auto_approved", &ruleID},
		"10.50.0.15": {"pending", nil},
	}
	for rows.Next() {
		var ip, status string
		var gotRule *uuid.UUID
		if err := rows.Scan(&ip, &status, &gotRule); err != nil {
			t.Fatal(err)
		}
		expect := want[ip]
		if status != expect.status || (expect.rule != nil && (gotRule == nil || *gotRule != *expect.rule)) || (expect.rule == nil && gotRule != nil) {
			t.Errorf("%s status/rule = %s/%v, want %s/%v", ip, status, gotRule, expect.status, expect.rule)
		}
		delete(want, ip)
	}
	if len(want) != 0 {
		t.Fatalf("missing processed discoveries: %#v", want)
	}
}
