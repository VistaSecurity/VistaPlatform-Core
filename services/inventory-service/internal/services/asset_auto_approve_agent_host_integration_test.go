package services

// AutoApproveAgentHost against a real Postgres.
//
// What is pinned: a pending host moves to monitoring with a history row that
// names the agent and no actor; a second call is a no-op that says so; a
// DENIED host is left denied — installing an agent on a host a person refused
// is not that person changing their mind — and a host that is already
// monitoring is untouched. The negative cases are the reason the method exists
// separately from ApproveAssets, which moves anything it is handed.

import (
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func newAgentHostApprovalFixture(t *testing.T) (*AssetService, *sqlx.DB, uuid.UUID) {
	t.Helper()
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)

	segSvc := NewNetworkSegmentService(db, NewLocationService(db))
	assetSvc := NewAssetService(db)
	assetSvc.SetEnrichmentServices(segSvc, nil)
	// A segment that does NOT auto-approve, so every asset created here lands
	// pending — the state the agent-host path is about.
	if _, err := segSvc.Create(tenant, models.NetworkSegmentInput{
		Name: "manual review", SegmentType: "cidr", Value: "198.51.100.0/24",
		NetworkType: "private", Environment: "production",
		AutoApproveDiscoveries: boolPtr(false),
	}); err != nil {
		t.Fatalf("create manual segment: %v", err)
	}
	return assetSvc, db.DB, tenant
}

func pendingHost(t *testing.T, svc *AssetService, tenant uuid.UUID, ip, name string) uuid.UUID {
	t.Helper()
	a, err := svc.CreateAsset(tenant, models.AssetInput{
		ClassKey: assetclass.KeyServer, IPAddress: strPtr(ip), Hostname: strPtr(name),
	})
	if err != nil {
		t.Fatalf("create %s: %v", name, err)
	}
	if a.AssetStatus != "pending_approval" {
		t.Fatalf("%s landed %q, want pending_approval", name, a.AssetStatus)
	}
	return a.ID
}

func assetStatus(t *testing.T, db *sqlx.DB, tenant, asset uuid.UUID) string {
	t.Helper()
	var s string
	if err := db.QueryRow(`SELECT asset_status FROM assets WHERE tenant_id=$1 AND id=$2`, tenant, asset).Scan(&s); err != nil {
		t.Fatalf("read status: %v", err)
	}
	return s
}

func TestIntegration_AutoApproveAgentHost_PendingHostIsApprovedAndAttributedToTheAgent(t *testing.T) {
	svc, db, tenant := newAgentHostApprovalFixture(t)
	asset := pendingHost(t, svc, tenant, "198.51.100.20", "xps16-bob")
	agent := uuid.New()

	approved, err := svc.AutoApproveAgentHost(tenant, asset, agent)
	if err != nil {
		t.Fatalf("AutoApproveAgentHost: %v", err)
	}
	if !approved {
		t.Fatal("pending host was not approved")
	}
	if got := assetStatus(t, db, tenant, asset); got != "monitoring" {
		t.Fatalf("status = %q, want monitoring", got)
	}

	// The timeline says the AGENT did it, and nobody else.
	var action, source string
	var actor *uuid.UUID
	var changes string
	if err := db.QueryRow(`SELECT action, source, actor_user_id, changes_json::text FROM asset_history
		WHERE tenant_id=$1 AND asset_id=$2 AND action='approved' ORDER BY created_at DESC LIMIT 1`,
		tenant, asset).Scan(&action, &source, &actor, &changes); err != nil {
		t.Fatalf("no approved history row: %v", err)
	}
	if source != AgentHostApprovalSourceRef(agent) {
		t.Fatalf("history source = %q, want %q", source, AgentHostApprovalSourceRef(agent))
	}
	if actor != nil {
		t.Fatalf("history actor = %s, want none: no person approved this", *actor)
	}
	var recorded map[string]string
	if err := json.Unmarshal([]byte(changes), &recorded); err != nil {
		t.Fatalf("history changes %s: %v", changes, err)
	}
	for key, want := range map[string]string{"reason": "agent_installed", "agent_id": agent.String(), "source_kind": "measured", "asset_status": "monitoring"} {
		if recorded[key] != want {
			t.Errorf("history changes %s: %s = %q, want %q", changes, key, recorded[key], want)
		}
	}

	// Asking again is a no-op that says so.
	again, err := svc.AutoApproveAgentHost(tenant, asset, agent)
	if err != nil || again {
		t.Fatalf("second call = (%v, %v), want (false, nil)", again, err)
	}
	if n := countHistory(t, db, tenant, asset, "approved"); n != 1 {
		t.Fatalf("approved history rows = %d after a repeat call, want 1", n)
	}
}

func TestIntegration_AutoApproveAgentHost_LeavesDeniedAndMonitoringAlone(t *testing.T) {
	svc, db, tenant := newAgentHostApprovalFixture(t)
	agent := uuid.New()

	denied := pendingHost(t, svc, tenant, "198.51.100.21", "refused-host")
	if err := svc.DenyAssets(tenant, []uuid.UUID{denied}, uuid.Nil); err != nil {
		t.Fatalf("deny: %v", err)
	}
	approved, err := svc.AutoApproveAgentHost(tenant, denied, agent)
	if err != nil || approved {
		t.Fatalf("denied host: got (%v, %v), want (false, nil)", approved, err)
	}
	if got := assetStatus(t, db, tenant, denied); got != "denied" {
		t.Fatalf("denied host is now %q: an installed agent must not overturn a person's refusal", got)
	}
	if n := countHistory(t, db, tenant, denied, "approved"); n != 0 {
		t.Fatalf("denied host gained %d approved history rows", n)
	}

	live := pendingHost(t, svc, tenant, "198.51.100.22", "already-live")
	if err := svc.ApproveAssets(tenant, []uuid.UUID{live}, uuid.Nil); err != nil {
		t.Fatalf("approve: %v", err)
	}
	approved, err = svc.AutoApproveAgentHost(tenant, live, agent)
	if err != nil || approved {
		t.Fatalf("monitoring host: got (%v, %v), want (false, nil)", approved, err)
	}
	if n := countHistory(t, db, tenant, live, "approved"); n != 1 {
		t.Fatalf("monitoring host has %d approved rows, want the human's 1", n)
	}

	// An unknown asset is not an error either: the agent's next report will
	// resolve to whatever exists by then.
	approved, err = svc.AutoApproveAgentHost(tenant, uuid.New(), agent)
	if err != nil || approved {
		t.Fatalf("unknown asset: got (%v, %v), want (false, nil)", approved, err)
	}
}

func TestIntegration_AutoApproveAgentHost_RequiresBothIDs(t *testing.T) {
	svc, _, tenant := newAgentHostApprovalFixture(t)
	if _, err := svc.AutoApproveAgentHost(tenant, uuid.Nil, uuid.New()); err == nil {
		t.Error("nil asset id accepted")
	}
	if _, err := svc.AutoApproveAgentHost(tenant, uuid.New(), uuid.Nil); err == nil {
		t.Error("nil agent id accepted")
	}
}

func countHistory(t *testing.T, db *sqlx.DB, tenant, asset uuid.UUID, action string) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM asset_history WHERE tenant_id=$1 AND asset_id=$2 AND action=$3`,
		tenant, asset, action).Scan(&n); err != nil {
		t.Fatalf("count history: %v", err)
	}
	return n
}
