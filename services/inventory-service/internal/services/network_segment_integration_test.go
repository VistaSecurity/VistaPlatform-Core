package services

// Regression tests for network-segment update field semantics.
//
// auto_approve_discoveries was bound as a plain bool, so any client that
// omitted the field zeroed it on every unrelated edit. The client that did
// exactly that in production was a stale cached web-ui bundle (Caddy served
// index.html with no Cache-Control, so browsers kept a pre-toggle UI alive
// across deploys) — every segment save from it silently disabled
// auto-approval, and discoveries piled up pending. The input field is now a
// *bool with keep-current-on-omit update semantics, matching is_active.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func newSegmentFixture(t *testing.T) (*NetworkSegmentService, uuid.UUID) {
	t.Helper()
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	svc := NewNetworkSegmentService(db, NewLocationService(db))
	return svc, testdb.NewTenant(t, raw)
}

func TestIntegration_SegmentUpdate_OmittedAutoApproveKeepsCurrent(t *testing.T) {
	svc, tenant := newSegmentFixture(t)

	seg, err := svc.Create(tenant, models.NetworkSegmentInput{
		Name: "lab", SegmentType: "cidr", Value: "10.9.0.0/24",
		NetworkType: "private", Environment: "production",
		AutoApproveDiscoveries: boolPtr(true),
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if !seg.AutoApproveDiscoveries {
		t.Fatal("create with auto_approve=true did not persist true")
	}

	// An update that omits the field (nil) — e.g. an older client — must keep it.
	upd, err := svc.Update(tenant, seg.ID, models.NetworkSegmentInput{
		Name: "lab renamed", SegmentType: "cidr", Value: "10.9.0.0/24",
		NetworkType: "private", Environment: "production",
	})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if !upd.AutoApproveDiscoveries {
		t.Fatal("update omitting auto_approve_discoveries wiped it to false (keep-current-on-omit broken)")
	}

	// An explicit false must still turn it off.
	upd, err = svc.Update(tenant, seg.ID, models.NetworkSegmentInput{
		Name: "lab renamed", SegmentType: "cidr", Value: "10.9.0.0/24",
		NetworkType: "private", Environment: "production",
		AutoApproveDiscoveries: boolPtr(false),
	})
	if err != nil {
		t.Fatalf("update explicit false: %v", err)
	}
	if upd.AutoApproveDiscoveries {
		t.Fatal("update with explicit auto_approve=false did not persist false")
	}

	// An explicit true turns it back on.
	upd, err = svc.Update(tenant, seg.ID, models.NetworkSegmentInput{
		Name: "lab renamed", SegmentType: "cidr", Value: "10.9.0.0/24",
		NetworkType: "private", Environment: "production",
		AutoApproveDiscoveries: boolPtr(true),
	})
	if err != nil {
		t.Fatalf("update explicit true: %v", err)
	}
	if !upd.AutoApproveDiscoveries {
		t.Fatal("update with explicit auto_approve=true did not persist true")
	}
}

// A segment save arriving over HMAC service auth has no real user (the handler
// passes uuid.Nil). The auto-approval rule must be created anyway — the
// discovery-processor only auto-approves via discovery_auto_approval_rules, so
// skipping the INSERT left auto_approve_discoveries=true on the segment with no
// rule behind it (flag/behavior desync observed live on a dev cluster).
func TestIntegration_ManageAutoApprovalRules_NilUserStillCreatesRule(t *testing.T) {
	svc, tenant := newSegmentFixture(t)

	seg, err := svc.Create(tenant, models.NetworkSegmentInput{
		Name: "svc-auth", SegmentType: "cidr", Value: "10.7.0.0/24",
		NetworkType: "private", Environment: "production",
		AutoApproveDiscoveries: boolPtr(true),
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	if err := svc.ManageAutoApprovalRules(tenant, uuid.Nil); err != nil {
		t.Fatalf("ManageAutoApprovalRules with uuid.Nil: %v", err)
	}

	var rule struct {
		ID        uuid.UUID  `db:"id"`
		IsActive  bool       `db:"is_active"`
		CreatedBy *uuid.UUID `db:"created_by"`
	}
	getRule := func() {
		t.Helper()
		err := database.WithTenantTx(t.Context(), svc.db, tenant, func(tx *sqlx.Tx) error {
			return tx.Get(&rule, `SELECT id, is_active, created_by FROM discovery_auto_approval_rules
				WHERE tenant_id = $1 AND conditions->>'network_segment_id' = $2`, tenant, seg.ID.String())
		})
		if err != nil {
			t.Fatalf("rule lookup (save without user context did not create the rule?): %v", err)
		}
	}
	getRule()
	if !rule.IsActive {
		t.Fatal("rule created by nil-user save should be active")
	}
	if rule.CreatedBy != nil {
		t.Fatalf("nil-user save should record created_by NULL, got %v", rule.CreatedBy)
	}

	// A second nil-user pass must update the existing rule, not duplicate it or error.
	firstID := rule.ID
	if err := svc.ManageAutoApprovalRules(tenant, uuid.Nil); err != nil {
		t.Fatalf("second ManageAutoApprovalRules: %v", err)
	}
	getRule() // tx.Get errors on multiple rows, so this also proves no duplicate
	if rule.ID != firstID {
		t.Fatalf("second pass replaced the rule (%s -> %s) instead of updating it", firstID, rule.ID)
	}

	// Turning the flag off then re-running disables the rule.
	if _, err := svc.Update(tenant, seg.ID, models.NetworkSegmentInput{
		Name: "svc-auth", SegmentType: "cidr", Value: "10.7.0.0/24",
		NetworkType: "private", Environment: "production",
		AutoApproveDiscoveries: boolPtr(false),
	}); err != nil {
		t.Fatalf("update to auto_approve=false: %v", err)
	}
	if err := svc.ManageAutoApprovalRules(tenant, uuid.Nil); err != nil {
		t.Fatalf("ManageAutoApprovalRules after disable: %v", err)
	}
	getRule()
	if rule.IsActive {
		t.Fatal("rule should be disabled after auto_approve_discoveries=false")
	}
}

func TestIntegration_SegmentCreate_OmittedAutoApproveDefaultsFalse(t *testing.T) {
	svc, tenant := newSegmentFixture(t)

	seg, err := svc.Create(tenant, models.NetworkSegmentInput{
		Name: "plain", SegmentType: "cidr", Value: "10.8.0.0/24",
		NetworkType: "private", Environment: "production",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if seg.AutoApproveDiscoveries {
		t.Fatal("create omitting auto_approve_discoveries should default to false")
	}
}
