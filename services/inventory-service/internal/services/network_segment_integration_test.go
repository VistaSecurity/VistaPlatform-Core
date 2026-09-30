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
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/approval"
	pgidentity "github.com/vistasecurity/vistaplatform/shared/identity/postgres"
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
	// The rule is found by the `network.segment_id=<uuid>` TERM in its query,
	// the same way ManageAutoApprovalRules finds the rule it owns. A LIKE over
	// the text would be the fragile form; this asserts the term is there.
	getRule := func() {
		t.Helper()
		var rows []struct {
			ID        uuid.UUID  `db:"id"`
			IsActive  bool       `db:"is_active"`
			CreatedBy *uuid.UUID `db:"created_by"`
			Query     string     `db:"query"`
		}
		err := database.WithTenantTx(t.Context(), svc.db, tenant, func(tx *sqlx.Tx) error {
			return tx.Select(&rows, `SELECT id, is_active, created_by, query
				FROM discovery_auto_approval_rules WHERE tenant_id = $1`, tenant)
		})
		if err != nil {
			t.Fatalf("rule lookup: %v", err)
		}
		found := false
		for _, r := range rows {
			if segID, ok := approval.SegmentIDFromQuery(r.Query); ok && segID == seg.ID {
				rule.ID, rule.IsActive, rule.CreatedBy = r.ID, r.IsActive, r.CreatedBy
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("no rule names segment %s (save without user context did not create the rule?); rows=%+v", seg.ID, rows)
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

// --- DHCP posture ( Phase 1a) ------------------------------------------
//
// A segment's DHCP posture has three authors — an operator (PUT `dhcp`), a
// device that measured it, traffic that implied it — and a precedence between
// them. These tests drive the REAL paths: the operator through
// NetworkSegmentService.Update, the other two through the shared helper both
// services call, and they read the answer back the two ways it matters — the
// API's view of the segment and what identity's ScopeForAddress sees.

func TestIntegration_SegmentPosture_PrecedenceMatrix(t *testing.T) {
	svc, tenant := newSegmentFixture(t)
	ctx := context.Background()
	db := svc.db.DB.DB

	seg, err := svc.Create(tenant, models.NetworkSegmentInput{
		Name: "lan", SegmentType: "cidr", Value: "192.0.2.0/24",
		NetworkType: "private", Environment: "production",
	})
	if err != nil {
		t.Fatal(err)
	}
	if seg.Dynamic != nil || seg.DynamicSource != nil {
		t.Fatalf("a segment nobody has spoken for reports dynamic=%v source=%v — unknown must not read as off", seg.Dynamic, seg.DynamicSource)
	}

	base := time.Date(2026, 9, 29, 9, 0, 0, 0, time.UTC)
	step := 0
	record := func(src pgidentity.PostureSource, dynamic bool) {
		t.Helper()
		step++
		if _, err := pgidentity.RecordSegmentPosture(ctx, db, tenant.String(), seg.ID.String(), src, dynamic,
			pgidentity.PostureEvidence{ObservedAt: base.Add(time.Duration(step) * time.Minute)}); err != nil {
			t.Fatal(err)
		}
	}
	operator := func(v models.OptionalBool) {
		t.Helper()
		if _, err := svc.Update(tenant, seg.ID, models.NetworkSegmentInput{
			Name: "lan", SegmentType: "cidr", Value: "192.0.2.0/24",
			NetworkType: "private", Environment: "production", DHCP: v,
		}); err != nil {
			t.Fatal(err)
		}
	}
	set := func(v bool) models.OptionalBool { return models.OptionalBool{Set: true, Value: &v} }
	clear := models.OptionalBool{Set: true}

	// expect reads the segment back both ways and compares.
	expect := func(what string, wantDyn *bool, wantSrc string) {
		t.Helper()
		got, err := svc.GetByID(tenant, seg.ID)
		if err != nil || got == nil {
			t.Fatalf("%s: read: %v", what, err)
		}
		gotSrc := ""
		if got.DynamicSource != nil {
			gotSrc = *got.DynamicSource
		}
		if gotSrc != wantSrc || (got.Dynamic == nil) != (wantDyn == nil) || (wantDyn != nil && *got.Dynamic != *wantDyn) {
			t.Fatalf("%s: API says dynamic=%v source=%q, want %v %q", what, got.Dynamic, gotSrc, wantDyn, wantSrc)
		}
		// What identity acts on. Unset is static; that is the reader's default.
		_, identityDynamic, err := pgidentity.New(db).ScopeForAddress(ctx, tenant.String(), netip.MustParseAddr("192.0.2.10"), "")
		if err != nil {
			t.Fatal(err)
		}
		if want := wantDyn != nil && *wantDyn; identityDynamic != want {
			t.Fatalf("%s: ScopeForAddress dynamic = %v, want %v", what, identityDynamic, want)
		}
	}
	yes, no := boolPtr(true), boolPtr(false)

	record(pgidentity.PostureInferred, true)
	expect("inferred alone is used", yes, "inferred")

	record(pgidentity.PostureMeasured, false)
	expect("measured beats inferred", no, "measured")

	record(pgidentity.PostureInferred, true)
	expect("inferred does not overwrite measured", no, "measured")

	record(pgidentity.PostureMeasured, true)
	expect("same rank: the newest measurement wins", yes, "measured")

	operator(set(false))
	expect("operator beats measured", no, "operator")

	record(pgidentity.PostureMeasured, true)
	expect("a measurement does not overwrite the operator", no, "operator")

	record(pgidentity.PostureInferred, true)
	expect("inference does not overwrite the operator", no, "operator")

	operator(set(true))
	expect("same rank: the operator's newest answer wins", yes, "operator")

	operator(models.OptionalBool{})
	expect("an update that omits dhcp leaves the posture alone", yes, "operator")

	operator(set(false))
	operator(clear)
	expect("null clears the operator and falls back to the measurement", yes, "measured")

	operator(clear)
	expect("clearing again changes nothing", yes, "measured")
}

func TestIntegration_SegmentPosture_ClearWithNothingElseLeavesItUnknown(t *testing.T) {
	svc, tenant := newSegmentFixture(t)
	seg, err := svc.Create(tenant, models.NetworkSegmentInput{
		Name: "lan", SegmentType: "cidr", Value: "198.51.100.0/24", NetworkType: "private", Environment: "production",
		DHCP: models.OptionalBool{Set: true, Value: boolPtr(true)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if seg.Dynamic == nil || !*seg.Dynamic || seg.DynamicSource == nil || *seg.DynamicSource != "operator" {
		t.Fatalf("create with dhcp:true = %v/%v", seg.Dynamic, seg.DynamicSource)
	}
	seg, err = svc.Update(tenant, seg.ID, models.NetworkSegmentInput{
		Name: "lan", SegmentType: "cidr", Value: "198.51.100.0/24", NetworkType: "private", Environment: "production",
		DHCP: models.OptionalBool{Set: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if seg.Dynamic != nil || seg.DynamicSource != nil {
		t.Fatalf("withdrawing the only statement left dynamic=%v source=%v, want unknown", seg.Dynamic, seg.DynamicSource)
	}
}

// A client that sends `metadata` without the posture keys — every client
// written before the field existed — must not erase a measurement or the
// operator's answer by doing so.
func TestIntegration_SegmentPosture_MetadataRewriteCannotEraseIt(t *testing.T) {
	svc, tenant := newSegmentFixture(t)
	db := svc.db.DB.DB
	seg, err := svc.Create(tenant, models.NetworkSegmentInput{
		Name: "lan", SegmentType: "cidr", Value: "203.0.113.0/24", NetworkType: "private", Environment: "production",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pgidentity.RecordSegmentPosture(context.Background(), db, tenant.String(), seg.ID.String(),
		pgidentity.PostureMeasured, true, pgidentity.PostureEvidence{}); err != nil {
		t.Fatal(err)
	}
	upd, err := svc.Update(tenant, seg.ID, models.NetworkSegmentInput{
		Name: "lan", SegmentType: "cidr", Value: "203.0.113.0/24", NetworkType: "private", Environment: "production",
		Metadata: map[string]interface{}{"note": "hand written", "dynamic": false, "dynamic_source": "operator"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if upd.Dynamic == nil || !*upd.Dynamic || upd.DynamicSource == nil || *upd.DynamicSource != "measured" {
		t.Fatalf("a metadata rewrite changed the posture: dynamic=%v source=%v", upd.Dynamic, upd.DynamicSource)
	}
	if upd.Metadata["note"] != "hand written" {
		t.Fatalf("the rest of the caller's metadata was dropped: %v", upd.Metadata)
	}
}

func TestIntegration_SegmentPosture_OnlyAddressSegmentsTakeAnAnswer(t *testing.T) {
	svc, tenant := newSegmentFixture(t)
	_, err := svc.Create(tenant, models.NetworkSegmentInput{
		Name: "corp", SegmentType: "domain", Value: "corp.example", NetworkType: "private", Environment: "production",
		DHCP: models.OptionalBool{Set: true, Value: boolPtr(true)},
	})
	if !errors.Is(err, ErrDHCPNotApplicable) {
		t.Fatalf("dhcp:true on a domain segment: err = %v, want ErrDHCPNotApplicable", err)
	}
}

// "measured by <device>": the response names the device the answer came from.
func TestIntegration_SegmentPosture_ResponseNamesTheMeasuringDevice(t *testing.T) {
	svc, tenant := newSegmentFixture(t)
	db := svc.db.DB.DB
	assetID := seedAsset(t, svc.db, tenant, "edge-router", "server", "hardware.computer.server", "production", 0, 0).String()
	seg, err := svc.Create(tenant, models.NetworkSegmentInput{
		Name: "lan", SegmentType: "cidr", Value: "192.0.2.0/24", NetworkType: "private", Environment: "production",
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pgidentity.RecordSegmentPosture(context.Background(), db, tenant.String(), seg.ID.String(),
		pgidentity.PostureMeasured, true, pgidentity.PostureEvidence{SourceAssetID: assetID}); err != nil {
		t.Fatal(err)
	}
	got, err := svc.GetByID(tenant, seg.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.DynamicSourceName == nil || *got.DynamicSourceName != "edge-router" {
		t.Fatalf("dynamic_source_name = %v, want edge-router", got.DynamicSourceName)
	}
	list, _, err := svc.List(tenant, models.NetworkSegmentFilters{})
	if err != nil || len(list) != 1 || list[0].DynamicSourceName == nil || *list[0].DynamicSourceName != "edge-router" {
		t.Fatalf("list did not resolve the device name: %v %+v", err, list)
	}
	// A device that has since been deleted must not break the read.
	if _, err := db.Exec(`UPDATE assets SET deleted_at = now() WHERE id = $1`, assetID); err != nil {
		t.Fatal(err)
	}
	got, err = svc.GetByID(tenant, seg.ID)
	if err != nil || got.DynamicSourceName != nil {
		t.Fatalf("a deleted device left a name: %v %v", err, got.DynamicSourceName)
	}
}
