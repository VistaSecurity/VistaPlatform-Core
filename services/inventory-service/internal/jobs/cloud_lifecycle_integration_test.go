package jobs

// ADR-0009 D6 through the REAL stale-asset job: a cloud resource its account's
// listing completed without returning moves monitoring → stale on its class's
// window, a provider-reported terminal state moves it at once with the state
// as the reason, and a listing that never completed proves nothing.
//
// MUTATION-VERIFIED (see the PR): deleting the SweepCloudDisappearance call in
// processTenant, or the `absent && !stale` rule in decideCloudLifecycle, turns
// this red.
//
// Skips without TEST_DATABASE_URL.

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func insertCloudAsset(t *testing.T, db *database.DB, tenant uuid.UUID, class string) uuid.UUID {
	t.Helper()
	id := uuid.New()
	if _, err := db.Exec(`
		INSERT INTO assets (id, tenant_id, hostname, class_key, class_path, asset_status, last_seen_at, first_discovered_at, created_at, updated_at)
		VALUES ($1, $2, $3, $4, 'cloud_resource.' || $4, 'monitoring', NOW(), NOW(), NOW(), NOW())`,
		id, tenant, class+"-"+id.String()[:8], class); err != nil {
		t.Fatalf("insert %s: %v", class, err)
	}
	return id
}

func insertCloudFact(t *testing.T, db *database.DB, tenant, asset uuid.UUID, key string, value any) {
	t.Helper()
	raw, _ := json.Marshal(value)
	if _, err := db.Exec(`
		INSERT INTO asset_facts (tenant_id, asset_id, key, value, source_kind, source_ref, observed_at)
		VALUES ($1, $2, $3, $4::jsonb, 'measured', 'cloud:aws', NOW())`, tenant, asset, key, string(raw)); err != nil {
		t.Fatalf("insert fact %s: %v", key, err)
	}
}

func hostOn(t *testing.T, db *database.DB, tenant, from, to uuid.UUID) {
	t.Helper()
	if _, err := db.Exec(`
		INSERT INTO asset_relationships (tenant_id, from_asset_id, to_asset_id, type, status)
		VALUES ($1, $2, $3, 'hosted_on', 'active')`, tenant, from, to); err != nil {
		t.Fatalf("hosted_on: %v", err)
	}
}

func TestIntegration_CloudLifecycle_AbsenceAndTerminalStateGoStale(t *testing.T) {
	det, db, raw := newDetector(t)
	tenant := testdb.NewTenant(t, raw)
	now := time.Now().UTC()
	ts := func(d time.Duration) string { return now.Add(d).Format(time.RFC3339Nano) }

	account := insertCloudAsset(t, db, tenant, "cloud_account")
	insertCloudFact(t, db, tenant, account, "cloud.enumeration_coverage", map[string]string{
		"compute_instances@us-east-1": ts(-time.Hour),
		"s3@global":                   ts(-time.Hour),
		// eu-west-1 was refused: no coverage key, so nothing there can be absent.
	})

	resource := func(class, listing string, lastListed time.Duration, state string) uuid.UUID {
		id := insertCloudAsset(t, db, tenant, class)
		hostOn(t, db, tenant, id, account)
		insertCloudFact(t, db, tenant, id, "cloud.listing", listing)
		insertCloudFact(t, db, tenant, id, "cloud.last_enumerated_at", ts(lastListed))
		if state != "" {
			insertCloudFact(t, db, tenant, id, "cloud.provider_state", state)
		}
		return id
	}
	gone := resource("compute_instance", "compute_instances@us-east-1", -48*time.Hour, "running")
	present := resource("compute_instance", "compute_instances@us-east-1", -time.Hour, "running")
	terminated := resource("compute_instance", "compute_instances@us-east-1", -time.Hour, "terminated")
	unlooked := resource("compute_instance", "compute_instances@eu-west-1", -72*time.Hour, "running")
	// A bucket absent for two days is inside the tenant's 30-day window.
	bucket := resource("object_storage", "s3@global", -48*time.Hour, "")

	if err := det.processTenant(context.Background(), tenant); err != nil {
		t.Fatalf("processTenant: %v", err)
	}

	want := map[uuid.UUID]string{gone: "stale", terminated: "stale", present: "", unlooked: "", bucket: ""}
	for id, w := range want {
		got := ""
		if s := staleStatus(t, db, id); s != nil {
			got = *s
		}
		if got != w {
			t.Errorf("asset %s stale_status = %q, want %q", id, got, w)
		}
	}

	reason := func(id uuid.UUID) string {
		var r string
		if err := db.QueryRow(`SELECT changes_json->>'reason' FROM asset_history WHERE asset_id = $1 AND source = 'lifecycle' ORDER BY created_at DESC LIMIT 1`, id).Scan(&r); err != nil {
			t.Fatalf("history for %s: %v", id, err)
		}
		return r
	}
	if r := reason(gone); r != "absent_from_listing:compute_instances@us-east-1" {
		t.Errorf("gone reason = %q", r)
	}
	if r := reason(terminated); r != "provider_state:terminated" {
		t.Errorf("terminated reason = %q", r)
	}

	// Nothing is deleted: the stale rows are still there and still monitoring.
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM assets WHERE id IN ($1, $2) AND deleted_at IS NULL AND asset_status = 'monitoring'`, gone, terminated).Scan(&n); err != nil || n != 2 {
		t.Errorf("stale resources still present = %d, %v; want 2", n, err)
	}

	// Listed again → back to active.
	if _, err := db.Exec(`UPDATE asset_facts SET value = to_jsonb($3::text) WHERE asset_id = $1 AND key = $2`,
		gone, "cloud.last_enumerated_at", ts(0)); err != nil {
		t.Fatal(err)
	}
	if err := det.processTenant(context.Background(), tenant); err != nil {
		t.Fatalf("processTenant (re-listed): %v", err)
	}
	if s := staleStatus(t, db, gone); s != nil {
		t.Errorf("re-listed resource stale_status = %q, want cleared", *s)
	}
}
