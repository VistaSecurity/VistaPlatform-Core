package security

import (
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
	_ "github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// The Security ▸ Dashboard read path, against a real Postgres.
//
// The bug this pins: the dashboard read public.security_events, a table with six
// readers and zero writers, so every panel showed a confident zero forever. It
// now reads audit.activity_logs, which every service writes to. A mock cannot
// prove that — the whole point is whether the rows a producer actually inserts
// come back — so this is a DB-integration test.
//
// audit.activity_logs is partitioned by occurred_at and RLS-policied on
// tenant_id, and platform-user rows carry a NULL tenant_id. Both facts are why
// the queries run on the bypass handle; a plain-role connection would return
// nothing at all. testdb.Connect hands back the owner connection, which likewise
// bypasses RLS, so it stands in for bypassDB here.
//
// Skips unless TEST_DATABASE_URL is set — run `make test-integration-db`.

// insertActivity writes one audit.activity_logs row and registers its cleanup.
func insertActivity(t *testing.T, db *sql.DB, row activityRow) uuid.UUID {
	t.Helper()
	id := uuid.New()
	_, err := db.Exec(`
		INSERT INTO audit.activity_logs (
			id, tenant_id, user_id, user_type, user_email,
			event_type, event_category, action, success, error_message,
			requires_attention, ip_address, occurred_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
		id, row.tenantID, row.userID, row.userType, row.userEmail,
		row.eventType, row.category, row.action, row.success, row.errorMessage,
		row.requiresAttention, row.ip, row.occurredAt,
	)
	if err != nil {
		t.Fatalf("insert activity log (%s/%s): %v", row.category, row.action, err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM audit.activity_logs WHERE id = $1`, id) })
	return id
}

type activityRow struct {
	tenantID          *uuid.UUID
	userID            *uuid.UUID
	userType          string
	userEmail         string
	eventType         string
	category          string
	action            string
	success           bool
	errorMessage      *string
	requiresAttention bool
	ip                string
	occurredAt        time.Time
}

// seedTrail writes one row of each interesting kind and returns the tenant it
// scoped them to. Everything is inside the last minute so any dashboard range
// covers it.
func seedTrail(t *testing.T, db *sql.DB) uuid.UUID {
	t.Helper()
	tenantID := testdb.NewTenant(t, db)
	now := time.Now().UTC()
	badCreds := "invalid credentials"

	// Security-relevant, and each in a different bucket.
	insertActivity(t, db, activityRow{
		tenantID: &tenantID, userType: "tenant", userEmail: "user@example.com",
		eventType: "auth.login", category: "authentication", action: "login",
		success: false, errorMessage: &badCreds, ip: "203.0.113.10", occurredAt: now,
	})
	insertActivity(t, db, activityRow{
		tenantID: &tenantID, userType: "tenant", userEmail: "user@example.com",
		eventType: "auth.login", category: "authentication", action: "login",
		success: true, ip: "203.0.113.10", occurredAt: now,
	})
	// Platform-user row: NULL tenant_id. Invisible to the app role under RLS —
	// which is exactly the row a platform security dashboard most needs to show.
	insertActivity(t, db, activityRow{
		userType: "platform", userEmail: "staff@example.com",
		eventType: "config.update", category: "config", action: "update_security_policy",
		success: true, ip: "198.51.100.4", occurredAt: now,
	})
	insertActivity(t, db, activityRow{
		tenantID: &tenantID, userType: "platform", userEmail: "staff@example.com",
		eventType: "user.role_changed", category: "user", action: "grant_role",
		success: true, requiresAttention: true, ip: "198.51.100.4", occurredAt: now,
	})
	// NOT security-relevant: a successful, unflagged row in an unrelated category.
	// It must be excluded from both the list and every count.
	insertActivity(t, db, activityRow{
		tenantID: &tenantID, userType: "tenant", userEmail: "user@example.com",
		eventType: "asset.viewed", category: "asset", action: "list_assets",
		success: true, ip: "203.0.113.10", occurredAt: now,
	})
	// A FAILED row in that same unrelated category — pulled in by the failure arm
	// of the filter, proving the arm is live and not decorative.
	insertActivity(t, db, activityRow{
		tenantID: &tenantID, userType: "tenant", userEmail: "user@example.com",
		eventType: "asset.export", category: "asset", action: "export_assets",
		success: false, ip: "203.0.113.10", occurredAt: now,
	})
	return tenantID
}

func TestIntegration_SecurityEvents_ReadFromActivityTrail(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	tenantID := seedTrail(t, db)

	svc := NewService(db, db)

	events, total, err := svc.GetSecurityEvents(map[string]interface{}{"tenant_id": tenantID.String()}, 50, 0)
	if err != nil {
		t.Fatalf("GetSecurityEvents: %v", err)
	}

	// The five tenant-scoped rows minus the successful `asset` one = 4.
	if total != 4 {
		t.Fatalf("total = %d, want 4 (the successful asset row must be excluded); got events: %+v", total, events)
	}
	if len(events) != 4 {
		t.Fatalf("len(events) = %d, want 4", len(events))
	}

	// This is the assertion the old code could never satisfy: real rows, with
	// their columns populated, not an empty slice behind a 200.
	byAction := map[string]SecurityEvent{}
	for _, e := range events {
		byAction[e.Action] = e
	}
	for _, want := range []string{"login", "grant_role", "export_assets"} {
		if _, ok := byAction[want]; !ok {
			t.Fatalf("action %q missing from %d returned events", want, len(events))
		}
	}
	if _, ok := byAction["list_assets"]; ok {
		t.Fatal("a successful, unflagged asset event leaked into the security view — the security-relevance filter is not applied")
	}

	grant := byAction["grant_role"]
	if !grant.RequiresAttention {
		t.Error("requires_attention did not survive the read")
	}
	if grant.UserEmail == nil || *grant.UserEmail != "staff@example.com" {
		t.Errorf("user_email = %v, want staff@example.com", grant.UserEmail)
	}
	// host() must render a bare address: the ::text form appends /32 and then
	// never matches a plain IP anywhere downstream.
	if grant.SourceIP == nil || *grant.SourceIP != "198.51.100.4" {
		t.Errorf("source_ip = %v, want a bare 198.51.100.4", grant.SourceIP)
	}

	fail := byAction["export_assets"]
	if fail.Success {
		t.Error("export_assets came back successful — the success column did not survive the read")
	}
}

// The NULL-tenant platform rows are the ones an operator most needs and the ones
// RLS hides from the app role. Unfiltered, the platform view must include them.
func TestIntegration_SecurityEvents_IncludePlatformRowsWithNoTenant(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)
	seedTrail(t, db)

	svc := NewService(db, db)
	events, _, err := svc.GetSecurityEvents(map[string]interface{}{
		"start_time": time.Now().Add(-5 * time.Minute),
	}, 100, 0)
	if err != nil {
		t.Fatalf("GetSecurityEvents: %v", err)
	}

	for _, e := range events {
		if e.Action == "update_security_policy" && e.TenantID == nil {
			return
		}
	}
	t.Fatalf("the NULL-tenant platform config event is not in the %d-row platform view", len(events))
}

func TestIntegration_SecurityDashboardStats_CountRealRows(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)

	svc := NewService(db, db)

	// Baseline first: this table is shared with whatever else the suite wrote,
	// so assert on the DELTA our seed causes, not on absolute totals.
	before, err := svc.GetSecurityDashboardStats("1h")
	if err != nil {
		t.Fatalf("GetSecurityDashboardStats (before): %v", err)
	}

	seedTrail(t, db)

	after, err := svc.GetSecurityDashboardStats("1h")
	if err != nil {
		t.Fatalf("GetSecurityDashboardStats (after): %v", err)
	}

	delta := func(key string) int {
		return after[key].(int) - before[key].(int)
	}

	// 4 tenant-scoped security-relevant + 1 NULL-tenant platform row = 5.
	if got := delta("total_events"); got != 5 {
		t.Errorf("total_events delta = %d, want 5", got)
	}
	// The failed login and the failed asset export.
	if got := delta("failed_events"); got != 2 {
		t.Errorf("failed_events delta = %d, want 2", got)
	}
	// Only the failed login is in the authentication category.
	if got := delta("failed_logins"); got != 1 {
		t.Errorf("failed_logins delta = %d, want 1", got)
	}
	if got := delta("requires_attention"); got != 1 {
		t.Errorf("requires_attention delta = %d, want 1", got)
	}

	beforeCat := before["events_by_category"].(map[string]int)
	afterCat := after["events_by_category"].(map[string]int)
	if got := afterCat["authentication"] - beforeCat["authentication"]; got != 2 {
		t.Errorf("events_by_category[authentication] delta = %d, want 2", got)
	}
	if got := afterCat["config"] - beforeCat["config"]; got != 1 {
		t.Errorf("events_by_category[config] delta = %d, want 1", got)
	}

	// events_by_outcome is derived from the same totals, so succeeded+failed must
	// equal total_events exactly — two independent queries could disagree.
	outcome := after["events_by_outcome"].(map[string]int)
	if outcome["succeeded"]+outcome["failed"] != after["total_events"].(int) {
		t.Errorf("events_by_outcome %v does not sum to total_events %v", outcome, after["total_events"])
	}
}
