package services

// DB-integration tests for the export feed (export_feed.go): the order, the
// paging, the settle window and the head, against real Postgres. They skip
// unless TEST_DATABASE_URL is set (make test-integration-db).
//
// The feed is platform-wide, and other suites write audit.activity_logs in
// parallel, so every fixture here is stamped with a created_at in a window no
// real row can have (a year long past) and every assertion reads only that
// window.

import (
	"context"
	"database/sql"
	"sort"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/audit-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// feedFixture writes one row with an explicit created_at. occurred_at (the
// partition key) is now, in a partition the test makes sure exists.
func feedFixture(t *testing.T, db *sql.DB, id uuid.UUID, createdAt time.Time, eventType string) {
	t.Helper()
	now := time.Now()
	if _, err := db.Exec(`SELECT audit.create_activity_logs_partition($1, $2)`, now.Year(), int(now.Month())); err != nil {
		t.Fatalf("ensure partition: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO audit.activity_logs
		(id, user_type, event_type, event_category, action, old_values, metadata, user_agent, ip_address, occurred_at, created_at)
		VALUES ($1, 'platform', $2, 'system', 'feed-test', '{"secret":"do-not-export"}', '{"k":"v"}', 'agent/1', '198.51.100.9', $3, $4)`,
		id, eventType, now, createdAt); err != nil {
		t.Fatalf("insert fixture: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM audit.activity_logs WHERE id = $1`, id) })
}

// windowItems keeps only the items stamped inside [from, to).
func windowItems(items []ExportItem, from, to time.Time) []ExportItem {
	var out []ExportItem
	for _, it := range items {
		if !it.Cursor.CreatedAt.Before(from) && it.Cursor.CreatedAt.Before(to) {
			out = append(out, it)
		}
	}
	return out
}

// Rows sharing one created_at come back in id order, and paging through them
// with a small limit neither skips nor repeats one — the (created_at, id) tie
// break is what makes a cursor between two same-microsecond events exact.
func TestIntegration_ExportFeed_EqualTimestampsPageInIDOrder(t *testing.T) {
	db := testdb.Connect(t)
	svc := NewActivityLogService(db, db)
	ctx := context.Background()

	base := time.Date(2001, 2, 3, 4, 5, 6, 789000, time.UTC) // microsecond precision, as stored
	end := base.Add(time.Hour)
	ids := []uuid.UUID{uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()}
	for _, id := range ids[:4] {
		feedFixture(t, db, id, base, "feed.itest.tie") // four at the SAME instant
	}
	feedFixture(t, db, ids[4], base.Add(time.Microsecond), "feed.itest.after")

	want := append([]uuid.UUID(nil), ids[:4]...)
	sort.Slice(want, func(i, j int) bool { return want[i].String() < want[j].String() })
	want = append(want, ids[4])

	var got []uuid.UUID
	cur := ExportCursor{CreatedAt: base.Add(-time.Second), ID: uuid.Nil}
	for pages := 0; pages < 10; pages++ {
		page, err := svc.ExportPage(ctx, cur, 2, ExportSettleWindow)
		if err != nil {
			t.Fatalf("page: %v", err)
		}
		in := windowItems(page.Items, base, end)
		for _, it := range in {
			got = append(got, it.Cursor.ID)
			if it.Event["id"] != it.Cursor.ID {
				t.Errorf("item cursor id %s does not match its event id %v", it.Cursor.ID, it.Event["id"])
			}
		}
		if len(in) < len(page.Items) || !page.More {
			break // left the fixture window, or the feed ran out
		}
		cur = page.Next
	}
	if len(got) != len(want) {
		t.Fatalf("paged %d fixture events (%v); want %d (%v) — a page boundary skipped or repeated one", len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("event %d = %s; want %s — equal timestamps must sort by id", i, got[i], want[i])
		}
	}

	// A cursor sitting BETWEEN two same-instant events resumes exactly after it.
	page, err := svc.ExportPage(ctx, ExportCursor{CreatedAt: base, ID: want[1]}, 10, ExportSettleWindow)
	if err != nil {
		t.Fatal(err)
	}
	in := windowItems(page.Items, base, end)
	if len(in) < 3 || in[0].Cursor.ID != want[2] || in[1].Cursor.ID != want[3] || in[2].Cursor.ID != want[4] {
		t.Fatalf("resuming mid-tie returned %v; want %v", in, want[2:])
	}
}

// What leaves is the projection: the fixture's change diff, metadata and user
// agent never appear, and the inet column comes back as a bare address.
func TestIntegration_ExportFeed_ExportsTheProjectionOnly(t *testing.T) {
	db := testdb.Connect(t)
	svc := NewActivityLogService(db, db)
	at := time.Date(2001, 3, 4, 5, 6, 7, 0, time.UTC)
	id := uuid.New()
	feedFixture(t, db, id, at, "feed.itest.projection")

	page, err := svc.ExportPage(context.Background(), ExportCursor{CreatedAt: at.Add(-time.Second), ID: uuid.Nil}, 5, ExportSettleWindow)
	if err != nil {
		t.Fatal(err)
	}
	in := windowItems(page.Items, at, at.Add(time.Second))
	if len(in) != 1 {
		t.Fatalf("got %d fixture items; want 1", len(in))
	}
	ev := in[0].Event
	for _, k := range []string{"old_values", "new_values", "metadata", "user_agent", "session_id"} {
		if _, ok := ev[k]; ok {
			t.Errorf("the feed exported %q: %v", k, ev)
		}
	}
	if ev["ip_address"] != "198.51.100.9" || ev["event_type"] != "feed.itest.projection" {
		t.Errorf("event = %v", ev)
	}
}

// An event stored just now is held back by the settle window, and appears once
// the window is zero — so the window, not luck, is what keeps a cursor from
// passing an uncommitted row. LogActivity (the real insert) stamps created_at
// with the database clock.
func TestIntegration_ExportFeed_SettleWindowHoldsFreshEvents(t *testing.T) {
	db := testdb.Connect(t)
	svc := NewActivityLogService(db, db)
	ctx := context.Background()

	head, err := svc.ExportHead(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if _, err := db.Exec(`SELECT audit.create_activity_logs_partition($1, $2)`, now.Year(), int(now.Month())); err != nil {
		t.Fatal(err)
	}
	entry := &models.ActivityLog{UserType: "platform", EventType: "feed.itest.settle", EventCategory: "system", Action: "settle", Success: true}
	if err := svc.LogActivity(ctx, entry); err != nil {
		t.Fatalf("LogActivity: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM audit.activity_logs WHERE id = $1`, entry.ID) })

	var stored, dbNow time.Time
	if err := db.QueryRow(`SELECT created_at, clock_timestamp() FROM audit.activity_logs WHERE id = $1`, entry.ID).Scan(&stored, &dbNow); err != nil {
		t.Fatal(err)
	}
	if stored.Before(head.CreatedAt) || stored.After(dbNow) {
		t.Fatalf("created_at %s is not the database clock between %s and %s", stored, head.CreatedAt, dbNow)
	}

	contains := func(settle time.Duration) bool {
		page, err := svc.ExportPage(ctx, head, ExportPageMax, settle)
		if err != nil {
			t.Fatal(err)
		}
		for _, it := range page.Items {
			if it.Cursor.ID == entry.ID {
				return true
			}
		}
		return false
	}
	if contains(time.Hour) {
		t.Fatal("an event stored this instant was served inside the settle window")
	}
	if !contains(0) {
		t.Fatal("with no settle window the stored event was not served after the head cursor")
	}
}

// The head is "after everything stored so far"; a backfill head starts that
// far back and before any event stamped at that instant.
func TestIntegration_ExportFeed_Head(t *testing.T) {
	db := testdb.Connect(t)
	svc := NewActivityLogService(db, db)
	ctx := context.Background()
	before := time.Now().Add(-time.Minute)

	head, err := svc.ExportHead(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	if head.CreatedAt.Before(before) || head.ID != maxEventID {
		t.Fatalf("head = %+v; want now with the max id", head)
	}
	back, err := svc.ExportHead(ctx, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if d := head.CreatedAt.Sub(back.CreatedAt); d < 59*time.Minute || d > 61*time.Minute || back.ID != uuid.Nil {
		t.Fatalf("backfill head = %+v; want ~1h before %s with the nil id", back, head.CreatedAt)
	}
	if _, err := svc.ExportHead(ctx, ExportBackfillMax+time.Second); err == nil {
		t.Fatal("a backfill beyond the bound was accepted")
	}
	if _, err := svc.ExportPage(ctx, ExportCursor{}, 10, 0); err == nil {
		t.Fatal("a page with no cursor was served")
	}
}
