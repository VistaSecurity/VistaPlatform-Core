package jobs

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// The job that keeps the audit partitions ahead of the clock keeps the DCIM
// change record's ahead too (DCIM BUILD_PLAN row 0.3). A scratch database,
// because the test drops a partition. Mutation: remove the
// ensureObjectChangePartitions call from ensurePartitions → the dropped month
// is not re-created and this fails.
func TestIntegration_PartitionManager_KeepsObjectChangesAhead(t *testing.T) {
	db := testdb.ScratchDatabase(t)
	now := time.Now().UTC()
	target := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC).AddDate(0, objectChangesMonthsAhead, 0)
	name := fmt.Sprintf("object_changes_y%dm%02d", target.Year(), int(target.Month()))

	if _, err := db.Exec(`DROP TABLE public.` + name); err != nil {
		t.Fatalf("drop %s (the schema apply should have made it): %v", name, err)
	}
	NewPartitionManager(db).ensurePartitions(context.Background())

	var exists bool
	if err := db.QueryRow(`SELECT to_regclass('public.' || $1) IS NOT NULL`, name).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if !exists {
		t.Fatalf("PartitionManager did not re-create %s", name)
	}
}

// The change log has its own retention (admin-ui → Security → Retention,
// "Inventory change log"): an active policy whose event_type is
// `inventory.change_log` decides which object_changes months the job drops,
// ahead of the general audit policy it otherwise follows (DCIM BUILD_PLAN row
// 5.2). Mutation: drop the change-log lookup from
// drop_expired_object_changes_partitions → the 30-day policy is ignored, the
// 10-year general one keeps the month, and this fails.
func TestIntegration_PartitionManager_ObjectChangesHonoursItsOwnRetention(t *testing.T) {
	db := testdb.ScratchDatabase(t)
	exists := func(name string) bool {
		var ok bool
		if err := db.QueryRow(`SELECT to_regclass('public.' || $1) IS NOT NULL`, name).Scan(&ok); err != nil {
			t.Fatal(err)
		}
		return ok
	}
	if _, err := db.Exec(`SELECT public.create_object_changes_partition(2020, 1)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO audit.retention_policies (policy_name, hot_storage_days, total_retention_days) VALUES ('it-general', 30, 3650)`); err != nil {
		t.Fatal(err)
	}
	pm := NewPartitionManager(db)

	// Only the 10-year general policy: 2020-01 is inside it.
	pm.ensurePartitions(context.Background())
	if !exists("object_changes_y2020m01") {
		t.Fatal("dropped under a 10-year general policy")
	}
	// An inactive change-log policy is ignored.
	if _, err := db.Exec(`INSERT INTO audit.retention_policies (policy_name, event_type, hot_storage_days, total_retention_days, is_active)
		VALUES ('Inventory change log', 'inventory.change_log', 30, 30, false)`); err != nil {
		t.Fatal(err)
	}
	pm.ensurePartitions(context.Background())
	if !exists("object_changes_y2020m01") {
		t.Fatal("an inactive change-log policy dropped a partition")
	}
	// Active at 30 days: the old month goes, the current one stays.
	if _, err := db.Exec(`UPDATE audit.retention_policies SET is_active = true WHERE policy_name = 'Inventory change log'`); err != nil {
		t.Fatal(err)
	}
	pm.ensurePartitions(context.Background())
	if exists("object_changes_y2020m01") {
		t.Fatal("the 30-day change-log policy did not drop a 2020 partition")
	}
	now := time.Now().UTC()
	if cur := fmt.Sprintf("object_changes_y%dm%02d", now.Year(), int(now.Month())); !exists(cur) {
		t.Fatalf("the current month %s was dropped", cur)
	}
}
