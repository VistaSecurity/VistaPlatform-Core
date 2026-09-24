package services

import (
	"context"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// TestIntegration_ProcessDueSchedules_SkipsBlockedTenants — a suspended,
// canceled or deleted tenant's due schedules do not fire (RC-4 /), and
// are left due, so the same schedule fires on the first sweep after the tenant
// is reactivated. Asserted per tenant (job count + next_run_at), never on the
// sweep's total, because the sweep is global and other suites seed schedules
// too. Mutation: drop the tenants EXISTS clause from ProcessDueSchedules and
// the suspended tenant gets a job.
func TestIntegration_ProcessDueSchedules_SkipsBlockedTenants(t *testing.T) {
	db := testdb.Connect(t)
	ctx := context.Background()
	svc := NewSchedulerService(db, db, NewJobQueueService(db, db, nil))

	for _, block := range []string{
		`UPDATE tenants SET payment_status = 'suspended' WHERE id = $1`,
		`UPDATE tenants SET payment_status = 'canceled' WHERE id = $1`,
		`UPDATE tenants SET deleted_at = NOW() WHERE id = $1`,
	} {
		tenant := testdb.NewTenant(t, db)
		scheduleID := seedDueSchedule(t, db, tenant, "0 * * * *")
		before := nextRunAt(t, db, scheduleID)
		if _, err := db.Exec(block, tenant); err != nil {
			t.Fatal(err)
		}

		if _, err := svc.ProcessDueSchedules(ctx); err != nil {
			t.Fatalf("ProcessDueSchedules: %v", err)
		}
		if got := jobCountForTenant(t, db, tenant); got != 0 {
			t.Fatalf("after %q: %d job(s) created for a blocked tenant, want 0", block, got)
		}
		if after := nextRunAt(t, db, scheduleID); after != before {
			t.Fatalf("after %q: next_run_at moved from %v to %v — a blocked tenant's schedule must stay due", block, before, after)
		}

		// Lifting the block: the overdue schedule fires on the next sweep.
		if _, err := db.Exec(`UPDATE tenants SET payment_status = 'active', deleted_at = NULL WHERE id = $1`, tenant); err != nil {
			t.Fatal(err)
		}
		if _, err := svc.ProcessDueSchedules(ctx); err != nil {
			t.Fatalf("ProcessDueSchedules after reactivation: %v", err)
		}
		if got := jobCountForTenant(t, db, tenant); got != 1 {
			t.Fatalf("after reactivation: %d job(s), want 1", got)
		}
	}
}
