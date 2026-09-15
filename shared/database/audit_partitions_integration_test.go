package database_test

// Guard: after schema.sql is applied, audit.activity_logs must be able to
// accept a row stamped now() — and keep accepting one for a while yet.
//
// audit.activity_logs is RANGE-partitioned on occurred_at, and the pg_dump body
// of schema.sql carries a FIXED list of monthly partitions: whatever existed
// when the dump was taken. An INSERT outside every attached partition does not
// fall back anywhere, it raises 23514 `no partition of relation
// "activity_logs" found for row` — and the write that fails is an AUDIT write.
// The dumped list ran out on and every apply from that date produced
// a table that could not take a row stamped now(). POST-MIGRATIONS now calls
// audit.ensure_future_partitions(3) to materialize the current month + 3.
//
// Why this test and not the tests that already broke: admin-service's
// security-event tests insert activity rows stamped now(), so they DO fail when
// the call is missing — but only while the dumped partition list happens to be
// exhausted. Regenerate the pg_dump body next month and those tests go quiet
// again for however long the newly-dumped months last, while the call could be
// deleted and nothing would say so until the new list expired too. That is a
// check whose ability to fail depends on the calendar. This one asserts the
// property directly — there is headroom, now — so it can fail on the day the
// call goes away, not months later.
//
// 60 days is the assertion because ensure_future_partitions(3) covers the
// current month plus three, i.e. at least ~89 days of forward coverage even
// when applied on the last day of a month. It is also the horizon
// audit-service's PartitionManager keeps at runtime (weekly, months ahead = 3),
// so the file and the job agree.
//
// Skips without TEST_DATABASE_URL, like every testdb-gated test.

import (
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_AuditPartitions_CoverTodayAndTheNearFuture(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, db)

	for _, ahead := range []time.Duration{0, 30 * 24 * time.Hour, 60 * 24 * time.Hour} {
		at := time.Now().Add(ahead)
		days := int(ahead.Hours() / 24)
		t.Run(fmt.Sprintf("now+%dd", days), func(t *testing.T) {
			if err := probeActivityInsert(t, db, at); err != nil {
				t.Fatalf("audit.activity_logs cannot accept a row stamped %s (now + %d days): %v\n\n"+
					"The partitions dumped into schema.sql have run out, and nothing recreated them. "+
					"scripts/database/schema.sql must call `SELECT * FROM audit.ensure_future_partitions(3);` "+
					"in POST-MIGRATIONS, above the ROLE GRANTS block so the new partitions are covered by "+
					"the blanket grant — check that statement is still there (and mirrored into "+
					"charts/vistaplatform/files/schema/schema.sql). Without it every fresh install and every "+
					"integration database loses the ability to write an audit record.",
					at.Format(time.RFC3339), days, err)
			}
		})
	}
}

// probeActivityInsert writes one row at the given instant inside a transaction
// that is always rolled back, so the probe leaves nothing behind. Partition
// routing is resolved at INSERT time, which is what makes this a real check
// rather than a catalogue reading that has to parse relpartbound text.
func probeActivityInsert(t *testing.T, db *sql.DB, at time.Time) error {
	t.Helper()
	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	defer func() { _ = tx.Rollback() }()

	_, err = tx.Exec(`
		INSERT INTO audit.activity_logs (user_type, event_type, event_category, action, occurred_at)
		VALUES ('platform', 'partition_probe', 'system', 'partition_probe', $1)`, at)
	return err
}
