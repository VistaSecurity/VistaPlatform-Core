package services

// Guard: retiring monitoring_notification_channels must never destroy data and
// must never abort a `helm upgrade`.
//
// monitoring-service no longer reads the table (incident notifications go out on
// notifications.send), and schema.sql no longer creates it. On an existing
// install POST-MIGRATIONS drops it — but only while it is EMPTY: the old setup
// guide told operators to INSERT channels by hand, so a row may hold a webhook
// URL or a PagerDuty key nobody else has. Each case stages the legacy table on a
// scratch database (which starts from the current schema, where it is absent),
// applies the CURRENT schema.sql as the migration Job does, then applies it a
// second time — the Job re-runs the file on every upgrade.
//
// Mutation-tested: making the drop unconditional turns the populated case red;
// removing the drop turns the empty case red; a static (non-dynamic) reference
// to the table in the guard makes the fresh-install pass fail outright.

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

const legacyMonitoringChannelsDDL = `
CREATE TABLE public.monitoring_notification_channels (
    id uuid DEFAULT gen_random_uuid() NOT NULL PRIMARY KEY,
    channel_name character varying(100) NOT NULL UNIQUE,
    channel_type character varying(50) NOT NULL,
    config jsonb NOT NULL,
    enabled boolean DEFAULT true
)`

func TestIntegration_Schema_RetiresMonitoringNotificationChannelsWithoutLosingData(t *testing.T) {
	schema := mustReadFile(t, filepath.Join(testdb.RepoRoot(t), "scripts", "database", "schema.sql"))

	for _, tc := range []struct {
		name        string
		stageLegacy bool // an install that predates the retirement has the table
		withRows    bool // ...and an operator INSERTed a channel by hand
		wantPresent bool
	}{
		{"fresh install never has it", false, false, false},
		{"upgrade with an empty legacy table drops it", true, false, false},
		{"upgrade with operator rows keeps the table and the rows", true, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := testdb.ScratchDatabase(t)
			if tablePresent(t, db) {
				t.Fatal("a fresh schema must not create monitoring_notification_channels")
			}
			if tc.stageLegacy {
				mustExec(t, db, legacyMonitoringChannelsDDL)
			}
			if tc.withRows {
				mustExec(t, db, `INSERT INTO public.monitoring_notification_channels (channel_name, channel_type, config)
					VALUES ('ops-slack', 'slack', '{"webhook_url":"https://hooks.example.invalid/T/B/x"}')`)
			}

			for pass := 1; pass <= 2; pass++ {
				applySchemaRetrying(t, db, schema, pass)
			}

			if got := tablePresent(t, db); got != tc.wantPresent {
				t.Fatalf("table present = %v after upgrade, want %v", got, tc.wantPresent)
			}
			if tc.withRows {
				var url string
				if err := db.QueryRow(`SELECT config->>'webhook_url' FROM public.monitoring_notification_channels WHERE channel_name = 'ops-slack'`).Scan(&url); err != nil || url == "" {
					t.Fatalf("operator row was lost or damaged: url=%q err=%v", url, err)
				}
			}
		})
	}
}

func tablePresent(t *testing.T, db *sql.DB) bool {
	t.Helper()
	var present bool
	if err := db.QueryRow(`SELECT to_regclass('public.monitoring_notification_channels') IS NOT NULL`).Scan(&present); err != nil {
		t.Fatal(err)
	}
	return present
}

// applySchemaRetrying runs schema.sql once, as the migration Job does. Only the
// cross-binary races every schema applier in the suite tolerates are retried; a
// real failure fails the test.
func applySchemaRetrying(t *testing.T, db *sql.DB, schema string, pass int) {
	t.Helper()
	const attempts = 3
	for i := 1; ; i++ {
		_, err := db.Exec(schema)
		if err == nil {
			return
		}
		if !testdb.IsTransientRace(err) || i == attempts {
			t.Fatalf("pass %d: schema.sql does not apply — the migration Job would abort `helm upgrade` here: %v", pass, err)
		}
		t.Logf("pass %d: transient cross-binary race (attempt %d/%d), retrying: %v", pass, i, attempts, err)
		time.Sleep(200 * time.Millisecond)
	}
}
