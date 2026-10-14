package runs

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// runsMaintenanceLockKey serialises the tests (in any package) that create
// `running` rows: the one-running index is global, so two test binaries doing
// it at once would refuse each other. The backups package takes the same key.
const runsMaintenanceLockKey = 2524

// runsLockMaintenanceTables holds the advisory lock for the test's lifetime on
// a dedicated connection, and clears any running row a crashed earlier test
// left behind.
func runsLockMaintenanceTables(t *testing.T, db *sql.DB) {
	t.Helper()
	ctx := context.Background()
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(ctx, `SELECT pg_advisory_lock($1)`, runsMaintenanceLockKey); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = conn.ExecContext(context.Background(), `SELECT pg_advisory_unlock($1)`, runsMaintenanceLockKey)
		_ = conn.Close()
	})
	if _, err := db.ExecContext(ctx, `UPDATE public.platform_maintenance_runs SET status = 'cancelled', finished_at = now() WHERE status = 'running'`); err != nil {
		t.Fatal(err)
	}
}

func TestIntegration_RunsStore(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchema(t, db)
	runsLockMaintenanceTables(t, db)
	ctx := context.Background()
	s := SQLStore{DB: db}

	user := uuid.New()
	run, err := s.Create(ctx, Run{ID: uuid.New(), Kind: KindUpdate, StartedBy: &user, FromVersion: "4.5.0", ToVersion: "4.6.0",
		Steps: []Step{{Name: "backup", Executor: ExecutorJob, Status: StepPending}}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM public.platform_maintenance_runs WHERE id = $1`, run.ID) })
	if run.Status != StatusRunning || run.StartedBy == nil || *run.StartedBy != user || run.FromVersion != "4.5.0" || len(run.Steps) != 1 {
		t.Fatalf("created %+v", run)
	}

	// The database itself allows one running run.
	if _, err := s.Create(ctx, Run{ID: uuid.New(), Kind: KindBackup}); !errors.Is(err, ErrRunInProgress) {
		t.Fatalf("second running run: %v, want ErrRunInProgress", err)
	}

	if err := s.SetJobName(ctx, run.ID, "maintenance-update-abc"); err != nil {
		t.Fatal(err)
	}
	steps := []Step{{Name: "backup", Executor: ExecutorJob, Status: StepRunning, LogTail: "dumping"}}
	if err := s.UpdateSteps(ctx, run.ID, steps); err != nil {
		t.Fatal(err)
	}
	running, err := s.ListRunning(ctx)
	if err != nil || len(running) != 1 || running[0].JobName != "maintenance-update-abc" || running[0].Steps[0].LogTail != "dumping" {
		t.Fatalf("ListRunning = %+v, %v", running, err)
	}

	steps[0].Status = StepFailed
	if err := s.Finish(ctx, run.ID, StatusFailed, steps, "helm upgrade failed"); err != nil {
		t.Fatal(err)
	}
	// Settling is idempotent: a second Finish does not overwrite the first.
	if err := s.Finish(ctx, run.ID, StatusSucceeded, nil, ""); err != nil {
		t.Fatal(err)
	}
	got, err := s.Get(ctx, run.ID)
	if err != nil || got.Status != StatusFailed || got.Error != "helm upgrade failed" || got.FinishedAt == nil || got.FailedStep() != "backup" {
		t.Fatalf("settled %+v, %v", got, err)
	}

	// Once nothing runs, a new run may start.
	next, err := s.Create(ctx, Run{ID: uuid.New(), Kind: KindBackup})
	if err != nil {
		t.Fatalf("after settling: %v", err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM public.platform_maintenance_runs WHERE id = $1`, next.ID) })
	list, err := s.List(ctx, 20)
	if err != nil || len(list) < 2 || list[0].ID != next.ID {
		t.Fatalf("List newest first: %+v, %v", list, err)
	}
	if _, err := s.Get(ctx, uuid.New()); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing run: %v", err)
	}
}
