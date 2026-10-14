package updates

// DB-integration tests: skip unless TEST_DATABASE_URL is set (nightly job and
// `make test-integration-db`). They prove what sqlmock cannot — the upsert
// against the real table (the id = 1 pin included) and that the advisory lock
// really excludes a second holder.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_PGStore_UpsertKeepsOneRowAndFailureKeepsLastGoodVersion(t *testing.T) {
	db := testdb.Connect(t)
	testdb.ApplySchema(t, db)
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, `DELETE FROM public.platform_update_status`); err != nil {
		t.Fatal(err)
	}
	store := PGStore{DB: db}

	empty, err := store.Get(ctx)
	if err != nil || empty.CheckedAt != nil || empty.LatestVersion != nil {
		t.Fatalf("before any check: %+v %v", empty, err)
	}

	at := time.Date(2026, 10, 14, 1, 2, 3, 0, time.UTC)
	src, cur, latest, notes := "oci://ghcr.io/vistasecurity/vistaplatform", "4.5.0", "4.6.0", "https://example/notes"
	if err := store.SaveSuccess(ctx, Status{CheckedAt: &at, Source: &src, CurrentVersion: &cur, LatestVersion: &latest, NotesURL: &notes, PrereleasesSeen: []string{"4.7.0-rc.1"}}); err != nil {
		t.Fatal(err)
	}
	got, err := store.Get(ctx)
	if err != nil || got.LatestVersion == nil || *got.LatestVersion != "4.6.0" || got.Error != nil ||
		len(got.PrereleasesSeen) != 1 || !got.CheckedAt.Equal(at) {
		t.Fatalf("after success: %+v %v", got, err)
	}

	later := at.Add(time.Hour)
	if err := store.SaveFailure(ctx, later, src, cur, "registry down"); err != nil {
		t.Fatal(err)
	}
	got, _ = store.Get(ctx)
	if got.Error == nil || *got.Error != "registry down" || got.LatestVersion == nil || *got.LatestVersion != "4.6.0" || !got.CheckedAt.Equal(later) {
		t.Fatalf("after failure: %+v", got)
	}

	if err := store.SaveSuccess(ctx, Status{CheckedAt: &later, Source: &src, CurrentVersion: &cur}); err != nil {
		t.Fatal(err)
	}
	got, _ = store.Get(ctx)
	if got.Error != nil || got.LatestVersion != nil || got.NotesURL != nil || len(got.PrereleasesSeen) != 0 {
		t.Fatalf("after an up-to-date success: %+v", got)
	}

	var n int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM public.platform_update_status`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("rows = %d, %v; want exactly 1", n, err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO public.platform_update_status (id) VALUES (2)`); err == nil {
		t.Fatal("the single-row CHECK let a second row in")
	}
}

func TestIntegration_PGLocker_ExcludesASecondHolderUntilReleased(t *testing.T) {
	db := testdb.Connect(t)
	ctx := context.Background()
	locker := PGLocker{DB: db}

	release, ok, err := locker.TryLock(ctx)
	if err != nil || !ok {
		t.Fatalf("first lock: ok=%v err=%v", ok, err)
	}
	_, ok2, err := locker.TryLock(ctx)
	if err != nil || ok2 {
		t.Fatalf("second lock while held: ok=%v err=%v; want refused", ok2, err)
	}
	release()
	release2, ok3, err := locker.TryLock(ctx)
	if err != nil || !ok3 {
		t.Fatalf("lock after release: ok=%v err=%v", ok3, err)
	}
	release2()

	// And through the checker: a held lock is ErrInProgress, with the registry untouched.
	hold, _, _ := locker.TryLock(ctx)
	defer hold()
	tags := &fakeTags{tags: []string{"4.6.0"}}
	c := newUpdatesTestChecker(tags, PGStore{DB: db}, locker)
	if _, err := c.Run(ctx); !errors.Is(err, ErrInProgress) || tags.count() != 0 {
		t.Fatalf("err=%v calls=%d", err, tags.count())
	}
}
