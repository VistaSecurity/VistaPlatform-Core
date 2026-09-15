package catalogfeeds

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// fakeFeed records the cursor it was handed and returns whatever the test says.
// `block` lets a test hold a run open long enough to assert the busy path.
type fakeFeed struct {
	name string

	mu           sync.Mutex
	cursorsSeen  []string
	calls        int
	result       SyncResult
	err          error
	block        chan struct{}
	started      chan struct{}
	startedClose sync.Once
}

func newFakeFeed(name string) *fakeFeed {
	return &fakeFeed{name: name, started: make(chan struct{})}
}

func (f *fakeFeed) Name() string { return f.name }

func (f *fakeFeed) Sync(ctx context.Context, _ Store, cursor string) (SyncResult, error) {
	f.mu.Lock()
	f.cursorsSeen = append(f.cursorsSeen, cursor)
	f.calls++
	block := f.block
	f.mu.Unlock()
	f.startedClose.Do(func() { close(f.started) })

	if block != nil {
		select {
		case <-block:
		case <-ctx.Done():
			return SyncResult{}, ctx.Err()
		}
	}
	return f.result, f.err
}

func (f *fakeFeed) seenCursors() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.cursorsSeen...)
}

func testRunner(t *testing.T, enabled bool, feeds ...Feed) (*Runner, *memStore) {
	t.Helper()
	store := newMemStore()
	cfg := Config{Enabled: enabled, Interval: time.Hour, StartupDelay: time.Hour}
	// db is nil: the advisory lock is a cross-REPLICA concern and needs a real
	// Postgres. The runner skips it when db is nil, and the integration test
	// covers the lock itself.
	return NewRunnerWithFeeds(cfg, store, nil, feeds), store
}

// The kill switch must refuse the manual trigger too. An operator who turned
// the feeds off must not find them running because someone clicked a button.
func TestRunner_killSwitchRefusesManualSync(t *testing.T) {
	feed := newFakeFeed(FeedNVD)
	r, store := testRunner(t, false, feed)

	if err := r.SyncNow(FeedNVD); !errors.Is(err, ErrFeedsDisabled) {
		t.Fatalf("SyncNow = %v, want ErrFeedsDisabled", err)
	}
	r.Start(context.Background()) // must be a no-op
	r.Stop()
	if feed.calls != 0 {
		t.Fatalf("the feed ran %d times with the kill switch off", feed.calls)
	}
	if len(store.results) != 0 {
		t.Fatal("nothing should have been recorded")
	}
}

func TestRunner_unknownFeedIsRefused(t *testing.T) {
	r, _ := testRunner(t, true, newFakeFeed(FeedNVD))
	if err := r.SyncNow("not-a-feed"); !errors.Is(err, ErrFeedUnknown) {
		t.Fatalf("SyncNow = %v, want ErrFeedUnknown", err)
	}
}

func TestRunner_secondSyncWhileOneIsRunningIsRefused(t *testing.T) {
	feed := newFakeFeed(FeedEOL)
	feed.block = make(chan struct{})
	r, _ := testRunner(t, true, feed)

	if err := r.SyncNow(FeedEOL); err != nil {
		t.Fatalf("first SyncNow: %v", err)
	}
	<-feed.started
	if err := r.SyncNow(FeedEOL); !errors.Is(err, ErrFeedBusy) {
		t.Fatalf("second SyncNow = %v, want ErrFeedBusy", err)
	}
	close(feed.block)
	r.Stop()
	if feed.calls != 1 {
		t.Fatalf("the feed ran %d times, want 1", feed.calls)
	}
}

// The runner reads the stored cursor and hands it to the feed. Without this the
// incremental feeds would re-walk their whole window every run and nobody would
// notice except NVD's rate limiter.
func TestRunner_handsTheStoredCursorToTheFeed(t *testing.T) {
	feed := newFakeFeed(FeedNVD)
	feed.result = SyncResult{Rows: 7, Cursor: "2026-09-11T00:00:00Z"}
	r, store := testRunner(t, true, feed)

	cursor := "2026-08-01T00:00:00Z"
	store.states[FeedNVD] = FeedState{Feed: FeedNVD, LastStatus: StatusOK, Cursor: &cursor}

	if err := r.SyncNow(FeedNVD); err != nil {
		t.Fatalf("SyncNow: %v", err)
	}
	r.Stop()

	seen := feed.seenCursors()
	if len(seen) != 1 || seen[0] != cursor {
		t.Fatalf("feed saw cursors %v, want [%s]", seen, cursor)
	}
	if got := store.states[FeedNVD]; got.Cursor == nil || *got.Cursor != "2026-09-11T00:00:00Z" {
		t.Fatalf("cursor after a successful run = %v, want the feed's new one", got.Cursor)
	}
	if store.states[FeedNVD].RowCount != 7 {
		t.Fatalf("row_count = %d, want 7", store.states[FeedNVD].RowCount)
	}
}

// A feed error is RECORDED, never fatal, and it must not advance the cursor.
func TestRunner_feedFailureIsRecordedAndLeavesTheCursorAlone(t *testing.T) {
	feed := newFakeFeed(FeedOSV)
	feed.err = errors.New("osv mirror incomplete: ecosystem \"Debian\": 503")
	feed.result = SyncResult{Rows: 3, Cursor: "should-be-ignored"}
	r, store := testRunner(t, true, feed)

	cursor := "2026-08-01T00:00:00Z"
	store.states[FeedOSV] = FeedState{Feed: FeedOSV, LastStatus: StatusOK, Cursor: &cursor}

	if err := r.SyncNow(FeedOSV); err != nil {
		t.Fatalf("SyncNow must not surface the feed's own failure: %v", err)
	}
	r.Stop()

	st := store.states[FeedOSV]
	if st.LastStatus != StatusError {
		t.Fatalf("last_status = %q, want error", st.LastStatus)
	}
	if st.LastError == nil || *st.LastError == "" {
		t.Fatal("the operator must be able to see WHY it failed")
	}
	if st.Cursor == nil || *st.Cursor != cursor {
		t.Fatalf("cursor = %v, want it left at %q so the window is retried", st.Cursor, cursor)
	}
}

// Marking the run in flight is what makes "running" visible in the console.
func TestRunner_marksRunningBeforeTheFeedStarts(t *testing.T) {
	feed := newFakeFeed(FeedEOL)
	feed.block = make(chan struct{})
	r, store := testRunner(t, true, feed)

	if err := r.SyncNow(FeedEOL); err != nil {
		t.Fatalf("SyncNow: %v", err)
	}
	<-feed.started

	store.mu.Lock()
	marked := append([]string(nil), store.markedRunning...)
	store.mu.Unlock()
	if len(marked) != 1 || marked[0] != FeedEOL {
		t.Fatalf("markedRunning = %v, want [eol] before the feed's work begins", marked)
	}

	close(feed.block)
	r.Stop()
}

// The scheduled pass runs EVERY feed, in the declared order.
func TestRunner_scheduledPassRunsEveryFeed(t *testing.T) {
	eol, nvd, osv := newFakeFeed(FeedEOL), newFakeFeed(FeedNVD), newFakeFeed(FeedOSV)
	r, store := testRunner(t, true, eol, nvd, osv)

	r.runAll(context.Background())

	for _, f := range []*fakeFeed{eol, nvd, osv} {
		if f.calls != 1 {
			t.Fatalf("feed %s ran %d times, want 1", f.Name(), f.calls)
		}
	}
	if len(store.results) != 3 {
		t.Fatalf("recorded %d outcomes, want 3", len(store.results))
	}
	order := []string{store.results[0].feed, store.results[1].feed, store.results[2].feed}
	want := []string{FeedEOL, FeedNVD, FeedOSV}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("ran in order %v, want %v", order, want)
		}
	}
}

// The follow-up runs AFTER every feed, not before and not instead.
//
// Ordering is the whole reason the hook exists: the follow-up is the catalogue
// enricher's gap pass, and a gap the endoflife.date mirror has just filled is
// not one a model should be asked about.
func TestRunner_followUpRunsAfterEveryFeed(t *testing.T) {
	eol, nvd, osv := newFakeFeed(FeedEOL), newFakeFeed(FeedNVD), newFakeFeed(FeedOSV)
	r, _ := testRunner(t, true, eol, nvd, osv)

	var callsAtFollowUp []int
	r.SetFollowUp(func(context.Context) {
		callsAtFollowUp = []int{eol.calls, nvd.calls, osv.calls}
	})
	r.runAll(context.Background())

	if callsAtFollowUp == nil {
		t.Fatal("the follow-up never ran")
	}
	for i, n := range callsAtFollowUp {
		if n != 1 {
			t.Fatalf("feed %d had run %d times when the follow-up fired, want 1", i, n)
		}
	}
}

// A panicking follow-up is recovered, not fatal. These runs are goroutines, so
// an unrecovered panic takes the whole admin-service process with it — the
// console, every admin route, and the feeds. Its input is a model's answer,
// whose shape nobody here controls.
func TestRunner_followUpPanicIsRecovered(t *testing.T) {
	feed := newFakeFeed(FeedEOL)
	r, _ := testRunner(t, true, feed)
	r.SetFollowUp(func(context.Context) { panic("the proposer exploded") })

	r.runAll(context.Background())
	if feed.calls != 1 {
		t.Fatalf("feed ran %d times", feed.calls)
	}
}

// A cancelled pass does not start the follow-up: there is nothing to follow up.
func TestRunner_followUpIsSkippedOnACancelledPass(t *testing.T) {
	feed := newFakeFeed(FeedEOL)
	r, _ := testRunner(t, true, feed)
	ran := false
	r.SetFollowUp(func(context.Context) { ran = true })

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r.runAll(ctx)
	if ran {
		t.Fatal("the follow-up ran after a cancelled pass")
	}
}

// A store that cannot be read must abort the run rather than silently sync from
// cursor "" and re-walk everything.
func TestRunner_unreadableFeedStateAbortsTheRun(t *testing.T) {
	feed := newFakeFeed(FeedNVD)
	r, store := testRunner(t, true, feed)
	store.feedStatesErr = errStubStore

	r.runOne(context.Background(), FeedNVD)
	if feed.calls != 0 {
		t.Fatalf("the feed ran %d times despite unreadable state", feed.calls)
	}
}

func TestValidFeed(t *testing.T) {
	for _, ok := range FeedNames {
		if !ValidFeed(ok) {
			t.Fatalf("%s should be a valid feed", ok)
		}
	}
	for _, bad := range []string{"", "EOL", "cve", "../eol"} {
		if ValidFeed(bad) {
			t.Fatalf("%q should not be a valid feed", bad)
		}
	}
}

func TestNormalizePagination(t *testing.T) {
	cases := []struct{ page, size, wantPage, wantSize int }{
		{0, 0, 1, DefaultPageSize},
		{-5, -5, 1, DefaultPageSize},
		{3, 10, 3, 10},
		{1, MaxPageSize + 1000, 1, MaxPageSize},
	}
	for _, tc := range cases {
		p, s := normalize(tc.page, tc.size)
		if p != tc.wantPage || s != tc.wantSize {
			t.Fatalf("normalize(%d,%d) = (%d,%d), want (%d,%d)", tc.page, tc.size, p, s, tc.wantPage, tc.wantSize)
		}
	}
}

func TestLoadConfig_defaults(t *testing.T) {
	t.Setenv("CATALOG_FEEDS_ENABLED", "")
	t.Setenv("OSV_ECOSYSTEMS", "")
	cfg := LoadConfig()
	if !cfg.Enabled {
		t.Fatal("feeds must default to ENABLED — a mirror nobody switched on is a catalogue that stays empty")
	}
	if cfg.Interval != 24*time.Hour {
		t.Fatalf("interval = %v, want 24h", cfg.Interval)
	}
	if len(cfg.OSVEcosystems) != len(DefaultOSVEcosystems) {
		t.Fatalf("ecosystems = %v, want the shipped default", cfg.OSVEcosystems)
	}
}

func TestLoadConfig_killSwitchAndEcosystems(t *testing.T) {
	t.Setenv("CATALOG_FEEDS_ENABLED", "false")
	t.Setenv("OSV_ECOSYSTEMS", " Debian , ,Rocky Linux ")
	cfg := LoadConfig()
	if cfg.Enabled {
		t.Fatal("CATALOG_FEEDS_ENABLED=false must disable the feeds")
	}
	if len(cfg.OSVEcosystems) != 2 || cfg.OSVEcosystems[0] != "Debian" || cfg.OSVEcosystems[1] != "Rocky Linux" {
		t.Fatalf("ecosystems = %#v, want the trimmed, blank-free list", cfg.OSVEcosystems)
	}
}
