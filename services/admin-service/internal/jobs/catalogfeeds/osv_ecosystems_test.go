package catalogfeeds

// Decision 13 (RC-29): keep Ubuntu, and never let one failing ecosystem throw
// away the others' progress.
//
// These tests stand up a fake osv.dev serving THREE ecosystems — Alpine and
// Debian healthy, Ubuntu failing — and drive the REAL Runner.runOne → OSVFeed →
// nextFeedState path (the same rule SQLStore.MarkResult applies). Before the
// fix, the failed run recorded row_count=0 and kept the old cursor, so the next
// run re-downloaded Debian and Alpine from scratch forever.
//
// Mutation checks run for this PR (each makes a test here fail, then restored):
//   - PartialProgress: true → false in OSVFeed.Sync: the cursor is dropped and
//     TestOSVRunner_oneFailingEcosystemKeepsTheOthersProgress fails;
//   - nextFeedState ignoring PartialProgress: same test fails;
//   - nextFeedState not carrying LastSuccessAt forward: the Ubuntu-recovers
//     assertions fail;
//   - OSVFeed ignoring SpoolDir: TestOSVFeed_spoolsIntoTheConfiguredDir fails.

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeEcosystem is one bucket on the fake osv.dev.
type fakeEcosystem struct {
	archive      []byte
	lastModified time.Time
	status       int // 0 = serve the archive
}

type fakeOSV struct {
	mu    sync.Mutex
	ecos  map[string]*fakeEcosystem
	gets  map[string]int    // full downloads served per ecosystem
	ifMod map[string]string // last If-Modified-Since per ecosystem
}

func newFakeOSV(t *testing.T) (*fakeOSV, *httptest.Server) {
	t.Helper()
	f := &fakeOSV{ecos: map[string]*fakeEcosystem{}, gets: map[string]int{}, ifMod: map[string]string{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/"), "/all.zip")
		f.mu.Lock()
		defer f.mu.Unlock()
		f.ifMod[name] = r.Header.Get("If-Modified-Since")
		eco, ok := f.ecos[name]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if eco.status != 0 {
			w.WriteHeader(eco.status)
			_, _ = w.Write([]byte("upstream refused " + name))
			return
		}
		// Like Cloud Storage: an archive not modified since the watermark is a
		// 304 with no body.
		if since, err := http.ParseTime(r.Header.Get("If-Modified-Since")); err == nil && !eco.lastModified.After(since) {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		f.gets[name]++
		w.Header().Set("Last-Modified", eco.lastModified.UTC().Format(http.TimeFormat))
		_, _ = w.Write(eco.archive)
	}))
	t.Cleanup(srv.Close)
	return f, srv
}

func (f *fakeOSV) set(name string, eco *fakeEcosystem) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.ecos[name] = eco
}

func (f *fakeOSV) downloads(name string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.gets[name]
}

// synthArchive builds an all.zip of n CVE-keyed advisories for one ecosystem,
// all modified at `modified`.
func synthArchive(t *testing.T, ecosystem string, n int, modified time.Time) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("%s-ADV-%d", strings.ToUpper(ecosystem), i)
		doc := map[string]any{
			"id":       id,
			"aliases":  []string{fmt.Sprintf("CVE-2026-%d%04d", len(ecosystem), i)},
			"modified": modified.UTC().Format(time.RFC3339),
			"summary":  "synthetic " + ecosystem + " advisory",
			"affected": []map[string]any{{
				"package": map[string]string{
					"ecosystem": ecosystem, "name": "pkg",
					"purl": "pkg:" + strings.ToLower(ecosystem) + "/pkg" + fmt.Sprint(i),
				},
				"ranges": []map[string]any{{"type": "ECOSYSTEM", "events": []map[string]string{{"introduced": "0"}, {"fixed": "1.0"}}}},
			}},
		}
		body, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		w, err := zw.Create(id + ".json")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// osvRunner wires the REAL OSV feed into the REAL runner over the stub store.
func osvRunner(t *testing.T, srv *httptest.Server, maxArchive int64) (*Runner, *memStore) {
	t.Helper()
	feed := NewOSVFeed(srv.Client(), []string{"Debian", "Ubuntu", "Alpine"})
	feed.BaseURL = srv.URL
	feed.SpoolDir = t.TempDir()
	if maxArchive > 0 {
		feed.MaxArchiveBytes = maxArchive
	}
	return testRunner(t, true, feed)
}

func runOSVOnce(t *testing.T, r *Runner) {
	t.Helper()
	r.runOne(context.Background(), FeedOSV)
}

func ecosystemByName(t *testing.T, st FeedState, name string) EcosystemStatus {
	t.Helper()
	for _, e := range st.Ecosystems {
		if e.Name == name {
			return e
		}
	}
	t.Fatalf("no ecosystem %q in %+v", name, st.Ecosystems)
	return EcosystemStatus{}
}

func TestOSVRunner_oneFailingEcosystemKeepsTheOthersProgress(t *testing.T) {
	fake, srv := newFakeOSV(t)
	t0 := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	fake.set("Debian", &fakeEcosystem{archive: synthArchive(t, "Debian", 3, t0), lastModified: t0})
	fake.set("Alpine", &fakeEcosystem{archive: synthArchive(t, "Alpine", 2, t0), lastModified: t0})
	// Ubuntu's archive is over the cap this test configures — the exact RC-29
	// failure, scaled down.
	ubuntu := synthArchive(t, "Ubuntu", 40, t0)
	fake.set("Ubuntu", &fakeEcosystem{archive: ubuntu, lastModified: t0})
	capBytes := int64(len(ubuntu) - 1)

	r, store := osvRunner(t, srv, capBytes)
	runOSVOnce(t, r)

	st := store.states[FeedOSV]
	if st.LastStatus != StatusError {
		t.Fatalf("feed status = %q, want error (Ubuntu failed)", st.LastStatus)
	}
	if st.LastError == nil || !strings.Contains(*st.LastError, "Ubuntu") || !strings.Contains(*st.LastError, "1 of 3") {
		t.Fatalf("feed error = %v, want it to name Ubuntu and the count", st.LastError)
	}
	if st.RowCount != 5 {
		t.Fatalf("row_count = %d, want 5 (Debian 3 + Alpine 2) — a failed run's committed rows must be reported", st.RowCount)
	}
	if st.Cursor == nil {
		t.Fatal("the cursor must be persisted despite Ubuntu's failure")
	}
	cur := parseOSVCursor(*st.Cursor)
	if cur["Debian"] == "" || cur["Alpine"] == "" {
		t.Fatalf("cursor = %s, want Debian and Alpine watermarks kept", *st.Cursor)
	}
	if _, ok := cur["Ubuntu"]; ok {
		t.Fatalf("cursor = %s, a failed ecosystem must not get a watermark", *st.Cursor)
	}

	deb, alp, ubu := ecosystemByName(t, st, "Debian"), ecosystemByName(t, st, "Alpine"), ecosystemByName(t, st, "Ubuntu")
	if deb.Status != EcosystemOK || deb.Rows != 3 || deb.LastSuccessAt == nil || deb.LastRunAt == nil {
		t.Fatalf("Debian = %+v, want ok with 3 rows and a success time", deb)
	}
	if alp.Status != EcosystemOK || alp.Rows != 2 {
		t.Fatalf("Alpine = %+v, want ok with 2 rows", alp)
	}
	if ubu.Status != EcosystemError || ubu.LastError == nil || !strings.Contains(*ubu.LastError, "cap") || ubu.LastSuccessAt != nil {
		t.Fatalf("Ubuntu = %+v, want error naming the cap and no success yet", ubu)
	}

	// Second run: Debian and Alpine resume from their watermarks (304, no
	// re-download); only Ubuntu is attempted from scratch.
	runOSVOnce(t, r)
	if fake.downloads("Debian") != 1 || fake.downloads("Alpine") != 1 {
		t.Fatalf("downloads Debian=%d Alpine=%d, want 1 each — their progress must survive Ubuntu's failure",
			fake.downloads("Debian"), fake.downloads("Alpine"))
	}
	firstUbuntuFailure := ecosystemByName(t, store.states[FeedOSV], "Ubuntu")
	if firstUbuntuFailure.Status != EcosystemError {
		t.Fatalf("Ubuntu should still be failing, got %+v", firstUbuntuFailure)
	}
	debAfter := ecosystemByName(t, store.states[FeedOSV], "Debian")
	if debAfter.Rows != 0 || debAfter.Status != EcosystemOK || debAfter.Watermark == nil || *debAfter.Watermark != *deb.Watermark {
		t.Fatalf("Debian second run = %+v, want ok, 0 rows, watermark unchanged", debAfter)
	}

	// Ubuntu recovers once the cap is raised: the feed goes green and Ubuntu
	// gets its first success, while Debian's earlier success time is kept
	// (it succeeded again, so it moves forward, not back).
	r.feeds[FeedOSV].(*OSVFeed).MaxArchiveBytes = defaultOSVMaxArchive
	runOSVOnce(t, r)
	final := store.states[FeedOSV]
	if final.LastStatus != StatusOK || final.LastError != nil {
		t.Fatalf("feed after Ubuntu recovered = %q / %v, want ok", final.LastStatus, final.LastError)
	}
	if u := ecosystemByName(t, final, "Ubuntu"); u.Status != EcosystemOK || u.Rows != 40 || u.LastSuccessAt == nil {
		t.Fatalf("Ubuntu after recovery = %+v, want ok with 40 rows", u)
	}
	if cur := parseOSVCursor(*final.Cursor); cur["Ubuntu"] == "" || cur["Debian"] == "" || cur["Alpine"] == "" {
		t.Fatalf("final cursor = %s, want all three watermarks", *final.Cursor)
	}
}

// A failing ecosystem keeps the time it last worked, so the console can say
// "failing since". Pure rule, both polarities.
func TestNextFeedState_carriesLastSuccessForwardOnlyForFailures(t *testing.T) {
	t1 := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	t2 := t1.Add(24 * time.Hour)
	prev := FeedState{Feed: FeedOSV, Ecosystems: []EcosystemStatus{
		{Name: "Ubuntu", Status: EcosystemOK, LastSuccessAt: &t1},
		{Name: "Debian", Status: EcosystemOK, LastSuccessAt: &t1},
	}}
	msg := "boom"
	next := nextFeedState(prev, SyncResult{
		Rows: 1, Cursor: `{"Debian":"x"}`, PartialProgress: true,
		Ecosystems: []EcosystemStatus{
			{Name: "Debian", Status: EcosystemOK, Rows: 1},
			{Name: "Ubuntu", Status: EcosystemError, LastError: &msg},
		},
	}, errors.New("osv mirror incomplete"), t2)

	if u := ecosystemByName(t, next, "Ubuntu"); u.LastSuccessAt == nil || !u.LastSuccessAt.Equal(t1) || !u.LastRunAt.Equal(t2) {
		t.Fatalf("failed Ubuntu = %+v, want last success %v kept and last run %v", u, t1, t2)
	}
	if d := ecosystemByName(t, next, "Debian"); d.LastSuccessAt == nil || !d.LastSuccessAt.Equal(t2) {
		t.Fatalf("succeeding Debian = %+v, want last success moved to %v", d, t2)
	}
	if next.Cursor == nil || *next.Cursor != `{"Debian":"x"}` {
		t.Fatalf("partial-progress cursor = %v, want it persisted on failure", next.Cursor)
	}

	// The other polarity: a feed WITHOUT partial progress keeps its old cursor
	// on failure, and a run that reports no ecosystems keeps the old list.
	old := "2026-08-01T00:00:00Z"
	nvd := nextFeedState(FeedState{Feed: FeedNVD, Cursor: &old, Ecosystems: prev.Ecosystems},
		SyncResult{Rows: 9, Cursor: "2026-09-01T00:00:00Z"}, errors.New("403"), t2)
	if nvd.Cursor == nil || *nvd.Cursor != old {
		t.Fatalf("NVD cursor on failure = %v, want %s unchanged", nvd.Cursor, old)
	}
	if nvd.RowCount != 9 {
		t.Fatalf("NVD row_count = %d, want the 9 rows the failed run committed", nvd.RowCount)
	}
	if len(nvd.Ecosystems) != 2 {
		t.Fatalf("a run with no ecosystem detail must keep the previous list, got %+v", nvd.Ecosystems)
	}
}

func TestOSVFeed_defaultArchiveCapFitsUbuntu(t *testing.T) {
	// Ubuntu's all.zip was ~705 MiB in September 2026; the cap is 2 GiB.
	const ubuntuSeptember2026 = 705 << 20
	f := NewOSVFeed(nil, nil)
	if f.MaxArchiveBytes != 2<<30 {
		t.Fatalf("default cap = %d, want 2 GiB", f.MaxArchiveBytes)
	}
	if f.MaxArchiveBytes < 2*ubuntuSeptember2026 {
		t.Fatalf("the cap must leave Ubuntu room to grow, got %d", f.MaxArchiveBytes)
	}
	found := false
	for _, e := range f.Ecosystems {
		if e == "Ubuntu" {
			found = true
		}
	}
	if !found {
		t.Fatalf("Ubuntu must stay in the default ecosystems (decision 13), got %v", f.Ecosystems)
	}
}

// Sync must not reorder the caller's ecosystem slice (it used to sort the
// package-level default in place).
func TestOSVFeed_doesNotMutateTheConfiguredEcosystems(t *testing.T) {
	_, srv := newFakeOSV(t)
	eco := []string{"Ubuntu", "Debian"}
	f := NewOSVFeed(srv.Client(), eco)
	f.BaseURL = srv.URL
	f.SpoolDir = t.TempDir()
	_, _ = f.Sync(context.Background(), newMemStore(), "")
	if eco[0] != "Ubuntu" || DefaultOSVEcosystems[0] != "Debian" || DefaultOSVEcosystems[1] != "Ubuntu" {
		t.Fatalf("configured slice mutated: %v / default %v", eco, DefaultOSVEcosystems)
	}
}

func TestOSVFeed_spoolsIntoTheConfiguredDir(t *testing.T) {
	fake, srv := newFakeOSV(t)
	t0 := time.Date(2026, 9, 20, 12, 0, 0, 0, time.UTC)
	fake.set("Debian", &fakeEcosystem{archive: synthArchive(t, "Debian", 1, t0), lastModified: t0})

	// A spool dir that does not exist fails the ecosystem at the spool step —
	// proof the configured dir, not the OS temp dir, is where it writes.
	f := NewOSVFeed(srv.Client(), []string{"Debian"})
	f.BaseURL = srv.URL
	f.SpoolDir = filepath.Join(t.TempDir(), "missing")
	res, err := f.Sync(context.Background(), newMemStore(), "")
	if err == nil || len(res.Ecosystems) != 1 || res.Ecosystems[0].LastError == nil ||
		!strings.Contains(*res.Ecosystems[0].LastError, "spool archive") {
		t.Fatalf("missing spool dir: err=%v statuses=%+v, want a spool failure", err, res.Ecosystems)
	}

	// A real one works and is left empty afterwards.
	dir := t.TempDir()
	f.SpoolDir = dir
	if _, err := f.Sync(context.Background(), newMemStore(), ""); err != nil {
		t.Fatalf("sync with spool dir: %v", err)
	}
	left, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 0 {
		t.Fatalf("spooled archives must be removed after reading, found %d file(s)", len(left))
	}
}

// A cancelled run names the ecosystems it never reached instead of leaving
// their previous "ok" standing as this run's answer.
func TestOSVFeed_cancelledRunMarksUnreachedEcosystems(t *testing.T) {
	_, srv := newFakeOSV(t)
	f := NewOSVFeed(srv.Client(), []string{"Alpine", "Debian"})
	f.BaseURL = srv.URL
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := f.Sync(ctx, newMemStore(), `{"Alpine":"2026-01-01T00:00:00Z"}`)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if len(res.Ecosystems) != 2 || res.Ecosystems[0].Status != EcosystemError ||
		!strings.Contains(*res.Ecosystems[0].LastError, "not attempted") {
		t.Fatalf("statuses = %+v, want both marked not attempted", res.Ecosystems)
	}
	if !res.PartialProgress || !strings.Contains(res.Cursor, "Alpine") {
		t.Fatalf("a cancelled run must still hand back the cursor it was given: %+v", res)
	}
}
