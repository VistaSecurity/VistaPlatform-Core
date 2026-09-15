package catalogfeeds

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// eolServer serves the recorded endoflife.date fixtures. No network in tests —
// the shapes below are copied from real responses (including the ones that make
// this feed awkward: a numeric `cycle`, and `eol` arriving as a boolean).
func eolServer(t *testing.T, missing ...string) *httptest.Server {
	t.Helper()
	gone := map[string]bool{}
	for _, m := range missing {
		gone[m] = true
	}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/")
		slug := strings.TrimSuffix(name, ".json")
		if gone[slug] {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"not found"}`))
			return
		}
		fixture := "eol_" + slug + ".json"
		if slug == "all" {
			fixture = "eol_all.json"
		}
		body, err := os.ReadFile(filepath.Join("testdata", fixture))
		if err != nil {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"no fixture"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
}

func testEOLFeed(t *testing.T, srv *httptest.Server) *EOLFeed {
	t.Helper()
	f := NewEOLFeed(srv.Client())
	f.BaseURL = srv.URL
	f.Delay = 0 // pacing is a production concern; a test must not sleep 300×250ms
	f.Now = func() time.Time { return time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC) }
	return f
}

func TestEOLFeed_Sync_writesCatalogueRows(t *testing.T) {
	srv := eolServer(t, "quirky-product")
	defer srv.Close()
	store := newMemStore()

	// "quirky-product" 404s, so this also pins the partial-pass behaviour: the
	// run reports an error AND keeps every row it did fetch.
	res, err := testEOLFeed(t, srv).Sync(context.Background(), store, "")
	if err == nil {
		t.Fatal("expected a degraded-pass error when one product 404s")
	}
	if !strings.Contains(err.Error(), "quirky-product") {
		t.Fatalf("error should name the failing product, got %v", err)
	}
	// ubuntu 3 + nginx 2 + raspberry-pi 1 = 6.
	if res.Rows != 6 {
		t.Fatalf("rows = %d, want 6", res.Rows)
	}
	if store.countEOL() != 6 {
		t.Fatalf("stored %d rows, want 6", store.countEOL())
	}
	// A degraded pass must NOT advance the cursor — the store only writes it on
	// success, and the feed reporting one here would be a lie the runner
	// happens not to act on today.
	if res.Cursor != "" {
		t.Fatalf("cursor = %q on a degraded pass, want empty", res.Cursor)
	}
}

// A clean pass sets the cursor; a degraded one (above) does not. The cursor is
// what the console shows as "last complete pass", so it must not move on a run
// that skipped products.
func TestEOLFeed_Sync_cleanPassSetsCursor(t *testing.T) {
	srv := eolServer(t)
	defer srv.Close()
	store := newMemStore()

	res, err := testEOLFeed(t, srv).Sync(context.Background(), store, "")
	if err != nil {
		t.Fatalf("clean pass: %v", err)
	}
	// 6 as before, plus quirky-product's ONE valid cycle — its first entry has
	// no `cycle` and is dropped rather than inserted with an empty identity.
	if res.Rows != 7 {
		t.Fatalf("rows = %d, want 7", res.Rows)
	}
	if res.Cursor != "2026-09-11T12:00:00Z" {
		t.Fatalf("cursor = %q, want the injected clock", res.Cursor)
	}
	if _, ok := store.get(KindSoftware + "\x00\x00quirky-product\x00"); ok {
		t.Fatal("an entry with no cycle must be dropped, not stored with an empty identity")
	}
}

func TestEOLFeed_classifiesKindAndVendor(t *testing.T) {
	srv := eolServer(t, "quirky-product")
	defer srv.Close()
	store := newMemStore()
	_, _ = testEOLFeed(t, srv).Sync(context.Background(), store, "")

	ubuntu, ok := store.get(KindOS + "\x00Canonical\x00ubuntu\x0024.04")
	if !ok {
		t.Fatal("ubuntu 24.04 should be stored as an OS with vendor Canonical")
	}
	if ubuntu.EOLDate == nil || ubuntu.EOLDate.Format("2006-01-02") != "2029-05-31" {
		t.Fatalf("ubuntu eol_date = %v, want 2029-05-31", ubuntu.EOLDate)
	}
	// `support` is later than `eol`, and there is an
	// extendedSupport date too — the later one wins.
	if ubuntu.ExtendedSupportDate == nil || ubuntu.ExtendedSupportDate.Format("2006-01-02") != "2036-04-25" {
		t.Fatalf("ubuntu extended_support = %v, want 2036-04-25", ubuntu.ExtendedSupportDate)
	}

	// nginx is not in the OS list → software, and its vendor is unknown, which
	// must be NULL rather than an invented string.
	nginx, ok := store.get(KindSoftware + "\x00\x00nginx\x001.24")
	if !ok {
		t.Fatal("nginx 1.24 should be stored as software with a null vendor")
	}
	if nginx.Vendor != nil {
		t.Fatalf("nginx vendor = %v, want nil (unknown)", *nginx.Vendor)
	}

	// raspberry-pi is hardware.
	if _, ok := store.get(KindHardware + "\x00\x00raspberry-pi\x005"); !ok {
		t.Fatal("raspberry-pi 5 should be stored as hardware")
	}
}

// A boolean `eol` must NOT become a date. "support ended, date unknown" and
// "ended on" are different claims, and the EOL producer bands by
// days-past-EOL — a fabricated date would give it a precise number derived from
// nothing.
func TestEOLFeed_booleanDatesStayNull(t *testing.T) {
	srv := eolServer(t, "quirky-product")
	defer srv.Close()
	store := newMemStore()
	_, _ = testEOLFeed(t, srv).Sync(context.Background(), store, "")

	old, ok := store.get(KindOS + "\x00Canonical\x00ubuntu\x0014.04")
	if !ok {
		t.Fatal("ubuntu 14.04 should be stored")
	}
	if old.EOLDate != nil {
		t.Fatalf("eol:true must leave eol_date NULL, got %v", old.EOLDate)
	}
	if old.ExtendedSupportDate != nil {
		t.Fatalf("extendedSupport:true must leave the column NULL, got %v", old.ExtendedSupportDate)
	}

	current, ok := store.get(KindSoftware + "\x00\x00nginx\x001.27")
	if !ok {
		t.Fatal("nginx 1.27 should be stored (a numeric cycle is still a cycle)")
	}
	if current.EOLDate != nil {
		t.Fatalf("eol:false must leave eol_date NULL, got %v", current.EOLDate)
	}
}

// The re-run is the idempotency assertion: the same pass over the same fixtures
// leaves the same number of rows, not double.
func TestEOLFeed_Sync_isIdempotent(t *testing.T) {
	srv := eolServer(t, "quirky-product")
	defer srv.Close()
	store := newMemStore()
	f := testEOLFeed(t, srv)

	_, _ = f.Sync(context.Background(), store, "")
	first := store.countEOL()
	_, _ = f.Sync(context.Background(), store, "")
	if store.countEOL() != first {
		t.Fatalf("re-run changed the row count: %d → %d", first, store.countEOL())
	}
}

func TestEOLFeed_indexFailureIsFatalToThePass(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("upstream is down"))
	}))
	defer srv.Close()
	store := newMemStore()

	_, err := testEOLFeed(t, srv).Sync(context.Background(), store, "")
	if err == nil {
		t.Fatal("a failed index fetch must be an error, not a silent empty pass")
	}
	if store.countEOL() != 0 {
		t.Fatalf("nothing should have been written, got %d rows", store.countEOL())
	}
}

func TestDateOrBool_unmarshal(t *testing.T) {
	cases := []struct {
		in       string
		wantTime string
		wantBool *bool
	}{
		{`"2024-04-25"`, "2024-04-25", nil},
		{`true`, "", ptr(true)},
		{`false`, "", ptr(false)},
		{`null`, "", nil},
		{`"not a date"`, "", nil},
		{`12345`, "", nil},
	}
	for _, tc := range cases {
		var d dateOrBool
		if err := d.UnmarshalJSON([]byte(tc.in)); err != nil {
			t.Fatalf("%s: unexpected error %v", tc.in, err)
		}
		if tc.wantTime == "" {
			if d.Time != nil {
				t.Fatalf("%s: expected no date, got %v", tc.in, d.Time)
			}
		} else if d.Time == nil || d.Time.Format("2006-01-02") != tc.wantTime {
			t.Fatalf("%s: date = %v, want %s", tc.in, d.Time, tc.wantTime)
		}
		if tc.wantBool == nil && d.Bool != nil {
			t.Fatalf("%s: expected no bool, got %v", tc.in, *d.Bool)
		}
		if tc.wantBool != nil && (d.Bool == nil || *d.Bool != *tc.wantBool) {
			t.Fatalf("%s: bool = %v, want %v", tc.in, d.Bool, *tc.wantBool)
		}
	}
}

func TestCycleString(t *testing.T) {
	for in, want := range map[string]string{
		`"24.04"`: "24.04",
		`1.27`:    "1.27",
		`8`:       "8",
		`null`:    "",
		`{}`:      "",
	} {
		if got := cycleString([]byte(in)); got != want {
			t.Fatalf("cycleString(%s) = %q, want %q", in, got, want)
		}
	}
}
