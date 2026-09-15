package catalogfeeds

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// nvdRecorder serves the recorded NVD 2.0 fixtures and remembers every query it
// was asked, so the windowing and paging rules are assertable without a network.
type nvdRecorder struct {
	mu      sync.Mutex
	queries []map[string]string
	status  int
}

func (n *nvdRecorder) record(r *http.Request) map[string]string {
	q := map[string]string{}
	for k, v := range r.URL.Query() {
		q[k] = v[0]
	}
	n.mu.Lock()
	n.queries = append(n.queries, q)
	n.mu.Unlock()
	return q
}

func (n *nvdRecorder) seen() []map[string]string {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := make([]map[string]string, len(n.queries))
	copy(out, n.queries)
	return out
}

func nvdServer(t *testing.T, rec *nvdRecorder) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := rec.record(r)
		if rec.status != 0 && rec.status != http.StatusOK {
			w.WriteHeader(rec.status)
			_, _ = w.Write([]byte("rate limit exceeded"))
			return
		}
		fixture := "nvd_page1.json"
		if q["startIndex"] != "0" {
			fixture = "nvd_page2.json"
		}
		body, err := os.ReadFile(filepath.Join("testdata", fixture))
		if err != nil {
			t.Errorf("read fixture: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
}

func testNVDFeed(t *testing.T, srv *httptest.Server) *NVDFeed {
	t.Helper()
	f := NewNVDFeed(srv.Client(), "")
	f.BaseURL = srv.URL
	// Explicitly tiny, NOT zero: zero means "derive from whether an API key is
	// set", which would make this test sleep 6 seconds between pages.
	f.RequestDelay = time.Microsecond
	// Same reasoning for the rate-limit backoff: zero derives 30s, and the 403
	// tests would then wait out a real NVD rolling window three times over.
	f.RetryBackoff = time.Microsecond
	f.InitialWindow = 30 * 24 * time.Hour
	f.Now = func() time.Time { return time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC) }
	return f
}

func TestNVDFeed_Sync_pagesUntilTotalResults(t *testing.T) {
	rec := &nvdRecorder{}
	srv := nvdServer(t, rec)
	defer srv.Close()
	store := newMemStore()

	res, err := testNVDFeed(t, srv).Sync(context.Background(), store, "")
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	if res.Rows != 3 {
		t.Fatalf("rows = %d, want 3 (2 on page one, 1 on page two)", res.Rows)
	}
	if store.countVulns() != 3 {
		t.Fatalf("stored %d CVEs, want 3", store.countVulns())
	}
	if got := len(rec.seen()); got != 2 {
		t.Fatalf("made %d requests, want 2", got)
	}
	if res.Cursor != "2026-09-11T12:00:00Z" {
		t.Fatalf("cursor = %q, want the window end", res.Cursor)
	}
}

func TestNVDFeed_projectsMetricsAndCPEMatches(t *testing.T) {
	rec := &nvdRecorder{}
	srv := nvdServer(t, rec)
	defer srv.Close()
	store := newMemStore()

	if _, err := testNVDFeed(t, srv).Sync(context.Background(), store, ""); err != nil {
		t.Fatalf("sync: %v", err)
	}

	v := store.vulns["CVE-2024-3094"]
	if v.Severity == nil || *v.Severity != SeverityCritical {
		t.Fatalf("severity = %v, want critical", v.Severity)
	}
	if v.CVSSScore == nil || *v.CVSSScore != 10.0 {
		t.Fatalf("score = %v, want 10", v.CVSSScore)
	}
	// v3.1 must win over the v2 metric the same CVE also carries: mixing
	// ladders in one column is exactly what cvss_version exists to prevent.
	if v.CVSSVersion == nil || *v.CVSSVersion != "3.1" {
		t.Fatalf("cvss_version = %v, want 3.1 (the newest ladder present)", v.CVSSVersion)
	}
	if v.Description == nil || !strings.Contains(*v.Description, "xz") {
		t.Fatalf("description = %v, want the English one", v.Description)
	}

	// Two vulnerable CPEs; the third is `vulnerable: false` (the platform the
	// bug runs ON, not an affected product) and must not become a match rule.
	if got := store.countMatches("CVE-2024-3094"); got != 2 {
		t.Fatalf("match rules = %d, want 2 (the non-vulnerable CPE is not a match)", got)
	}

	var ranged bool
	for _, m := range store.matches["CVE-2024-3094"] {
		if m.CPEMatch == nil {
			t.Fatal("an NVD match must set cpe_match_string, not purl_range")
		}
		var rule cpeMatchRule
		if err := json.Unmarshal([]byte(*m.CPEMatch), &rule); err != nil {
			t.Fatalf("match is not the documented JSON object: %v (%s)", err, *m.CPEMatch)
		}
		if rule.VersionEndExcluding == "5.6.2" && rule.VersionStartIncluding == "5.6.0" {
			ranged = true
		}
	}
	if !ranged {
		t.Fatal("version bounds must survive into the match rule — 'xz is affected' and 'xz before 5.6.2 is affected' are different claims")
	}
}

// A score with no qualitative word must still band. Rendering a 5.5 as "—"
// reads as "not serious" rather than "the feed omitted the word".
func TestNVDFeed_derivesSeverityFromScore(t *testing.T) {
	rec := &nvdRecorder{}
	srv := nvdServer(t, rec)
	defer srv.Close()
	store := newMemStore()
	if _, err := testNVDFeed(t, srv).Sync(context.Background(), store, ""); err != nil {
		t.Fatalf("sync: %v", err)
	}
	v := store.vulns["CVE-2023-0001"]
	if v.Severity == nil || *v.Severity != SeverityMedium {
		t.Fatalf("severity = %v, want medium derived from 5.5", v.Severity)
	}
}

func TestNVDFeed_dedupesIdenticalCPEMatches(t *testing.T) {
	rec := &nvdRecorder{}
	srv := nvdServer(t, rec)
	defer srv.Close()
	store := newMemStore()
	if _, err := testNVDFeed(t, srv).Sync(context.Background(), store, ""); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if got := store.countMatches("CVE-2022-9999"); got != 1 {
		t.Fatalf("match rules = %d, want 1 — the fixture repeats the same CPE twice", got)
	}
}

// The API refuses a window wider than 120 days, so a long catch-up must be cut
// into slices rather than sent as one request that 404s.
func TestNVDFeed_splitsLongCatchUpIntoWindows(t *testing.T) {
	rec := &nvdRecorder{}
	srv := nvdServer(t, rec)
	defer srv.Close()
	store := newMemStore()

	f := testNVDFeed(t, srv)
	f.InitialWindow = 300 * 24 * time.Hour // 3 windows: 120 + 120 + 60

	if _, err := f.Sync(context.Background(), store, ""); err != nil {
		t.Fatalf("sync: %v", err)
	}
	windows := map[string]bool{}
	for _, q := range rec.seen() {
		windows[q["lastModStartDate"]+".."+q["lastModEndDate"]] = true
		start, err := time.Parse(nvdTimestampLayout+"Z07:00", q["lastModStartDate"])
		if err != nil {
			t.Fatalf("lastModStartDate %q is not the layout NVD accepts: %v", q["lastModStartDate"], err)
		}
		end, err := time.Parse(nvdTimestampLayout+"Z07:00", q["lastModEndDate"])
		if err != nil {
			t.Fatalf("lastModEndDate %q is not the layout NVD accepts: %v", q["lastModEndDate"], err)
		}
		if end.Sub(start) > nvdMaxWindow {
			t.Fatalf("window %s..%s is wider than the API's 120-day maximum", start, end)
		}
	}
	if len(windows) != 3 {
		t.Fatalf("asked for %d distinct windows, want 3", len(windows))
	}
}

func TestNVDFeed_resumesFromStoredCursor(t *testing.T) {
	rec := &nvdRecorder{}
	srv := nvdServer(t, rec)
	defer srv.Close()
	store := newMemStore()

	cursor := "2026-09-01T00:00:00Z"
	if _, err := testNVDFeed(t, srv).Sync(context.Background(), store, cursor); err != nil {
		t.Fatalf("sync: %v", err)
	}
	first := rec.seen()[0]
	if first["lastModStartDate"] != "2026-09-01T00:00:00.000Z" {
		t.Fatalf("lastModStartDate = %q, want the stored cursor", first["lastModStartDate"])
	}
}

// An unparseable cursor must fall back to the initial window, not wedge the
// feed forever on one bad string.
func TestNVDFeed_badCursorFallsBackToInitialWindow(t *testing.T) {
	rec := &nvdRecorder{}
	srv := nvdServer(t, rec)
	defer srv.Close()
	store := newMemStore()

	if _, err := testNVDFeed(t, srv).Sync(context.Background(), store, "not-a-timestamp"); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if len(rec.seen()) == 0 {
		t.Fatal("a bad cursor must not stop the feed from asking for anything")
	}
	first := rec.seen()[0]
	if first["lastModStartDate"] != "2026-08-12T12:00:00.000Z" {
		t.Fatalf("lastModStartDate = %q, want now-30d", first["lastModStartDate"])
	}
}

// A 403 (which is what NVD answers when the rate limit is exceeded) must
// surface as an error with NO cursor, so the store leaves the bookmark where it
// was and the same window is retried.
func TestNVDFeed_upstreamFailureReturnsNoCursor(t *testing.T) {
	rec := &nvdRecorder{status: http.StatusForbidden}
	srv := nvdServer(t, rec)
	defer srv.Close()
	store := newMemStore()

	res, err := testNVDFeed(t, srv).Sync(context.Background(), store, "")
	if err == nil {
		t.Fatal("a 403 must be an error")
	}
	if res.Cursor != "" {
		t.Fatalf("cursor = %q on failure, want empty so the window is retried", res.Cursor)
	}
	if store.countVulns() != 0 {
		t.Fatalf("nothing should have been stored, got %d", store.countVulns())
	}
}

// NVD answers 403 — not 429 — when a caller exceeds its rate window, which makes
// 403 the single most common TRANSIENT failure this feed sees. Treating it as a
// hard refusal loses the whole pass, and the cursor-only-advances-on-success rule
// then throws away everything already ingested.
func TestNVDFeed_rateLimit403IsRetriedAndThenSucceeds(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		n := calls
		mu.Unlock()
		if n == 1 {
			// Exactly what NVD sends over the limit.
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("rate limit exceeded"))
			return
		}
		body, err := os.ReadFile(filepath.Join("testdata", "nvd_page1.json"))
		if err != nil {
			t.Errorf("read fixture: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	f := testNVDFeed(t, srv)
	store := newMemStore()
	res, err := f.Sync(context.Background(), store, "")
	if err != nil {
		t.Fatalf("a single 403 must be waited out, not fatal: %v", err)
	}
	if store.countVulns() == 0 {
		t.Fatal("the retried page must actually be ingested")
	}
	if res.Cursor == "" {
		t.Fatal("a run that recovered from a 403 completed, so it must advance the cursor")
	}
}

// A retry is a request as far as NVD's window is concerned. A budget that did
// not count retries would be the rate-limit violation it exists to prevent.
func TestNVDFeed_retriesCountAgainstTheRequestBudget(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		calls++
		mu.Unlock()
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte("rate limit exceeded"))
	}))
	defer srv.Close()

	f := testNVDFeed(t, srv)
	f.MaxAttempts = 3
	if _, err := f.Sync(context.Background(), newMemStore(), ""); err == nil {
		t.Fatal("exhausted retries must fail the run")
	}
	mu.Lock()
	got := calls
	mu.Unlock()
	if got != 3 {
		t.Fatalf("made %d requests, want exactly MaxAttempts=3 — retries must be bounded and counted", got)
	}
}

// The failure text lands in catalog_feed_state.last_error and from there into
// the feed card, which is the only place an operator sees it. "returned 403"
// reads as an authentication problem and sends them to check a key; the actual
// fix is the rate limit.
func TestNVDFeed_rateLimitErrorNamesTheRateLimitNotJustTheStatus(t *testing.T) {
	rec := &nvdRecorder{status: http.StatusForbidden}
	srv := nvdServer(t, rec)
	defer srv.Close()

	_, err := testNVDFeed(t, srv).Sync(context.Background(), newMemStore(), "")
	if err == nil {
		t.Fatal("want an error")
	}
	for _, want := range []string{"rate limit", "403", "NVD_API_KEY"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not mention %q", err.Error(), want)
		}
	}
}

// A genuine refusal must NOT be retried — retrying a 404 is a slower way to get
// the same answer while spending the run's budget.
func TestNVDFeed_nonRateLimitStatusIsNotRetried(t *testing.T) {
	var mu sync.Mutex
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		calls++
		mu.Unlock()
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	if _, err := testNVDFeed(t, srv).Sync(context.Background(), newMemStore(), ""); err == nil {
		t.Fatal("a 404 must fail the run")
	}
	mu.Lock()
	got := calls
	mu.Unlock()
	if got != 1 {
		t.Fatalf("made %d requests, want 1 — a 404 is not a rate limit", got)
	}
}

func TestNVDRetryableAndRetryAfter(t *testing.T) {
	for status, want := range map[int]bool{
		http.StatusForbidden: true, http.StatusTooManyRequests: true,
		http.StatusServiceUnavailable: true, http.StatusBadGateway: true,
		http.StatusNotFound: false, http.StatusUnauthorized: false, http.StatusBadRequest: false,
	} {
		if got := nvdRetryable(status); got != want {
			t.Errorf("nvdRetryable(%d) = %v, want %v", status, got, want)
		}
	}
	if got := parseRetryAfter("120"); got != 2*time.Minute {
		t.Errorf("parseRetryAfter(\"120\") = %v, want 2m", got)
	}
	// An absent or unreadable header must mean "use your own backoff", never
	// "retry immediately".
	for _, bad := range []string{"", "soon", "-5", "0"} {
		if got := parseRetryAfter(bad); got != 0 {
			t.Errorf("parseRetryAfter(%q) = %v, want 0", bad, got)
		}
	}
}

// A cold start must not loop for a day: the request budget stops the run and
// reports the window it DID finish, so the next run resumes rather than
// restarting.
func TestNVDFeed_requestBudgetReportsPartialProgress(t *testing.T) {
	rec := &nvdRecorder{}
	srv := nvdServer(t, rec)
	defer srv.Close()
	store := newMemStore()

	f := testNVDFeed(t, srv)
	f.InitialWindow = 300 * 24 * time.Hour
	f.MaxRequests = 3

	res, err := f.Sync(context.Background(), store, "")
	if err != nil {
		t.Fatalf("hitting the budget is not an error: %v", err)
	}
	if len(rec.seen()) != 3 {
		t.Fatalf("made %d requests, want exactly the budget of 3", len(rec.seen()))
	}
	if res.Cursor == "" {
		t.Fatal("a budget-limited run must still report the window it finished")
	}
	if res.Cursor == "2026-09-11T12:00:00Z" {
		t.Fatal("a budget-limited run must NOT claim it reached the present")
	}
}

func TestNormalizeSeverity(t *testing.T) {
	cases := []struct {
		raw   string
		score float64
		want  string
	}{
		{"CRITICAL", 9.8, SeverityCritical},
		{"High", 7.5, SeverityHigh},
		{"MODERATE", 5.0, SeverityMedium},
		{"LOW", 2.0, SeverityLow},
		{"NONE", 0, SeverityNone},
		{"", 9.0, SeverityCritical},
		{"", 8.9, SeverityHigh},
		{"", 7.0, SeverityHigh},
		{"", 6.9, SeverityMedium},
		{"", 4.0, SeverityMedium},
		{"", 3.9, SeverityLow},
		{"", 0.1, SeverityLow},
		{"", 0, SeverityNone},
		// A word we do not recognise falls through to the score rather than
		// being taken at face value.
		{"catastrophic", 9.5, SeverityCritical},
	}
	for _, tc := range cases {
		if got := normalizeSeverity(tc.raw, tc.score); got != tc.want {
			t.Fatalf("normalizeSeverity(%q, %v) = %q, want %q", tc.raw, tc.score, got, tc.want)
		}
	}
}

func TestConvertNVD_rejectsNonCVEIdentifiers(t *testing.T) {
	if _, ok := convertNVD(nvdCVE{ID: "GHSA-xxxx"}); ok {
		t.Fatal("a non-CVE id must not be written to a CVE-keyed table")
	}
	if _, ok := convertNVD(nvdCVE{ID: "cve-2024-0001"}); !ok {
		t.Fatal("a lower-case CVE id is still a CVE id")
	}
}

func TestParseNVDTime(t *testing.T) {
	if _, ok := parseNVDTime("2024-03-29T17:15:21.150"); !ok {
		t.Fatal("the NVD 2.0 default layout must parse")
	}
	if _, ok := parseNVDTime("2024-03-29T17:15:21Z"); !ok {
		t.Fatal("RFC3339 must parse")
	}
	if _, ok := parseNVDTime("yesterday"); ok {
		t.Fatal("garbage must not parse to a time")
	}
}
