package catalogfeeds

import (
	"archive/zip"
	"bytes"
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

// osvZip builds an all.zip from the recorded advisory fixtures. Building the
// archive in the test rather than committing a binary keeps the fixtures
// readable and diffable.
func osvZip(t *testing.T, fixtures ...string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, name := range fixtures {
		body, err := os.ReadFile(filepath.Join("testdata", name))
		if err != nil {
			t.Fatalf("read fixture %s: %v", name, err)
		}
		var doc struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(body, &doc); err != nil {
			t.Fatalf("fixture %s is not JSON: %v", name, err)
		}
		w, err := zw.Create(doc.ID + ".json")
		if err != nil {
			t.Fatalf("zip create: %v", err)
		}
		if _, err := w.Write(body); err != nil {
			t.Fatalf("zip write: %v", err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip close: %v", err)
	}
	return buf.Bytes()
}

type osvRecorder struct {
	mu      sync.Mutex
	paths   []string
	ifMod   []string
	archive []byte
	// status per path suffix; 0 means 200 + archive.
	statusFor map[string]int
}

func (o *osvRecorder) seen() ([]string, []string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]string(nil), o.paths...), append([]string(nil), o.ifMod...)
}

func osvServer(t *testing.T, rec *osvRecorder) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		o := rec
		o.mu.Lock()
		o.paths = append(o.paths, r.URL.Path)
		o.ifMod = append(o.ifMod, r.Header.Get("If-Modified-Since"))
		o.mu.Unlock()

		for suffix, status := range o.statusFor {
			if strings.Contains(r.URL.Path, suffix) {
				w.WriteHeader(status)
				if status != http.StatusNotModified {
					_, _ = w.Write([]byte("upstream said no"))
				}
				return
			}
		}
		w.Header().Set("Content-Type", "application/zip")
		_, _ = w.Write(o.archive)
	}))
}

func testOSVFeed(t *testing.T, srv *httptest.Server, ecosystems ...string) *OSVFeed {
	t.Helper()
	if len(ecosystems) == 0 {
		ecosystems = []string{"Debian"}
	}
	f := NewOSVFeed(srv.Client(), ecosystems)
	f.BaseURL = srv.URL
	return f
}

func TestOSVFeed_importsOnlyRecordsWithACVEIdentity(t *testing.T) {
	rec := &osvRecorder{
		archive:   osvZip(t, "osv_debian_dsa.json", "osv_ghsa_no_cve.json", "osv_cve_direct.json"),
		statusFor: map[string]int{},
	}
	srv := osvServer(t, rec)
	defer srv.Close()
	store := newMemStore()

	res, err := testOSVFeed(t, srv).Sync(context.Background(), store, "")
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	// DSA-5122-1 aliases CVE-2022-1271; the record whose own id is a CVE is
	// taken directly; the GHSA with no CVE alias is skipped — a stated coverage
	// gap, not a silent one.
	if res.Rows != 2 {
		t.Fatalf("rows = %d, want 2", res.Rows)
	}
	if _, ok := store.vulns["CVE-2022-1271"]; !ok {
		t.Fatal("the DSA's CVE alias should become the catalogue key")
	}
	if _, ok := store.vulns["CVE-2021-44228"]; !ok {
		t.Fatal("a record whose own id is a CVE should be imported under it")
	}
	if store.countVulns() != 2 {
		t.Fatalf("stored %d, want 2 — the GHSA with no CVE must be skipped, not minted an id", store.countVulns())
	}
}

func TestOSVFeed_purlRangesCarryTheirBounds(t *testing.T) {
	rec := &osvRecorder{archive: osvZip(t, "osv_debian_dsa.json"), statusFor: map[string]int{}}
	srv := osvServer(t, rec)
	defer srv.Close()
	store := newMemStore()

	if _, err := testOSVFeed(t, srv).Sync(context.Background(), store, ""); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if got := store.countMatches("CVE-2022-1271"); got != 2 {
		t.Fatalf("match rules = %d, want 2 (gzip and xz-utils)", got)
	}
	var sawFixed, sawLastAffected bool
	for _, m := range store.matches["CVE-2022-1271"] {
		if m.PURLRange == nil {
			t.Fatal("an OSV match must set purl_range, not cpe_match_string")
		}
		var rule purlRangeRule
		if err := json.Unmarshal([]byte(*m.PURLRange), &rule); err != nil {
			t.Fatalf("match is not the documented JSON object: %v (%s)", err, *m.PURLRange)
		}
		if rule.Fixed == "1.10-4+deb11u1" {
			sawFixed = true
		}
		if rule.LastAffected == "5.2.5-2" {
			sawLastAffected = true
		}
	}
	if !sawFixed || !sawLastAffected {
		t.Fatalf("both range shapes must survive (fixed=%v last_affected=%v)", sawFixed, sawLastAffected)
	}
}

// An affected entry with no PURL matches nothing, and guessing one from
// ecosystem+name would produce authoritative-looking matches that are not.
func TestOSVFeed_affectedWithoutPurlProducesNoRule(t *testing.T) {
	rec := &osvRecorder{archive: osvZip(t, "osv_cve_direct.json"), statusFor: map[string]int{}}
	srv := osvServer(t, rec)
	defer srv.Close()
	store := newMemStore()

	if _, err := testOSVFeed(t, srv).Sync(context.Background(), store, ""); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if got := store.countMatches("CVE-2021-44228"); got != 1 {
		t.Fatalf("match rules = %d, want 1 — the second affected entry has no purl", got)
	}
}

// OSV publishes a vector and no base score. The score stays NULL rather than
// being computed here: a derived number that looks like NVD's but was produced
// by a different implementation is worse than a missing one.
func TestOSVFeed_recordsVectorAndLeavesScoreNull(t *testing.T) {
	rec := &osvRecorder{archive: osvZip(t, "osv_cve_direct.json"), statusFor: map[string]int{}}
	srv := osvServer(t, rec)
	defer srv.Close()
	store := newMemStore()

	if _, err := testOSVFeed(t, srv).Sync(context.Background(), store, ""); err != nil {
		t.Fatalf("sync: %v", err)
	}
	v := store.vulns["CVE-2021-44228"]
	if v.CVSSVector == nil || !strings.HasPrefix(*v.CVSSVector, "CVSS:3.1/") {
		t.Fatalf("cvss_vector = %v, want the OSV vector", v.CVSSVector)
	}
	if v.CVSSVersion == nil || *v.CVSSVersion != "3.1" {
		t.Fatalf("cvss_version = %v, want 3.1", v.CVSSVersion)
	}
	if v.CVSSScore != nil {
		t.Fatalf("cvss_score = %v, want NULL — OSV publishes no base score", *v.CVSSScore)
	}
	if v.Severity == nil || *v.Severity != SeverityCritical {
		t.Fatalf("severity = %v, want critical from database_specific", v.Severity)
	}
}

func TestOSVFeed_watermarkSkipsUnchangedRecords(t *testing.T) {
	rec := &osvRecorder{
		archive:   osvZip(t, "osv_debian_dsa.json", "osv_cve_direct.json"),
		statusFor: map[string]int{},
	}
	srv := osvServer(t, rec)
	defer srv.Close()
	store := newMemStore()
	f := testOSVFeed(t, srv)

	first, err := f.Sync(context.Background(), store, "")
	if err != nil {
		t.Fatalf("first sync: %v", err)
	}
	if first.Rows != 2 {
		t.Fatalf("first run rows = %d, want 2", first.Rows)
	}
	// The watermark is the newest `modified` seen: (the DSA).
	var cur osvCursor
	if err := json.Unmarshal([]byte(first.Cursor), &cur); err != nil {
		t.Fatalf("cursor is not the documented JSON map: %v (%s)", err, first.Cursor)
	}
	if cur["Debian"] != "2024-05-02T10:00:00Z" {
		t.Fatalf("watermark = %q, want the newest modified timestamp", cur["Debian"])
	}

	second, err := f.Sync(context.Background(), store, first.Cursor)
	if err != nil {
		t.Fatalf("second sync: %v", err)
	}
	if second.Rows != 0 {
		t.Fatalf("second run rows = %d, want 0 — nothing changed upstream", second.Rows)
	}
	if second.Cursor != first.Cursor {
		t.Fatalf("watermark moved with no new records: %s → %s", first.Cursor, second.Cursor)
	}
}

// 304 is the fast path, not an error, and it must leave the watermark alone.
func TestOSVFeed_notModifiedIsNotAnError(t *testing.T) {
	rec := &osvRecorder{
		archive:   osvZip(t, "osv_debian_dsa.json"),
		statusFor: map[string]int{"Debian": http.StatusNotModified},
	}
	srv := osvServer(t, rec)
	defer srv.Close()
	store := newMemStore()

	cursor := `{"Debian":"2024-05-02T10:00:00Z"}`
	res, err := testOSVFeed(t, srv).Sync(context.Background(), store, cursor)
	if err != nil {
		t.Fatalf("304 must not be an error: %v", err)
	}
	if res.Rows != 0 || store.countVulns() != 0 {
		t.Fatalf("a 304 must import nothing (rows=%d stored=%d)", res.Rows, store.countVulns())
	}
	if res.Cursor != cursor {
		t.Fatalf("cursor = %q, want it unchanged", res.Cursor)
	}
	_, ifMod := rec.seen()
	if len(ifMod) == 0 || ifMod[0] == "" {
		t.Fatal("the request must carry If-Modified-Since built from the watermark")
	}
}

// One ecosystem failing must not discard the others' progress, and the run must
// still be reported as degraded.
func TestOSVFeed_oneEcosystemFailureKeepsTheRest(t *testing.T) {
	rec := &osvRecorder{
		archive:   osvZip(t, "osv_debian_dsa.json"),
		statusFor: map[string]int{"Alpine": http.StatusInternalServerError},
	}
	srv := osvServer(t, rec)
	defer srv.Close()
	store := newMemStore()

	res, err := testOSVFeed(t, srv, "Alpine", "Debian").Sync(context.Background(), store, "")
	if err == nil {
		t.Fatal("a failing ecosystem must surface as a degraded run")
	}
	if !strings.Contains(err.Error(), "Alpine") {
		t.Fatalf("the error must name the ecosystem, got %v", err)
	}
	if res.Rows == 0 {
		t.Fatal("Debian's rows must survive Alpine's failure")
	}
	var cur osvCursor
	if err := json.Unmarshal([]byte(res.Cursor), &cur); err != nil {
		t.Fatalf("cursor is not a JSON map: %v", err)
	}
	if _, ok := cur["Alpine"]; ok {
		t.Fatal("a failed ecosystem must not get a watermark")
	}
	if cur["Debian"] == "" {
		t.Fatal("the succeeding ecosystem must keep its watermark")
	}
}

// A space in an ecosystem name must be percent-escaped, not turned into "+".
func TestOSVFeed_escapesEcosystemNamesInThePath(t *testing.T) {
	rec := &osvRecorder{archive: osvZip(t), statusFor: map[string]int{}}
	srv := osvServer(t, rec)
	defer srv.Close()

	if _, err := testOSVFeed(t, srv, "Rocky Linux").Sync(context.Background(), newMemStore(), ""); err != nil {
		t.Fatalf("sync: %v", err)
	}
	paths, _ := rec.seen()
	if len(paths) == 0 {
		t.Fatal("no request was made")
	}
	// httptest decodes the path back, so assert the DECODED form arrived
	// intact — a "+" would have arrived as a literal plus.
	if paths[0] != "/Rocky Linux/all.zip" {
		t.Fatalf("path = %q, want the space preserved through percent-escaping", paths[0])
	}
}

func TestOSVCursor_badJSONStartsOver(t *testing.T) {
	if got := parseOSVCursor("not json"); len(got) != 0 {
		t.Fatalf("an unreadable cursor must mean start over, got %v", got)
	}
	if got := parseOSVCursor(""); len(got) != 0 {
		t.Fatalf("an empty cursor must be an empty map, got %v", got)
	}
	c := osvCursor{"Debian": "2024-01-01T00:00:00Z"}
	if round := parseOSVCursor(c.encode()); round["Debian"] != c["Debian"] {
		t.Fatalf("cursor round-trip lost the watermark: %v", round)
	}
}

func TestNormalizeSeverityName(t *testing.T) {
	for raw, want := range map[string]string{
		"Critical": SeverityCritical, "HIGH": SeverityHigh, "Moderate": SeverityMedium,
		"low": SeverityLow, "Negligible": SeverityNone,
		// Unrecognised is NOT evidence of low risk.
		"spicy": "", "": "",
	} {
		if got := normalizeSeverityName(raw); got != want {
			t.Fatalf("normalizeSeverityName(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestParseOSVTime(t *testing.T) {
	if _, ok := parseOSVTime("2024-05-02T10:00:00Z"); !ok {
		t.Fatal("RFC3339 must parse")
	}
	if _, ok := parseOSVTime("2024-05-02T10:00:00.123456Z"); !ok {
		t.Fatal("fractional seconds must parse")
	}
	if _, ok := parseOSVTime("soon"); ok {
		t.Fatal("garbage must not parse")
	}
	_ = time.Now
}
