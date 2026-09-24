package handlers

// Contract test for the platform-catalogue HTTP surface: /admin/catalogs/**.
//
// The REAL gin handlers run over httptest with in-memory stubs — no database,
// no network, no feed runner — and every response body is validated against
// api/openapi/admin-service.openapi.yaml through the shared harness in
// contract_harness_test.go.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/vistasecurity/vistaplatform/admin-service/internal/jobs/catalogfeeds"
)

// --- stubs ------------------------------------------------------------------

type stubCatalogStore struct {
	eol      []catalogfeeds.EOLEntry
	eolTotal int64
	eolErr   error

	vulns      []catalogfeeds.Vulnerability
	vulnsTotal int64
	vulnsErr   error

	states    []catalogfeeds.FeedState
	statesErr error

	lastEOLQuery  catalogfeeds.EOLQuery
	lastVulnQuery catalogfeeds.VulnQuery
}

func (s *stubCatalogStore) ListEOL(_ context.Context, q catalogfeeds.EOLQuery) ([]catalogfeeds.EOLEntry, int64, error) {
	s.lastEOLQuery = q
	return s.eol, s.eolTotal, s.eolErr
}

func (s *stubCatalogStore) ListVulnerabilities(_ context.Context, q catalogfeeds.VulnQuery) ([]catalogfeeds.Vulnerability, int64, error) {
	s.lastVulnQuery = q
	return s.vulns, s.vulnsTotal, s.vulnsErr
}

func (s *stubCatalogStore) FeedStates(context.Context) ([]catalogfeeds.FeedState, error) {
	return s.states, s.statesErr
}

type stubFeedRunner struct {
	enabled  bool
	interval time.Duration
	err      error
	synced   []string
}

func (r *stubFeedRunner) Enabled() bool           { return r.enabled }
func (r *stubFeedRunner) Interval() time.Duration { return r.interval }
func (r *stubFeedRunner) SyncNow(feed string) error {
	r.synced = append(r.synced, feed)
	return r.err
}

type stubBundleImporter struct {
	result *catalogfeeds.ImportResult
	err    error
	body   []byte
}

func (b *stubBundleImporter) ImportBundle(_ context.Context, r io.Reader) (*catalogfeeds.ImportResult, error) {
	b.body, _ = io.ReadAll(r)
	return b.result, b.err
}

// --- engine -----------------------------------------------------------------

func catalogEngine(store CatalogStore, runner CatalogFeedRunner, importer CatalogBundleImporter) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	grp := r.Group(apiBase)
	grp.GET("/admin/catalogs/eol", ListEOLCatalogue(store))
	grp.GET("/admin/catalogs/vulnerabilities", ListVulnerabilityCatalogue(store))
	grp.GET("/admin/catalogs/feeds", ListCatalogFeeds(store, runner))
	grp.POST("/admin/catalogs/feeds/:feed/sync", SyncCatalogFeed(runner))
	grp.POST("/admin/catalogs/import-bundle", ImportCatalogBundle(importer))
	return r
}

const catalogBase = apiBase + "/admin/catalogs"

func sampleEOLEntries() []catalogfeeds.EOLEntry {
	eol := time.Date(2029, 5, 31, 0, 0, 0, 0, time.UTC)
	updated := time.Date(2026, 9, 11, 6, 0, 0, 0, time.UTC)
	vendor := "Canonical"
	src := "https://endoflife.date/ubuntu"
	return []catalogfeeds.EOLEntry{
		{
			ID: "3f3d2c1b-0000-4000-8000-000000000001", ProductKind: "os",
			Vendor: &vendor, Product: "ubuntu", Cycle: "24.04",
			EOLDate: &eol, SourceURL: &src, SourceKind: "imported", UpdatedAt: &updated,
		},
		// The nullable-everything row: an unknown vendor, no dates, no source.
		// This is the shape the contract most needs pinned — it is what a
		// sparse upstream document produces.
		{
			ID: "3f3d2c1b-0000-4000-8000-000000000002", ProductKind: "software",
			Product: "nginx", Cycle: "1.27", SourceKind: "imported",
		},
	}
}

func sampleVulnerabilities() []catalogfeeds.Vulnerability {
	published := time.Date(2024, 3, 29, 17, 15, 21, 0, time.UTC)
	score := 10.0
	version, vector, sev := "3.1", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "critical"
	desc := "Malicious code in xz."
	return []catalogfeeds.Vulnerability{
		{
			CVEID: "CVE-2024-3094", CVSSVersion: &version, CVSSScore: &score,
			CVSSVector: &vector, Severity: &sev, PublishedAt: &published,
			Description: &desc, SourceKind: "imported",
		},
		// OSV's shape: a vector and no score. The contract must allow it, or
		// the only way to satisfy the spec would be to invent a number.
		{CVEID: "CVE-2021-44228", CVSSVector: &vector, CVSSVersion: &version, SourceKind: "imported"},
	}
}

// --- EOL list ---------------------------------------------------------------

func TestContract_ListEOLCatalogue_200(t *testing.T) {
	sv := loadSpec(t)
	store := &stubCatalogStore{eol: sampleEOLEntries(), eolTotal: 2}
	eng := catalogEngine(store, &stubFeedRunner{enabled: true}, nil)

	w := doRequest(eng, http.MethodGet, catalogBase+"/eol?search=ubuntu&kind=os&page=2&page_size=25", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "EolCatalogueListResponse", w.Body.Bytes())

	if store.lastEOLQuery.Search != "ubuntu" || store.lastEOLQuery.Kind != "os" ||
		store.lastEOLQuery.Page != 2 || store.lastEOLQuery.PageSize != 25 {
		t.Fatalf("filters were not passed through: %+v", store.lastEOLQuery)
	}
}

func TestContract_ListEOLCatalogue_200_empty(t *testing.T) {
	sv := loadSpec(t)
	// nil, not an empty slice — the handler must still render `[]`, because a
	// null list and an empty one mean different things to a client.
	eng := catalogEngine(&stubCatalogStore{eol: nil}, &stubFeedRunner{}, nil)

	w := doRequest(eng, http.MethodGet, catalogBase+"/eol", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "EolCatalogueListResponse", w.Body.Bytes())
	var body map[string]json.RawMessage
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if string(body["entries"]) != "[]" {
		t.Fatalf("entries = %s, want []", body["entries"])
	}
}

// The response must echo the page it SERVED, not the one that was asked for.
func TestContract_ListEOLCatalogue_clampsPageSize(t *testing.T) {
	eng := catalogEngine(&stubCatalogStore{}, &stubFeedRunner{}, nil)
	w := doRequest(eng, http.MethodGet, catalogBase+"/eol?page=0&page_size=100000", nil)
	var body struct {
		Page     int `json:"page"`
		PageSize int `json:"page_size"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body.Page != 1 || body.PageSize != catalogfeeds.MaxPageSize {
		t.Fatalf("echoed page=%d page_size=%d, want 1 and %d", body.Page, body.PageSize, catalogfeeds.MaxPageSize)
	}
}

func TestContract_ListEOLCatalogue_400_badKind(t *testing.T) {
	sv := loadSpec(t)
	eng := catalogEngine(&stubCatalogStore{}, &stubFeedRunner{}, nil)
	w := doRequest(eng, http.MethodGet, catalogBase+"/eol?kind=firmware", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_ListEOLCatalogue_500(t *testing.T) {
	sv := loadSpec(t)
	eng := catalogEngine(&stubCatalogStore{eolErr: errors.New("boom")}, &stubFeedRunner{}, nil)
	w := doRequest(eng, http.MethodGet, catalogBase+"/eol", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- vulnerability list ------------------------------------------------------

func TestContract_ListVulnerabilityCatalogue_200(t *testing.T) {
	sv := loadSpec(t)
	store := &stubCatalogStore{vulns: sampleVulnerabilities(), vulnsTotal: 2}
	eng := catalogEngine(store, &stubFeedRunner{}, nil)

	w := doRequest(eng, http.MethodGet, catalogBase+"/vulnerabilities?search=xz&severity=critical", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "VulnerabilityCatalogueListResponse", w.Body.Bytes())
	if store.lastVulnQuery.Search != "xz" || store.lastVulnQuery.Severity != "critical" {
		t.Fatalf("filters were not passed through: %+v", store.lastVulnQuery)
	}
}

func TestContract_ListVulnerabilityCatalogue_200_empty(t *testing.T) {
	sv := loadSpec(t)
	eng := catalogEngine(&stubCatalogStore{vulns: nil}, &stubFeedRunner{}, nil)
	w := doRequest(eng, http.MethodGet, catalogBase+"/vulnerabilities", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "VulnerabilityCatalogueListResponse", w.Body.Bytes())
}

func TestContract_ListVulnerabilityCatalogue_400_badSeverity(t *testing.T) {
	sv := loadSpec(t)
	eng := catalogEngine(&stubCatalogStore{}, &stubFeedRunner{}, nil)
	w := doRequest(eng, http.MethodGet, catalogBase+"/vulnerabilities?severity=spicy", nil)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_ListVulnerabilityCatalogue_500(t *testing.T) {
	sv := loadSpec(t)
	eng := catalogEngine(&stubCatalogStore{vulnsErr: errors.New("boom")}, &stubFeedRunner{}, nil)
	w := doRequest(eng, http.MethodGet, catalogBase+"/vulnerabilities", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- feed status --------------------------------------------------------------

func TestContract_ListCatalogFeeds_200(t *testing.T) {
	sv := loadSpec(t)
	ran := time.Date(2026, 9, 11, 6, 0, 0, 0, time.UTC)
	cursor := `{"Debian":"2026-09-10T00:00:00Z"}`
	failure := "nvd window: 403 rate limit exceeded"
	store := &stubCatalogStore{states: []catalogfeeds.FeedState{
		{Feed: "eol", LastStatus: "ok", LastRunAt: &ran, RowCount: 1842, UpdatedAt: &ran},
		{Feed: "nvd", LastStatus: "error", LastRunAt: &ran, LastError: &failure},
		// The feed that has never run must be LISTED, not omitted. Its nil
		// ecosystem list must still go out as an array.
		{Feed: "osv", LastStatus: "never", Cursor: &cursor},
	}}
	eng := catalogEngine(store, &stubFeedRunner{enabled: true, interval: 24 * time.Hour}, nil)

	w := doRequest(eng, http.MethodGet, catalogBase+"/feeds", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "CatalogFeedListResponse", w.Body.Bytes())

	var body struct {
		Enabled         bool `json:"enabled"`
		IntervalSeconds int  `json:"interval_seconds"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if !body.Enabled || body.IntervalSeconds != 86400 {
		t.Fatalf("enabled=%v interval=%d, want true and 86400", body.Enabled, body.IntervalSeconds)
	}
}

// Decision 13 (RC-29): OSV reports per-ecosystem status, so a failing Ubuntu
// shows against Ubuntu while Debian and Alpine stay green.
func TestContract_ListCatalogFeeds_200_perEcosystemStatus(t *testing.T) {
	sv := loadSpec(t)
	ran := time.Date(2026, 9, 23, 6, 0, 0, 0, time.UTC)
	earlier := ran.Add(-48 * time.Hour)
	wm := "2026-09-22T00:00:00Z"
	runErr := "osv mirror incomplete: 1 of 3 ecosystems failed (Ubuntu)"
	ubuntuErr := "archive for Ubuntu exceeds the 2048 MiB cap"
	store := &stubCatalogStore{states: []catalogfeeds.FeedState{
		{Feed: "osv", LastStatus: "error", LastRunAt: &ran, LastError: &runErr, RowCount: 72,
			Ecosystems: []catalogfeeds.EcosystemStatus{
				{Name: "Alpine", Status: "ok", Rows: 4, Watermark: &wm, LastRunAt: &ran, LastSuccessAt: &ran},
				{Name: "Debian", Status: "ok", Rows: 68, Watermark: &wm, LastRunAt: &ran, LastSuccessAt: &ran},
				{Name: "Ubuntu", Status: "error", LastError: &ubuntuErr, LastRunAt: &ran, LastSuccessAt: &earlier},
			}},
	}}
	eng := catalogEngine(store, &stubFeedRunner{enabled: true, interval: 24 * time.Hour}, nil)
	w := doRequest(eng, http.MethodGet, catalogBase+"/feeds", nil)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "CatalogFeedListResponse", w.Body.Bytes())
	var body struct {
		Feeds []struct {
			Ecosystems []struct {
				Name      string  `json:"name"`
				Status    string  `json:"status"`
				LastError *string `json:"last_error"`
			} `json:"ecosystems"`
		} `json:"feeds"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(body.Feeds) != 1 || len(body.Feeds[0].Ecosystems) != 3 || body.Feeds[0].Ecosystems[2].Status != "error" ||
		body.Feeds[0].Ecosystems[2].LastError == nil {
		t.Fatalf("ecosystems did not reach the wire intact: %s", w.Body.String())
	}
}

// With the kill switch off the page must be able to SAY so.
func TestContract_ListCatalogFeeds_reportsDisabled(t *testing.T) {
	sv := loadSpec(t)
	eng := catalogEngine(&stubCatalogStore{states: []catalogfeeds.FeedState{}}, &stubFeedRunner{enabled: false}, nil)
	w := doRequest(eng, http.MethodGet, catalogBase+"/feeds", nil)
	sv.assertConforms(t, "CatalogFeedListResponse", w.Body.Bytes())
	var body struct {
		Enabled bool `json:"enabled"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &body)
	if body.Enabled {
		t.Fatal("enabled must be false when the runner is switched off")
	}
}

func TestContract_ListCatalogFeeds_500(t *testing.T) {
	sv := loadSpec(t)
	eng := catalogEngine(&stubCatalogStore{statesErr: errors.New("boom")}, &stubFeedRunner{}, nil)
	w := doRequest(eng, http.MethodGet, catalogBase+"/feeds", nil)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- manual sync ---------------------------------------------------------------

func TestContract_SyncCatalogFeed_202(t *testing.T) {
	sv := loadSpec(t)
	runner := &stubFeedRunner{enabled: true, interval: time.Hour}
	eng := catalogEngine(&stubCatalogStore{}, runner, nil)

	w := doRequest(eng, http.MethodPost, catalogBase+"/feeds/nvd/sync", nil)
	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "CatalogFeedSyncResponse", w.Body.Bytes())
	if len(runner.synced) != 1 || runner.synced[0] != "nvd" {
		t.Fatalf("runner saw %v, want [nvd]", runner.synced)
	}
}

func TestContract_SyncCatalogFeed_404_unknownFeed(t *testing.T) {
	sv := loadSpec(t)
	runner := &stubFeedRunner{enabled: true}
	eng := catalogEngine(&stubCatalogStore{}, runner, nil)

	w := doRequest(eng, http.MethodPost, catalogBase+"/feeds/not-a-feed/sync", nil)
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
	if len(runner.synced) != 0 {
		t.Fatal("an unknown feed must be rejected before the runner is touched")
	}
}

// Disabled is 409, not 403: the operator HAS the permission, the deployment has
// the feature off. Collapsing the two sends someone to look at their role.
func TestContract_SyncCatalogFeed_409_disabled(t *testing.T) {
	sv := loadSpec(t)
	eng := catalogEngine(&stubCatalogStore{}, &stubFeedRunner{err: catalogfeeds.ErrFeedsDisabled}, nil)
	w := doRequest(eng, http.MethodPost, catalogBase+"/feeds/eol/sync", nil)
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_SyncCatalogFeed_409_busy(t *testing.T) {
	sv := loadSpec(t)
	eng := catalogEngine(&stubCatalogStore{}, &stubFeedRunner{err: catalogfeeds.ErrFeedBusy}, nil)
	w := doRequest(eng, http.MethodPost, catalogBase+"/feeds/osv/sync", nil)
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_SyncCatalogFeed_503_noRunner(t *testing.T) {
	sv := loadSpec(t)
	eng := catalogEngine(&stubCatalogStore{}, nil, nil)
	w := doRequest(eng, http.MethodPost, catalogBase+"/feeds/eol/sync", nil)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

// --- bundle import -------------------------------------------------------------

func multipartBundle(t *testing.T, field, filename string, body []byte) (*bytes.Buffer, string) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	part, err := mw.CreateFormFile(field, filename)
	if err != nil {
		t.Fatalf("create form file: %v", err)
	}
	if _, err := part.Write(body); err != nil {
		t.Fatalf("write part: %v", err)
	}
	if err := mw.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}
	return &buf, mw.FormDataContentType()
}

func doMultipart(eng *gin.Engine, path string, body *bytes.Buffer, contentType string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, body)
	req.Header.Set("Content-Type", contentType)
	w := httptest.NewRecorder()
	eng.ServeHTTP(w, req)
	return w
}

func TestContract_ImportCatalogBundle_200(t *testing.T) {
	sv := loadSpec(t)
	generated := time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC)
	importer := &stubBundleImporter{result: &catalogfeeds.ImportResult{
		Files: []catalogfeeds.BundleFile{
			{Name: "eol_catalogue.jsonl", SHA256: "abc", Rows: 1842, Bytes: 400000},
			{Name: "vulnerability_catalogue.jsonl", SHA256: "def", Rows: 90210, Bytes: 90000000},
		},
		EOLRows: 1842, VulnerabilityRows: 90210, MatchRows: 412000, GeneratedAt: &generated,
	}}
	eng := catalogEngine(&stubCatalogStore{}, &stubFeedRunner{enabled: true}, importer)

	body, ct := multipartBundle(t, "file", "catalog-bundle-2026-09-10.tar.gz", []byte("not really a tarball"))
	w := doMultipart(eng, catalogBase+"/import-bundle", body, ct)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "CatalogBundleImportResponse", w.Body.Bytes())
	if string(importer.body) != "not really a tarball" {
		t.Fatalf("the uploaded bytes did not reach the importer: %q", importer.body)
	}
}

// The verification failure is the operator's diagnosis — it must survive to the
// response rather than be replaced with "import failed".
func TestContract_ImportCatalogBundle_400_surfacesTheVerificationError(t *testing.T) {
	sv := loadSpec(t)
	importer := &stubBundleImporter{err: errors.New("vulnerability_catalogue.jsonl: sha256 mismatch — manifest says abc, bundle contains def")}
	eng := catalogEngine(&stubCatalogStore{}, &stubFeedRunner{enabled: true}, importer)

	body, ct := multipartBundle(t, "file", "bundle.tar.gz", []byte("x"))
	w := doMultipart(eng, catalogBase+"/import-bundle", body, ct)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
	var e struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &e)
	if e.Error == "" || !bytes.Contains([]byte(e.Error), []byte("sha256 mismatch")) {
		t.Fatalf("error = %q, want the verification failure verbatim", e.Error)
	}
}

func TestContract_ImportCatalogBundle_400_noFile(t *testing.T) {
	sv := loadSpec(t)
	eng := catalogEngine(&stubCatalogStore{}, &stubFeedRunner{enabled: true}, &stubBundleImporter{})

	body, ct := multipartBundle(t, "bundle", "bundle.tar.gz", []byte("x"))
	w := doMultipart(eng, catalogBase+"/import-bundle", body, ct)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}

func TestContract_ImportCatalogBundle_503_noImporter(t *testing.T) {
	sv := loadSpec(t)
	eng := catalogEngine(&stubCatalogStore{}, &stubFeedRunner{enabled: true}, nil)
	body, ct := multipartBundle(t, "file", "bundle.tar.gz", []byte("x"))
	w := doMultipart(eng, catalogBase+"/import-bundle", body, ct)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503; body=%s", w.Code, w.Body.String())
	}
	sv.assertConforms(t, "LegacyError", w.Body.Bytes())
}
