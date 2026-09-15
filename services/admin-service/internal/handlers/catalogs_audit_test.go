package handlers

// The platform-catalogue mutations must reach the audit trail.
//
// Both routes under test WRITE: one starts a mirror pass whose cost lands on a
// shared egress IP, the other applies operator-supplied rows into a catalogue
// every tenant is evaluated against. Roles, users, tenants and plan changes are
// all recorded; these were the gap. Each test drives the REAL gin handler and
// asserts on the body the emitter actually POSTed to audit-service, so removing
// the recordPlatformAudit call fails the test rather than merely changing a
// line nobody checks.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/admin-service/internal/jobs/catalogfeeds"
)

// captureAudit points the package-level emitter at a test server and returns a
// channel of the decoded POST bodies. The emitter is package state wired once
// from NewServer, so a test has to swap it and put it back.
func captureAudit(t *testing.T) <-chan map[string]interface{} {
	t.Helper()
	gin.SetMode(gin.TestMode)

	got := make(chan map[string]interface{}, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		got <- body
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"id":"` + uuid.NewString() + `"}`))
	}))
	t.Cleanup(srv.Close)

	saved := platformAuditor
	platformAuditor = NewPlatformAuditEmitter(AuditEmitterConfig{
		AuditServiceURL:    srv.URL,
		InternalAuthSecret: "test-secret",
		Enabled:            true,
	})
	t.Cleanup(func() { platformAuditor = saved })
	return got
}

// awaitAudit waits for one recorded event. Emit posts from a goroutine, so a
// test that only checked "no panic" would pass with the call removed.
func awaitAudit(t *testing.T, ch <-chan map[string]interface{}) map[string]interface{} {
	t.Helper()
	select {
	case body := <-ch:
		return body
	case <-time.After(3 * time.Second):
		t.Fatal("no audit event was recorded for a mutating catalogue route")
		return nil
	}
}

func expectNoAudit(t *testing.T, ch <-chan map[string]interface{}) {
	t.Helper()
	select {
	case body := <-ch:
		t.Fatalf("an action that changed nothing must not be audited, got %v", body["event_type"])
	case <-time.After(400 * time.Millisecond):
	}
}

// auditedEngine mounts the real catalogue routes behind an actor, the way
// AuthMiddleware leaves one in production. The emitter reads userID/email off
// the context, and asserting them is how we know the record identifies WHO
// acted rather than merely that something happened.
//
// Built here rather than by calling catalogEngine and adding middleware after:
// gin applies a handler chain at REGISTRATION time, so an engine-level Use()
// after the routes exist affects nothing — and the test would then assert an
// absent actor was absent.
func auditedEngine(store CatalogStore, runner CatalogFeedRunner, importer CatalogBundleImporter) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("userID", auditActorID)
		c.Set("email", auditActorEmail)
		c.Next()
	})
	grp := r.Group(apiBase)
	grp.POST("/admin/catalogs/feeds/:feed/sync", SyncCatalogFeed(runner))
	grp.POST("/admin/catalogs/import-bundle", ImportCatalogBundle(importer))
	return r
}

var (
	auditActorID    = uuid.NewString()
	auditActorEmail = "platform-admin@example.com"
)

func actorRequest(t *testing.T, eng *gin.Engine, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	w := httptest.NewRecorder()
	eng.ServeHTTP(w, req)
	return w
}

// --- feed sync ---------------------------------------------------------------

func TestCatalogAudit_SyncRecordsTheActionAndTheFeed(t *testing.T) {
	events := captureAudit(t)
	runner := &stubFeedRunner{enabled: true, interval: 24 * time.Hour}
	eng := auditedEngine(&stubCatalogStore{}, runner, nil)

	w := actorRequest(t, eng, http.MethodPost, catalogBase+"/feeds/nvd/sync")
	if w.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202; body=%s", w.Code, w.Body.String())
	}

	body := awaitAudit(t, events)
	assertField(t, body, "user_type", "platform")
	assertField(t, body, "event_type", "catalog_feed.sync_started")
	assertField(t, body, "action", "sync")
	assertField(t, body, "event_category", "system")
	assertField(t, body, "resource_type", "catalog_feed")
	// Who ran it. NVD's rate limit is per egress IP, so a record that cannot
	// name the operator answers none of the questions it exists for.
	assertField(t, body, "user_id", auditActorID)
	assertField(t, body, "user_email", auditActorEmail)

	meta, _ := body["metadata"].(map[string]interface{})
	if meta == nil || meta["feed"] != "nvd" {
		t.Fatalf("the audit record must name WHICH feed was run, got metadata %v", meta)
	}
}

// A refused trigger changed nothing. An audit trail padded with non-events is
// one people stop reading.
func TestCatalogAudit_RefusedSyncIsNotAudited(t *testing.T) {
	events := captureAudit(t)

	// Kill switch on: 409, nothing started.
	disabled := &stubFeedRunner{enabled: false, err: catalogfeeds.ErrFeedsDisabled}
	w := actorRequest(t, auditedEngine(&stubCatalogStore{}, disabled, nil),
		http.MethodPost, catalogBase+"/feeds/nvd/sync")
	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", w.Code)
	}

	// Unknown feed: 404, nothing started.
	ok := &stubFeedRunner{enabled: true}
	w = actorRequest(t, auditedEngine(&stubCatalogStore{}, ok, nil),
		http.MethodPost, catalogBase+"/feeds/not-a-feed/sync")
	if w.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", w.Code)
	}

	expectNoAudit(t, events)
}

// --- bundle import -----------------------------------------------------------

func importResultFixture() *catalogfeeds.ImportResult {
	generated := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	return &catalogfeeds.ImportResult{
		Files: []catalogfeeds.BundleFile{
			{Name: "eol_catalogue.jsonl", SHA256: "aaaa1111", Rows: 1842, Bytes: 91000},
			{Name: "vulnerability_catalogue.jsonl", SHA256: "bbbb2222", Rows: 90210, Bytes: 40000000},
		},
		EOLRows: 1842, VulnerabilityRows: 90210, MatchRows: 512,
		GeneratedAt: &generated,
	}
}

// The manifest hash is the part that matters: after a bad bundle, "an import
// happened" is not the question — "which bytes were applied" is, and only the
// hash settles it.
func TestCatalogAudit_BundleImportRecordsHashesAndMeasuredRowCounts(t *testing.T) {
	events := captureAudit(t)
	importer := &stubBundleImporter{result: importResultFixture()}
	eng := auditedEngine(&stubCatalogStore{}, nil, importer)

	body, ct := multipartBundle(t, "file", "catalog-bundle-2026-09-10.tar.gz", []byte("tarball"))
	w := doMultipart(eng, catalogBase+"/import-bundle", body, ct)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", w.Code, w.Body.String())
	}

	rec := awaitAudit(t, events)
	assertField(t, rec, "user_type", "platform")
	assertField(t, rec, "event_type", "catalog_bundle.imported")
	assertField(t, rec, "action", "import")
	assertField(t, rec, "resource_type", "catalog_bundle")
	assertField(t, rec, "user_id", auditActorID)
	assertField(t, rec, "user_email", auditActorEmail)

	meta, _ := rec["metadata"].(map[string]interface{})
	if meta == nil {
		t.Fatal("the import record must carry metadata")
	}
	for key, want := range map[string]float64{
		"eol_rows": 1842, "vulnerability_rows": 90210, "match_rows": 512,
	} {
		if got, _ := meta[key].(float64); got != want {
			t.Errorf("metadata[%q] = %v, want %v", key, meta[key], want)
		}
	}
	if meta["bundle_generated_at"] != "2026-09-10T12:00:00Z" {
		t.Errorf("bundle_generated_at = %v", meta["bundle_generated_at"])
	}

	files, _ := meta["files"].([]interface{})
	if len(files) != 2 {
		t.Fatalf("metadata.files has %d entries, want 2", len(files))
	}
	seen := map[string]string{}
	for _, raw := range files {
		f, _ := raw.(map[string]interface{})
		name, _ := f["name"].(string)
		sha, _ := f["sha256"].(string)
		seen[name] = sha
	}
	if seen["eol_catalogue.jsonl"] != "aaaa1111" || seen["vulnerability_catalogue.jsonl"] != "bbbb2222" {
		t.Fatalf("the manifest SHA-256 per file must be in the audit record, got %v", seen)
	}
}

// A partial apply is the messiest write in this slice — half a catalogue, from
// a file carried in by hand. It is exactly the one that must not be missing
// from the trail because the request ended in an error status.
func TestCatalogAudit_PartiallyAppliedBundleIsStillAudited(t *testing.T) {
	events := captureAudit(t)
	partial := &catalogfeeds.ImportResult{
		Files:   []catalogfeeds.BundleFile{{Name: "eol_catalogue.jsonl", SHA256: "cccc3333", Rows: 1842}},
		EOLRows: 1842,
	}
	importer := &stubBundleImporter{
		result: partial,
		err:    catalogfeeds.ErrBundleApplyFailed,
	}
	eng := auditedEngine(&stubCatalogStore{}, nil, importer)

	body, ct := multipartBundle(t, "file", "bundle.tar.gz", []byte("tarball"))
	w := doMultipart(eng, catalogBase+"/import-bundle", body, ct)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", w.Code)
	}

	rec := awaitAudit(t, events)
	assertField(t, rec, "event_type", "catalog_bundle.partially_imported")
	meta, _ := rec["metadata"].(map[string]interface{})
	if got, _ := meta["eol_rows"].(float64); got != 1842 {
		t.Fatalf("a partial apply must record what it DID write, got %v", meta["eol_rows"])
	}
}

// A bundle refused by verification wrote nothing, so there is no mutation to
// record. This is the polarity check on the two tests above: without it, an
// implementation that audited unconditionally would look correct.
func TestCatalogAudit_RefusedBundleIsNotAudited(t *testing.T) {
	events := captureAudit(t)
	importer := &stubBundleImporter{
		err: errFromString("vulnerability_catalogue.jsonl: sha256 mismatch"),
	}
	eng := auditedEngine(&stubCatalogStore{}, nil, importer)

	body, ct := multipartBundle(t, "file", "bundle.tar.gz", []byte("tarball"))
	w := doMultipart(eng, catalogBase+"/import-bundle", body, ct)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
	expectNoAudit(t, events)
}

type stringErr string

func (e stringErr) Error() string { return string(e) }

func errFromString(s string) error { return stringErr(s) }
