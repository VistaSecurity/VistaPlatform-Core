package handlers

// Catalog ▸ End-of-life and Catalog ▸ Vulnerability feed (ADR-0006 D7).
//
// The platform-admin surface over the non-crypto catalogues: browse
// eol_catalogue and vulnerability_catalogue, see how each mirror feed is doing,
// run one out of band, and import an offline bundle on an air-gapped install.
// Every route is gated on catalogs.manage and mounted under /admin, which is a
// declared admin-plane prefix — the tenant host serves none of it.
//
// Shape notes, for the contract:
//   - Lists are wrapped under their resource key with total/page/page_size, and
//     the array is ALWAYS present (empty, never null). A null list and an empty
//     one render identically in a table but mean different things to a client,
//     and this surface is new enough to get it right rather than pin the
//     pre-envelope nullable shape the older handlers are stuck with.
//   - Errors are the legacy single-string `{"error": "..."}` used everywhere
//     else in this service.
//
// The handlers take interfaces, not *sql.DB, so the contract tests run the REAL
// gin handlers over httptest with in-memory stubs — the pattern from
// entitlements_contract_test.go.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/vistasecurity/vistaplatform/admin-service/internal/jobs/catalogfeeds"
)

// CatalogStore is the read/import surface the handlers need. A narrower
// interface than catalogfeeds.Store on purpose: an HTTP handler has no business
// advancing a feed cursor.
type CatalogStore interface {
	ListEOL(ctx context.Context, q catalogfeeds.EOLQuery) ([]catalogfeeds.EOLEntry, int64, error)
	ListVulnerabilities(ctx context.Context, q catalogfeeds.VulnQuery) ([]catalogfeeds.Vulnerability, int64, error)
	FeedStates(ctx context.Context) ([]catalogfeeds.FeedState, error)
}

// CatalogFeedRunner is the control surface the console drives.
type CatalogFeedRunner interface {
	Enabled() bool
	Interval() time.Duration
	SyncNow(feed string) error
}

// CatalogBundleImporter applies an uploaded offline bundle. Separate from
// CatalogStore so a deployment could one day refuse imports without refusing
// reads.
type CatalogBundleImporter interface {
	ImportBundle(ctx context.Context, r io.Reader) (*catalogfeeds.ImportResult, error)
}

// --- responses --------------------------------------------------------------

type eolListResponse struct {
	Entries  []catalogfeeds.EOLEntry `json:"entries"`
	Total    int64                   `json:"total"`
	Page     int                     `json:"page"`
	PageSize int                     `json:"page_size"`
}

type vulnerabilityListResponse struct {
	Vulnerabilities []catalogfeeds.Vulnerability `json:"vulnerabilities"`
	Total           int64                        `json:"total"`
	Page            int                          `json:"page"`
	PageSize        int                          `json:"page_size"`
}

type catalogFeedListResponse struct {
	Feeds []catalogfeeds.FeedState `json:"feeds"`
	// Enabled is the CATALOG_FEEDS_ENABLED kill switch. The console renders a
	// banner from it rather than leaving an operator to wonder why "last run"
	// never moves.
	Enabled bool `json:"enabled"`
	// IntervalSeconds is the scheduled cadence, so the page can say "daily"
	// without hard-coding what this deployment is configured for.
	IntervalSeconds int `json:"interval_seconds"`
}

type catalogFeedSyncResponse struct {
	Feed    string `json:"feed"`
	Status  string `json:"status"`
	Message string `json:"message"`
}

type catalogBundleImportResponse struct {
	Files             []catalogfeeds.BundleFile `json:"files"`
	EOLRows           int64                     `json:"eol_rows"`
	VulnerabilityRows int64                     `json:"vulnerability_rows"`
	MatchRows         int64                     `json:"match_rows"`
	GeneratedAt       *time.Time                `json:"generated_at,omitempty"`
	Message           string                    `json:"message"`
}

// --- handlers ---------------------------------------------------------------

// ListEOLCatalogue serves GET /admin/catalogs/eol.
func ListEOLCatalogue(store CatalogStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		kind := c.Query("kind")
		if kind != "" && !validProductKind(kind) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "kind must be one of os, software, hardware"})
			return
		}
		page, pageSize := pageParams(c)
		entries, total, err := store.ListEOL(c.Request.Context(), catalogfeeds.EOLQuery{
			Search: c.Query("search"), Kind: kind, Page: page, PageSize: pageSize,
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load the end-of-life catalogue"})
			return
		}
		if entries == nil {
			entries = []catalogfeeds.EOLEntry{}
		}
		normPage, normSize := catalogPageEcho(page, pageSize)
		c.JSON(http.StatusOK, eolListResponse{
			Entries: entries, Total: total, Page: normPage, PageSize: normSize,
		})
	}
}

// ListVulnerabilityCatalogue serves GET /admin/catalogs/vulnerabilities.
func ListVulnerabilityCatalogue(store CatalogStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		severity := c.Query("severity")
		if severity != "" && !validSeverity(severity) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "severity must be one of none, low, medium, high, critical"})
			return
		}
		page, pageSize := pageParams(c)
		vulns, total, err := store.ListVulnerabilities(c.Request.Context(), catalogfeeds.VulnQuery{
			Search: c.Query("search"), Severity: severity, Page: page, PageSize: pageSize,
		})
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load the vulnerability catalogue"})
			return
		}
		if vulns == nil {
			vulns = []catalogfeeds.Vulnerability{}
		}
		normPage, normSize := catalogPageEcho(page, pageSize)
		c.JSON(http.StatusOK, vulnerabilityListResponse{
			Vulnerabilities: vulns, Total: total, Page: normPage, PageSize: normSize,
		})
	}
}

// ListCatalogFeeds serves GET /admin/catalogs/feeds.
func ListCatalogFeeds(store CatalogStore, runner CatalogFeedRunner) gin.HandlerFunc {
	return func(c *gin.Context) {
		states, err := store.FeedStates(c.Request.Context())
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load feed status"})
			return
		}
		if states == nil {
			states = []catalogfeeds.FeedState{}
		}
		for i := range states {
			// Always an array on the wire (the contract requires it), so the
			// console never has to tell "no ecosystems" from "field missing".
			if states[i].Ecosystems == nil {
				states[i].Ecosystems = []catalogfeeds.EcosystemStatus{}
			}
		}
		resp := catalogFeedListResponse{Feeds: states}
		if runner != nil {
			resp.Enabled = runner.Enabled()
			resp.IntervalSeconds = int(runner.Interval() / time.Second)
		}
		c.JSON(http.StatusOK, resp)
	}
}

// SyncCatalogFeed serves POST /admin/catalogs/feeds/{feed}/sync.
//
// 202, not 200: the run is started, not finished. A mirror pass takes minutes
// (NVD's rate limit alone guarantees it), so blocking the request until it
// completes would time out at the gateway and leave the operator with no idea
// whether the run happened. The outcome lands in catalog_feed_state, which is
// what the page polls.
func SyncCatalogFeed(runner CatalogFeedRunner) gin.HandlerFunc {
	return func(c *gin.Context) {
		feed := c.Param("feed")
		if !catalogfeeds.ValidFeed(feed) {
			c.JSON(http.StatusNotFound, gin.H{"error": fmt.Sprintf("Unknown feed %q", feed)})
			return
		}
		if runner == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "The feed runner is not configured in this deployment"})
			return
		}
		switch err := runner.SyncNow(feed); {
		case err == nil:
			// Recorded like every other platform-admin mutation (roles, users,
			// tenants, plan changes). Re-pointing the platform at a feed run is
			// an operator action with a cost at the far end — NVD's rate limit
			// is per egress IP — so "who set this off, and when" has to be
			// answerable. Emitted only on the path that actually STARTED a run:
			// a 409 or 404 changed nothing and an audit trail padded with
			// non-events is one people stop reading.
			recordPlatformAudit(c, PlatformAuditEntry{
				EventType:     "catalog_feed.sync_started",
				Action:        "sync",
				EventCategory: "system",
				ResourceType:  "catalog_feed",
				Metadata:      map[string]interface{}{"feed": feed},
			})
			c.JSON(http.StatusAccepted, catalogFeedSyncResponse{
				Feed: feed, Status: catalogfeeds.StatusRunning,
				Message: "Sync started. Refresh feed status to see the result.",
			})
		case errors.Is(err, catalogfeeds.ErrFeedsDisabled):
			// 409, not 403: the operator has the permission; the deployment has
			// the feature switched off. Those are different problems with
			// different fixes, and collapsing them sends someone to look at
			// their role.
			c.JSON(http.StatusConflict, gin.H{"error": "Catalogue feeds are disabled on this deployment (CATALOG_FEEDS_ENABLED=false)"})
		case errors.Is(err, catalogfeeds.ErrFeedBusy):
			c.JSON(http.StatusConflict, gin.H{"error": "A sync is already running for this feed"})
		case errors.Is(err, catalogfeeds.ErrFeedUnknown):
			c.JSON(http.StatusNotFound, gin.H{"error": fmt.Sprintf("Unknown feed %q", feed)})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to start the sync"})
		}
	}
}

// ImportCatalogBundle serves POST /admin/catalogs/import-bundle (multipart,
// field `file`).
func ImportCatalogBundle(importer CatalogBundleImporter) gin.HandlerFunc {
	return func(c *gin.Context) {
		if importer == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Bundle import is not configured in this deployment"})
			return
		}
		// Bound the upload before gin buffers it. MaxBytesReader makes an
		// oversize body fail at the socket rather than after the pod has
		// written a gigabyte to disk.
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, catalogfeeds.MaxBundleBytes)

		header, err := c.FormFile("file")
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Attach the bundle as multipart field 'file'"})
			return
		}
		f, err := header.Open()
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Could not read the uploaded file"})
			return
		}
		defer func() { _ = f.Close() }()

		res, err := importer.ImportBundle(c.Request.Context(), f)
		if err != nil {
			// The import's errors are the operator's diagnosis — "sha256
			// mismatch on vulnerability_catalogue.jsonl" is the whole point of
			// the manifest — so they are surfaced verbatim rather than replaced
			// with "import failed".
			//
			// 400 means the BUNDLE was refused and nothing was written, which is
			// what the console tells the operator. A failure after verification
			// passed is not that: rows are already in the catalogue, so it
			// answers 500 and the console says so instead.
			status := http.StatusBadRequest
			if errors.Is(err, catalogfeeds.ErrBundleApplyFailed) {
				status = http.StatusInternalServerError
				// A partial apply WROTE ROWS, so it is audited like the
				// successful case. Auditing only the clean path would leave the
				// messiest write in this slice — half a catalogue, from a file
				// carried in by hand — as the one with no record of who did it.
				// The event type carries the outcome; the emitter's Success flag
				// is not expressive enough for "partly".
				recordBundleImportAudit(c, "catalog_bundle.partially_imported", res)
			}
			c.JSON(status, gin.H{"error": err.Error()})
			return
		}

		// The highest-consequence write in this surface: operator-supplied rows
		// landing in a platform catalogue that every tenant is evaluated
		// against. The manifest's per-file SHA-256 goes into the record, so the
		// trail answers WHICH bytes were applied and not merely that an import
		// happened — which is the question asked after a bad bundle, and the
		// only one the hash can settle.
		recordBundleImportAudit(c, "catalog_bundle.imported", res)
		files := res.Files
		if files == nil {
			files = []catalogfeeds.BundleFile{}
		}
		c.JSON(http.StatusOK, catalogBundleImportResponse{
			Files:             files,
			EOLRows:           res.EOLRows,
			VulnerabilityRows: res.VulnerabilityRows,
			MatchRows:         res.MatchRows,
			GeneratedAt:       res.GeneratedAt,
			Message: fmt.Sprintf("Imported %d end-of-life rows and %d vulnerabilities (%d match rules).",
				res.EOLRows, res.VulnerabilityRows, res.MatchRows),
		})
	}
}

// --- helpers ----------------------------------------------------------------

// recordBundleImportAudit writes the audit entry for a bundle import, clean or
// partial, carrying the manifest's per-file SHA-256 and the rows the database
// actually wrote.
//
// The counts here are MEASURED, not the file's own claims: match rules are
// INSERT … DO NOTHING, so a re-import writes none of them and an audit record
// quoting the file would overstate what changed by tens of thousands of rows.
// An audit trail that reports writes which did not happen is not a smaller
// problem than one that misses writes which did.
func recordBundleImportAudit(c *gin.Context, eventType string, res *catalogfeeds.ImportResult) {
	if res == nil {
		return
	}
	files := make([]map[string]interface{}, 0, len(res.Files))
	for _, f := range res.Files {
		files = append(files, map[string]interface{}{
			"name": f.Name, "sha256": f.SHA256, "rows": f.Rows, "bytes": f.Bytes,
		})
	}
	meta := map[string]interface{}{
		"files":              files,
		"eol_rows":           res.EOLRows,
		"vulnerability_rows": res.VulnerabilityRows,
		"match_rows":         res.MatchRows,
	}
	if res.GeneratedAt != nil {
		meta["bundle_generated_at"] = res.GeneratedAt.UTC().Format(time.RFC3339)
	}
	recordPlatformAudit(c, PlatformAuditEntry{
		EventType:     eventType,
		Action:        "import",
		EventCategory: "system",
		ResourceType:  "catalog_bundle",
		Metadata:      meta,
	})
}

func pageParams(c *gin.Context) (int, int) {
	page, _ := strconv.Atoi(c.Query("page"))
	pageSize, _ := strconv.Atoi(c.Query("page_size"))
	return page, pageSize
}

// catalogPageEcho mirrors the store's clamping so the response reports the page
// that was actually served, not the one that was asked for.
func catalogPageEcho(page, pageSize int) (int, int) {
	if page < 1 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = catalogfeeds.DefaultPageSize
	}
	if pageSize > catalogfeeds.MaxPageSize {
		pageSize = catalogfeeds.MaxPageSize
	}
	return page, pageSize
}

func validProductKind(k string) bool {
	switch k {
	case catalogfeeds.KindOS, catalogfeeds.KindSoftware, catalogfeeds.KindHardware:
		return true
	}
	return false
}

func validSeverity(s string) bool {
	switch s {
	case catalogfeeds.SeverityNone, catalogfeeds.SeverityLow, catalogfeeds.SeverityMedium,
		catalogfeeds.SeverityHigh, catalogfeeds.SeverityCritical:
		return true
	}
	return false
}
