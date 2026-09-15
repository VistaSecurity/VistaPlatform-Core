package catalogfeeds

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/network"
)

// Store is every database touch this package makes. It is an interface rather
// than a *sql.DB so the handlers can be contract-tested over an in-memory stub
// (the house pattern — see handlers/entitlements_contract_test.go) without a
// live Postgres, while the real upsert SQL is exercised by the
// TestIntegration_* tests against an ephemeral database.
type Store interface {
	UpsertEOL(ctx context.Context, entries []EOLEntry) (int64, error)
	// UpsertVulnerabilities returns the CVE rows and the MATCH rules the
	// database actually wrote, as two numbers because they are two different
	// quantities. The match count in particular cannot be inferred from the
	// input: match rules are INSERT … DO NOTHING, so a re-import of the same
	// data writes none of them.
	UpsertVulnerabilities(ctx context.Context, vulns []Vulnerability) (vulnRows, matchRows int64, err error)

	ListEOL(ctx context.Context, q EOLQuery) ([]EOLEntry, int64, error)
	ListVulnerabilities(ctx context.Context, q VulnQuery) ([]Vulnerability, int64, error)

	FeedStates(ctx context.Context) ([]FeedState, error)
	MarkRunning(ctx context.Context, feed string) error
	MarkResult(ctx context.Context, feed string, res SyncResult, runErr error) error

	// ExportAll streams every catalogue row for the offline bundle. Returned in
	// a deterministic order so two exports of the same database produce the
	// same bytes and therefore the same SHA-256.
	ExportAll(ctx context.Context) (*Export, error)
}

// Export is the catalogue content of an offline bundle.
type Export struct {
	EOL   []EOLEntry
	Vulns []Vulnerability
}

// EOLQuery is the admin list filter for eol_catalogue.
type EOLQuery struct {
	Search   string
	Kind     string
	Page     int
	PageSize int
}

// VulnQuery is the admin list filter for vulnerability_catalogue.
type VulnQuery struct {
	Search   string
	Severity string
	Page     int
	PageSize int
}

// Pagination bounds. A page size of 0 means "unset" and takes the default; the
// cap exists because the admin table is a browsing surface, not an export —
// the offline bundle is the export.
const (
	DefaultPageSize = 50
	MaxPageSize     = 200
)

// normalize clamps page/page_size so a hand-crafted query string cannot ask for
// page 0 (which would make OFFSET negative) or a million rows.
func normalize(page, pageSize int) (int, int) {
	if page < 1 {
		page = 1
	}
	if pageSize <= 0 {
		pageSize = DefaultPageSize
	}
	if pageSize > MaxPageSize {
		pageSize = MaxPageSize
	}
	return page, pageSize
}

// SQLStore is the Postgres implementation of Store.
//
// It takes the BYPASSRLS pool. These tables carry no tenant_id and no RLS
// policy, so the two pools behave identically against them today; using the
// bypass handle is the same choice every other platform-scoped surface in this
// service makes, and it means a future decision to put a policy on a catalogue
// does not silently empty the admin console.
type SQLStore struct{ db *sql.DB }

// NewSQLStore builds the Postgres-backed Store.
func NewSQLStore(db *sql.DB) *SQLStore { return &SQLStore{db: db} }

// --- writes ----------------------------------------------------------------

const upsertEOLSQL = `
INSERT INTO public.eol_catalogue
    (product_kind, vendor, product, cycle, release_date, eol_date,
     extended_support_date, source_url, source_kind)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
ON CONFLICT (product_kind, coalesce(vendor, ''), product, cycle) DO UPDATE SET
    release_date          = EXCLUDED.release_date,
    eol_date              = EXCLUDED.eol_date,
    extended_support_date = EXCLUDED.extended_support_date,
    source_url            = EXCLUDED.source_url,
    source_kind           = EXCLUDED.source_kind,
    updated_at            = now()`

// UpsertEOL writes entries idempotently on the catalogue's identity index.
//
// Returns the rows the DATABASE reports affected, not the number of statements
// issued. The two agree today — ON CONFLICT DO UPDATE affects one row per
// execution whether it inserted or updated — and that is the point of measuring
// rather than assuming: if this statement ever became DO NOTHING, a count
// derived from the loop would keep reporting the input size while writing
// nothing.
//
// For a re-run of unchanged data the count is still len(entries), because the
// statement did touch every row. That is deliberate: the number reported to the
// operator answers "how much of the feed did we ingest", not "how much changed",
// and a feed whose count dropped to 0 because nothing moved would read as
// broken. Match rules are the opposite case and are counted differently — see
// UpsertVulnerabilities.
func (s *SQLStore) UpsertEOL(ctx context.Context, entries []EOLEntry) (int64, error) {
	if len(entries) == 0 {
		return 0, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin eol upsert: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	stmt, err := tx.PrepareContext(ctx, upsertEOLSQL)
	if err != nil {
		return 0, fmt.Errorf("prepare eol upsert: %w", err)
	}
	defer func() { _ = stmt.Close() }()

	var n int64
	for _, e := range entries {
		if e.ProductKind == "" || e.Product == "" || e.Cycle == "" {
			// The identity columns are NOT NULL; a feed row missing one of them
			// is a parse failure, and inserting it would abort the whole
			// transaction. Skip it rather than lose the batch.
			continue
		}
		kind := e.SourceKind
		if kind == "" {
			kind = "imported"
		}
		res, err := stmt.ExecContext(ctx,
			e.ProductKind, e.Vendor, e.Product, e.Cycle,
			e.ReleaseDate, e.EOLDate, e.ExtendedSupportDate, e.SourceURL, kind,
		)
		if err != nil {
			return n, fmt.Errorf("upsert eol %s/%s/%s: %w", e.ProductKind, e.Product, e.Cycle, err)
		}
		n += rowsAffected(res)
	}
	if err := tx.Commit(); err != nil {
		return n, fmt.Errorf("commit eol upsert: %w", err)
	}
	return n, nil
}

const upsertVulnSQL = `
INSERT INTO public.vulnerability_catalogue
    (cve_id, cvss_version, cvss_score, cvss_vector, severity,
     published_at, modified_at, description, source_kind)
VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
ON CONFLICT (cve_id) DO UPDATE SET
    cvss_version = EXCLUDED.cvss_version,
    cvss_score   = EXCLUDED.cvss_score,
    cvss_vector  = EXCLUDED.cvss_vector,
    severity     = EXCLUDED.severity,
    published_at = EXCLUDED.published_at,
    modified_at  = EXCLUDED.modified_at,
    description  = EXCLUDED.description,
    source_kind  = EXCLUDED.source_kind,
    updated_at   = now()`

const upsertMatchSQL = `
INSERT INTO public.vulnerability_matches (cve_id, cpe_match_string, purl_range)
VALUES ($1, $2, $3)
ON CONFLICT (cve_id, coalesce(cpe_match_string, ''), coalesce(purl_range, ''))
DO NOTHING`

// UpsertVulnerabilities writes each CVE and its match rules, returning what the
// database actually affected for each.
//
// Matches are INSERT ... DO NOTHING rather than a delete-and-replace: a CVE's
// match set is contributed by several feeds (NVD brings CPEs, OSV brings
// PURLs), so replacing on each run would have NVD delete OSV's rows and back
// again on every cycle. The consequence to know about: a match rule withdrawn
// upstream is not withdrawn here. Re-import from a fresh bundle is the reset.
//
// That DO NOTHING is exactly why the match count is MEASURED rather than taken
// from len(v.Matches): on a re-import every rule conflicts and none is written,
// so the input length would report tens of thousands of rules "imported" while
// the database wrote zero. Counting the rules in the file answers a question
// nobody asked.
func (s *SQLStore) UpsertVulnerabilities(ctx context.Context, vulns []Vulnerability) (int64, int64, error) {
	if len(vulns) == 0 {
		return 0, 0, nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, fmt.Errorf("begin vuln upsert: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	vStmt, err := tx.PrepareContext(ctx, upsertVulnSQL)
	if err != nil {
		return 0, 0, fmt.Errorf("prepare vuln upsert: %w", err)
	}
	defer func() { _ = vStmt.Close() }()
	mStmt, err := tx.PrepareContext(ctx, upsertMatchSQL)
	if err != nil {
		return 0, 0, fmt.Errorf("prepare match upsert: %w", err)
	}
	defer func() { _ = mStmt.Close() }()

	var n, matches int64
	for _, v := range vulns {
		if v.CVEID == "" {
			continue
		}
		kind := v.SourceKind
		if kind == "" {
			kind = "imported"
		}
		vRes, err := vStmt.ExecContext(ctx,
			v.CVEID, v.CVSSVersion, v.CVSSScore, v.CVSSVector, v.Severity,
			v.PublishedAt, v.ModifiedAt, v.Description, kind,
		)
		if err != nil {
			return n, matches, fmt.Errorf("upsert cve %s: %w", v.CVEID, err)
		}
		n += rowsAffected(vRes)
		for _, m := range v.Matches {
			// The table's CHECK is `(cpe IS NOT NULL) <> (purl IS NOT NULL)`.
			// Enforce it here too so a malformed feed row is skipped instead of
			// aborting the batch.
			if (m.CPEMatch == nil) == (m.PURLRange == nil) {
				continue
			}
			mRes, err := mStmt.ExecContext(ctx, v.CVEID, m.CPEMatch, m.PURLRange)
			if err != nil {
				return n, matches, fmt.Errorf("upsert match for %s: %w", v.CVEID, err)
			}
			matches += rowsAffected(mRes)
		}
	}
	if err := tx.Commit(); err != nil {
		return n, matches, fmt.Errorf("commit vuln upsert: %w", err)
	}
	return n, matches, nil
}

// rowsAffected reads sql.Result.RowsAffected, treating a driver that cannot
// report it as zero.
//
// lib/pq always can, so this is not a live branch — but the alternative,
// swallowing the error and returning 1, would invent a row that may not exist.
// A count is either measured or it is not; guessing is what this whole change
// is removing.
func rowsAffected(res sql.Result) int64 {
	if res == nil {
		return 0
	}
	n, err := res.RowsAffected()
	if err != nil || n < 0 {
		return 0
	}
	return n
}

// --- reads -----------------------------------------------------------------

// ListEOL returns one page of the catalogue plus the unpaginated total.
func (s *SQLStore) ListEOL(ctx context.Context, q EOLQuery) ([]EOLEntry, int64, error) {
	page, pageSize := normalize(q.Page, q.PageSize)

	where := []string{"1 = 1"}
	args := []any{}
	if strings.TrimSpace(q.Search) != "" {
		args = append(args, "%"+strings.ToLower(strings.TrimSpace(q.Search))+"%")
		where = append(where, fmt.Sprintf(
			"(lower(product) LIKE $%d OR lower(coalesce(vendor, '')) LIKE $%d OR lower(cycle) LIKE $%d)",
			len(args), len(args), len(args)))
	}
	if q.Kind != "" {
		args = append(args, q.Kind)
		where = append(where, fmt.Sprintf("product_kind = $%d", len(args)))
	}
	clause := strings.Join(where, " AND ")

	var total int64
	if err := s.db.QueryRowContext(ctx,
		"SELECT count(*) FROM public.eol_catalogue WHERE "+clause, args...,
	).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count eol: %w", err)
	}

	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := s.db.QueryContext(ctx, `
        SELECT id, product_kind, vendor, product, cycle, release_date, eol_date,
               extended_support_date, source_url, source_kind, updated_at
        FROM public.eol_catalogue
        WHERE `+clause+`
        ORDER BY product_kind, product, cycle
        LIMIT $`+fmt.Sprint(len(args)-1)+` OFFSET $`+fmt.Sprint(len(args)), args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list eol: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := []EOLEntry{}
	for rows.Next() {
		var (
			e                               EOLEntry
			vendor, sourceURL               sql.NullString
			release, eol, extended, updated sql.NullTime
		)
		if err := rows.Scan(&e.ID, &e.ProductKind, &vendor, &e.Product, &e.Cycle,
			&release, &eol, &extended, &sourceURL, &e.SourceKind, &updated); err != nil {
			return nil, 0, fmt.Errorf("scan eol: %w", err)
		}
		e.Vendor, e.SourceURL = nullString(vendor), nullString(sourceURL)
		e.ReleaseDate, e.EOLDate, e.ExtendedSupportDate = nullTime(release), nullTime(eol), nullTime(extended)
		e.UpdatedAt = nullTime(updated)
		out = append(out, e)
	}
	return out, total, rows.Err()
}

// ListVulnerabilities returns one page of the catalogue plus the unpaginated
// total. Match rules are NOT joined in — a CVE can carry thousands, and the
// admin table shows a count, not the list.
func (s *SQLStore) ListVulnerabilities(ctx context.Context, q VulnQuery) ([]Vulnerability, int64, error) {
	page, pageSize := normalize(q.Page, q.PageSize)

	where := []string{"1 = 1"}
	args := []any{}
	if strings.TrimSpace(q.Search) != "" {
		args = append(args, "%"+strings.ToLower(strings.TrimSpace(q.Search))+"%")
		where = append(where, fmt.Sprintf(
			"(lower(cve_id) LIKE $%d OR lower(coalesce(description, '')) LIKE $%d)",
			len(args), len(args)))
	}
	if q.Severity != "" {
		args = append(args, q.Severity)
		where = append(where, fmt.Sprintf("severity = $%d", len(args)))
	}
	clause := strings.Join(where, " AND ")

	var total int64
	if err := s.db.QueryRowContext(ctx,
		"SELECT count(*) FROM public.vulnerability_catalogue WHERE "+clause, args...,
	).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count vulnerabilities: %w", err)
	}

	args = append(args, pageSize, (page-1)*pageSize)
	rows, err := s.db.QueryContext(ctx, `
        SELECT cve_id, cvss_version, cvss_score, cvss_vector, severity,
               published_at, modified_at, description, source_kind
        FROM public.vulnerability_catalogue
        WHERE `+clause+`
        ORDER BY coalesce(published_at, to_timestamp(0)) DESC, cve_id
        LIMIT $`+fmt.Sprint(len(args)-1)+` OFFSET $`+fmt.Sprint(len(args)), args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list vulnerabilities: %w", err)
	}
	defer func() { _ = rows.Close() }()

	out := []Vulnerability{}
	for rows.Next() {
		var (
			v                          Vulnerability
			version, vector, sev, desc sql.NullString
			score                      sql.NullFloat64
			published, modified        sql.NullTime
		)
		if err := rows.Scan(&v.CVEID, &version, &score, &vector, &sev,
			&published, &modified, &desc, &v.SourceKind); err != nil {
			return nil, 0, fmt.Errorf("scan vulnerability: %w", err)
		}
		v.CVSSVersion, v.CVSSVector, v.Severity, v.Description =
			nullString(version), nullString(vector), nullString(sev), nullString(desc)
		v.CVSSScore = nullFloat(score)
		v.PublishedAt, v.ModifiedAt = nullTime(published), nullTime(modified)
		out = append(out, v)
	}
	return out, total, rows.Err()
}

// --- feed state ------------------------------------------------------------

// FeedStates returns one row per KNOWN feed, in FeedNames order, synthesising a
// `never` row for a feed that has not run yet.
//
// Synthesising rather than seeding: a feed that has never run has no row, and
// the console must still list it (with a Sync-now button) rather than show a
// shorter list than the product has feeds. This is the three-valued rule — "not
// run" is an answer, not an absence.
func (s *SQLStore) FeedStates(ctx context.Context) ([]FeedState, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT feed, cursor, last_run_at, last_status, last_error, row_count, updated_at
        FROM public.catalog_feed_state`)
	if err != nil {
		return nil, fmt.Errorf("list feed state: %w", err)
	}
	defer func() { _ = rows.Close() }()

	byFeed := map[string]FeedState{}
	for rows.Next() {
		var (
			st               FeedState
			cursor, lastErr  sql.NullString
			lastRun, updated sql.NullTime
		)
		if err := rows.Scan(&st.Feed, &cursor, &lastRun, &st.LastStatus, &lastErr,
			&st.RowCount, &updated); err != nil {
			return nil, fmt.Errorf("scan feed state: %w", err)
		}
		st.Cursor, st.LastError = nullString(cursor), nullString(lastErr)
		st.LastRunAt, st.UpdatedAt = nullTime(lastRun), nullTime(updated)
		byFeed[st.Feed] = st
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	out := make([]FeedState, 0, len(FeedNames))
	for _, name := range FeedNames {
		if st, ok := byFeed[name]; ok {
			out = append(out, st)
			continue
		}
		out = append(out, FeedState{Feed: name, LastStatus: StatusNever})
	}
	return out, nil
}

// MarkRunning stamps a feed as in-flight. It does NOT clear last_error or
// row_count: while a run is in progress the console should keep showing the
// previous outcome rather than blank out to "unknown".
func (s *SQLStore) MarkRunning(ctx context.Context, feed string) error {
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO public.catalog_feed_state (feed, last_status)
        VALUES ($1, $2)
        ON CONFLICT (feed) DO UPDATE SET last_status = EXCLUDED.last_status, updated_at = now()`,
		feed, StatusRunning)
	if err != nil {
		return fmt.Errorf("mark feed %s running: %w", feed, err)
	}
	return nil
}

// MarkResult records the outcome of a run.
//
// On failure the CURSOR IS NOT ADVANCED — the run is retried from where the
// last successful one finished, so a transient NVD outage cannot silently skip
// a window of CVEs. That is the whole reason the cursor write lives here rather
// than in the feed clients.
func (s *SQLStore) MarkResult(ctx context.Context, feed string, res SyncResult, runErr error) error {
	status := StatusOK
	var errText any
	if runErr != nil {
		status = StatusError
		// Cap the stored text: a wrapped HTTP error can carry a whole response
		// body, and this column is read straight into an admin table cell.
		msg := runErr.Error()
		if len(msg) > 1000 {
			msg = msg[:1000] + "…"
		}
		errText = msg
	}

	if runErr != nil {
		_, err := s.db.ExecContext(ctx, `
            INSERT INTO public.catalog_feed_state (feed, last_run_at, last_status, last_error, row_count)
            VALUES ($1, now(), $2, $3, 0)
            ON CONFLICT (feed) DO UPDATE SET
                last_run_at = now(), last_status = EXCLUDED.last_status,
                last_error  = EXCLUDED.last_error, updated_at = now()`,
			feed, status, errText)
		if err != nil {
			return fmt.Errorf("record feed %s failure: %w", feed, err)
		}
		return nil
	}

	var cursor any
	if res.Cursor != "" {
		cursor = res.Cursor
	}
	_, err := s.db.ExecContext(ctx, `
        INSERT INTO public.catalog_feed_state (feed, cursor, last_run_at, last_status, last_error, row_count)
        VALUES ($1, $2, now(), $3, NULL, $4)
        ON CONFLICT (feed) DO UPDATE SET
            cursor      = coalesce(EXCLUDED.cursor, public.catalog_feed_state.cursor),
            last_run_at = now(), last_status = EXCLUDED.last_status,
            last_error  = NULL, row_count = EXCLUDED.row_count, updated_at = now()`,
		feed, cursor, status, res.Rows)
	if err != nil {
		return fmt.Errorf("record feed %s success: %w", feed, err)
	}
	return nil
}

// --- export ----------------------------------------------------------------

// ExportAll reads every catalogue row for the offline bundle, in a
// deterministic order so the manifest's SHA-256 is reproducible.
func (s *SQLStore) ExportAll(ctx context.Context) (*Export, error) {
	out := &Export{EOL: []EOLEntry{}, Vulns: []Vulnerability{}}

	eolRows, err := s.db.QueryContext(ctx, `
        SELECT product_kind, vendor, product, cycle, release_date, eol_date,
               extended_support_date, source_url, source_kind
        FROM public.eol_catalogue
        ORDER BY product_kind, coalesce(vendor, ''), product, cycle`)
	if err != nil {
		return nil, fmt.Errorf("export eol: %w", err)
	}
	defer func() { _ = eolRows.Close() }()
	for eolRows.Next() {
		var (
			e                      EOLEntry
			vendor, sourceURL      sql.NullString
			release, eol, extended sql.NullTime
		)
		if err := eolRows.Scan(&e.ProductKind, &vendor, &e.Product, &e.Cycle,
			&release, &eol, &extended, &sourceURL, &e.SourceKind); err != nil {
			return nil, fmt.Errorf("scan export eol: %w", err)
		}
		e.Vendor, e.SourceURL = nullString(vendor), nullString(sourceURL)
		e.ReleaseDate, e.EOLDate, e.ExtendedSupportDate = nullTime(release), nullTime(eol), nullTime(extended)
		out.EOL = append(out.EOL, e)
	}
	if err := eolRows.Err(); err != nil {
		return nil, err
	}

	// One query, CVE joined to its matches, ordered so matches arrive grouped
	// under their CVE. A LEFT JOIN rather than N+1 round trips: the bundle is
	// built over the whole catalogue and a per-CVE query would be one statement
	// per row.
	vRows, err := s.db.QueryContext(ctx, `
        SELECT v.cve_id, v.cvss_version, v.cvss_score, v.cvss_vector, v.severity,
               v.published_at, v.modified_at, v.description, v.source_kind,
               m.cpe_match_string, m.purl_range
        FROM public.vulnerability_catalogue v
        LEFT JOIN public.vulnerability_matches m ON m.cve_id = v.cve_id
        ORDER BY v.cve_id, coalesce(m.cpe_match_string, ''), coalesce(m.purl_range, '')`)
	if err != nil {
		return nil, fmt.Errorf("export vulnerabilities: %w", err)
	}
	defer func() { _ = vRows.Close() }()

	var current *Vulnerability
	for vRows.Next() {
		var (
			v                          Vulnerability
			version, vector, sev, desc sql.NullString
			score                      sql.NullFloat64
			published, modified        sql.NullTime
			cpe, purl                  sql.NullString
		)
		if err := vRows.Scan(&v.CVEID, &version, &score, &vector, &sev,
			&published, &modified, &desc, &v.SourceKind, &cpe, &purl); err != nil {
			return nil, fmt.Errorf("scan export vulnerability: %w", err)
		}
		if current == nil || current.CVEID != v.CVEID {
			v.CVSSVersion, v.CVSSVector, v.Severity, v.Description =
				nullString(version), nullString(vector), nullString(sev), nullString(desc)
			v.CVSSScore = nullFloat(score)
			v.PublishedAt, v.ModifiedAt = nullTime(published), nullTime(modified)
			v.Matches = []VulnerabilityMatch{}
			out.Vulns = append(out.Vulns, v)
			current = &out.Vulns[len(out.Vulns)-1]
		}
		if cpe.Valid || purl.Valid {
			current.Matches = append(current.Matches, VulnerabilityMatch{
				CPEMatch:  nullString(cpe),
				PURLRange: nullString(purl),
			})
		}
	}
	return out, vRows.Err()
}

// --- cross-replica exclusion ------------------------------------------------

// advisoryLockKey is the fixed 64-bit key this package's runs take. Derived by
// hand rather than from a hash so it is greppable: 0x7645... spells "VF" for
// Vista Feeds, and the low word is the feed's index in FeedNames.
const advisoryLockBase int64 = 0x7645_0000_0000_0000

// TryLock takes a session-level advisory lock for one feed and returns a
// release function, or ok=false when another replica already holds it.
//
// Without this, every admin-service replica runs every feed on its own ticker.
// For the EOL feed that is wasted requests; for NVD it is a rate-limit
// violation the moment there are two pods, and NIST answers 403 to a caller
// that exceeds the window. A green log line on each replica would say nothing
// about it.
func TryLock(ctx context.Context, db *sql.DB, feed string) (release func(), ok bool, err error) {
	key := advisoryLockBase
	for i, name := range FeedNames {
		if name == feed {
			key += int64(i + 1)
		}
	}
	conn, err := db.Conn(ctx)
	if err != nil {
		return nil, false, fmt.Errorf("acquire connection for feed lock: %w", err)
	}
	var got bool
	if err := conn.QueryRowContext(ctx, "SELECT pg_try_advisory_lock($1)", key).Scan(&got); err != nil {
		_ = conn.Close()
		return nil, false, fmt.Errorf("try advisory lock for %s: %w", feed, err)
	}
	if !got {
		_ = conn.Close()
		return nil, false, nil
	}
	return func() {
		// Release on the SAME connection that took it — a session-level lock is
		// held by the session, so unlocking through the pool could hit a
		// different backend and leave the lock held until the pod restarts.
		_, _ = conn.ExecContext(context.WithoutCancel(ctx), "SELECT pg_advisory_unlock($1)", key)
		_ = conn.Close()
	}, true, nil
}

// ErrFeedUnknown is returned by the runner for a feed name not in FeedNames.
var ErrFeedUnknown = errors.New("unknown catalogue feed")

// ErrFeedsDisabled is returned when CATALOG_FEEDS_ENABLED=false.
var ErrFeedsDisabled = errors.New("catalogue feeds are disabled (CATALOG_FEEDS_ENABLED=false)")

// ErrFeedBusy is returned when a sync is already in flight for that feed.
var ErrFeedBusy = errors.New("a sync is already running for this feed")

// httpTimeout bounds every outbound feed request. Generous because the OSV
// bulk export is tens of megabytes.
const httpTimeout = 10 * time.Minute

// feedRunTimeout bounds one whole PASS of one feed, scheduled or manual.
//
// It is deliberately NOT httpTimeout. Those are different quantities and
// spending one constant on both is what made a manually triggered NVD sync
// unable to finish: a pass is up to MaxRequests pages with a mandated 6-second
// gap between them (360s of sleeping before a single byte is transferred) plus
// the requests themselves, and NVD's 2000-result pages are not fast. Capping
// the run at the per-request timeout meant the deadline expired mid-pass, the
// run was recorded `error`, and — because the cursor only advances on success —
// every bit of progress it had made was thrown away. The feed could never move
// forward from the console's own button.
const feedRunTimeout = 2 * time.Hour

// newFeedHTTPClient builds the client every mirror uses.
//
// SSRF-guarded (shared/network) even though the three feed URLs are compile-time
// constants and no tenant supplies one. The exposure a constant base URL does
// NOT close is the redirect: net/http follows up to 10 of them by default, so a
// hijacked or compromised upstream — or a poisoned resolver — can walk this
// client to 169.254.169.254 or a service on the cluster network. The guard's
// Control hook runs after resolution on each concrete address, redirects
// included, so it closes that. It costs nothing here: every production endpoint
// is a public address, and the tests inject their own client.
func newFeedHTTPClient() *http.Client {
	return network.SafeHTTPClient(httpTimeout)
}
