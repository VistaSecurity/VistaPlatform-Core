package catalogfeeds

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"reflect"
	"testing"
	"time"

	_ "github.com/lib/pq"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// Real-Postgres assertions the stub store cannot make: that the ON CONFLICT
// targets match the catalogue's actual indexes, that the CHECK constraints hold,
// that `cursor` is usable as a column name, and that the advisory lock really
// excludes a second holder.
//
// Skips unless TEST_DATABASE_URL is set — run `make test-integration-db`.

func integrationStore(t *testing.T) (*SQLStore, *sql.DB) {
	t.Helper()
	db := testdb.Connect(t)
	testdb.ApplySchema(t, db)
	return NewSQLStore(db), db
}

// uniqueProduct keeps parallel package binaries from colliding on the
// catalogue's natural key — these tables are platform-scoped, so there is no
// tenant to isolate by.
func uniqueProduct(t *testing.T, prefix string) string {
	t.Helper()
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
}

func TestIntegration_UpsertEOL_IsIdempotentOnTheIdentityIndex(t *testing.T) {
	store, db := integrationStore(t)
	ctx := context.Background()
	product := uniqueProduct(t, "it-eol")
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM public.eol_catalogue WHERE product = $1`, product) })

	first := time.Date(2029, 5, 31, 0, 0, 0, 0, time.UTC)
	entries := []EOLEntry{
		{ProductKind: KindOS, Vendor: ptr("Canonical"), Product: product, Cycle: "24.04",
			EOLDate: &first, SourceURL: ptr("https://endoflife.date/x"), SourceKind: "imported"},
		// Same product and cycle, NULL vendor: a different row, because the
		// index coalesces vendor to '' rather than treating NULL as a wildcard.
		{ProductKind: KindOS, Product: product, Cycle: "24.04", SourceKind: "imported"},
	}
	if _, err := store.UpsertEOL(ctx, entries); err != nil {
		t.Fatalf("first upsert: %v", err)
	}

	var count int
	if err := db.QueryRow(`SELECT count(*) FROM public.eol_catalogue WHERE product = $1`, product).Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 2 {
		t.Fatalf("rows = %d, want 2 (a NULL vendor is a distinct identity)", count)
	}

	// Re-run with a MOVED date: the row must be updated in place, not doubled.
	moved := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	entries[0].EOLDate = &moved
	if _, err := store.UpsertEOL(ctx, entries); err != nil {
		t.Fatalf("second upsert: %v", err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM public.eol_catalogue WHERE product = $1`, product).Scan(&count); err != nil {
		t.Fatalf("recount: %v", err)
	}
	if count != 2 {
		t.Fatalf("rows after re-run = %d, want 2 — the upsert is not hitting the identity index", count)
	}

	var stored time.Time
	if err := db.QueryRow(
		`SELECT eol_date FROM public.eol_catalogue WHERE product = $1 AND vendor = 'Canonical'`, product,
	).Scan(&stored); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if !stored.UTC().Equal(moved) {
		t.Fatalf("eol_date = %s, want the updated %s", stored, moved)
	}

	// The trigger must move updated_at on a real change; without it "when did
	// this row last change" silently answers "when was it created".
	var created, updated time.Time
	if err := db.QueryRow(
		`SELECT created_at, updated_at FROM public.eol_catalogue WHERE product = $1 AND vendor = 'Canonical'`, product,
	).Scan(&created, &updated); err != nil {
		t.Fatalf("read timestamps: %v", err)
	}
	if !updated.After(created) {
		t.Fatalf("updated_at (%s) did not move past created_at (%s)", updated, created)
	}
}

// An entry missing one of the identity columns must be skipped, not sent to
// Postgres where the NOT NULL would abort the whole batch.
func TestIntegration_UpsertEOL_SkipsIncompleteIdentityWithoutLosingTheBatch(t *testing.T) {
	store, db := integrationStore(t)
	ctx := context.Background()
	product := uniqueProduct(t, "it-eol-skip")
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM public.eol_catalogue WHERE product = $1`, product) })

	n, err := store.UpsertEOL(ctx, []EOLEntry{
		{ProductKind: KindSoftware, Product: product, Cycle: ""},
		{ProductKind: KindSoftware, Product: product, Cycle: "1.0", SourceKind: "imported"},
	})
	if err != nil {
		t.Fatalf("upsert: %v", err)
	}
	if n != 1 {
		t.Fatalf("wrote %d rows, want 1 — the cycle-less entry must be skipped", n)
	}
	var count int
	_ = db.QueryRow(`SELECT count(*) FROM public.eol_catalogue WHERE product = $1`, product).Scan(&count)
	if count != 1 {
		t.Fatalf("stored %d rows, want 1", count)
	}
}

func TestIntegration_UpsertVulnerabilities_IdempotentAndMatchesDeduped(t *testing.T) {
	store, db := integrationStore(t)
	ctx := context.Background()
	cve := fmt.Sprintf("CVE-2099-%d", time.Now().UnixNano()%100000)
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM public.vulnerability_catalogue WHERE cve_id = $1`, cve) })

	v := Vulnerability{
		CVEID: cve, CVSSVersion: ptr("3.1"), CVSSScore: ptr(9.8),
		CVSSVector: ptr("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
		Severity:   ptr(SeverityCritical), Description: ptr("integration fixture"),
		SourceKind: "imported",
		Matches: []VulnerabilityMatch{
			{CPEMatch: ptr(`{"cpe":"cpe:2.3:a:x:y:1.0:*:*:*:*:*:*:*"}`)},
			{PURLRange: ptr(`{"purl":"pkg:deb/debian/y","fixed":"1.1"}`)},
			// Both set — the table's CHECK forbids it, and the store must drop
			// it rather than abort the batch.
			{CPEMatch: ptr(`{"cpe":"a"}`), PURLRange: ptr(`{"purl":"b"}`)},
			// Neither set — same reason.
			{},
		},
	}
	// The counts are what the console shows, and the two statements here have
	// DIFFERENT idempotency: the CVE is ON CONFLICT DO UPDATE (affects its row
	// every time), a match rule is ON CONFLICT DO NOTHING (affects nothing the
	// second time). Only Postgres can settle which number each produces — the
	// old code inferred the match count from the input and was wrong by the
	// whole batch on every re-run.
	vulnRows, matchRows, err := store.UpsertVulnerabilities(ctx, []Vulnerability{v})
	if err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	if vulnRows != 1 || matchRows != 2 {
		t.Fatalf("first upsert reported vulns=%d matches=%d, want 1 and 2 (the two malformed rules dropped)",
			vulnRows, matchRows)
	}
	vulnRows, matchRows, err = store.UpsertVulnerabilities(ctx, []Vulnerability{v})
	if err != nil {
		t.Fatalf("second upsert: %v", err)
	}
	if vulnRows != 1 {
		t.Fatalf("re-upsert reported vulns=%d; DO UPDATE affects the row again, want 1", vulnRows)
	}
	if matchRows != 0 {
		t.Fatalf("re-upsert reported matches=%d; DO NOTHING wrote none, want 0", matchRows)
	}

	var matches int
	if err := db.QueryRow(`SELECT count(*) FROM public.vulnerability_matches WHERE cve_id = $1`, cve).Scan(&matches); err != nil {
		t.Fatalf("count matches: %v", err)
	}
	if matches != 2 {
		t.Fatalf("match rows = %d, want 2 (the two malformed rules dropped, no duplicates on re-run)", matches)
	}

	// Deleting the CVE must take its match rules with it — the FK is ON DELETE
	// CASCADE, and orphan match rules would match forever against a CVE nobody
	// can look up.
	if _, err := db.Exec(`DELETE FROM public.vulnerability_catalogue WHERE cve_id = $1`, cve); err != nil {
		t.Fatalf("delete cve: %v", err)
	}
	_ = db.QueryRow(`SELECT count(*) FROM public.vulnerability_matches WHERE cve_id = $1`, cve).Scan(&matches)
	if matches != 0 {
		t.Fatalf("%d orphan match rules survived the CVE", matches)
	}
}

// The catalogue's severity CHECK is the contract the mirrors are written
// against. If it ever widens or narrows, this fails rather than a feed silently
// dropping rows in production.
func TestIntegration_VulnerabilitySeverityCheckMatchesTheConstants(t *testing.T) {
	store, db := integrationStore(t)
	ctx := context.Background()

	for _, sev := range []string{SeverityNone, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical} {
		cve := fmt.Sprintf("CVE-2098-%d%s", time.Now().UnixNano()%100000, sev[:1])
		t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM public.vulnerability_catalogue WHERE cve_id = $1`, cve) })
		if _, _, err := store.UpsertVulnerabilities(ctx, []Vulnerability{
			{CVEID: cve, Severity: ptr(sev), SourceKind: "imported"},
		}); err != nil {
			t.Fatalf("severity %q was rejected by the catalogue: %v", sev, err)
		}
	}

	cve := fmt.Sprintf("CVE-2097-%d", time.Now().UnixNano()%100000)
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM public.vulnerability_catalogue WHERE cve_id = $1`, cve) })
	if _, _, err := store.UpsertVulnerabilities(ctx, []Vulnerability{
		{CVEID: cve, Severity: ptr("spicy"), SourceKind: "imported"},
	}); err == nil {
		t.Fatal("an off-ladder severity must be refused by the CHECK, not stored")
	}
}

func TestIntegration_ListEOL_FiltersAndPaginates(t *testing.T) {
	store, db := integrationStore(t)
	ctx := context.Background()
	product := uniqueProduct(t, "it-list")
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM public.eol_catalogue WHERE product = $1`, product) })

	entries := []EOLEntry{}
	for i := range 5 {
		entries = append(entries, EOLEntry{
			ProductKind: KindSoftware, Product: product, Cycle: fmt.Sprintf("%d.0", i), SourceKind: "imported",
		})
	}
	entries = append(entries, EOLEntry{ProductKind: KindOS, Product: product, Cycle: "os-1", SourceKind: "imported"})
	if _, err := store.UpsertEOL(ctx, entries); err != nil {
		t.Fatalf("seed: %v", err)
	}

	rows, total, err := store.ListEOL(ctx, EOLQuery{Search: product, PageSize: 2})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if total != 6 {
		t.Fatalf("total = %d, want 6 (the unpaginated count for the same filters)", total)
	}
	if len(rows) != 2 {
		t.Fatalf("page held %d rows, want 2", len(rows))
	}

	page2, _, err := store.ListEOL(ctx, EOLQuery{Search: product, Page: 2, PageSize: 2})
	if err != nil {
		t.Fatalf("list page 2: %v", err)
	}
	if len(page2) != 2 || page2[0].Cycle == rows[0].Cycle {
		t.Fatalf("page 2 repeated page 1: %+v vs %+v", page2, rows)
	}

	osOnly, osTotal, err := store.ListEOL(ctx, EOLQuery{Search: product, Kind: KindOS})
	if err != nil {
		t.Fatalf("list by kind: %v", err)
	}
	if osTotal != 1 || len(osOnly) != 1 || osOnly[0].Cycle != "os-1" {
		t.Fatalf("kind filter returned %d rows (total %d), want the single OS row", len(osOnly), osTotal)
	}

	// Search is case-insensitive over product/vendor/cycle.
	upper, _, err := store.ListEOL(ctx, EOLQuery{Search: "IT-LIST"})
	if err != nil {
		t.Fatalf("case-insensitive search: %v", err)
	}
	if len(upper) == 0 {
		t.Fatal("search must be case-insensitive")
	}
}

// `cursor` is a non-reserved keyword in PostgreSQL, so it is legal unquoted as a
// column name — but that is the kind of claim that should be executed, not
// asserted in a comment.
func TestIntegration_FeedState_RoundTripsAndAdvancesTheCursorOnlyOnSuccess(t *testing.T) {
	store, db := integrationStore(t)
	ctx := context.Background()
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM public.catalog_feed_state WHERE feed = ANY($1)`, pqArray(FeedNames))
	})

	// Before any run, every known feed is LISTED with `never` — the console
	// must not show a shorter list than the product has feeds.
	states, err := store.FeedStates(ctx)
	if err != nil {
		t.Fatalf("feed states: %v", err)
	}
	if len(states) != len(FeedNames) {
		t.Fatalf("got %d feeds, want %d", len(states), len(FeedNames))
	}
	for i, st := range states {
		if st.Feed != FeedNames[i] {
			t.Fatalf("feed %d = %q, want %q (declared order)", i, st.Feed, FeedNames[i])
		}
		if st.LastStatus != StatusNever || st.Cursor != nil {
			t.Fatalf("%s should start at never with no cursor, got %+v", st.Feed, st)
		}
	}

	if err := store.MarkRunning(ctx, FeedNVD); err != nil {
		t.Fatalf("mark running: %v", err)
	}
	if got := feedState(t, store, FeedNVD).LastStatus; got != StatusRunning {
		t.Fatalf("last_status = %q, want running", got)
	}

	if err := store.MarkResult(ctx, FeedNVD, SyncResult{Rows: 42, Cursor: "2026-09-11T00:00:00Z"}, nil); err != nil {
		t.Fatalf("mark success: %v", err)
	}
	st := feedState(t, store, FeedNVD)
	if st.LastStatus != StatusOK || st.RowCount != 42 || st.Cursor == nil || *st.Cursor != "2026-09-11T00:00:00Z" {
		t.Fatalf("after success: %+v", st)
	}
	if st.LastRunAt == nil {
		t.Fatal("a completed run must stamp last_run_at")
	}

	// A failure records the error and LEAVES THE CURSOR WHERE IT WAS, so the
	// same window is retried rather than skipped.
	failErr := fmt.Errorf("nvd window 2026-09-11..2026-09-12: 403 rate limit exceeded")
	if err := store.MarkResult(ctx, FeedNVD, SyncResult{Rows: 0}, failErr); err != nil {
		t.Fatalf("mark failure: %v", err)
	}
	st = feedState(t, store, FeedNVD)
	if st.LastStatus != StatusError {
		t.Fatalf("last_status = %q, want error", st.LastStatus)
	}
	if st.LastError == nil || *st.LastError != failErr.Error() {
		t.Fatalf("last_error = %v, want the failure text", st.LastError)
	}
	if st.Cursor == nil || *st.Cursor != "2026-09-11T00:00:00Z" {
		t.Fatalf("cursor = %v, want it unchanged by the failure", st.Cursor)
	}

	// A very long error must not blow past the column's practical use as a
	// table cell; the store caps it.
	long := make([]byte, 5000)
	for i := range long {
		long[i] = 'x'
	}
	if err := store.MarkResult(ctx, FeedNVD, SyncResult{}, fmt.Errorf("%s", long)); err != nil {
		t.Fatalf("mark long failure: %v", err)
	}
	if got := feedState(t, store, FeedNVD); got.LastError == nil || len(*got.LastError) > 1100 {
		t.Fatalf("last_error length = %d, want it capped", len(*got.LastError))
	}
}

// Decision 13 (RC-29) against real Postgres: a partially failed OSV run
// persists the completed ecosystems' cursor, the rows it committed and the
// per-ecosystem status (jsonb round trip), and the next run carries a failing
// ecosystem's last success forward.
func TestIntegration_FeedState_PartialProgressPersistsEcosystems(t *testing.T) {
	store, db := integrationStore(t)
	ctx := context.Background()
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM public.catalog_feed_state WHERE feed = $1`, FeedOSV) })
	_, _ = db.Exec(`DELETE FROM public.catalog_feed_state WHERE feed = $1`, FeedOSV)

	boom := "archive for Ubuntu exceeds the 2048 MiB cap"
	debWM := "2026-09-20T12:00:00Z"
	first := SyncResult{
		Rows: 12, Cursor: `{"Alpine":"2026-09-19T00:00:00Z","Debian":"2026-09-20T12:00:00Z"}`, PartialProgress: true,
		Ecosystems: []EcosystemStatus{
			{Name: "Alpine", Status: EcosystemOK, Rows: 2},
			{Name: "Debian", Status: EcosystemOK, Rows: 10, Watermark: &debWM},
			{Name: "Ubuntu", Status: EcosystemError, LastError: &boom},
		},
	}
	if err := store.MarkResult(ctx, FeedOSV, first, fmt.Errorf("osv mirror incomplete: 1 of 3 ecosystems failed (Ubuntu)")); err != nil {
		t.Fatalf("mark partial failure: %v", err)
	}
	st := feedState(t, store, FeedOSV)
	if st.LastStatus != StatusError || st.RowCount != 12 {
		t.Fatalf("after partial failure: status %q rows %d, want error / 12", st.LastStatus, st.RowCount)
	}
	if st.Cursor == nil || *st.Cursor != first.Cursor {
		t.Fatalf("cursor = %v, want the completed ecosystems' watermarks persisted", st.Cursor)
	}
	if len(st.Ecosystems) != 3 {
		t.Fatalf("ecosystems = %+v, want 3", st.Ecosystems)
	}
	var ubuntu, debian EcosystemStatus
	for _, e := range st.Ecosystems {
		switch e.Name {
		case "Ubuntu":
			ubuntu = e
		case "Debian":
			debian = e
		}
	}
	if ubuntu.Status != EcosystemError || ubuntu.LastError == nil || *ubuntu.LastError != boom || ubuntu.LastSuccessAt != nil {
		t.Fatalf("Ubuntu = %+v, want error with its reason and no success", ubuntu)
	}
	if debian.Status != EcosystemOK || debian.Rows != 10 || debian.LastSuccessAt == nil ||
		debian.Watermark == nil || *debian.Watermark != debWM {
		t.Fatalf("Debian = %+v, want ok with 10 rows, its watermark and a success time", debian)
	}

	// Next run: Debian 304s and Ubuntu recovers. Both now carry a success
	// time, and the feed goes green.
	second := SyncResult{Rows: 0, Cursor: first.Cursor, PartialProgress: true, Ecosystems: []EcosystemStatus{
		{Name: "Debian", Status: EcosystemOK},
		{Name: "Ubuntu", Status: EcosystemOK, Rows: 40},
	}}
	if err := store.MarkResult(ctx, FeedOSV, second, nil); err != nil {
		t.Fatalf("mark success: %v", err)
	}
	st = feedState(t, store, FeedOSV)
	if st.LastStatus != StatusOK || st.LastError != nil || len(st.Ecosystems) != 2 {
		t.Fatalf("after recovery: %+v", st)
	}
	for _, e := range st.Ecosystems {
		if e.LastSuccessAt == nil {
			t.Fatalf("%s has no success time after an ok run: %+v", e.Name, e)
		}
	}

	// A feed that has never run lists an EMPTY ecosystem array, not null.
	_, _ = db.Exec(`DELETE FROM public.catalog_feed_state WHERE feed = $1`, FeedOSV)
	if got := feedState(t, store, FeedOSV); got.Ecosystems == nil || len(got.Ecosystems) != 0 {
		t.Fatalf("never-run ecosystems = %#v, want an empty array", got.Ecosystems)
	}
}

func feedState(t *testing.T, store *SQLStore, feed string) FeedState {
	t.Helper()
	states, err := store.FeedStates(context.Background())
	if err != nil {
		t.Fatalf("feed states: %v", err)
	}
	for _, st := range states {
		if st.Feed == feed {
			return st
		}
	}
	t.Fatalf("feed %q not in %v", feed, states)
	return FeedState{}
}

// The advisory lock is what stops N replicas running N copies of the NVD mirror
// and tripping its rate limit. It is a real Postgres object, so it can only be
// proven against a real Postgres.
func TestIntegration_TryLock_ExcludesASecondHolder(t *testing.T) {
	_, db := integrationStore(t)
	ctx := context.Background()

	release, ok, err := TryLock(ctx, db, FeedNVD)
	if err != nil {
		t.Fatalf("first lock: %v", err)
	}
	if !ok {
		t.Fatal("the first caller must get the lock")
	}

	// A second *session* — a second pool — is what another replica looks like.
	other := testdb.Connect(t)
	_, got, err := TryLock(ctx, other, FeedNVD)
	if err != nil {
		t.Fatalf("second lock: %v", err)
	}
	if got {
		t.Fatal("a second holder must be refused while the first holds the lock")
	}

	// A DIFFERENT feed must not be blocked by it — the key is per-feed.
	releaseOther, gotOther, err := TryLock(ctx, other, FeedEOL)
	if err != nil {
		t.Fatalf("other-feed lock: %v", err)
	}
	if !gotOther {
		t.Fatal("feeds must not block each other")
	}
	releaseOther()

	release()
	_, after, err := TryLock(ctx, other, FeedNVD)
	if err != nil {
		t.Fatalf("relock: %v", err)
	}
	if !after {
		t.Fatal("the lock must be released on the connection that took it")
	}
}

// The bundle is the air-gap path, so its round trip has to hold against the real
// schema — including the JSONB-free text encodings of the match rules.
func TestIntegration_Bundle_RoundTripsThroughPostgres(t *testing.T) {
	store, db := integrationStore(t)
	ctx := context.Background()
	product := uniqueProduct(t, "it-bundle")
	cve := fmt.Sprintf("CVE-2096-%d", time.Now().UnixNano()%100000)
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM public.eol_catalogue WHERE product = $1`, product)
		_, _ = db.Exec(`DELETE FROM public.vulnerability_catalogue WHERE cve_id = $1`, cve)
	})

	eol := time.Date(2031, 1, 1, 0, 0, 0, 0, time.UTC)
	if _, err := store.UpsertEOL(ctx, []EOLEntry{
		{ProductKind: KindOS, Vendor: ptr("ACME"), Product: product, Cycle: "1.0",
			EOLDate: &eol, SourceKind: "imported"},
	}); err != nil {
		t.Fatalf("seed eol: %v", err)
	}
	if _, _, err := store.UpsertVulnerabilities(ctx, []Vulnerability{{
		CVEID: cve, Severity: ptr(SeverityHigh), CVSSScore: ptr(7.5), SourceKind: "imported",
		Matches: []VulnerabilityMatch{{CPEMatch: ptr(`{"cpe":"cpe:2.3:a:acme:thing:1.0:*:*:*:*:*:*:*"}`)}},
	}}); err != nil {
		t.Fatalf("seed vuln: %v", err)
	}

	var buf bytes.Buffer
	if _, err := BuildBundle(ctx, store, &buf); err != nil {
		t.Fatalf("build bundle: %v", err)
	}

	// Wipe and re-import: what a fresh air-gapped install does.
	if _, err := db.Exec(`DELETE FROM public.eol_catalogue WHERE product = $1`, product); err != nil {
		t.Fatalf("wipe eol: %v", err)
	}
	if _, err := db.Exec(`DELETE FROM public.vulnerability_catalogue WHERE cve_id = $1`, cve); err != nil {
		t.Fatalf("wipe vuln: %v", err)
	}

	if _, err := ImportBundle(ctx, store, bytes.NewReader(buf.Bytes())); err != nil {
		t.Fatalf("import bundle: %v", err)
	}

	rows, _, err := store.ListEOL(ctx, EOLQuery{Search: product})
	if err != nil {
		t.Fatalf("list eol: %v", err)
	}
	if len(rows) != 1 || rows[0].Vendor == nil || *rows[0].Vendor != "ACME" ||
		rows[0].EOLDate == nil || !rows[0].EOLDate.UTC().Equal(eol) {
		t.Fatalf("eol row did not survive the round trip: %+v", rows)
	}

	vulns, _, err := store.ListVulnerabilities(ctx, VulnQuery{Search: cve})
	if err != nil {
		t.Fatalf("list vulns: %v", err)
	}
	if len(vulns) != 1 || vulns[0].CVSSScore == nil || *vulns[0].CVSSScore != 7.5 {
		t.Fatalf("cve did not survive the round trip: %+v", vulns)
	}
	var matches int
	_ = db.QueryRow(`SELECT count(*) FROM public.vulnerability_matches WHERE cve_id = $1`, cve).Scan(&matches)
	if matches != 1 {
		t.Fatalf("match rules after import = %d, want 1", matches)
	}
}

// ExportAll must group each CVE's match rules under it, not emit one CVE per
// match row — the LEFT JOIN makes that a real risk.
func TestIntegration_ExportAll_GroupsMatchesUnderTheirCVE(t *testing.T) {
	store, db := integrationStore(t)
	ctx := context.Background()
	cve := fmt.Sprintf("CVE-2095-%d", time.Now().UnixNano()%100000)
	t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM public.vulnerability_catalogue WHERE cve_id = $1`, cve) })

	if _, _, err := store.UpsertVulnerabilities(ctx, []Vulnerability{{
		CVEID: cve, SourceKind: "imported",
		Matches: []VulnerabilityMatch{
			{CPEMatch: ptr(`{"cpe":"a"}`)},
			{CPEMatch: ptr(`{"cpe":"b"}`)},
			{PURLRange: ptr(`{"purl":"c"}`)},
		},
	}}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	export, err := store.ExportAll(ctx)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	var found *Vulnerability
	for i := range export.Vulns {
		if export.Vulns[i].CVEID == cve {
			if found != nil {
				t.Fatal("the CVE appeared more than once — matches are not being grouped")
			}
			found = &export.Vulns[i]
		}
	}
	if found == nil {
		t.Fatal("the seeded CVE is missing from the export")
	}
	if len(found.Matches) != 3 {
		t.Fatalf("exported %d match rules, want 3", len(found.Matches))
	}

	// Determinism: a second export must be byte-identical.
	again, err := store.ExportAll(ctx)
	if err != nil {
		t.Fatalf("second export: %v", err)
	}
	for i := range again.Vulns {
		if again.Vulns[i].CVEID == cve && !reflect.DeepEqual(again.Vulns[i], *found) {
			t.Fatal("two exports of the same row differed — the bundle hash would not be reproducible")
		}
	}
}

// pqArray renders a []string as a Postgres array literal, so the cleanup can use
// `= ANY($1)` without pulling in pq.Array at every call site.
func pqArray(values []string) string {
	out := "{"
	for i, v := range values {
		if i > 0 {
			out += ","
		}
		out += `"` + v + `"`
	}
	return out + "}"
}
