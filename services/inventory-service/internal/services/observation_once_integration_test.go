package services

// WP4a, both halves, driven through the real ingest path
// (IngestFindingsReport) against a real database.
//
// F5 — one owner read per identifier. The ingest used to build the discovery
// observation twice and look every identifier up twice: once in a pre-lookup
// (lookupExistingAsset) deciding denied / third-party / suppressed, and again
// inside the engine's Resolve. The ingest gate now reads the owners once, on
// the engine's transaction under the identifier locks, and the engine resolves
// on that snapshot. The lookups are counted at the DRIVER, by the SQL text of
// the repository's FindByIdentifier, so any second read — through the engine,
// a reintroduced pre-lookup on the service's own connection, or anything else
// — is seen, whatever code path makes it.
//
// Mutation that proves it: in resolveObservationGated, hand the engine no
// snapshot (`.WithOwnerSnapshot(nil)`) — every identifier is read twice and
// the per-key assertion goes red. Restoring a lookupExistingAsset call ahead of
// resolveDiscoveryObservation does the same.
//
// F6 — one `created` row per new asset. The engine wrote a `created` row
// (class, identifiers, endpoints) and applyAssetContext wrote a SECOND one for
// the tags, metadata and ownership. The context is now folded into the
// engine's row (foldIntoCreatedHistory).
//
// Mutation that proves it: make foldIntoCreatedHistory return false without
// folding — the asset gets two `created` rows and the count assertion goes red.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db). RFC 5737 documentation addresses throughout.

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	sharedDatabase "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// findByIdentifierSQL is shared/identity/postgres Repository.FindByIdentifier's
// statement, whitespace-collapsed. If that statement is reworded the counter
// sees nothing — which is why the F5 test also asserts that every identifier
// was read at least once.
const findByIdentifierSQL = "SELECT asset_id FROM public.asset_identifiers WHERE tenant_id = $1 AND kind = $2 AND value = $3 AND coalesce(scope, '') = $4 ORDER BY asset_id"

// ownerLookups counts FindByIdentifier statements per (kind, value, scope).
type ownerLookups struct {
	mu sync.Mutex
	n  map[string]int
}

func (c *ownerLookups) observe(query string, args []driver.NamedValue) {
	if strings.Join(strings.Fields(query), " ") != findByIdentifierSQL || len(args) != 4 {
		return
	}
	key := ""
	for i, a := range args[1:] {
		if i > 0 {
			key += "|"
		}
		s, _ := a.Value.(string)
		key += s
	}
	c.mu.Lock()
	c.n[key]++
	c.mu.Unlock()
}

func (c *ownerLookups) reset() {
	c.mu.Lock()
	c.n = map[string]int{}
	c.mu.Unlock()
}

func (c *ownerLookups) snapshot() map[string]int {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make(map[string]int, len(c.n))
	for k, v := range c.n {
		out[k] = v
	}
	return out
}

// lookupCountingConnector is lib/pq's connector with every statement observed. The
// connection forwards each optional driver interface pq implements, so
// database/sql drives it exactly as it drives pq.
type lookupCountingConnector struct {
	base    *pq.Connector
	lookups *ownerLookups
}

func (k lookupCountingConnector) Connect(ctx context.Context) (driver.Conn, error) {
	conn, err := k.base.Connect(ctx)
	if err != nil {
		return nil, err
	}
	return &lookupCountingConn{Conn: conn, lookups: k.lookups}, nil
}

func (k lookupCountingConnector) Driver() driver.Driver { return k.base.Driver() }

type lookupCountingConn struct {
	driver.Conn
	lookups *ownerLookups
}

func (c *lookupCountingConn) QueryContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Rows, error) {
	c.lookups.observe(query, args)
	q, ok := c.Conn.(driver.QueryerContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	return q.QueryContext(ctx, query, args)
}

func (c *lookupCountingConn) ExecContext(ctx context.Context, query string, args []driver.NamedValue) (driver.Result, error) {
	e, ok := c.Conn.(driver.ExecerContext)
	if !ok {
		return nil, driver.ErrSkip
	}
	return e.ExecContext(ctx, query, args)
}

func (c *lookupCountingConn) PrepareContext(ctx context.Context, query string) (driver.Stmt, error) {
	if p, ok := c.Conn.(driver.ConnPrepareContext); ok {
		return p.PrepareContext(ctx, query)
	}
	return c.Prepare(query)
}

func (c *lookupCountingConn) BeginTx(ctx context.Context, opts driver.TxOptions) (driver.Tx, error) {
	if b, ok := c.Conn.(driver.ConnBeginTx); ok {
		return b.BeginTx(ctx, opts)
	}
	return c.Begin() //nolint:staticcheck // fallback for a driver without BeginTx
}

func (c *lookupCountingConn) Ping(ctx context.Context) error {
	if p, ok := c.Conn.(driver.Pinger); ok {
		return p.Ping(ctx)
	}
	return nil
}

func (c *lookupCountingConn) ResetSession(ctx context.Context) error {
	if r, ok := c.Conn.(driver.SessionResetter); ok {
		return r.ResetSession(ctx)
	}
	return nil
}

func (c *lookupCountingConn) IsValid() bool {
	if v, ok := c.Conn.(driver.Validator); ok {
		return v.IsValid()
	}
	return true
}

func (c *lookupCountingConn) CheckNamedValue(nv *driver.NamedValue) error {
	if n, ok := c.Conn.(driver.NamedValueChecker); ok {
		return n.CheckNamedValue(nv)
	}
	return driver.ErrSkip
}

// countingDB opens the integration database through lookupCountingConnector.
func countingDB(t *testing.T) (*sql.DB, *ownerLookups) {
	t.Helper()
	base, err := pq.NewConnector(os.Getenv(testdb.URLEnv))
	if err != nil {
		t.Fatalf("pq connector: %v", err)
	}
	lookups := &ownerLookups{n: map[string]int{}}
	db := sql.OpenDB(lookupCountingConnector{base: base, lookups: lookups})
	// The ingest's post-resolution enrichment takes session advisory locks on
	// a control pool registered against the data pool, as the service's own
	// connection does at start-up.
	if err := sharedDatabase.RegisterSessionPool(db, "postgres", os.Getenv(testdb.URLEnv)); err != nil {
		t.Fatalf("register session pool: %v", err)
	}
	t.Cleanup(func() { _ = sharedDatabase.CloseWithSessionPool(db) })
	return db, lookups
}

// assetIdentifierKeys reads the identifiers an asset carries, keyed the way
// ownerLookups keys a lookup.
func assetIdentifierKeys(t *testing.T, db *sql.DB, tenant, asset uuid.UUID) []string {
	t.Helper()
	rows, err := db.Query(`SELECT kind, value, coalesce(scope, '') FROM asset_identifiers WHERE tenant_id = $1 AND asset_id = $2`, tenant, asset)
	if err != nil {
		t.Fatalf("read identifiers: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var keys []string
	for rows.Next() {
		var kind, value, scope string
		if err := rows.Scan(&kind, &value, &scope); err != nil {
			t.Fatalf("scan identifier: %v", err)
		}
		keys = append(keys, kind+"|"+value+"|"+scope)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("read identifiers: %v", err)
	}
	return keys
}

func TestIntegration_Ingest_LooksEachIdentifierUpOnce(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	tenant := testdb.NewTenant(t, raw)
	counted, lookups := countingDB(t)
	svc := NewAssetService(&database.DB{DB: sqlx.NewDb(counted, "postgres")})

	const host = "once-host.example.test"
	const addr = "198.51.100.71"
	finding := func() []IngestFinding {
		return []IngestFinding{effectiveStatusFinding(host, addr, 443, hexFingerprint("observation-once-443"))}
	}

	// Two passes: the creating observation, then a re-observation that
	// MATCHES — the steady state, and the path the old pre-lookup and the
	// engine both read every identifier on.
	for _, pass := range []string{"create", "match"} {
		lookups.reset()
		report, err := svc.IngestFindingsReport(tenant, finding(), identity.StatusMonitoring)
		if err != nil {
			t.Fatalf("%s: IngestFindingsReport: %v", pass, err)
		}
		if len(report.Results) != 1 || report.Results[0].AssetID == "" {
			t.Fatalf("%s: outcomes = %+v, want one finding on an asset", pass, report.Results)
		}
		wantOutcome := string(identity.OutcomeCreated)
		if pass == "match" {
			wantOutcome = string(identity.OutcomeMatched)
		}
		if report.Results[0].Outcome != wantOutcome {
			t.Fatalf("%s: outcome = %q, want %q", pass, report.Results[0].Outcome, wantOutcome)
		}
		assetID := uuid.MustParse(report.Results[0].AssetID)

		keys := assetIdentifierKeys(t, raw, tenant, assetID)
		if len(keys) < 2 {
			t.Fatalf("%s: the asset carries %d identifiers (%v); the test needs a finding with several", pass, len(keys), keys)
		}
		got := lookups.snapshot()
		for _, key := range keys {
			if got[key] == 0 {
				t.Errorf("%s: %s was never looked up — the counter no longer recognises the repository's statement", pass, key)
			}
		}
		for key, n := range got {
			if n != 1 {
				t.Errorf("%s: %s was looked up %d times for one finding, want 1 (#2374 F5)", pass, key, n)
			}
		}
	}
}

func TestIntegration_Ingest_NewAssetHasOneCreatedHistoryRow(t *testing.T) {
	raw := testdb.Connect(t)
	testdb.ApplySchemaAndSeed(t, raw)
	db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
	tenant := testdb.NewTenant(t, raw)
	svc := NewAssetService(db)

	report, err := svc.IngestFindingsReport(tenant,
		[]IngestFinding{effectiveStatusFinding("one-created.example.test", "198.51.100.72", 443, hexFingerprint("one-created-443"))},
		identity.StatusPendingApproval)
	if err != nil {
		t.Fatalf("IngestFindingsReport: %v", err)
	}
	if len(report.Results) != 1 || report.Results[0].Outcome != string(identity.OutcomeCreated) {
		t.Fatalf("outcomes = %+v, want one created asset", report.Results)
	}
	asset := uuid.MustParse(report.Results[0].AssetID)

	timeline := assetTimeline(t, db, tenant, asset)
	if n := countTimelineAction(timeline, string(identity.ActionCreated)); n != 1 {
		t.Fatalf("a new asset has %d `created` history rows, want 1 (#2374 F6):%s", n, describeTimeline(timeline))
	}
	// The one row carries both halves: the engine's identity record and the
	// context the asset was born with.
	for _, r := range timeline {
		if r.Action != string(identity.ActionCreated) {
			continue
		}
		for _, key := range []string{"class_key", "identifiers", "metadata", "asset_ownership"} {
			if r.Changes[key] == nil {
				t.Errorf("the created row has no %q:%s", key, describeTimeline(timeline))
			}
		}
	}
	if n := countTimelineAction(timeline, string(identity.ActionUpdated)); n != 0 {
		t.Errorf("the creating observation wrote %d `updated` rows:%s", n, describeTimeline(timeline))
	}
}

// The fold's fallback ( F6, review of). foldIntoCreatedHistory folds
// only into a `created` row of the same producer that THIS transaction wrote;
// anything else must leave that row alone and record the context in a row of
// its own, losing nothing. Both cases are driven through applyAssetContext on
// its own transaction against an asset the ingest created (and committed)
// earlier, so the engine's `created` row belongs to a different transaction:
//
//   - same source: the old row is a candidate by asset/action/source but was
//     not written by this transaction — rewriting it would corrupt the audit
//     trail, so the context must land in a new row;
//   - different source: no candidate at all.
//
// Mutation that proves it: make the fallback return without writing (drop the
// recordAssetHistory call after foldIntoCreatedHistory) — the context appears
// in no row and both subtests go red. Dropping the xmin predicate turns the
// same-source subtest red (the old row is rewritten).
func TestIntegration_ApplyAssetContext_CreatedFoldFallsBackToOwnRow(t *testing.T) {
	cases := []struct {
		name   string
		source func(engine string) identity.Source
	}{
		{"same source, row from an earlier transaction", func(engine string) identity.Source {
			return identity.Source{Ref: engine}
		}},
		{"different source, no created row of its own", func(string) identity.Source {
			return identity.Source{Ref: "fallback-test:context"}
		}},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := testdb.Connect(t)
			testdb.ApplySchemaAndSeed(t, raw)
			db := &database.DB{DB: sqlx.NewDb(raw, "postgres")}
			tenant := testdb.NewTenant(t, raw)
			svc := NewAssetService(db)

			report, err := svc.IngestFindingsReport(tenant,
				[]IngestFinding{effectiveStatusFinding(fmt.Sprintf("fold-fallback-%d.example.test", i), fmt.Sprintf("198.51.100.%d", 80+i), 443, hexFingerprint(fmt.Sprintf("fold-fallback-%d", i)))},
				identity.StatusPendingApproval)
			if err != nil || len(report.Results) != 1 || report.Results[0].Outcome != string(identity.OutcomeCreated) {
				t.Fatalf("setup ingest: %v, %+v", err, report.Results)
			}
			asset := uuid.MustParse(report.Results[0].AssetID)

			before := assetTimeline(t, db, tenant, asset)
			var created *contextHistoryRow
			for j := range before {
				if before[j].Action == string(identity.ActionCreated) {
					created = &before[j]
				}
			}
			if created == nil {
				t.Fatalf("setup: no created row:%s", describeTimeline(before))
			}

			own := "third_party"
			in := models.AssetInput{
				Tags:           map[string]interface{}{"fold_fallback_tag": "t1"},
				Metadata:       map[string]interface{}{"fold_fallback_meta": "m1"},
				AssetOwnership: &own,
			}
			if err := svc.applyAssetContext(nil, tenant, asset, in, tc.source(created.Source), identity.OutcomeCreated); err != nil {
				t.Fatalf("applyAssetContext: %v", err)
			}

			after := assetTimeline(t, db, tenant, asset)
			// Every row that existed before is untouched (history is
			// append-only, and ordered by seq).
			if len(after) < len(before) {
				t.Fatalf("history shrank:%s", describeTimeline(after))
			}
			for j := range before {
				was, _ := json.Marshal(before[j].Changes)
				now, _ := json.Marshal(after[j].Changes)
				if string(was) != string(now) {
					t.Errorf("history row %d (%s) was rewritten:\n before %s\n after  %s", j+1, before[j].Action, was, now)
				}
			}
			// And nothing was lost: every context key is in a row of its own.
			for _, key := range []string{"tags", "metadata", "asset_ownership"} {
				found := false
				for _, r := range after[len(before):] {
					if r.Changes[key] != nil {
						found = true
					}
				}
				if !found {
					t.Errorf("%q was written to no new history row:%s", key, describeTimeline(after))
				}
			}
			if len(after) != len(before)+1 {
				t.Errorf("history grew from %d to %d rows, want exactly one new row:%s", len(before), len(after), describeTimeline(after))
			}
		})
	}
}
