package processor

// ProcessBatch's call to foldTLSEnrichmentPairs, driven WITHOUT a database, so
// the PR gate (which never sets TEST_DATABASE_URL) goes red if the call is
// deleted: the pair tests elsewhere call the fold directly or need Postgres.
//
// The store is a minimal database/sql driver that serves two unprocessed rows
// for the batch read and accepts every write. Mutation: delete the
// foldTLSEnrichmentPairs call in processBatch; this test then sees two imports.

import (
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/client"
	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/config"
	"github.com/vistasecurity/vistaplatform/discovery-processor-service/internal/converter"
)

type fakeStore struct {
	mu    sync.Mutex
	rows  [][]driver.Value
	execs []string
}

type fakeDriver struct{ s *fakeStore }
type fakeConn struct{ s *fakeStore }
type fakeTx struct{}
type fakeStmt struct {
	s *fakeStore
	q string
}

func (d fakeDriver) Open(string) (driver.Conn, error)    { return fakeConn(d), nil }
func (c fakeConn) Prepare(q string) (driver.Stmt, error) { return fakeStmt{c.s, q}, nil }
func (c fakeConn) Close() error                          { return nil }
func (c fakeConn) Begin() (driver.Tx, error)             { return fakeTx{}, nil }
func (fakeTx) Commit() error                             { return nil }
func (fakeTx) Rollback() error                           { return nil }
func (st fakeStmt) Close() error                         { return nil }
func (st fakeStmt) NumInput() int                        { return -1 }
func (st fakeStmt) Exec([]driver.Value) (driver.Result, error) {
	st.s.mu.Lock()
	st.s.execs = append(st.s.execs, st.q)
	st.s.mu.Unlock()
	return driver.RowsAffected(1), nil
}

var discoveryReadCols = []string{"id", "sensor_id", "tenant_id", "batch_id", "protocol", "dest_ip", "port", "confidence",
	"metadata", "timestamp", "created_at", "processed_at", "approval_status", "auto_approval_rule_id", "asset_id", "hostname", "source_ip"}

func (st fakeStmt) Query([]driver.Value) (driver.Rows, error) {
	if strings.Contains(st.q, "FROM sensor_discoveries") && strings.Contains(st.q, "ORDER BY created_at") {
		return &fakeRows{cols: discoveryReadCols, rows: st.s.rows}, nil
	}
	return &fakeRows{}, nil // any other read (auto-approval rules ...) is empty
}

type fakeRows struct {
	cols []string
	rows [][]driver.Value
	i    int
}

func (r *fakeRows) Columns() []string { return r.cols }
func (r *fakeRows) Close() error      { return nil }
func (r *fakeRows) Next(dest []driver.Value) error {
	if r.i >= len(r.rows) {
		return io.EOF
	}
	copy(dest, r.rows[r.i])
	r.i++
	return nil
}

func openFakeStore(t *testing.T, s *fakeStore) *sql.DB {
	t.Helper()
	name := "fakestore-" + uuid.NewString()
	sql.Register(name, fakeDriver{s})
	db, err := sql.Open(name, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func fakeDiscoveryRow(t *testing.T, tenant, batch uuid.UUID, host string, envelope map[string]any, at time.Time) []driver.Value {
	t.Helper()
	blob, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	var hostname driver.Value
	if host != "" {
		hostname = host
	}
	return []driver.Value{uuid.NewString(), uuid.NewString(), tenant.String(), batch.String(), "TLS", "10.20.30.40", int64(443), 0.8,
		blob, at, at, nil, "pending", nil, nil, hostname, "10.0.0.5"}
}

func TestProcessBatch_FoldsAPassiveActivePairIntoOneImport_NoDB(t *testing.T) {
	tenant, batch := uuid.New(), uuid.New()
	now := time.Now().UTC()
	store := &fakeStore{rows: [][]driver.Value{
		fakeDiscoveryRow(t, tenant, batch, "portal.example.test", passiveTLSEnvelope("10.0.0.5", "portal.example.test", nil), now),
		fakeDiscoveryRow(t, tenant, batch, "", activeTLSEnvelope("10.0.0.5"), now.Add(time.Millisecond)),
	}}
	raw := openFakeStore(t, store)
	rec := newPairRecorder(t)
	inventory, err := client.NewInventoryClient(&config.Config{InventoryServiceURL: rec.srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	previous := lookupPTR
	lookupPTR = func(string) string { return "" }
	t.Cleanup(func() { lookupPTR = previous })
	p := NewBatchProcessor(sqlx.NewDb(raw, "postgres"), converter.NewSensorDiscoveryConverter(), inventory, nil)

	if err := p.processBatch(batch.String(), tenant, nil); err != nil {
		t.Fatalf("processBatch: %v", err)
	}
	imported, external := rec.snapshot()
	if len(external) != 0 || len(imported) != 1 {
		t.Fatalf("pair produced %d import finding(s) and %d external upsert(s), want exactly 1 import: the fold must run in ProcessBatch", len(imported), len(external))
	}
	// Both rows are stamped processed, the follower with its survivor.
	store.mu.Lock()
	defer store.mu.Unlock()
	stamped := false
	for _, q := range store.execs {
		if strings.Contains(q, "SET processed_at") {
			stamped = true
		}
	}
	if !stamped {
		t.Fatal("no processed_at stamp was written")
	}
}
