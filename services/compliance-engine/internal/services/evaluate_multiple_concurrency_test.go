package services

// EvaluateMultipleFrameworks used to start one goroutine per requested
// framework with no ceiling, and every evaluation holds database connections —
// a single request naming a few thousand frameworks parked that many
// goroutines on the pool every other request in the service shares. This test
// counts how many queries the database sees at once: the driver is a stand-in
// that holds each query for a moment and records the high-water mark, so the
// number it reports is what the connection pool would actually have been asked
// for.

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"

	"github.com/vistasecurity/vistaplatform/compliance-engine/internal/models"
)

type concurrencyProbe struct {
	inflight  atomic.Int64
	highWater atomic.Int64
}

func (p *concurrencyProbe) enter() {
	n := p.inflight.Add(1)
	for {
		cur := p.highWater.Load()
		if n <= cur || p.highWater.CompareAndSwap(cur, n) {
			return
		}
	}
}

type probeDriver struct{ probe *concurrencyProbe }

func (d probeDriver) Open(string) (driver.Conn, error) { return &probeConn{probe: d.probe}, nil }

type probeConn struct{ probe *concurrencyProbe }

func (c *probeConn) Prepare(string) (driver.Stmt, error) { return nil, errors.New("probe: no prepare") }
func (c *probeConn) Close() error                        { return nil }
func (c *probeConn) Begin() (driver.Tx, error)           { return nil, errors.New("probe: no tx") }

// QueryContext holds the query open long enough for concurrent callers to
// overlap, then fails it: the evaluation under test then takes its not-found
// path, which is all this test needs of it.
func (c *probeConn) QueryContext(ctx context.Context, _ string, _ []driver.NamedValue) (driver.Rows, error) {
	c.probe.enter()
	defer c.probe.inflight.Add(-1)
	select {
	case <-time.After(25 * time.Millisecond):
	case <-ctx.Done():
	}
	return nil, errors.New("probe: query refused")
}

func newProbeDB(t *testing.T, probe *concurrencyProbe) *sqlx.DB {
	t.Helper()
	// Registered once per test under a unique name: sql.Register panics on a duplicate.
	name := "compliance-concurrency-probe-" + uuid.NewString()
	sql.Register(name, probeDriver{probe: probe})
	raw, err := sql.Open(name, "")
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	return sqlx.NewDb(raw, "postgres")
}

func TestEvaluateMultipleFrameworks_BoundsConcurrentEvaluations(t *testing.T) {
	probe := &concurrencyProbe{}
	svc := NewEvaluationService(newProbeDB(t, probe))

	ids := make([]uuid.UUID, 64)
	for i := range ids {
		ids[i] = uuid.New()
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _ = svc.EvaluateMultipleFrameworks(uuid.New(), ids, nil, models.ScenarioFilters{}, "")
	}()
	wg.Wait()

	if got := probe.highWater.Load(); got == 0 {
		t.Fatal("the probe saw no queries: the test is not exercising the evaluation path")
	}
	if got := probe.highWater.Load(); got > maxConcurrentFrameworkEvaluations {
		t.Fatalf("%d queries were in flight at once for one request; the ceiling is %d",
			got, maxConcurrentFrameworkEvaluations)
	}
}
