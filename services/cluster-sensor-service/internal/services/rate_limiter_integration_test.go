package services

// A tenant's first rate-limit read creates its default row. Concurrent first
// reads — the deliveries of a new tenant's first job racing each other — used
// to lose the insert race with a unique violation, which CheckRateLimit
// reported as "rate limit exceeded" and the processor turned into a failed job.
//
// Skips without TEST_DATABASE_URL (nightly test-backend / make
// test-integration-db).

import (
	"sync"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

func TestIntegration_RateLimit_ConcurrentFirstReadsAllSucceed(t *testing.T) {
	f := newDispatchFixture(t)
	// The race is a narrow window between the read and the insert, so it is
	// run on several fresh tenants to make losing it near certain.
	const rounds, readers = 10, 16
	for round := 0; round < rounds; round++ {
		tenant := testdb.NewTenant(t, f.raw).String()
		errs := make(chan error, readers)
		var wg sync.WaitGroup
		gate := make(chan struct{})
		for i := 0; i < readers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-gate
				errs <- f.jp.rateLimiter.CheckRateLimit(tenant)
			}()
		}
		close(gate)
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatalf("CheckRateLimit on a tenant's first concurrent reads: %v", err)
			}
		}
		var rows int
		if err := f.raw.QueryRow(`SELECT COUNT(*) FROM discovery_rate_limits WHERE tenant_id = $1`, tenant).Scan(&rows); err != nil {
			t.Fatal(err)
		}
		if rows != 1 {
			t.Fatalf("default rate-limit rows = %d, want 1", rows)
		}
	}
}
