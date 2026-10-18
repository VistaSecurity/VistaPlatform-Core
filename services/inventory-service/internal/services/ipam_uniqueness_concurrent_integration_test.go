package services

// DB-integration test for IP address uniqueness under concurrency. The rule
// (one address per host per VRF that enforces it) is held by the service under
// an advisory lock, not by an index, so only concurrent writers can show the
// lock working. Skips unless TEST_DATABASE_URL is set (`make test-integration-db`).

import (
	"errors"
	"fmt"
	"sync"
	"testing"
)

// Eight writers create the same host at once, in different spellings of it
// (/24, /32, /25), in the global table and in a VRF that enforces uniqueness:
// exactly one wins, seven are refused as conflicts, one row remains. Repeated
// over several hosts so a race has room to show.
//
// Mutation: remove the pg_advisory_xact_lock in ipAddressUniqueness → several
// writers read "no duplicate" and commit, leaving duplicate rows.
func TestIntegration_IPAddress_ConcurrentCreateExactlyOneWins(t *testing.T) {
	f := newIPAMFixture(t)
	strict := f.create(t, "vrfs", map[string]any{"name": "strict-conc", "rd": "65000:77"})
	masks := []string{"/24", "/32", "/25", "/24", "/32", "/25", "/24", "/32"}

	for _, vrf := range []any{nil, strict["id"]} {
		for round := 0; round < 4; round++ {
			host := fmt.Sprintf("10.77.%d.5", round)
			if vrf != nil {
				host = fmt.Sprintf("10.78.%d.5", round)
			}
			var (
				wg       sync.WaitGroup
				start    = make(chan struct{})
				mu       sync.Mutex
				ok, conf int
				other    []error
			)
			for _, m := range masks {
				wg.Add(1)
				go func(mask string) {
					defer wg.Done()
					<-start
					body := map[string]any{"address": host + mask}
					if vrf != nil {
						body["vrf_id"] = vrf
					}
					err := f.tryCreate("ip-addresses", body)
					mu.Lock()
					defer mu.Unlock()
					switch {
					case err == nil:
						ok++
					case errors.Is(err, ErrIPAMConflict):
						conf++
					default:
						other = append(other, err)
					}
				}(m)
			}
			close(start)
			wg.Wait()
			if len(other) > 0 {
				t.Fatalf("vrf=%v round %d: unexpected errors %v", vrf, round, other)
			}
			var rows int
			if err := f.owner.QueryRow(`SELECT count(*) FROM ip_addresses WHERE tenant_id = $1 AND host = $2::inet
				AND COALESCE(vrf_id::text, '') = COALESCE($3::text, '')`, f.tenant, host, vrf).Scan(&rows); err != nil {
				t.Fatal(err)
			}
			if ok != 1 || conf != 7 || rows != 1 {
				t.Fatalf("vrf=%v round %d: %d created, %d refused, %d rows — want exactly one", vrf, round, ok, conf, rows)
			}
		}
	}
}

// Addresses whose role may be shared (anycast, VIP) never conflict with each
// other, even when created at once.
func TestIntegration_IPAddress_ConcurrentSharedRolesAllSucceed(t *testing.T) {
	f := newIPAMFixture(t)
	var (
		wg    sync.WaitGroup
		start = make(chan struct{})
		mu    sync.Mutex
		errs  []error
	)
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if err := f.tryCreate("ip-addresses", map[string]any{"address": "10.79.0.1/32", "role": "anycast"}); err != nil {
				mu.Lock()
				errs = append(errs, err)
				mu.Unlock()
			}
		}()
	}
	close(start)
	wg.Wait()
	if len(errs) > 0 {
		t.Fatalf("shared-role creates were refused: %v", errs)
	}
	var rows int
	if err := f.owner.QueryRow(`SELECT count(*) FROM ip_addresses WHERE tenant_id = $1 AND host = '10.79.0.1'::inet`, f.tenant).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 6 {
		t.Fatalf("%d anycast rows, want 6", rows)
	}
}
