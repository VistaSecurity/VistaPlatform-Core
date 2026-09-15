package producers

// `asset_endpoints.status = 'stale'` finally has a writer.
//
// The CHECK has allowed `active` / `stale` / `closed` since the table was
// written; `active` is set by every intake and `closed` by the host-inventory
// ingest, and `stale` was set by nothing at all — so a filter on it returned
// nothing and the column could not distinguish "this endpoint went quiet" from
// "this endpoint is fine". The hygiene pass writes it now, at the stale
// ladder's first rung, which is the same boundary its `stale` FINDING and the
// Inventory Hygiene control IH-004 use. DATA_MODEL §2 has the state machine.
//
// All three transitions are pinned here, and so is the one that must NOT
// happen: `closed` is an authoritative negative from a host and a time-based
// rule may never overrule it.
//
// Skips without TEST_DATABASE_URL.

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

func endpointStatus(t *testing.T, f *hygieneFixture, id uuid.UUID) string {
	t.Helper()
	var status string
	if err := f.owner.QueryRow(
		`SELECT status FROM asset_endpoints WHERE tenant_id = $1 AND id = $2`,
		f.tenant, id).Scan(&status); err != nil {
		t.Fatalf("read endpoint status: %v", err)
	}
	return status
}

func TestIntegration_HygieneProducer_MarksUnseenEndpointsStaleAndBackAgain(t *testing.T) {
	f := newHygieneFixture(t)
	ctx := context.Background()

	// A second endpoint on the same host, seen this morning. It is the negative
	// control: without it a writer that marked EVERY endpoint stale would pass.
	freshEP := endpoint(t, f.owner, f.tenant, f.tidy, "198.51.100.21", 22, "tcp", "sshd", "banner", nil)

	if got := endpointStatus(t, f, f.staleEP); got != "active" {
		t.Fatalf("the fixture endpoint starts %q, want active", got)
	}

	run := f.run(t, ctx)
	if run.EndpointsMarkedStale != 1 {
		t.Errorf("run.EndpointsMarkedStale = %d, want 1", run.EndpointsMarkedStale)
	}
	if got := endpointStatus(t, f, f.staleEP); got != "stale" {
		t.Errorf("an endpoint unseen for 200 days is %q, want stale", got)
	}
	if got := endpointStatus(t, f, freshEP); got != "active" {
		t.Errorf("an endpoint seen today is %q, want active — staleness is about the last "+
			"observation, not about the pass running", got)
	}

	// A converged re-run writes nothing. The UPDATE is guarded on the current
	// status as well as the date, so a nightly pass does not touch every row in
	// the table.
	again := f.run(t, ctx)
	if again.EndpointsMarkedStale != 0 || again.EndpointsMarkedActive != 0 {
		t.Errorf("a converged re-run moved %d to stale and %d to active; it should move none",
			again.EndpointsMarkedStale, again.EndpointsMarkedActive)
	}

	// Something sees it again. Staleness is a property of the last observation,
	// not a flag that sticks.
	exec(t, f.owner, `UPDATE asset_endpoints SET last_seen_at = now() WHERE id = $1 AND tenant_id = $2`,
		f.staleEP, f.tenant)
	back := f.run(t, ctx)
	if back.EndpointsMarkedActive != 1 {
		t.Errorf("run.EndpointsMarkedActive = %d after the endpoint was observed again, want 1",
			back.EndpointsMarkedActive)
	}
	if got := endpointStatus(t, f, f.staleEP); got != "active" {
		t.Errorf("a re-observed endpoint is %q, want active", got)
	}
}

// The transition that must never happen: a closed endpoint is not re-opened,
// not re-staled, and not read at all.
//
// `closed` means a host inventory said the socket is gone. A time-based rule
// overruling a measurement is the port-heuristic mistake in another costume,
// and it points both ways: the pass must not write `closed` from a date, and it
// must not drag a `closed` row back to `stale` or `active` either.
func TestIntegration_HygieneProducer_LeavesClosedEndpointsAlone(t *testing.T) {
	f := newHygieneFixture(t)
	ctx := context.Background()

	closedEP := endpoint(t, f.owner, f.tenant, f.tidy, "198.51.100.22", 8080, "tcp", "", "", nil)
	exec(t, f.owner, `UPDATE asset_endpoints SET status = 'closed', last_seen_at = $1
	                  WHERE id = $2 AND tenant_id = $3`, daysFromNow(-300), closedEP, f.tenant)

	f.run(t, ctx)

	if got := endpointStatus(t, f, closedEP); got != "closed" {
		t.Errorf("a closed endpoint became %q; only a host inventory decides that column's "+
			"negative, and only an observation takes it back", got)
	}
	// And the endpoint the pass DID look at is still marked, so this test
	// cannot pass by the producer doing nothing at all.
	if got := endpointStatus(t, f, f.staleEP); got != "stale" {
		t.Errorf("the long-unseen endpoint is %q, want stale — if it is active this test proves "+
			"nothing about closed rows", got)
	}
}

// A closed endpoint is excluded from the stale FINDING too, and a stale one is
// not: the pass reads `status <> 'closed'`, which is what stops the status
// transition from eating the finding that describes it.
//
// Without the widened read the sequence is: pass 1 raises the finding and marks
// the endpoint stale; pass 2 no longer reads the endpoint, does not re-assert
// the finding, and the sweep resolves it. The condition is unchanged throughout.
func TestIntegration_HygieneProducer_StaleEndpointKeepsItsFindingAcrossPasses(t *testing.T) {
	f := newHygieneFixture(t)
	ctx := context.Background()

	f.run(t, ctx)
	first := f.finding(t, "stale", "endpoint", f.staleEP)
	if first == nil {
		t.Fatal("no stale finding on an endpoint unseen for 200 days")
	}

	second := f.run(t, ctx)
	after := f.finding(t, "stale", "endpoint", f.staleEP)
	if after == nil || after.state != "ACTIVE" {
		t.Fatalf("the stale finding is %v on the pass after the endpoint was marked stale — the "+
			"status transition swept its own finding", after)
	}
	if after.occurrence <= first.occurrence {
		t.Errorf("occurrence_count did not advance (%d then %d): the second pass did not see the "+
			"endpoint at all", first.occurrence, after.occurrence)
	}
	if second.Resolved != 0 {
		t.Errorf("the second pass resolved %d findings; nothing changed between them", second.Resolved)
	}
}
