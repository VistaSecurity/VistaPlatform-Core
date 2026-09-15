package producers

// A pass that FAILED must not sweep.
//
// This is the single most dangerous property of the producer contract and the
// one no existing test covered. `Sweep` is a producer saying "this is
// everything I currently see", so an empty seen-set inactivates every ACTIVE
// row of that kind — correct for a producer that genuinely saw nothing, and
// catastrophic for a run that died half way. The symptom is not an error: every
// finding in the tenant goes INACTIVE, disappears from the page, and comes back
// tomorrow with its workflow status reset and its notification re-sent.
//
// The producers protect against this in two ways, and BOTH are asserted here
// because each looks fine with the other deleted:
//
//  1. the read and resolve phases return an ERROR rather than a partial result,
//     and Run returns before the write phase;
//  2. the write phase is ONE transaction — upserts, facts and sweep — so a
//     sweep physically cannot commit without the upserts that justify it.
//
// Mutation-proven: make `Run` swallow the resolve error and carry on, and
// TestIntegration_EOLProducer_AFailedPassDoesNotSweep goes red with every
// finding in the fixture INACTIVE.

import (
	"context"
	"errors"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/ai/seams"
	"github.com/vistasecurity/vistaplatform/shared/catalogs"
	"github.com/vistasecurity/vistaplatform/shared/testdb"
)

// explodingStore answers the first N lookups and then fails, which is exactly
// the shape of a catalogue read that dies part way: some subjects resolved,
// the rest never will, and the producer has NOT made a full statement.
type explodingStore struct {
	inner catalogs.LookupStore
	calls int
	after int
}

var errCatalogueDown = errors.New("catalogue read failed part way through the pass")

func (s *explodingStore) LookupEOL(ctx context.Context, q catalogs.EOLLookup) ([]catalogs.EOLRow, error) {
	s.calls++
	if s.calls > s.after {
		return nil, errCatalogueDown
	}
	return s.inner.LookupEOL(ctx, q)
}

func (s *explodingStore) LookupCPE(ctx context.Context, vendor, product string) (string, string, error) {
	return s.inner.LookupCPE(ctx, vendor, product)
}

func (s *explodingStore) RecordMiss(ctx context.Context, m catalogs.MissSubject) error {
	return s.inner.RecordMiss(ctx, m)
}

func TestIntegration_EOLProducer_AFailedPassDoesNotSweep(t *testing.T) {
	f := newEOLFixture(t)

	// A good pass first, so there is something a bad sweep could destroy.
	if _, err := f.producer.Run(context.Background(), f.tenant); err != nil {
		t.Fatalf("the first pass failed: %v", err)
	}
	before := activeFindings(t, f)
	if len(before) == 0 {
		t.Fatal("the first pass raised nothing; there is no finding for a bad sweep to inactivate")
	}

	// Now a pass whose catalogue dies after the first lookup.
	f.producer.lookup = catalogs.NewLookupEnricher(&explodingStore{
		inner: catalogs.NewSQLLookupStore(f.owner), after: 1,
	})
	_, err := f.producer.Run(context.Background(), f.tenant)
	if err == nil {
		t.Fatal("a pass whose catalogue read failed reported success — a partial answer presented as a full statement is exactly what makes the sweep unsafe")
	}
	if !errors.Is(err, errCatalogueDown) {
		t.Errorf("the error does not name what went wrong: %v", err)
	}

	after := activeFindings(t, f)
	if len(after) != len(before) {
		t.Fatalf("the failed pass changed the ACTIVE finding count from %d to %d — a run that did not complete swept on a partial answer, "+
			"which inactivates live findings and re-raises them tomorrow with their workflow status reset", len(before), len(after))
	}
	for id, state := range after {
		if before[id] != state {
			t.Errorf("finding %s moved from %q to %q during a failed pass", id, before[id], state)
		}
	}
}

// The other half: a pass that genuinely sees nothing MUST sweep. Without this
// the test above is satisfied by a producer that never sweeps at all, which
// would leave every resolved condition ACTIVE forever.
func TestIntegration_EOLProducer_ACompletedPassWithNothingToSayDoesSweep(t *testing.T) {
	f := newEOLFixture(t)

	if _, err := f.producer.Run(context.Background(), f.tenant); err != nil {
		t.Fatalf("the first pass failed: %v", err)
	}
	if len(activeFindings(t, f)) == 0 {
		t.Fatal("the first pass raised nothing")
	}

	// An EMPTY catalogue: every lookup completes and answers "I have never
	// heard of this". The pass is complete and its statement is "I see
	// nothing", which is a sweep.
	f.producer.lookup = catalogs.NewLookupEnricher(emptyCatalogue{})
	run, err := f.producer.Run(context.Background(), f.tenant)
	if err != nil {
		t.Fatalf("a completed pass over an empty catalogue failed: %v", err)
	}
	if run.Resolved == 0 {
		t.Error("the pass reported 0 resolved; a producer that no longer sees a condition has to say so")
	}
	if n := len(activeFindings(t, f)); n != 0 {
		t.Errorf("%d findings are still ACTIVE after a completed pass that saw nothing", n)
	}
}

// emptyCatalogue answers every lookup successfully, with nothing.
type emptyCatalogue struct{}

func (emptyCatalogue) LookupEOL(context.Context, catalogs.EOLLookup) ([]catalogs.EOLRow, error) {
	return nil, nil
}
func (emptyCatalogue) LookupCPE(context.Context, string, string) (string, string, error) {
	return "", "", nil
}
func (emptyCatalogue) RecordMiss(context.Context, catalogs.MissSubject) error { return nil }

// activeFindings is this producer's ACTIVE rows for the fixture tenant, by id.
func activeFindings(t *testing.T, f *eolFixture) map[string]string {
	t.Helper()
	out := map[string]string{}
	testdb.RetryTransient(t, func() error {
		clear(out)
		rows, err := f.owner.Query(`
			SELECT id::text, detection_state FROM findings
			WHERE tenant_id = $1 AND producer = 'eol' AND detection_state = 'ACTIVE'`, f.tenant)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var id, state string
			if err := rows.Scan(&id, &state); err != nil {
				return err
			}
			out[id] = state
		}
		return rows.Err()
	})
	return out
}

// Keeps the seams import honest if the fixture stops using it.
var _ = seams.EnrichmentSubject{}
