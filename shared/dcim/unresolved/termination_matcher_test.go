package unresolved_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/dcim/dcimtest"
	"github.com/vistasecurity/vistaplatform/shared/dcim/unresolved"
)

// wholeMatcher resolves a row only when its chassis id AND port id name a
// known far interface — the row-3.3 shape a per-key matcher cannot express.
type wholeMatcher struct {
	unresolved.NullMatcher
	known map[[2]string]uuid.UUID
	seen  []unresolved.Parked
}

func (m *wholeMatcher) MatchTermination(_ context.Context, _ uuid.UUID, p unresolved.Parked) (unresolved.Match, bool, error) {
	m.seen = append(m.seen, p)
	id, ok := m.known[[2]string{p.FarIdentity[unresolved.KeyChassisID], p.FarIdentity[unresolved.KeyPortID]}]
	if !ok {
		return unresolved.Match{}, false, nil
	}
	return unresolved.Match{Kind: dcim.ObjectKindInterface, ID: id}, true, nil
}

func TestResolver_AsksATerminationMatcherForTheWholeIdentity(t *testing.T) {
	ctx := context.Background()
	tenant := uuid.New()
	t0 := time.Date(2026, 10, 16, 9, 0, 0, 0, time.UTC)
	repo := unresolved.NewMemoryRepository()
	park := func(port string) {
		t.Helper()
		if _, err := repo.Park(ctx, tenant, unresolved.Termination{
			Producer: "lldp", OriginKind: dcim.ObjectKindInterface, OriginID: uuid.New(),
			FarIdentity: map[string]string{unresolved.KeyChassisID: "aa:bb:cc:00:00:01", unresolved.KeyPortID: port},
			Intent:      unresolved.IntentCable,
		}, t0); err != nil {
			t.Fatal(err)
		}
	}
	park("Gi1/0/1")
	park("Gi1/0/2") // the device is known, this port is not yet

	far := uuid.New()
	m := &wholeMatcher{known: map[[2]string]uuid.UUID{{"aa:bb:cc:00:00:01", "Gi1/0/1"}: far}}
	ap := &dcimtest.RecordingApplier{}
	n, err := unresolved.NewResolver(repo, m, ap, func() time.Time { return t0 }).Resolve(ctx, tenant)
	if err != nil {
		t.Fatal(err)
	}
	if n.Resolved != 1 || n.Unmatched != 1 {
		t.Fatalf("resolved %d unmatched %d, want 1 and 1", n.Resolved, n.Unmatched)
	}
	if len(m.seen) != 2 {
		t.Fatalf("the termination matcher saw %d rows, want both", len(m.seen))
	}
	if len(ap.Calls) != 1 || ap.Calls[0].Method != "cable" || ap.Calls[0].Far.ID != far {
		t.Fatalf("applied %+v, want one cable onto the far interface", ap.Calls)
	}
	left, err := repo.List(ctx, tenant, uuid.Nil, 10)
	if err != nil || len(left) != 1 || left[0].FarIdentity[unresolved.KeyPortID] != "Gi1/0/2" {
		t.Fatalf("still parked = %+v (%v), want only the unknown port", left, err)
	}
}
