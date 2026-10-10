package identity_test

import (
	"context"
	"sync"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/identity/memory"
)

// countingRepo is the real in-memory repository with its owner lookups
// counted per identifier key. It EMBEDS the concrete repository, so every
// optional interface the engine type-asserts for (reassignment, history
// checks, …) is still there: a thin fake would quietly change which engine
// branches run.
type countingRepo struct {
	*memory.Repository
	mu     sync.Mutex
	lookup map[string]int
}

func newCountingRepo() *countingRepo {
	return &countingRepo{Repository: memory.New(), lookup: map[string]int{}}
}

func (r *countingRepo) FindByIdentifier(ctx context.Context, tenantID string, kind identity.Kind, value, scope string) ([]identity.AssetRef, error) {
	r.mu.Lock()
	r.lookup[string(kind)+"|"+value+"|"+scope]++
	r.mu.Unlock()
	return r.Repository.FindByIdentifier(ctx, tenantID, kind, value, scope)
}

func (r *countingRepo) reset() {
	r.mu.Lock()
	r.lookup = map[string]int{}
	r.mu.Unlock()
}

func (r *countingRepo) counts() map[string]int {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make(map[string]int, len(r.lookup))
	for k, v := range r.lookup {
		out[k] = v
	}
	return out
}

func snapshotObservation() identity.Observation {
	return obs("server",
		id(identity.KindSerialNumber, "SN-SNAP-1"),
		identity.Identifier{Kind: identity.KindHostname, Value: "snap-host.example.test", Scope: identity.ScopeTenantDefault, Confidence: 1},
		identity.Identifier{Kind: identity.KindIPAddress, Value: "198.51.100.40", Scope: identity.ScopeTenantDefault, Confidence: 1},
	)
}

// F5: an intake that read the owners once (SnapshotOwners) and handed
// them to the engine (WithOwnerSnapshot) must not have them read again. Both
// polarities run here: without the snapshot every identifier is read twice,
// which is what proves the counter can see a second read at all.
func TestOwnerSnapshot_ResolveDoesNotReadTheOwnersAgain(t *testing.T) {
	ctx := context.Background()
	repo := newCountingRepo()
	e, err := identity.New(identity.Config{Repo: repo})
	if err != nil {
		t.Fatalf("identity.New: %v", err)
	}
	seeded := mustResolve(t, e, snapshotObservation())
	if seeded.Outcome != identity.OutcomeCreated {
		t.Fatalf("seeding: outcome = %s, want created", seeded.Outcome)
	}

	for _, tc := range []struct {
		name         string
		withSnapshot bool
		want         int
	}{
		{"snapshot handed to the engine", true, 1},
		{"snapshot taken but not handed over", false, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo.reset()
			o := snapshotObservation()
			snap, err := e.SnapshotOwners(ctx, o)
			if err != nil {
				t.Fatalf("SnapshotOwners: %v", err)
			}
			var owned int
			for _, io := range snap.Owners() {
				if len(io.Owners) == 1 && io.Owners[0].ID == seeded.Asset.ID {
					owned++
				}
			}
			if owned != len(o.Identifiers) {
				t.Fatalf("the snapshot names the seeded asset for %d of %d identifiers: %+v", owned, len(o.Identifiers), snap.Owners())
			}
			eng := e
			if tc.withSnapshot {
				eng = e.WithOwnerSnapshot(snap)
			}
			res, err := eng.Resolve(ctx, o)
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if res.Outcome != identity.OutcomeMatched || res.Asset.ID != seeded.Asset.ID {
				t.Fatalf("outcome = %s on %s, want matched on %s", res.Outcome, res.Asset.ID, seeded.Asset.ID)
			}
			got := repo.counts()
			if len(got) != len(o.Identifiers) {
				t.Fatalf("looked up %d identifier keys, want %d: %v", len(got), len(o.Identifiers), got)
			}
			for key, n := range got {
				if n != tc.want {
					t.Errorf("%s was looked up %d times, want %d", key, n, tc.want)
				}
			}
		})
	}
}

// A snapshot answers only for the tenant it was taken in; the engine reads
// any other tenant's owners itself.
func TestOwnerSnapshot_OtherTenantIsReadAfresh(t *testing.T) {
	ctx := context.Background()
	repo := newCountingRepo()
	e, err := identity.New(identity.Config{Repo: repo})
	if err != nil {
		t.Fatalf("identity.New: %v", err)
	}
	snap, err := e.SnapshotOwners(ctx, snapshotObservation())
	if err != nil {
		t.Fatalf("SnapshotOwners: %v", err)
	}
	repo.reset()
	other := snapshotObservation()
	other.TenantID = "tenant-b"
	res, err := e.WithOwnerSnapshot(snap).Resolve(ctx, other)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.Outcome != identity.OutcomeCreated {
		t.Fatalf("outcome = %s, want created", res.Outcome)
	}
	for key, n := range repo.counts() {
		if n != 1 {
			t.Errorf("%s was looked up %d times in the other tenant, want 1", key, n)
		}
	}
	if len(repo.counts()) != len(other.Identifiers) {
		t.Errorf("the other tenant's owners were not read: %v", repo.counts())
	}
}
