package memory_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/identity/identitytest"
	"github.com/vistasecurity/vistaplatform/shared/identity/memory"
)

// TestRepositoryContract is the whole point of identitytest: the Postgres
// implementation of workstream 1.2 runs this same function, so the two stores
// cannot drift apart unnoticed.
func TestRepositoryContract(t *testing.T) {
	identitytest.RunRepositoryContract(t, func() identity.Repository { return memory.New() })
}

// TestSingletonGuardContract is the same arrangement for the engine rule that
// an asset holds at most one agent_id / cloud_resource_id / serial_number /
// cmdb_sys_id. The Postgres store runs it too.
func TestSingletonGuardContract(t *testing.T) {
	identitytest.RunSingletonGuardContract(t, func() identity.Repository { return memory.New() })
}

// TestUnknownHostSerialContract is the same arrangement for ADR-0002 D3's
// erratum — `unknown_host` identifies by serial_number — including
// the half that must NOT have loosened: a differing serial is still contested.
func TestUnknownHostSerialContract(t *testing.T) {
	identitytest.RunUnknownHostSerialContract(t, func() identity.Repository { return memory.New() })
}

func TestEndpointUpsertDoesNotDuplicate(t *testing.T) {
	ctx := context.Background()
	r := memory.New()
	ref, err := r.CreateAsset(ctx, "t", identity.NewAsset{DisplayName: "host", Status: identity.StatusPendingApproval})
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}
	ep := identity.EndpointObservation{Address: "192.0.2.1", Port: 443, Transport: "tcp"}
	for range 3 {
		if err := r.UpsertEndpoints(ctx, ref, []identity.EndpointObservation{ep}); err != nil {
			t.Fatalf("UpsertEndpoints: %v", err)
		}
	}
	if got := r.Endpoints(ref); len(got) != 1 {
		t.Fatalf("%d endpoints after three identical upserts, want 1: %+v", len(got), got)
	}

	// A different port is a different endpoint.
	other := ep
	other.Port = 22
	if err := r.UpsertEndpoints(ctx, ref, []identity.EndpointObservation{other}); err != nil {
		t.Fatalf("UpsertEndpoints: %v", err)
	}
	if got := r.Endpoints(ref); len(got) != 2 {
		t.Fatalf("%d endpoints, want 2", len(got))
	}
}

func TestUpsertEndpointsRejectsAnAddresslessEndpoint(t *testing.T) {
	ctx := context.Background()
	r := memory.New()
	ref, err := r.CreateAsset(ctx, "t", identity.NewAsset{DisplayName: "host"})
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}
	if err := r.UpsertEndpoints(ctx, ref, []identity.EndpointObservation{{Port: 443, Transport: "tcp"}}); err == nil {
		t.Fatal("an endpoint with neither address nor fqdn was accepted")
	}
}

func TestTouchDoesNotMoveLastSeenBackwards(t *testing.T) {
	ctx := context.Background()
	r := memory.New()
	now := time.Date(2026, 9, 11, 0, 0, 0, 0, time.UTC)
	ref, err := r.CreateAsset(ctx, "t", identity.NewAsset{DisplayName: "host", LastSeenAt: now})
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}
	if err := r.Touch(ctx, ref, now.Add(-time.Hour)); err != nil {
		t.Fatalf("Touch: %v", err)
	}
	if got := r.LastSeen(ref); !got.Equal(now) {
		t.Fatalf("last seen = %v after an older sighting, want it unchanged at %v", got, now)
	}
	if err := r.Touch(ctx, ref, now.Add(time.Hour)); err != nil {
		t.Fatalf("Touch: %v", err)
	}
	if got := r.LastSeen(ref); !got.Equal(now.Add(time.Hour)) {
		t.Fatalf("last seen = %v after a newer sighting, want it advanced", got)
	}
}

// TestCorruptIsTheOnlyWayToBreakTheInvariant pins the escape hatch: the normal
// API cannot produce a two-owner identifier, and Corrupt can. Without it,
// FindByIdentifier's slice return would be a shape no test could reach — a
// check that cannot fail.
func TestCorruptIsTheOnlyWayToBreakTheInvariant(t *testing.T) {
	ctx := context.Background()
	r := memory.New()
	id := identity.Identifier{Kind: identity.KindSerialNumber, Value: "SN-1", Confidence: 1}
	a, err := r.CreateAsset(ctx, "t", identity.NewAsset{DisplayName: "a", Identifiers: []identity.Identifier{id}})
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}
	b, err := r.CreateAsset(ctx, "t", identity.NewAsset{DisplayName: "b"})
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}
	got, err := r.FindByIdentifier(ctx, "t", id.Kind, id.Value, "")
	if err != nil {
		t.Fatalf("FindByIdentifier: %v", err)
	}
	if len(got) != 1 || got[0].ID != a.ID {
		t.Fatalf("before corruption: %+v, want [%s]", got, a.ID)
	}

	r.Corrupt("t", id, b)
	got, err = r.FindByIdentifier(ctx, "t", id.Kind, id.Value, "")
	if err != nil {
		t.Fatalf("FindByIdentifier: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("after corruption: %+v, want two owners so the engine can detect the lost invariant", got)
	}
}

func TestConcurrentUseIsSafe(t *testing.T) {
	// Run with -race: the engine documents that it is concurrency-safe if the
	// repository is, so the repository has to actually be.
	ctx := context.Background()
	r := memory.New()
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ref, err := r.CreateAsset(ctx, "t", identity.NewAsset{
				DisplayName: "host",
				Identifiers: []identity.Identifier{{Kind: identity.KindSerialNumber, Value: string(rune('A' + i))}},
			})
			if err != nil {
				t.Errorf("CreateAsset: %v", err)
				return
			}
			if err := r.Touch(ctx, ref, time.Now()); err != nil {
				t.Errorf("Touch: %v", err)
			}
			if err := r.RecordHistory(ctx, identity.HistoryEntry{TenantID: "t", AssetID: ref.ID, Action: identity.ActionCreated}); err != nil {
				t.Errorf("RecordHistory: %v", err)
			}
			_ = r.History()
		}(i)
	}
	wg.Wait()
	if r.AssetCount() != 16 {
		t.Fatalf("%d assets, want 16", r.AssetCount())
	}
}

func TestIDFuncOverride(t *testing.T) {
	ctx := context.Background()
	r := memory.New()
	r.IDFunc = func(prefix string, n int) string { return prefix + "/" + string(rune('a'+n-1)) }
	ref, err := r.CreateAsset(ctx, "t", identity.NewAsset{DisplayName: "host"})
	if err != nil {
		t.Fatalf("CreateAsset: %v", err)
	}
	if ref.ID != "asset/a" {
		t.Fatalf("id = %q, want the injected generator's", ref.ID)
	}
}
