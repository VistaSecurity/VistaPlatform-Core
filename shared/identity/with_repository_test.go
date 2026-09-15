package identity_test

import (
	"context"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/identity/memory"
)

// WithRepository is the transaction seam Repository does not have: a SQL
// implementation hands the engine a per-transaction Repository for the duration
// of one observation (shared/identity/postgres's RunInTx). These tests pin the
// three properties that makes it safe to use that way.

func TestWithRepositoryStoresThroughTheSuppliedRepository(t *testing.T) {
	e, original := newEngine(t, identity.Config{})
	swapped := memory.New()

	res, err := e.WithRepository(swapped).Resolve(context.Background(),
		obs("server", id(identity.KindSerialNumber, "SN-SWAP")))
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if res.Outcome != identity.OutcomeCreated {
		t.Fatalf("outcome = %s, want created", res.Outcome)
	}

	// The asset must be in the repository that was passed in, and ONLY there.
	got, err := swapped.FindByIdentifier(context.Background(), tenant, identity.KindSerialNumber, "SN-SWAP", "")
	if err != nil || len(got) != 1 {
		t.Fatalf("swapped repo: FindByIdentifier = %+v (err %v), want one owner", got, err)
	}
	stale, err := original.FindByIdentifier(context.Background(), tenant, identity.KindSerialNumber, "SN-SWAP", "")
	if err != nil {
		t.Fatalf("original repo: %v", err)
	}
	if len(stale) != 0 {
		t.Errorf("the engine wrote to its ORIGINAL repository as well: %+v — a per-transaction "+
			"repository that is only half used is worse than none, since the writes it did not "+
			"receive cannot be rolled back with it", stale)
	}
}

func TestWithRepositoryDoesNotMutateTheEngine(t *testing.T) {
	// An engine is shared across goroutines (one per service, one observation
	// per request). If WithRepository mutated the receiver, two concurrent
	// observations would write through each other's transaction.
	e, original := newEngine(t, identity.Config{})
	_ = e.WithRepository(memory.New())

	if _, err := e.Resolve(context.Background(), obs("server", id(identity.KindSerialNumber, "SN-ORIG"))); err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	got, err := original.FindByIdentifier(context.Background(), tenant, identity.KindSerialNumber, "SN-ORIG", "")
	if err != nil || len(got) != 1 {
		t.Fatalf("the original engine no longer writes to its own repository: %+v (err %v)", got, err)
	}
}

func TestWithRepositoryKeepsEverySetting(t *testing.T) {
	// The copy must carry the dynamic-scope rule. A copy that dropped it would
	// match on a DHCP address — today's lease is tomorrow's other host — and
	// the failure would appear only in the SQL path, which is the one path the
	// unit tests do not cover.
	const segment = "seg-dhcp"
	e, _ := newEngine(t, identity.Config{DynamicScopes: map[string]bool{segment: true}})
	repo := memory.New()
	bound := e.WithRepository(repo)

	first := mustResolve(t, bound, obs("server", scoped(identity.KindIPAddress, "10.0.0.5", segment)))
	if first.Outcome != identity.OutcomeCreated {
		t.Fatalf("first outcome = %s, want created", first.Outcome)
	}
	second := mustResolve(t, bound, obs("server", scoped(identity.KindIPAddress, "10.0.0.5", segment)))
	// Conflict, not matched: the address may not decide inside a dynamic scope,
	// and it already belongs to the first asset, so there is nothing left to
	// attach and nothing is created (the floor). A copy that had LOST
	// DynamicScopes would report `matched` here.
	if second.Outcome != identity.OutcomeConflict {
		t.Fatalf("second outcome = %s, want conflict: an ip_address inside a DYNAMIC scope must not "+
			"decide a match, so the copy lost Config.DynamicScopes", second.Outcome)
	}
	if !second.Asset.Zero() {
		t.Errorf("resolution names asset %s; the only identifier is owned by %s, so nothing may be created",
			second.Asset.ID, first.Asset.ID)
	}
	if second.Proposal.ID == "" {
		t.Error("no merge proposal: a human has to say whether this is the same host on the same lease")
	}
}

func TestWithRepositoryIgnoresANilRepository(t *testing.T) {
	e, original := newEngine(t, identity.Config{})
	if e.WithRepository(nil) != e {
		t.Fatal("WithRepository(nil) returned a different engine; a nil repository would panic " +
			"several calls deep with nothing naming the caller that supplied it")
	}
	if _, err := e.Resolve(context.Background(), obs("server", id(identity.KindSerialNumber, "SN-NIL"))); err != nil {
		t.Fatalf("Resolve after WithRepository(nil): %v", err)
	}
	got, _ := original.FindByIdentifier(context.Background(), tenant, identity.KindSerialNumber, "SN-NIL", "")
	if len(got) != 1 {
		t.Errorf("the engine stopped writing to its own repository after WithRepository(nil): %+v", got)
	}
}
