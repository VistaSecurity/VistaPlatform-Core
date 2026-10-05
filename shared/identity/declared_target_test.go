package identity_test

import (
	"context"
	"errors"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/identity/memory"
)

func declaredAsset(t *testing.T, r *memory.Repository, ids ...identity.Identifier) identity.AssetRef {
	t.Helper()
	for i := range ids {
		ids[i].Source = identity.Source{Kind: identity.SourceDeclared, Ref: "manual"}
		ids[i].Confidence = 1
	}
	ref, err := r.CreateAsset(context.Background(), intakeTenant, identity.NewAsset{
		ClassKey: "server", DisplayName: "fixture", Status: identity.StatusMonitoring, Identifiers: ids,
	})
	if err != nil {
		t.Fatalf("create asset: %v", err)
	}
	return ref
}

func declaration(ids ...identity.Identifier) identity.Observation {
	return identity.Observation{TenantID: intakeTenant, Source: identity.Source{Kind: identity.SourceDeclared, Ref: "manual"}, Identifiers: ids}
}

func held(t *testing.T, r *memory.Repository, ref identity.AssetRef) map[string]identity.Identifier {
	t.Helper()
	sums, err := r.LoadSummaries(context.Background(), ref.TenantID, []string{ref.ID})
	if err != nil || len(sums) != 1 {
		t.Fatalf("load %s: %v (%d)", ref.ID, err, len(sums))
	}
	out := map[string]identity.Identifier{}
	for _, id := range sums[0].Identifiers {
		out[id.Key()] = id
	}
	return out
}

// TestResolveDeclaredFor pins the engine's entry point for a declaration that
// names its asset (the identifier edit, a connector's source link): it
// attaches to THAT asset whatever the precedence walk would say, it refuses —
// writing nothing — when another asset owns an identifier or a singleton
// disagrees, it refuses a measurement, and it records one history entry.
func TestResolveDeclaredFor(t *testing.T) {
	ctx := context.Background()
	mac := identity.Identifier{Kind: identity.KindMACAddress, Value: "a8:bb:cc:00:00:01"}
	addr := identity.Identifier{Kind: identity.KindIPAddress, Value: "192.0.2.5", Scope: identity.ScopeTenantDefault}

	t.Run("attaches_to_the_named_asset", func(t *testing.T) {
		r := memory.New()
		e, _ := identity.New(identity.Config{Repo: r})
		target := declaredAsset(t, r, identity.Identifier{Kind: identity.KindHostname, Value: "fixture", Scope: identity.ScopeTenantDefault})
		// An address and a MAC nobody owns: Resolve would CREATE an asset for
		// them; the declaration puts them on the asset the operator edited.
		res, err := e.ResolveDeclaredFor(ctx, declaration(mac, addr), target)
		if err != nil {
			t.Fatal(err)
		}
		if res.Outcome != identity.OutcomeMatched || res.Asset != target || res.DecidedBy != identity.KindDeclarationID {
			t.Fatalf("resolution %+v, want matched on the target, decided by declaration", res)
		}
		h := held(t, r, target)
		got, ok := h[addr.Key()]
		if !ok || h[mac.Key()].Value == "" {
			t.Fatalf("held %v, want the MAC and the address attached", h)
		}
		if got.StoredAssignment() != identity.AssignmentStatic {
			t.Errorf("declared address stored as %q, want static (owner decision 1)", got.StoredAssignment())
		}
		if n := len(r.HistoryFor(target)); n != 1 {
			t.Errorf("%d history entries, want 1 naming what was attached", n)
		}
	})

	t.Run("another_owner_is_a_conflict_and_writes_nothing", func(t *testing.T) {
		r := memory.New()
		e, _ := identity.New(identity.Config{Repo: r})
		other := declaredAsset(t, r, mac)
		target := declaredAsset(t, r, identity.Identifier{Kind: identity.KindHostname, Value: "target", Scope: identity.ScopeTenantDefault})
		_, err := e.ResolveDeclaredFor(ctx, declaration(addr, mac), target)
		var c *identity.DeclaredTargetConflict
		if !errors.As(err, &c) || !errors.Is(err, identity.ErrDeclaredTargetConflict) || c.Owner.ID != other.ID || c.Identifier.Kind != identity.KindMACAddress {
			t.Fatalf("err = %v, want a declared-target conflict naming %s's MAC", err, other.ID)
		}
		if _, attached := held(t, r, target)[addr.Key()]; attached {
			t.Error("the unowned address was attached although the declaration was refused; it must be all or nothing")
		}
	})

	t.Run("a_second_singleton_value_is_a_conflict", func(t *testing.T) {
		r := memory.New()
		e, _ := identity.New(identity.Config{Repo: r})
		target := declaredAsset(t, r, identity.Identifier{Kind: identity.KindCloudResourceID, Value: "arn:aws:s3:::one"})
		_, err := e.ResolveDeclaredFor(ctx, declaration(identity.Identifier{Kind: identity.KindCloudResourceID, Value: "arn:aws:s3:::two"}), target)
		var c *identity.DeclaredTargetConflict
		if !errors.As(err, &c) || !c.Singleton || c.Held.Value != "arn:aws:s3:::one" {
			t.Fatalf("err = %v, want a singleton conflict against the held ARN", err)
		}
	})

	t.Run("a_measurement_never_names_its_asset", func(t *testing.T) {
		r := memory.New()
		e, _ := identity.New(identity.Config{Repo: r})
		target := declaredAsset(t, r, mac)
		obs := declaration(addr)
		obs.Source = identity.Source{Kind: identity.SourceMeasured, Ref: "sensor", Mode: identity.ModePassive}
		if _, err := e.ResolveDeclaredFor(ctx, obs, target); !errors.Is(err, identity.ErrInvalidObservation) {
			t.Fatalf("err = %v, want ErrInvalidObservation", err)
		}
		other := target
		other.TenantID = "another-tenant"
		if _, err := e.ResolveDeclaredFor(ctx, declaration(addr), other); !errors.Is(err, identity.ErrInvalidObservation) {
			t.Fatalf("cross-tenant target: err = %v, want ErrInvalidObservation", err)
		}
	})
}
