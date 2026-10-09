package identitytest

import (
	"context"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// RunLeaseFreshAddressContract holds a store to the lease-fresh address rule
// (shared/identity/leasefresh.go, ADR-0002 D3 erratum): the engine reads the
// owner's `device_confirmed_at` back through LoadSummaries, and the identifier
// upsert decides what that value is. Both stores must agree, or the rule works
// in the memory tests and not in production.
//
// Three things are pinned here:
//
//   - the round trip: a confirmation written at CreateAsset or AttachIdentifiers
//     comes back on the owner's summary, as UTC;
//   - the upsert never moves it backwards, and a re-sighting that confirmed
//     nothing (zero) does not erase it;
//   - through the engine, a direct probe of the address matches its owner
//     within the window and is held outside it.
func RunLeaseFreshAddressContract(t *testing.T, newRepo func() identity.Repository) {
	t.Helper()

	const (
		tenant  = "tenant-a"
		dynamic = "seg-dhcp"
	)
	ctx := context.Background()
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)

	mac := identity.Identifier{
		Kind: identity.KindMACAddress, Value: "00:00:5e:00:53:10", Confidence: 1,
		Source: identity.Source{Kind: identity.SourceMeasured, Ref: "contract"}, SeenAt: now,
	}
	addr := func(confirmedAt time.Time) identity.Identifier {
		return identity.Identifier{
			Kind: identity.KindIPAddress, Value: "192.0.2.10", Scope: dynamic, Confidence: 1,
			Source: identity.Source{Kind: identity.SourceMeasured, Ref: "contract"}, SeenAt: now,
			DeviceConfirmedAt: confirmedAt,
		}
	}
	holder := func(r identity.Repository, ids ...identity.Identifier) identity.AssetRef {
		t.Helper()
		ref, err := r.CreateAsset(ctx, tenant, identity.NewAsset{
			ClassKey: "server", ClassSourceKind: identity.ClassSourceMeasured, DisplayName: "host",
			Status: identity.StatusMonitoring, Source: identity.Source{Kind: identity.SourceMeasured, Ref: "contract"},
			Identifiers: ids, FirstSeenAt: now, LastSeenAt: now,
		})
		if err != nil {
			t.Fatalf("CreateAsset: %v", err)
		}
		return ref
	}
	confirmedAt := func(r identity.Repository, ref identity.AssetRef) time.Time {
		t.Helper()
		sums, err := r.LoadSummaries(ctx, tenant, []string{ref.ID})
		if err != nil || len(sums) != 1 {
			t.Fatalf("LoadSummaries: %v (%d summaries)", err, len(sums))
		}
		for _, held := range sums[0].Identifiers {
			if held.Kind == identity.KindIPAddress {
				return held.DeviceConfirmedAt
			}
		}
		t.Fatalf("the summary carries no address")
		return time.Time{}
	}
	// A direct probe of the address: measured, direct, an endpoint answered.
	probe := func(at time.Time) identity.Observation {
		o := identity.Observation{
			TenantID: tenant, ClassHint: "server",
			Source:     identity.Source{Kind: identity.SourceMeasured, Ref: "sensor:probe", Mode: identity.ModeActive},
			ObservedAt: at, Confidence: 1,
			Identifiers:   []identity.Identifier{{Kind: identity.KindIPAddress, Value: "192.0.2.10", Scope: dynamic, Confidence: 1}},
			Endpoints:     []identity.EndpointObservation{{Address: "192.0.2.10", Port: 22, Transport: "tcp", Protocol: "SSH"}},
			Admission:     identity.AdmissionEvidence{Direct: true},
			DynamicScopes: map[string]bool{dynamic: true},
		}
		o.Network.SegmentID = dynamic
		return o
	}
	engineOver := func(r identity.Repository) *identity.Engine {
		eng, err := identity.New(identity.Config{Repo: r})
		if err != nil {
			t.Fatalf("identity.New: %v", err)
		}
		return eng
	}

	t.Run("a confirmation round-trips through CreateAsset and LoadSummaries", func(t *testing.T) {
		r := newRepo()
		ref := holder(r, mac, addr(now.Add(-time.Hour)))
		if got := confirmedAt(r, ref); !got.Equal(now.Add(-time.Hour)) {
			t.Fatalf("device_confirmed_at = %v, want %v", got, now.Add(-time.Hour))
		}
	})

	t.Run("the upsert keeps the newest confirmation and never erases one", func(t *testing.T) {
		r := newRepo()
		ref := holder(r, mac, addr(now.Add(-time.Hour)))

		older := addr(now.Add(-2 * time.Hour))
		if _, err := r.AttachIdentifiers(ctx, ref, []identity.Identifier{older}); err != nil {
			t.Fatalf("AttachIdentifiers(older): %v", err)
		}
		if got := confirmedAt(r, ref); !got.Equal(now.Add(-time.Hour)) {
			t.Fatalf("an older confirmation moved it to %v; want %v kept", got, now.Add(-time.Hour))
		}

		unconfirmed := addr(time.Time{})
		if _, err := r.AttachIdentifiers(ctx, ref, []identity.Identifier{unconfirmed}); err != nil {
			t.Fatalf("AttachIdentifiers(unconfirmed): %v", err)
		}
		if got := confirmedAt(r, ref); !got.Equal(now.Add(-time.Hour)) {
			t.Fatalf("a sighting that confirmed nothing erased it: %v; want %v kept", got, now.Add(-time.Hour))
		}

		newer := addr(now)
		if _, err := r.AttachIdentifiers(ctx, ref, []identity.Identifier{newer}); err != nil {
			t.Fatalf("AttachIdentifiers(newer): %v", err)
		}
		if got := confirmedAt(r, ref); !got.Equal(now) {
			t.Fatalf("a newer confirmation did not advance it: %v; want %v", got, now)
		}
	})

	t.Run("a probe within the window matches the owner; outside it is held", func(t *testing.T) {
		r := newRepo()
		ref := holder(r, mac, addr(now))
		eng := engineOver(r)

		res, err := eng.Resolve(ctx, probe(now.Add(time.Hour)))
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if res.Outcome != identity.OutcomeMatched || res.Asset.ID != ref.ID || res.DecidedBy != identity.KindIPAddress {
			t.Fatalf("within the window: %s on %q by %s, want matched on the host by ip_address", res.Outcome, res.Asset.ID, res.DecidedBy)
		}

		res, err = eng.Resolve(ctx, probe(now.Add(identity.DefaultLeaseWindow+time.Hour)))
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if res.Outcome == identity.OutcomeMatched {
			t.Fatalf("outside the window the probe still matched: %+v", res)
		}
	})

	t.Run("an address nothing confirmed a device at still does not decide", func(t *testing.T) {
		r := newRepo()
		holder(r, mac, addr(time.Time{}))
		res, err := engineOver(r).Resolve(ctx, probe(now.Add(time.Hour)))
		if err != nil {
			t.Fatalf("Resolve: %v", err)
		}
		if res.Outcome == identity.OutcomeMatched {
			t.Fatalf("an unconfirmed address decided a match inside a dynamic scope: %+v", res)
		}
	})
}
