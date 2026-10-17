package identitytest

import (
	"context"
	"net/netip"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// PrefixPostureWriter registers a LEARNED prefix (one a collector reported,
// with no posture stated) and states a DHCP posture for a prefix the way a
// collector does: written only where nobody has said yet
// (`prefixes.dhcp_managed IS NULL`), reporting whether it was. The SQL implementation must route it through the real writer
// (shared/identity/postgres RecordPrefixPosture). OPTIONAL, on the same terms
// as [SegmentWriter].
type PrefixPostureWriter interface {
	AddLearnedPrefix(tenantID, cidr, scope string) error
	RecordPrefixPosture(tenantID, scope string, dynamic bool) (bool, error)
}

// RunIntakeContract holds a repository to what [identity.Intake] needs of it:
// a [identity.Repository.SegmentSnapshot] that agrees with
// [identity.Repository.ScopeForAddress], and segment posture that reads as the
// STORED effective value. It drives a real Intake over the repository, so a
// store whose snapshot drifted from its per-address lookup fails here rather
// than in an adapter's shadow log.
//
// newRepo must return a FRESH, empty repository on every call.
func RunIntakeContract(t *testing.T, newRepo func() identity.Repository) {
	t.Helper()
	const tenant = "tenant-intake"
	ctx := context.Background()

	sighting := func(ids ...identity.SightedIdentifier) identity.Sighting {
		return identity.Sighting{
			TenantID:    tenant,
			Source:      identity.Source{Kind: identity.SourceMeasured, Ref: "sensor", Mode: identity.ModePassive},
			Channel:     identity.ChannelL2Frame,
			Identifiers: ids,
		}
	}
	ip := func(v string) identity.SightedIdentifier {
		return identity.SightedIdentifier{Kind: identity.KindIPAddress, Value: v}
	}
	build := func(t *testing.T, r identity.Repository, s identity.Sighting) identity.Observation {
		t.Helper()
		in, err := identity.NewIntake(r, identity.WithIntakeGenericNames(nil))
		if err != nil {
			t.Fatalf("NewIntake: %v", err)
		}
		obs, err := in.Build(ctx, s)
		if err != nil {
			t.Fatalf("Build: %v", err)
		}
		return obs
	}
	scopeOf := func(obs identity.Observation, kind identity.Kind, value string) string {
		for _, id := range obs.Identifiers {
			if id.Kind == kind && id.Value == value {
				return id.Scope
			}
		}
		return "<absent>"
	}

	t.Run("SegmentSnapshot of a tenant with no segments is empty, not an error", func(t *testing.T) {
		r := newRepo()
		snap, err := r.SegmentSnapshot(ctx, tenant)
		if err != nil {
			t.Fatalf("SegmentSnapshot: %v", err)
		}
		if len(snap.Prefixes) != 0 {
			t.Errorf("snapshot has %d prefixes for a tenant with none", len(snap.Prefixes))
		}
		obs := build(t, r, sighting(ip("192.0.2.10")))
		if got := scopeOf(obs, identity.KindIPAddress, "192.0.2.10"); got != identity.ScopeTenantDefault {
			t.Errorf("scope = %q, want the tenant default", got)
		}
	})

	t.Run("SegmentSnapshot answers exactly what ScopeForAddress answers", func(t *testing.T) {
		r := newRepo()
		seg, ok := r.(SegmentWriter)
		if !ok {
			t.Skipf("%T cannot register segments", r)
		}
		for _, s := range []struct {
			cidr, scope string
			dynamic     bool
		}{
			{"192.0.2.0/24", "seg-wide", false},
			{"192.0.2.0/28", "seg-narrow", true},
			{"2001:db8:5::/64", "seg-v6", false},
		} {
			if err := seg.AddSegment(tenant, s.cidr, s.scope, s.dynamic); err != nil {
				t.Fatalf("AddSegment(%s): %v", s.cidr, err)
			}
		}
		snap, err := r.SegmentSnapshot(ctx, tenant)
		if err != nil {
			t.Fatalf("SegmentSnapshot: %v", err)
		}
		for _, a := range []string{"192.0.2.5", "192.0.2.200", "198.51.100.1", "2001:db8:5::10", "2001:db8:6::1"} {
			addr := netip.MustParseAddr(a)
			wantScope, wantDyn, err := r.ScopeForAddress(ctx, tenant, addr, "")
			if err != nil {
				t.Fatalf("ScopeForAddress(%s): %v", a, err)
			}
			gotScope, gotDyn := snap.ScopeForAddress(addr, "")
			if gotScope != wantScope || gotDyn != wantDyn {
				t.Errorf("%s: snapshot says (%q, %t), ScopeForAddress says (%q, %t) — two answers to one question",
					a, gotScope, gotDyn, wantScope, wantDyn)
			}
		}
	})

	t.Run("Intake scopes every address on its own and marks only the dynamic one", func(t *testing.T) {
		r := newRepo()
		seg, ok := r.(SegmentWriter)
		if !ok {
			t.Skipf("%T cannot register segments", r)
		}
		if err := seg.AddSegment(tenant, "203.0.113.0/24", "seg-wan", false); err != nil {
			t.Fatalf("AddSegment: %v", err)
		}
		if err := seg.AddSegment(tenant, "198.51.100.0/24", "seg-lan", true); err != nil {
			t.Fatalf("AddSegment: %v", err)
		}
		// A router: WAN, LAN, and an address no segment covers. One scope for
		// all three is item 5.
		obs := build(t, r, sighting(ip("203.0.113.2"), ip("198.51.100.1"), ip("192.0.2.77")))
		for value, want := range map[string]string{
			"203.0.113.2": "seg-wan", "198.51.100.1": "seg-lan", "192.0.2.77": identity.ScopeTenantDefault,
		} {
			if got := scopeOf(obs, identity.KindIPAddress, value); got != want {
				t.Errorf("%s scoped %q, want %q", value, got, want)
			}
		}
		if obs.Network.SegmentID != "seg-wan" {
			t.Errorf("Network.SegmentID = %q, want seg-wan (the first address that resolved)", obs.Network.SegmentID)
		}
		if !obs.DynamicScopes["seg-lan"] || obs.DynamicScopes["seg-wan"] || len(obs.DynamicScopes) != 1 {
			t.Errorf("DynamicScopes = %v, want exactly {seg-lan}", obs.DynamicScopes)
		}
	})

	t.Run("Intake scopes a name with no prefixed address to the tenant default", func(t *testing.T) {
		r := newRepo()
		// The domain rule retired with the segments (DCIM row 1.6): a prefix
		// places addresses, not names. A short name whose address is in no
		// prefix lands in the tenant default; an fqdn carries no scope.
		obs := build(t, r, sighting(
			ip("192.0.2.40"),
			identity.SightedIdentifier{Kind: identity.KindHostname, Value: "db01.corp.example", Address: "192.0.2.40"},
			identity.SightedIdentifier{Kind: identity.KindHostname, Value: "build-7", Address: "192.0.2.40"},
		))
		if got := scopeOf(obs, identity.KindFQDN, "db01.corp.example"); got != "" {
			t.Errorf("fqdn scoped %q, want unscoped", got)
		}
		if got := scopeOf(obs, identity.KindHostname, "build-7"); got != identity.ScopeTenantDefault {
			t.Errorf("short name scoped %q, want the tenant default", got)
		}
	})

	// The dynamic-scope rule. Intake reads the posture STORED on the prefix
	// and nothing a collector says on the run; a collector's statement is
	// written only where nobody has said (DCIM row 1.6, the rule 1.5a's
	// observed-network writer applies). Mutation check: drop the
	// `dhcp_managed IS NULL` guard from RecordPrefixPosture (or the `said`
	// check in the memory store) and the second statement overrides the first.
	t.Run("Intake reads the stored posture; the first statement stands", func(t *testing.T) {
		r := newRepo()
		seg, ok := r.(SegmentWriter)
		if !ok {
			t.Skipf("%T cannot register prefixes", r)
		}
		pw, ok := r.(PrefixPostureWriter)
		if !ok {
			t.Skipf("%T cannot record prefix posture", r)
		}
		if err := seg.AddSegment(tenant, "192.0.2.0/24", "seg-declared", false); err != nil {
			t.Fatalf("AddSegment: %v", err)
		}
		if err := pw.AddLearnedPrefix(tenant, "198.51.100.0/24", "seg-learned"); err != nil {
			t.Fatalf("AddLearnedPrefix: %v", err)
		}
		probe := func(addr string) (string, bool) {
			t.Helper()
			obs := build(t, r, sighting(ip(addr)))
			scope := scopeOf(obs, identity.KindIPAddress, addr)
			if scope == identity.ScopeTenantDefault || scope == "<absent>" {
				t.Fatalf("%s scoped %q, want a prefix", addr, scope)
			}
			return scope, obs.DynamicScopes[scope]
		}

		// A declared prefix nobody stated a posture for reads static — and a
		// collector's measurement is written there, since nobody has said
		// ( C2).
		declared, dyn := probe("192.0.2.20")
		if dyn {
			t.Fatal("a declared prefix with no posture reads dynamic")
		}
		if wrote, err := pw.RecordPrefixPosture(tenant, declared, true); err != nil || !wrote {
			t.Fatalf("RecordPrefixPosture on a silent declared prefix = (%t, %v), want written", wrote, err)
		}
		if _, dyn := probe("192.0.2.20"); !dyn {
			t.Fatal("a measured dynamic posture on a silent declared prefix reads static")
		}

		// A learned prefix nobody stated a posture for reads dynamic; the first
		// collector statement is written and the next one is not.
		learned, dyn := probe("198.51.100.20")
		if !dyn {
			t.Fatal("a learned prefix with no posture reads static")
		}
		if wrote, err := pw.RecordPrefixPosture(tenant, learned, false); err != nil || !wrote {
			t.Fatalf("RecordPrefixPosture(false) = (%t, %v), want written", wrote, err)
		}
		if _, dyn := probe("198.51.100.20"); dyn {
			t.Fatal("a stated static posture reads dynamic")
		}
		if wrote, err := pw.RecordPrefixPosture(tenant, learned, true); err != nil || wrote {
			t.Fatalf("second RecordPrefixPosture = (%t, %v), want not written", wrote, err)
		}
		if _, dyn := probe("198.51.100.20"); dyn {
			t.Fatal("a later collector statement overrode the stored posture")
		}
	})
}
