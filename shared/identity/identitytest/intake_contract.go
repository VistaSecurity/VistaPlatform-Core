package identitytest

import (
	"context"
	"net/netip"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/identity"
)

type (
	// DomainSegmentWriter registers a `domain` segment — a name pattern —
	// so the intake's domain rule has something to match. OPTIONAL, on the
	// same terms as [SegmentWriter].
	DomainSegmentWriter interface {
		AddDomainSegment(tenantID, pattern, scope string) error
	}

	// SegmentPostureWriter states one source's DHCP posture for a segment
	// registered through [SegmentWriter], the way the product does:
	// `source` is "operator", "measured" or "inferred", and a nil `dynamic`
	// withdraws that source's statement. The SQL implementation must route it
	// through the real posture writer (shared/identity/postgres
	// RecordSegmentPosture / ClearSegmentPosture), so the contract exercises
	// the precedence rule that is actually deployed. OPTIONAL, on the same
	// terms as [SegmentWriter].
	SegmentPostureWriter interface {
		StateSegmentPosture(tenantID, scope, source string, dynamic *bool) error
	}
)

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
		if len(snap.Segments) != 0 {
			t.Errorf("snapshot has %d segments for a tenant with none", len(snap.Segments))
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

	t.Run("Intake scopes a name no address placed by the domain rule", func(t *testing.T) {
		r := newRepo()
		dom, ok := r.(DomainSegmentWriter)
		if !ok {
			t.Skipf("%T cannot register domain segments", r)
		}
		if err := dom.AddDomainSegment(tenant, "corp.example", "seg-corp"); err != nil {
			t.Fatalf("AddDomainSegment: %v", err)
		}
		// The name has an address of its own, and that address is in no
		// segment: before Intake the name took the address's tenant-default
		// scope and never reached its domain segment ( item 8).
		obs := build(t, r, sighting(
			ip("192.0.2.40"),
			identity.SightedIdentifier{Kind: identity.KindHostname, Value: "db01.corp.example", Address: "192.0.2.40"},
			identity.SightedIdentifier{Kind: identity.KindHostname, Value: "build-7", Address: "192.0.2.40"},
		))
		// A dotted name is an fqdn and carries no scope at all; the domain
		// rule scopes a name that is NOT globally unique. So the case the
		// rule matters for is a short name — which a domain pattern cannot
		// match — or a `.local` one. Assert both halves of that.
		if got := scopeOf(obs, identity.KindFQDN, "db01.corp.example"); got != "" {
			t.Errorf("fqdn scoped %q, want unscoped", got)
		}
		if got := scopeOf(obs, identity.KindHostname, "build-7"); got != identity.ScopeTenantDefault {
			t.Errorf("short name scoped %q, want the tenant default", got)
		}
		if err := dom.AddDomainSegment(tenant, "lab.local", "seg-lab"); err != nil {
			t.Fatalf("AddDomainSegment: %v", err)
		}
		obs = build(t, r, sighting(
			identity.SightedIdentifier{Kind: identity.KindFQDN, Value: "printer.lab.local", Address: "192.0.2.41"},
		))
		if got := scopeOf(obs, identity.KindHostname, "printer.lab.local"); got != "seg-lab" {
			t.Errorf("`.local` name in a domain segment scoped %q, want seg-lab", got)
		}
		if obs.Network.SegmentID != "seg-lab" {
			t.Errorf("Network.SegmentID = %q, want seg-lab", obs.Network.SegmentID)
		}
	})

	// The dynamic-scope rule. Intake must read the posture the PRECEDENCE
	// rule stored — operator > measured > inferred — and nothing a collector
	// says on the run. Mutation check: swap the operator and measured
	// branches of the precedence (postureUpdateSQL's CASE in
	// shared/identity/postgres/segment_posture.go, or postureRank in the
	// memory store) and the "operator says static" step goes red.
	t.Run("Intake reads the stored effective posture: operator > measured > inferred", func(t *testing.T) {
		r := newRepo()
		seg, ok := r.(SegmentWriter)
		if !ok {
			t.Skipf("%T cannot register segments", r)
		}
		pw, ok := r.(SegmentPostureWriter)
		if !ok {
			t.Skipf("%T cannot state segment posture", r)
		}
		const scope = "seg-posture"
		if err := seg.AddSegment(tenant, "198.51.100.0/24", scope, false); err != nil {
			t.Fatalf("AddSegment: %v", err)
		}
		yes, no := true, false
		state := func(source string, v *bool) {
			t.Helper()
			if err := pw.StateSegmentPosture(tenant, scope, source, v); err != nil {
				t.Fatalf("StateSegmentPosture(%s): %v", source, err)
			}
		}
		dynamic := func() bool {
			t.Helper()
			obs := build(t, r, sighting(ip("198.51.100.20")))
			if got := scopeOf(obs, identity.KindIPAddress, "198.51.100.20"); got != scope {
				t.Fatalf("address scoped %q, want %q", got, scope)
			}
			return obs.DynamicScopes[scope]
		}

		// AddSegment stored a bare legacy value, which reads as an operator's.
		// Withdraw it so the automatic sources can speak.
		state("operator", nil)
		if dynamic() {
			t.Fatal("no source has stated a posture, yet the segment reads dynamic")
		}
		state("inferred", &yes)
		if !dynamic() {
			t.Fatal("inferred=dynamic is the only statement, yet the segment reads static")
		}
		state("measured", &no)
		if dynamic() {
			t.Fatal("measured=static must outrank inferred=dynamic")
		}
		state("measured", &yes)
		state("operator", &no)
		if dynamic() {
			t.Fatal("operator=static must outrank measured=dynamic: a person who marked the segment " +
				"static is not overruled by the controller's next report")
		}
		state("operator", nil)
		if !dynamic() {
			t.Fatal("withdrawing the operator's statement must fall back to measured=dynamic")
		}
	})
}
