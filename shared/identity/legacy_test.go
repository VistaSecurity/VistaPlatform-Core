package identity_test

import (
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

func TestFromLegacyAsset(t *testing.T) {
	t.Run("a dotted hostname becomes an fqdn", func(t *testing.T) {
		got, err := identity.FromLegacyAsset("Host.Example.COM", "192.0.2.10", 443, "tls_scan")
		if err != nil {
			t.Fatalf("FromLegacyAsset: %v", err)
		}
		if len(got.Identifiers) != 2 {
			t.Fatalf("identifiers = %+v, want an fqdn and an ip", got.Identifiers)
		}
		if got.Identifiers[0].Kind != identity.KindFQDN || got.Identifiers[0].Value != "host.example.com" {
			t.Errorf("first identifier = %+v, want a normalised fqdn", got.Identifiers[0])
		}
		if got.Identifiers[1].Kind != identity.KindIPAddress || got.Identifiers[1].Value != "192.0.2.10" {
			t.Errorf("second identifier = %+v, want the ip", got.Identifiers[1])
		}
		if got.Source.Kind != identity.SourceMeasured || got.Source.Ref != "tls_scan" {
			t.Errorf("source = %+v, want the discovery method", got.Source)
		}
		if len(got.Endpoints) != 1 || got.Endpoints[0].Port != 443 || got.Endpoints[0].Transport != "tcp" {
			t.Errorf("endpoints = %+v, want one tcp/443", got.Endpoints)
		}
	})

	t.Run("a single-label hostname becomes a hostname", func(t *testing.T) {
		got, err := identity.FromLegacyAsset("printer-2", "", 0, "sensor")
		if err != nil {
			t.Fatalf("FromLegacyAsset: %v", err)
		}
		if len(got.Identifiers) != 1 || got.Identifiers[0].Kind != identity.KindHostname {
			t.Fatalf("identifiers = %+v, want one hostname", got.Identifiers)
		}
	})

	t.Run("port 0 is an at-rest endpoint, not a tcp socket", func(t *testing.T) {
		got, err := identity.FromLegacyAsset("", "192.0.2.10", 0, "import")
		if err != nil {
			t.Fatalf("FromLegacyAsset: %v", err)
		}
		if len(got.Endpoints) != 1 || got.Endpoints[0].Transport != "none" {
			t.Fatalf("endpoints = %+v, want a 'none' transport", got.Endpoints)
		}
	})

	t.Run("neither hostname nor ip is rejected", func(t *testing.T) {
		if _, err := identity.FromLegacyAsset("  ", "", 443, "sensor"); err == nil {
			t.Fatal("an empty legacy asset was accepted")
		}
	})

	t.Run("a malformed address is rejected, not dropped", func(t *testing.T) {
		_, err := identity.FromLegacyAsset("host.example.com", "not-an-ip", 443, "sensor")
		if err == nil {
			t.Fatal("a malformed ip was accepted")
		}
		if !strings.Contains(err.Error(), "not an IP address") {
			t.Errorf("error = %v, want it to name the problem", err)
		}
	})

	t.Run("an empty discovery method still names a producer", func(t *testing.T) {
		got, err := identity.FromLegacyAsset("host.example.com", "", 0, "")
		if err != nil {
			t.Fatalf("FromLegacyAsset: %v", err)
		}
		if got.Source.Ref == "" {
			t.Error("source ref is empty; a value with no producer cannot be audited or filtered")
		}
	})
}

// TestFromLegacyAssetMatchesUnderTheTenantDefaultScope is the erratum to the
// gap this test used to pin.
//
// A legacy row has no segment, and the rule USED to be that its hostname and IP
// therefore carried no scope and could not vote. That was honest about what we
// know and catastrophic about what it does: two observations of one host became
// two assets, the second carrying no identifier at all, and a third became a
// third. The scope is now the tenant-wide default (ADR-0002 D3 erratum), so the
// same host resolves to the same asset — which is what a caller re-observing a
// legacy row means.
//
// The gap that remains is real and narrower: a host in segment A and a host of
// the same name in segment B are one asset until something scopes them apart.
// TestSegmentScopedAndDefaultScopedHostnamesAreDifferentIdentifiers covers what
// happens then.
func TestFromLegacyAssetMatchesUnderTheTenantDefaultScope(t *testing.T) {
	e, repo := newEngine(t, identity.Config{})

	first, err := identity.FromLegacyAsset("printer-2", "10.0.0.5", 9100, "sensor")
	if err != nil {
		t.Fatalf("FromLegacyAsset: %v", err)
	}
	first.TenantID = tenant
	a := mustResolve(t, e, first)

	second, err := identity.FromLegacyAsset("printer-2", "10.0.0.5", 9100, "sensor")
	if err != nil {
		t.Fatalf("FromLegacyAsset: %v", err)
	}
	second.TenantID = tenant
	b := mustResolve(t, e, second)

	if b.Outcome != identity.OutcomeMatched {
		t.Fatalf("outcome = %s, want matched: with no segment the hostname and IP are scoped to the "+
			"tenant default, and one host observed twice is one asset", b.Outcome)
	}
	if b.Asset.ID != a.Asset.ID {
		t.Fatalf("matched %s, want the asset created first (%s)", b.Asset.ID, a.Asset.ID)
	}
	if a.ClassKey != assetclass.KeyUnknownHost {
		t.Errorf("class = %q, want unknown_host: the legacy shape carries no class", a.ClassKey)
	}
	if repo.AssetCount() != 1 {
		t.Errorf("%d assets, want 1: re-observing one legacy row must not multiply it", repo.AssetCount())
	}

	// Supplying the segment — which is what a real phase-1 builder does — is
	// what makes them match.
	scopeThem := func(o identity.Observation) identity.Observation {
		o.Network = identity.Network{Ownership: identity.OwnershipInternal, Type: "private", SegmentID: "segment-1"}
		for i := range o.Identifiers {
			if o.Identifiers[i].Kind.RequiresScope() {
				o.Identifiers[i].Scope = "segment-1"
			}
		}
		return o
	}
	c := mustResolve(t, e, scopeThem(first))
	d := mustResolve(t, e, scopeThem(second))
	if d.Outcome != identity.OutcomeMatched || d.Asset.ID != c.Asset.ID {
		t.Fatalf("with a segment: outcome = %s on %s, want matched on %s", d.Outcome, d.Asset.ID, c.Asset.ID)
	}
}
