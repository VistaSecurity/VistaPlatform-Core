package identity_test

// A multi-homed device owns one MAC per interface. When an interrogation has
// attached every interface MAC to the asset, a passive sighting that hears the
// device at one of its addresses from ANY interface is the same device — not a
// "replaced" verdict and not a merge proposal against the device's own asset.

import (
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/identity/matcher"
)

const (
	ifaceMACPrimary = "00:00:5e:00:53:a1"
	ifaceMACSecond  = "00:00:5e:00:53:a2"
	ifaceAddr       = "192.0.2.1"
	ifaceSeg        = "segment-lan"
)

// interrogated creates the asset as a passive sensor first found it (primary
// MAC and address), then attaches the interface MACs an interrogation reported.
func interrogated(t *testing.T, e *identity.Engine, withInterfaceMACs bool) identity.AssetRef {
	t.Helper()
	t0 := observedAt
	asset := establish(t, e, driftObs(t0, id(identity.KindMACAddress, ifaceMACPrimary), scoped(identity.KindIPAddress, ifaceAddr, ifaceSeg)))
	if !withInterfaceMACs {
		return asset
	}
	o := driftObs(t0.Add(time.Minute), id(identity.KindMACAddress, ifaceMACPrimary), id(identity.KindMACAddress, ifaceMACSecond))
	o.Source = identity.Source{Kind: identity.SourceMeasured, Ref: "interrogation", Mode: identity.ModeActive}
	res := mustResolve(t, e, o)
	if res.Asset.ID != asset.ID {
		t.Fatalf("interface MACs resolved to %q, want the established asset %q", res.Asset.ID, asset.ID)
	}
	return asset
}

func TestDrift_InterrogatedInterfaceMAC_SightingIsTheSameDevice(t *testing.T) {
	e, repo := newEngine(t, identity.Config{})
	asset := interrogated(t, e, true)
	if !holds(repo, asset, identity.KindMACAddress, ifaceMACSecond) {
		t.Fatalf("setup: the asset does not own the second interface MAC: %+v", repo.Identifiers(asset))
	}

	res := mustResolve(t, e, driftObs(observedAt.Add(time.Hour), id(identity.KindMACAddress, ifaceMACSecond), scoped(identity.KindIPAddress, ifaceAddr, ifaceSeg)))

	if res.Outcome != identity.OutcomeMatched || res.Asset.ID != asset.ID {
		t.Fatalf("outcome = %s asset = %q, want matched on %q", res.Outcome, res.Asset.ID, asset.ID)
	}
	if res.Proposal.ID != "" || len(repo.Proposals()) != 0 {
		t.Errorf("a merge proposal was opened against the device's own asset: %+v", repo.Proposals())
	}
	if res.Drift != nil && res.Drift.Verdict == matcher.DriftReplaced {
		t.Errorf("drift verdict = %s, want no 'replaced' verdict", res.Drift.Verdict)
	}
}

// The control: the same sighting when the interface MAC was never attached is
// what produced the false review item.
func TestDrift_UnownedInterfaceMAC_SightingIsAReplacementProposal(t *testing.T) {
	e, repo := newEngine(t, identity.Config{})
	interrogated(t, e, false)

	res := mustResolve(t, e, driftObs(observedAt.Add(time.Hour), id(identity.KindMACAddress, ifaceMACSecond), scoped(identity.KindIPAddress, ifaceAddr, ifaceSeg)))

	if res.Outcome != identity.OutcomeConflict || len(repo.Proposals()) != 1 {
		t.Fatalf("outcome = %s proposals = %d, want the conflict the interface MACs prevent", res.Outcome, len(repo.Proposals()))
	}
}
