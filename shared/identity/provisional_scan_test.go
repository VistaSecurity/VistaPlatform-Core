package identity_test

// A direct, authorized probe of an address held by exactly one PROVISIONAL
// asset is the corroboration D3 describes: the same item, met directly.
// Addresses are RFC 5737 and every name is invented.

import (
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/identity"
)

const scanAddr = "192.0.2.33"

// laptopAdverts delivers the two same-second mDNS observations of one
// dual-homed laptop: the relayed one creates the provisional asset, the direct
// one attaches the MAC and link-local address to it.
func laptopAdverts(t *testing.T, e *identity.Engine) identity.AssetRef {
	t.Helper()
	name := scoped(identity.KindHostname, "laptop-a", segmentB)
	fqdn := scoped(identity.KindHostname, "laptop-a.local", segmentB)
	ip := scoped(identity.KindIPAddress, scanAddr, segmentB)

	relayed := mustResolve(t, e, advert(advertAt, segmentB, name, fqdn, ip))
	if relayed.Outcome != identity.OutcomeProvisional {
		t.Fatalf("setup: relayed advert outcome = %s, want provisional", relayed.Outcome)
	}
	d := direct(advertAt, segmentB, name, fqdn, ip,
		id(identity.KindMACAddress, "02:aa:bb:cc:dd:33"),
		scoped(identity.KindIPAddress, "fe80::1", segmentB))
	d.Source.Mode = identity.ModePassive
	d.Confidence = 0.8
	// The direct advert is the same item's own announcement; it does not
	// establish by itself in every configuration, so only the asset matters.
	mustResolve(t, e, d)
	return relayed.Asset
}

// authorizedScan is a direct, measured probe of the address that found an SSH
// host key nobody owns yet.
func authorizedScan(at time.Time) identity.Observation {
	o := direct(at, segmentB,
		scoped(identity.KindIPAddress, scanAddr, segmentB),
		id(identity.KindSSHHostKeyFingerprint, "SHA256:abcdefghijklmnopqrstuvwxyz0123456789ABCDEF"))
	o.Source.Ref = "scan:sensor-1"
	o.Confidence = 0.9
	o.ClassHint = "server"
	return o
}

func heldKinds(ids []identity.Identifier) map[identity.Kind]bool {
	out := map[identity.Kind]bool{}
	for _, i := range ids {
		out[i.Kind] = true
	}
	return out
}

func assertOneCorroboratedAsset(t *testing.T, repo *admissionRepo, asset identity.AssetRef, res identity.Resolution) {
	t.Helper()
	if res.Outcome != identity.OutcomeMatched {
		t.Fatalf("scan outcome = %s, want matched: the probe met the provisional asset directly", res.Outcome)
	}
	if res.Asset.ID != asset.ID {
		t.Fatalf("scan landed on %s, want the provisional asset %s", res.Asset.ID, asset.ID)
	}
	if n := repo.AssetCount(); n != 1 {
		t.Fatalf("asset count = %d, want 1: a second row is the duplicate this rule prevents", n)
	}
	held := heldKinds(repo.Identifiers(asset))
	for _, k := range []identity.Kind{identity.KindIPAddress, identity.KindHostname, identity.KindMACAddress, identity.KindSSHHostKeyFingerprint} {
		if !held[k] {
			t.Errorf("the asset holds no %s: %+v", k, repo.Identifiers(asset))
		}
	}
	for _, u := range res.Unattached {
		if u.Kind == identity.KindIPAddress {
			t.Errorf("the scanned address is reported unattached: %+v", res.Unattached)
		}
	}
	if last := repo.lastFinished(t); !last.decision.Established || !last.establish {
		t.Errorf("FinishObservation(establish=%v, established=%v); the corroborating probe is what promotes "+
			"the provisional asset", last.establish, last.decision.Established)
	}
	if !hasChange(repo.HistoryFor(asset), identity.ActionUpdated, "corroborated_provisional", true) {
		t.Errorf("no `corroborated_provisional` in history: %+v", repo.HistoryFor(asset))
	}
}

func TestProvisionalDirectScanOfItsAddressCorroboratesIt(t *testing.T) {
	e, repo := newProvisionalEngine(t, true)
	asset := laptopAdverts(t, e)

	res := mustResolve(t, e, authorizedScan(advertAt.Add(time.Minute)))
	assertOneCorroboratedAsset(t, repo, asset, res)
}

// The scan arrives first and the adverts second: still one asset.
func TestProvisionalScanThenAdvertsIsOneAsset(t *testing.T) {
	e, repo := newProvisionalEngine(t, true)
	scan := mustResolve(t, e, authorizedScan(advertAt))
	if scan.Outcome != identity.OutcomeCreated {
		t.Fatalf("setup: scan outcome = %s, want created", scan.Outcome)
	}
	name := scoped(identity.KindHostname, "laptop-a", segmentB)
	ip := scoped(identity.KindIPAddress, scanAddr, segmentB)
	mustResolve(t, e, advert(advertAt.Add(time.Minute), segmentB, name, ip))
	d := direct(advertAt.Add(time.Minute), segmentB, name, ip, id(identity.KindMACAddress, "02:aa:bb:cc:dd:33"))
	d.Source.Mode = identity.ModePassive
	mustResolve(t, e, d)
	if n := repo.AssetCount(); n != 1 {
		t.Errorf("asset count = %d, want 1", n)
	}
}

// A relayed observation never corroborates, whatever else it carries.
func TestProvisionalRelayedObservationDoesNotCorroborateByAddress(t *testing.T) {
	e, _ := newProvisionalEngine(t, true)
	asset := laptopAdverts(t, e)
	o := authorizedScan(advertAt.Add(time.Minute))
	o.Admission = identity.AdmissionEvidence{Relayed: true}
	res := mustResolve(t, e, o)
	if res.Asset.ID == asset.ID && res.Outcome == identity.OutcomeMatched {
		t.Errorf("a relayed observation corroborated the provisional asset")
	}
}
