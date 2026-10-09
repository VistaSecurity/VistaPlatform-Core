package identity_test

import (
	"slices"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// A laptop with an Ethernet and a Wi-Fi NIC, running a sensor. Passive capture
// met the Wi-Fi NIC on its own segment first and recorded it as an asset; the
// sensor's self-report then names both NICs. These are the shapes from the
// first deployment with two sensors on one network.
const (
	ethernetMAC = "00:1a:2b:3c:4d:01"
	wifiMAC     = "00:1a:2b:3c:4d:02"
)

func passiveWiFiSighting() identity.Observation {
	return obs(assetclass.KeyUnknownHost,
		id(identity.KindMACAddress, wifiMAC),
		scoped(identity.KindIPAddress, "10.1.0.172", "seg-wifi"),
		scoped(identity.KindHostname, "laptop-7", "seg-wifi"),
	)
}

// selfReport is a host's own report over an authenticated session, decided by
// the installation identity the platform issued.
func selfReport(kind identity.Kind, installation string, extra ...identity.Identifier) identity.Observation {
	o := obs(assetclass.KeyWorkstation, append([]identity.Identifier{
		id(kind, installation),
		id(identity.KindMACAddress, ethernetMAC),
		scoped(identity.KindIPAddress, "10.0.0.173", "seg-lan"),
		scoped(identity.KindHostname, "laptop-7", "seg-lan"),
	}, extra...)...)
	o.Source.Ref = "sensor:" + installation
	o.Source.Mode = identity.ModeActive
	o.Admission.Authoritative = true
	o.Admission.Direct = true
	return o
}

func candidateIDsOf(cs []identity.MergeCandidate) []string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, c.Ref.ID)
	}
	slices.Sort(out)
	return out
}

func assetHolds(repo interface {
	Identifiers(identity.AssetRef) []identity.Identifier
}, ref identity.AssetRef, kind identity.Kind, value string) bool {
	for _, i := range repo.Identifiers(ref) {
		if i.Kind == kind && i.Value == value {
			return true
		}
	}
	return false
}

// TestInstallationReport_SecondNICProposesAndStaysMatched is the defect: the
// report naming the Wi-Fi NIC's MAC was a conflict that attached to NEITHER
// asset, so the host stopped being refreshed by its own sensor. It must stay
// matched to the installation's asset and propose the Wi-Fi record beside it.
func TestInstallationReport_SecondNICProposesAndStaysMatched(t *testing.T) {
	for _, kind := range []identity.Kind{identity.KindSensorID, identity.KindAgentID} {
		t.Run(string(kind), func(t *testing.T) {
			e, repo := newEngine(t, identity.Config{})
			wifi := mustResolve(t, e, passiveWiFiSighting())
			host := mustResolve(t, e, selfReport(kind, "inst-1"))
			if host.Asset == wifi.Asset {
				t.Fatal("setup: the Ethernet self-report landed on the Wi-Fi asset")
			}
			// Both records are in service, as they are on a live tenant.
			repo.SetStatus(host.Asset, identity.StatusMonitoring)
			repo.SetStatus(wifi.Asset, identity.StatusMonitoring)

			res := mustResolve(t, e, selfReport(kind, "inst-1", id(identity.KindMACAddress, wifiMAC)))

			if res.Outcome != identity.OutcomeMatched || res.Asset != host.Asset {
				t.Fatalf("outcome = %v on %v, want matched to the installation's asset %v", res.Outcome, res.Asset, host.Asset)
			}
			if res.Proposal.ID == "" {
				t.Fatalf("no merge proposal for the Wi-Fi record: %+v", res)
			}
			if got, want := candidateIDsOf(res.Candidates), candidateIDsOf([]identity.MergeCandidate{{Ref: host.Asset}, {Ref: wifi.Asset}}); !slices.Equal(got, want) {
				t.Fatalf("proposal candidates = %v, want both records %v", got, want)
			}
			// ADR-0002 D5: nothing moved. The Wi-Fi MAC is still the Wi-Fi
			// record's, and neither asset was pinned pending.
			if !assetHolds(repo, wifi.Asset, identity.KindMACAddress, wifiMAC) || assetHolds(repo, host.Asset, identity.KindMACAddress, wifiMAC) {
				t.Fatal("the Wi-Fi MAC moved without a person deciding")
			}
			// The Postgres store pins a proposal's OBSERVATION asset to
			// pending_approval; this proposal must name none, or the host
			// would leave service every time its own sensor reported.
			if stored, ok := repo.PendingProposal(res.Proposal); !ok || stored.ObservationAssetID != "" {
				t.Fatalf("stored proposal observation asset = %q (pending=%v), want none", stored.ObservationAssetID, ok)
			}
			for _, ref := range []identity.AssetRef{host.Asset, wifi.Asset} {
				if got := repo.StatusOf(ref); got != identity.StatusMonitoring {
					t.Fatalf("asset %s is %s after the proposal, want it left in service", ref.ID, got)
				}
			}

			// The next hourly report re-asks the same question: the pending
			// proposal is reused, and the timeline gets no second pointer.
			again := mustResolve(t, e, selfReport(kind, "inst-1", id(identity.KindMACAddress, wifiMAC)))
			if again.Proposal.ID != res.Proposal.ID || !again.Proposal.Reused {
				t.Fatalf("repeat report proposal = %+v, want the pending %s reused", again.Proposal, res.Proposal.ID)
			}
			pointers := 0
			for _, h := range repo.HistoryFor(host.Asset) {
				if h.Action == identity.ActionMergeProposed {
					pointers++
				}
			}
			if pointers != 1 {
				t.Fatalf("%d merge_proposed entries on the installation's asset, want 1", pointers)
			}
		})
	}
}

// TestInstallationReport_KeptSeparateIsNotAskedAgain: a reviewer who decided
// the two records are different machines is not asked again on the same
// evidence, every hour, by the sensor's report.
func TestInstallationReport_KeptSeparateIsNotAskedAgain(t *testing.T) {
	e, repo := newEngine(t, identity.Config{})
	mustResolve(t, e, passiveWiFiSighting())
	host := mustResolve(t, e, selfReport(identity.KindSensorID, "inst-1"))
	first := mustResolve(t, e, selfReport(identity.KindSensorID, "inst-1", id(identity.KindMACAddress, wifiMAC)))
	if first.Proposal.ID == "" {
		t.Fatal("setup: no proposal to keep separate")
	}
	if err := repo.ResolveProposal(first.Proposal, "kept_separate", "reviewer-1", observedAt.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	later := selfReport(identity.KindSensorID, "inst-1", id(identity.KindMACAddress, wifiMAC))
	later.ObservedAt = observedAt.Add(2 * time.Hour)
	res := mustResolve(t, e, later)
	if res.Outcome != identity.OutcomeMatched || res.Asset != host.Asset {
		t.Fatalf("outcome = %v on %v, want still matched to %v", res.Outcome, res.Asset, host.Asset)
	}
	if res.Proposal.ID != "" || res.Suppressed == nil {
		t.Fatalf("kept-separate pair re-proposed: proposal=%+v suppressed=%+v", res.Proposal, res.Suppressed)
	}
	if n := len(repo.Proposals()); n != 1 {
		t.Fatalf("%d proposals after a keep-separate, want only the one the reviewer answered", n)
	}
}

// TestInstallationReport_RequiresFirstHandAuthority is the other polarity:
// the same identifiers without an authenticated session are not the host
// describing itself, and keep the conflict path's behaviour.
func TestInstallationReport_RequiresFirstHandAuthority(t *testing.T) {
	for _, tc := range []struct {
		name  string
		adapt func(*identity.Observation)
	}{
		{"not authoritative", func(o *identity.Observation) { o.Admission.Authoritative = false }},
		{"not direct", func(o *identity.Observation) { o.Admission.Direct = false }},
		{"relayed", func(o *identity.Observation) { o.Admission.Relayed = true }},
		{"declared, not measured", func(o *identity.Observation) { o.Source.Kind = identity.SourceDeclared }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, _ := newEngine(t, identity.Config{})
			wifi := mustResolve(t, e, passiveWiFiSighting())
			// The installation's asset exists, established by a genuine report.
			host := mustResolve(t, e, selfReport(identity.KindSensorID, "inst-1"))

			o := selfReport(identity.KindSensorID, "inst-1", id(identity.KindMACAddress, wifiMAC))
			tc.adapt(&o)
			res := mustResolve(t, e, o)
			if res.Outcome == identity.OutcomeMatched && res.Asset == host.Asset && res.Proposal.ID != "" {
				t.Fatalf("a %s report took the installation rule: %+v", tc.name, res)
			}
			if res.Asset == wifi.Asset && res.Outcome == identity.OutcomeMatched {
				t.Fatalf("a %s report attached to the Wi-Fi record", tc.name)
			}
		})
	}
}

// TestInstallationReport_NoOtherOwnerNoProposal: a report whose identifiers
// all belong to its own asset (or to nobody) is an ordinary match — no
// proposal, no history beyond the update.
func TestInstallationReport_NoOtherOwnerNoProposal(t *testing.T) {
	e, repo := newEngine(t, identity.Config{})
	host := mustResolve(t, e, selfReport(identity.KindSensorID, "inst-1"))
	res := mustResolve(t, e, selfReport(identity.KindSensorID, "inst-1", id(identity.KindMACAddress, wifiMAC)))
	if res.Outcome != identity.OutcomeMatched || res.Asset != host.Asset || res.Proposal.ID != "" || len(res.Candidates) != 0 {
		t.Fatalf("unowned second NIC: %+v, want a plain match", res)
	}
	if !assetHolds(repo, host.Asset, identity.KindMACAddress, wifiMAC) {
		t.Fatal("the unowned second NIC's MAC was not attached to the host")
	}
}
