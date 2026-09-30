package identity_test

// Phase 4 — the same-device rule (owner decision D1).
//
// One test per condition of identity.SameDeviceVerdict. Each starts from a
// pair the rule MUST merge (the control — without it a refusal proves nothing,
// because a verdict that is always false passes every negative), breaks exactly
// the one thing its condition is about, and names the mutation that turns it
// red. Then the engine half: the verdict is stamped on the proposal only when
// the tenant lets rule merges run, a kept-separate pair is never stamped
// whatever the evidence, and nothing is merged inside Resolve (guard rail 2).
//
// Every name is invented and every address is RFC 5737 / a locally
// administered MAC.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/identity/memory"
)

const sdSeg = "seg-lab-a"

// sameDevicePair is two records of one laptop: A known by its name, B by its
// NIC and address, both in service in one segment, and the sighting that
// carried the name and the NIC together.
type sameDevicePair struct {
	obs        identity.Observation
	candidates []identity.MergeCandidate
	summaries  map[string]identity.AssetSummary
	link       identity.SameDeviceLink
}

func newSameDevicePair() sameDevicePair {
	name := scoped(identity.KindHostname, "laptop-7", sdSeg)
	mac := id(identity.KindMACAddress, "02:00:5e:10:00:07")
	addr := scoped(identity.KindIPAddress, "192.0.2.47", sdSeg)
	o := obs(assetclass.KeyUnknownHost, name, mac, addr)
	o.Source.Ref = "sensor:collector-1"
	o.Admission = identity.AdmissionEvidence{Direct: true}
	return sameDevicePair{
		obs: o,
		candidates: []identity.MergeCandidate{
			{Ref: identity.AssetRef{TenantID: tenant, ID: "asset-a"}, MatchedIdentifiers: []identity.Identifier{name}},
			{Ref: identity.AssetRef{TenantID: tenant, ID: "asset-b"}, MatchedIdentifiers: []identity.Identifier{mac, addr}},
		},
		summaries: map[string]identity.AssetSummary{
			"asset-a": {Ref: identity.AssetRef{TenantID: tenant, ID: "asset-a"}, DisplayName: "laptop-7",
				Status: identity.StatusMonitoring, NetworkSegment: sdSeg, Identifiers: []identity.Identifier{name}},
			"asset-b": {Ref: identity.AssetRef{TenantID: tenant, ID: "asset-b"}, DisplayName: "192.0.2.47",
				Status: identity.StatusMonitoring, NetworkSegment: sdSeg, Identifiers: []identity.Identifier{mac, addr}},
		},
		link: identity.SameDeviceLink{Direct: identity.DirectEvidence(o)},
	}
}

func (p sameDevicePair) verdict() (bool, []string) {
	return identity.SameDeviceVerdict(p.obs, p.candidates, p.summaries, p.link)
}

func (p sameDevicePair) setSummary(assetID string, edit func(*identity.AssetSummary)) {
	s := p.summaries[assetID]
	edit(&s)
	p.summaries[assetID] = s
}

// requireControl is the positive polarity every condition test starts from.
func requireControl(t *testing.T) {
	t.Helper()
	if ok, ev := newSameDevicePair().verdict(); !ok || len(ev) == 0 {
		t.Fatalf("control: the rule refused a pair it must merge (evidence %v) — every refusal below would prove nothing", ev)
	}
}

func requireRefused(t *testing.T, p sameDevicePair, why string) {
	t.Helper()
	if ok, ev := p.verdict(); ok || ev != nil {
		t.Fatalf("the rule held (%v), want refused: %s", ev, why)
	}
}

// Condition 1 — exactly two LIVE candidates.
//
// Mutation check: replace `len(live) != 2` with `len(live) < 2` → the
// three-candidate case holds; drop the archived/denied skip → the "third, dead
// candidate" control is refused (a dead record in a PAIR is also caught by
// condition 6, which is why that control carries three).
func TestSameDevice_Cond1_ExactlyTwoLiveCandidates(t *testing.T) {
	requireControl(t)

	t.Run("three live candidates", func(t *testing.T) {
		p := newSameDevicePair()
		third := scoped(identity.KindHostname, "laptop-7b", sdSeg)
		p.candidates = append(p.candidates, identity.MergeCandidate{Ref: identity.AssetRef{TenantID: tenant, ID: "asset-c"}, MatchedIdentifiers: []identity.Identifier{third}})
		p.summaries["asset-c"] = identity.AssetSummary{Ref: identity.AssetRef{TenantID: tenant, ID: "asset-c"}, Status: identity.StatusMonitoring, NetworkSegment: sdSeg}
		requireRefused(t, p, "three records are not a pair")
	})
	for _, dead := range []string{identity.StatusArchived, identity.StatusDenied} {
		t.Run("one candidate "+dead, func(t *testing.T) {
			p := newSameDevicePair()
			p.setSummary("asset-a", func(s *identity.AssetSummary) { s.Status = dead })
			requireRefused(t, p, "a "+dead+" record is not a live candidate")
		})
	}
	// The other polarity: a third candidate that was merged away (archived) or
	// denied is not a record anyone can merge, so the two live ones are still
	// exactly a pair.
	t.Run("a third, dead candidate does not count (control)", func(t *testing.T) {
		for _, dead := range []string{identity.StatusArchived, identity.StatusDenied} {
			p := newSameDevicePair()
			gone := scoped(identity.KindHostname, "laptop-7-old", sdSeg)
			p.candidates = append(p.candidates, identity.MergeCandidate{Ref: identity.AssetRef{TenantID: tenant, ID: "asset-c"}, MatchedIdentifiers: []identity.Identifier{gone}})
			p.summaries["asset-c"] = identity.AssetSummary{Ref: identity.AssetRef{TenantID: tenant, ID: "asset-c"}, Status: dead, NetworkSegment: sdSeg}
			if ok, _ := p.verdict(); !ok {
				t.Fatalf("a %s third record stopped the rule; only live records are candidates", dead)
			}
		}
	})
	t.Run("one candidate unknown to the store", func(t *testing.T) {
		p := newSameDevicePair()
		delete(p.summaries, "asset-a")
		requireRefused(t, p, "a record the store no longer holds is not a candidate")
	})
}

// Condition 2 — the sighting links them: at least one matched identifier each.
//
// Mutation check: delete the `len(a.MatchedIdentifiers) == 0 || …` guard → the
// case holds on the other candidate's MAC alone.
func TestSameDevice_Cond2_TheSightingLinksBoth(t *testing.T) {
	requireControl(t)
	p := newSameDevicePair()
	p.candidates[0].MatchedIdentifiers = nil
	requireRefused(t, p, "a candidate nothing in the sighting matched is not linked by it")
}

// Condition 3 — a device-binding identifier, from direct or authoritative
// evidence.
//
// Mutation checks: delete the `!link.Direct` refusal → "relayed" holds; make
// bindsDevice accept any kind → "no device binding" holds; drop the
// `|| id.Kind == KindMACAddress` arm → "derived MAC" is refused; drop the
// `!id.Inferred()` term → "derived serial" holds; drop the Authoritative term
// from DirectEvidence → the "controller inventory" control is refused.
func TestSameDevice_Cond3_DeviceBindingSeenDirectly(t *testing.T) {
	requireControl(t)

	t.Run("relayed sighting", func(t *testing.T) {
		p := newSameDevicePair()
		p.obs.Admission = identity.AdmissionEvidence{Direct: true, Relayed: true}
		p.link.Direct = identity.DirectEvidence(p.obs)
		requireRefused(t, p, "a relayed advert is hearsay about the device")
	})
	t.Run("indirect sighting", func(t *testing.T) {
		p := newSameDevicePair()
		p.obs.Admission = identity.AdmissionEvidence{}
		p.link.Direct = identity.DirectEvidence(p.obs)
		requireRefused(t, p, "nothing met the device")
	})
	t.Run("no device binding", func(t *testing.T) {
		p := newSameDevicePair()
		addr := scoped(identity.KindIPAddress, "192.0.2.47", sdSeg)
		p.candidates[1].MatchedIdentifiers = []identity.Identifier{addr}
		requireRefused(t, p, "a name and an address tie no device together")
	})
	t.Run("controller inventory (control)", func(t *testing.T) {
		p := newSameDevicePair()
		p.obs.Admission = identity.AdmissionEvidence{Authoritative: true}
		p.link.Direct = identity.DirectEvidence(p.obs)
		ok, ev := p.verdict()
		if !ok {
			t.Fatal("an authoritative inventory naming the NIC must satisfy condition 3")
		}
		if !strings.Contains(ev[0], "authoritative") {
			t.Errorf("evidence %q, want it to say the inventory was authoritative", ev[0])
		}
	})
	// Phase 2: a MAC the intake DERIVED (from an EUI-64 address or a
	// serial) counts — the spec names it — and says so in the evidence; a
	// derived identifier of any other device-binding kind does not.
	t.Run("derived MAC (control)", func(t *testing.T) {
		p := newSameDevicePair()
		derived := id(identity.KindMACAddress, "a0:b2:c3:d4:e5:f6")
		derived.Source = identity.Source{Kind: identity.SourceInferred, Ref: "derived:eui64:fd00::a2b2:c3ff:fed4:e5f6"}
		p.candidates[1].MatchedIdentifiers = []identity.Identifier{derived}
		ok, ev := p.verdict()
		if !ok {
			t.Fatal("a derived MAC is a device binding (spec condition 3)")
		}
		if !containsEvidence(ev, "derived from the IPv6 address fd00::a2b2:c3ff:fed4:e5f6") {
			t.Errorf("evidence %q does not say the MAC was derived", ev)
		}
	})
	t.Run("derived serial", func(t *testing.T) {
		p := newSameDevicePair()
		derived := id(identity.KindSerialNumber, "SN-4471")
		derived.Source = identity.Source{Kind: identity.SourceInferred, Ref: "derived:elsewhere"}
		p.candidates[1].MatchedIdentifiers = []identity.Identifier{derived}
		requireRefused(t, p, "only a derived MAC counts; no other derived kind is named")
	})
	t.Run("serial number (control)", func(t *testing.T) {
		p := newSameDevicePair()
		serial := id(identity.KindSerialNumber, "SN-4471")
		p.candidates[1].MatchedIdentifiers = []identity.Identifier{serial}
		if ok, _ := p.verdict(); !ok {
			t.Fatal("a serial number is a device binding")
		}
	})
}

// c1Pair is C1's shape on a STATIC segment: record X is a laptop's
// provisional record (its advertised name and the address it held), record Y
// an access point (its MAC and serial). A controller's client table — direct
// and authoritative — reports the AP's MAC and serial at the address the
// laptop used to hold. On a static segment the address votes, so this is a
// cross-kind conflict: MAC → Y, address → X.
func c1Pair() sameDevicePair {
	name := scoped(identity.KindHostname, "laptop-9", sdSeg)
	addr := scoped(identity.KindIPAddress, "203.0.113.9", sdSeg)
	mac := id(identity.KindMACAddress, "02:00:5e:10:00:09")
	serial := id(identity.KindSerialNumber, "AP-SN-0009")
	o := obs(assetclass.KeyUnknownHost, mac, serial, addr)
	o.Source.Ref = "interrogation"
	o.Admission = identity.AdmissionEvidence{Direct: true, Authoritative: true}
	return sameDevicePair{
		obs: o,
		candidates: []identity.MergeCandidate{
			{Ref: identity.AssetRef{TenantID: tenant, ID: "laptop-x"}, MatchedIdentifiers: []identity.Identifier{addr}},
			{Ref: identity.AssetRef{TenantID: tenant, ID: "ap-y"}, MatchedIdentifiers: []identity.Identifier{mac, serial}},
		},
		summaries: map[string]identity.AssetSummary{
			"laptop-x": {Ref: identity.AssetRef{TenantID: tenant, ID: "laptop-x"}, DisplayName: "laptop-9",
				Status: identity.StatusPendingApproval, NetworkSegment: sdSeg, Identifiers: []identity.Identifier{name, addr}},
			"ap-y": {Ref: identity.AssetRef{TenantID: tenant, ID: "ap-y"}, DisplayName: "ap-9",
				Status: identity.StatusMonitoring, NetworkSegment: sdSeg, Identifiers: []identity.Identifier{mac, serial}},
		},
		link: identity.SameDeviceLink{Direct: identity.DirectEvidence(o)},
	}
}

// Condition 3a — a record reached by addresses alone must itself be nothing
// but addresses.
//
// Mutation check: delete the 3a refusal (`!holdsOnlyAddresses`) → the C1 shape
// merges the laptop into the access point.
func TestSameDevice_Cond3a_AnAddressIsALeaseNotAnIdentity(t *testing.T) {
	t.Run("C1 on a static segment", func(t *testing.T) {
		requireRefused(t, c1Pair(), "the laptop's record held the lease; it is not the access point")
	})
	t.Run("the IP-only record (control)", func(t *testing.T) {
		p := c1Pair()
		p.setSummary("laptop-x", func(s *identity.AssetSummary) {
			s.Identifiers = []identity.Identifier{scoped(identity.KindIPAddress, "203.0.113.9", sdSeg)}
		})
		ok, ev := p.verdict()
		if !ok {
			t.Fatal("a record of nothing but the address is what the device's NIC should absorb")
		}
		if !containsEvidence(ev, "nothing but addresses") {
			t.Errorf("evidence %q does not say the record was address-only", ev)
		}
	})
	t.Run("a name beside the address still links (control)", func(t *testing.T) {
		p := c1Pair()
		p.candidates[0].MatchedIdentifiers = append(p.candidates[0].MatchedIdentifiers, scoped(identity.KindHostname, "laptop-9", sdSeg))
		if ok, _ := p.verdict(); !ok {
			t.Fatal("a name in common is corroboration, not a lease link")
		}
	})
}

// Condition 3b — a record not reached through a device binding must not carry
// one of its own that the sighting did not match.
//
// Mutation check: delete the 3b refusal (`holdsAnUnmatchedDevice`) → "name link,
// its own different MAC" merges. The lead's "address link, its own different
// MAC" case is refused by 3a as well (defence in depth), so it cannot tell 3b's
// deletion apart; the name-link case is 3b's own.
func TestSameDevice_Cond3b_AnotherDevicesRecord(t *testing.T) {
	ownMAC := id(identity.KindMACAddress, "02:00:5e:10:00:aa")
	t.Run("address link, its own different MAC", func(t *testing.T) {
		p := c1Pair()
		p.setSummary("laptop-x", func(s *identity.AssetSummary) {
			s.Identifiers = []identity.Identifier{scoped(identity.KindIPAddress, "203.0.113.9", sdSeg), ownMAC}
		})
		requireRefused(t, p, "a reused lease: the address's previous holder has its own NIC")
	})
	t.Run("name link, its own different MAC", func(t *testing.T) {
		p := newSameDevicePair()
		p.setSummary("asset-a", func(s *identity.AssetSummary) { s.Identifiers = append(s.Identifiers, ownMAC) })
		requireRefused(t, p, "a record with its own NIC, reached only by name, is another (or a re-imaged) device")
	})
	t.Run("its own MAC was matched too — two NICs (control)", func(t *testing.T) {
		p := newSameDevicePair()
		p.setSummary("asset-a", func(s *identity.AssetSummary) { s.Identifiers = append(s.Identifiers, ownMAC) })
		p.candidates[0].MatchedIdentifiers = append(p.candidates[0].MatchedIdentifiers, ownMAC)
		if ok, _ := p.verdict(); !ok {
			t.Fatal("a sighting that met both NICs links them; that is one device with two interfaces")
		}
	})
}

// Condition 4 — no singleton disagreement between the two records.
//
// Mutation check: make summariesDisagree return false → the case holds.
func TestSameDevice_Cond4_NoSingletonDisagreement(t *testing.T) {
	requireControl(t)
	p := newSameDevicePair()
	// A is reached through a NIC of its own too, so condition 3b (an unmatched
	// device binding) does not also refuse it: this case is condition 4's alone.
	nicA := id(identity.KindMACAddress, "02:00:5e:10:00:0a")
	p.candidates[0].MatchedIdentifiers = append(p.candidates[0].MatchedIdentifiers, nicA)
	p.setSummary("asset-a", func(s *identity.AssetSummary) {
		s.Identifiers = append(s.Identifiers, nicA, id(identity.KindSerialNumber, "SN-1000"))
	})
	p.setSummary("asset-b", func(s *identity.AssetSummary) {
		s.Identifiers = append(s.Identifiers, id(identity.KindSerialNumber, "SN-2000"))
	})
	requireRefused(t, p, "two serial numbers are two devices, whatever else they share")

	t.Run("same serial on both (control)", func(t *testing.T) {
		p := newSameDevicePair()
		for _, a := range []string{"asset-a", "asset-b"} {
			p.setSummary(a, func(s *identity.AssetSummary) {
				s.Identifiers = append(s.Identifiers, id(identity.KindSerialNumber, "SN-1000"))
			})
		}
		// The sighting carried that serial too (so condition 3b sees it matched).
		p.candidates[0].MatchedIdentifiers = append(p.candidates[0].MatchedIdentifiers, id(identity.KindSerialNumber, "SN-1000"))
		if ok, _ := p.verdict(); !ok {
			t.Fatal("an equal singleton is agreement, not disagreement")
		}
	})
}

// Condition 5 — the same real segment, or one of them has none.
//
// Mutation check: delete the segment comparison → "different segments" holds;
// treat the tenant default as a real segment → "one in the tenant default"
// is refused.
func TestSameDevice_Cond5_SameSegmentOrNone(t *testing.T) {
	requireControl(t)
	t.Run("different segments", func(t *testing.T) {
		p := newSameDevicePair()
		p.setSummary("asset-b", func(s *identity.AssetSummary) { s.NetworkSegment = "seg-lab-b" })
		requireRefused(t, p, "records in two segments are two things that share a name")
	})
	for _, none := range []string{"", identity.ScopeTenantDefault} {
		t.Run("one record in no segment "+none+" (control)", func(t *testing.T) {
			p := newSameDevicePair()
			p.setSummary("asset-a", func(s *identity.AssetSummary) { s.NetworkSegment = none })
			ok, ev := p.verdict()
			if !ok {
				t.Fatal("a record with no segment (a declared one, say) may merge")
			}
			if !containsEvidence(ev, "no segment") {
				t.Errorf("evidence %v, want it to say one record has no segment", ev)
			}
		})
	}
}

// Condition 6 — monitoring + monitoring, or monitoring + pending; never two
// pending.
//
// Mutation check: let pairStatusMergeable accept pending + pending → the case
// holds.
func TestSameDevice_Cond6_NeverTwoPendingRecords(t *testing.T) {
	requireControl(t)
	t.Run("both pending", func(t *testing.T) {
		p := newSameDevicePair()
		for _, a := range []string{"asset-a", "asset-b"} {
			p.setSummary(a, func(s *identity.AssetSummary) { s.Status = identity.StatusPendingApproval })
		}
		requireRefused(t, p, "merging two records nobody admitted decides the admission too")
	})
	t.Run("monitoring + pending (control)", func(t *testing.T) {
		p := newSameDevicePair()
		p.setSummary("asset-a", func(s *identity.AssetSummary) { s.Status = identity.StatusPendingApproval })
		if ok, _ := p.verdict(); !ok {
			t.Fatal("a pending duplicate of an approved asset is still a duplicate")
		}
	})
	t.Run("unknown status", func(t *testing.T) {
		p := newSameDevicePair()
		p.setSummary("asset-a", func(s *identity.AssetSummary) { s.Status = "" })
		requireRefused(t, p, "a status the store did not report is not monitoring")
	})
}

// Condition 7 — a person's "keep separate" is never overridden.
//
// Mutation check: delete the `link.KeptSeparate` refusal → the case holds.
func TestSameDevice_Cond7_KeptSeparateIsFinal(t *testing.T) {
	requireControl(t)
	p := newSameDevicePair()
	p.link.KeptSeparate = true
	requireRefused(t, p, "a reviewer already said these are two things")
}

// Condition 8 — neither record's only link is a generic or synthetic name.
//
// Mutation checks: make weakNamesOnly return false → both cases hold; drop the
// IsIdentityName term → the synthetic case holds.
func TestSameDevice_Cond8_NoGenericOrSyntheticOnlyLink(t *testing.T) {
	requireControl(t)
	t.Run("generic name", func(t *testing.T) {
		p := newSameDevicePair()
		p.candidates[0].MatchedIdentifiers = []identity.Identifier{generic("iphone", sdSeg)}
		requireRefused(t, p, "a default name ties no two phones together")
	})
	t.Run("synthetic name", func(t *testing.T) {
		p := newSameDevicePair()
		p.candidates[0].MatchedIdentifiers = []identity.Identifier{
			scoped(identity.KindHostname, "6f1c2d3e-4b5a-4c6d-8e7f-0a1b2c3d4e5f.local", sdSeg)}
		requireRefused(t, p, "a rotating instance name identifies nothing")
	})
	t.Run("generic name beside a real link (control)", func(t *testing.T) {
		p := newSameDevicePair()
		p.candidates[0].MatchedIdentifiers = append(p.candidates[0].MatchedIdentifiers, generic("iphone", sdSeg))
		if ok, _ := p.verdict(); !ok {
			t.Fatal("a generic name alongside a real link does not undo the link")
		}
	})
}

// The evidence is readable, names the device binding and who met it, and is
// the audit reason — so it must not be empty or carry anything but runtime data.
func TestSameDevice_EvidenceReadsAsAReason(t *testing.T) {
	ok, ev := newSameDevicePair().verdict()
	if !ok {
		t.Fatal("control refused")
	}
	want := []string{"MAC address 02:00:5e:10:00:07", "seen directly by sensor:collector-1", "hostname laptop-7", "same segment"}
	for _, w := range want {
		if !containsEvidence(ev, w) {
			t.Errorf("evidence %q lacks %q", ev, w)
		}
	}
}

func containsEvidence(ev []string, want string) bool {
	for _, e := range ev {
		if strings.Contains(e, want) {
			return true
		}
	}
	return false
}

// ── the engine half ────────────────────────────────────────────────────────

// laptopRecords seeds the two records of one laptop the engine will be asked
// about: A by its name, B by its NIC, both in service, one segment.
func laptopRecords(t *testing.T, e *identity.Engine, repo *memory.Repository) (a, b identity.AssetRef, sighting identity.Observation) {
	t.Helper()
	name := scoped(identity.KindHostname, "laptop-7", sdSeg)
	mac := id(identity.KindMACAddress, "02:00:5e:10:00:07")
	oa := obs(assetclass.KeyUnknownHost, name)
	oa.Network.SegmentID = sdSeg
	ob := obs(assetclass.KeyUnknownHost, mac)
	ob.Network.SegmentID = sdSeg
	a = mustResolve(t, e, oa).Asset
	b = mustResolve(t, e, ob).Asset
	repo.SetStatus(a, identity.StatusMonitoring)
	repo.SetStatus(b, identity.StatusMonitoring)

	sighting = obs(assetclass.KeyUnknownHost, name, mac)
	sighting.Network.SegmentID = sdSeg
	sighting.Admission = identity.AdmissionEvidence{Direct: true}
	sighting.ObservedAt = observedAt.Add(time.Hour)
	return a, b, sighting
}

// TestEngine_SameDeviceVerdictIsStampedOnlyWhenTheTenantAllowsIt: with the
// setting on, the conflict opens its proposal as always and stamps the verdict;
// off (and on an engine nobody told), nothing is stamped — today's behaviour.
//
// Mutation checks: delete the `!e.autoMerge` early return → the "off" and
// "unset" cases stamp; drop RuleVerdict from proposeWithoutCreating's proposal
// → the "on" case sees no verdict.
func TestEngine_SameDeviceVerdictIsStampedOnlyWhenTheTenantAllowsIt(t *testing.T) {
	for _, tt := range []struct {
		name  string
		setOn func(*identity.Engine) *identity.Engine
		want  bool
	}{
		{"on", func(e *identity.Engine) *identity.Engine { return e.WithAutoMergeExisting(true) }, true},
		{"off", func(e *identity.Engine) *identity.Engine { return e.WithAutoMergeExisting(false) }, false},
		{"unset", func(e *identity.Engine) *identity.Engine { return e }, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			base, repo := newEngine(t, identity.Config{})
			a, b, sighting := laptopRecords(t, base, repo)
			res := mustResolve(t, tt.setOn(base), sighting)

			if res.Outcome != identity.OutcomeConflict {
				t.Fatalf("outcome %s, want conflict (the name says %s, the MAC says %s)", res.Outcome, a.ID, b.ID)
			}
			props := repo.Proposals()
			if len(props) != 1 {
				t.Fatalf("%d proposals, want 1: the question is still opened either way", len(props))
			}
			stamped := props[0].RuleVerdict == identity.RuleVerdictSameDevice
			if stamped != tt.want || res.MergeRecommended != tt.want {
				t.Fatalf("verdict %q / MergeRecommended %v, want stamped=%v", props[0].RuleVerdict, res.MergeRecommended, tt.want)
			}
			if tt.want && len(props[0].RuleEvidence) == 0 {
				t.Error("a stamped verdict carries no evidence")
			}
			if !tt.want && props[0].RuleEvidence != nil {
				t.Errorf("evidence %v on an unstamped proposal", props[0].RuleEvidence)
			}
		})
	}
}

// TestEngine_SameDeviceVerdictMergesNothing is guard rail 2: even with the
// verdict stamped, Resolve leaves both records exactly as they were — each
// keeps its own identifier, neither is archived, and the sighting's identifiers
// are reported unattached.
//
// Mutation check: have withSameDeviceVerdict call ReassignIdentifier/ArchiveAsset
// (any merge inside Resolve) → this fails.
func TestEngine_SameDeviceVerdictMergesNothing(t *testing.T) {
	base, repo := newEngine(t, identity.Config{})
	a, b, sighting := laptopRecords(t, base, repo)
	res := mustResolve(t, base.WithAutoMergeExisting(true), sighting)
	if !res.MergeRecommended {
		t.Fatal("control: the verdict did not hold")
	}
	for _, ref := range []identity.AssetRef{a, b} {
		if st := repo.StatusOf(ref); st != identity.StatusMonitoring {
			t.Errorf("%s is %q after Resolve, want still monitoring", ref.ID, st)
		}
		if n := len(repo.Identifiers(ref)); n != 1 {
			t.Errorf("%s holds %d identifiers after Resolve, want its own one", ref.ID, n)
		}
	}
}

// TestEngine_KeptSeparateBlocksTheVerdictWhateverTheEvidence is guard rail 4.
// A reviewer kept the pair apart when the only link was the name and an
// address; today's sighting adds a MAC, which is NEW evidence for a person —
// so the question is re-opened for them — but never licence for the rule.
//
// Mutation check: pass `false` for KeptSeparate in withSameDeviceVerdict (i.e.
// reuse only the evidence-filtered priorDecision) → the verdict is stamped.
func TestEngine_KeptSeparateBlocksTheVerdictWhateverTheEvidence(t *testing.T) {
	ctx := context.Background()
	base, repo := newEngine(t, identity.Config{})
	a, b, sighting := laptopRecords(t, base, repo)

	// The earlier question: the reviewer weighed the name against an ADDRESS,
	// and said "no".
	earlier, err := repo.OpenMergeProposal(ctx, tenant, identity.MergeProposal{
		Candidates: []identity.MergeCandidate{
			{Ref: a, MatchedIdentifiers: []identity.Identifier{scoped(identity.KindHostname, "laptop-7", sdSeg)}},
			{Ref: b, MatchedIdentifiers: []identity.Identifier{scoped(identity.KindIPAddress, "192.0.2.47", sdSeg)}},
		},
		ProposedAt: observedAt.Add(10 * time.Minute),
	})
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	if err := repo.ResolveProposal(earlier, "kept_separate", "reviewer-1", observedAt.Add(20*time.Minute)); err != nil {
		t.Fatalf("ResolveProposal: %v", err)
	}

	res := mustResolve(t, base.WithAutoMergeExisting(true), sighting)
	// Today's MAC is evidence the reviewer never saw: the question goes back to
	// a person (decision memory's own rule) ...
	if res.Outcome != identity.OutcomeConflict || res.Proposal.ID == "" || res.Proposal.ID == earlier.ID {
		t.Fatalf("outcome %s proposal %q, want a NEW proposal for the reviewer (new evidence)", res.Outcome, res.Proposal.ID)
	}
	// ... and never to the rule.
	if res.MergeRecommended {
		t.Fatal("the rule recommended merging a pair a reviewer kept separate")
	}
	for _, p := range repo.Proposals() {
		if p.RuleVerdict != "" {
			t.Fatalf("a proposal carries verdict %q for a kept-separate pair", p.RuleVerdict)
		}
	}

	t.Run("control: without the decision the verdict is stamped", func(t *testing.T) {
		base, repo := newEngine(t, identity.Config{})
		_, _, sighting := laptopRecords(t, base, repo)
		if res := mustResolve(t, base.WithAutoMergeExisting(true), sighting); !res.MergeRecommended {
			t.Fatal("control refused")
		}
	})
}

// TestEngine_SameDeviceVerdictRidesAnAutoAccept: a tenant with an auto-accept
// threshold has the matcher file the sighting into one record; the rule's
// verdict about merging the two records is still stamped on that proposal,
// because filing an observation and merging two records are different acts.
//
// Mutation check: drop RuleVerdict from acceptMerge's proposal → no verdict.
func TestEngine_SameDeviceVerdictRidesAnAutoAccept(t *testing.T) {
	m := &stubMatcher{scores: map[string]float64{}}
	base, repo := newEngine(t, identity.Config{Matcher: m})
	a, b, sighting := laptopRecords(t, base, repo)
	m.scores[a.ID], m.scores[b.ID] = 0.99, 0.2

	res := mustResolve(t, base.WithAutoAcceptThreshold(0.9).WithAutoMergeExisting(true), sighting)
	if !res.AutoAccepted {
		t.Fatalf("control: not auto-accepted (outcome %s)", res.Outcome)
	}
	if !res.MergeRecommended {
		t.Error("MergeRecommended not set on an auto-accept the rule also held for")
	}
	props := repo.Proposals()
	if len(props) != 1 || props[0].RuleVerdict != identity.RuleVerdictSameDevice || !props[0].AutoAccepted {
		t.Fatalf("proposals %+v, want one auto-accepted proposal carrying the verdict", props)
	}
}

// TestFoldMergeProposal_CarriesTheVerdict: a verdict stamped by one sighting
// survives a later sighting that did not establish it, and a later one that did
// restates the evidence.
//
// Mutation check: delete the RuleVerdict branch in FoldMergeProposal → the
// relayed-then-direct case loses the verdict.
func TestFoldMergeProposal_CarriesTheVerdict(t *testing.T) {
	cand := []identity.MergeCandidate{{Ref: identity.AssetRef{ID: "a"}}, {Ref: identity.AssetRef{ID: "b"}}}
	plain := identity.MergeProposal{Candidates: cand, ProposedAt: observedAt}
	stamped := identity.MergeProposal{Candidates: cand, ProposedAt: observedAt.Add(time.Minute),
		RuleVerdict: identity.RuleVerdictSameDevice, RuleEvidence: []string{"x"}}

	if got := identity.FoldMergeProposal(plain, stamped); got.RuleVerdict != identity.RuleVerdictSameDevice || len(got.RuleEvidence) != 1 {
		t.Errorf("a direct sighting folded into a plain proposal: verdict %q evidence %v", got.RuleVerdict, got.RuleEvidence)
	}
	if got := identity.FoldMergeProposal(stamped, plain); got.RuleVerdict != identity.RuleVerdictSameDevice {
		t.Errorf("a later sighting without the verdict erased it: %q", got.RuleVerdict)
	}
}
