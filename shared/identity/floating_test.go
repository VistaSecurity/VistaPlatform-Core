package identity_test

// The floating-address rule and decision memory (floating.go), against the
// in-memory store.
//
// The dev-cluster case that motivated it, in RFC 5737 addresses: MetalLB
// announces the ingress VIP from a node's real NIC by gratuitous ARP. The
// sensor decodes {mac: the node's, addr: VIP}; the MAC resolves to the node's
// asset and the address to the asset at the VIP; the walk called it a
// cross-kind conflict and proposed merging the node with the service, three
// times, because a reviewer's "kept separate" was never read back.

import (
	"context"
	"testing"
	"time"

	"github.com/vistasecurity/vistaplatform/shared/assetclass"
	"github.com/vistasecurity/vistaplatform/shared/identity"
	"github.com/vistasecurity/vistaplatform/shared/identity/memory"
)

const (
	nodeMAC = "e8:ff:1e:00:00:07"
	vipAddr = "192.0.2.230"
)

// floatingFixture is a node asset that owns nodeMAC and a VIP asset that owns
// vipAddr (and a name, so it is a real thing and not a bare address).
func floatingFixture(t *testing.T, e *identity.Engine) (node, vip identity.Resolution) {
	t.Helper()
	node = mustResolve(t, e, obs(assetclass.KeyServer,
		id(identity.KindMACAddress, nodeMAC),
		scoped(identity.KindIPAddress, "192.0.2.10", identity.ScopeTenantDefault),
	))
	vip = mustResolve(t, e, obs(assetclass.KeyUnknownHost,
		id(identity.KindFQDN, "vista.example.test"),
		scoped(identity.KindIPAddress, vipAddr, identity.ScopeTenantDefault),
	))
	if node.Asset.ID == vip.Asset.ID {
		t.Fatal("fixture: the node and the VIP resolved to one asset")
	}
	return node, vip
}

// arpAnnouncement is what the sensor's ARP decoder says about a gratuitous ARP
// for the VIP sent from the node's NIC: MAC, address, nothing else.
func arpAnnouncement() identity.Observation {
	o := obs(assetclass.KeyUnknownHost,
		id(identity.KindMACAddress, nodeMAC),
		scoped(identity.KindIPAddress, vipAddr, identity.ScopeTenantDefault),
	)
	o.Attributes = map[string]any{"arp_gratuitous": true, "arp_operation": "request"}
	return o
}

func proposalCount(repo *memory.Repository) int { return len(repo.Proposals()) }

func hasKind(ids []identity.Identifier, kind identity.Kind) bool {
	for _, i := range ids {
		if i.Kind == kind {
			return true
		}
	}
	return false
}

func TestFloatingAddressResolvesToTheHolderWithoutAProposal(t *testing.T) {
	e, repo := newEngine(t, identity.Config{})
	node, vip := floatingFixture(t, e)
	before := proposalCount(repo)
	nodeSeen := repo.LastSeen(node.Asset)

	ann := arpAnnouncement()
	ann.ObservedAt = observedAt.Add(time.Hour)
	res := mustResolve(t, e, ann)

	if res.Outcome != identity.OutcomeMatched {
		t.Fatalf("outcome = %s, want matched: a node announcing a floating address is not a conflict", res.Outcome)
	}
	if res.Asset.ID != vip.Asset.ID {
		t.Fatalf("resolved to %s, want the VIP's asset %s (the node is %s)", res.Asset.ID, vip.Asset.ID, node.Asset.ID)
	}
	if res.DecidedBy != identity.KindIPAddress {
		t.Errorf("DecidedBy = %s, want ip_address", res.DecidedBy)
	}
	if res.FloatingAddress == nil {
		t.Fatal("Resolution.FloatingAddress is nil; the caller cannot tell this from an ordinary match")
	}
	if res.FloatingAddress.AnnouncerAssetID != node.Asset.ID {
		t.Errorf("announcer = %s, want the node %s", res.FloatingAddress.AnnouncerAssetID, node.Asset.ID)
	}
	if !res.FloatingAddress.Announcement.Gratuitous {
		t.Error("the arp_gratuitous attribute was not carried into the announcement")
	}
	if res.Proposal.ID != "" || proposalCount(repo) != before {
		t.Errorf("a merge proposal was opened (%q, %d → %d); the node and the VIP are two things and nobody needs to be asked",
			res.Proposal.ID, before, proposalCount(repo))
	}

	// The MAC is the node's. It was NOT written onto the VIP's asset, and the
	// skip is reported rather than silent.
	if hasKind(repo.Identifiers(vip.Asset), identity.KindMACAddress) {
		t.Error("the announcer's MAC was attached to the VIP's asset")
	}
	if !hasKind(res.Unattached, identity.KindMACAddress) {
		t.Errorf("Unattached = %v, want the MAC reported there", res.Unattached)
	}

	// The knowledge lands as a relationship instead.
	recs := repo.Announcements(vip.Asset)
	if len(recs) != 1 {
		t.Fatalf("%d announcement records on the VIP, want 1", len(recs))
	}
	if recs[0].Announcer.ID != node.Asset.ID || recs[0].Holder.ID != vip.Asset.ID {
		t.Errorf("announcement joins %s → %s, want node %s → vip %s", recs[0].Announcer.ID, recs[0].Holder.ID, node.Asset.ID, vip.Asset.ID)
	}
	if len(recs[0].Latest.MACs) != 1 || recs[0].Latest.MACs[0] != nodeMAC {
		t.Errorf("announcement MACs = %v, want [%s]", recs[0].Latest.MACs, nodeMAC)
	}
	if len(recs[0].Latest.Addresses) != 1 || recs[0].Latest.Addresses[0] != vipAddr {
		t.Errorf("announcement addresses = %v, want [%s]", recs[0].Latest.Addresses, vipAddr)
	}

	// History on BOTH assets, and the node was seen: its NIC sent the frame.
	var vipNoted, nodeNoted bool
	for _, h := range repo.HistoryFor(vip.Asset) {
		if h.Action == identity.ActionUpdated {
			if _, ok := h.Changes["floating_address"]; ok {
				vipNoted = true
			}
		}
	}
	for _, h := range repo.HistoryFor(node.Asset) {
		if h.Action == identity.ActionUpdated {
			if _, ok := h.Changes["announces"]; ok {
				nodeNoted = true
			}
		}
	}
	if !vipNoted {
		t.Error("the VIP's history does not record the floating address")
	}
	if !nodeNoted {
		t.Error("the node's history does not record that it announces the VIP")
	}
	if !repo.LastSeen(node.Asset).After(nodeSeen) {
		t.Error("the node's last-seen did not advance; its NIC sent the frame, so it was on the wire")
	}

	// A second announcement is the same edge, seen again — not a second row
	// and still not a proposal.
	again := arpAnnouncement()
	again.ObservedAt = observedAt.Add(2 * time.Hour)
	res2 := mustResolve(t, e, again)
	if res2.FloatingAddress == nil || res2.Asset.ID != vip.Asset.ID {
		t.Fatalf("second announcement: outcome %s on %s, want the floating path onto the VIP again", res2.Outcome, res2.Asset.ID)
	}
	if recs := repo.Announcements(vip.Asset); len(recs) != 1 || recs[0].Count != 2 {
		t.Errorf("after two announcements: %d records, count %d; want one record seen twice", len(recs), recs[0].Count)
	}
	if proposalCount(repo) != before {
		t.Error("the second announcement opened a proposal")
	}
}

// THE QUALIFIER. An observation that carries the node's MAC PLUS evidence of
// which host it is — a host key, a serial, a name — is not an announcement. It
// is a re-imaged, cloned or spoofed host, and it gets the proposal.
func TestFloatingAddressWithStrongerOrNamedEvidenceIsAConflict(t *testing.T) {
	cases := []struct {
		name  string
		extra identity.Identifier
	}{
		{"the VIP's SSH host key", id(identity.KindSSHHostKeyFingerprint, "SHA256:vipkey")},
		{"the VIP's name", id(identity.KindFQDN, "vista.example.test")},
		{"a hostname of the VIP", scoped(identity.KindHostname, "vista", identity.ScopeTenantDefault)},
		{"a serial nobody owns", id(identity.KindSerialNumber, "SN-REIMAGED")},
		{"an agent id nobody owns", id(identity.KindAgentID, "agent-9")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e, repo := newEngine(t, identity.Config{})
			_, vip := floatingFixture(t, e)
			if tc.extra.Kind == identity.KindSSHHostKeyFingerprint || tc.extra.Kind == identity.KindHostname {
				// Make it genuinely the VIP's: attach it there first.
				mustResolve(t, e, obs(assetclass.KeyUnknownHost,
					scoped(identity.KindIPAddress, vipAddr, identity.ScopeTenantDefault), tc.extra))
			}
			before := proposalCount(repo)

			o := arpAnnouncement()
			o.Identifiers = append(o.Identifiers, tc.extra)
			res := mustResolve(t, e, o)

			if res.FloatingAddress != nil {
				t.Fatalf("an observation carrying %s took the floating-address path onto %s; that is a genuine conflict", tc.name, res.Asset.ID)
			}
			if res.Outcome != identity.OutcomeConflict {
				t.Fatalf("outcome = %s, want conflict", res.Outcome)
			}
			if res.Proposal.ID == "" || proposalCount(repo) != before+1 {
				t.Error("no merge proposal was opened for a real MAC-vs-host contradiction")
			}
			if hasKind(repo.Identifiers(vip.Asset), identity.KindMACAddress) {
				t.Error("the node's MAC was attached to the VIP's asset on the conflict path")
			}
		})
	}
}

// Which kinds are L2-only is pinned exactly: mac_address and ip_address, and
// nothing else in the vocabulary. Adding a kind to the allowlist in floating.go
// turns its case here red.
func TestFloatingAddressL2OnlyIsExactlyMACAndIP(t *testing.T) {
	for _, kind := range identity.AllKinds() {
		if kind == identity.KindMACAddress || kind == identity.KindIPAddress {
			continue
		}
		t.Run(string(kind), func(t *testing.T) {
			e, repo := newEngine(t, identity.Config{})
			floatingFixture(t, e)
			before := proposalCount(repo)
			o := arpAnnouncement()
			extra := identity.Identifier{Kind: kind, Value: "extra-" + string(kind), Confidence: 1}
			switch kind {
			case identity.KindFQDN:
				extra.Value = "extra.example.test"
			case identity.KindHostname:
				extra.Scope = identity.ScopeTenantDefault
			case identity.KindName:
				extra.Scope = assetclass.KeyUnknownHost
			case identity.KindCMDBSysID:
				extra.Scope = "profile-1"
			}
			o.Identifiers = append(o.Identifiers, extra)
			res := mustResolve(t, e, o)
			if res.FloatingAddress != nil {
				t.Errorf("an observation also carrying %s was treated as L2-only", kind)
			}
			if proposalCount(repo) != before+1 {
				t.Errorf("no proposal for the conflict an extra %s makes", kind)
			}
		})
	}
}

// An imported or declared pairing of one asset's MAC with another's address is
// a question for a human, not a measurement of the wire.
func TestFloatingAddressRequiresAMeasuredSource(t *testing.T) {
	for _, kind := range []identity.SourceKind{identity.SourceImported, identity.SourceDeclared, identity.SourceInferred} {
		t.Run(string(kind), func(t *testing.T) {
			e, repo := newEngine(t, identity.Config{})
			floatingFixture(t, e)
			before := proposalCount(repo)
			o := arpAnnouncement()
			o.Source = identity.Source{Kind: kind, Ref: "import:sheet"}
			res := mustResolve(t, e, o)
			if res.FloatingAddress != nil || res.Outcome != identity.OutcomeConflict {
				t.Fatalf("a %s MAC/address pairing took the floating path (outcome %s); only a measured one may", kind, res.Outcome)
			}
			if proposalCount(repo) != before+1 {
				t.Error("no proposal was opened")
			}
		})
	}
}

// MAC and address on the SAME asset is the ordinary corroboration it always
// was: nothing floats, nothing is announced.
func TestFloatingAddressSameAssetIsPlainCorroboration(t *testing.T) {
	e, repo := newEngine(t, identity.Config{})
	node, _ := floatingFixture(t, e)

	o := obs(assetclass.KeyUnknownHost,
		id(identity.KindMACAddress, nodeMAC),
		scoped(identity.KindIPAddress, "192.0.2.10", identity.ScopeTenantDefault),
	)
	o.Attributes = map[string]any{"arp_gratuitous": true}
	res := mustResolve(t, e, o)
	if res.Outcome != identity.OutcomeMatched || res.Asset.ID != node.Asset.ID {
		t.Fatalf("outcome %s on %s, want matched on the node %s", res.Outcome, res.Asset.ID, node.Asset.ID)
	}
	if res.DecidedBy != identity.KindMACAddress {
		t.Errorf("DecidedBy = %s, want mac_address — the strongest kind decided, as before", res.DecidedBy)
	}
	if res.FloatingAddress != nil {
		t.Error("a host announcing its OWN address was recorded as a floating address")
	}
	if len(repo.Announcements(node.Asset)) != 0 {
		t.Error("an announcement was recorded for a host's own address")
	}
}

// Narrowness: an address nobody owns beside the VIP's is not the shape, and
// falls through to the ordinary conflict. So does a MAC the store has lost the
// invariant on.
func TestFloatingAddressFallsThroughWhenTheShapeIsNotExact(t *testing.T) {
	t.Run("a second, unowned address", func(t *testing.T) {
		e, repo := newEngine(t, identity.Config{})
		floatingFixture(t, e)
		before := proposalCount(repo)
		o := arpAnnouncement()
		o.Identifiers = append(o.Identifiers, scoped(identity.KindIPAddress, "192.0.2.231", identity.ScopeTenantDefault))
		res := mustResolve(t, e, o)
		if res.FloatingAddress != nil {
			t.Fatal("an observation with an address nobody owns took the floating path; that address would have been attached to the VIP")
		}
		if res.Outcome != identity.OutcomeConflict || proposalCount(repo) != before+1 {
			t.Errorf("outcome %s, proposals %d → %d; want the ordinary conflict", res.Outcome, before, proposalCount(repo))
		}
	})
	t.Run("a MAC owned by two assets", func(t *testing.T) {
		e, repo := newEngine(t, identity.Config{})
		node, vip := floatingFixture(t, e)
		repo.Corrupt(tenant, id(identity.KindMACAddress, nodeMAC), identity.AssetRef{TenantID: tenant, ID: "ghost"})
		res := mustResolve(t, e, arpAnnouncement())
		if res.FloatingAddress != nil {
			t.Fatalf("a lost-invariant store was papered over by the floating rule (resolved to %s; node %s, vip %s)", res.Asset.ID, node.Asset.ID, vip.Asset.ID)
		}
		if res.Outcome != identity.OutcomeConflict {
			t.Errorf("outcome = %s, want conflict", res.Outcome)
		}
	})
}

// ── decision memory ────────────────────────────────────────────────────────

// keptSeparatePair opens the serial-vs-hostname floor conflict and has a
// reviewer keep the pair separate.
func keptSeparatePair(t *testing.T, e *identity.Engine, repo *memory.Repository) (a, b identity.Resolution, o identity.Observation, proposal identity.ProposalRef) {
	t.Helper()
	a, b, o = conflictingObservations(t, e, repo)
	first := mustResolve(t, e, o)
	if first.Outcome != identity.OutcomeConflict || first.Proposal.ID == "" {
		t.Fatalf("fixture: outcome %s, proposal %q; want a conflict with a proposal", first.Outcome, first.Proposal.ID)
	}
	if err := repo.ResolveProposal(first.Proposal, "kept_separate", "reviewer-1", observedAt.Add(time.Hour)); err != nil {
		t.Fatalf("ResolveProposal: %v", err)
	}
	return a, b, o, first.Proposal
}

func TestKeptSeparatePairIsNotReproposed(t *testing.T) {
	e, repo := newEngine(t, identity.Config{})
	a, b, o, proposal := keptSeparatePair(t, e, repo)
	before := proposalCount(repo)

	o.ObservedAt = observedAt.Add(2 * time.Hour)
	res := mustResolve(t, e, o)

	if res.Outcome == identity.OutcomeConflict || res.Proposal.ID != "" {
		t.Fatalf("outcome %s with proposal %q; the reviewer already said these are different things", res.Outcome, res.Proposal.ID)
	}
	if proposalCount(repo) != before {
		t.Errorf("proposals %d → %d; a kept-separate pair was re-proposed", before, proposalCount(repo))
	}
	if res.Suppressed == nil {
		t.Fatal("Resolution.Suppressed is nil; the ingest log cannot say why no proposal was opened")
	}
	if res.Suppressed.ProposalID != proposal.ID {
		t.Errorf("Suppressed names proposal %s, want %s", res.Suppressed.ProposalID, proposal.ID)
	}
	if res.Suppressed.DecidedBy != "reviewer-1" || res.Suppressed.DecidedAt.IsZero() {
		t.Errorf("Suppressed = %+v, want the reviewer and the date the decision was made", res.Suppressed)
	}
	// A floor proposal created no observation asset, so the observation lands
	// on the candidate the WEAKEST evidence points at: the reviewer overruled
	// the serial's claim, and the hostname says B.
	if res.Asset.ID != b.Asset.ID {
		t.Errorf("resolved to %s, want %s (the hostname's asset); the serial's asset is %s", res.Asset.ID, b.Asset.ID, a.Asset.ID)
	}
	if res.DecidedBy != identity.KindHostname {
		t.Errorf("DecidedBy = %s, want hostname", res.DecidedBy)
	}
	// The serial is A's and stays A's.
	if hasKind(repo.Identifiers(b.Asset), identity.KindSerialNumber) {
		t.Error("A's serial was attached to B")
	}
	if !hasKind(res.Unattached, identity.KindSerialNumber) {
		t.Errorf("Unattached = %v, want the serial reported", res.Unattached)
	}
	var noted bool
	for _, h := range repo.HistoryFor(b.Asset) {
		if _, ok := h.Changes["suppressed_proposal"]; ok && h.Action == identity.ActionUpdated {
			noted = true
		}
	}
	if !noted {
		t.Error("B's history does not say the proposal was suppressed and why")
	}
}

func TestKeptSeparateResolvesToTheObservationAssetWhenThereWasOne(t *testing.T) {
	e, repo := newEngine(t, identity.Config{})
	a, b, o := conflictingObservations(t, e, repo)
	// This time something is left to attach, so the conflict CREATES a pending
	// asset Z for the observation, and the reviewer keeps Z apart from A and B.
	o.Identifiers = append(o.Identifiers, id(identity.KindMACAddress, "aa:bb:cc:dd:ee:77"))
	first := mustResolve(t, e, o)
	if first.Outcome != identity.OutcomeConflict || first.Asset.Zero() {
		t.Fatalf("fixture: outcome %s, asset %q; want a conflict that created an observation asset", first.Outcome, first.Asset.ID)
	}
	z := first.Asset
	if err := repo.ResolveProposal(first.Proposal, "kept_separate", "", observedAt.Add(time.Hour)); err != nil {
		t.Fatalf("ResolveProposal: %v", err)
	}
	before := proposalCount(repo)

	o.ObservedAt = observedAt.Add(2 * time.Hour)
	res := mustResolve(t, e, o)
	if res.Suppressed == nil || proposalCount(repo) != before {
		t.Fatalf("outcome %s, suppressed %v, proposals %d → %d; want the decision honoured", res.Outcome, res.Suppressed != nil, before, proposalCount(repo))
	}
	if res.Asset.ID != z.ID {
		t.Errorf("resolved to %s, want Z %s — the asset the earlier proposal was opened FOR (A is %s, B is %s)", res.Asset.ID, z.ID, a.Asset.ID, b.Asset.ID)
	}
	if res.DecidedBy != identity.KindMACAddress {
		t.Errorf("DecidedBy = %s, want mac_address, Z's own identifier", res.DecidedBy)
	}
}

// New evidence is a new question. A reviewer who weighed a serial against a
// hostname never saw an SSH host key; a conflict that now carries one is
// proposed again.
func TestNewEvidenceReopensAKeptSeparatePair(t *testing.T) {
	e, repo := newEngine(t, identity.Config{})
	_, b, o, _ := keptSeparatePair(t, e, repo)
	// B now also has a host key.
	key := id(identity.KindSSHHostKeyFingerprint, "SHA256:bkey")
	mustResolve(t, e, obs(assetclass.KeyServer, scoped(identity.KindHostname, "host-1", "segment-1"), key))
	before := proposalCount(repo)

	o.Identifiers = append(o.Identifiers, key)
	o.ObservedAt = observedAt.Add(3 * time.Hour)
	res := mustResolve(t, e, o)
	if res.Suppressed != nil {
		t.Fatalf("a conflict carrying a kind the reviewer never saw was suppressed on their earlier decision (resolved to %s, B is %s)", res.Asset.ID, b.Asset.ID)
	}
	if res.Outcome != identity.OutcomeConflict || proposalCount(repo) != before+1 {
		t.Errorf("outcome %s, proposals %d → %d; want a fresh proposal", res.Outcome, before, proposalCount(repo))
	}
}

// Decision memory outranks the auto-accept threshold: a model scoring a pair
// 1.0 does not overturn a human who said no.
func TestKeptSeparateIsNeverAutoMerged(t *testing.T) {
	m := &stubMatcher{scores: map[string]float64{}}
	e, repo := newEngine(t, identity.Config{Matcher: m, AutoAcceptThreshold: 0.5})
	a, b, o, _ := keptSeparatePair(t, e, repo)
	m.scores[a.Asset.ID] = 1.0
	m.scores[b.Asset.ID] = 0.9
	before := proposalCount(repo)

	o.ObservedAt = observedAt.Add(2 * time.Hour)
	res := mustResolve(t, e, o)
	if res.AutoAccepted || res.Proposal.ID != "" || proposalCount(repo) != before {
		t.Fatalf("auto_accepted=%v proposal=%q proposals %d → %d; a kept-separate pair was merged on a score", res.AutoAccepted, res.Proposal.ID, before, proposalCount(repo))
	}
	if res.Suppressed == nil {
		t.Error("the resolution does not say the decision was honoured")
	}
	if res.Asset.ID == a.Asset.ID {
		t.Errorf("resolved to A %s, the matcher's favourite; the reviewer overruled the serial's claim", a.Asset.ID)
	}
}

// A single candidate is not a pair. Since A1 a single-owner floor opens
// no proposal at all — it is supporting evidence — but a LEGACY one-candidate
// proposal (opened before A1, then kept separate by a reviewer) must still not
// be read back as a decision about anything.
func TestDecisionMemoryNeedsAPair(t *testing.T) {
	e, repo := newEngine(t, identity.Config{})
	cloud := mustResolve(t, e, obs(assetclass.KeyCloudResource,
		id(identity.KindCloudResourceID, "arn:aws:ec2:us-east-1:1:instance/i-1"),
		id(identity.KindMACAddress, "aa:bb:cc:dd:ee:01"),
	))
	macOnly := obs(assetclass.KeyCloudResource, id(identity.KindMACAddress, "aa:bb:cc:dd:ee:01"))
	first := mustResolve(t, e, macOnly)
	if first.Outcome != identity.OutcomeSupporting || first.Proposal.ID != "" || proposalCount(repo) != 0 {
		t.Fatalf("fixture: outcome %s, proposal %q, %d proposals; want supporting and no proposal",
			first.Outcome, first.Proposal.ID, proposalCount(repo))
	}

	// The legacy row, as a pre-A1 floor wrote it.
	legacy, err := repo.OpenMergeProposal(context.Background(), tenant, identity.MergeProposal{
		Candidates: []identity.MergeCandidate{{Ref: cloud.Asset, MatchedIdentifiers: []identity.Identifier{
			id(identity.KindMACAddress, "aa:bb:cc:dd:ee:01")}}},
		Source: macOnly.Source, Reason: "legacy single-candidate floor", ProposedAt: observedAt,
	})
	if err != nil {
		t.Fatalf("OpenMergeProposal(legacy): %v", err)
	}
	if err := repo.ResolveProposal(legacy, "kept_separate", "", observedAt.Add(time.Hour)); err != nil {
		t.Fatalf("ResolveProposal: %v", err)
	}
	res := mustResolve(t, e, macOnly)
	if res.Suppressed != nil {
		t.Errorf("a one-candidate proposal was treated as a pair decision and the observation was resolved to %s (the cloud resource is %s)", res.Asset.ID, cloud.Asset.ID)
	}
	if res.Outcome != identity.OutcomeSupporting {
		t.Errorf("outcome = %s, want supporting — the MAC is the cloud resource's and nothing else claims it", res.Outcome)
	}
}

// ── re-noting ──────────────────────────────────────────────────────────────

// A question already in the queue is not re-noted in history on every
// observation that asks it again.
func TestPendingProposalIsNotRenoted(t *testing.T) {
	e, repo := newEngine(t, identity.Config{})
	a, _, o := conflictingObservations(t, e, repo)
	first := mustResolve(t, e, o)
	if first.Outcome != identity.OutcomeConflict || first.Proposal.Reused {
		t.Fatalf("fixture: outcome %s, reused %v", first.Outcome, first.Proposal.Reused)
	}
	notes := func() int {
		n := 0
		for _, h := range repo.HistoryFor(a.Asset) {
			if h.Action == identity.ActionMergeProposed {
				n++
			}
		}
		return n
	}
	if notes() != 1 {
		t.Fatalf("after the first conflict A carries %d merge_proposed entries, want 1", notes())
	}

	for i := 2; i <= 4; i++ {
		o.ObservedAt = observedAt.Add(time.Duration(i) * time.Hour)
		again := mustResolve(t, e, o)
		if again.Proposal.ID != first.Proposal.ID {
			t.Fatalf("observation %d opened proposal %s beside %s", i, again.Proposal.ID, first.Proposal.ID)
		}
		if !again.Proposal.Reused {
			t.Errorf("observation %d: the reused proposal is not reported as reused", i)
		}
	}
	if notes() != 1 {
		t.Errorf("after four identical observations A carries %d merge_proposed entries, want 1: the question is in the queue once and the note about it belongs there once", notes())
	}
	if proposalCount(repo) != 1 {
		t.Errorf("%d proposals, want 1", proposalCount(repo))
	}
}

// ── B3: the announcer's own address in the frame ─────────────────────

const nodeOwnAddr = "192.0.2.10" // the node's own address in floatingFixture

// announcementWithOwnAddress is a node's frame that carries its OWN address
// beside the VIP it holds — what a sensor aggregating one node's ARP claims
// hands the engine.
func announcementWithOwnAddress() identity.Observation {
	o := arpAnnouncement()
	o.Identifiers = append(o.Identifiers, scoped(identity.KindIPAddress, nodeOwnAddr, identity.ScopeTenantDefault))
	return o
}

func ownerOfAddr(t *testing.T, repo *memory.Repository, addr, scope string) []identity.AssetRef {
	t.Helper()
	refs, err := repo.FindByIdentifier(context.Background(), tenant, identity.KindIPAddress, addr, scope)
	if err != nil {
		t.Fatalf("FindByIdentifier(%s): %v", addr, err)
	}
	return refs
}

// TestFloatingAddressWithTheAnnouncersOwnAddress is B3: node A's MAC announcing
// A's own address AND a VIP held by B. Before, A's own address disqualified the
// shape — every voting address had to be the holder's — so the frame was a
// cross-kind conflict and a proposal to merge the node with the service. Now
// it is the floating-address outcome: the observation lands on the VIP's
// asset, A's own address stays A's (re-attached there, not reported as
// declined), the announcement names the VIP only, and nobody is asked.
//
// Mutation check: make an announcer-owned address return false in
// floatingAddress (the pre-B3 rule) → a conflict and a proposal, and this
// fails.
func TestFloatingAddressWithTheAnnouncersOwnAddress(t *testing.T) {
	e, repo := newEngine(t, identity.Config{})
	node, vip := floatingFixture(t, e)
	before := proposalCount(repo)

	o := announcementWithOwnAddress()
	o.ObservedAt = observedAt.Add(time.Hour)
	res := mustResolve(t, e, o)

	if res.FloatingAddress == nil || res.Outcome != identity.OutcomeMatched {
		t.Fatalf("outcome %s, floating %v: a node announcing its own address beside a VIP is still a floating address",
			res.Outcome, res.FloatingAddress != nil)
	}
	if res.Asset.ID != vip.Asset.ID {
		t.Fatalf("resolved to %s, want the VIP's asset %s", res.Asset.ID, vip.Asset.ID)
	}
	if res.Proposal.ID != "" || proposalCount(repo) != before {
		t.Errorf("a proposal was opened (%d → %d)", before, proposalCount(repo))
	}

	// A's own address: still A's, not the VIP's, and written rather than declined.
	if refs := ownerOfAddr(t, repo, nodeOwnAddr, identity.ScopeTenantDefault); len(refs) != 1 || refs[0].ID != node.Asset.ID {
		t.Errorf("the node's own address is owned by %+v, want only the node %s", refs, node.Asset.ID)
	}
	for _, u := range res.Unattached {
		if u.Kind == identity.KindIPAddress && u.Value == nodeOwnAddr {
			t.Errorf("the node's own address is reported unattached; it was written to the node")
		}
	}
	if !hasKind(res.Unattached, identity.KindMACAddress) {
		t.Errorf("Unattached = %v, want the MAC reported, as before", res.Unattached)
	}

	// The VIP is recorded as hosted on A, and the announcement is about the
	// VIP alone: the node's own address never floated.
	recs := repo.Announcements(vip.Asset)
	if len(recs) != 1 || recs[0].Announcer.ID != node.Asset.ID {
		t.Fatalf("announcement records %+v, want one from the node", recs)
	}
	if got := recs[0].Latest.Addresses; len(got) != 1 || got[0] != vipAddr {
		t.Errorf("announced addresses = %v, want only the VIP %s", got, vipAddr)
	}
	if res.FloatingAddress.AnnouncerAssetID != node.Asset.ID {
		t.Errorf("announcer = %s, want %s", res.FloatingAddress.AnnouncerAssetID, node.Asset.ID)
	}
	var nodeNoted bool
	for _, h := range repo.HistoryFor(node.Asset) {
		if _, ok := h.Changes["announces"]; ok {
			if keys, _ := h.Changes["identifiers"].([]string); len(keys) == 1 {
				nodeNoted = true
			}
		}
	}
	if !nodeNoted {
		t.Error("the node's history does not record the announcement with its own address re-attached")
	}
}

// The L2-only qualifier holds with the announcer's own address in the frame:
// any other kind beside the node's MAC is still a genuine conflict. This is
// TestFloatingAddressL2OnlyIsExactlyMACAndIP on the widened shape.
func TestFloatingAddressWithOwnAddressStillL2Only(t *testing.T) {
	for _, kind := range identity.AllKinds() {
		if kind == identity.KindMACAddress || kind == identity.KindIPAddress {
			continue
		}
		t.Run(string(kind), func(t *testing.T) {
			e, repo := newEngine(t, identity.Config{})
			floatingFixture(t, e)
			before := proposalCount(repo)
			o := announcementWithOwnAddress()
			extra := identity.Identifier{Kind: kind, Value: "extra-" + string(kind), Confidence: 1}
			switch kind {
			case identity.KindFQDN:
				extra.Value = "extra.example.test"
			case identity.KindHostname:
				extra.Scope = identity.ScopeTenantDefault
			case identity.KindName:
				extra.Scope = assetclass.KeyUnknownHost
			case identity.KindCMDBSysID:
				extra.Scope = "profile-1"
			}
			o.Identifiers = append(o.Identifiers, extra)
			res := mustResolve(t, e, o)
			if res.FloatingAddress != nil {
				t.Errorf("an observation also carrying %s was treated as L2-only", kind)
			}
			if proposalCount(repo) != before+1 {
				t.Errorf("no proposal for the conflict an extra %s makes", kind)
			}
		})
	}
}

// A frame whose every address is the announcer's own has nothing floating in
// it: the node's MAC and its own address are plain corroboration, with no
// announcement recorded.
func TestFloatingAddressOwnAddressesAloneAreNotFloating(t *testing.T) {
	e, repo := newEngine(t, identity.Config{})
	node, vip := floatingFixture(t, e)
	o := obs(assetclass.KeyUnknownHost,
		id(identity.KindMACAddress, nodeMAC),
		scoped(identity.KindIPAddress, nodeOwnAddr, identity.ScopeTenantDefault))
	res := mustResolve(t, e, o)
	if res.FloatingAddress != nil || res.Asset.ID != node.Asset.ID || res.Outcome != identity.OutcomeMatched {
		t.Fatalf("outcome %s on %s (floating %v), want an ordinary match on the node %s",
			res.Outcome, res.Asset.ID, res.FloatingAddress != nil, node.Asset.ID)
	}
	if len(repo.Announcements(vip.Asset)) != 0 {
		t.Error("an announcement was recorded with no floating address in the frame")
	}
}

// TestFloatingAddressOwnAddressOnADynamicSegment traces the widened frame
// through a DHCP scope, where it meets the lease rule ( 1b) instead.
//
// In a dynamic scope neither address votes, so the walk never finds the
// cross-kind conflict and floatingAddress is never consulted: the frame is a
// match on the node by its MAC. The VIP must not follow that MAC. Two holders:
//
//   - a VIP record with a name and no device binding — holderLostALease
//     refuses it at any time;
//   - an IP-ONLY VIP record, which the lease rule WOULD move. What protects it
//     is history: the frame was first seen while the segment was static, the
//     widened rule recognised it as floating (before B3 it was a conflict and
//     a proposal, and left no such history), and AddressAnnounced then honours
//     that record after the segment is marked DHCP.
//
// Mutation check: revert the B3 widening → the static-phase frame opens a
// proposal and this fails (and with no floating history recorded, the
// dynamic-phase frame would then move the IP-only VIP to the node).
func TestFloatingAddressOwnAddressOnADynamicSegment(t *testing.T) {
	const seg = "seg-float"
	nodeAddr := scoped(identity.KindIPAddress, "192.0.2.40", seg)
	vip := scoped(identity.KindIPAddress, "192.0.2.240", seg)
	frame := func(at time.Time, dynamic bool) identity.Observation {
		o := obs(assetclass.KeyUnknownHost, id(identity.KindMACAddress, nodeMAC), nodeAddr, vip)
		o.Admission = identity.AdmissionEvidence{Direct: true}
		o.Attributes = map[string]any{"arp_gratuitous": true}
		o.ObservedAt = at
		if dynamic {
			o.DynamicScopes = map[string]bool{seg: true}
		}
		return o
	}

	for _, tt := range []struct {
		name       string
		holderIDs  []identity.Identifier
		staticSeen bool // the frame was seen while the segment was static
	}{
		{"a named VIP record", []identity.Identifier{id(identity.KindFQDN, "ingress.example.test"), vip}, false},
		{"an IP-only VIP record first seen on a static segment", []identity.Identifier{vip}, true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			e, repo := newEngine(t, identity.Config{})
			node := mustResolve(t, e, obs(assetclass.KeyServer, id(identity.KindMACAddress, nodeMAC), nodeAddr))
			holder := mustResolve(t, e, obs(assetclass.KeyUnknownHost, tt.holderIDs...))
			if node.Asset.ID == holder.Asset.ID {
				t.Fatal("setup: the node and the VIP resolved to one asset")
			}

			if tt.staticSeen {
				res := mustResolve(t, e, frame(observedAt.Add(time.Hour), false))
				if res.FloatingAddress == nil || proposalCount(repo) != 0 {
					t.Fatalf("static phase: outcome %s, floating %v, %d proposals; want the floating outcome and no proposal",
						res.Outcome, res.FloatingAddress != nil, proposalCount(repo))
				}
			}

			res := mustResolve(t, e, frame(observedAt.Add(2*time.Hour), true))

			if res.Outcome != identity.OutcomeMatched || res.Asset.ID != node.Asset.ID {
				t.Fatalf("dynamic phase: outcome %s on %s, want a match on the node %s by its MAC",
					res.Outcome, res.Asset.ID, node.Asset.ID)
			}
			if n := proposalCount(repo); n != 0 {
				t.Errorf("%d proposals, want 0", n)
			}
			if refs := ownerOfAddr(t, repo, "192.0.2.240", seg); len(refs) != 1 || refs[0].ID != holder.Asset.ID {
				t.Errorf("the VIP is owned by %+v, want still the VIP record %s: an announced address is not a lease",
					refs, holder.Asset.ID)
			}
			if refs := ownerOfAddr(t, repo, "192.0.2.40", seg); len(refs) != 1 || refs[0].ID != node.Asset.ID {
				t.Errorf("the node's own address is owned by %+v, want the node %s", refs, node.Asset.ID)
			}
			for _, h := range repo.History() {
				if h.Action == identity.ActionIdentifierReassigned && h.Changes["reason"] == identity.ReasonLeaseMoved {
					t.Errorf("a lease_moved entry was written on %s", h.AssetID)
				}
			}
		})
	}
}
