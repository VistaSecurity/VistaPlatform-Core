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

// A single candidate is not a pair: decision memory does not apply, and the
// floor's single-candidate proposal keeps today's behaviour.
func TestDecisionMemoryNeedsAPair(t *testing.T) {
	e, repo := newEngine(t, identity.Config{})
	cloud := mustResolve(t, e, obs(assetclass.KeyCloudResource,
		id(identity.KindCloudResourceID, "arn:aws:ec2:us-east-1:1:instance/i-1"),
		id(identity.KindMACAddress, "aa:bb:cc:dd:ee:01"),
	))
	macOnly := obs(assetclass.KeyCloudResource, id(identity.KindMACAddress, "aa:bb:cc:dd:ee:01"))
	first := mustResolve(t, e, macOnly)
	if first.Outcome != identity.OutcomeConflict || len(first.Candidates) != 1 {
		t.Fatalf("fixture: outcome %s with %d candidates; want the single-candidate floor proposal", first.Outcome, len(first.Candidates))
	}
	if err := repo.ResolveProposal(first.Proposal, "kept_separate", "", observedAt.Add(time.Hour)); err != nil {
		t.Fatalf("ResolveProposal: %v", err)
	}
	res := mustResolve(t, e, macOnly)
	if res.Suppressed != nil {
		t.Errorf("a one-candidate proposal was treated as a pair decision and the observation was resolved to %s (the cloud resource is %s)", res.Asset.ID, cloud.Asset.ID)
	}
	if res.Outcome != identity.OutcomeConflict {
		t.Errorf("outcome = %s, want conflict — nothing else can take this observation", res.Outcome)
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
