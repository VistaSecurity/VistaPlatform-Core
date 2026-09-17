package identity

// Two rules that live beside the precedence walk of [Engine.Resolve]: the
// floating-address rule, and decision memory.
//
// # Floating addresses
//
// ADR-0002 D3's premise for `mac_address` is that a MAC has exactly one owning
// asset: it ranks above every name and address kind, and the unique index of
// DATA_MODEL §2 lets it belong to one asset. First-hop redundancy breaks that
// premise on purpose. MetalLB in L2 mode, kube-vip, keepalived, Windows NLB,
// VRRP, HSRP and CARP all put a FLOATING address on the wire — announced, by
// gratuitous ARP, from whichever node currently holds it, using that node's
// own NIC. The sensor decodes the announcement correctly: "MAC of node X, at
// address Y". Ingest turns both into identifiers. The walk then finds the MAC
// on X's asset and the address on Y's, and calls it a cross-kind conflict.
//
// It is not a conflict. It is "X announces Y's address", and a merge proposal
// for it — scored 0.84 by the matcher, because a MAC is a strong kind — asks a
// human to consider merging a Kubernetes node with the service that floats
// across the cluster. On the dev cluster the proposal was re-raised three
// times; on an enterprise network with daily auto-scan it would never stop.
//
// The rule: when an observation is L2-ONLY — its evidence is nothing but a MAC
// and addresses, measured on the wire — and its MAC resolves to one asset while
// its addresses resolve to a different one, the observation is of the ADDRESS
// holder. It lands there, WITHOUT the MAC (deliberately unattached, and
// reported as such), the announcement is recorded as a relationship between
// the two assets so the knowledge is not lost, both assets get history, and no
// proposal is opened.
//
// The qualifier is load-bearing and pinned by [isL2Only]: an observation that
// carries the MAC of X PLUS a stronger identifier of Y — an SSH host key, a
// serial, an agent id — or a name of Y is a re-imaged, cloned or spoofed host,
// and that IS a conflict a human has to see.
//
// # Decision memory
//
// `kept_separate` used to be write-only. A reviewer's "these are different
// things" stamped the proposal row and nothing in this package ever read it, so
// the next observation of unchanged evidence opened the same proposal again.
// [Engine.priorDecision] reads it back before any proposal is opened, and a
// pair a human has already answered for — on the same kinds of evidence — is
// resolved without asking again ([Resolution.Suppressed]).

import (
	"context"
	"fmt"
	"time"
)

// FloatingAddress is set on a [Resolution] when the floating-address rule
// decided it: the observation landed on the asset that HOLDS the address, and
// the asset whose NIC announced it is named here.
type FloatingAddress struct {
	// AnnouncerAssetID is the asset the observation's MAC belongs to.
	AnnouncerAssetID string `json:"announcer_asset_id"`
	// Announcement is what was recorded between the two assets.
	Announcement Announcement `json:"announcement"`
}

// SuppressedProposal is set on a [Resolution] when a merge proposal would have
// been opened and was not, because a reviewer already resolved one for the
// same assets on the same kinds of evidence as `kept_separate`.
type SuppressedProposal struct {
	// ProposalID is the earlier proposal whose decision was honoured.
	ProposalID string `json:"proposal_id"`
	// DecidedAt and DecidedBy are the reviewer's decision, as recorded.
	DecidedAt time.Time `json:"decided_at,omitzero"`
	DecidedBy string    `json:"decided_by,omitempty"`
	// Candidates are the assets the proposal would have named.
	Candidates []string `json:"candidates"`
	// Reason is the conflict that would have been reported.
	Reason string `json:"reason"`
}

// l2OnlyKinds are the identifier kinds an L2-only observation may carry: what
// an ARP frame says about its sender, and nothing more. Every other kind — a
// name, a host key, a serial, an agent or cloud id — is evidence about WHICH
// host this is beyond "the one at this MAC and this address", and its presence
// alongside a foreign MAC is a real contradiction.
//
// mDNS, NetBIOS, LLDP and CDP observations qualify too when they carry only a
// MAC and addresses: the source protocol is not the test, the evidence is. An
// LLDP frame that names the chassis has named it, and is not L2-only.
var l2OnlyKinds = map[Kind]bool{
	KindMACAddress: true,
	KindIPAddress:  true,
}

// isL2Only reports whether an observation is nothing but a measured MAC-to-
// address binding.
//
// Three conditions:
//
//   - the source is MEASURED. An imported spreadsheet row or a declared
//     (typed) asset that pairs one asset's MAC with another's address is a
//     question for a human, not a fact about the wire;
//   - every identifier is a mac_address or an ip_address;
//   - there is at least one of each. A MAC alone or an address alone cannot
//     be a floating-address observation, and the walk never reaches the rule
//     with either.
func isL2Only(obs Observation, ids []Identifier) bool {
	if obs.Source.Kind != SourceMeasured {
		return false
	}
	var macs, addrs int
	for _, id := range ids {
		if !l2OnlyKinds[id.Kind] {
			return false
		}
		switch id.Kind {
		case KindMACAddress:
			macs++
		case KindIPAddress:
			addrs++
		}
	}
	return macs > 0 && addrs > 0
}

// floatingPair is the shape [Engine.floatingAddress] recognised: the asset the
// MAC belongs to and the asset the addresses belong to.
type floatingPair struct {
	announcer, holder string
	macs, addresses   []string
}

// floatingAddress recognises the floating-address shape after the precedence
// walk has found a cross-kind conflict.
//
// It is deliberately narrow. Every voting MAC must resolve to one asset (the
// announcer) and every voting address to one OTHER asset (the holder); a second
// MAC belonging to nobody, or an address belonging to a third asset, is not
// this shape and falls through to the ordinary conflict. The store must also
// be healthy — a MAC owned by two assets is the lost-invariant case the walk
// already flagged, and no rule should paper over it.
func (e *Engine) floatingAddress(obs Observation, ids []Identifier, owners map[string][]AssetRef, decided string, decidedBy Kind, candidateSeq []string) (floatingPair, bool) {
	if !isL2Only(obs, ids) {
		return floatingPair{}, false
	}
	if decidedBy != KindMACAddress || len(candidateSeq) != 2 || candidateSeq[0] != decided {
		return floatingPair{}, false
	}
	p := floatingPair{announcer: candidateSeq[0], holder: candidateSeq[1]}
	for _, id := range ids {
		if !e.kindVotes(obs, id) {
			continue
		}
		refs := owners[id.Key()]
		if len(refs) == 0 {
			// An unowned identifier would be ATTACHED by whichever asset wins.
			// A MAC nobody owns arriving with a foreign address is not the
			// announcement shape, and an unowned address beside an owned one
			// might be a second VIP that is its own thing.
			return floatingPair{}, false
		}
		if len(refs) != 1 {
			return floatingPair{}, false
		}
		switch id.Kind {
		case KindMACAddress:
			if refs[0].ID != p.announcer {
				return floatingPair{}, false
			}
			p.macs = append(p.macs, id.Value)
		case KindIPAddress:
			if refs[0].ID != p.holder {
				return floatingPair{}, false
			}
			p.addresses = append(p.addresses, id.Value)
		default:
			// Unreachable: isL2Only above admits only the two kinds. It is
			// deliberately NOT a second refusal — a duplicate guard here would
			// mask a broken isL2Only from the tests that pin it, and one rule
			// should have one place.
			continue
		}
	}
	if len(p.macs) == 0 || len(p.addresses) == 0 {
		return floatingPair{}, false
	}
	return p, true
}

// gratuitousARP reads the corroborating attribute the ARP decoder sets when the
// sender and target protocol addresses agree — the host CLAIMING the address.
// An absent attribute is "not stated", never false.
func gratuitousARP(obs Observation) bool {
	v, ok := obs.Attributes["arp_gratuitous"]
	if !ok {
		return false
	}
	b, isBool := v.(bool)
	return isBool && b
}

// resolveFloating writes the floating-address outcome.
//
// The observation lands on the HOLDER — the asset at the announced address —
// because that is what the frame was about: the service at the VIP was seen,
// reachable, at that address. The announcer's MAC is reported unattached, not
// silently skipped, and would be refused by the unique index anyway. The
// announcer is touched too: its NIC sent the frame, so it was on the wire.
func (e *Engine) resolveFloating(ctx context.Context, obs Observation, at time.Time, ids []Identifier, owners map[string][]AssetRef, p floatingPair) (Resolution, error) {
	holder := AssetRef{TenantID: obs.TenantID, ID: p.holder}
	announcer := AssetRef{TenantID: obs.TenantID, ID: p.announcer}
	ann := Announcement{
		MACs:       p.macs,
		Addresses:  p.addresses,
		Gratuitous: gratuitousARP(obs),
		Source:     obs.Source,
		At:         at,
	}
	evidence := map[string]any{
		"macs":           ann.MACs,
		"addresses":      ann.Addresses,
		"gratuitous_arp": ann.Gratuitous,
	}

	// splitByOwner puts the MACs — the announcer's — in unattached. That is
	// the deliberate skip: the holder must not acquire the node's MAC.
	attach, unattached := splitByOwner(ids, owners, holder.ID)
	holderChanges := map[string]any{
		"decided_by": string(KindIPAddress),
		"floating_address": map[string]any{
			"announcer_asset_id": announcer.ID,
			"macs":               ann.MACs,
			"addresses":          ann.Addresses,
			"gratuitous_arp":     ann.Gratuitous,
		},
	}
	if err := e.applyToAsset(ctx, holder, obs, at, attach, unattached, ActionUpdated, holderChanges); err != nil {
		return Resolution{}, err
	}

	if err := e.repo.RecordAnnouncement(ctx, announcer, holder, ann); err != nil {
		return Resolution{}, fmt.Errorf("identity: recording that %s announces %s's address: %w", announcer.ID, holder.ID, err)
	}
	if err := e.repo.Touch(ctx, announcer, at); err != nil {
		return Resolution{}, fmt.Errorf("identity: touching announcer %s: %w", announcer.ID, err)
	}
	announcerChanges := map[string]any{
		"announces": map[string]any{
			"asset_id":       holder.ID,
			"macs":           evidence["macs"],
			"addresses":      evidence["addresses"],
			"gratuitous_arp": evidence["gratuitous_arp"],
		},
	}
	if err := e.history(ctx, announcer, obs, at, ActionUpdated, announcerChanges); err != nil {
		return Resolution{}, err
	}

	return Resolution{
		Outcome:    OutcomeMatched,
		Asset:      holder,
		DecidedBy:  KindIPAddress,
		Unattached: unattached,
		FloatingAddress: &FloatingAddress{
			AnnouncerAssetID: announcer.ID,
			Announcement:     ann,
		},
	}, nil
}

// priorDecision is decision memory: the `kept_separate` answer a reviewer
// already gave for these candidates, on this evidence, or nil.
//
// Two gates beyond the store's own lookup, both here so they are testable
// without a database:
//
//   - a proposal is about a PAIR. One candidate is not a pair, and a decision
//     that "this observation is not that asset" says nothing about the next
//     observation to share an identifier with it;
//   - the evidence must be the same KINDS or a subset. A reviewer who weighed a
//     MAC against an address did not weigh an SSH host key; a conflict that now
//     carries one is a new question, and the same pair gets a new proposal.
func (e *Engine) priorDecision(ctx context.Context, obs Observation, candidates []MergeCandidate) (*PriorDecision, error) {
	if len(candidates) < 2 {
		return nil, nil
	}
	ids := candidateIDs(candidates)
	d, ok, err := e.repo.LastKeptSeparate(ctx, obs.TenantID, ids)
	if err != nil {
		return nil, fmt.Errorf("identity: reading prior decisions for %v: %w", ids, err)
	}
	if !ok || !d.Covers(ids) {
		return nil, nil
	}
	// The identifiers that matched the earlier proposal's OWN observation
	// asset are not evidence about the pair: they are what that asset was
	// created carrying, and the reviewer saw them as its identity. Only the
	// kinds pointing at the other candidates are compared.
	if !d.SameEvidence(evidenceKinds(candidates, d.ObservationAssetID)) {
		return nil, nil
	}
	return &d, nil
}

// evidenceKinds are the identifier kinds that matched any candidate other than
// `except` — the kinds a reviewer would be shown as the reason for a proposal.
func evidenceKinds(candidates []MergeCandidate, except string) []Kind {
	seen := map[Kind]bool{}
	var out []Kind
	for _, c := range candidates {
		if except != "" && c.Ref.ID == except {
			continue
		}
		for _, id := range c.MatchedIdentifiers {
			if !seen[id.Kind] {
				seen[id.Kind] = true
				out = append(out, id.Kind)
			}
		}
	}
	return out
}

// resolveSuppressed resolves an observation whose conflict a reviewer already
// settled, without re-asking.
//
// Which asset it lands on:
//
//   - the earlier proposal's OBSERVATION asset, when it had one and it is
//     among today's candidates. That asset was created to be exactly this
//     observation, and the reviewer said it is distinct from the others;
//   - otherwise — a floor proposal that created nothing — the candidate the
//     WEAKEST evidence points at. The reviewer's "no" was an answer to the
//     strong kind's claim (the MAC that said "this is the node"), so that is
//     the claim set aside, and the address or name that remains says where the
//     observation belongs. The lowest-precedence match is that asset.
//
// Identifiers owned by the other candidates are reported unattached, as on
// any match; nothing is taken from them.
func (e *Engine) resolveSuppressed(ctx context.Context, obs Observation, at time.Time, ids []Identifier, owners map[string][]AssetRef, candidates []MergeCandidate, d PriorDecision, why string) (Resolution, error) {
	target, decidedBy := suppressedTarget(candidates, d)
	attach, unattached := splitByOwner(ids, owners, target.Ref.ID)
	suppressed := &SuppressedProposal{
		ProposalID: d.ProposalID,
		DecidedAt:  d.DecidedAt,
		DecidedBy:  d.DecidedBy,
		Candidates: candidateIDs(candidates),
		Reason:     why,
	}
	changes := map[string]any{
		"decided_by": string(decidedBy),
		"suppressed_proposal": map[string]any{
			"proposal_id": d.ProposalID,
			"status":      "kept_separate",
			"decided_at":  d.DecidedAt,
			"decided_by":  d.DecidedBy,
			"candidates":  suppressed.Candidates,
			"conflict":    why,
		},
	}
	if err := e.applyToAsset(ctx, target.Ref, obs, at, attach, unattached, ActionUpdated, changes); err != nil {
		return Resolution{}, err
	}
	return Resolution{
		Outcome:    OutcomeMatched,
		Asset:      target.Ref,
		DecidedBy:  decidedBy,
		Candidates: candidates,
		Unattached: unattached,
		Suppressed: suppressed,
	}, nil
}

// suppressedTarget picks the asset a suppressed conflict resolves to (see
// [Engine.resolveSuppressed]) and the kind that decided it.
func suppressedTarget(candidates []MergeCandidate, d PriorDecision) (MergeCandidate, Kind) {
	if d.ObservationAssetID != "" {
		for _, c := range candidates {
			if c.Ref.ID == d.ObservationAssetID {
				return c, strongestKind(c.MatchedIdentifiers)
			}
		}
	}
	// The candidate whose BEST evidence is the weakest. Ties go to the later
	// candidate, which the walk found later, i.e. by a later kind.
	best, bestRank := candidates[0], -1
	for _, c := range candidates {
		rank := kindRank(strongestKind(c.MatchedIdentifiers))
		if rank >= bestRank {
			best, bestRank = c, rank
		}
	}
	return best, strongestKind(best.MatchedIdentifiers)
}

// strongestKind is the highest-precedence kind among these identifiers, in the
// default order — the kind a reviewer would name as the reason.
func strongestKind(ids []Identifier) Kind {
	var best Kind
	bestRank := len(allKinds) + 1
	for _, id := range ids {
		if r := kindRank(id.Kind); r < bestRank {
			best, bestRank = id.Kind, r
		}
	}
	return best
}

// kindRank is a kind's position in the whole vocabulary, default precedence
// first; an unknown kind ranks last.
func kindRank(k Kind) int {
	for i, known := range allKinds {
		if k == known {
			return i
		}
	}
	return len(allKinds)
}
