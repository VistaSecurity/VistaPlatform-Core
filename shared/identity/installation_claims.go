package identity

// A host describing itself, decided by the installation identity we issued.
//
// A sensor's self-report and a device agent's host inventory are the host
// reading its own configuration over a session the platform authenticated,
// and the walk decides them by `sensor_id` / `agent_id`: an identifier the
// platform minted for exactly one installation. The asset that holds it IS
// that installation's host. Nothing weaker in the same report can make it
// someone else.
//
// What a weaker identifier CAN say is that another asset is the same machine.
// A laptop's Ethernet and Wi-Fi NICs are met passively on two segments and
// recorded as two assets; the laptop's own report lists both MACs. Before this
// rule the walk saw two owners and took the conflict path: the report was
// attached to NEITHER asset (the host stopped being refreshed by its own
// sensor until a person answered) — or, when the second NIC's identifier did
// not vote for the class, it was dropped as Unattached with no proposal at
// all, and the two records never met.
//
// Now the report stays matched to the installation's asset, and every OTHER
// asset it links to — through an identifier that voted in the walk, or a
// burned-in MAC the host reports as its own — is named in a merge proposal
// beside it. ADR-0002 D5 is unchanged: nothing merges here, the other asset's
// identifiers stay where they are, neither asset's status changes (the
// proposal names no observation asset), a pair a reviewer kept separate is not
// asked about again, and the rule-merge executor acts only on a tenant's own
// opt-in.

import (
	"context"
	"fmt"
	"time"
)

// installationDecides reports whether a decided match is the installation
// rule's: a first-hand, authoritative measurement (claimsFirstHand) whose walk
// was decided by an installation identity.
func installationDecides(obs Observation, decidedBy Kind) bool {
	return (decidedBy == KindSensorID || decidedBy == KindAgentID) && claimsFirstHand(obs.Source, obs.Admission)
}

// installationProposal is what [Engine.proposeSameInstallation] adds to the
// installation's match.
type installationProposal struct {
	candidates       []MergeCandidate
	proposal         ProposalRef
	topScore         float64
	mergeRecommended bool
	suppressed       *SuppressedProposal
}

// proposeSameInstallation opens the merge proposal for an installation match
// that links to other assets (see the file header), or does nothing when it
// links to none.
//
// The other candidates are, in walk order, every asset an identifier VOTED
// for (walkEvidence/walkOrder — what the conflict path would have proposed),
// then every owner of a burned-in MAC the report could not attach (a MAC the
// class does not vote on still names a chassis).
func (e *Engine) proposeSameInstallation(
	ctx context.Context,
	obs Observation,
	at time.Time,
	ref AssetRef,
	decidedBy Kind,
	ids []Identifier,
	owners map[string][]AssetRef,
	walkEvidence map[string][]Identifier,
	walkOrder []string,
	unattached []Identifier,
) (installationProposal, error) {
	evidence := map[string][]Identifier{}
	var order []string
	add := func(assetID string, id Identifier) {
		if assetID == ref.ID {
			return
		}
		if _, seen := evidence[assetID]; !seen {
			order = append(order, assetID)
		}
		for _, have := range evidence[assetID] {
			if have.Key() == id.Key() {
				return
			}
		}
		evidence[assetID] = append(evidence[assetID], id)
	}
	for _, assetID := range walkOrder {
		for _, id := range walkEvidence[assetID] {
			add(assetID, id)
		}
	}
	for _, id := range unattached {
		if id.Kind != KindMACAddress || id.Inferred() {
			continue
		}
		for _, owner := range owners[id.Key()] {
			add(owner.ID, id)
		}
	}
	// B2: a generic name alone ties nothing to anything.
	order = withoutGenericOnly(order, evidence)
	if len(order) == 0 {
		return installationProposal{}, nil
	}

	candidates := make([]MergeCandidate, 0, len(order)+1)
	candidates = append(candidates, MergeCandidate{Ref: ref, MatchedIdentifiers: matchedAgainst(ids, owners, ref.ID)})
	for _, assetID := range order {
		candidates = append(candidates, MergeCandidate{
			Ref:                AssetRef{TenantID: obs.TenantID, ID: assetID},
			MatchedIdentifiers: evidence[assetID],
		})
	}
	var linked []Identifier
	for _, assetID := range order {
		linked = append(linked, evidence[assetID]...)
	}
	why := fmt.Sprintf("this host's own report, matched to %s by its %s, also names %v, which another asset holds — the two records may be one machine",
		ref.ID, decidedBy, identifierKeys(linked))

	// Decision memory: a pair a person kept separate is not asked about
	// again on the same kinds of evidence.
	prior, keptApart, err := e.keptSeparate(ctx, obs, candidates)
	if err != nil {
		return installationProposal{}, err
	}
	if keptApart {
		if d := prior.appliesTo(candidates); d != nil {
			return installationProposal{
				candidates: candidates,
				suppressed: &SuppressedProposal{
					ProposalID: d.ProposalID,
					DecidedAt:  d.DecidedAt,
					DecidedBy:  d.DecidedBy,
					Candidates: candidateIDs(candidates),
					Reason:     why,
				},
			}, nil
		}
	}

	r, err := e.rank(ctx, obs, at, candidates)
	if err != nil {
		return installationProposal{}, err
	}
	r = e.withSameDeviceVerdict(obs, r, keptApart)
	proposal, err := e.openMergeProposal(ctx, obs.TenantID, r, MergeProposal{
		// No ObservationAssetID: the installation's asset is matched, not a
		// pending observation, and must not be pinned to pending_approval.
		Candidates:   r.candidates,
		Source:       obs.Source,
		Reason:       why,
		ProposedAt:   at,
		ModelID:      rankedBy(r.top).ModelID,
		SourceRef:    rankedBy(r.top).SourceRef,
		RuleVerdict:  r.ruleVerdict(),
		RuleEvidence: r.ruleEvidence,
	})
	if err != nil {
		return installationProposal{}, fmt.Errorf("identity: opening the merge proposal for %s's own report: %w", ref.ID, err)
	}
	// One pointer entry per question, as proposeWithoutCreating writes it: an
	// hourly self-report re-asking a pending question folds its evidence into
	// the proposal and writes no further history.
	if !proposal.Reused {
		if err := e.history(ctx, ref, obs, at, ActionMergeProposed, map[string]any{
			"proposal_id": proposal.ID,
			"candidates":  candidateIDs(r.candidates),
			"reason":      why,
			"contested":   identifierKeys(linked),
			"created":     false,
		}); err != nil {
			return installationProposal{}, err
		}
	}
	return installationProposal{
		candidates:       r.candidates,
		proposal:         proposal,
		topScore:         topScore(r.top),
		mergeRecommended: r.mergeRecommended(),
	}, nil
}
