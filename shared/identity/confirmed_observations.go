package identity

import (
	"context"
	"sort"
)

// resolveConfirmedLink follows explicit decisions without making their weak
// aliases identifiers. A changed fingerprint requires device corroboration;
// shared names or addresses merely open a review question.
func (e *Engine) resolveConfirmedLink(ctx context.Context, obs Observation, observationID string, decision AdmissionDecision) (*Resolution, error) {
	reader, ok := e.repo.(interface {
		ConfirmedObservationLinks(context.Context, Observation, string) ([]ConfirmedObservationLink, error)
	})
	if !ok {
		return nil, nil
	}
	links, err := reader.ConfirmedObservationLinks(ctx, obs, observationID)
	if err != nil || len(links) == 0 {
		return nil, err
	}
	ids := make([]Identifier, 0, len(obs.Identifiers))
	for _, raw := range obs.Identifiers {
		id, err := raw.Normalized()
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	candidates := map[string]MergeCandidate{}
	trusted, exact := map[string]bool{}, map[string]bool{}
	for _, link := range links {
		candidate := candidates[link.Asset.ID]
		candidate.Ref = link.Asset
		exact[link.Asset.ID] = exact[link.Asset.ID] || (link.Exact && !link.Unavailable)
		for _, previous := range link.Identifiers {
			for _, id := range ids {
				if id.Key() != previous.Key() {
					continue
				}
				candidate.MatchedIdentifiers = append(candidate.MatchedIdentifiers, id)
				stable := id.Kind == KindMACAddress && obs.Admission.Direct && !obs.Admission.Relayed
				if obs.Admission.Authoritative {
					switch id.Kind {
					case KindAgentID, KindCloudResourceID, KindCMDBSysID, KindSerialNumber:
						stable = true
					}
				}
				trusted[link.Asset.ID] = trusted[link.Asset.ID] || (stable && !link.Unavailable)
			}
		}
		candidates[link.Asset.ID] = candidate
	}
	// Inspect every owner, including identifiers excluded from class precedence.
	// A previous human link never licenses stealing or ignoring another owner.
	owners := map[string][]AssetRef{}
	for _, id := range ids {
		refs, err := e.repo.FindByIdentifier(ctx, obs.TenantID, id.Kind, id.Value, id.Scope)
		if err != nil {
			return nil, err
		}
		owners[id.Key()] = refs
		for _, ref := range refs {
			candidate := candidates[ref.ID]
			candidate.Ref = ref
			candidate.MatchedIdentifiers = append(candidate.MatchedIdentifiers, id)
			candidates[ref.ID] = candidate
		}
	}
	if len(candidates) == 1 {
		for id, candidate := range candidates {
			if !decision.Established && exact[id] {
				// A replay acknowledges the decision without promoting names,
				// attaching aliases, or refreshing the asset's observation clock.
				return &Resolution{Outcome: OutcomeMatched, Asset: candidate.Ref}, nil
			}
			if trusted[id] {
				ref := candidate.Ref
				e.admissionCandidate = &ref
				return nil, nil
			}
		}
	}
	ordered := make([]string, 0, len(candidates))
	for id := range candidates {
		ordered = append(ordered, id)
	}
	sort.Strings(ordered)
	list := make([]MergeCandidate, 0, len(ordered))
	for _, id := range ordered {
		list = append(list, candidates[id])
	}
	if prior, err := e.priorDecision(ctx, obs, list); err != nil {
		return nil, err
	} else if prior != nil {
		res, err := e.resolveSuppressed(ctx, obs, obs.ObservedAt, ids, owners, list, *prior, "previous explicit observation link")
		return &res, err
	}
	ranked, err := e.rank(ctx, obs, obs.ObservedAt, list)
	if err != nil {
		return nil, err
	}
	res, err := e.proposeWithoutCreating(ctx, obs, obs.ObservedAt, ids, ranked, "evidence overlaps an explicitly linked observation; device corroboration or ownership requires review")
	return &res, err
}
