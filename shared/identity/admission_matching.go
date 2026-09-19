package identity

import "context"

// A shared name/address cannot establish that a new interface belongs to a
// known device. Stronger matches (agent, serial, provider) may legitimately add
// another interface and never reach this guard.
func (e *Engine) interfaceBindingConflict(ctx context.Context, ids []Identifier, ref AssetRef) (bool, error) {
	observed := map[string]bool{}
	for _, id := range ids {
		if id.Kind == KindMACAddress {
			observed[id.Value] = true
		}
	}
	if len(observed) == 0 {
		return false, nil
	}
	summaries, err := e.repo.LoadSummaries(ctx, ref.TenantID, []string{ref.ID})
	if err != nil {
		return false, err
	}
	hasKnown := false
	for _, summary := range summaries {
		for _, id := range summary.Identifiers {
			if id.Kind == KindMACAddress {
				hasKnown = true
				if observed[id.Value] {
					return false, nil
				}
			}
		}
	}
	return hasKnown, nil
}
