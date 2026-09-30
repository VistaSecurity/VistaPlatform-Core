package identity

import "context"

// ResolveContestedForTest exposes the floor's contested path to the external
// test package, so A1's belt-and-braces refusal — resolveContested never
// opens a proposal with fewer than two candidates — can be driven directly.
// Through Resolve both callers already route a single owner elsewhere, which
// is exactly why the belt needs a way in of its own: a guard no test can reach
// is a guard no test can prove.
// ResolveCreateForTest exposes the one create to the external test package, so
// Phase 2's guard 1 — an asset whose every identifier is derived is never
// written — can be proven at the INSERT itself and not only through Resolve's
// routing, which already sends such an observation to the floor.
func (e *Engine) ResolveCreateForTest(ctx context.Context, obs Observation, attach, unattached []Identifier) (Resolution, error) {
	return e.resolveCreate(ctx, obs, obs.ObservedAt, attach, unattached)
}

func (e *Engine) ResolveContestedForTest(ctx context.Context, obs Observation, ids []Identifier, owners map[string][]AssetRef) (Resolution, error) {
	return e.resolveContested(ctx, obs, obs.ObservedAt, ids, owners)
}

// ResolveConflictForTest exposes the cross-kind conflict path with evidence the
// caller chooses. Through Resolve a generic name never votes, so no candidate
// can reach resolveConflict linked by one alone — which is exactly why its
// B2 pruning needs a way in of its own.
func (e *Engine) ResolveConflictForTest(ctx context.Context, obs Observation, ids []Identifier, owners map[string][]AssetRef, evidence map[string][]Identifier, candidateSeq []string) (Resolution, error) {
	return e.resolveConflict(ctx, obs, obs.ObservedAt, ids, owners, evidence, candidateSeq, "test conflict")
}

// ProvisionalMatchModeForTest classifies a decided match against ref as an
// ESTABLISHED observation would, with provisional inventory on: "none",
// "corroborate" or "yield".
func (e *Engine) ProvisionalMatchModeForTest(ctx context.Context, ref AssetRef, matched []Identifier) (string, error) {
	cp := *e
	cp.provisional = true
	cp.admissionDecision = &AdmissionDecision{Established: true}
	mode, err := cp.provisionalMatchMode(ctx, ref, matched)
	return [...]string{"none", "corroborate", "yield"}[mode], err
}
