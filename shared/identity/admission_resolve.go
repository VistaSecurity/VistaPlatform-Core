package identity

import (
	"context"
	"fmt"
)

// ObservationRepository is implemented by durable repositories. Rollout stays
// disabled until every consumer understands resolutions without an asset.
type ObservationRepository interface {
	AdmissionMode(context.Context, string) (string, error)
	StoreObservation(context.Context, Observation, AdmissionDecision) (string, error)
	FinishObservation(context.Context, Observation, string, Resolution, AdmissionDecision, bool) error
	PreserveObservationDismissal(context.Context, Observation, string, AdmissionDecision) (bool, error)
}

func (e *Engine) Resolve(ctx context.Context, obs Observation) (Resolution, error) {
	obs = canonicalSensorIdentity(obs)
	if locker, ok := e.repo.(interface {
		LockIdentifiers(context.Context, string, []Identifier) error
	}); ok {
		ids := make([]Identifier, 0, len(obs.Identifiers))
		for _, raw := range obs.Identifiers {
			id, err := raw.Normalized()
			if err != nil {
				return Resolution{}, fmt.Errorf("%w: %w", ErrInvalidObservation, err)
			}
			ids = append(ids, id)
		}
		if err := locker.LockIdentifiers(ctx, obs.TenantID, ids); err != nil {
			return Resolution{}, err
		}
	}
	recorder, ok := e.repo.(ObservationRepository)
	if !ok {
		return e.resolve(ctx, obs)
	}
	mode, err := recorder.AdmissionMode(ctx, obs.TenantID)
	if err != nil {
		return Resolution{}, err
	}
	if mode == "disabled" {
		return e.resolve(ctx, obs)
	}
	if mode != "observe" && mode != "enforce" && mode != "paused" {
		return Resolution{}, fmt.Errorf("unknown identity admission mode %q", mode)
	}
	// The foundation release records evidence in observe mode. Enforcement is
	// deliberately unavailable until all ingest consumers and decision actions
	// have shipped; a database setting alone must not enable a partial feature.
	if (mode == "enforce" || mode == "paused") && !e.admissionEnabled {
		return Resolution{}, fmt.Errorf("identity admission enforcement is not available in this release")
	}
	// Preserve the producer's clock for replay. Intake adapters without one
	// need to supply their stable discovery creation time, not a retry time.
	if obs.ObservedAt.IsZero() {
		return Resolution{}, fmt.Errorf("durable identity admission requires observation time")
	}
	// A configured dynamic scope is as uncertain as one supplied by the
	// adapter. Assess admission with the same union the matcher uses.
	assessment := obs
	assessment.DynamicScopes = make(map[string]bool, len(e.dynamic)+len(obs.DynamicScopes))
	for scope, dynamic := range e.dynamic {
		assessment.DynamicScopes[scope] = dynamic
	}
	for scope, dynamic := range obs.DynamicScopes {
		assessment.DynamicScopes[scope] = assessment.DynamicScopes[scope] || dynamic
	}
	decision := AssessAdmission(assessment)
	id, err := recorder.StoreObservation(ctx, obs, decision)
	if err != nil {
		return Resolution{}, err
	}
	if mode == "paused" {
		return Resolution{Outcome: OutcomeUnresolved, ObservationID: id}, nil
	}
	// A dismissed sighting is retained successfully but must not reach matching:
	// even a newly available weak alias owner would otherwise refresh an asset.
	dismissed, err := recorder.PreserveObservationDismissal(ctx, obs, id, decision)
	if err != nil {
		return Resolution{}, err
	}
	if dismissed {
		return Resolution{Outcome: OutcomeUnresolved, ObservationID: id}, nil
	}

	engine := e
	if mode == "enforce" {
		engine = e.WithAutoAcceptThreshold(0)
		engine.admissionDecision = &decision
		// The evidence row this resolution is for, so the history entries the
		// provisional rules write can name it. It is set on the per-observation
		// COPY WithAutoAcceptThreshold just made, never on the shared engine.
		engine.observationID = id
		settled, err := engine.resolveConfirmedLink(ctx, obs, id, decision)
		if err != nil {
			return Resolution{}, err
		}
		if settled != nil {
			settled.ObservationID = id
			if err := recorder.FinishObservation(ctx, obs, id, *settled, decision, true); err != nil {
				return Resolution{}, err
			}
			return *settled, nil
		}
	}
	res, err := engine.resolve(ctx, obs)
	if err != nil {
		return Resolution{}, err
	}
	res.ObservationID = id
	if err := recorder.FinishObservation(ctx, obs, id, res, decision, mode == "enforce"); err != nil {
		return Resolution{}, err
	}
	return res, nil
}
