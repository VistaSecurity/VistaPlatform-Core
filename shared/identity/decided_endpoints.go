package identity

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// Endpoints of evidence a DECISION already tied to an asset ( WP7 F17).
//
// The engine writes an observation's endpoints when it matches, creates,
// provisionally creates, or (D4) supports a single live owner with a direct
// measurement. Four other decisions tie evidence to an asset without the
// precedence walk, and each owes the asset the evidence's sockets:
//
//   - an operator's Link or Confirm of an observation the engine held
//     (platform ADR-0003 D2: the person's decision is the attachment the
//     engine declined to make);
//   - an interrogated device's own finding, whose address inventory-service
//     verified belongs to the device the session was opened to;
//   - a retained finding payload replayed onto the asset its observation is
//     linked to (enforce-mode admission);
//   - the enrichment worker's corroboration of a held observation, whose
//     proof resolved the observation's identifiers but not its sockets.
//
// They used to write asset_endpoints themselves, beside the engine. They call
// this instead, so every endpoint row is written by shared/identity under the
// same rules — sanitised, deduplicated, stamped with the evidence's own source
// and time, never onto an archived or denied asset — and the asset's timeline
// names what was attached and which decision attached it.

// DecidedEndpoints names the decision that tied the evidence to the asset; it
// is recorded as the history entry's `decided_by`.
type DecidedEndpoints string

const (
	DecidedByOperatorLink       DecidedEndpoints = "operator_link"
	DecidedByInterrogatedDevice DecidedEndpoints = "interrogated_device"
	DecidedByLinkedObservation  DecidedEndpoints = "linked_observation"
	DecidedByCorroboration      DecidedEndpoints = "corroborated_observation"
)

// AttachDecidedEndpoints writes obs's endpoints onto target, an asset decision
// already tied the evidence to, through repo (the caller's per-transaction
// repository). It returns how many endpoints were new or changed. An archived
// or denied target, or an observation with no endpoint, writes nothing.
func AttachDecidedEndpoints(ctx context.Context, repo Repository, obs Observation, target AssetRef, decision DecidedEndpoints, at time.Time) (int, error) {
	if target.Zero() || strings.TrimSpace(obs.TenantID) != target.TenantID {
		return 0, fmt.Errorf("%w: decided endpoints must name an asset of the observation's tenant", ErrInvalidObservation)
	}
	if strings.TrimSpace(string(decision)) == "" {
		return 0, fmt.Errorf("%w: decided endpoints must name the decision", ErrInvalidObservation)
	}
	if at.IsZero() {
		at = obs.ObservedAt
	}
	if at.IsZero() {
		at = time.Now().UTC()
	}
	eps := stampEndpoints(obs.Endpoints, obs.Source, at)
	if len(eps) == 0 {
		return 0, nil
	}
	summaries, err := repo.LoadSummaries(ctx, target.TenantID, []string{target.ID})
	if err != nil {
		return 0, fmt.Errorf("identity: reading %s before attaching decided endpoints: %w", target.ID, err)
	}
	if len(summaries) != 1 || summaries[0].Status == StatusArchived || summaries[0].Status == StatusDenied {
		return 0, nil
	}
	n, err := repo.UpsertEndpoints(ctx, target, eps)
	if err != nil {
		return 0, fmt.Errorf("identity: attaching decided endpoints to %s: %w", target.ID, err)
	}
	if n == 0 {
		// A re-sighting of sockets the asset already has: no timeline row.
		return 0, nil
	}
	if err := repo.RecordHistory(ctx, HistoryEntry{
		TenantID: target.TenantID,
		AssetID:  target.ID,
		Action:   ActionUpdated,
		Source:   obs.Source,
		Changes:  map[string]any{"decided_by": string(decision), "endpoints": endpointKeys(eps)},
		At:       at,
	}); err != nil {
		return 0, fmt.Errorf("identity: recording decided endpoints on %s: %w", target.ID, err)
	}
	return n, nil
}
