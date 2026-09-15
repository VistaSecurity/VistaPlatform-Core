// Package identityaudit records the one thing on the identification path that
// nobody asked for: a merge the MATCHER made on a tenant's behalf.
//
// # Why this is shared
//
// Three identification engines auto-accept — inventory-service's intake, and
// device-interrogation-service's DeviceService and ObservationSink — and the
// event they write has to be the SAME event. A tenant asking "what has the
// matcher done to my inventory?" is asking one question, and an answer that
// depends on which service happened to observe the asset is not an answer.
//
// ADR-0008 D4.7 requires an audit event for a generative call; this is not one,
// and it needs the record MORE rather than less. A classical model that merged
// two rows in a customer's inventory at three in the morning is precisely the
// event somebody will want to account for later, and unlike every other write on
// this path there is no user behind it to ask.
package identityaudit

import (
	"context"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/shared/identity"
	auditmiddleware "github.com/vistasecurity/vistaplatform/shared/middleware/audit"
)

// EventType is the `event_type` an auto-accepted merge is recorded under. It is
// a constant rather than a literal at three call sites for the obvious reason:
// a query that filters on it must find all three.
const EventType = "asset.merge.auto_accepted"

// Action is the `action` field of the same event.
const Action = "auto_accept_merge"

// ActorMatcher is what the event's `actor` says.
//
// `matcher` rather than a user id or "system": a person did not do this, and
// naming one would be false. "system" would be true and useless — it is what
// every background write says, and this one is not a background write, it is a
// DECISION.
const ActorMatcher = "matcher"

// Logger is the one method of the audit middleware this package uses.
//
// An interface rather than the concrete *audit.Middleware so a service can be
// tested without an audit-service to POST to, and so a nil one is a documented
// state rather than a panic.
type Logger interface {
	LogActivity(ctx context.Context, req *auditmiddleware.ActivityLogRequest) error
}

// LogAutoAcceptedMerge records that the platform merged two assets without
// being asked.
//
// A resolution that was NOT auto-accepted writes nothing, so every call site can
// call this unconditionally after a resolve and none of them has to re-derive
// the condition — the shape of bug where one path checks `res.AutoAccepted` and
// another checks `res.Proposal.AutoAccepted` and they disagree about a merge.
//
// Best-effort, and deliberately returns nothing. A merge that committed and an
// audit event that did not send is bad; refusing the merge afterwards would be
// worse, because it already happened — the same reason the identity package
// LOGS a failed history insert rather than returning it.
//
// CALL IT AFTER THE COMMIT. An audit event announcing a merge that then rolled
// back would be a record of something that did not happen.
func LogAutoAcceptedMerge(ctx context.Context, l Logger, obs identity.Observation, res identity.Resolution) {
	req := Request(obs, res)
	if l == nil || req == nil {
		return
	}
	_ = l.LogActivity(ctx, req)
}

// Request builds the event, or nil when there is nothing to record.
//
// Exported separately from [LogAutoAcceptedMerge] so a test can assert on the
// event's CONTENT without standing up a logger, and so the "what goes in it"
// decision has one home.
//
// Nil for a resolution that was not auto-accepted, and for one whose tenant or
// asset id will not parse — an event naming no asset is not a thinner record,
// it is an unusable one.
func Request(obs identity.Observation, res identity.Resolution) *auditmiddleware.ActivityLogRequest {
	if !res.AutoAccepted {
		return nil
	}
	tenantID, err := uuid.Parse(strings.TrimSpace(obs.TenantID))
	if err != nil {
		return nil
	}
	assetID, err := uuid.Parse(strings.TrimSpace(res.Asset.ID))
	if err != nil {
		return nil
	}

	resourceType := "asset"
	candidates := make([]string, 0, len(res.Candidates))
	for _, c := range res.Candidates {
		candidates = append(candidates, c.Ref.ID)
	}
	var reason string
	if len(res.Candidates) > 0 {
		reason = res.Candidates[0].Reason
	}
	var modelID string
	if res.Proposal.ID != "" {
		modelID = ModelID(res)
	}

	return &auditmiddleware.ActivityLogRequest{
		TenantID:  &tenantID,
		UserType:  "system",
		EventType: EventType,
		// `asset`, not a category of its own: activity_logs constrains
		// event_category and would reject anything outside that set — which is
		// exactly what happened to "data_modification", so this event never
		// landed in any database (security review X.5, X5-09).
		EventCategory: auditmiddleware.EventCategoryAsset,
		Action:        Action,
		ResourceType:  &resourceType,
		ResourceID:    &assetID,
		Success:       true,
		OccurredAt:    time.Now().UTC(),
		// RequiresAttention: a merge nobody approved is reversible only by
		// hand today, so it belongs in whatever a reviewer looks at first.
		RequiresAttention: true,
		// The score, the model id and the proposal are all in the event, so the
		// audit row answers "what decided this and on what evidence" without a
		// join.
		Metadata: map[string]any{
			"actor":       ActorMatcher,
			"score":       res.TopScore,
			"model_id":    modelID,
			"proposal_id": res.Proposal.ID,
			"candidates":  candidates,
			"reason":      reason,
			"source":      obs.Source.Ref,
		},
	}
}

// ModelID is the model behind an auto-accept: the top candidate's, which is the
// one the engine acted on.
//
// Not `res.Candidates[0]`, even though the ranking sorts by score: the candidate
// the engine ACCEPTED is the one whose ref equals the resolution's asset, and
// those two coincide today only because nothing between the sort and the accept
// re-orders. Reading the accepted one directly is the same answer for the right
// reason.
func ModelID(res identity.Resolution) string {
	for _, c := range res.Candidates {
		if c.Ref.ID == res.Asset.ID {
			return c.ModelID()
		}
	}
	return ""
}
