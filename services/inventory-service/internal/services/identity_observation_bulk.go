package services

import (
	"context"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// MaxBulkObservationDecisions bounds one bulk request ( §4).
const MaxBulkObservationDecisions = 200

// BulkObservationItem is one id's answer. Err carries the same sentinel errors
// the single-item endpoints return, so the handler maps both with one table.
type BulkObservationItem struct {
	ID     uuid.UUID
	Result identity.IngestResult
	Err    error
}

// BulkDecideIdentityObservations runs the single-item decision for each id
// ( R4). It does not fork that logic: each id goes through
// DecideIdentityObservation, in its own transaction, with the same
// authorization (the route's), the same allowance and ownership checks, and
// the same audit row — plus a batch id shared by every row of the request.
//
// One item's failure never aborts the batch: a 402, a 409 or a 404 is that
// item's answer and the loop carries on. Cancellation is the exception, and
// only for the items not yet started: each of those is reported as cancelled
// rather than silently missing, and nothing already committed is undone.
//
// Sequential on purpose. Every confirm takes the tenant's allowance advisory
// lock (CheckAdmissionAllowance) and the identifier locks of its evidence, so
// parallel workers would queue behind each other on the first and could
// contend on the second when a batch holds sightings of the same device; at
// 200 items of a few milliseconds each there is nothing to win, and a
// predictable, ordered audit trail is worth having.
func (s *AssetService) BulkDecideIdentityObservations(ctx context.Context, tenant, actor uuid.UUID, action string, ids []uuid.UUID, input ObservationDecisionInput) (uuid.UUID, []BulkObservationItem, error) {
	var decision string
	switch action {
	case "confirm":
		decision = "confirmed"
	case "dismiss":
		decision = "dismissed"
	case "link":
		// Link in bulk is only ever "to the asset that already owns this
		// observation's identifier": each row's target is decided on
		// its locked row, so no client-named asset is accepted.
		decision = "linked"
	default:
		return uuid.Nil, nil, fmt.Errorf("invalid bulk observation action")
	}
	if len(ids) == 0 || len(ids) > MaxBulkObservationDecisions {
		return uuid.Nil, nil, fmt.Errorf("between 1 and %d observations are required", MaxBulkObservationDecisions)
	}
	if strings.TrimSpace(input.Reason) == "" || len(input.Reason) > 2000 {
		return uuid.Nil, nil, fmt.Errorf("a reason of at most 2000 characters is required")
	}
	batch := uuid.New()
	input.AssetID = nil
	input.batchID = batch
	input.readyOnly = decision == "confirmed"
	input.linkSuggested = decision == "linked"

	seen := make(map[uuid.UUID]bool, len(ids))
	out := make([]BulkObservationItem, 0, len(ids))
	for _, id := range ids {
		if seen[id] {
			continue
		}
		seen[id] = true
		item := BulkObservationItem{ID: id}
		if err := ctx.Err(); err != nil {
			item.Err = err
		} else {
			item.Result, item.Err = s.DecideIdentityObservation(ctx, tenant, id, actor, decision, input)
		}
		out = append(out, item)
	}
	return batch, out, nil
}
