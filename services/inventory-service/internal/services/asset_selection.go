// Package services: which assets a bulk action acts on.
package services

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
)

// MaxBulkAssets bounds every bulk write except a scan. It is a guard against a
// mistyped query, not a throughput limit: a person who means more narrows the
// query and runs the action again.
const MaxBulkAssets = 5000

// MaxBulkScanAssets bounds a bulk Active Scan at the scan engine's own per-job
// target limit (cluster-sensor-service rejects a job with more than 1000
// targets), so a selection the UI lets through is one a job can carry.
const MaxBulkScanAssets = 1000

// AssetSelection is what a bulk action acts on: an explicit list of asset ids
// (rows a person ticked) or a query (every asset the list shows for it).
//
// A query selection carries the count the person confirmed. The set a query
// matches moves while they read the dialog — discovery keeps adding assets —
// and the rule is that an action never touches MORE assets than the person
// agreed to. Fewer is fine: an asset that left the set in the meantime is not
// one anybody asked to change.
type AssetSelection struct {
	AssetIDs []string
	// Query is a pointer because "" is a real selection: everything in the
	// list's default scope, which is what All assets shows with an empty box.
	Query         *string
	ExpectedCount *int
}

var (
	// ErrSelectionInvalid is a selection that names neither, or both, forms,
	// or a query with no confirmed count.
	ErrSelectionInvalid = errors.New("invalid selection")
	// ErrSelectionEmpty is a selection that resolved to no asset.
	ErrSelectionEmpty = errors.New("the selection matches no asset")
)

// SelectionTooLargeError is a selection over the action's cap.
type SelectionTooLargeError struct {
	Limit int
	// Count is how many assets the selection named or matched, or Limit+1 when
	// a query matched more than the cap (it is not counted past it).
	Count int
}

func (e *SelectionTooLargeError) Error() string {
	return fmt.Sprintf("the selection has more than %d assets; narrow the query and run the action again", e.Limit)
}

// SelectionChangedError is a query that now matches more assets than the
// person confirmed.
type SelectionChangedError struct {
	Expected int
	Count    int
}

func (e *SelectionChangedError) Error() string {
	return fmt.Sprintf("the query now matches %d assets, more than the %d you confirmed", e.Count, e.Expected)
}

// ResolveAssetSelection turns a selection into asset ids, at most `limit` of
// them.
//
// An id list is parsed and de-duplicated; an id that does not parse is dropped,
// as every existing bulk endpoint does. Ids are NOT checked here against the
// tenant: each action's write is tenant-scoped and RLS-isolated, so an id from
// another tenant changes nothing, and the action reports how many it changed.
//
// A query compiles through buildAssetWhere — the function the asset list
// compiles through — so the default `status:monitoring` scope, the
// `deleted_at IS NULL` cut and RLS are exactly what the person was looking at.
// A second WHERE-builder here is how "select all matching" would come to mean
// something other than what was on screen.
func (s *AssetService) ResolveAssetSelection(tenantID uuid.UUID, sel AssetSelection, limit int) ([]uuid.UUID, error) {
	hasIDs := len(sel.AssetIDs) > 0
	hasQuery := sel.Query != nil
	if hasIDs == hasQuery {
		return nil, fmt.Errorf("%w: send either asset_ids or query", ErrSelectionInvalid)
	}
	if hasIDs {
		return ResolveAssetIDList(sel.AssetIDs, limit)
	}
	if sel.ExpectedCount == nil || *sel.ExpectedCount < 0 {
		return nil, fmt.Errorf("%w: a query selection needs expected_count, the number of assets the person confirmed", ErrSelectionInvalid)
	}

	pred, err := buildAssetWhere(*sel.Query, models.AssetFilters{}, 2, assetQueryAlias)
	if err != nil {
		return nil, err
	}
	args := append([]interface{}{tenantID}, pred.Args...)
	// limit+1 rows: enough to know the selection is over the cap without
	// reading the whole tenant. Ordered so two resolutions of an unchanged set
	// agree, which the over-cap message does not need but a log line does.
	q := `SELECT a.id FROM assets a WHERE a.tenant_id = $1 AND a.deleted_at IS NULL AND (` + pred.Where + `)
		ORDER BY a.id LIMIT ` + fmt.Sprint(limit+1)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var ids []uuid.UUID
	// The caller's own predicate reaches Postgres, so the statement timeout
	// applies, as on the list (see assetQueryStatementTimeout).
	if err := database.WithTenantTxTimeout(ctx, s.db, tenantID, assetQueryStatementTimeout, func(tx *sqlx.Tx) error {
		return tx.SelectContext(ctx, &ids, q, args...)
	}); err != nil {
		return nil, fmt.Errorf("resolve selection: %w", err)
	}
	if len(ids) > limit {
		return nil, &SelectionTooLargeError{Limit: limit, Count: len(ids)}
	}
	if len(ids) > *sel.ExpectedCount {
		return nil, &SelectionChangedError{Expected: *sel.ExpectedCount, Count: len(ids)}
	}
	if len(ids) == 0 {
		return nil, ErrSelectionEmpty
	}
	return ids, nil
}

// ResolveAssetIDList is the id-list half of ResolveAssetSelection. It needs no
// database, so a handler can resolve ticked rows without an AssetService.
func ResolveAssetIDList(raw []string, limit int) ([]uuid.UUID, error) {
	ids := parseAssetIDs(raw)
	if len(ids) == 0 {
		return nil, fmt.Errorf("%w: no valid asset ids", ErrSelectionInvalid)
	}
	if len(ids) > limit {
		return nil, &SelectionTooLargeError{Limit: limit, Count: len(ids)}
	}
	return ids, nil
}

// parseAssetIDs parses and de-duplicates, keeping the caller's order.
func parseAssetIDs(raw []string) []uuid.UUID {
	seen := make(map[uuid.UUID]bool, len(raw))
	out := make([]uuid.UUID, 0, len(raw))
	for _, s := range raw {
		id, err := uuid.Parse(strings.TrimSpace(s))
		if err != nil || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}
