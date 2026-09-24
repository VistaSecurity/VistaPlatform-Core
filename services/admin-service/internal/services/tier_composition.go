package services

// Tier composition writes — the tier_entitlements rows a plan grants.
//
// There used to be one write primitive, ReplaceTierEntitlements: delete every
// row for the tier, re-insert what the request carried. Every caller built
// that request from client state, so an empty or stale client view erased the
// composition — the Plans & Pricing matrix sent one tier's WHOLE composition
// from its react-query cache on every cell edit, and a cache that was empty
// (load failed or still running) or stale (two quick edits) wiped the rows it
// did not carry. A missing numeric_cap row resolves to the catalogue default,
// which for capacity caps is 0: sensor and asset creation then failed for
// every tenant on the tier.
//
// The rules now, for every path that writes a composition:
//
//   - OMISSION NEVER DELETES. A write upserts the rows it names and deletes
//     only the keys it lists in `remove`. There is no "replace with this set".
//   - A multi-item write must name the composition it was computed from
//     (`version`, a content hash GET returns). A write made from a stale view
//     is refused with 409 instead of overwriting the newer state; one with no
//     version at all is refused with 428.
//   - A single-cell write (UpsertTierEntitlement) is last-writer-wins for that
//     one cell and needs no version: it cannot touch any other row.
//   - The write, its subscription_tier_history row and (for UpdateTier) the
//     tier's own column changes commit in ONE transaction, holding the tier's
//     row lock so concurrent composition writers serialise.
//   - Omitted overage fields are left as stored (a new row gets NULL). The
//     old replace path nulled them on every save that did not repeat them,
//     which is every save the admin UI makes.

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"

	"github.com/google/uuid"
	"github.com/lib/pq"
)

// ErrTierNotFound is returned when a composition write names a tier that does
// not exist. Handlers map it to 404.
var ErrTierNotFound = errors.New("subscription tier not found")

// ErrCompositionVersionRequired is returned by a multi-item composition write
// that carries no version. Handlers map it to 428 Precondition Required: the
// caller must read the composition (GET …/entitlements) and send its version.
var ErrCompositionVersionRequired = errors.New("composition version required: read the tier's entitlements first and send their version")

// StaleCompositionError is returned when a multi-item write names a version
// that is no longer current — someone changed the composition since the caller
// read it. Handlers map it to 409 and echo Current.
type StaleCompositionError struct {
	Current string
}

func (e *StaleCompositionError) Error() string {
	return "tier composition changed since it was read (current version " + e.Current + ")"
}

// sqlRunner is satisfied by both *sql.DB and *sql.Tx, so the composition
// reads run identically inside and outside a write transaction.
type sqlRunner interface {
	Query(query string, args ...any) (*sql.Rows, error)
	QueryRow(query string, args ...any) *sql.Row
	Exec(query string, args ...any) (sql.Result, error)
}

// TierComposition is a tier's entitlement rows plus the version that names
// exactly this set of rows.
type TierComposition struct {
	Entitlements []TierEntitlement
	Version      string
}

// EntitlementValue is one side of an EntitlementChange.
type EntitlementValue struct {
	IncludedValue     json.RawMessage `json:"included_value"`
	OveragePriceCents *int            `json:"overage_price_cents,omitempty"`
	OverageUnitSize   *int            `json:"overage_unit_size,omitempty"`
}

// EntitlementChange records one row a composition write actually changed.
// Before is nil for an added row, After is nil for a removed one. Rows the
// write named but left identical produce no change.
type EntitlementChange struct {
	ItemKey string            `json:"item_key"`
	Before  *EntitlementValue `json:"before"`
	After   *EntitlementValue `json:"after"`
}

// ChangedKeys lists the item keys of a change set, for audit metadata.
func ChangedKeys(changes []EntitlementChange) []string {
	out := make([]string, 0, len(changes))
	for _, c := range changes {
		out = append(out, c.ItemKey)
	}
	return out
}

// CompositionWriteResult is what a composition write returns: the state after
// the commit and what the write changed.
type CompositionWriteResult struct {
	Composition TierComposition
	Changes     []EntitlementChange
}

// CompositionUpdate is a multi-item composition write.
type CompositionUpdate struct {
	Set     []TierEntitlementInput
	Remove  []string
	Version string
}

// compositionVersion is a content hash of a composition: the same rows give
// the same version however they were reached, so a write computed from a view
// that is still accurate is never refused. included_value is jsonb read back
// from Postgres, whose text form is canonical (key order, whitespace).
func compositionVersion(ents []TierEntitlement) string {
	sorted := make([]TierEntitlement, len(ents))
	copy(sorted, ents)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].ItemKey < sorted[j].ItemKey })
	h := sha256.New()
	for _, e := range sorted {
		_, _ = fmt.Fprintf(h, "%s\x00%s\x00%s\x00%s\n", e.ItemKey, []byte(e.IncludedValue), intOrEmpty(e.OveragePriceCents), intOrEmpty(e.OverageUnitSize))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func intOrEmpty(p *int) string {
	if p == nil {
		return ""
	}
	return fmt.Sprint(*p)
}

// readTierComposition reads a tier's rows and their version through q.
func readTierComposition(q sqlRunner, tierID uuid.UUID) (TierComposition, error) {
	ents, err := queryTierEntitlements(q, tierID)
	if err != nil {
		return TierComposition{}, err
	}
	return TierComposition{Entitlements: ents, Version: compositionVersion(ents)}, nil
}

// GetTierComposition returns a tier's composition and its version — what a
// caller must send back on a multi-item write.
func (s *EntitlementsService) GetTierComposition(tierID uuid.UUID) (TierComposition, error) {
	return readTierComposition(s.db, tierID)
}

// lockTier takes the tier's row lock for the rest of tx. Every composition
// writer takes it first, so two writers for one tier serialise and the second
// one's version check sees the first one's commit.
func lockTier(tx *sql.Tx, tierID uuid.UUID) error {
	var one int
	err := tx.QueryRow(`SELECT 1 FROM subscription_tiers WHERE id = $1 FOR UPDATE`, tierID).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrTierNotFound
	}
	if err != nil {
		return fmt.Errorf("lock tier: %w", err)
	}
	return nil
}

// applyTierComposition upserts set and deletes remove for tierID inside tx,
// which must already hold the tier lock. Everything is validated before the
// first write: a set key must be an ACTIVE catalogue item and carry a value of
// its kind's shape; a remove key must be a catalogue item (active or not — a
// deactivated item's row can still be taken off a plan); no key may appear
// twice across both lists. Returns only the rows that actually changed.
func applyTierComposition(tx *sql.Tx, tierID uuid.UUID, set []TierEntitlementInput, remove []string) ([]EntitlementChange, error) {
	seen := make(map[string]bool, len(set)+len(remove))
	keys := make([]string, 0, len(set)+len(remove))
	for _, in := range set {
		if seen[in.ItemKey] {
			return nil, &DuplicateItemKeyError{Key: in.ItemKey}
		}
		seen[in.ItemKey] = true
		keys = append(keys, in.ItemKey)
	}
	for _, k := range remove {
		if seen[k] {
			return nil, &DuplicateItemKeyError{Key: k}
		}
		seen[k] = true
		keys = append(keys, k)
	}
	if len(keys) == 0 {
		return nil, nil
	}

	type catalogRow struct {
		id     uuid.UUID
		kind   string
		active bool
	}
	catalog := make(map[string]catalogRow, len(keys))
	rows, err := tx.Query(`SELECT key, id, kind, is_active FROM billable_items WHERE key = ANY($1)`, pq.Array(keys))
	if err != nil {
		return nil, fmt.Errorf("resolve item keys: %w", err)
	}
	for rows.Next() {
		var (
			key string
			r   catalogRow
		)
		if err := rows.Scan(&key, &r.id, &r.kind, &r.active); err != nil {
			_ = rows.Close()
			return nil, fmt.Errorf("scan item key: %w", err)
		}
		catalog[key] = r
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return nil, fmt.Errorf("iterate item keys: %w", err)
	}
	_ = rows.Close()

	for _, in := range set {
		item, ok := catalog[in.ItemKey]
		if !ok || !item.active {
			return nil, &UnknownItemKeyError{Key: in.ItemKey}
		}
		if err := validateItemValue(in.ItemKey, item.kind, in.IncludedValue); err != nil {
			return nil, err
		}
	}
	for _, k := range remove {
		if _, ok := catalog[k]; !ok {
			return nil, &UnknownItemKeyError{Key: k}
		}
	}

	current, err := queryTierEntitlements(tx, tierID)
	if err != nil {
		return nil, err
	}
	before := make(map[string]*EntitlementValue, len(current))
	for _, e := range current {
		before[e.ItemKey] = &EntitlementValue{IncludedValue: e.IncludedValue, OveragePriceCents: e.OveragePriceCents, OverageUnitSize: e.OverageUnitSize}
	}

	var changes []EntitlementChange
	for _, in := range set {
		var overageCents, overageSize any
		if in.OveragePriceCents != nil {
			overageCents = *in.OveragePriceCents
		}
		if in.OverageUnitSize != nil {
			overageSize = *in.OverageUnitSize
		}
		// The WHERE makes an identical write a no-op that RETURNs nothing, so
		// only real changes reach history and audit (and updated_at).
		var (
			after                     EntitlementValue
			afterJSON                 []byte
			afterCents, afterUnitSize sql.NullInt64
		)
		err := tx.QueryRow(`
			INSERT INTO tier_entitlements AS te (tier_id, item_id, included_value, overage_price_cents, overage_unit_size)
			VALUES ($1, $2, $3::jsonb, $4, $5)
			ON CONFLICT (tier_id, item_id) DO UPDATE SET
				included_value      = EXCLUDED.included_value,
				overage_price_cents = COALESCE(EXCLUDED.overage_price_cents, te.overage_price_cents),
				overage_unit_size   = COALESCE(EXCLUDED.overage_unit_size, te.overage_unit_size)
			WHERE (te.included_value, te.overage_price_cents, te.overage_unit_size)
			      IS DISTINCT FROM
			      (EXCLUDED.included_value,
			       COALESCE(EXCLUDED.overage_price_cents, te.overage_price_cents),
			       COALESCE(EXCLUDED.overage_unit_size, te.overage_unit_size))
			RETURNING te.included_value, te.overage_price_cents, te.overage_unit_size
		`, tierID, catalog[in.ItemKey].id, []byte(in.IncludedValue), overageCents, overageSize).
			Scan(&afterJSON, &afterCents, &afterUnitSize)
		if errors.Is(err, sql.ErrNoRows) {
			continue // identical to what is stored
		}
		if err != nil {
			return nil, fmt.Errorf("upsert tier entitlement %s: %w", in.ItemKey, err)
		}
		after.IncludedValue = json.RawMessage(afterJSON)
		after.OveragePriceCents = nullIntPtr(afterCents)
		after.OverageUnitSize = nullIntPtr(afterUnitSize)
		changes = append(changes, EntitlementChange{ItemKey: in.ItemKey, Before: before[in.ItemKey], After: &after})
	}
	for _, k := range remove {
		res, err := tx.Exec(`DELETE FROM tier_entitlements WHERE tier_id = $1 AND item_id = $2`, tierID, catalog[k].id)
		if err != nil {
			return nil, fmt.Errorf("remove tier entitlement %s: %w", k, err)
		}
		if n, _ := res.RowsAffected(); n > 0 {
			changes = append(changes, EntitlementChange{ItemKey: k, Before: before[k]})
		}
	}
	return changes, nil
}

func nullIntPtr(n sql.NullInt64) *int {
	if !n.Valid {
		return nil
	}
	v := int(n.Int64)
	return &v
}

// recordCompositionHistory writes the subscription_tier_history row for a
// composition change inside tx. A failure here fails the write: a composition
// change with no history row is exactly the unexplained drift history exists
// to rule out. changedBy uuid.Nil (no platform user) is stored as NULL.
func recordCompositionHistory(tx *sql.Tx, tierID uuid.UUID, changes []EntitlementChange, changedBy uuid.UUID, note string) error {
	if len(changes) == 0 {
		return nil
	}
	body, err := json.Marshal(map[string]any{"entitlements": changes})
	if err != nil {
		return fmt.Errorf("marshal composition history: %w", err)
	}
	var actor any
	if changedBy != uuid.Nil {
		actor = changedBy
	}
	if _, err := tx.Exec(`
		INSERT INTO subscription_tier_history (tier_id, change_type, changes_json, changed_by, notes)
		VALUES ($1, 'modified', $2::jsonb, $3, $4)
	`, tierID, body, actor, note); err != nil {
		return fmt.Errorf("record composition history: %w", err)
	}
	return nil
}

// UpsertTierEntitlement sets ONE item on a tier — the matrix's cell edit. It
// cannot remove or alter any other row, so it needs no version: two admins
// editing different cells both land, and two editing the same cell resolve
// last-writer-wins on that cell alone.
func (s *EntitlementsService) UpsertTierEntitlement(tierID uuid.UUID, in TierEntitlementInput, changedBy uuid.UUID) (*CompositionWriteResult, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := lockTier(tx, tierID); err != nil {
		return nil, err
	}
	changes, err := applyTierComposition(tx, tierID, []TierEntitlementInput{in}, nil)
	if err != nil {
		return nil, err
	}
	if err := recordCompositionHistory(tx, tierID, changes, changedBy, "Entitlement set via admin API"); err != nil {
		return nil, err
	}
	comp, err := readTierComposition(tx, tierID)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}
	return &CompositionWriteResult{Composition: comp, Changes: changes}, nil
}

// UpdateTierComposition applies a multi-item write: upsert u.Set, delete
// u.Remove, nothing else. u.Version must be the version of the composition the
// caller computed the write from.
func (s *EntitlementsService) UpdateTierComposition(tierID uuid.UUID, u CompositionUpdate, changedBy uuid.UUID) (*CompositionWriteResult, error) {
	if u.Version == "" {
		return nil, ErrCompositionVersionRequired
	}
	tx, err := s.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if err := lockTier(tx, tierID); err != nil {
		return nil, err
	}
	changes, err := applyVersionedComposition(tx, tierID, u)
	if err != nil {
		return nil, err
	}
	if err := recordCompositionHistory(tx, tierID, changes, changedBy, "Entitlements updated via admin API"); err != nil {
		return nil, err
	}
	comp, err := readTierComposition(tx, tierID)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit: %w", err)
	}
	return &CompositionWriteResult{Composition: comp, Changes: changes}, nil
}

// applyVersionedComposition checks u.Version against the composition as it
// stands under the tier lock, then applies u. Shared by UpdateTierComposition
// and TierService.UpdateTier.
func applyVersionedComposition(tx *sql.Tx, tierID uuid.UUID, u CompositionUpdate) ([]EntitlementChange, error) {
	if u.Version == "" {
		return nil, ErrCompositionVersionRequired
	}
	current, err := readTierComposition(tx, tierID)
	if err != nil {
		return nil, err
	}
	if current.Version != u.Version {
		return nil, &StaleCompositionError{Current: current.Version}
	}
	return applyTierComposition(tx, tierID, u.Set, u.Remove)
}
