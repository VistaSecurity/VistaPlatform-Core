package services

// Spares, stock and RMA (DCIM gap 8; owner decision: extend inventory items,
// no second stock table). An inventory item is either on an asset or a spare
// at a stock location, with a quantity and a stock state:
//
//	installed  on an asset (every item discovery reports, and every item
//	           before this gap)
//	in_stock   at a stock location, ready to use
//	reserved   at a stock location, set aside
//	rma        out for a return-merchandise case: still on its asset (the
//	           replacement is to arrive first), at a stock location, or with
//	           neither once it has shipped to the vendor
//	retired    gone from the estate; no asset, location optional
//
// A plain create or PATCH may put a spare in stock, reserve it, retire it or
// move it between stock locations; everything that crosses between an asset
// and the shelf goes through an action, so the transition is one recorded
// change and the quantity arithmetic is the service's:
//
//	POST /dcim/inventory-items/{id}/install  a spare (in_stock / reserved) onto
//	     an asset, optionally into a module bay (the bay's module, or a module
//	     of the module type the spare's part number names is installed). Part
//	     of a stock row splits off; the rest stays on the shelf.
//	POST /dcim/inventory-items/{id}/remove   an item on an asset (installed, or
//	     rma) to a stock location. An unserialised item joins a stock row of the
//	     same name and part there (its quantity adds); otherwise it moves.
//	POST /dcim/inventory-items/{id}/rma      opens an rma_case (state open) and
//	     puts the item in rma — one unit split off a stock row of several;
//	     with location_id an installed item comes off its asset first.
//	PATCH /dcim/rma-cases/{id}               shipped: the unit leaves (no asset,
//	     no location); received: the replacement lands in stock (the named
//	     replacement_item_id, or a new unit like the failed one at its stock
//	     location, or its asset's location); closed (final): a unit still on its
//	     asset or shelf goes back into service, a shipped one is retired.
//
// Every write goes through the object engine (createTx / updateTx), so each
// transition is recorded in object_changes with the request's actor, inside
// the one tenant transaction. A spare is never pushed to NetBox, which
// requires a device (the NetBox connector's inventory item rule).

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	shareddb "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
)

// HardwareRMACase is the RMA case route segment under /dcim.
const HardwareRMACase = "rma-cases"

// The stock states (inventory_items_stock_state_check) and the RMA case
// states (rma_cases_state_check).
var (
	stockStates    = []string{"installed", "in_stock", "reserved", "rma", "retired"}
	rmaCaseStates  = []string{"open", "shipped", "received", "closed"}
	patchStockable = map[string]bool{"in_stock": true, "reserved": true, "retired": true}
)

// spareMoveKey marks a write the spares service makes: only an action may move
// an item between an asset and a stock location or change its state to or
// from installed / rma.
type spareMoveKey struct{}

func withSpareMove(ctx context.Context) context.Context {
	return context.WithValue(ctx, spareMoveKey{}, true)
}

func isSpareMove(ctx context.Context) bool {
	v, _ := ctx.Value(spareMoveKey{}).(bool)
	return v
}

func quantityOf(v any) int {
	n, err := strconv.Atoi(str(v))
	if err != nil {
		return 1
	}
	return n
}

// prepareStockPlacement holds an item's placement to its stock state: installed
// = on an asset; in_stock / reserved = at a stock location; rma = not both;
// retired = no asset. A plain write never moves an item between an asset and
// a stock location, and never makes one installed or rma (the actions do).
func prepareStockPlacement(ctx context.Context, tx *sql.Tx, _ uuid.UUID, id uuid.UUID, row map[string]any) error {
	hasAsset, hasLoc := !isEmpty(row["asset_id"]), !isEmpty(row["location_id"])
	if isEmpty(row["stock_state"]) {
		row["stock_state"] = "in_stock"
		if hasAsset {
			row["stock_state"] = "installed"
		}
	}
	state, _ := row["stock_state"].(string)
	if err := oneOf(row, "stock_state", stockStates); err != nil {
		return err
	}
	if q, ok := row["quantity"]; ok && q != nil && quantityOf(q) < 1 {
		return ipamInvalid("quantity must be at least 1")
	}
	if hasAsset && hasLoc {
		return ipamInvalid("an item is on an asset or at a stock location, not both")
	}
	switch state {
	case "installed":
		if !hasAsset {
			return ipamInvalid("an installed item is on an asset: give asset_id, or put it in stock at a location_id")
		}
	case "in_stock", "reserved":
		if !hasLoc {
			return ipamInvalid("a spare that is %s needs a stock location (location_id)", state)
		}
	case "retired":
		if hasAsset {
			return ipamInvalid("a retired item is not on an asset; remove it to stock first")
		}
	}
	if hasLoc {
		if err := visible(ctx, tx, "locations", row["location_id"]); err != nil {
			return err
		}
	}
	if isSpareMove(ctx) {
		return nil
	}
	if id == uuid.Nil {
		if state == "rma" {
			return ipamInvalid("an item goes out for RMA through POST /dcim/inventory-items/{id}/rma, which opens its case")
		}
		return nil
	}
	var curAsset, curState string
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(asset_id::text, ''), stock_state FROM inventory_items WHERE id = $1`, id).
		Scan(&curAsset, &curState); err != nil {
		return mapIPAMError(err, false)
	}
	if curAsset != str(row["asset_id"]) {
		if curAsset == "" {
			return ipamInvalid("a spare goes onto an asset through POST /dcim/inventory-items/{id}/install")
		}
		return ipamInvalid("asset_id cannot be changed; remove the item to stock (POST /dcim/inventory-items/{id}/remove) and install it on the other asset")
	}
	if curState != state && (!patchStockable[curState] || !patchStockable[state]) {
		return ipamInvalid("stock_state %s → %s is an action: install, remove or rma (a write may only move a spare between in_stock, reserved and retired)", curState, state)
	}
	return nil
}

// inventoryItemSiteFilter is ?site_id=: spares at any of the site's locations.
func inventoryItemSiteFilter(v string, n int) (string, any, error) {
	if _, err := uuid.Parse(v); err != nil {
		return "", nil, ipamInvalid("site_id must be a UUID")
	}
	return fmt.Sprintf("t.location_id IN (SELECT l.id FROM public.locations l WHERE l.site_id = $%d::uuid)", n), v, nil
}

// rmaCaseSpec is the engine spec of rma_cases. A case is opened by the rma
// action (inventory_item_id is computed); PATCH moves it through its states.
func rmaCaseSpec() *ipamSpec {
	return &ipamSpec{
		Kind: dcim.ObjectKindRmaCase, Table: "rma_cases", Route: HardwareRMACase,
		Cols: withSubstrate(
			ipamCol{Name: "inventory_item_id", Type: colUUID, Computed: true},
			ipamCol{Name: "vendor", Type: colText},
			ipamCol{Name: "case_number", Type: colText},
			ipamCol{Name: "opened_at", Type: colDate},
			ipamCol{Name: "shipped_at", Type: colDate},
			ipamCol{Name: "received_at", Type: colDate},
			ipamCol{Name: "replacement_item_id", Type: colUUID},
			ipamCol{Name: "replacement_location_id", Type: colUUID},
			ipamCol{Name: "state", Type: colText},
			ipamCol{Name: "notes", Type: colText},
		),
		Filters: []ipamFilter{
			{Param: "state", Column: "state", Type: colText},
			{Param: "inventory_item_id", Column: "inventory_item_id", Type: colUUID},
			{Param: "open", Custom: rmaOpenFilter},
		},
		Search:     []string{"vendor", "case_number", "notes", "description"},
		Order:      "t.opened_at DESC, t.created_at DESC, t.id",
		Prepare:    prepareRMACase,
		AfterWrite: afterRMACaseWrite,
	}
}

// rmaOpenFilter is ?open=true (every case that is not closed) or false.
func rmaOpenFilter(v string, _ int) (string, any, error) {
	switch v {
	case "true":
		return "t.state <> 'closed'", nil, nil
	case "false":
		return "t.state = 'closed'", nil, nil
	}
	return "", nil, ipamInvalid("open must be true or false")
}

func today() string { return time.Now().UTC().Format("2006-01-02") }

// prepareRMACase: a state from the set; a closed case is final; shipping and
// receiving stamp their dates (today unless given); the replacement is another
// item the tenant can read; no date before the case was opened.
func prepareRMACase(ctx context.Context, tx *sql.Tx, _ uuid.UUID, id uuid.UUID, row map[string]any) error {
	if isEmpty(row["state"]) {
		row["state"] = "open"
	}
	if err := oneOf(row, "state", rmaCaseStates); err != nil {
		return err
	}
	if isEmpty(row["opened_at"]) {
		row["opened_at"] = today()
	}
	if id != uuid.Nil {
		var cur string
		if err := tx.QueryRowContext(ctx, `SELECT state FROM rma_cases WHERE id = $1`, id).Scan(&cur); err != nil {
			return mapIPAMError(err, false)
		}
		if cur == "closed" && row["state"] != "closed" {
			return ipamInvalid("a closed RMA case is final")
		}
	}
	switch row["state"] {
	case "shipped":
		if isEmpty(row["shipped_at"]) {
			row["shipped_at"] = today()
		}
	case "received":
		if isEmpty(row["received_at"]) {
			row["received_at"] = today()
		}
	}
	opened := str(row["opened_at"])
	for _, c := range []string{"shipped_at", "received_at"} {
		if d := str(row[c]); d != "" && opened != "" && d < opened {
			return ipamInvalid("%s is before the case was opened (%s)", c, opened)
		}
	}
	if err := visible(ctx, tx, "locations", row["replacement_location_id"]); err != nil {
		return err
	}
	if rep := str(row["replacement_item_id"]); rep != "" {
		if rep == str(row["inventory_item_id"]) {
			return ipamInvalid("the replacement is another item, not the one out for RMA")
		}
		if err := visible(ctx, tx, "inventory_items", rep); err != nil {
			return err
		}
	}
	return nil
}

// afterRMACaseWrite applies a state change to the item and its replacement.
func afterRMACaseWrite(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, pre, post map[string]any) error {
	if pre == nil || post == nil || pre["state"] == post["state"] {
		return nil
	}
	sp := NewSparesService(nil)
	item, err := getRow(ctx, tx, sp.itemSpec(), uuid.MustParse(str(post["inventory_item_id"])), true)
	if err != nil {
		return err
	}
	ctx = withSpareMove(ctx)
	switch post["state"] {
	case "shipped":
		// The unit has left: no asset, no shelf.
		if str(item["asset_id"]) == "" && str(item["location_id"]) == "" {
			return nil
		}
		if err := sp.refuseChildren(ctx, tx, item); err != nil {
			return err
		}
		_, err := sp.hw.eng.updateTx(ctx, tx, sp.itemSpec(), tenant, uuid.MustParse(str(item["id"])), map[string]any{
			"asset_id": nil, "location_id": nil, "parent_id": nil, "component_kind": nil, "component_id": nil, "stock_state": "rma",
		}, "")
		return err
	case "received":
		return sp.receiveReplacement(ctx, tx, tenant, item, post)
	case "closed":
		state := "retired"
		switch {
		case str(item["asset_id"]) != "":
			state = "installed"
		case str(item["location_id"]) != "":
			state = "in_stock"
		}
		if item["stock_state"] == state {
			return nil
		}
		_, err := sp.hw.eng.updateTx(ctx, tx, sp.itemSpec(), tenant, uuid.MustParse(str(item["id"])), map[string]any{"stock_state": state}, "")
		return err
	}
	return nil
}

// SparesService is DCIM gap 8's actions over the hardware engine.
type SparesService struct {
	db  *sql.DB
	hw  *HardwareService
	rma *IPAMService
}

// NewSparesService returns the store over db (the raw pool; RLS is set per
// transaction).
func NewSparesService(db *sql.DB) *SparesService {
	return &SparesService{db: db, hw: NewHardwareService(db), rma: newObjectEngine(db, []*ipamSpec{rmaCaseSpec()})}
}

// RMACaseObject describes rma_cases for the contract tests.
func RMACaseObject() IPAMObjectInfo {
	sp := rmaCaseSpec()
	info := IPAMObjectInfo{Route: sp.Route, Table: sp.Table, Kind: string(sp.Kind)}
	for _, c := range sp.Cols {
		if !c.Computed {
			info.Writable = append(info.Writable, c.Name)
		}
	}
	return info
}

func (s *SparesService) itemSpec() *ipamSpec {
	sp, _ := s.hw.eng.spec(HardwareInventoryItem)
	return sp
}

func (s *SparesService) caseSpec() *ipamSpec {
	sp, _ := s.rma.spec(HardwareRMACase)
	return sp
}

// SpareInstallInput is POST /dcim/inventory-items/{id}/install.
type SpareInstallInput struct {
	AssetID     uuid.UUID  `json:"asset_id"`
	ModuleBayID *uuid.UUID `json:"module_bay_id,omitempty"`
	ParentID    *uuid.UUID `json:"parent_id,omitempty"`
	Name        string     `json:"name,omitempty"`
	Quantity    *int       `json:"quantity,omitempty"`
}

// SpareRemoveInput is POST /dcim/inventory-items/{id}/remove.
type SpareRemoveInput struct {
	LocationID uuid.UUID `json:"location_id"`
	Name       string    `json:"name,omitempty"`
	StockState string    `json:"stock_state,omitempty"`
}

// SpareRMAInput is POST /dcim/inventory-items/{id}/rma.
type SpareRMAInput struct {
	Vendor     string     `json:"vendor,omitempty"`
	CaseNumber string     `json:"case_number,omitempty"`
	OpenedAt   string     `json:"opened_at,omitempty"`
	Notes      string     `json:"notes,omitempty"`
	LocationID *uuid.UUID `json:"location_id,omitempty"`
}

// SpareResult is what an action did: the item it acted on (the unit split off,
// or the row it was merged into), the stock row left behind by a split, and
// the case an RMA opened.
type SpareResult struct {
	Item    map[string]any `json:"item"`
	Stock   map[string]any `json:"stock,omitempty"`
	RMACase map[string]any `json:"rma_case,omitempty"`
}

func (s *SparesService) run(ctx context.Context, tenant uuid.UUID, fn func(ctx context.Context, tx *sql.Tx) error) error {
	err := shareddb.WithTenantTx(ctx, s.db, tenant, func(tx *sql.Tx) error { return fn(withSpareMove(ctx), tx) })
	return mapIPAMError(err, false)
}

// splitFields are the columns a unit split off a stock row (or a replacement
// like a failed unit) takes from it. Serial and asset tag are the unit's own.
var splitFields = []string{"name", "label", "role_id", "manufacturer_id", "part_id", "description"}

func (s *SparesService) split(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, from map[string]any, n int, extra map[string]any) (unit, rest map[string]any, err error) {
	id := uuid.MustParse(str(from["id"]))
	rest, err = s.hw.eng.updateTx(ctx, tx, s.itemSpec(), tenant, id, map[string]any{"quantity": quantityOf(from["quantity"]) - n}, "")
	if err != nil {
		return nil, nil, err
	}
	row := map[string]any{"quantity": n, "source_kind": "declared"}
	for _, f := range splitFields {
		if from[f] != nil {
			row[f] = from[f]
		}
	}
	for k, v := range extra {
		row[k] = v
	}
	unit, err = s.hw.eng.createTx(ctx, tx, s.itemSpec(), tenant, row, "")
	return unit, rest, err
}

// refuseChildren: an item leaving its asset takes no child items with it.
func (s *SparesService) refuseChildren(ctx context.Context, tx *sql.Tx, item map[string]any) error {
	var n int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM inventory_items WHERE parent_id = $1 AND status <> 'rejected'`, str(item["id"])).Scan(&n); err != nil {
		return err
	}
	if n > 0 {
		return ipamInvalid("%v has %d child item(s) on the asset; remove or re-parent them first", item["name"], n)
	}
	return nil
}

func (s *SparesService) lockItem(ctx context.Context, tx *sql.Tx, id uuid.UUID) (map[string]any, error) {
	return getRow(ctx, tx, s.itemSpec(), id, true)
}

// Install puts a spare (in_stock or reserved) onto an asset.
func (s *SparesService) Install(ctx context.Context, tenant, id uuid.UUID, in SpareInstallInput) (*SpareResult, error) {
	var out SpareResult
	err := s.run(ctx, tenant, func(ctx context.Context, tx *sql.Tx) error {
		item, err := s.lockItem(ctx, tx, id)
		if err != nil {
			return err
		}
		if st := str(item["stock_state"]); st != "in_stock" && st != "reserved" {
			return ipamInvalid("only a spare in stock or reserved can be installed; this item is %s", st)
		}
		have := quantityOf(item["quantity"])
		n := 1
		if in.Quantity != nil {
			n = *in.Quantity
		}
		if n < 1 || n > have {
			return ipamInvalid("quantity must be 1 to %d (what this stock row holds)", have)
		}
		place := map[string]any{"asset_id": in.AssetID.String(), "location_id": nil, "stock_state": "installed",
			"parent_id": nil, "component_kind": nil, "component_id": nil}
		if in.ParentID != nil {
			place["parent_id"] = in.ParentID.String()
		}
		if name := strings.TrimSpace(in.Name); name != "" {
			place["name"] = name
		}
		if in.ModuleBayID != nil {
			mod, err := s.moduleInBay(ctx, tx, tenant, in.AssetID, *in.ModuleBayID, item)
			if err != nil {
				return err
			}
			place["component_kind"], place["component_id"] = "module", mod.String()
		}
		if n == have {
			out.Item, err = s.hw.eng.updateTx(ctx, tx, s.itemSpec(), tenant, id, place, "")
			return err
		}
		out.Item, out.Stock, err = s.split(ctx, tx, tenant, item, n, place)
		return err
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// moduleInBay is the module the spare is, in a bay of the asset: the bay's
// module, or one of the module type the spare's part number names, installed
// now (its templates instantiated) with the spare's serial.
func (s *SparesService) moduleInBay(ctx context.Context, tx *sql.Tx, tenant, asset, bay uuid.UUID, item map[string]any) (uuid.UUID, error) {
	var ok bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM module_bays WHERE id = $1 AND asset_id = $2 AND status <> 'rejected')`,
		bay, asset).Scan(&ok); err != nil {
		return uuid.Nil, err
	}
	if !ok {
		return uuid.Nil, ipamInvalid("module_bay_id must name a module bay of asset %s", asset)
	}
	var mod uuid.UUID
	err := tx.QueryRowContext(ctx, `SELECT id FROM modules WHERE module_bay_id = $1 AND status <> 'rejected'`, bay).Scan(&mod)
	if err == nil {
		return mod, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return uuid.Nil, err
	}
	part := str(item["part_id"])
	var typ uuid.UUID
	if part != "" {
		err = tx.QueryRowContext(ctx, `SELECT id FROM module_types
			WHERE (tenant_id = $1 OR tenant_id IS NULL) AND (lower(part_number) = lower($2) OR lower(model) = lower($2))
			ORDER BY tenant_id NULLS LAST, created_at LIMIT 1`, tenant, part).Scan(&typ)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return uuid.Nil, err
		}
	}
	if typ == uuid.Nil {
		return uuid.Nil, ipamInvalid("the module bay is empty and no module type has part number %q; install a module in the bay first", part)
	}
	row := map[string]any{"module_bay_id": bay.String(), "module_type_id": typ.String()}
	if serial := str(item["serial"]); serial != "" {
		row["serial"] = serial
	}
	res, err := s.hw.InstallModuleTx(ctx, tx, tenant, &asset, row, "")
	if err != nil {
		return uuid.Nil, err
	}
	return uuid.Parse(str(res.Module["id"]))
}

// Remove takes an item off its asset to a stock location.
func (s *SparesService) Remove(ctx context.Context, tenant, id uuid.UUID, in SpareRemoveInput) (*SpareResult, error) {
	var out SpareResult
	err := s.run(ctx, tenant, func(ctx context.Context, tx *sql.Tx) error {
		item, err := s.lockItem(ctx, tx, id)
		if err != nil {
			return err
		}
		st := str(item["stock_state"])
		if str(item["asset_id"]) == "" || (st != "installed" && st != "rma") {
			return ipamInvalid("only an item on an asset can be removed to stock; this one is %s and on no asset", st)
		}
		if in.LocationID == uuid.Nil {
			return ipamInvalid("location_id (the stock location) is required")
		}
		if err := s.refuseChildren(ctx, tx, item); err != nil {
			return err
		}
		target := st
		if st == "installed" {
			target = "in_stock"
			if in.StockState != "" {
				target = in.StockState
			}
			if target != "in_stock" && target != "reserved" {
				return ipamInvalid("stock_state must be in_stock or reserved")
			}
		}
		name := strings.TrimSpace(in.Name)
		if name == "" {
			name = str(item["name"])
		}
		patch := map[string]any{"asset_id": nil, "location_id": in.LocationID.String(), "parent_id": nil,
			"component_kind": nil, "component_id": nil, "stock_state": target, "name": name}
		if target != "rma" && str(item["serial"]) == "" {
			merged, err := s.mergeIntoStock(ctx, tx, tenant, item, in.LocationID, name, target)
			if err != nil || merged != nil {
				out.Item = merged
				return err
			}
		}
		out.Item, err = s.hw.eng.updateTx(ctx, tx, s.itemSpec(), tenant, id, patch, "")
		return err
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// mergeIntoStock adds an unserialised item to the stock row of the same name
// and part at the location (nil when there is none): the row's quantity grows
// and the item, now counted there, is deleted (its change recorded). The same
// name with another part is a conflict — two different parts cannot share a
// shelf name.
func (s *SparesService) mergeIntoStock(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, item map[string]any, loc uuid.UUID, name, state string) (map[string]any, error) {
	rows, err := jsonRows(ctx, tx, `SELECT to_jsonb(i) FROM inventory_items i
		WHERE i.location_id = $1 AND i.asset_id IS NULL AND i.name = $2 AND i.serial IS NULL AND i.stock_state = $3
		  AND i.status <> 'rejected' AND i.id <> $4 FOR UPDATE`, loc, name, state, str(item["id"]))
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	into := rows[0]
	if str(into["part_id"]) != str(item["part_id"]) || str(into["manufacturer_id"]) != str(item["manufacturer_id"]) {
		return nil, fmt.Errorf("%w: a spare named %q of another part is already %s at that location; give this one another name", ErrIPAMConflict, name, state)
	}
	merged, err := s.hw.eng.updateTx(ctx, tx, s.itemSpec(), tenant, uuid.MustParse(str(into["id"])),
		map[string]any{"quantity": quantityOf(into["quantity"]) + quantityOf(item["quantity"])}, "")
	if err != nil {
		return nil, err
	}
	pre, err := getRow(ctx, tx, s.itemSpec(), uuid.MustParse(str(item["id"])), true)
	if err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM inventory_items WHERE tenant_id = $1 AND id = $2`, tenant, str(item["id"])); err != nil {
		return nil, err
	}
	if err := recordIPAMChange(ctx, tx, s.itemSpec(), tenant, changes.ActionDelete, pre, nil, ""); err != nil {
		return nil, err
	}
	return merged, nil
}

// OpenRMA opens a case for an item and puts it (or one unit of a stock row of
// several) in rma.
func (s *SparesService) OpenRMA(ctx context.Context, tenant, id uuid.UUID, in SpareRMAInput) (*SpareResult, error) {
	var out SpareResult
	err := s.run(ctx, tenant, func(ctx context.Context, tx *sql.Tx) error {
		item, err := s.lockItem(ctx, tx, id)
		if err != nil {
			return err
		}
		switch st := str(item["stock_state"]); st {
		case "installed", "in_stock", "reserved":
		case "rma":
			return fmt.Errorf("%w: this item is already out for RMA", ErrIPAMConflict)
		default:
			return ipamInvalid("a %s item cannot go out for RMA", st)
		}
		var unit map[string]any
		if quantityOf(item["quantity"]) > 1 {
			// One unit of several goes out. On a shelf it stays there; off an
			// asset it needs a stock location, or it would share the asset's
			// item name with the rest.
			extra := map[string]any{"stock_state": "rma", "asset_id": item["asset_id"], "location_id": item["location_id"]}
			if str(item["asset_id"]) != "" {
				if in.LocationID == nil {
					return ipamInvalid("this item counts %d units; give location_id, the stock location the failed unit comes off the asset to", quantityOf(item["quantity"]))
				}
				extra["asset_id"], extra["location_id"] = nil, in.LocationID.String()
			}
			if unit, out.Stock, err = s.split(ctx, tx, tenant, item, 1, extra); err != nil {
				return err
			}
		} else {
			patch := map[string]any{"stock_state": "rma"}
			if str(item["asset_id"]) != "" && in.LocationID != nil {
				if err := s.refuseChildren(ctx, tx, item); err != nil {
					return err
				}
				patch["asset_id"], patch["location_id"], patch["parent_id"] = nil, in.LocationID.String(), nil
				patch["component_kind"], patch["component_id"] = nil, nil
			}
			if unit, err = s.hw.eng.updateTx(ctx, tx, s.itemSpec(), tenant, id, patch, ""); err != nil {
				return err
			}
		}
		row := map[string]any{"inventory_item_id": str(unit["id"]), "state": "open", "source_kind": "declared"}
		if loc, err := s.homeLocation(ctx, tx, unit); err != nil {
			return err
		} else if loc != "" {
			row["replacement_location_id"] = loc
		}
		for k, v := range map[string]string{"vendor": in.Vendor, "case_number": in.CaseNumber, "opened_at": in.OpenedAt, "notes": in.Notes} {
			if v = strings.TrimSpace(v); v != "" {
				row[k] = v
			}
		}
		out.Item = unit
		out.RMACase, err = s.rma.createTx(ctx, tx, s.caseSpec(), tenant, row, "")
		return err
	})
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// homeLocation is where an item sits: its stock location, or its asset's
// location ("" for neither).
func (s *SparesService) homeLocation(ctx context.Context, tx *sql.Tx, item map[string]any) (string, error) {
	if loc := str(item["location_id"]); loc != "" {
		return loc, nil
	}
	if str(item["asset_id"]) == "" {
		return "", nil
	}
	var l sql.NullString
	if err := tx.QueryRowContext(ctx, `SELECT location_id::text FROM assets WHERE id = $1`, str(item["asset_id"])).Scan(&l); err != nil {
		return "", err
	}
	return l.String, nil
}

// receiveReplacement lands the case's replacement in stock: the named one, or
// a new unit like the failed one at the case's replacement location (where the
// unit was when the case opened), else where the unit is now.
func (s *SparesService) receiveReplacement(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, item, rcase map[string]any) error {
	loc := str(rcase["replacement_location_id"])
	if loc == "" {
		var err error
		if loc, err = s.homeLocation(ctx, tx, item); err != nil {
			return err
		}
	}
	if rep := str(rcase["replacement_item_id"]); rep != "" {
		r, err := getRow(ctx, tx, s.itemSpec(), uuid.MustParse(rep), true)
		if err != nil {
			return err
		}
		if st := str(r["stock_state"]); st == "installed" || st == "in_stock" {
			return nil // already in service or on the shelf
		}
		patch := map[string]any{"stock_state": "in_stock", "asset_id": nil}
		if str(r["location_id"]) == "" {
			if loc == "" {
				return ipamInvalid("the replacement item has no stock location and the case names none (replacement_location_id)")
			}
			patch["location_id"] = loc
		}
		_, err = s.hw.eng.updateTx(ctx, tx, s.itemSpec(), tenant, uuid.MustParse(rep), patch, "")
		return err
	}
	if loc == "" {
		return ipamInvalid("the replacement needs a stock location: set the case's replacement_location_id, or create the replacement in stock and name it as replacement_item_id")
	}
	name := str(item["name"])
	var into map[string]any
	rows, err := jsonRows(ctx, tx, `SELECT to_jsonb(i) FROM inventory_items i
		WHERE i.location_id = $1::uuid AND i.asset_id IS NULL AND i.name = $2 AND i.serial IS NULL AND i.stock_state = 'in_stock'
		  AND i.status <> 'rejected' FOR UPDATE`, loc, name)
	if err != nil {
		return err
	}
	if len(rows) > 0 {
		if str(rows[0]["part_id"]) != str(item["part_id"]) {
			return fmt.Errorf("%w: a spare named %q of another part is already in stock there; create the replacement and name it as replacement_item_id", ErrIPAMConflict, name)
		}
		into, err = s.hw.eng.updateTx(ctx, tx, s.itemSpec(), tenant, uuid.MustParse(str(rows[0]["id"])),
			map[string]any{"quantity": quantityOf(rows[0]["quantity"]) + 1}, "")
	} else {
		row := map[string]any{"quantity": 1, "location_id": loc, "stock_state": "in_stock", "source_kind": "declared"}
		for _, f := range splitFields {
			if item[f] != nil {
				row[f] = item[f]
			}
		}
		into, err = s.hw.eng.createTx(ctx, tx, s.itemSpec(), tenant, row, "")
	}
	if err != nil {
		return err
	}
	_, err = s.rma.updateTx(ctx, tx, s.caseSpec(), tenant, uuid.MustParse(str(rcase["id"])), map[string]any{"replacement_item_id": str(into["id"])}, "")
	return err
}

// ListRMACases returns one page of cases.
func (s *SparesService) ListRMACases(ctx context.Context, tenant uuid.UUID, p IPAMListParams) ([]json.RawMessage, int, error) {
	return s.rma.List(ctx, tenant, HardwareRMACase, p)
}

// GetRMACase returns one case.
func (s *SparesService) GetRMACase(ctx context.Context, tenant, id uuid.UUID) (json.RawMessage, error) {
	return s.rma.Get(ctx, tenant, HardwareRMACase, id)
}

// UpdateRMACase patches a case (state, dates, vendor, case number,
// replacement, notes) and applies a state change to the item; it returns the
// case as it stands after the change (a received case names the replacement
// it created).
func (s *SparesService) UpdateRMACase(ctx context.Context, tenant, id uuid.UUID, body []byte) (json.RawMessage, error) {
	patch, err := decodeBody(s.caseSpec(), body)
	if err != nil {
		return nil, err
	}
	var out json.RawMessage
	err = s.run(ctx, tenant, func(ctx context.Context, tx *sql.Tx) error {
		if _, err := s.rma.updateTx(ctx, tx, s.caseSpec(), tenant, id, patch, ""); err != nil {
			return err
		}
		row, err := getRow(ctx, tx, s.caseSpec(), id, false)
		if err != nil {
			return err
		}
		out, err = json.Marshal(row)
		return err
	})
	return out, err
}
