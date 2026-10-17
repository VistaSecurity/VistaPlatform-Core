package services

// The inventory side of the sync for the dcim objects (DCIM BUILD_PLAN row
// 2.6; SYNC_MODEL §3): regions, site groups, sites, locations, the rack
// objects, the device catalogue, modules, inventory items, virtual chassis,
// and the placement and catalogue fields of an asset that came from a NetBox
// device. dcim_sync.go owns the protocol (list, changes, write, delete); this
// file answers it for these kinds, each through the service that already owns
// the table, so a sync write is validated, change-recorded and RLS-scoped
// exactly like a person's:
//
//   - regions, site groups, sites, locations → SiteService (tree depth, the
//     location-in-its-site rule, slugs);
//   - rack roles/types/racks/reservations, manufacturers, device roles,
//     platforms, module types, module bays, modules, inventory item roles,
//     inventory items, virtual chassis → the object engine over their specs;
//   - a device type created from the peer → the devicetype-library importer
//     (catalogue_import.go): the connector renders the peer's type and its
//     component templates as ONE library document, and the type and every
//     template are created by importOne, the same path a pasted library file
//     takes. There is no second template-instantiation path;
//   - an asset → never created or deleted here (the NetBox import creates it,
//     with the identity engine and the approval policy); its placement goes
//     through PlacementService (rack overlap, the rack's site), its catalogue
//     columns through CatalogueService.UpdateHardware, its chassis membership
//     through setMembership.
//
// The peer id is stamped into external_ids.<peer> by stampExternalID for the
// typed kinds, and through the engine's external_ids column otherwise.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	shareddb "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
	"github.com/vistasecurity/vistaplatform/shared/dcim/devicetypelib"
)

// dcimSyncObjects holds the services the row 2.6 kinds write through.
type dcimSyncObjects struct {
	raw       *sql.DB
	sx        *database.DB
	eng       *IPAMService
	sites     *SiteService
	catalogue *CatalogueService
	placement *PlacementService
	// cables writes a cable with its ends (row 3.5, dcim_sync_cabling.go).
	cables *CableService
}

func newDCIMSyncObjects(raw *sql.DB, db *database.DB) *dcimSyncObjects {
	o := &dcimSyncObjects{raw: raw, sx: db, eng: newObjectEngine(raw, dcimSyncSpecs())}
	if raw != nil {
		o.catalogue = NewCatalogueService(raw)
		o.placement = NewPlacementService(raw)
		o.cables = NewCableService(raw)
	}
	if db != nil {
		o.sites = NewSiteService(db)
	}
	return o
}

// dcimEngineKinds are the row 2.6 kinds served by the object engine.
var dcimEngineKinds = map[dcim.ObjectKind]bool{
	dcim.ObjectKindRackRole: true, dcim.ObjectKindRackType: true, dcim.ObjectKindRack: true,
	dcim.ObjectKindRackReservation: true, dcim.ObjectKindManufacturer: true, dcim.ObjectKindDeviceType: true,
	dcim.ObjectKindModuleType: true, dcim.ObjectKindDeviceRole: true, dcim.ObjectKindPlatform: true,
	dcim.ObjectKindModuleBay: true, dcim.ObjectKindModule: true, dcim.ObjectKindInventoryItemRole: true,
	dcim.ObjectKindInventoryItem: true, dcim.ObjectKindVirtualChassis: true,
}

// dcimSiteKinds are the row 2.6 kinds SiteService owns.
var dcimSiteKinds = map[dcim.ObjectKind]bool{
	dcim.ObjectKindRegion: true, dcim.ObjectKindSiteGroup: true, dcim.ObjectKindSite: true, dcim.ObjectKindLocation: true,
}

// dcimSyncSpecs are the engine specs of dcimEngineKinds and of row 3.5's port
// kinds (syncPortKinds), taken from the services that own them (no copy of a
// spec lives here).
func dcimSyncSpecs() []*ipamSpec {
	var out []*ipamSpec
	all := append(append(append(rackSpecs(), catalogueSpecs()...), hardwareSpecs()...), componentSpecs()...)
	for _, sp := range all {
		if dcimEngineKinds[sp.Kind] || syncPortKinds[sp.Kind] {
			out = append(out, sp)
		}
	}
	return out
}

// engine is the row 2.6 object engine (nil-safe, for a service built without
// a pool in the route-gate tests).
func (o *dcimSyncObjects) engine() *IPAMService {
	if o == nil {
		return &IPAMService{specs: map[string]*ipamSpec{}}
	}
	return o.eng
}

// ---------------------------------------------------------------------------
// List: an asset is listed only when a NetBox device names it.
// ---------------------------------------------------------------------------

// syncAssetColumns are an asset's synced columns (sync-authority.yaml kind
// asset), read in their API shape.
var syncAssetColumns = []string{
	"display_name", "site_id", "location_id", "rack_id", "position", "face", "device_role_id", "platform_id",
	"device_type_id", "serial", "asset_tag", "virtual_chassis_id", "vc_position", "vc_priority",
}

// listDCIM answers ListObjects for the kinds whose listing is not a plain
// table read; handled is false for every other kind.
func (s *DCIMSyncService) listDCIM(ctx context.Context, tenant uuid.UUID, kind dcim.ObjectKind, after uuid.UUID, limit int) ([]SyncObject, bool, bool, error) {
	if kind == dcim.ObjectKindCable {
		out, more, err := s.listCables(ctx, tenant, after, limit)
		return out, more, true, err
	}
	if kind != dcim.ObjectKindAsset {
		return nil, false, false, nil
	}
	if limit <= 0 || limit > 1000 {
		limit = 500
	}
	pairs := make([]string, 0, 2*len(syncAssetColumns))
	for _, c := range syncAssetColumns {
		pairs = append(pairs, pq.QuoteLiteral(c), "a."+pq.QuoteIdentifier(c))
	}
	// The asset a NetBox device id names is the oldest live one carrying it
	// (PeerAssets' rule), so a duplicate never syncs as a second device.
	q := fmt.Sprintf(`
		SELECT a.id, jsonb_build_object(%s) || jsonb_build_object('external_ids', jsonb_build_object('netbox', a.metadata ->> 'netbox_device_id')),
		       a.updated_at, CASE WHEN a.import_only_sources IS NULL THEN a.last_seen_at END
		  FROM public.assets a
		 WHERE a.tenant_id = $1 AND a.deleted_at IS NULL AND a.id > $2 AND a.metadata ? 'netbox_device_id'
		   AND a.id = (SELECT b.id FROM public.assets b WHERE b.tenant_id = a.tenant_id AND b.deleted_at IS NULL
		                 AND b.metadata ->> 'netbox_device_id' = a.metadata ->> 'netbox_device_id' ORDER BY b.created_at, b.id LIMIT 1)
		 ORDER BY a.id LIMIT $3`, strings.Join(pairs, ", "))
	var out []SyncObject
	err := shareddb.WithTenantTx(ctx, s.raw, tenant, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, q, tenant, after, limit+1)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var (
				id       uuid.UUID
				raw      []byte
				updated  time.Time
				observed sql.NullTime
			)
			if err := rows.Scan(&id, &raw, &updated, &observed); err != nil {
				return err
			}
			dec := json.NewDecoder(strings.NewReader(string(raw)))
			dec.UseNumber()
			var values map[string]any
			if err := dec.Decode(&values); err != nil {
				return err
			}
			values["id"] = id.String()
			obj := SyncObject{ID: id, Values: values, UpdatedAt: updated}
			if observed.Valid {
				t := observed.Time
				obj.ObservedAt = &t
			}
			out = append(out, obj)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, false, true, err
	}
	more := len(out) > limit
	if more {
		out = out[:limit]
	}
	return out, more, true, nil
}

// ---------------------------------------------------------------------------
// Create
// ---------------------------------------------------------------------------

// createDCIM creates one object of a row 2.6 kind; handled is false for a kind
// the generic engine path writes unchanged.
func (s *DCIMSyncService) createDCIM(ctx context.Context, tenant uuid.UUID, peer string, kind dcim.ObjectKind, it SyncWrite) (uuid.UUID, bool, error) {
	o := s.objs
	if o == nil {
		return uuid.Nil, false, nil
	}
	sourceRef := peer + ":" + it.PeerID
	switch {
	case kind == dcim.ObjectKindAsset:
		return uuid.Nil, true, fmt.Errorf("%w: the sync never creates an asset; the NetBox import does, and the sync then owns its placement", ErrSyncInvalid)
	case kind == dcim.ObjectKindDeviceType:
		id, err := o.createDeviceType(ctx, tenant, peer, it)
		return id, true, err
	case kind == dcim.ObjectKindCable:
		id, err := o.createCable(ctx, tenant, peer, it)
		return id, true, err
	case dcimSiteKinds[kind]:
		if o.sites == nil {
			return uuid.Nil, true, fmt.Errorf("%w: %s has no writer", ErrSyncInvalid, kind)
		}
		id, err := o.createSiteKind(ctx, tenant, kind, it.Values)
		if err != nil {
			return uuid.Nil, true, mapSiteSyncError(err)
		}
		return id, true, o.stampExternalID(ctx, tenant, kind, id, peer, it.PeerID, &sourceRef, false)
	}
	return uuid.Nil, false, nil
}

func (o *dcimSyncObjects) createSiteKind(ctx context.Context, tenant uuid.UUID, kind dcim.ObjectKind, values map[string]any) (uuid.UUID, error) {
	switch kind {
	case dcim.ObjectKindRegion, dcim.ObjectKindSiteGroup:
		var in models.RegionInput
		if err := remarshal(values, &in); err != nil {
			return uuid.Nil, err
		}
		if kind == dcim.ObjectKindRegion {
			r, err := o.sites.CreateRegion(ctx, tenant, uuid.Nil, in)
			if err != nil {
				return uuid.Nil, err
			}
			return r.ID, nil
		}
		g, err := o.sites.CreateSiteGroup(ctx, tenant, uuid.Nil, in)
		if err != nil {
			return uuid.Nil, err
		}
		return g.ID, nil
	case dcim.ObjectKindSite:
		var in models.SiteInput
		if err := remarshal(values, &in); err != nil {
			return uuid.Nil, err
		}
		st, err := o.sites.CreateSite(ctx, tenant, uuid.Nil, in)
		if err != nil {
			return uuid.Nil, err
		}
		return st.ID, nil
	default:
		var in models.LocationInput
		if err := remarshal(values, &in); err != nil {
			return uuid.Nil, err
		}
		l, err := o.sites.CreateLocation(ctx, tenant, uuid.Nil, in)
		if err != nil {
			return uuid.Nil, err
		}
		return l.ID, nil
	}
}

// createDeviceType creates a device type pulled from the peer through the
// devicetype-library importer. The write carries the library document the
// connector rendered from the peer's type and templates; Values carry the
// synced columns (the identity's manufacturer as OUR id, and what a library
// document cannot say, such as the default platform).
func (o *dcimSyncObjects) createDeviceType(ctx context.Context, tenant uuid.UUID, peer string, it SyncWrite) (uuid.UUID, error) {
	if o.catalogue == nil {
		return uuid.Nil, fmt.Errorf("%w: device_type has no writer", ErrSyncInvalid)
	}
	if strings.TrimSpace(it.Library) == "" {
		return uuid.Nil, fmt.Errorf("%w: a device type is created from its device-type library document (library), which the write lacks", ErrSyncInvalid)
	}
	docs, err := devicetypelib.Parse([]byte(it.Library))
	if err != nil {
		return uuid.Nil, fmt.Errorf("%w: the device type's library document: %v", ErrSyncInvalid, err)
	}
	if len(docs) != 1 {
		return uuid.Nil, fmt.Errorf("%w: one write creates one device type (the document holds %d)", ErrSyncInvalid, len(docs))
	}
	doc := docs[0]
	var id uuid.UUID
	err = shareddb.WithTenantTx(ctx, o.raw, tenant, func(tx *sql.Tx) error {
		// The manufacturer is the one the sync already linked (its identity),
		// named the way OUR row names it, so the importer finds it rather than
		// creating a second one from the peer's spelling.
		if m, ok := it.Values["manufacturer_id"]; ok && m != nil {
			var name string
			if err := tx.QueryRowContext(ctx, `SELECT name FROM public.manufacturers WHERE id = $1::uuid`, fmt.Sprint(m)).Scan(&name); err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					return ipamInvalid("no such manufacturer %v", m)
				}
				return err
			}
			doc.Manufacturer = name
		}
		res, err := o.catalogue.importOne(ctx, tx, tenant, doc)
		if err != nil {
			return err
		}
		id = res.DeviceTypeID
		sp := o.eng.specs["device-types"]
		pre, err := getRow(ctx, tx, sp, id, true)
		if err != nil {
			return err
		}
		if pre["tenant_id"] == nil {
			return nil // a platform type of that manufacturer and model: read-only, nothing to stamp
		}
		patch := map[string]any{}
		for k, v := range it.Values {
			if k == "manufacturer_id" {
				continue
			}
			patch[k] = v
		}
		patch["external_ids"] = externalIDsWith(pre["external_ids"], peer, it.PeerID)
		if res.Status == "created" {
			patch["source_ref"] = peer + ":" + it.PeerID
		}
		_, err = o.eng.updateTx(ctx, tx, sp, tenant, id, patch, "")
		return err
	})
	return id, mapIPAMError(err, false)
}

// ---------------------------------------------------------------------------
// Update
// ---------------------------------------------------------------------------

// updateDCIM updates one object of a row 2.6 kind; handled is false for a kind
// the generic engine path writes unchanged.
func (s *DCIMSyncService) updateDCIM(ctx context.Context, tenant uuid.UUID, peer string, kind dcim.ObjectKind, it SyncWrite) (bool, error) {
	o := s.objs
	if o == nil {
		return false, nil
	}
	switch {
	case kind == dcim.ObjectKindAsset:
		if it.Unlink {
			return true, fmt.Errorf("%w: an asset's NetBox link is the import's, not the sync's", ErrSyncInvalid)
		}
		return true, o.writeAsset(ctx, tenant, it.ID, it.Values)
	case kind == dcim.ObjectKindCable:
		return true, o.updateCable(ctx, tenant, peer, it)
	case dcimSiteKinds[kind]:
		if o.sites == nil {
			return true, fmt.Errorf("%w: %s has no writer", ErrSyncInvalid, kind)
		}
		if len(it.Values) > 0 {
			if err := o.updateSiteKind(ctx, tenant, kind, it.ID, it.Values); err != nil {
				return true, mapSiteSyncError(err)
			}
		}
		return true, o.stampExternalID(ctx, tenant, kind, it.ID, peer, it.PeerID, nil, it.Unlink)
	case kind == dcim.ObjectKindVirtualChassis:
		// NetBox's master is always a member of its chassis; make it one here
		// before the engine's rule (the master must be a member) is checked.
		// The member's position and priority follow with the asset.
		if m, ok := it.Values["master_asset_id"]; ok && m != nil {
			if err := o.joinMaster(ctx, tenant, it.ID, fmt.Sprint(m)); err != nil {
				return true, mapIPAMError(err, false)
			}
		}
	}
	return false, nil
}

func (o *dcimSyncObjects) updateSiteKind(ctx context.Context, tenant uuid.UUID, kind dcim.ObjectKind, id uuid.UUID, values map[string]any) error {
	switch kind {
	case dcim.ObjectKindRegion, dcim.ObjectKindSiteGroup:
		var in models.RegionInput
		if err := remarshal(values, &in); err != nil {
			return err
		}
		if kind == dcim.ObjectKindRegion {
			_, err := o.sites.UpdateRegion(ctx, tenant, uuid.Nil, id, in)
			return err
		}
		_, err := o.sites.UpdateSiteGroup(ctx, tenant, uuid.Nil, id, in)
		return err
	case dcim.ObjectKindSite:
		var in models.SiteInput
		if err := remarshal(values, &in); err != nil {
			return err
		}
		_, err := o.sites.UpdateSite(ctx, tenant, uuid.Nil, id, in)
		return err
	default:
		var in models.LocationInput
		if err := remarshal(values, &in); err != nil {
			return err
		}
		_, err := o.sites.UpdateLocation(ctx, tenant, uuid.Nil, id, in)
		return err
	}
}

// joinMaster makes asset a member of chassis vc when it is in no chassis.
func (o *dcimSyncObjects) joinMaster(ctx context.Context, tenant, vc uuid.UUID, asset string) error {
	aid, err := uuid.Parse(asset)
	if err != nil {
		return ipamInvalid("master_asset_id is not a uuid")
	}
	return shareddb.WithTenantTx(ctx, o.raw, tenant, func(tx *sql.Tx) error {
		var cur uuid.NullUUID
		if err := tx.QueryRowContext(ctx, `SELECT virtual_chassis_id FROM public.assets WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL`,
			tenant, aid).Scan(&cur); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ipamInvalid("no such asset %s", aid)
			}
			return err
		}
		if cur.Valid {
			return nil // already a member (here or elsewhere: the engine decides)
		}
		return setMembership(ctx, tx, tenant, aid, &vc, nil, nil)
	})
}

// writeAsset applies a sync's write to an asset's synced columns, each group
// through the service that owns it: catalogue columns first (a new device type
// changes the height the placement checks), then the rack placement, then the
// site and location of an unracked asset, then the chassis membership.
func (o *dcimSyncObjects) writeAsset(ctx context.Context, tenant, asset uuid.UUID, values map[string]any) error {
	if o.catalogue == nil || o.placement == nil {
		return fmt.Errorf("%w: asset has no writer", ErrSyncInvalid)
	}
	hw := HardwarePatch{}
	for _, k := range []string{"device_type_id", "device_role_id", "platform_id", "serial", "asset_tag"} {
		if v, ok := values[k]; ok {
			b, err := json.Marshal(stringOrNil(v))
			if err != nil {
				return err
			}
			hw[k] = b
		}
	}
	if len(hw) > 0 {
		if _, err := o.catalogue.UpdateHardware(ctx, tenant, asset, hw); err != nil {
			return err
		}
	}

	_, rackSet := values["rack_id"]
	_, posSet := values["position"]
	_, faceSet := values["face"]
	cur, err := o.placement.Get(ctx, tenant, asset)
	if err != nil {
		return err
	}
	racked := cur.Rack != nil
	if rackSet || posSet || faceSet {
		var rack *uuid.UUID
		if cur.Rack != nil {
			r := cur.Rack.ID
			rack = &r
		}
		pos, face := cur.Position, cur.Face
		if rackSet {
			rack = nil
			if s := stringOrNil(values["rack_id"]); s != nil {
				r, err := uuid.Parse(*s)
				if err != nil {
					return ipamInvalid("rack_id is not a uuid")
				}
				rack = &r
			}
		}
		if posSet {
			pos = nil
			if f, ok := floatOf(values["position"]); ok {
				pos = &f
			}
		}
		if faceSet {
			face = stringOrNil(values["face"])
		}
		switch {
		case rack != nil && pos == nil:
			return ipamInvalid("NetBox has this device in a rack without a position; a racked asset here takes a U position")
		case rack != nil:
			f := "front"
			if face != nil {
				f = *face
			}
			if _, err := o.placement.Place(ctx, tenant, asset, PlaceInput{RackID: *rack, Position: *pos, Face: f}); err != nil {
				return err
			}
			racked = true
		case cur.Rack != nil:
			if _, err := o.placement.Unplace(ctx, tenant, asset); err != nil {
				return err
			}
			racked = false
		}
	}

	_, siteSet := values["site_id"]
	_, locSet := values["location_id"]
	if (siteSet || locSet) && !racked && o.sx != nil {
		var siteRef, locRef *string
		if siteSet {
			v := ""
			if s := stringOrNil(values["site_id"]); s != nil {
				v = *s
			}
			siteRef = &v
		}
		if locSet {
			v := ""
			if s := stringOrNil(values["location_id"]); s != nil {
				v = *s
			}
			locRef = &v
		}
		if err := o.setAssetSite(ctx, tenant, asset, siteRef, locRef); err != nil {
			return err
		}
	}

	_, vcSet := values["virtual_chassis_id"]
	_, vposSet := values["vc_position"]
	_, vpriSet := values["vc_priority"]
	if vcSet || vposSet || vpriSet {
		return mapIPAMError(shareddb.WithTenantTx(ctx, o.raw, tenant, func(tx *sql.Tx) error {
			var (
				vc       uuid.NullUUID
				pos, pri sql.NullInt64
			)
			if err := tx.QueryRowContext(ctx, `SELECT virtual_chassis_id, vc_position, vc_priority FROM public.assets WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL`,
				tenant, asset).Scan(&vc, &pos, &pri); err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					return ErrCatalogueAssetNotFound
				}
				return err
			}
			var vcp *uuid.UUID
			if vc.Valid {
				u := vc.UUID
				vcp = &u
			}
			if vcSet {
				vcp = nil
				if s := stringOrNil(values["virtual_chassis_id"]); s != nil {
					u, err := uuid.Parse(*s)
					if err != nil {
						return ipamInvalid("virtual_chassis_id is not a uuid")
					}
					vcp = &u
				}
			}
			posp, prip := nullIntPtr(pos), nullIntPtr(pri)
			if vposSet {
				posp = intPtrOf(values["vc_position"])
			}
			if vpriSet {
				prip = intPtrOf(values["vc_priority"])
			}
			if vcp != nil && posp != nil {
				// A position is unique within its chassis: a member moving onto a
				// taken position is NetBox's statement that the other moved too;
				// that member's own write follows in this run.
				var taken bool
				if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM public.assets WHERE tenant_id = $1 AND virtual_chassis_id = $2
					AND vc_position = $3 AND id <> $4 AND deleted_at IS NULL)`, tenant, *vcp, *posp, asset).Scan(&taken); err != nil {
					return err
				}
				if taken {
					return fmt.Errorf("%w: position %d of the virtual chassis is taken", ErrIPAMConflict, *posp)
				}
			}
			return setMembership(ctx, tx, tenant, asset, vcp, posp, prip)
		}), false)
	}
	return nil
}

// setAssetSite writes an unracked asset's site and location (the asset
// service's placement rules: ResolveAssetPlacement, the rack consistency
// check, the recorded change).
func (o *dcimSyncObjects) setAssetSite(ctx context.Context, tenant, asset uuid.UUID, siteRef, locRef *string) error {
	err := database.WithTenantTx(ctx, o.sx, tenant, func(tx *sqlx.Tx) error {
		var curSite, curLoc uuid.NullUUID
		if err := tx.QueryRowContext(ctx, `SELECT site_id, location_id FROM assets WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL FOR UPDATE`,
			tenant, asset).Scan(&curSite, &curLoc); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrCatalogueAssetNotFound
			}
			return err
		}
		site, loc, changed, err := ResolveAssetPlacement(ctx, tx, nullUUIDPtr(curSite), nullUUIDPtr(curLoc), siteRef, locRef)
		if err != nil || !changed {
			return err
		}
		if err := CheckRackConsistencyTx(ctx, tx, tenant, asset, site, loc); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE assets SET site_id = $3, location_id = $4, updated_at = now() WHERE tenant_id = $1 AND id = $2`,
			tenant, asset, site, loc); err != nil {
			return err
		}
		return o.sites.RecordAssetPlacement(ctx, tx, tenant, uuid.Nil, asset, nullUUIDPtr(curSite), nullUUIDPtr(curLoc), site, loc)
	})
	return mapSiteSyncError(err)
}

// ---------------------------------------------------------------------------
// Delete
// ---------------------------------------------------------------------------

// deleteDCIM deletes one object of a row 2.6 kind after a person accepted the
// delete proposal; handled is false for every other kind.
func (s *DCIMSyncService) deleteDCIM(ctx context.Context, tenant uuid.UUID, kind dcim.ObjectKind, id uuid.UUID) (bool, error) {
	o := s.objs
	if o == nil {
		return false, nil
	}
	switch {
	case kind == dcim.ObjectKindAsset:
		return true, fmt.Errorf("%w: the sync never deletes an asset; a device removed from NetBox is the import's drift report", ErrSyncInvalid)
	case kind == dcim.ObjectKindCable:
		if o.cables == nil {
			return true, fmt.Errorf("%w: cable has no writer", ErrSyncInvalid)
		}
		return true, mapIPAMError(o.cables.Delete(ctx, tenant, id), true)
	case dcimSiteKinds[kind]:
		if o.sites == nil {
			return true, fmt.Errorf("%w: %s has no writer", ErrSyncInvalid, kind)
		}
		var err error
		switch kind {
		case dcim.ObjectKindRegion:
			err = o.sites.DeleteRegion(ctx, tenant, uuid.Nil, id)
		case dcim.ObjectKindSiteGroup:
			err = o.sites.DeleteSiteGroup(ctx, tenant, uuid.Nil, id)
		case dcim.ObjectKindSite:
			err = o.sites.DeleteSite(ctx, tenant, uuid.Nil, id, nil)
		default:
			err = o.sites.DeleteLocation(ctx, tenant, uuid.Nil, id)
		}
		return true, mapSiteSyncError(err)
	}
	return false, nil
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// stampExternalID records (or, with unlink, removes) the peer id on an object
// of a typed kind, and on a create its import provenance — recorded as the
// sync's own change, which Changes excludes.
func (o *dcimSyncObjects) stampExternalID(ctx context.Context, tenant uuid.UUID, kind dcim.ObjectKind, id uuid.UUID, peer, peerID string, sourceRef *string, unlink bool) error {
	if peerID == "" && sourceRef == nil && !unlink {
		return nil
	}
	table := pq.QuoteIdentifier(kind.Table())
	return shareddb.WithTenantTx(ctx, o.raw, tenant, func(tx *sql.Tx) error {
		var cur []byte
		if err := tx.QueryRowContext(ctx, `SELECT external_ids FROM public.`+table+` WHERE tenant_id = $1 AND id = $2 FOR UPDATE`, tenant, id).Scan(&cur); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrSyncNotFound
			}
			return err
		}
		var existing map[string]any
		_ = json.Unmarshal(cur, &existing)
		next := externalIDsWith(existing, peer, peerID)
		if unlink {
			next = externalIDsWithout(existing, peer)
		}
		nb, _ := json.Marshal(next)
		if string(nb) == string(cur) && sourceRef == nil {
			return nil
		}
		if sourceRef != nil {
			if _, err := tx.ExecContext(ctx, `UPDATE public.`+table+` SET external_ids = $3::jsonb, source_kind = 'imported', source_ref = $4 WHERE tenant_id = $1 AND id = $2`,
				tenant, id, string(nb), *sourceRef); err != nil {
				return err
			}
		} else if _, err := tx.ExecContext(ctx, `UPDATE public.`+table+` SET external_ids = $3::jsonb WHERE tenant_id = $1 AND id = $2`,
			tenant, id, string(nb)); err != nil {
			return err
		}
		return changes.InTx(tx).Record(ctx, changes.Change{
			TenantID: tenant, Kind: kind, ID: id, Action: changes.ActionUpdate,
			Pre: map[string]any{"external_ids": existing}, Post: map[string]any{"external_ids": next},
		})
	})
}

// mapSiteSyncError maps SiteService's errors onto the sync's.
func mapSiteSyncError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrSiteNotFound):
		return fmt.Errorf("%w: %v", ErrSyncNotFound, err)
	case errors.Is(err, ErrSiteInvalid), errors.Is(err, ErrSiteConflict):
		return fmt.Errorf("%w: %v", ErrSyncInvalid, err)
	}
	var inUse *SiteInUseError
	if errors.As(err, &inUse) {
		return fmt.Errorf("%w: %v", ErrSyncInvalid, err)
	}
	return err
}

func stringOrNil(v any) *string {
	if v == nil {
		return nil
	}
	s := strings.TrimSpace(fmt.Sprint(v))
	if s == "" {
		return nil
	}
	return &s
}

func floatOf(v any) (float64, bool) {
	switch t := v.(type) {
	case float64:
		return t, true
	case int:
		return float64(t), true
	case json.Number:
		f, err := t.Float64()
		return f, err == nil
	case string:
		var f float64
		_, err := fmt.Sscan(t, &f)
		return f, err == nil
	}
	return 0, false
}

func intPtrOf(v any) *int {
	f, ok := floatOf(v)
	if !ok {
		return nil
	}
	n := int(f)
	return &n
}

func nullIntPtr(n sql.NullInt64) *int {
	if !n.Valid {
		return nil
	}
	v := int(n.Int64)
	return &v
}
