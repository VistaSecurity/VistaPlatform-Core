package services

// The inventory side of a one-way DCIM import (DCIM SYNC_MODEL §6; BUILD_PLAN
// row 5.6): what an import-only connector running outside this service (the
// Enterprise Device42 importer) reads and writes through the HMAC-only
// /internal/dcim-import/* routes.
//
// It is not the bidirectional sync surface (/internal/dcim-sync/*, dcim_sync.go)
// and deliberately so. A sync decides per field who wins, from the authority
// registry, and only for the kinds that registry names; an import has one
// authority for everything (`imported`) and needs the physical kinds — sites,
// locations, racks, device types, ports, cables, circuits — that the sync does
// not carry yet. So an import is matched on its own provenance and nothing
// else: every object it writes carries source_kind = 'imported' and a
// source_ref the connector chose (`<producer>:<connection>:<class>:<id>`),
// and the next run finds the same object by that source_ref. Nothing here
// merges an import into an object a person declared or a collector measured:
// the identification engine does that for assets, through /internal/sources/*.
//
// Three operations:
//
//   - Objects: the kind's objects whose source_ref starts with a prefix — what
//     an earlier run wrote — in their stored shape, so the connector can plan
//     creates and updates (the dry run) without writing anything.
//   - Write: create or update, matched by source_ref. Every write goes through
//     the kind's own service (validation, custom-field defaults, cable paths,
//     rack utilisation) and is recorded in object_changes as `intake:<producer>`.
//   - Placements: put an imported asset in a rack at a unit and face, and give
//     it its device type (templates instantiated), through the placement and
//     catalogue services.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	shareddb "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
)

// Import errors the handlers map onto statuses.
var (
	ErrImportInvalid = errors.New("invalid import request")
)

var importProducerPattern = regexp.MustCompile(`^[a-z0-9_]+$`)

// ImportAssetRefKey is the asset metadata key an import connector stamps its
// source_ref under when it resolves a device through /internal/sources/assets
// (the identification engine owns assets, so the reference cannot live in
// assets.source_ref, which belongs to the asset's first discoverer).
const ImportAssetRefKey = "import_ref"

// ImportObject is one previously imported object.
type ImportObject struct {
	ID        uuid.UUID      `json:"id"`
	SourceRef string         `json:"source_ref"`
	Values    map[string]any `json:"values"`
}

// ImportWrite is one create-or-update, matched on SourceRef.
type ImportWrite struct {
	SourceRef string         `json:"source_ref"`
	PeerID    string         `json:"peer_id,omitempty"`
	Values    map[string]any `json:"values"`
}

// Import write outcomes.
const (
	ImportCreated = "created"
	ImportUpdated = "updated"
)

// ImportWriteResult answers one ImportWrite, in order.
type ImportWriteResult struct {
	ID     uuid.UUID `json:"id,omitempty"`
	Action string    `json:"action,omitempty"`
	Error  string    `json:"error,omitempty"`
}

// ImportPlacement places one asset.
type ImportPlacement struct {
	AssetID      uuid.UUID  `json:"asset_id"`
	DeviceTypeID *uuid.UUID `json:"device_type_id,omitempty"`
	RackID       *uuid.UUID `json:"rack_id,omitempty"`
	Position     *float64   `json:"position,omitempty"`
	Face         string     `json:"face,omitempty"`
}

// ImportPlacementResult answers one ImportPlacement, in order.
type ImportPlacementResult struct {
	AssetID uuid.UUID `json:"asset_id"`
	Error   string    `json:"error,omitempty"`
}

// importEngineKind is a kind written through the object engine.
type importEngineKind struct {
	eng   *IPAMService
	route string
}

// DCIMImportService implements the internal import surface.
type DCIMImportService struct {
	raw        *sql.DB
	engines    map[dcim.ObjectKind]importEngineKind
	cables     *CableService
	sites      *SiteService
	units      *BusinessUnitService
	interfaces *InterfaceService
	placement  *PlacementService
	catalogue  *CatalogueService
}

// NewDCIMImportService builds the service over the raw (RLS-subject) pool and
// the sqlx wrapper the site and business-unit services use.
func NewDCIMImportService(raw *sql.DB, db *database.DB) *DCIMImportService {
	s := &DCIMImportService{
		raw: raw, engines: map[dcim.ObjectKind]importEngineKind{},
		cables: NewCableService(raw), sites: NewSiteService(db), units: NewBusinessUnitService(db),
		interfaces: NewInterfaceService(raw), placement: NewPlacementService(raw), catalogue: NewCatalogueService(raw),
	}
	add := func(eng *IPAMService, kinds ...dcim.ObjectKind) {
		for _, sp := range eng.specs {
			for _, k := range kinds {
				if sp.Kind == k {
					s.engines[k] = importEngineKind{eng: eng, route: sp.Route}
				}
			}
		}
	}
	add(NewIPAMService(raw), dcim.ObjectKindVrf, dcim.ObjectKindVlan, dcim.ObjectKindPrefix, dcim.ObjectKindIpAddress)
	add(newObjectEngine(raw, catalogueSpecs()), dcim.ObjectKindManufacturer, dcim.ObjectKindDeviceType)
	add(newObjectEngine(raw, rackSpecs()), dcim.ObjectKindRack)
	add(newObjectEngine(raw, circuitSpecs()), dcim.ObjectKindProvider, dcim.ObjectKindCircuitType, dcim.ObjectKindCircuit)
	add(newObjectEngine(raw, componentSpecs()), dcim.ObjectKindFrontPort, dcim.ObjectKindRearPort)
	return s
}

// ImportKinds lists the kinds Write accepts (the asset kind is read-only: an
// asset is written through the identification engine).
func ImportKinds() []dcim.ObjectKind {
	return []dcim.ObjectKind{
		dcim.ObjectKindBusinessUnit, dcim.ObjectKindSite, dcim.ObjectKindLocation, dcim.ObjectKindRack,
		dcim.ObjectKindManufacturer, dcim.ObjectKindDeviceType, dcim.ObjectKindInterface,
		dcim.ObjectKindFrontPort, dcim.ObjectKindRearPort, dcim.ObjectKindCable,
		dcim.ObjectKindVrf, dcim.ObjectKindVlan, dcim.ObjectKindPrefix, dcim.ObjectKindIpAddress,
		dcim.ObjectKindProvider, dcim.ObjectKindCircuitType, dcim.ObjectKindCircuit,
	}
}

func importKindAllowed(kind dcim.ObjectKind) bool {
	for _, k := range ImportKinds() {
		if k == kind {
			return true
		}
	}
	return false
}

func checkImportRef(producer, ref string) error {
	if !importProducerPattern.MatchString(producer) {
		return fmt.Errorf("%w: producer %q", ErrImportInvalid, producer)
	}
	if !strings.HasPrefix(ref, producer+":") || len(ref) <= len(producer)+1 || len(ref) > 500 {
		return fmt.Errorf("%w: source_ref %q must start with %q", ErrImportInvalid, ref, producer+":")
	}
	return nil
}

// Objects returns the kind's objects whose source_ref starts with prefix, in
// source_ref order. For the asset kind the reference is the asset's
// metadata.import_ref and the values are its placement.
func (s *DCIMImportService) Objects(ctx context.Context, tenant uuid.UUID, kind dcim.ObjectKind, prefix string) ([]ImportObject, error) {
	producer, _, _ := strings.Cut(prefix, ":")
	if err := checkImportRef(producer, prefix); err != nil {
		return nil, err
	}
	var q string
	switch {
	case kind == dcim.ObjectKindAsset:
		q = fmt.Sprintf(`SELECT a.id, a.metadata ->> '%s', jsonb_build_object(
				'display_name', a.display_name, 'rack_id', a.rack_id, 'position', a.position,
				'face', a.face, 'device_type_id', a.device_type_id)
			  FROM public.assets a
			 WHERE a.tenant_id = $1 AND a.deleted_at IS NULL
			   AND left(a.metadata ->> '%[1]s', length($2)) = $2
			 ORDER BY a.metadata ->> '%[1]s', a.id`, ImportAssetRefKey)
	case importKindAllowed(kind):
		q = fmt.Sprintf(`SELECT t.id, t.source_ref, to_jsonb(t) - 'tenant_id'
			  FROM public.%s t
			 WHERE t.tenant_id = $1 AND left(t.source_ref, length($2)) = $2
			 ORDER BY t.source_ref, t.id`, pq.QuoteIdentifier(kind.Table()))
	default:
		return nil, fmt.Errorf("%w: %q is not an imported object kind", ErrImportInvalid, kind)
	}
	var out []ImportObject
	err := shareddb.WithTenantTx(ctx, s.raw, tenant, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, q, tenant, prefix)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var o ImportObject
			var raw []byte
			if err := rows.Scan(&o.ID, &o.SourceRef, &raw); err != nil {
				return err
			}
			if err := json.Unmarshal(raw, &o.Values); err != nil {
				return err
			}
			out = append(out, o)
		}
		return rows.Err()
	})
	return out, err
}

// findByRef returns the object of kind carrying ref, or uuid.Nil.
func (s *DCIMImportService) findByRef(ctx context.Context, tenant uuid.UUID, kind dcim.ObjectKind, ref string) (uuid.UUID, error) {
	var id uuid.UUID
	err := shareddb.WithTenantTx(ctx, s.raw, tenant, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, fmt.Sprintf(`SELECT id FROM public.%s WHERE tenant_id = $1 AND source_ref = $2 ORDER BY created_at LIMIT 1`,
			pq.QuoteIdentifier(kind.Table())), tenant, ref).Scan(&id)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return uuid.Nil, nil
	}
	return id, err
}

// Write applies writes of one kind, each on its own, in order. A refused
// write is reported on its result and the rest still run.
func (s *DCIMImportService) Write(ctx context.Context, tenant uuid.UUID, producer string, kind dcim.ObjectKind, items []ImportWrite) ([]ImportWriteResult, error) {
	if !importProducerPattern.MatchString(producer) {
		return nil, fmt.Errorf("%w: producer %q", ErrImportInvalid, producer)
	}
	if !importKindAllowed(kind) {
		return nil, fmt.Errorf("%w: %q is not an imported object kind", ErrImportInvalid, kind)
	}
	ctx = changes.WithSource(ctx, changes.IntakeSource(producer))
	out := make([]ImportWriteResult, len(items))
	for i, it := range items {
		if err := checkImportRef(producer, it.SourceRef); err != nil {
			out[i].Error = err.Error()
			continue
		}
		if _, ok := it.Values["source_ref"]; ok {
			out[i].Error = "source_ref is set from the write, not from its values"
			continue
		}
		existing, err := s.findByRef(ctx, tenant, kind, it.SourceRef)
		if err != nil {
			out[i].Error = err.Error()
			continue
		}
		if existing != uuid.Nil {
			if err := s.update(ctx, tenant, producer, kind, existing, it); err != nil {
				out[i].Error = err.Error()
				continue
			}
			out[i] = ImportWriteResult{ID: existing, Action: ImportUpdated}
			continue
		}
		id, err := s.create(ctx, tenant, producer, kind, it)
		if err != nil {
			out[i].Error = err.Error()
			continue
		}
		out[i] = ImportWriteResult{ID: id, Action: ImportCreated}
	}
	return out, nil
}

func importIDOf(raw json.RawMessage) (uuid.UUID, error) {
	var v struct {
		ID uuid.UUID `json:"id"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		return uuid.Nil, err
	}
	return v.ID, nil
}

func (s *DCIMImportService) create(ctx context.Context, tenant uuid.UUID, producer string, kind dcim.ObjectKind, it ImportWrite) (uuid.UUID, error) {
	switch kind {
	case dcim.ObjectKindBusinessUnit:
		var in models.BusinessUnitInput
		if err := remarshal(it.Values, &in); err != nil {
			return uuid.Nil, err
		}
		in.ExternalIDs = externalIDsWith(in.ExternalIDs, producer, it.PeerID)
		ref := it.SourceRef
		u, err := s.units.CreateImported(ctx, tenant, in, &ref)
		if err != nil {
			return uuid.Nil, err
		}
		return u.ID, nil
	case dcim.ObjectKindSite:
		var in models.SiteInput
		if err := remarshal(it.Values, &in); err != nil {
			return uuid.Nil, err
		}
		in.ExternalIDs = externalIDsWith(in.ExternalIDs, producer, it.PeerID)
		st, err := s.sites.CreateSite(ctx, tenant, uuid.Nil, in)
		if err != nil {
			return uuid.Nil, err
		}
		return st.ID, s.stamp(ctx, tenant, kind, st.ID, producer, it, false)
	case dcim.ObjectKindLocation:
		var in models.LocationInput
		if err := remarshal(it.Values, &in); err != nil {
			return uuid.Nil, err
		}
		loc, err := s.sites.CreateLocation(ctx, tenant, uuid.Nil, in)
		if err != nil {
			return uuid.Nil, err
		}
		return loc.ID, s.stamp(ctx, tenant, kind, loc.ID, producer, it, false)
	case dcim.ObjectKindInterface:
		var in InterfaceInput
		if err := remarshal(it.Values, &in); err != nil {
			return uuid.Nil, err
		}
		got, err := s.interfaces.Create(ctx, tenant, uuid.Nil, in)
		if err != nil {
			return uuid.Nil, err
		}
		return got.ID, s.stamp(ctx, tenant, kind, got.ID, producer, it, true)
	}
	body, err := s.engineBody(kind, producer, it, true)
	if err != nil {
		return uuid.Nil, err
	}
	var raw json.RawMessage
	if kind == dcim.ObjectKindCable {
		raw, err = s.cables.Create(ctx, tenant, body)
	} else {
		ek := s.engines[kind]
		raw, err = ek.eng.Create(ctx, tenant, ek.route, body)
	}
	if err != nil {
		return uuid.Nil, err
	}
	return importIDOf(raw)
}

// engineBody is the write's values plus, on a create, the import provenance.
func (s *DCIMImportService) engineBody(kind dcim.ObjectKind, producer string, it ImportWrite, create bool) ([]byte, error) {
	row := map[string]any{}
	for k, v := range it.Values {
		row[k] = v
	}
	if create {
		row["source_kind"] = "imported"
		row["source_ref"] = it.SourceRef
		var sp *ipamSpec
		if kind == dcim.ObjectKindCable {
			sp, _ = s.cables.eng.spec(CableRoute)
		} else if ek, ok := s.engines[kind]; ok {
			sp, _ = ek.eng.spec(ek.route)
		}
		if sp == nil {
			return nil, fmt.Errorf("%w: %s has no writer", ErrImportInvalid, kind)
		}
		if _, ok := sp.col("external_ids"); ok && it.PeerID != "" {
			row["external_ids"] = externalIDsWith(row["external_ids"], producer, it.PeerID)
		}
		if _, ok := row["status"]; !ok && sp.Lifecycle {
			// The source is the customer's statement of what exists, not a
			// guess of ours: an imported object is live, not a proposal.
			row["status"] = "active"
		}
	}
	return json.Marshal(row)
}

func (s *DCIMImportService) update(ctx context.Context, tenant uuid.UUID, producer string, kind dcim.ObjectKind, id uuid.UUID, it ImportWrite) error {
	if len(it.Values) == 0 {
		return nil
	}
	switch kind {
	case dcim.ObjectKindBusinessUnit:
		var in models.BusinessUnitInput
		if err := remarshal(it.Values, &in); err != nil {
			return err
		}
		_, err := s.units.Update(ctx, tenant, uuid.Nil, id, in)
		return err
	case dcim.ObjectKindSite:
		var in models.SiteInput
		if err := remarshal(it.Values, &in); err != nil {
			return err
		}
		_, err := s.sites.UpdateSite(ctx, tenant, uuid.Nil, id, in)
		return err
	case dcim.ObjectKindLocation:
		var in models.LocationInput
		if err := remarshal(it.Values, &in); err != nil {
			return err
		}
		_, err := s.sites.UpdateLocation(ctx, tenant, uuid.Nil, id, in)
		return err
	case dcim.ObjectKindInterface:
		patch := map[string]json.RawMessage{}
		for k, v := range it.Values {
			b, err := json.Marshal(v)
			if err != nil {
				return err
			}
			patch[k] = b
		}
		_, err := s.interfaces.Patch(ctx, tenant, id, patch)
		return err
	}
	body, err := s.engineBody(kind, producer, it, false)
	if err != nil {
		return err
	}
	if kind == dcim.ObjectKindCable {
		_, err = s.cables.Update(ctx, tenant, id, body)
		return err
	}
	ek := s.engines[kind]
	_, err = ek.eng.Update(ctx, tenant, ek.route, id, body)
	return err
}

// stamp records the import provenance on an object whose own service does not
// take it (sites, locations, interfaces), as the import's own change.
func (s *DCIMImportService) stamp(ctx context.Context, tenant uuid.UUID, kind dcim.ObjectKind, id uuid.UUID, producer string, it ImportWrite, externalIDs bool) error {
	table := pq.QuoteIdentifier(kind.Table())
	return shareddb.WithTenantTx(ctx, s.raw, tenant, func(tx *sql.Tx) error {
		pre := map[string]any{"source_kind": nil, "source_ref": nil}
		post := map[string]any{"source_kind": "imported", "source_ref": it.SourceRef}
		if externalIDs {
			var cur []byte
			if err := tx.QueryRowContext(ctx, `SELECT COALESCE(external_ids, '{}'::jsonb) FROM public.`+table+` WHERE tenant_id = $1 AND id = $2 FOR UPDATE`,
				tenant, id).Scan(&cur); err != nil {
				return err
			}
			var existing map[string]any
			_ = json.Unmarshal(cur, &existing)
			next := externalIDsWith(existing, producer, it.PeerID)
			nb, _ := json.Marshal(next)
			if _, err := tx.ExecContext(ctx, `UPDATE public.`+table+` SET source_kind = 'imported', source_ref = $3, external_ids = $4::jsonb WHERE tenant_id = $1 AND id = $2`,
				tenant, id, it.SourceRef, string(nb)); err != nil {
				return err
			}
			pre["external_ids"], post["external_ids"] = existing, next
		} else if _, err := tx.ExecContext(ctx, `UPDATE public.`+table+` SET source_kind = 'imported', source_ref = $3 WHERE tenant_id = $1 AND id = $2`,
			tenant, id, it.SourceRef); err != nil {
			return err
		}
		return changes.InTx(tx).Record(ctx, changes.Change{
			TenantID: tenant, Kind: kind, ID: id, Action: changes.ActionUpdate, Pre: pre, Post: post,
		})
	})
}

// Placements gives each asset its device type (when it has none, or another)
// and its rack position. Each item runs on its own; a refused one is reported
// and the rest still run.
func (s *DCIMImportService) Placements(ctx context.Context, tenant uuid.UUID, producer string, items []ImportPlacement) ([]ImportPlacementResult, error) {
	if !importProducerPattern.MatchString(producer) {
		return nil, fmt.Errorf("%w: producer %q", ErrImportInvalid, producer)
	}
	ctx = changes.WithSource(ctx, changes.IntakeSource(producer))
	out := make([]ImportPlacementResult, len(items))
	for i, p := range items {
		out[i].AssetID = p.AssetID
		if err := s.placeOne(ctx, tenant, p); err != nil {
			out[i].Error = err.Error()
		}
	}
	return out, nil
}

func (s *DCIMImportService) placeOne(ctx context.Context, tenant uuid.UUID, p ImportPlacement) error {
	if p.AssetID == uuid.Nil {
		return fmt.Errorf("%w: asset_id is required", ErrImportInvalid)
	}
	cur, err := s.placement.Get(ctx, tenant, p.AssetID)
	if err != nil {
		return err
	}
	if p.DeviceTypeID != nil {
		var have uuid.NullUUID
		if err := shareddb.WithTenantTx(ctx, s.raw, tenant, func(tx *sql.Tx) error {
			return tx.QueryRowContext(ctx, `SELECT device_type_id FROM public.assets WHERE tenant_id = $1 AND id = $2`, tenant, p.AssetID).Scan(&have)
		}); err != nil {
			return err
		}
		if !have.Valid || have.UUID != *p.DeviceTypeID {
			if _, err := s.catalogue.ApplyDeviceType(ctx, tenant, p.AssetID, *p.DeviceTypeID); err != nil {
				return fmt.Errorf("device type: %w", err)
			}
		}
	}
	if p.RackID == nil || p.Position == nil {
		return nil
	}
	face := p.Face
	if face == "" {
		face = "front"
	}
	if cur.Rack != nil && cur.Rack.ID == *p.RackID && cur.Position != nil && *cur.Position == *p.Position && cur.Face != nil && *cur.Face == face {
		return nil
	}
	if _, err := s.placement.Place(ctx, tenant, p.AssetID, PlaceInput{RackID: *p.RackID, Position: *p.Position, Face: face}); err != nil {
		return fmt.Errorf("placement: %w", err)
	}
	return nil
}
