package services

// The inventory side of a bidirectional sync (asset-inventory ADR-0010 D7;
// DCIM SYNC_MODEL §1.5): what the Enterprise NetBox connector reads and
// writes through the HMAC-only /internal/dcim-sync/* routes. The connector owns
// the exchange and the decisions; this file owns the tables and applies what
// it is told, with every write recorded in object_changes as `sync:<peer>`.
//
// Four questions the connector asks, per synced object kind:
//
//   - ListObjects: every live object of the kind, in its API shape, with its
//     external_ids and — for objects our collectors measure — when they last
//     saw it (the `observed` authority's window).
//   - Changes: which fields of which objects a person or a collector changed
//     since a time, and the value each had before the first such change (the
//     three-way baseline), EXCLUDING the peer's own sync writes — otherwise
//     every pull would look like a local edit on the next run.
//   - Write / Delete: apply a create or an update (or, after a person accepts a
//     delete proposal, a delete), stamping external_ids.<peer>.
//   - Park / Resolve: a pulled object whose far end we do not have yet (an
//     address assigned to an interface whose device was never imported) parks
//     an unresolved termination keyed `sync:<peer>:<kind>`, and resolves when
//     an object carrying that peer id arrives.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/database"
	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	shareddb "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
	"github.com/vistasecurity/vistaplatform/shared/dcim/unresolved"
	"github.com/vistasecurity/vistaplatform/shared/syncauthority"
)

// Sync errors the handlers map onto statuses.
var (
	ErrSyncInvalid  = errors.New("invalid sync request")
	ErrSyncNotFound = errors.New("not found")
)

var syncPeerPattern = regexp.MustCompile(`^[a-z0-9_]+$`)

// SyncObject is one object as the connector sees it.
type SyncObject struct {
	ID uuid.UUID `json:"id"`
	// Values is the object's row in its API shape (column → value).
	Values map[string]any `json:"values"`
	// ObservedAt is our collectors' last observation; nil when nothing of ours
	// ever measured the object.
	ObservedAt *time.Time `json:"observed_at,omitempty"`
	UpdatedAt  time.Time  `json:"updated_at"`
	// Catalogue marks a platform-provided row (RIRs, prefix roles): read-only.
	Catalogue bool `json:"catalogue,omitempty"`
}

// SyncFieldChange is one field a person or collector changed since a time.
type SyncFieldChange struct {
	ObjectID uuid.UUID `json:"object_id"`
	Field    string    `json:"field"`
	// Baseline is the field's value before the first change since the time —
	// the value both sides last agreed on.
	Baseline       any       `json:"baseline"`
	FirstChangedAt time.Time `json:"first_changed_at"`
	LastChangedAt  time.Time `json:"last_changed_at"`
}

// SyncDeleted is an object of the kind deleted here since a time that carried
// a peer id (a candidate "deleted here" proposal).
type SyncDeleted struct {
	ObjectID  uuid.UUID `json:"object_id"`
	PeerID    string    `json:"peer_id"`
	Label     string    `json:"label"`
	DeletedAt time.Time `json:"deleted_at"`
}

// SyncWrite is one create or update.
type SyncWrite struct {
	Op string `json:"op"` // create | update
	// ID is the object to update (update only).
	ID uuid.UUID `json:"id,omitempty"`
	// Values are columns in our API shape. A create carries the identity
	// columns and every field; an update only what changes.
	Values map[string]any `json:"values"`
	// PeerID is stamped into external_ids.<peer> (both ops; empty = leave).
	PeerID string `json:"peer_id,omitempty"`
	// Unlink removes external_ids.<peer> (update only): the object stays and
	// is no longer linked to a peer object (a "deleted in the peer" proposal
	// a person answered "keep ours").
	Unlink bool `json:"unlink,omitempty"`
	// Library is a device-type library document (YAML) a device_type create
	// is made from: the peer's type and its component templates, created by
	// the devicetype-library importer (row 2.6, dcim_sync_objects.go).
	Library string `json:"library,omitempty"`
}

// SyncWriteResult answers one SyncWrite, in order.
type SyncWriteResult struct {
	ID    uuid.UUID `json:"id,omitempty"`
	Error string    `json:"error,omitempty"`
}

// SyncPark is one termination a sync parks.
type SyncPark struct {
	OriginKind dcim.ObjectKind `json:"origin_kind"`
	OriginID   uuid.UUID       `json:"origin_id"`
	// FarKind and FarPeerID name the far object by the peer's id.
	FarKind   dcim.ObjectKind `json:"far_kind"`
	FarPeerID string          `json:"far_peer_id"`
	Intent    string          `json:"intent"`
	// CreateKind, PeerID and Values: a termination that cannot exist until
	// its far end does (a tunnel termination on an interface not here yet) is
	// parked on its parent (Origin*) and created as CreateKind, with Values,
	// the far end, and external_ids.<peer> = PeerID, when the far end
	// arrives (row 4.5).
	CreateKind dcim.ObjectKind `json:"create_kind,omitempty"`
	PeerID     string          `json:"peer_id,omitempty"`
	Values     map[string]any  `json:"values,omitempty"`
}

// syncParkedChildren names, per kind a sync creates on resolution, its
// parent column and its generic reference (kind column, id column).
var syncParkedChildren = map[dcim.ObjectKind]struct {
	Parent         dcim.ObjectKind
	ParentCol      string
	KindCol, IDCol string
}{
	dcim.ObjectKindTunnelTermination: {dcim.ObjectKindTunnel, "tunnel_id", "termination_kind", "termination_id"},
	dcim.ObjectKindL2vpnTermination:  {dcim.ObjectKindL2vpn, "l2vpn_id", "assigned_kind", "assigned_id"},
}

// DCIMSyncService implements the internal sync surface.
type DCIMSyncService struct {
	raw  *sql.DB
	ipam *IPAMService
	// objects is the same object engine over the row 4.1–4.4 specs
	// (circuits, virtualisation, VPN, wireless) the row 4.5 sync writes.
	objects    *IPAMService
	units      *BusinessUnitService
	interfaces *InterfaceService
	// objs writes the dcim objects of row 2.6 (dcim_sync_objects.go).
	objs *dcimSyncObjects
	now  func() time.Time
}

// NewDCIMSyncService builds the service over the raw (RLS-subject) pool and the
// sqlx wrapper the business-unit service uses.
func NewDCIMSyncService(raw *sql.DB, db *database.DB) *DCIMSyncService {
	return &DCIMSyncService{
		raw: raw, ipam: NewIPAMService(raw), objects: newObjectEngine(raw, syncObjectSpecs()), units: NewBusinessUnitService(db),
		interfaces: NewInterfaceService(raw), objs: newDCIMSyncObjects(raw, db), now: time.Now,
	}
}

func syncSpec(kind dcim.ObjectKind) (syncauthority.KindSpec, error) {
	k, ok := syncauthority.Kind(kind)
	if !ok {
		return syncauthority.KindSpec{}, fmt.Errorf("%w: %q is not a synced object kind", ErrSyncInvalid, kind)
	}
	return k, nil
}

func checkPeer(peer string) error {
	if !syncPeerPattern.MatchString(peer) {
		return fmt.Errorf("%w: peer %q", ErrSyncInvalid, peer)
	}
	return nil
}

// syncTable is the table of a synced kind.
func syncTable(kind dcim.ObjectKind) string { return kind.Table() }

func (s *DCIMSyncService) ipamSpecFor(kind dcim.ObjectKind) *ipamSpec {
	sp, _ := s.engineFor(kind)
	return sp
}

// engineFor answers the engine spec of a synced kind and the engine that
// serves it: the IPAM objects (row 1.9) or the circuit, virtualisation, VPN
// and wireless objects (row 4.5).
func (s *DCIMSyncService) engineFor(kind dcim.ObjectKind) (*ipamSpec, *IPAMService) {
	for _, eng := range []*IPAMService{s.ipam, s.objects, s.objs.engine()} {
		for _, sp := range eng.specs {
			if sp.Kind == kind {
				return sp, eng
			}
		}
	}
	return nil, nil
}

// syncObjectSpecs are the row 4.1–4.4 and 6.1 specs a sync writes through.
func syncObjectSpecs() []*ipamSpec {
	var out []*ipamSpec
	out = append(out, circuitSpecs()...)
	out = append(out, virtualizationSpecs()...)
	out = append(out, vpnSpecs()...)
	out = append(out, wirelessSpecs()...)
	// Row 6.1: power panels and feeds.
	out = append(out, powerSpecs()...)
	return out
}

// ListObjects returns a page of the kind's live objects ordered by id.
func (s *DCIMSyncService) ListObjects(ctx context.Context, tenant uuid.UUID, kind dcim.ObjectKind, after uuid.UUID, limit int) ([]SyncObject, bool, error) {
	if _, err := syncSpec(kind); err != nil {
		return nil, false, err
	}
	if out, more, handled, err := s.listVM(ctx, tenant, kind, after, limit); handled {
		return out, more, err
	}
	if out, more, handled, err := s.listDCIM(ctx, tenant, kind, after, limit); handled {
		return out, more, err
	}
	if limit <= 0 || limit > 1000 {
		limit = 500
	}
	table := syncTable(kind)
	// The tenant predicate is explicit as well as RLS's: a pool that bypasses
	// RLS (the owner role, a misconfigured deployment) must still not hand one
	// tenant's objects to another tenant's sync. Catalogue kinds add the
	// platform's rows.
	where := []string{"t.id > $1", "t.tenant_id = $3"}
	sp := s.ipamSpecFor(kind)
	if sp != nil && sp.Catalogue {
		where[1] = "(t.tenant_id = $3 OR t.tenant_id IS NULL)"
	}
	if (sp != nil && sp.Lifecycle) || kind == dcim.ObjectKindInterface {
		where = append(where, "t.status <> 'rejected'")
	}
	if kind == dcim.ObjectKindInterface {
		// A virtual machine's interface is a NetBox VM interface (kind
		// vm_interface, its own id space), never a device interface: it is
		// listed there, and pushed to virtualization/interfaces.
		where = append(where, `NOT EXISTS (SELECT 1 FROM public.assets a WHERE a.tenant_id = t.tenant_id AND a.id = t.asset_id AND `+vmSideAsset+`)`)
	}
	sel := "to_jsonb(t)"
	if kind == dcim.ObjectKindInterface {
		// The interface's virtual device context memberships (DCIM gap 1;
		// sync-authority computed field virtual_device_context_ids) live in
		// the junction, not in a column.
		sel = `to_jsonb(t) || jsonb_build_object('virtual_device_context_ids',
			COALESCE((SELECT jsonb_agg(j.virtual_device_context_id ORDER BY j.virtual_device_context_id)
			            FROM public.interface_virtual_device_contexts j WHERE j.interface_id = t.id), '[]'::jsonb))`
	}
	var out []SyncObject
	err := shareddb.WithTenantTx(ctx, s.raw, tenant, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, fmt.Sprintf(`SELECT %s FROM public.%s t WHERE %s ORDER BY t.id LIMIT $2`,
			sel, pq.QuoteIdentifier(table), strings.Join(where, " AND ")), after, limit+1, tenant)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var raw []byte
			if err := rows.Scan(&raw); err != nil {
				return err
			}
			obj, err := syncObjectOf(sp, kind, raw)
			if err != nil {
				return err
			}
			out = append(out, obj)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, false, err
	}
	more := len(out) > limit
	if more {
		out = out[:limit]
	}
	return out, more, nil
}

func syncObjectOf(sp *ipamSpec, kind dcim.ObjectKind, raw []byte) (SyncObject, error) {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	var row map[string]any
	if err := dec.Decode(&row); err != nil {
		return SyncObject{}, err
	}
	if sp != nil {
		presentRow(sp, row)
	} else if v, ok := row["mac_address"].(string); ok {
		row["mac_address"] = eui48(v)
	}
	id, err := uuid.Parse(fmt.Sprint(row["id"]))
	if err != nil {
		return SyncObject{}, fmt.Errorf("sync: %s row without an id", kind)
	}
	obj := SyncObject{ID: id, Values: row}
	if t, ok := parseRowTime(row["updated_at"]); ok {
		obj.UpdatedAt = t
	}
	if n, _ := row["observation_count"].(json.Number); n != "" && n.String() != "0" {
		if t, ok := parseRowTime(row["last_seen_at"]); ok {
			obj.ObservedAt = &t
		}
	}
	if sp != nil && sp.Catalogue && row["tenant_id"] == nil {
		obj.Catalogue = true
	}
	return obj, nil
}

func parseRowTime(v any) (time.Time, bool) {
	s, ok := v.(string)
	if !ok || s == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999-07:00", "2006-01-02T15:04:05.999999"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// Changes returns the fields of the kind's objects changed since `since` by
// anything other than the peer's own sync, with each field's pre-change
// baseline, and the objects deleted here since then that carried a peer id.
func (s *DCIMSyncService) Changes(ctx context.Context, tenant uuid.UUID, peer string, kind dcim.ObjectKind, since time.Time) ([]SyncFieldChange, []SyncDeleted, error) {
	if err := checkPeer(peer); err != nil {
		return nil, nil, err
	}
	if _, err := syncSpec(kind); err != nil {
		return nil, nil, err
	}
	source := string(changes.SyncSource(peer))
	// A sync kind's rows are its object's (a VM is an asset): their changes
	// are recorded under that kind, and its peer id under its own key.
	stored, key := syncStored(kind), syncPeerKey(peer, kind)
	var fields []SyncFieldChange
	var deleted []SyncDeleted
	err := shareddb.WithTenantTx(ctx, s.raw, tenant, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `
			SELECT c.object_id, f.field,
			       (array_agg(c.prechange_data -> f.field ORDER BY c.created_at))[1],
			       min(c.created_at), max(c.created_at)
			  FROM public.object_changes c, unnest(c.changed_fields) AS f(field)
			 WHERE c.tenant_id = $1 AND c.object_kind = $2 AND c.created_at > $3
			   AND c.action = 'update' AND c.source <> $4
			 GROUP BY c.object_id, f.field`, tenant, string(stored), since, source)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var fc SyncFieldChange
			var base []byte
			if err := rows.Scan(&fc.ObjectID, &fc.Field, &base, &fc.FirstChangedAt, &fc.LastChangedAt); err != nil {
				return err
			}
			if len(base) > 0 {
				dec := json.NewDecoder(strings.NewReader(string(base)))
				dec.UseNumber()
				if err := dec.Decode(&fc.Baseline); err != nil {
					return err
				}
			}
			fields = append(fields, fc)
		}
		if err := rows.Err(); err != nil {
			return err
		}
		if kind == syncKindVirtualMachine {
			var derr error
			deleted, derr = vmDeleted(ctx, tx, tenant, since)
			return derr
		}
		drows, err := tx.QueryContext(ctx, `
			SELECT c.object_id, c.prechange_data -> 'external_ids' ->> $5,
			       COALESCE(c.prechange_data ->> 'name', c.prechange_data ->> 'prefix', c.prechange_data ->> 'address',
			                c.prechange_data ->> 'cid', c.prechange_data ->> 'ssid', c.object_id::text),
			       c.created_at
			  FROM public.object_changes c
			 WHERE c.tenant_id = $1 AND c.object_kind = $2 AND c.created_at > $3
			   AND c.action = 'delete' AND c.source <> $4
			   AND c.prechange_data -> 'external_ids' ? $5`, tenant, string(stored), since, source, key)
		if err != nil {
			return err
		}
		defer func() { _ = drows.Close() }()
		for drows.Next() {
			var d SyncDeleted
			if err := drows.Scan(&d.ObjectID, &d.PeerID, &d.Label, &d.DeletedAt); err != nil {
				return err
			}
			deleted = append(deleted, d)
		}
		return drows.Err()
	})
	return fields, deleted, err
}

// Write applies writes of one kind, each on its own, in order. A refused
// write is reported on its result and the rest still run.
func (s *DCIMSyncService) Write(ctx context.Context, tenant uuid.UUID, peer string, kind dcim.ObjectKind, items []SyncWrite) ([]SyncWriteResult, error) {
	if err := checkPeer(peer); err != nil {
		return nil, err
	}
	spec, err := syncSpec(kind)
	if err != nil {
		return nil, err
	}
	ctx = changes.WithSource(ctx, changes.SyncSource(peer))
	out := make([]SyncWriteResult, len(items))
	for i, it := range items {
		if err := checkWriteColumns(spec, it); err != nil {
			out[i].Error = err.Error()
			continue
		}
		var id uuid.UUID
		var werr error
		switch it.Op {
		case "create":
			id, werr = s.create(ctx, tenant, peer, kind, it)
		case "update":
			if it.ID == uuid.Nil {
				werr = fmt.Errorf("%w: update needs an id", ErrSyncInvalid)
				break
			}
			id, werr = it.ID, s.update(ctx, tenant, peer, kind, it)
		default:
			werr = fmt.Errorf("%w: op %q (create or update)", ErrSyncInvalid, it.Op)
		}
		if werr != nil {
			out[i].Error = werr.Error()
			continue
		}
		out[i].ID = id
	}
	return out, nil
}

// syncExtraColumns are written on a create besides identity and fields: what
// a peer object needs to exist here at all (a business unit's slug, a VLAN
// group's vid ranges are fields already; an IP address's assignment kind
// travels with its assigned id).
var syncExtraColumns = map[dcim.ObjectKind][]string{
	dcim.ObjectKindBusinessUnit: {"name"},
	dcim.ObjectKindIpAddress:    {"assigned_kind"},
	dcim.ObjectKindInterface:    {"type"},
	// Row 4.5: a generic reference's kind travels with its id.
	dcim.ObjectKindCircuitTermination: {"termination_kind"},
	dcim.ObjectKindTunnelTermination:  {"termination_kind"},
	dcim.ObjectKindL2vpnTermination:   {"assigned_kind"},
}

// checkWriteColumns refuses a column the authority registry does not sync: the
// connector may set what it syncs, never e.g. a prefix's auto-approval flag.
func checkWriteColumns(spec syncauthority.KindSpec, it SyncWrite) error {
	allowed := map[string]bool{}
	for _, f := range spec.Fields {
		allowed[f.Field] = true
	}
	for _, c := range syncExtraColumns[spec.Kind] {
		allowed[c] = true
	}
	if it.Op == "create" {
		for _, c := range spec.Identity {
			allowed[c] = true
		}
	}
	for k := range it.Values {
		if !allowed[k] {
			return fmt.Errorf("%w: %s.%s is not a synced column", ErrSyncInvalid, spec.Kind, k)
		}
	}
	return nil
}

func externalIDsWith(existing any, peer, peerID string) map[string]any {
	out := map[string]any{}
	if m, ok := existing.(map[string]any); ok {
		for k, v := range m {
			out[k] = v
		}
	}
	if peerID != "" {
		out[peer] = peerID
	}
	return out
}

func externalIDsWithout(existing any, peer string) map[string]any {
	out := externalIDsWith(existing, peer, "")
	delete(out, peer)
	return out
}

func (s *DCIMSyncService) create(ctx context.Context, tenant uuid.UUID, peer string, kind dcim.ObjectKind, it SyncWrite) (uuid.UUID, error) {
	if id, handled, err := s.createVMKind(ctx, tenant, peer, kind, it); handled {
		return id, err
	}
	if id, handled, err := s.createDCIM(ctx, tenant, peer, kind, it); handled {
		return id, err
	}
	sourceRef := peer + ":" + it.PeerID
	switch kind {
	case dcim.ObjectKindBusinessUnit:
		in := models.BusinessUnitInput{ExternalIDs: externalIDsWith(nil, peer, it.PeerID)}
		if err := remarshal(it.Values, &in); err != nil {
			return uuid.Nil, err
		}
		in.ExternalIDs = externalIDsWith(nil, peer, it.PeerID)
		u, err := s.units.CreateImported(ctx, tenant, in, &sourceRef)
		if err != nil {
			return uuid.Nil, err
		}
		return u.ID, nil
	case dcim.ObjectKindInterface:
		var in InterfaceInput
		if err := remarshal(it.Values, &in); err != nil {
			return uuid.Nil, err
		}
		got, err := s.interfaces.Create(ctx, tenant, uuid.Nil, in)
		if err != nil {
			return uuid.Nil, err
		}
		return got.ID, s.stampInterface(ctx, tenant, got.ID, peer, it.PeerID, &sourceRef)
	}
	sp := s.ipamSpecFor(kind)
	if sp == nil {
		return uuid.Nil, fmt.Errorf("%w: %s has no writer", ErrSyncInvalid, kind)
	}
	row := map[string]any{}
	for k, v := range it.Values {
		row[k] = v
	}
	row["external_ids"] = externalIDsWith(nil, peer, it.PeerID)
	row["source_kind"] = "imported"
	row["source_ref"] = sourceRef
	if sp.Lifecycle {
		// The peer is the customer's statement of intent, not a guess of
		// ours: an imported object is live, not a proposal.
		row["status"] = "active"
	}
	var id uuid.UUID
	err := s.ipam.tx(ctx, tenant, func(tx *sql.Tx) error {
		post, err := s.ipam.createTx(ctx, tx, sp, tenant, row, "")
		if err != nil {
			return err
		}
		id, err = uuid.Parse(fmt.Sprint(post["id"]))
		return err
	})
	return id, mapIPAMError(err, false)
}

func (s *DCIMSyncService) update(ctx context.Context, tenant uuid.UUID, peer string, kind dcim.ObjectKind, it SyncWrite) error {
	if handled, err := s.updateVMKind(ctx, tenant, peer, kind, it); handled {
		return err
	}
	if handled, err := s.updateDCIM(ctx, tenant, peer, kind, it); handled {
		return err
	}
	switch kind {
	case dcim.ObjectKindBusinessUnit:
		cur, err := s.units.Get(ctx, tenant, it.ID)
		if err != nil {
			return err
		}
		var in models.BusinessUnitInput
		if err := remarshal(it.Values, &in); err != nil {
			return err
		}
		in.ExternalIDs = externalIDsWith(cur.ExternalIDs, peer, it.PeerID)
		if it.Unlink {
			in.ExternalIDs = externalIDsWithout(cur.ExternalIDs, peer)
		}
		_, err = s.units.Update(ctx, tenant, uuid.Nil, it.ID, in)
		return err
	case dcim.ObjectKindInterface:
		if len(it.Values) > 0 {
			patch := map[string]json.RawMessage{}
			for k, v := range it.Values {
				b, err := json.Marshal(v)
				if err != nil {
					return err
				}
				patch[k] = b
			}
			if _, err := s.interfaces.Patch(ctx, tenant, it.ID, patch); err != nil {
				return err
			}
		}
		if it.Unlink {
			return s.unlinkInterface(ctx, tenant, it.ID, peer)
		}
		return s.stampInterface(ctx, tenant, it.ID, peer, it.PeerID, nil)
	}
	sp := s.ipamSpecFor(kind)
	if sp == nil {
		return fmt.Errorf("%w: %s has no writer", ErrSyncInvalid, kind)
	}
	err := s.ipam.tx(ctx, tenant, func(tx *sql.Tx) error {
		if err := refuseCatalogueRow(ctx, tx, sp, it.ID); err != nil {
			return err
		}
		pre, err := getRow(ctx, tx, sp, it.ID, true)
		if err != nil {
			return err
		}
		patch := map[string]any{}
		for k, v := range it.Values {
			patch[k] = v
		}
		if it.PeerID != "" {
			if m, _ := pre["external_ids"].(map[string]any); fmt.Sprint(m[peer]) != it.PeerID {
				patch["external_ids"] = externalIDsWith(pre["external_ids"], peer, it.PeerID)
			}
		}
		if it.Unlink {
			patch["external_ids"] = externalIDsWithout(pre["external_ids"], peer)
		}
		if len(patch) == 0 {
			return nil
		}
		_, err = s.ipam.updateTx(ctx, tx, sp, tenant, it.ID, patch, "")
		return err
	})
	return mapIPAMError(err, false)
}

// stampInterface records the peer id (and, on a create, the import
// provenance) on an interface. The interface API does not carry external_ids,
// so it is set here, recorded as the sync's own change.
func (s *DCIMSyncService) stampInterface(ctx context.Context, tenant, id uuid.UUID, peer, peerID string, sourceRef *string) error {
	if peerID == "" && sourceRef == nil {
		return nil
	}
	return shareddb.WithTenantTx(ctx, s.raw, tenant, func(tx *sql.Tx) error {
		var cur []byte
		if err := tx.QueryRowContext(ctx, `SELECT external_ids FROM public.interfaces WHERE tenant_id = $1 AND id = $2 FOR UPDATE`, tenant, id).Scan(&cur); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrSyncNotFound
			}
			return err
		}
		var existing map[string]any
		_ = json.Unmarshal(cur, &existing)
		next := externalIDsWith(existing, peer, peerID)
		nb, _ := json.Marshal(next)
		if string(nb) == string(cur) && sourceRef == nil {
			return nil
		}
		if sourceRef != nil {
			if _, err := tx.ExecContext(ctx, `UPDATE public.interfaces SET external_ids = $3::jsonb, source_kind = 'imported', source_ref = $4 WHERE tenant_id = $1 AND id = $2`,
				tenant, id, string(nb), *sourceRef); err != nil {
				return err
			}
		} else if _, err := tx.ExecContext(ctx, `UPDATE public.interfaces SET external_ids = $3::jsonb WHERE tenant_id = $1 AND id = $2`,
			tenant, id, string(nb)); err != nil {
			return err
		}
		return changes.InTx(tx).Record(ctx, changes.Change{
			TenantID: tenant, Kind: dcim.ObjectKindInterface, ID: id, Action: changes.ActionUpdate,
			Pre: map[string]any{"external_ids": existing}, Post: map[string]any{"external_ids": next},
		})
	})
}

// unlinkInterface removes the peer id from an interface.
func (s *DCIMSyncService) unlinkInterface(ctx context.Context, tenant, id uuid.UUID, peer string) error {
	return shareddb.WithTenantTx(ctx, s.raw, tenant, func(tx *sql.Tx) error {
		var cur []byte
		if err := tx.QueryRowContext(ctx, `SELECT external_ids FROM public.interfaces WHERE tenant_id = $1 AND id = $2 FOR UPDATE`, tenant, id).Scan(&cur); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrSyncNotFound
			}
			return err
		}
		var existing map[string]any
		_ = json.Unmarshal(cur, &existing)
		next := externalIDsWithout(existing, peer)
		nb, _ := json.Marshal(next)
		if _, err := tx.ExecContext(ctx, `UPDATE public.interfaces SET external_ids = $3::jsonb WHERE tenant_id = $1 AND id = $2`, tenant, id, string(nb)); err != nil {
			return err
		}
		return changes.InTx(tx).Record(ctx, changes.Change{
			TenantID: tenant, Kind: dcim.ObjectKindInterface, ID: id, Action: changes.ActionUpdate,
			Pre: map[string]any{"external_ids": existing}, Post: map[string]any{"external_ids": next},
		})
	})
}

// Delete removes one object after a person accepted a delete proposal.
func (s *DCIMSyncService) Delete(ctx context.Context, tenant uuid.UUID, peer string, kind dcim.ObjectKind, id uuid.UUID) error {
	if err := checkPeer(peer); err != nil {
		return err
	}
	if _, err := syncSpec(kind); err != nil {
		return err
	}
	ctx = changes.WithSource(ctx, changes.SyncSource(peer))
	if handled, err := s.deleteVMKind(ctx, tenant, kind, id); handled {
		return err
	}
	if handled, err := s.deleteDCIM(ctx, tenant, kind, id); handled {
		return err
	}
	switch kind {
	case dcim.ObjectKindBusinessUnit:
		return s.units.Delete(ctx, tenant, uuid.Nil, id, nil)
	case dcim.ObjectKindInterface:
		return s.interfaces.Delete(ctx, tenant, id)
	}
	sp := s.ipamSpecFor(kind)
	if sp == nil {
		return fmt.Errorf("%w: %s has no writer", ErrSyncInvalid, kind)
	}
	_, eng := s.engineFor(kind)
	return eng.Delete(ctx, tenant, sp.Route, id)
}

// PeerAssets maps the peer's device ids to our assets: the NetBox importer
// records each device's id on the asset it resolved (metadata
// netbox_device_id). An interface is synced only on an asset we can name in
// the peer; dcim/devices themselves are row 2.6.
func (s *DCIMSyncService) PeerAssets(ctx context.Context, tenant uuid.UUID, peer string) (map[string]uuid.UUID, error) {
	if peer != "netbox" {
		return nil, fmt.Errorf("%w: no device mapping for peer %q", ErrSyncInvalid, peer)
	}
	out := map[string]uuid.UUID{}
	err := shareddb.WithTenantTx(ctx, s.raw, tenant, func(tx *sql.Tx) error {
		rows, err := tx.QueryContext(ctx, `
			SELECT a.id, a.metadata ->> 'netbox_device_id'
			  FROM public.assets a
			 WHERE a.tenant_id = $1 AND a.deleted_at IS NULL AND a.metadata ? 'netbox_device_id'
			 ORDER BY a.created_at`, tenant)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			var id uuid.UUID
			var peerID string
			if err := rows.Scan(&id, &peerID); err != nil {
				return err
			}
			if _, taken := out[peerID]; !taken {
				out[peerID] = id
			}
		}
		return rows.Err()
	})
	return out, err
}

func remarshal(in any, out any) error {
	b, err := json.Marshal(in)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, out); err != nil {
		return fmt.Errorf("%w: %v", ErrSyncInvalid, err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// Unresolved terminations: park and resolve by sync key
// ---------------------------------------------------------------------------

// SyncKey is the unresolved far-identity key for a peer object of a kind.
func SyncKey(peer string, kind dcim.ObjectKind) string {
	return unresolved.KeySyncPrefix + peer + ":" + string(kind)
}

// Park parks terminations for the peer's producer.
func (s *DCIMSyncService) Park(ctx context.Context, tenant uuid.UUID, peer string, items []SyncPark) error {
	if err := checkPeer(peer); err != nil {
		return err
	}
	repo := NewUnresolvedRepository(s.raw)
	now := s.now()
	for _, p := range items {
		attrs := map[string]any{"far_kind": string(p.FarKind)}
		if p.CreateKind == dcim.ObjectKindCable {
			// Row 3.5: a cable parks on one of its ends, whatever kind it is.
			if err := parkCable(p); err != nil {
				return err
			}
			attrs["create_kind"] = string(p.CreateKind)
			attrs["peer_id"] = p.PeerID
			attrs["values"] = p.Values
		} else if p.CreateKind != "" {
			child, ok := syncParkedChildren[p.CreateKind]
			if !ok || child.Parent != p.OriginKind {
				return fmt.Errorf("%w: a %s cannot be parked on a %s", ErrSyncInvalid, p.CreateKind, p.OriginKind)
			}
			if err := checkWriteColumns(mustSyncSpec(p.CreateKind), SyncWrite{Op: "create", Values: p.Values}); err != nil {
				return err
			}
			attrs["create_kind"] = string(p.CreateKind)
			attrs["peer_id"] = p.PeerID
			attrs["values"] = p.Values
		}
		_, err := repo.Park(ctx, tenant, unresolved.Termination{
			Producer: peer, OriginKind: p.OriginKind, OriginID: p.OriginID,
			FarIdentity: map[string]string{SyncKey(peer, p.FarKind): p.FarPeerID},
			Intent:      p.Intent, Attributes: attrs,
		}, now)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrSyncInvalid, err)
		}
	}
	return nil
}

// Resolve runs the resolver over the tenant's parked terminations with the
// sync-key matcher and the assignment applier.
func (s *DCIMSyncService) Resolve(ctx context.Context, tenant uuid.UUID) (unresolved.ResolvedCount, error) {
	r := unresolved.NewResolver(NewUnresolvedRepository(s.raw), syncKeyMatcher{raw: s.raw}, syncApplier{s: s}, s.now)
	return r.Resolve(changes.System(ctx), tenant)
}

// syncKeyMatcher resolves "sync:<peer>:<kind>" to the object carrying that
// peer id in external_ids. The other identity kinds belong to rows 1.4 and 3.3.
type syncKeyMatcher struct {
	unresolved.NullMatcher
	raw *sql.DB
}

func (m syncKeyMatcher) MatchBySyncKey(ctx context.Context, tenant uuid.UUID, key, value string) (unresolved.Match, bool, error) {
	parts := strings.SplitN(strings.TrimPrefix(key, unresolved.KeySyncPrefix), ":", 2)
	if len(parts) != 2 || !syncPeerPattern.MatchString(parts[0]) {
		return unresolved.Match{}, false, nil
	}
	kind := dcim.ObjectKind(parts[1])
	if _, ok := syncauthority.Kind(kind); !ok {
		return unresolved.Match{}, false, nil
	}
	if isVMSyncKind(kind) {
		id, ok, err := vmMatch(ctx, m.raw, tenant, parts[0], kind, value)
		if err != nil || !ok {
			return unresolved.Match{}, false, err
		}
		return unresolved.Match{Kind: kind, ID: id}, true, nil
	}
	var id uuid.UUID
	err := shareddb.WithTenantTx(ctx, m.raw, tenant, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, fmt.Sprintf(`SELECT id FROM public.%s WHERE tenant_id = $1 AND external_ids ->> $2 = $3 ORDER BY created_at LIMIT 1`,
			pq.QuoteIdentifier(syncTable(kind))), tenant, parts[0], value).Scan(&id)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return unresolved.Match{}, false, nil
	}
	if err != nil {
		return unresolved.Match{}, false, err
	}
	return unresolved.Match{Kind: kind, ID: id}, true, nil
}

// syncApplier writes what a resolved sync termination intended: an IP
// address assigned to an interface (or FHRP group) that has now arrived; a
// circuit termination's site, location, region, site group or provider
// network; a tunnel or L2VPN termination created on its parent once its
// interface (or VLAN) exists (row 4.5).
type syncApplier struct{ s *DCIMSyncService }

func mustSyncSpec(kind dcim.ObjectKind) syncauthority.KindSpec {
	k, _ := syncauthority.Kind(kind)
	return k
}

// ApplyCable creates a cable a sync parked because a termination was not here
// (row 3.5, dcim_sync_cabling.go). A cable row parked by another producer
// without the cable it intends (Device42's import re-plans its own) is not
// the sync's to write.
func (a syncApplier) ApplyCable(ctx context.Context, tenant uuid.UUID, p unresolved.Parked, _ unresolved.Match) error {
	if ck, _ := p.Attributes["create_kind"].(string); ck != string(dcim.ObjectKindCable) {
		return fmt.Errorf("sync: a cable parked by %s without the cable to create is re-planned by its importer", p.Producer)
	}
	return a.applyParkedCable(ctx, tenant, p)
}

func (a syncApplier) ApplyRelationship(context.Context, uuid.UUID, unresolved.Parked, string, unresolved.Match) error {
	return errors.New("sync: relationship terminations are not parked by a sync")
}

func (a syncApplier) ApplyAssignment(ctx context.Context, tenant uuid.UUID, p unresolved.Parked, far unresolved.Match) error {
	if ck, _ := p.Attributes["create_kind"].(string); ck != "" {
		return a.createParkedChild(ctx, tenant, p, dcim.ObjectKind(ck), far)
	}
	if p.OriginKind == dcim.ObjectKindCircuitTermination {
		return a.applyCircuitTermination(ctx, tenant, p, far)
	}
	if p.OriginKind != dcim.ObjectKindIpAddress {
		return fmt.Errorf("sync: an assignment from %s is not supported", p.OriginKind)
	}
	farKind := far.Kind
	if farKind == syncKindVMInterface {
		farKind = dcim.ObjectKindInterface // a VM interface is an interface row
	}
	if farKind != dcim.ObjectKindInterface && farKind != dcim.ObjectKindFhrpGroup {
		return fmt.Errorf("sync: an address cannot be assigned to a %s", far.Kind)
	}
	sp := a.s.ipamSpecFor(dcim.ObjectKindIpAddress)
	ctx = changes.WithSource(ctx, changes.SyncSource(p.Producer))
	err := a.s.ipam.tx(ctx, tenant, func(tx *sql.Tx) error {
		_, err := a.s.ipam.updateTx(ctx, tx, sp, tenant, p.OriginID, map[string]any{
			"assigned_kind": string(farKind), "assigned_id": far.ID.String(),
		}, "")
		return err
	})
	return mapIPAMError(err, false)
}

// applyCircuitTermination lands a circuit termination on the site, location,
// region, site group or provider network that has now arrived.
func (a syncApplier) applyCircuitTermination(ctx context.Context, tenant uuid.UUID, p unresolved.Parked, far unresolved.Match) error {
	switch far.Kind {
	case dcim.ObjectKindSite, dcim.ObjectKindLocation, dcim.ObjectKindRegion, dcim.ObjectKindSiteGroup, dcim.ObjectKindProviderNetwork:
	default:
		return fmt.Errorf("sync: a circuit cannot terminate on a %s", far.Kind)
	}
	sp, eng := a.s.engineFor(dcim.ObjectKindCircuitTermination)
	ctx = changes.WithSource(ctx, changes.SyncSource(p.Producer))
	err := eng.tx(ctx, tenant, func(tx *sql.Tx) error {
		_, err := eng.updateTx(ctx, tx, sp, tenant, p.OriginID, map[string]any{
			"termination_kind": string(far.Kind), "termination_id": far.ID.String(),
		}, "")
		return err
	})
	return mapIPAMError(err, false)
}

// createParkedChild creates a termination parked on its parent (a tunnel, an
// L2VPN) now that its far end exists, stamped with the peer's id.
func (a syncApplier) createParkedChild(ctx context.Context, tenant uuid.UUID, p unresolved.Parked, kind dcim.ObjectKind, far unresolved.Match) error {
	child, ok := syncParkedChildren[kind]
	if !ok || child.Parent != p.OriginKind {
		return fmt.Errorf("sync: a %s cannot be created from a %s", kind, p.OriginKind)
	}
	values := map[string]any{}
	if v, ok := p.Attributes["values"].(map[string]any); ok {
		for k, x := range v {
			values[k] = x
		}
	}
	values[child.ParentCol] = p.OriginID.String()
	values[child.KindCol] = string(far.Kind)
	values[child.IDCol] = far.ID.String()
	peerID, _ := p.Attributes["peer_id"].(string)
	if peerID != "" {
		// The sync that pulled the far end may have created the termination
		// itself in the same run (it is no longer missing anything): then the
		// parked row is satisfied, not a second object to create.
		if _, found, err := (syncKeyMatcher{raw: a.s.raw}).MatchBySyncKey(ctx, tenant, SyncKey(p.Producer, kind), peerID); err != nil {
			return err
		} else if found {
			return nil
		}
	}
	ctx = changes.WithSource(ctx, changes.SyncSource(p.Producer))
	_, err := a.s.create(ctx, tenant, p.Producer, kind, SyncWrite{Op: "create", Values: values, PeerID: peerID})
	return err
}
