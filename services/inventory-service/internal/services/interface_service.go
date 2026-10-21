package services

// InterfaceService owns `interfaces`, `mac_addresses` and
// `interface_tagged_vlans` (DCIM BUILD_PLAN row 1.2; DATA_MODEL §2.4).
//
// Every read and write runs in a tenant-scoped transaction (RLS), and every
// create, update and delete is handed to the change recorder inside that same
// transaction, so the change record commits or rolls back with the change.
//
// Two writers, deliberately different:
//
//   - Create / Patch / Delete / BulkCreate are a PERSON declaring the
//     interface (source_kind `declared`, status `active`).
//   - UpsertObserved is intake (row 1.5's adapters: the agent's net.interfaces
//     fact, SNMP ifTable, UniFi port_table, LLDP). It keys on the canonical
//     name (shared/dcim/ifnames), writes MEASURED fields only, never touches
//     what a person declared (`enabled`, `description`, mode, VLANs, LAG …),
//     and marks interfaces it no longer sees `stale` once they have gone
//     unobserved for the tenant's stale window — never deletes them.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	shareddb "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
	"github.com/vistasecurity/vistaplatform/shared/dcim/customfields"
	"github.com/vistasecurity/vistaplatform/shared/dcim/ifnames"
)

// ---------------------------------------------------------------- changes --

// InterfaceChange is one create, update or delete of an interface. Source is
// empty for a change a person made through the API (the recorder takes the
// actor and source from the request context, set by changes.Middleware) and
// `intake:<producer>` for intake.
type InterfaceChange struct {
	TenantID uuid.UUID
	Kind     dcim.ObjectKind
	ID       uuid.UUID
	Action   changes.Action
	Pre      any
	Post     any
	Source   changes.Source
}

// InterfaceChangeRecorder records a change inside the writer's transaction.
// The production recorder writes `object_changes` through shared/dcim/changes
// (row 0.3); tests substitute a memory recorder.
// TestIntegration_Interfaces_RecordsChanges pins that every write calls it.
type InterfaceChangeRecorder interface {
	RecordInterfaceChange(ctx context.Context, tx *sql.Tx, c InterfaceChange) error
}

// objectChangesRecorder is the production recorder: changes.InTx over the
// writer's own transaction, so the record commits or rolls back with the
// change.
type objectChangesRecorder struct{}

func (objectChangesRecorder) RecordInterfaceChange(ctx context.Context, tx *sql.Tx, c InterfaceChange) error {
	return changes.InTx(tx).Record(ctx, changes.Change{
		TenantID: c.TenantID, Kind: c.Kind, ID: c.ID, Action: c.Action,
		Pre: c.Pre, Post: c.Post, Source: c.Source,
	})
}

// ---------------------------------------------------------------- service --

// InterfaceService is the interface store.
type InterfaceService struct {
	db  *sql.DB
	rec InterfaceChangeRecorder
	now func() time.Time
}

// NewInterfaceService returns the store over db (the raw pool; RLS is set per
// transaction).
func NewInterfaceService(db *sql.DB) *InterfaceService {
	return &InterfaceService{db: db, rec: objectChangesRecorder{}, now: time.Now}
}

// WithRecorder sets the change recorder.
func (s *InterfaceService) WithRecorder(r InterfaceChangeRecorder) *InterfaceService {
	if r == nil {
		r = objectChangesRecorder{}
	}
	s.rec = r
	return s
}

func (s *InterfaceService) record(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, action changes.Action, id uuid.UUID, pre, post any, source changes.Source) error {
	return s.rec.RecordInterfaceChange(ctx, tx, InterfaceChange{
		TenantID: tenant, Kind: dcim.ObjectKindInterface, ID: id, Action: action,
		Pre: pre, Post: post, Source: source,
	})
}

// InterfaceFilter is the list query (NetBox-style filters).
type InterfaceFilter struct {
	AssetID    *uuid.UUID
	Name       string
	Type       string
	Enabled    *bool
	MgmtOnly   *bool
	MACAddress string
	LagID      *uuid.UUID
	VLAN       *uuid.UUID
	Status     string
	Q          string
	Limit      int
	Offset     int
}

const interfaceColumns = `i.id, i.asset_id, i.module_id, i.name, i.label, i.type, i.enabled, i.mgmt_only,
	i.mtu, i.mac_address::text, i.speed_kbps, i.duplex, i.mode, i.untagged_vlan_id, i.vrf_id,
	i.parent_id, i.bridge_id, i.lag_id, i.rf_role, i.rf_channel, i.rf_channel_frequency::float8,
	i.rf_channel_width::float8, i.tx_power, i.poe_mode, i.poe_type, i.wwn, i.operational_status,
	i.admin_status,
	COALESCE((SELECT array_agg(c.name ORDER BY c.name) FROM interface_virtual_device_contexts j
	           JOIN virtual_device_contexts c ON c.id = j.virtual_device_context_id
	          WHERE j.interface_id = i.id), '{}'),
	i.mark_connected, i.cable_id, i.cable_end::text, i.source_kind,
	i.source_ref, i.custom_fields, i.description, i.comments, i.status, i.first_seen_at,
	i.last_seen_at, i.observation_count, i.approved_by, i.approved_at, i.created_at,
	i.updated_at, i.created_by,
	COALESCE((SELECT array_agg(t.vlan_id::text ORDER BY t.vlan_id) FROM interface_tagged_vlans t
	           WHERE t.interface_id = i.id), '{}'),
	COALESCE((SELECT json_agg(json_build_object('id', m.id, 'mac', m.mac::text, 'is_primary', m.is_primary,
	                 'source_kind', m.source_kind) ORDER BY m.is_primary DESC, m.mac)
	            FROM mac_addresses m WHERE m.interface_id = i.id), '[]'),
	COALESCE((SELECT json_agg(json_build_object('id', c.id, 'name', c.name) ORDER BY c.name, c.id)
	            FROM interface_virtual_device_contexts j JOIN virtual_device_contexts c ON c.id = j.virtual_device_context_id
	           WHERE j.interface_id = i.id), '[]'),
	i.vlan_translation_policy_id`

// interfaceNaturalOrder sorts `Gi1/0/2` before `Gi1/0/10`, as NetBox's
// naturalised name does: the name with its numbers blanked, then the numbers
// zero-padded, then the name itself as the tie-break.
const interfaceNaturalOrder = `regexp_replace(i.name, '\d+', '#', 'g'),
	array(SELECT lpad(x[1], 12, '0') FROM regexp_matches(i.name, '(\d+)', 'g') AS x), i.name`

type ifaceRowScanner interface{ Scan(dest ...any) error }

func ifaceScanInterface(r ifaceRowScanner) (Interface, error) {
	var (
		i                                  Interface
		mac, cableEnd                      sql.NullString
		mtu, tx                            sql.NullInt64
		vdcs                               pq.StringArray
		tagged                             pq.StringArray
		custom, macs, contexts             []byte
		speed                              sql.NullInt64
		freq, width                        sql.NullFloat64
		label, duplex, mode, rfRole, rfCh  sql.NullString
		poeMode, poeType, wwn, oper, admin sql.NullString
		srcRef, desc, comments             sql.NullString
		module, uvlan, vrf, parent, bridge uuid.NullUUID
		lag, cable, approvedBy, createdBy  uuid.NullUUID
		vtPolicy                           uuid.NullUUID
		approvedAt                         sql.NullTime
	)
	if err := r.Scan(&i.ID, &i.AssetID, &module, &i.Name, &label, &i.Type, &i.Enabled, &i.MgmtOnly,
		&mtu, &mac, &speed, &duplex, &mode, &uvlan, &vrf,
		&parent, &bridge, &lag, &rfRole, &rfCh, &freq,
		&width, &tx, &poeMode, &poeType, &wwn, &oper,
		&admin, &vdcs, &i.MarkConnected, &cable, &cableEnd, &i.SourceKind,
		&srcRef, &custom, &desc, &comments, &i.Status, &i.FirstSeenAt,
		&i.LastSeenAt, &i.ObservationCount, &approvedBy, &approvedAt, &i.CreatedAt,
		&i.UpdatedAt, &createdBy, &tagged, &macs, &contexts, &vtPolicy); err != nil {
		return Interface{}, err
	}
	i.ModuleID, i.UntaggedVLANID, i.VRFID = ifaceUuidPtr(module), ifaceUuidPtr(uvlan), ifaceUuidPtr(vrf)
	i.ParentID, i.BridgeID, i.LagID, i.CableID = ifaceUuidPtr(parent), ifaceUuidPtr(bridge), ifaceUuidPtr(lag), ifaceUuidPtr(cable)
	i.ApprovedBy, i.CreatedBy = ifaceUuidPtr(approvedBy), ifaceUuidPtr(createdBy)
	i.VLANTranslationPolicyID = ifaceUuidPtr(vtPolicy)
	i.Label, i.Duplex, i.Mode, i.RFRole, i.RFChannel = ifaceStrPtr(label), ifaceStrPtr(duplex), ifaceStrPtr(mode), ifaceStrPtr(rfRole), ifaceStrPtr(rfCh)
	i.PoEMode, i.PoEType, i.WWN = ifaceStrPtr(poeMode), ifaceStrPtr(poeType), ifaceStrPtr(wwn)
	i.OperationalStatus, i.AdminStatus, i.CableEnd = ifaceStrPtr(oper), ifaceStrPtr(admin), ifaceStrPtr(cableEnd)
	i.SourceRef, i.Description, i.Comments = ifaceStrPtr(srcRef), ifaceStrPtr(desc), ifaceStrPtr(comments)
	if mac.Valid {
		m := ifaceDisplayMAC(mac.String)
		i.MACAddress = &m
	}
	if mtu.Valid {
		v := int(mtu.Int64)
		i.MTU = &v
	}
	if tx.Valid {
		v := int(tx.Int64)
		i.TxPower = &v
	}
	if speed.Valid {
		v := speed.Int64
		i.SpeedKbps = &v
	}
	if freq.Valid {
		v := freq.Float64
		i.RFChannelFrequency = &v
	}
	if width.Valid {
		v := width.Float64
		i.RFChannelWidth = &v
	}
	if approvedAt.Valid {
		v := approvedAt.Time
		i.ApprovedAt = &v
	}
	i.VDCs = []string(vdcs)
	if i.VDCs == nil {
		i.VDCs = []string{}
	}
	i.VirtualDeviceContexts = []VirtualDeviceContextRef{}
	if len(contexts) > 0 {
		if err := json.Unmarshal(contexts, &i.VirtualDeviceContexts); err != nil {
			return Interface{}, err
		}
	}
	i.VirtualDeviceContextIDs = make([]uuid.UUID, 0, len(i.VirtualDeviceContexts))
	for _, c := range i.VirtualDeviceContexts {
		i.VirtualDeviceContextIDs = append(i.VirtualDeviceContextIDs, c.ID)
	}
	i.TaggedVLANIDs = []uuid.UUID{}
	for _, v := range tagged {
		if id, err := uuid.Parse(v); err == nil {
			i.TaggedVLANIDs = append(i.TaggedVLANIDs, id)
		}
	}
	i.CustomFields = map[string]any{}
	if len(custom) > 0 {
		_ = json.Unmarshal(custom, &i.CustomFields)
	}
	i.MACAddresses = []MacAddress{}
	if len(macs) > 0 {
		if err := json.Unmarshal(macs, &i.MACAddresses); err != nil {
			return Interface{}, err
		}
		for k := range i.MACAddresses {
			i.MACAddresses[k].MAC = ifaceDisplayMAC(i.MACAddresses[k].MAC)
		}
	}
	if t, ok := dcim.ParseInterfaceType(i.Type); ok {
		i.TypeLabel = dcim.InterfaceTypeLabel(t)
	}
	return i, nil
}

func ifaceUuidPtr(u uuid.NullUUID) *uuid.UUID {
	if !u.Valid {
		return nil
	}
	v := u.UUID
	return &v
}

func ifaceStrPtr(s sql.NullString) *string {
	if !s.Valid {
		return nil
	}
	v := s.String
	return &v
}

// List returns one page of interfaces and the total matching.
func (s *InterfaceService) List(ctx context.Context, tenant uuid.UUID, f InterfaceFilter) ([]Interface, int, error) {
	where := []string{"i.tenant_id = $1"}
	args := []any{tenant}
	add := func(cond string, v any) {
		args = append(args, v)
		where = append(where, strings.ReplaceAll(cond, "?", "$"+strconv.Itoa(len(args))))
	}
	if f.AssetID != nil {
		add("i.asset_id = ?", *f.AssetID)
	}
	if f.Name != "" {
		add("i.name = ?", f.Name)
	}
	if f.Type != "" {
		add("i.type = ?", f.Type)
	}
	if f.Enabled != nil {
		add("i.enabled = ?", *f.Enabled)
	}
	if f.MgmtOnly != nil {
		add("i.mgmt_only = ?", *f.MgmtOnly)
	}
	if f.MACAddress != "" {
		mac, err := ifaceNormalizeMAC(f.MACAddress)
		if err != nil {
			return nil, 0, ifaceInvalid("mac_address", "%v", err)
		}
		add("(i.mac_address = ?::macaddr8 OR EXISTS (SELECT 1 FROM mac_addresses m WHERE m.interface_id = i.id AND m.mac = ?::macaddr8))", mac)
	}
	if f.LagID != nil {
		add("i.lag_id = ?", *f.LagID)
	}
	if f.VLAN != nil {
		add("(i.untagged_vlan_id = ? OR EXISTS (SELECT 1 FROM interface_tagged_vlans t WHERE t.interface_id = i.id AND t.vlan_id = ?))", *f.VLAN)
	}
	if f.Status != "" {
		add("i.status = ?", f.Status)
	} else {
		// A rejected observation is kept only so it is recognised next time;
		// it is not part of the inventory a list shows.
		where = append(where, "i.status <> 'rejected'")
	}
	if q := strings.TrimSpace(f.Q); q != "" {
		like := "%" + strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(q) + "%"
		add("(i.name ILIKE ? OR i.label ILIKE ? OR i.description ILIKE ?)", like)
	}
	if f.Limit <= 0 {
		f.Limit = 50
	}
	cond := strings.Join(where, " AND ")

	var (
		out   []Interface
		total int
	)
	err := shareddb.WithTenantTx(ctx, s.db, tenant, func(tx *sql.Tx) error {
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM interfaces i WHERE "+cond, args...).Scan(&total); err != nil {
			return err
		}
		page := append(append([]any{}, args...), f.Limit, f.Offset)
		rows, err := tx.QueryContext(ctx, "SELECT "+interfaceColumns+" FROM interfaces i WHERE "+cond+
			" ORDER BY i.asset_id, "+interfaceNaturalOrder+
			" LIMIT $"+strconv.Itoa(len(args)+1)+" OFFSET $"+strconv.Itoa(len(args)+2), page...)
		if err != nil {
			return err
		}
		defer func() { _ = rows.Close() }()
		for rows.Next() {
			i, err := ifaceScanInterface(rows)
			if err != nil {
				return err
			}
			out = append(out, i)
		}
		return rows.Err()
	})
	if out == nil {
		out = []Interface{}
	}
	return out, total, err
}

// Get returns one interface.
func (s *InterfaceService) Get(ctx context.Context, tenant, id uuid.UUID) (Interface, error) {
	var out Interface
	err := shareddb.WithTenantTx(ctx, s.db, tenant, func(tx *sql.Tx) error {
		var err error
		out, err = ifaceGetInterfaceTx(ctx, tx, tenant, id)
		return err
	})
	return out, err
}

func ifaceGetInterfaceTx(ctx context.Context, tx *sql.Tx, tenant, id uuid.UUID) (Interface, error) {
	i, err := ifaceScanInterface(tx.QueryRowContext(ctx,
		"SELECT "+interfaceColumns+" FROM interfaces i WHERE i.tenant_id = $1 AND i.id = $2", tenant, id))
	if errors.Is(err, sql.ErrNoRows) {
		return Interface{}, ErrInterfaceNotFound
	}
	return i, err
}

// ifaceAssetStatus returns the asset's approval status, or ErrInterfaceAssetNotFound.
func ifaceAssetStatus(ctx context.Context, tx *sql.Tx, tenant, asset uuid.UUID) (string, error) {
	var st string
	err := tx.QueryRowContext(ctx,
		`SELECT asset_status FROM assets WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL`,
		tenant, asset).Scan(&st)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrInterfaceAssetNotFound
	}
	return st, err
}

// ifaceRefsOf loads the asset's interfaces plus any other ids the candidates name,
// as the rules' lookup. Ids named but outside the asset are loaded so the
// rules can say "same asset" rather than "no such interface".
func ifaceRefsOf(ctx context.Context, tx *sql.Tx, tenant, asset uuid.UUID, extra []uuid.UUID) (map[uuid.UUID]interfaceRef, error) {
	ids := make([]string, 0, len(extra))
	for _, e := range extra {
		ids = append(ids, e.String())
	}
	rows, err := tx.QueryContext(ctx, `
		SELECT id, asset_id, type, lag_id, parent_id, bridge_id
		  FROM interfaces
		 WHERE tenant_id = $1 AND status <> 'rejected' AND (asset_id = $2 OR id = ANY($3::uuid[]))`,
		tenant, asset, pq.Array(ids))
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := map[uuid.UUID]interfaceRef{}
	for rows.Next() {
		var r interfaceRef
		var lag, parent, bridge uuid.NullUUID
		if err := rows.Scan(&r.ID, &r.AssetID, &r.Type, &lag, &parent, &bridge); err != nil {
			return nil, err
		}
		r.LagID, r.ParentID, r.BridgeID = ifaceUuidPtr(lag), ifaceUuidPtr(parent), ifaceUuidPtr(bridge)
		out[r.ID] = r
	}
	return out, rows.Err()
}

// ifaceCheckIPAMRefs says, field by field, when a VLAN or VRF the candidate
// names is not one of this tenant's (row 1.3's tables). The tenant-paired FKs
// would refuse the write anyway; this turns the refusal into a 422 that names
// the field instead of a 500.
func ifaceCheckIPAMRefs(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, in InterfaceInput) error {
	exists := func(table string, id uuid.UUID) (bool, error) {
		var ok bool
		err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM public.`+table+` WHERE tenant_id = $1 AND id = $2)`, tenant, id).Scan(&ok)
		return ok, err
	}
	if in.UntaggedVLANID != nil {
		if ok, err := exists("vlans", *in.UntaggedVLANID); err != nil || !ok {
			if err != nil {
				return err
			}
			return ifaceInvalid("untagged_vlan_id", "no such VLAN")
		}
	}
	for _, v := range in.TaggedVLANIDs {
		if ok, err := exists("vlans", v); err != nil || !ok {
			if err != nil {
				return err
			}
			return ifaceInvalid("tagged_vlan_ids", "no such VLAN %s", v)
		}
	}
	if in.VRFID != nil {
		if ok, err := exists("vrfs", *in.VRFID); err != nil || !ok {
			if err != nil {
				return err
			}
			return ifaceInvalid("vrf_id", "no such VRF")
		}
	}
	if in.VLANTranslationPolicyID != nil {
		if ok, err := exists("vlan_translation_policies", *in.VLANTranslationPolicyID); err != nil || !ok {
			if err != nil {
				return err
			}
			return ifaceInvalid("vlan_translation_policy_id", "no such VLAN translation policy")
		}
	}
	return nil
}

// ifaceSetTranslationPolicy writes the interface's VLAN translation policy
// (DCIM gap 10). Its own statement, so the column stays out of the row 1.2
// INSERT / UPDATE lists.
func ifaceSetTranslationPolicy(ctx context.Context, tx *sql.Tx, tenant, id uuid.UUID, policy *uuid.UUID) error {
	_, err := tx.ExecContext(ctx, `UPDATE interfaces SET vlan_translation_policy_id = $3
		 WHERE tenant_id = $1 AND id = $2 AND vlan_translation_policy_id IS DISTINCT FROM $3`, tenant, id, ifaceNullUUID(policy))
	return err
}

func ifaceRefsNamed(in InterfaceInput) []uuid.UUID {
	var out []uuid.UUID
	for _, p := range []*uuid.UUID{in.LagID, in.ParentID, in.BridgeID} {
		if p != nil {
			out = append(out, *p)
		}
	}
	return out
}

func ifaceRefOfInput(id uuid.UUID, in InterfaceInput) interfaceRef {
	return interfaceRef{ID: id, AssetID: in.AssetID, Type: in.Type, LagID: in.LagID, ParentID: in.ParentID, BridgeID: in.BridgeID}
}

func ifaceMapLookup(m map[uuid.UUID]interfaceRef) interfaceLookup {
	return func(id uuid.UUID) (interfaceRef, bool) {
		r, ok := m[id]
		return r, ok
	}
}

func ifaceUniqueViolation(err error) bool {
	var pqErr *pq.Error
	return errors.As(err, &pqErr) && pqErr.Code == "23505" && pqErr.Constraint == "interfaces_identity_uniq"
}

// Create declares one interface.
func (s *InterfaceService) Create(ctx context.Context, tenant, actor uuid.UUID, in InterfaceInput) (Interface, error) {
	out, err := s.BulkCreate(ctx, tenant, actor, []InterfaceInput{in})
	if err != nil {
		return Interface{}, err
	}
	return out[0], nil
}

// BulkCreate declares several interfaces in one transaction: all or none. A
// LAG and its members may arrive in the same list; the rules see the whole
// batch.
func (s *InterfaceService) BulkCreate(ctx context.Context, tenant, actor uuid.UUID, ins []InterfaceInput) ([]Interface, error) {
	if len(ins) == 0 {
		return nil, ifaceInvalid("body", "at least one interface is required")
	}
	out := make([]Interface, 0, len(ins))
	err := shareddb.WithTenantTx(ctx, s.db, tenant, func(tx *sql.Tx) error {
		refs := map[uuid.UUID]map[uuid.UUID]interfaceRef{} // per asset
		ids := make([]uuid.UUID, len(ins))
		for k, in := range ins {
			if in.AssetID == uuid.Nil {
				return ifaceInvalid("asset_id", "is required")
			}
			if _, ok := refs[in.AssetID]; !ok {
				if _, err := ifaceAssetStatus(ctx, tx, tenant, in.AssetID); err != nil {
					return err
				}
				var named []uuid.UUID
				for _, other := range ins {
					if other.AssetID == in.AssetID {
						named = append(named, ifaceRefsNamed(other)...)
					}
				}
				m, err := ifaceRefsOf(ctx, tx, tenant, in.AssetID, named)
				if err != nil {
					return err
				}
				refs[in.AssetID] = m
			}
			ids[k] = uuid.New()
			refs[in.AssetID][ids[k]] = ifaceRefOfInput(ids[k], in)
		}
		for k, in := range ins {
			if err := validateInterface(in, ids[k], ifaceMapLookup(refs[in.AssetID])); err != nil {
				return err
			}
			// Custom fields (DCIM row 5.1): defaults filled, values checked
			// against the tenant's definitions.
			cf, err := validateCustomFieldsTx(ctx, tx, dcim.ObjectKindInterface, true, nil, in.CustomFields, enforcesRequired(ctx, ""))
			if err != nil {
				return ifaceCustomFieldError(err)
			}
			ins[k].CustomFields = cf
			if err := ifaceCheckIPAMRefs(ctx, tx, tenant, in); err != nil {
				return err
			}
			vdcs, err := ifaceResolveContexts(ctx, tx, tenant, in.AssetID, in.VirtualDeviceContextIDs, in.VDCs,
				len(in.VirtualDeviceContextIDs) > 0, len(in.VDCs) > 0)
			if err != nil {
				return err
			}
			ins[k].VirtualDeviceContextIDs = vdcs
		}
		// Members reference their LAG / parent: insert referenced rows first.
		for _, k := range ifaceInsertOrder(ins, ids) {
			if err := ifaceInsertInterface(ctx, tx, tenant, ids[k], actor, ins[k]); err != nil {
				return err
			}
		}
		for k := range ins {
			got, err := ifaceGetInterfaceTx(ctx, tx, tenant, ids[k])
			if err != nil {
				return err
			}
			if err := s.record(ctx, tx, tenant, changes.ActionCreate, got.ID, nil, got, ""); err != nil {
				return err
			}
			out = append(out, got)
		}
		return nil
	})
	if ifaceUniqueViolation(err) {
		return nil, ErrInterfaceNameTaken
	}
	return out, err
}

// ifaceInsertOrder sorts a batch so an interface is inserted after any interface
// of the same batch it references. The rules have already refused cycles.
func ifaceInsertOrder(ins []InterfaceInput, ids []uuid.UUID) []int {
	pos := map[uuid.UUID]int{}
	for k, id := range ids {
		pos[id] = k
	}
	depth := make([]int, len(ins))
	var walk func(k, d int) int
	walk = func(k, d int) int {
		if d > ifaceMaxChainWalk {
			return 0
		}
		best := 0
		for _, ref := range ifaceRefsNamed(ins[k]) {
			if j, ok := pos[ref]; ok && j != k {
				if v := walk(j, d+1) + 1; v > best {
					best = v
				}
			}
		}
		return best
	}
	order := make([]int, len(ins))
	for k := range ins {
		depth[k] = walk(k, 0)
		order[k] = k
	}
	sort.SliceStable(order, func(a, b int) bool { return depth[order[a]] < depth[order[b]] })
	return order
}

func ifaceNullUUID(p *uuid.UUID) any {
	if p == nil {
		return nil
	}
	return *p
}

func ifaceNullStr(p *string) any {
	if p == nil {
		return nil
	}
	return *p
}

func ifaceCustomJSON(m map[string]any) []byte {
	if m == nil {
		return []byte("{}")
	}
	b, err := json.Marshal(m)
	if err != nil {
		return []byte("{}")
	}
	return b
}

func ifaceMacOf(p *string) any {
	if p == nil {
		return nil
	}
	m, _ := ifaceNormalizeMAC(*p)
	return m
}

func ifaceInsertInterface(ctx context.Context, tx *sql.Tx, tenant, id, actor uuid.UUID, in InterfaceInput) error {
	enabled := true
	if in.Enabled != nil {
		enabled = *in.Enabled
	}
	var createdBy any
	if actor != uuid.Nil {
		createdBy = actor
	}
	_, err := tx.ExecContext(ctx, `
		INSERT INTO interfaces (id, tenant_id, asset_id, name, label, type, enabled, mgmt_only, mtu,
			mac_address, speed_kbps, duplex, mode, untagged_vlan_id, vrf_id, parent_id, bridge_id, lag_id,
			rf_role, rf_channel, rf_channel_frequency, rf_channel_width, tx_power, poe_mode, poe_type, wwn,
			mark_connected, description, comments, custom_fields, source_kind, status, created_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::macaddr8,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,
			$24,$25,$26,$27,$28,$29,$30,'declared','active',$31)`,
		id, tenant, in.AssetID, in.Name, ifaceNullStr(in.Label), in.Type, enabled, in.MgmtOnly, in.MTU,
		ifaceMacOf(in.MACAddress), in.SpeedKbps, ifaceNullStr(in.Duplex), ifaceNullStr(in.Mode), ifaceNullUUID(in.UntaggedVLANID),
		ifaceNullUUID(in.VRFID), ifaceNullUUID(in.ParentID), ifaceNullUUID(in.BridgeID), ifaceNullUUID(in.LagID),
		ifaceNullStr(in.RFRole), ifaceNullStr(in.RFChannel), in.RFChannelFrequency, in.RFChannelWidth, in.TxPower,
		ifaceNullStr(in.PoEMode), ifaceNullStr(in.PoEType), ifaceNullStr(in.WWN), in.MarkConnected,
		ifaceNullStr(in.Description), ifaceNullStr(in.Comments), ifaceCustomJSON(in.CustomFields), createdBy)
	if err != nil {
		return err
	}
	if err := ifaceReplaceMACs(ctx, tx, tenant, id, in.MACAddress, in.MACAddresses); err != nil {
		return err
	}
	if err := ifaceReplaceContexts(ctx, tx, tenant, id, in.VirtualDeviceContextIDs); err != nil {
		return err
	}
	if err := ifaceSetTranslationPolicy(ctx, tx, tenant, id, in.VLANTranslationPolicyID); err != nil {
		return err
	}
	return ifaceReplaceTaggedVLANs(ctx, tx, tenant, id, in.TaggedVLANIDs)
}

// ifaceReplaceMACs makes the interface's declared MAC rows exactly the primary plus
// the extras. Measured rows (intake's) are left alone unless the person names
// the same MAC, which then becomes declared.
func ifaceReplaceMACs(ctx context.Context, tx *sql.Tx, tenant, id uuid.UUID, primary *string, extra []string) error {
	want := map[string]bool{}
	var p string
	if primary != nil {
		p, _ = ifaceNormalizeMAC(*primary)
		want[p] = true
	}
	for _, e := range extra {
		m, _ := ifaceNormalizeMAC(e)
		if _, ok := want[m]; !ok {
			want[m] = false
		}
	}
	macs := make([]string, 0, len(want))
	for m := range want {
		macs = append(macs, m)
	}
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM mac_addresses
		 WHERE interface_id = $1 AND source_kind = 'declared'
		   AND NOT (mac = ANY ($2::macaddr8[]))`, id, pq.Array(macs)); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE mac_addresses SET is_primary = false WHERE interface_id = $1 AND is_primary`, id); err != nil {
		return err
	}
	for _, m := range macs {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO mac_addresses (tenant_id, interface_id, mac, is_primary, source_kind)
			VALUES ($1, $2, $3::macaddr8, $4, 'declared')
			ON CONFLICT (interface_id, mac) DO UPDATE SET is_primary = EXCLUDED.is_primary, source_kind = 'declared'`,
			tenant, id, m, m == p); err != nil {
			return err
		}
	}
	return nil
}

func ifaceReplaceTaggedVLANs(ctx context.Context, tx *sql.Tx, tenant, id uuid.UUID, vlans []uuid.UUID) error {
	ids := make([]string, 0, len(vlans))
	for _, v := range vlans {
		ids = append(ids, v.String())
	}
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM interface_tagged_vlans WHERE interface_id = $1 AND NOT (vlan_id = ANY ($2::uuid[]))`,
		id, pq.Array(ids)); err != nil {
		return err
	}
	for _, v := range ids {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO interface_tagged_vlans (tenant_id, interface_id, vlan_id) VALUES ($1, $2, $3)
			ON CONFLICT DO NOTHING`, tenant, id, v); err != nil {
			return err
		}
	}
	return nil
}

// Patch applies a JSON merge-patch to a declared view of the interface.
func (s *InterfaceService) Patch(ctx context.Context, tenant, id uuid.UUID, patch map[string]json.RawMessage) (Interface, error) {
	var out Interface
	err := shareddb.WithTenantTx(ctx, s.db, tenant, func(tx *sql.Tx) error {
		pre, err := ifaceGetInterfaceTx(ctx, tx, tenant, id)
		if err != nil {
			return err
		}
		in, err := ifaceApplyPatch(ifaceInputOf(pre), patch)
		if err != nil {
			return err
		}
		refs, err := ifaceRefsOf(ctx, tx, tenant, pre.AssetID, ifaceRefsNamed(in))
		if err != nil {
			return err
		}
		refs[id] = ifaceRefOfInput(id, in)
		if err := validateInterface(in, id, ifaceMapLookup(refs)); err != nil {
			return err
		}
		// Custom fields (DCIM row 5.1): a patch that names custom_fields
		// replaces only the fields it names, and is checked against the
		// tenant's definitions.
		if _, ok := patch["custom_fields"]; ok {
			cf, err := validateCustomFieldsTx(ctx, tx, dcim.ObjectKindInterface, false, pre.CustomFields, in.CustomFields, enforcesRequired(ctx, ""))
			if err != nil {
				return ifaceCustomFieldError(err)
			}
			in.CustomFields = cf
		}
		if err := ifaceCheckIPAMRefs(ctx, tx, tenant, in); err != nil {
			return err
		}
		_, idsSent := patch["virtual_device_context_ids"]
		_, namesSent := patch["vdcs"]
		if idsSent || namesSent {
			vdcs, err := ifaceResolveContexts(ctx, tx, tenant, pre.AssetID, in.VirtualDeviceContextIDs, in.VDCs, idsSent, namesSent)
			if err != nil {
				return err
			}
			in.VirtualDeviceContextIDs = vdcs
		}
		// A cabled interface (row 3.2) cannot also be marked connected, nor
		// become a kind no cable can attach to (NetBox Interface.clean).
		if pre.CableID != nil {
			if in.MarkConnected {
				return ifaceInvalid("mark_connected", "cannot be set while a cable is attached; remove the cable first")
			}
			if g := dcim.InterfaceTypeGroup(dcim.InterfaceType(in.Type)); g == "virtual" || g == "wireless" {
				return ifaceInvalid("type", "a cabled interface cannot become %s; remove the cable first", g)
			}
		}
		if pre.Type == string(dcim.InterfaceTypeLag) && in.Type != pre.Type {
			for _, r := range refs {
				if r.LagID != nil && *r.LagID == id {
					return ifaceInvalid("type", "this LAG has members; remove them before changing its type")
				}
			}
		}
		enabled := pre.Enabled
		if in.Enabled != nil {
			enabled = *in.Enabled
		}
		if _, err := tx.ExecContext(ctx, `
			UPDATE interfaces SET name = $3, label = $4, type = $5, enabled = $6, mgmt_only = $7, mtu = $8,
				mac_address = $9::macaddr8, speed_kbps = $10, duplex = $11, mode = $12, untagged_vlan_id = $13,
				vrf_id = $14, parent_id = $15, bridge_id = $16, lag_id = $17, rf_role = $18, rf_channel = $19,
				rf_channel_frequency = $20, rf_channel_width = $21, tx_power = $22, poe_mode = $23,
				poe_type = $24, wwn = $25, mark_connected = $26, description = $27,
				comments = $28, custom_fields = $29
			 WHERE tenant_id = $1 AND id = $2`,
			tenant, id, in.Name, ifaceNullStr(in.Label), in.Type, enabled, in.MgmtOnly, in.MTU,
			ifaceMacOf(in.MACAddress), in.SpeedKbps, ifaceNullStr(in.Duplex), ifaceNullStr(in.Mode), ifaceNullUUID(in.UntaggedVLANID),
			ifaceNullUUID(in.VRFID), ifaceNullUUID(in.ParentID), ifaceNullUUID(in.BridgeID), ifaceNullUUID(in.LagID),
			ifaceNullStr(in.RFRole), ifaceNullStr(in.RFChannel), in.RFChannelFrequency, in.RFChannelWidth, in.TxPower,
			ifaceNullStr(in.PoEMode), ifaceNullStr(in.PoEType), ifaceNullStr(in.WWN), in.MarkConnected,
			ifaceNullStr(in.Description), ifaceNullStr(in.Comments), ifaceCustomJSON(in.CustomFields)); err != nil {
			return err
		}
		if err := ifaceReplaceMACs(ctx, tx, tenant, id, in.MACAddress, in.MACAddresses); err != nil {
			return err
		}
		if err := ifaceReplaceTaggedVLANs(ctx, tx, tenant, id, in.TaggedVLANIDs); err != nil {
			return err
		}
		if err := ifaceReplaceContexts(ctx, tx, tenant, id, in.VirtualDeviceContextIDs); err != nil {
			return err
		}
		if err := ifaceSetTranslationPolicy(ctx, tx, tenant, id, in.VLANTranslationPolicyID); err != nil {
			return err
		}
		out, err = ifaceGetInterfaceTx(ctx, tx, tenant, id)
		if err != nil {
			return err
		}
		return s.record(ctx, tx, tenant, changes.ActionUpdate, id, pre, out, "")
	})
	if ifaceUniqueViolation(err) {
		return Interface{}, ErrInterfaceNameTaken
	}
	return out, err
}

// Delete removes an interface. Its LAG members, children and bridged
// interfaces are detached (ON DELETE SET NULL); each detachment is recorded as
// an update of that interface, so the change log explains why it moved.
func (s *InterfaceService) Delete(ctx context.Context, tenant, id uuid.UUID) error {
	return shareddb.WithTenantTx(ctx, s.db, tenant, func(tx *sql.Tx) error {
		pre, err := ifaceGetInterfaceTx(ctx, tx, tenant, id)
		if err != nil {
			return err
		}
		rows, err := tx.QueryContext(ctx, `
			SELECT id FROM interfaces
			 WHERE tenant_id = $1 AND (lag_id = $2 OR parent_id = $2 OR bridge_id = $2)`, tenant, id)
		if err != nil {
			return err
		}
		var dependants []uuid.UUID
		for rows.Next() {
			var d uuid.UUID
			if err := rows.Scan(&d); err != nil {
				_ = rows.Close()
				return err
			}
			dependants = append(dependants, d)
		}
		_ = rows.Close()
		befores := make([]Interface, 0, len(dependants))
		for _, d := range dependants {
			b, err := ifaceGetInterfaceTx(ctx, tx, tenant, d)
			if err != nil {
				return err
			}
			befores = append(befores, b)
		}
		// Addresses assigned to it stay in IPAM, unassigned (assigned_id is
		// polymorphic, so no FK does this). FHRP assignments cascade.
		if _, err := tx.ExecContext(ctx, `UPDATE ip_addresses SET assigned_kind = NULL, assigned_id = NULL
		    WHERE tenant_id = $1 AND assigned_kind = 'interface' AND assigned_id = $2`, tenant, id); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM interfaces WHERE tenant_id = $1 AND id = $2`, tenant, id); err != nil {
			return err
		}
		if err := s.record(ctx, tx, tenant, changes.ActionDelete, id, pre, nil, ""); err != nil {
			return err
		}
		// Its cable end goes with it, and the paths over it are recomputed
		// (row 3.2).
		if err := sweepOrphanTerminations(ctx, tx, tenant, dcim.ObjectKindInterface); err != nil {
			return err
		}
		for _, b := range befores {
			after, err := ifaceGetInterfaceTx(ctx, tx, tenant, b.ID)
			if err != nil {
				return err
			}
			if err := s.record(ctx, tx, tenant, changes.ActionUpdate, b.ID, b, after, ""); err != nil {
				return err
			}
		}
		return nil
	})
}

// ------------------------------------------------------------- intake ----

// ObservedInterface is one interface as a collector measured it: the input of
// UpsertObserved, built by row 1.5's adapters from the agent's net.interfaces
// fact (name, mac, state), SNMP ifTable/ifXTable (ifDescr/ifName, ifType,
// ifMtu, ifHighSpeed, ifPhysAddress, ifAdminStatus, ifOperStatus, ifAlias) and
// UniFi port_table (name, up, enable, speed). Posture only: nothing here can
// carry a credential, and adapters must not invent fields to smuggle one in.
type ObservedInterface struct {
	// Name as the source spelled it; canonicalised with Vendor.
	Name   string
	Vendor string
	// Type is a registry key where the source can say (ifType mapping); empty
	// lets the name's kind choose (lag, virtual, bridge) or leaves `other`.
	Type              string
	MAC               string
	MTU               *int
	SpeedKbps         *int64
	Duplex            string
	OperationalStatus string // up, down, testing, unknown
	AdminStatus       string // up, down, testing
	// Description (ifAlias) seeds a NEW interface's description and is never
	// written over an existing one: the description is declared.
	Description string
}

// UpsertObservedResult says what one observation did.
type UpsertObservedResult struct {
	Created     int
	Updated     int
	Seen        int
	MarkedStale int
	Skipped     []string // names that could not be stored, with the reason
}

// defaultInterfaceStaleDays is the asset lifecycle default (asset_lifecycle_service.go)
// and the hygiene ladder's first rung, used when the tenant has no policy row.
const defaultInterfaceStaleDays = 30

// UpsertObserved records a complete observation of an asset's interfaces.
//
// Keyed by canonical name. A new name inserts a `measured` interface whose
// status follows its asset (active if the asset is approved, pending
// otherwise — row 1.4 gives interfaces their own approval rules). An existing
// interface — measured or declared — gets its MEASURED fields only
// (operational/admin status, speed, duplex, MTU, MAC, type where it is still
// `other`), last_seen_at and observation_count. `enabled`, `description` and
// every other declared field are never written by this path.
//
// Interfaces of the asset this observation does not contain, that are
// themselves measured and have gone unobserved longer than the tenant's stale
// window, become `stale`. Nothing is deleted.
func (s *InterfaceService) UpsertObserved(ctx context.Context, tenant, asset uuid.UUID, producer string, obs []ObservedInterface) (UpsertObservedResult, error) {
	var res UpsertObservedResult
	producer = strings.TrimSpace(producer)
	if producer == "" {
		return res, errors.New("upsert observed: producer is required")
	}
	source := changes.IntakeSource(producer)
	now := s.now().UTC()

	err := shareddb.WithTenantTx(ctx, s.db, tenant, func(tx *sql.Tx) error {
		ast, err := ifaceAssetStatus(ctx, tx, tenant, asset)
		if err != nil {
			return err
		}
		status := "pending"
		if ast == "monitoring" {
			status = "active"
		}

		existing := map[string]Interface{}
		rows, err := tx.QueryContext(ctx, "SELECT "+interfaceColumns+
			" FROM interfaces i WHERE i.tenant_id = $1 AND i.asset_id = $2 AND i.status <> 'rejected'", tenant, asset)
		if err != nil {
			return err
		}
		for rows.Next() {
			i, err := ifaceScanInterface(rows)
			if err != nil {
				_ = rows.Close()
				return err
			}
			existing[i.Name] = i
		}
		_ = rows.Close()

		seen := map[string]bool{}
		for _, o := range obs {
			name, kind := ifnames.Canonical(o.Vendor, o.Name)
			if name == "" {
				continue
			}
			if seen[name] {
				continue // the same interface twice in one observation
			}
			o, skip := ifaceSanitizeObserved(o, name, kind)
			if skip != "" {
				res.Skipped = append(res.Skipped, name+": "+skip)
				continue
			}
			seen[name] = true
			res.Seen++
			if cur, ok := existing[name]; ok {
				changed, err := ifaceUpdateObserved(ctx, tx, tenant, cur, o, status, now)
				if err != nil {
					return err
				}
				if changed {
					after, err := ifaceGetInterfaceTx(ctx, tx, tenant, cur.ID)
					if err != nil {
						return err
					}
					if err := s.record(ctx, tx, tenant, changes.ActionUpdate, cur.ID, cur, after, source); err != nil {
						return err
					}
					res.Updated++
				}
				continue
			}
			id := uuid.New()
			if err := ifaceInsertObserved(ctx, tx, tenant, asset, id, o, status, producer, now); err != nil {
				return err
			}
			after, err := ifaceGetInterfaceTx(ctx, tx, tenant, id)
			if err != nil {
				return err
			}
			if err := s.record(ctx, tx, tenant, changes.ActionCreate, id, nil, after, source); err != nil {
				return err
			}
			res.Created++
		}

		// The sweep: absent, measured, unobserved past the window → stale.
		days := defaultInterfaceStaleDays
		var policyDays sql.NullInt64
		if err := tx.QueryRowContext(ctx,
			`SELECT stale_warning_days FROM asset_lifecycle_policies WHERE tenant_id = $1`, tenant).Scan(&policyDays); err == nil && policyDays.Valid && policyDays.Int64 > 0 {
			days = int(policyDays.Int64)
		}
		cutoff := now.AddDate(0, 0, -days)
		for name, cur := range existing {
			if seen[name] || cur.SourceKind != "measured" || cur.Status == "stale" || cur.Status == "archived" {
				continue
			}
			if !cur.LastSeenAt.Before(cutoff) {
				continue
			}
			if _, err := tx.ExecContext(ctx,
				`UPDATE interfaces SET status = 'stale' WHERE tenant_id = $1 AND id = $2`, tenant, cur.ID); err != nil {
				return err
			}
			after, err := ifaceGetInterfaceTx(ctx, tx, tenant, cur.ID)
			if err != nil {
				return err
			}
			if err := s.record(ctx, tx, tenant, changes.ActionUpdate, cur.ID, cur, after, source); err != nil {
				return err
			}
			res.MarkedStale++
		}
		return nil
	})
	return res, err
}

// ifaceSanitizeObserved drops values the schema would refuse rather than failing
// the whole observation over one odd field, and picks a type.
func ifaceSanitizeObserved(o ObservedInterface, name string, kind string) (ObservedInterface, string) {
	o.Name = name
	if len(name) > 64 {
		return o, "name longer than 64 characters"
	}
	if _, ok := dcim.ParseInterfaceType(o.Type); !ok {
		o.Type = ifaceTypeForKind(kind)
	}
	if o.MAC != "" {
		if m, err := ifaceNormalizeMAC(o.MAC); err == nil {
			o.MAC = m
		} else {
			o.MAC = ""
		}
	}
	if o.MTU != nil && (*o.MTU < 1 || *o.MTU > 65536) {
		o.MTU = nil
	}
	if o.SpeedKbps != nil && *o.SpeedKbps < 0 {
		o.SpeedKbps = nil
	}
	if _, ok := dcim.ParseInterfaceDuplex(o.Duplex); !ok {
		o.Duplex = ""
	}
	switch o.OperationalStatus {
	case "up", "down", "testing", "unknown":
	default:
		o.OperationalStatus = ""
	}
	switch o.AdminStatus {
	case "up", "down", "testing":
	default:
		o.AdminStatus = ""
	}
	return o, ""
}

// ifaceTypeForKind is the type a name's kind implies when the source gave none.
func ifaceTypeForKind(kind string) string {
	switch ifnames.Kind(kind) {
	case ifnames.KindLAG:
		return string(dcim.InterfaceTypeLag)
	case ifnames.KindBridge:
		return string(dcim.InterfaceTypeBridge)
	case ifnames.KindVirtual, ifnames.KindLoopback, ifnames.KindVLAN, ifnames.KindTunnel:
		return string(dcim.InterfaceTypeVirtual)
	}
	return "other"
}

func ifaceEmptyNil(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func ifaceInsertObserved(ctx context.Context, tx *sql.Tx, tenant, asset, id uuid.UUID, o ObservedInterface, status, producer string, now time.Time) error {
	// enabled is declared, but a new interface has no declaration yet; the
	// device's own admin state is the best first answer. Later observations
	// never touch it.
	enabled := o.AdminStatus != "down"
	_, err := tx.ExecContext(ctx, `
		INSERT INTO interfaces (id, tenant_id, asset_id, name, type, enabled, mtu, mac_address, speed_kbps,
			duplex, operational_status, admin_status, description, source_kind, source_ref, status,
			first_seen_at, last_seen_at, observation_count)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8::macaddr8,$9,$10,$11,$12,$13,'measured',$14,$15,$16,$16,1)`,
		id, tenant, asset, o.Name, o.Type, enabled, o.MTU, ifaceEmptyNil(o.MAC), o.SpeedKbps, ifaceEmptyNil(o.Duplex),
		ifaceEmptyNil(o.OperationalStatus), ifaceEmptyNil(o.AdminStatus), ifaceEmptyNil(o.Description), producer, status, now)
	if err != nil {
		return err
	}
	if o.MAC != "" {
		return ifaceSetMeasuredPrimaryMAC(ctx, tx, tenant, id, o.MAC)
	}
	return nil
}

// ifaceUpdateObserved writes the measured fields of an existing interface. It
// reports whether anything a reader would see changed (last_seen_at and the
// count always move and are not, on their own, a change worth recording).
func ifaceUpdateObserved(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, cur Interface, o ObservedInterface, assetDerived string, now time.Time) (bool, error) {
	status := cur.Status
	if status == "stale" || (status == "pending" && assetDerived == "active") {
		// Seen again: back to what its asset says; and an interface proposed
		// while its asset was pending follows the asset once it is approved.
		status = assetDerived
	}
	typ := cur.Type
	if typ == "other" && o.Type != "other" {
		typ = o.Type
	}
	mtu, speed := cur.MTU, cur.SpeedKbps
	if o.MTU != nil {
		mtu = o.MTU
	}
	if o.SpeedKbps != nil {
		speed = o.SpeedKbps
	}
	pick := func(cur *string, obs string) *string {
		if obs == "" {
			return cur
		}
		return &obs
	}
	duplex := pick(cur.Duplex, o.Duplex)
	oper := pick(cur.OperationalStatus, o.OperationalStatus)
	admin := pick(cur.AdminStatus, o.AdminStatus)
	mac := pick(cur.MACAddress, o.MAC)

	changed := status != cur.Status || typ != cur.Type || !ifaceEqInt(mtu, cur.MTU) || !ifaceEqInt64(speed, cur.SpeedKbps) ||
		!ifaceEqStr(duplex, cur.Duplex) || !ifaceEqStr(oper, cur.OperationalStatus) || !ifaceEqStr(admin, cur.AdminStatus) ||
		!ifaceEqStr(mac, cur.MACAddress)

	// The column list IS the guard: enabled, description, label, mode, VLANs,
	// LAG/parent/bridge, mgmt_only and custom fields are not in it.
	if _, err := tx.ExecContext(ctx, `
		UPDATE interfaces SET status = $3, type = $4, mtu = $5, speed_kbps = $6, duplex = $7,
			operational_status = $8, admin_status = $9, mac_address = $10::macaddr8,
			last_seen_at = $11, observation_count = observation_count + 1
		 WHERE tenant_id = $1 AND id = $2`,
		tenant, cur.ID, status, typ, mtu, speed, ifaceNullStr(duplex), ifaceNullStr(oper), ifaceNullStr(admin), ifaceMacOf(mac), now); err != nil {
		return false, err
	}
	if o.MAC != "" && !ifaceEqStr(mac, cur.MACAddress) {
		if err := ifaceSetMeasuredPrimaryMAC(ctx, tx, tenant, cur.ID, o.MAC); err != nil {
			return false, err
		}
	}
	return changed, nil
}

func ifaceSetMeasuredPrimaryMAC(ctx context.Context, tx *sql.Tx, tenant, id uuid.UUID, mac string) error {
	if _, err := tx.ExecContext(ctx,
		`UPDATE mac_addresses SET is_primary = false WHERE interface_id = $1 AND is_primary AND mac <> $2::macaddr8`,
		id, mac); err != nil {
		return err
	}
	_, err := tx.ExecContext(ctx, `
		INSERT INTO mac_addresses (tenant_id, interface_id, mac, is_primary, source_kind)
		VALUES ($1, $2, $3::macaddr8, true, 'measured')
		ON CONFLICT (interface_id, mac) DO UPDATE SET is_primary = true`, tenant, id, mac)
	return err
}

func ifaceEqStr(a, b *string) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func ifaceEqInt(a, b *int) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func ifaceEqInt64(a, b *int64) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

// String renders a result for logs.
func (r UpsertObservedResult) String() string {
	return fmt.Sprintf("seen=%d created=%d updated=%d stale=%d skipped=%d", r.Seen, r.Created, r.Updated, r.MarkedStale, len(r.Skipped))
}

// ------------------------------------------------- template instantiation --

// InterfaceTemplateSpec is one interface template being instantiated onto an
// asset (DCIM row 2.2; ADR-0010 D4): the device type's interface_templates row.
type InterfaceTemplateSpec struct {
	Name, Label, Type, Description string
	Enabled, MgmtOnly              bool
	PoEMode, PoEType, RFRole       string
	// Bridge is the name of another template of the same type.
	Bridge string
}

// InstantiateInterfacesResult says what one instantiation did to the asset's
// interfaces.
type InstantiateInterfacesResult struct {
	Created   int `json:"created"`
	Updated   int `json:"updated"`
	Unchanged int `json:"unchanged"`
	Removed   int `json:"removed"`
	// Skipped names a template that could not be placed and why ({module}
	// names wait for a module; a name longer than 64 characters).
	Skipped []string `json:"skipped"`
}

// DeviceTypeSourceRef is the source_ref a template-declared interface carries:
// it is how a later change of device type recognises the rows the previous
// type declared.
func DeviceTypeSourceRef(deviceType uuid.UUID) string { return "device-type:" + deviceType.String() }

// InstantiateInterfaceTemplatesTx applies a device type's interface templates
// to an asset INSIDE the caller's tenant transaction (the catalogue service's
// ApplyDeviceType), recording each change through the interface recorder.
//
// The merge rule, by canonical name (shared/dcim/ifnames with the
// manufacturer as vendor hint — a measured `GigabitEthernet1/0/1` and a
// template `GigabitEthernet1/0/1` are ONE row):
//
//   - No interface of that name: one is created, source_kind `declared`,
//     source_ref DeviceTypeSourceRef(deviceType), status `active`.
//   - An interface of that name exists (measured or declared): it is never
//     duplicated, and its measured fields — MAC addresses, speed, duplex, MTU,
//     operational/admin status — and the person-declared `enabled` and
//     `description` are never touched. The template fills `type` where the
//     row says `other`, and `label`, `poe_mode`, `poe_type` where the row has
//     none. A row the previous device type declared is re-attributed to this
//     one.
//
// Re-applying the same type is therefore idempotent (nothing to create, nothing
// to fill). Changing to another type is ADDITIVE, with one removal rule:
// an interface is deleted only when ALL hold — it was declared from a template
// (source_kind `declared`, source_ref `device-type:<a different type>`), the
// new type has no template of that name, no collector has ever reported it
// (observation_count = 0), and nothing hangs off it (no MAC address rows, no
// IP address assigned, no cable, not marked connected, no member, child or
// bridged interface). Anything measured, or carrying data, stays.
func (s *InterfaceService) InstantiateInterfaceTemplatesTx(ctx context.Context, tx *sql.Tx, tenant, asset, deviceType uuid.UUID, vendor string, tpls []InterfaceTemplateSpec) (InstantiateInterfacesResult, error) {
	res := InstantiateInterfacesResult{Skipped: []string{}}
	ref := DeviceTypeSourceRef(deviceType)

	existing := map[string]Interface{}
	rows, err := tx.QueryContext(ctx, "SELECT "+interfaceColumns+
		" FROM interfaces i WHERE i.tenant_id = $1 AND i.asset_id = $2 AND i.status <> 'rejected'", tenant, asset)
	if err != nil {
		return res, err
	}
	for rows.Next() {
		i, err := ifaceScanInterface(rows)
		if err != nil {
			_ = rows.Close()
			return res, err
		}
		existing[i.Name] = i
	}
	_ = rows.Close()

	wanted := map[string]bool{}
	byName := map[string]uuid.UUID{}
	for name, i := range existing {
		byName[name] = i.ID
	}
	var bridges [][2]string // (interface name, bridge template name)
	for _, t := range tpls {
		if strings.Contains(t.Name, "{module}") {
			res.Skipped = append(res.Skipped, t.Name+": placed when a module is installed")
			continue
		}
		name, _ := ifnames.Canonical(vendor, t.Name)
		if name == "" {
			continue
		}
		if len(name) > 64 {
			res.Skipped = append(res.Skipped, name+": name longer than 64 characters")
			continue
		}
		if wanted[name] {
			continue
		}
		wanted[name] = true
		typ := t.Type
		if _, ok := dcim.ParseInterfaceType(typ); !ok {
			typ = "other"
		}
		if t.Bridge != "" {
			bridges = append(bridges, [2]string{name, t.Bridge})
		}
		if cur, ok := existing[name]; ok {
			changed, err := ifaceFillFromTemplate(ctx, tx, tenant, cur, typ, t, ref)
			if err != nil {
				return res, err
			}
			if !changed {
				res.Unchanged++
				continue
			}
			after, err := ifaceGetInterfaceTx(ctx, tx, tenant, cur.ID)
			if err != nil {
				return res, err
			}
			if err := s.record(ctx, tx, tenant, changes.ActionUpdate, cur.ID, cur, after, ""); err != nil {
				return res, err
			}
			res.Updated++
			continue
		}
		id := uuid.New()
		rfRole := t.RFRole
		if !strings.HasPrefix(typ, "ieee802.11") {
			rfRole = ""
		}
		poeMode, poeType := t.PoEMode, t.PoEType
		if _, ok := dcim.ParsePoEMode(poeMode); !ok {
			poeMode = ""
		}
		if _, ok := dcim.ParsePoEType(poeType); !ok {
			poeType = ""
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO interfaces (id, tenant_id, asset_id, name, label, type, enabled, mgmt_only,
				poe_mode, poe_type, rf_role, description, source_kind, source_ref, status)
			VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'declared',$13,'active')`,
			id, tenant, asset, name, ifaceEmptyNil(t.Label), typ, t.Enabled, t.MgmtOnly,
			ifaceEmptyNil(poeMode), ifaceEmptyNil(poeType), ifaceEmptyNil(rfRole), ifaceEmptyNil(t.Description), ref); err != nil {
			return res, err
		}
		after, err := ifaceGetInterfaceTx(ctx, tx, tenant, id)
		if err != nil {
			return res, err
		}
		if err := s.record(ctx, tx, tenant, changes.ActionCreate, id, nil, after, ""); err != nil {
			return res, err
		}
		byName[name] = id
		res.Created++
	}

	// Bridges name another template; set them where the row has none.
	for _, b := range bridges {
		self, okSelf := byName[b[0]]
		bname, _ := ifnames.Canonical(vendor, b[1])
		target, okT := byName[bname]
		if !okSelf || !okT || self == target {
			continue
		}
		if _, err := tx.ExecContext(ctx, `UPDATE interfaces SET bridge_id = $3 WHERE tenant_id = $1 AND id = $2 AND bridge_id IS NULL`,
			tenant, self, target); err != nil {
			return res, err
		}
	}

	// The removal rule (see above): declared by ANOTHER type's template, not in
	// this type, never observed, carrying nothing.
	for name, cur := range existing {
		if wanted[name] || cur.SourceKind != "declared" || cur.SourceRef == nil ||
			!strings.HasPrefix(*cur.SourceRef, "device-type:") || *cur.SourceRef == ref ||
			cur.ObservationCount > 0 || cur.CableID != nil || cur.MarkConnected || len(cur.MACAddresses) > 0 {
			continue
		}
		var busy bool
		if err := tx.QueryRowContext(ctx, `
			SELECT EXISTS (SELECT 1 FROM ip_addresses WHERE tenant_id = $1 AND assigned_kind = 'interface' AND assigned_id = $2)
			    OR EXISTS (SELECT 1 FROM interfaces WHERE tenant_id = $1 AND (lag_id = $2 OR parent_id = $2 OR bridge_id = $2))`,
			tenant, cur.ID).Scan(&busy); err != nil {
			return res, err
		}
		if busy {
			continue
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM interfaces WHERE tenant_id = $1 AND id = $2`, tenant, cur.ID); err != nil {
			return res, err
		}
		if err := s.record(ctx, tx, tenant, changes.ActionDelete, cur.ID, cur, nil, ""); err != nil {
			return res, err
		}
		res.Removed++
	}
	return res, nil
}

// ifaceFillFromTemplate writes what a template may fill on an existing
// interface. The column list IS the guard: MAC, speed, duplex, MTU,
// operational/admin status, enabled and description are not in it.
func ifaceFillFromTemplate(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, cur Interface, typ string, t InterfaceTemplateSpec, ref string) (bool, error) {
	newType := cur.Type
	if cur.Type == "other" && typ != "other" {
		newType = typ
	}
	fill := func(cur *string, v string, ok bool) *string {
		if cur != nil || v == "" || !ok {
			return cur
		}
		return &v
	}
	_, poeModeOK := dcim.ParsePoEMode(t.PoEMode)
	_, poeTypeOK := dcim.ParsePoEType(t.PoEType)
	label := fill(cur.Label, t.Label, true)
	poeMode := fill(cur.PoEMode, t.PoEMode, poeModeOK)
	poeType := fill(cur.PoEType, t.PoEType, poeTypeOK)
	srcRef := cur.SourceRef
	if cur.SourceKind == "declared" && cur.SourceRef != nil && strings.HasPrefix(*cur.SourceRef, "device-type:") && *cur.SourceRef != ref {
		srcRef = &ref
	}
	if newType == cur.Type && ifaceEqStr(label, cur.Label) && ifaceEqStr(poeMode, cur.PoEMode) &&
		ifaceEqStr(poeType, cur.PoEType) && ifaceEqStr(srcRef, cur.SourceRef) {
		return false, nil
	}
	_, err := tx.ExecContext(ctx, `
		UPDATE interfaces SET type = $3, label = $4, poe_mode = $5, poe_type = $6, source_ref = $7, updated_at = now()
		 WHERE tenant_id = $1 AND id = $2`,
		tenant, cur.ID, newType, ifaceNullStr(label), ifaceNullStr(poeMode), ifaceNullStr(poeType), ifaceNullStr(srcRef))
	return err == nil, err
}

// ifaceCustomFieldError maps a custom-field refusal onto the interface
// validation error (400 with field custom_fields).
func ifaceCustomFieldError(err error) error {
	if errors.Is(err, customfields.ErrInvalid) {
		return ifaceInvalid("custom_fields", "%s", customFieldMessage(err))
	}
	return err
}
