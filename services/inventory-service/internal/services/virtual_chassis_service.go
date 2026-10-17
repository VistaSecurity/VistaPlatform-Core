package services

// Virtual chassis (DCIM BUILD_PLAN row 2.4; ADR-0010 D4; NetBox
// dcim/virtual-chassis): a switch stack, VSS or VPC pair managed as one.
// Members are assets carrying virtual_chassis_id, vc_position (unique within
// the chassis, 0-255) and vc_priority (0-255). The master is a member.
//
// The virtual_chassis row is CRUD on the object engine (hardware_specs.go);
// membership is written here, on the asset, with an asset change recorded for
// every member added or released.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"

	shareddb "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
)

// VirtualChassisMember is one member as the panel lists it.
type VirtualChassisMember struct {
	AssetID     uuid.UUID `json:"asset_id"`
	DisplayName string    `json:"display_name"`
	Serial      *string   `json:"serial"`
	VCPosition  *int      `json:"vc_position"`
	VCPriority  *int      `json:"vc_priority"`
	IsMaster    bool      `json:"is_master"`
}

// AssetVirtualChassis is an asset's chassis and its members; Chassis is nil
// when the asset is in none.
type AssetVirtualChassis struct {
	Chassis map[string]any         `json:"virtual_chassis"`
	Members []VirtualChassisMember `json:"members"`
}

// VirtualChassisMemberInput adds an asset to a chassis.
type VirtualChassisMemberInput struct {
	AssetID    uuid.UUID `json:"asset_id"`
	VCPosition *int      `json:"vc_position"`
	VCPriority *int      `json:"vc_priority"`
}

func prepareVirtualChassis(ctx context.Context, tx *sql.Tx, tenant, id uuid.UUID, row map[string]any) error {
	if n, ok := row["name"].(string); ok {
		row["name"] = strings.TrimSpace(n)
	}
	if d, ok := row["domain"].(string); ok && strings.TrimSpace(d) == "" {
		row["domain"] = nil
	}
	if isEmpty(row["master_asset_id"]) {
		row["master_asset_id"] = nil
		return nil
	}
	var vc uuid.NullUUID
	err := tx.QueryRowContext(ctx, `SELECT virtual_chassis_id FROM assets WHERE tenant_id = $1 AND id = $2::uuid AND deleted_at IS NULL`,
		tenant, fmt.Sprint(row["master_asset_id"])).Scan(&vc)
	if errors.Is(err, sql.ErrNoRows) {
		return ipamInvalid("no such asset %v", row["master_asset_id"])
	}
	if err != nil {
		return mapIPAMError(err, false)
	}
	switch {
	case !vc.Valid && id == uuid.Nil:
		return nil // a new chassis takes its master as its first member (AfterWrite)
	case vc.Valid && vc.UUID == id:
		return nil
	case vc.Valid:
		return ipamInvalid("asset %v is a member of another virtual chassis", row["master_asset_id"])
	default:
		return ipamInvalid("the master must be a member of the virtual chassis; add asset %v as a member first", row["master_asset_id"])
	}
}

// afterVirtualChassisWrite: a chassis created with a master makes the master
// its member at position 1 (NetBox's create form) when it is in no chassis.
func afterVirtualChassisWrite(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, pre, post map[string]any) error {
	if pre != nil || post == nil || post["master_asset_id"] == nil {
		return nil
	}
	vc := uuid.MustParse(fmt.Sprint(post["id"]))
	asset := uuid.MustParse(fmt.Sprint(post["master_asset_id"]))
	one := 1
	return setMembership(ctx, tx, tenant, asset, &vc, &one, nil)
}

// beforeVirtualChassisDelete releases every member.
func beforeVirtualChassisDelete(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, pre map[string]any) error {
	vc := fmt.Sprint(pre["id"])
	rows, err := tx.QueryContext(ctx, `SELECT id FROM assets WHERE tenant_id = $1 AND virtual_chassis_id = $2::uuid`, tenant, vc)
	if err != nil {
		return err
	}
	var members []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			_ = rows.Close()
			return err
		}
		members = append(members, id)
	}
	_ = rows.Close()
	for _, m := range members {
		if err := setMembership(ctx, tx, tenant, m, nil, nil, nil); err != nil {
			return err
		}
	}
	return nil
}

// setMembership writes an asset's three chassis columns and records the
// change (nil chassis releases it).
func setMembership(ctx context.Context, tx *sql.Tx, tenant, asset uuid.UUID, vc *uuid.UUID, position, priority *int) error {
	var (
		preVC          uuid.NullUUID
		prePos, prePri sql.NullInt64
	)
	err := tx.QueryRowContext(ctx, `SELECT virtual_chassis_id, vc_position, vc_priority FROM assets WHERE tenant_id = $1 AND id = $2 FOR UPDATE`,
		tenant, asset).Scan(&preVC, &prePos, &prePri)
	if errors.Is(err, sql.ErrNoRows) {
		return ipamInvalid("no such asset %s", asset)
	}
	if err != nil {
		return err
	}
	if vc == nil {
		position, priority = nil, nil
	}
	if position != nil && (*position < 0 || *position > 255) {
		return ipamInvalid("vc_position must be between 0 and 255")
	}
	if priority != nil && (*priority < 0 || *priority > 255) {
		return ipamInvalid("vc_priority must be between 0 and 255")
	}
	ptr := func(p *int) any {
		if p == nil {
			return nil
		}
		return *p
	}
	var vcv any
	if vc != nil {
		vcv = *vc
	}
	if _, err := tx.ExecContext(ctx, `UPDATE assets SET virtual_chassis_id = $3, vc_position = $4, vc_priority = $5, updated_at = now()
		WHERE tenant_id = $1 AND id = $2`, tenant, asset, vcv, ptr(position), ptr(priority)); err != nil {
		return err
	}
	if vc == nil && preVC.Valid {
		// A released master leaves its chassis without one.
		if _, err := tx.ExecContext(ctx, `UPDATE virtual_chassis SET master_asset_id = NULL, updated_at = now()
			WHERE tenant_id = $1 AND id = $2 AND master_asset_id = $3`, tenant, preVC.UUID, asset); err != nil {
			return err
		}
	}
	nullInt := func(n sql.NullInt64) any {
		if !n.Valid {
			return nil
		}
		return n.Int64
	}
	var preVCv any
	if preVC.Valid {
		preVCv = preVC.UUID.String()
	}
	var postVCv any
	if vc != nil {
		postVCv = vc.String()
	}
	return changes.InTx(tx).Record(ctx, changes.Change{
		TenantID: tenant, Kind: dcim.ObjectKindAsset, ID: asset, Action: changes.ActionUpdate,
		Pre:  map[string]any{"virtual_chassis_id": preVCv, "vc_position": nullInt(prePos), "vc_priority": nullInt(prePri)},
		Post: map[string]any{"virtual_chassis_id": postVCv, "vc_position": ptr(position), "vc_priority": ptr(priority)},
	})
}

func (s *HardwareService) chassisExists(ctx context.Context, tx *sql.Tx, tenant, vc uuid.UUID) error {
	var ok bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM virtual_chassis WHERE tenant_id = $1 AND id = $2)`, tenant, vc).Scan(&ok); err != nil {
		return err
	}
	if !ok {
		return ErrIPAMNotFound
	}
	return nil
}

// AddVirtualChassisMember makes an asset a member of a chassis. An asset in
// another chassis is refused (release it there first); a taken position is a
// conflict.
func (s *HardwareService) AddVirtualChassisMember(ctx context.Context, tenant, vc uuid.UUID, in VirtualChassisMemberInput) ([]VirtualChassisMember, error) {
	var out []VirtualChassisMember
	err := shareddb.WithTenantTx(ctx, s.db, tenant, func(tx *sql.Tx) error {
		if err := s.chassisExists(ctx, tx, tenant, vc); err != nil {
			return err
		}
		var cur uuid.NullUUID
		err := tx.QueryRowContext(ctx, `SELECT virtual_chassis_id FROM assets WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL`,
			tenant, in.AssetID).Scan(&cur)
		if errors.Is(err, sql.ErrNoRows) {
			return ipamInvalid("no such asset %s", in.AssetID)
		}
		if err != nil {
			return err
		}
		if cur.Valid && cur.UUID != vc {
			return ipamInvalid("asset %s is a member of another virtual chassis; remove it there first", in.AssetID)
		}
		if err := setMembership(ctx, tx, tenant, in.AssetID, &vc, in.VCPosition, in.VCPriority); err != nil {
			return err
		}
		out, err = membersTx(ctx, tx, tenant, vc)
		return err
	})
	return out, mapIPAMError(err, false)
}

// RemoveVirtualChassisMember releases an asset from a chassis.
func (s *HardwareService) RemoveVirtualChassisMember(ctx context.Context, tenant, vc, asset uuid.UUID) error {
	err := shareddb.WithTenantTx(ctx, s.db, tenant, func(tx *sql.Tx) error {
		var cur uuid.NullUUID
		err := tx.QueryRowContext(ctx, `SELECT virtual_chassis_id FROM assets WHERE tenant_id = $1 AND id = $2`, tenant, asset).Scan(&cur)
		if errors.Is(err, sql.ErrNoRows) || (err == nil && (!cur.Valid || cur.UUID != vc)) {
			return ErrIPAMNotFound
		}
		if err != nil {
			return err
		}
		return setMembership(ctx, tx, tenant, asset, nil, nil, nil)
	})
	return mapIPAMError(err, false)
}

// VirtualChassisMembers lists a chassis's members by position.
func (s *HardwareService) VirtualChassisMembers(ctx context.Context, tenant, vc uuid.UUID) ([]VirtualChassisMember, error) {
	var out []VirtualChassisMember
	err := shareddb.WithTenantTx(ctx, s.db, tenant, func(tx *sql.Tx) error {
		if err := s.chassisExists(ctx, tx, tenant, vc); err != nil {
			return err
		}
		var err error
		out, err = membersTx(ctx, tx, tenant, vc)
		return err
	})
	return out, mapIPAMError(err, false)
}

// AssetVirtualChassis is the asset page's panel: the asset's chassis and its
// members, or no chassis.
func (s *HardwareService) AssetVirtualChassis(ctx context.Context, tenant, asset uuid.UUID) (*AssetVirtualChassis, error) {
	out := &AssetVirtualChassis{Members: []VirtualChassisMember{}}
	err := shareddb.WithTenantTx(ctx, s.db, tenant, func(tx *sql.Tx) error {
		var vc uuid.NullUUID
		err := tx.QueryRowContext(ctx, `SELECT virtual_chassis_id FROM assets WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL`, tenant, asset).Scan(&vc)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrCatalogueAssetNotFound
		}
		if err != nil || !vc.Valid {
			return err
		}
		sp, err := s.eng.spec(HardwareVirtualChassis)
		if err != nil {
			return err
		}
		if out.Chassis, err = getRow(ctx, tx, sp, vc.UUID, false); err != nil {
			return err
		}
		out.Members, err = membersTx(ctx, tx, tenant, vc.UUID)
		return err
	})
	if err != nil {
		return nil, mapIPAMError(err, false)
	}
	return out, nil
}

func membersTx(ctx context.Context, tx *sql.Tx, tenant, vc uuid.UUID) ([]VirtualChassisMember, error) {
	rows, err := tx.QueryContext(ctx, `
		SELECT a.id, COALESCE(NULLIF(a.display_name, ''), a.hostname, a.id::text), a.serial, a.vc_position, a.vc_priority,
		       COALESCE(v.master_asset_id = a.id, false)
		  FROM assets a JOIN virtual_chassis v ON v.id = a.virtual_chassis_id
		 WHERE a.tenant_id = $1 AND a.virtual_chassis_id = $2 AND a.deleted_at IS NULL
		 ORDER BY a.vc_position NULLS LAST, a.id`, tenant, vc)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	out := []VirtualChassisMember{}
	for rows.Next() {
		var (
			m        VirtualChassisMember
			serial   sql.NullString
			pos, pri sql.NullInt64
		)
		if err := rows.Scan(&m.AssetID, &m.DisplayName, &serial, &pos, &pri, &m.IsMaster); err != nil {
			return nil, err
		}
		m.Serial = ifaceStrPtr(serial)
		if pos.Valid {
			p := int(pos.Int64)
			m.VCPosition = &p
		}
		if pri.Valid {
			p := int(pri.Int64)
			m.VCPriority = &p
		}
		out = append(out, m)
	}
	return out, rows.Err()
}
