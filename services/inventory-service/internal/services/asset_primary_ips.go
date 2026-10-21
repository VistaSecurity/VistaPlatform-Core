package services

// An asset's primary IPv4, primary IPv6 and out-of-band addresses (NetBox
// Device.primary_ip4 / primary_ip6 / oob_ip; DCIM DATA_MODEL §2 and §5).
// PATCH /dcim/assets/{id}/primary-ips writes the three columns, one change
// record per request, and enforces server-side what the UI only offers:
// IPv4 goes to primary_ip4, IPv6 to primary_ip6 (oob_ip takes either), and
// the address must be one this asset holds.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"

	shareddb "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
)

// AssetPrimaryIPs is the three address columns of an asset.
type AssetPrimaryIPs struct {
	AssetID      uuid.UUID  `json:"asset_id"`
	PrimaryIP4ID *uuid.UUID `json:"primary_ip4_id"`
	PrimaryIP6ID *uuid.UUID `json:"primary_ip6_id"`
	OOBIPID      *uuid.UUID `json:"oob_ip_id"`
}

// AssetPrimaryIPsPatch is a partial update: an absent field is left alone,
// JSON null clears it.
type AssetPrimaryIPsPatch map[string]json.RawMessage

// assetPrimaryIPFields maps each writable field to the address family it
// requires (0 = either).
var assetPrimaryIPFields = map[string]int{"primary_ip4_id": 4, "primary_ip6_id": 6, "oob_ip_id": 0}

// AssetPrimaryIPService writes the columns.
type AssetPrimaryIPService struct{ db *sql.DB }

// NewAssetPrimaryIPService returns the service over db.
func NewAssetPrimaryIPService(db *sql.DB) *AssetPrimaryIPService {
	return &AssetPrimaryIPService{db: db}
}

// Update applies patch to the asset.
func (s *AssetPrimaryIPService) Update(ctx context.Context, tenant, asset uuid.UUID, patch AssetPrimaryIPsPatch) (*AssetPrimaryIPs, error) {
	if len(patch) == 0 {
		return nil, ipamInvalid("say at least one of primary_ip4_id, primary_ip6_id, oob_ip_id")
	}
	sets := map[string]any{}
	for k, raw := range patch {
		if _, ok := assetPrimaryIPFields[k]; !ok {
			return nil, ipamInvalid("unknown or read-only field %q", k)
		}
		var v *string
		if err := json.Unmarshal(raw, &v); err != nil {
			return nil, ipamInvalid("%s must be a UUID or null", k)
		}
		if v == nil || strings.TrimSpace(*v) == "" {
			sets[k] = nil
			continue
		}
		id, err := uuid.Parse(strings.TrimSpace(*v))
		if err != nil {
			return nil, ipamInvalid("%s must be a UUID or null", k)
		}
		sets[k] = id.String()
	}
	var out *AssetPrimaryIPs
	err := shareddb.WithTenantTx(ctx, s.db, tenant, func(tx *sql.Tx) error {
		var p4, p6, oob uuid.NullUUID
		err := tx.QueryRowContext(ctx, `SELECT primary_ip4_id, primary_ip6_id, oob_ip_id FROM assets
			WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL FOR UPDATE`, tenant, asset).Scan(&p4, &p6, &oob)
		if errors.Is(err, sql.ErrNoRows) {
			return ErrCatalogueAssetNotFound
		}
		if err != nil {
			return err
		}
		cur := map[string]uuid.NullUUID{"primary_ip4_id": p4, "primary_ip6_id": p6, "oob_ip_id": oob}
		before, after := map[string]any{}, map[string]any{}
		var clauses []string
		args := []any{tenant, asset}
		for _, k := range []string{"primary_ip4_id", "primary_ip6_id", "oob_ip_id"} {
			v, ok := sets[k]
			if !ok {
				continue
			}
			old := any(nil)
			if cur[k].Valid {
				old = cur[k].UUID.String()
			}
			if fmt.Sprint(old) == fmt.Sprint(v) {
				continue
			}
			if v != nil {
				if err := s.checkAddress(ctx, tx, tenant, asset, k, v.(string)); err != nil {
					return err
				}
			}
			args = append(args, v)
			clauses = append(clauses, fmt.Sprintf("%s = $%d::uuid", k, len(args)))
			before[k], after[k] = old, v
		}
		if len(clauses) > 0 {
			if _, err := tx.ExecContext(ctx, `UPDATE assets SET `+strings.Join(clauses, ", ")+`, updated_at = now()
				WHERE tenant_id = $1 AND id = $2`, args...); err != nil {
				return err
			}
			if err := changes.InTx(tx).Record(ctx, changes.Change{
				TenantID: tenant, Kind: dcim.ObjectKindAsset, ID: asset, Action: changes.ActionUpdate,
				Pre: before, Post: after,
			}); err != nil {
				return err
			}
		}
		out = &AssetPrimaryIPs{AssetID: asset}
		for k, dst := range map[string]**uuid.UUID{"primary_ip4_id": &out.PrimaryIP4ID, "primary_ip6_id": &out.PrimaryIP6ID, "oob_ip_id": &out.OOBIPID} {
			val := cur[k]
			if v, ok := after[k]; ok {
				val = uuid.NullUUID{}
				if v != nil {
					val = uuid.NullUUID{UUID: uuid.MustParse(v.(string)), Valid: true}
				}
			}
			if val.Valid {
				u := val.UUID
				*dst = &u
			}
		}
		return nil
	})
	return out, mapIPAMError(err, false)
}

// checkAddress refuses an address of the wrong family, one that does not
// exist for the tenant, or one the asset does not hold (not assigned to one of
// its interfaces, and not already in one of its three columns).
func (s *AssetPrimaryIPService) checkAddress(ctx context.Context, tx *sql.Tx, tenant, asset uuid.UUID, field, addr string) error {
	var fam sql.NullInt64
	var held bool
	err := tx.QueryRowContext(ctx, `
		SELECT family(ip.address),
		       EXISTS (SELECT 1 FROM interfaces i WHERE i.tenant_id = ip.tenant_id AND i.asset_id = $3
		                  AND ip.assigned_kind = 'interface' AND ip.assigned_id = i.id)
		    OR EXISTS (SELECT 1 FROM assets a WHERE a.tenant_id = ip.tenant_id AND a.id = $3
		                  AND (a.primary_ip4_id = ip.id OR a.primary_ip6_id = ip.id OR a.oob_ip_id = ip.id))
		  FROM ip_addresses ip
		 WHERE ip.tenant_id = $1 AND ip.id = $2::uuid AND ip.status <> 'rejected'`, tenant, addr, asset).Scan(&fam, &held)
	if errors.Is(err, sql.ErrNoRows) {
		return ipamInvalid("no such IP address %s", addr)
	}
	if err != nil {
		return err
	}
	if want := assetPrimaryIPFields[field]; want != 0 && int(fam.Int64) != want {
		return ipamInvalid("%s takes an IPv%d address", field, want)
	}
	if !held {
		return ipamInvalid("the address is not held by this asset (assign it to one of the asset's interfaces first)")
	}
	return nil
}
