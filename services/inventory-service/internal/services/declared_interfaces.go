package services

// Declared interfaces: the source's own ids on the rows the engine wrote
// (DCIM row 1.5f).
//
// A declaration's interfaces travel on its observation (declaredInterfaces,
// intake_adapters.go) and the identity engine writes the `interfaces` and
// `ip_addresses` rows, as it does for every adapter. What the engine cannot
// carry is the SOURCE's id for each one — NetBox's interface and IP address
// ids — which the bidirectional sync (row 1.9) matches on first
// (`external_ids.netbox`). This stamps them, on the same transaction as the
// resolution, and records each stamp in `object_changes`.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"github.com/google/uuid"

	"github.com/vistasecurity/vistaplatform/inventory-service/internal/models"
	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
	"github.com/vistasecurity/vistaplatform/shared/identity"
)

// stampDeclaredExternalIDs merges each declared interface's and address's
// ExternalIDs into the `external_ids` of the row the engine holds for it on
// this asset: the interface by its canonical name, the address by its host on
// that interface. A row the engine did not write (an unnamed interface, an
// address in a VRF the tenant does not have) is skipped — there is nothing to
// stamp. Only the keys the declaration states are written; another peer's ids
// are left alone.
func stampDeclaredExternalIDs(ctx context.Context, tx changes.Tx, tenantID, assetID uuid.UUID, ifaces []models.AssetInterfaceInput) error {
	for _, in := range ifaces {
		name := identity.CanonicalInterfaceName(in.Name)
		if name == "" {
			continue
		}
		var ifaceID uuid.UUID
		err := tx.QueryRowContext(ctx, `
			SELECT id FROM public.interfaces
			 WHERE tenant_id = $1 AND asset_id = $2 AND name = $3 AND status <> 'rejected'`,
			tenantID, assetID, name).Scan(&ifaceID)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return fmt.Errorf("read declared interface %q: %w", name, err)
		}
		if err := stampExternalIDs(ctx, tx, tenantID, dcim.ObjectKindInterface, ifaceID, in.ExternalIDs); err != nil {
			return fmt.Errorf("stamp interface %q: %w", name, err)
		}
		for _, a := range in.Addresses {
			if len(a.ExternalIDs) == 0 {
				continue
			}
			host := strings.TrimSpace(a.Address)
			if p, err := netip.ParsePrefix(host); err == nil {
				host = p.Addr().String()
			}
			addr, err := netip.ParseAddr(host)
			if err != nil {
				continue
			}
			var addrID uuid.UUID
			err = tx.QueryRowContext(ctx, `
				SELECT id FROM public.ip_addresses
				 WHERE tenant_id = $1 AND assigned_kind = 'interface' AND assigned_id = $2
				   AND host = $3::inet AND status <> 'rejected'
				 ORDER BY created_at LIMIT 1`,
				tenantID, ifaceID, addr.Unmap().WithZone("").String()).Scan(&addrID)
			if errors.Is(err, sql.ErrNoRows) {
				continue
			}
			if err != nil {
				return fmt.Errorf("read declared address %s on %q: %w", host, name, err)
			}
			if err := stampExternalIDs(ctx, tx, tenantID, dcim.ObjectKindIpAddress, addrID, a.ExternalIDs); err != nil {
				return fmt.Errorf("stamp address %s on %q: %w", host, name, err)
			}
		}
	}
	return nil
}

// stampExternalIDs merges ids into one row's external_ids when they are not
// already there, and records the change.
func stampExternalIDs(ctx context.Context, tx changes.Tx, tenantID uuid.UUID, kind dcim.ObjectKind, id uuid.UUID, ids map[string]string) error {
	clean := map[string]string{}
	for k, v := range ids {
		if k, v = strings.TrimSpace(k), strings.TrimSpace(v); k != "" && v != "" {
			clean[k] = v
		}
	}
	if len(clean) == 0 {
		return nil
	}
	want, err := json.Marshal(clean)
	if err != nil {
		return err
	}
	table := kind.Table()
	var pre, post []byte
	err = tx.QueryRowContext(ctx, `
		WITH prior AS (SELECT external_ids FROM public.`+table+` WHERE tenant_id = $1 AND id = $2 FOR UPDATE)
		UPDATE public.`+table+` t SET external_ids = t.external_ids || $3::jsonb, updated_at = now()
		  FROM prior
		 WHERE t.tenant_id = $1 AND t.id = $2 AND NOT (t.external_ids @> $3::jsonb)
		RETURNING prior.external_ids, t.external_ids`, tenantID, id, string(want)).Scan(&pre, &post)
	if errors.Is(err, sql.ErrNoRows) {
		return nil // already stamped
	}
	if err != nil {
		return err
	}
	var preIDs, postIDs map[string]any
	_ = json.Unmarshal(pre, &preIDs)
	_ = json.Unmarshal(post, &postIDs)
	return changes.InTx(tx).Record(ctx, changes.Change{
		TenantID: tenantID, Kind: kind, ID: id, Action: changes.ActionUpdate,
		Pre: map[string]any{"external_ids": preIDs}, Post: map[string]any{"external_ids": postIDs},
		Source: changes.IntakeSource("identity"),
	})
}
