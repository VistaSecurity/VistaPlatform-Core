package services

// The inventory side of the NetBox virtual machine sync (owner decision: no
// asset-kind split): the sync kinds `virtual_machine` (an asset of the
// virtual_machine class) and `vm_interface` (an interface on such an asset),
// standards/sync-authority.yaml's `object:` kinds. Virtual disks are an engine
// kind already (virtualizationSpecs) and need nothing here.
//
// NetBox keeps devices and VMs — and device interfaces and VM interfaces — in
// separate id spaces, so each sync kind keeps its peer id under its own key:
//
//   - a VM's NetBox id is the asset's metadata `netbox_vm_id`, beside the
//     import's `netbox_device_id` (an asset carries one or the other: one the
//     import resolved from a NetBox device is that device's, whatever its
//     class, and is never listed as a VM);
//   - a VM interface's is external_ids `<peer>:vm_interface`, beside a device
//     interface's external_ids `<peer>`.
//
// What is written goes through the services that own the columns, exactly as
// a person's edit: a VM's cluster and resources through the virtualization
// service's rules, its role, platform and serial through the catalogue's, its
// site through the asset placement rules; a VM interface through the
// interface service. A VM is never CREATED here: the connector brings it in
// through the identity engine (intake, admission, the approval policy) and the
// create adopts the asset that engine answered.

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
	"github.com/jmoiron/sqlx"
	"github.com/lib/pq"

	shareddb "github.com/vistasecurity/vistaplatform/shared/database"
	"github.com/vistasecurity/vistaplatform/shared/dcim"
	"github.com/vistasecurity/vistaplatform/shared/dcim/changes"
	"github.com/vistasecurity/vistaplatform/shared/syncauthority"
)

// The sync kinds (not vocabulary object kinds; see the file comment).
const (
	syncKindVirtualMachine dcim.ObjectKind = "virtual_machine"
	syncKindVMInterface    dcim.ObjectKind = "vm_interface"
)

// vmSideAsset is the SQL predicate (over alias `a`) of an asset the VM kinds
// sync: a virtual_machine-class asset the NetBox import did not resolve from a
// NetBox DEVICE (that one is synced as the device it is).
const vmSideAsset = `(a.class_path = 'virtual.virtual_machine' OR a.class_path LIKE 'virtual.virtual_machine.%')
	AND NOT a.metadata ? 'netbox_device_id'`

// vmPeerKey is the asset metadata key a VM's NetBox id lives under.
const vmPeerKey = "netbox_vm_id"

// syncPeerKey is the key a kind's peer id lives under in external_ids.
func syncPeerKey(peer string, kind dcim.ObjectKind) string {
	if kind == syncKindVMInterface {
		return peer + ":" + string(kind)
	}
	return peer
}

// syncStored is the object kind a synced kind's rows are (the sync kinds'
// object; every other kind itself): what object_changes names.
func syncStored(kind dcim.ObjectKind) dcim.ObjectKind {
	if k, ok := syncauthority.Kind(kind); ok {
		return k.Stored()
	}
	return kind
}

// syncTableOf is the table of a synced kind, a sync kind's object's included.
func syncTableOf(kind dcim.ObjectKind) string { return syncStored(kind).Table() }

// isVMSyncKind reports the two sync kinds this file answers.
func isVMSyncKind(kind dcim.ObjectKind) bool {
	return kind == syncKindVirtualMachine || kind == syncKindVMInterface
}

// ---------------------------------------------------------------------------
// List
// ---------------------------------------------------------------------------

// vmSyncColumns are a VM's synced columns (sync-authority.yaml kind
// virtual_machine: identity and fields), read in their API shape, plus its
// approval state (a pending VM is never pushed).
var vmSyncColumns = []string{
	"cluster_id", "display_name", "site_id", "device_role_id", "platform_id", "serial", "vcpus", "memory_mb", "disk_mb",
	"asset_status",
}

func (s *DCIMSyncService) listVM(ctx context.Context, tenant uuid.UUID, kind dcim.ObjectKind, after uuid.UUID, limit int) ([]SyncObject, bool, bool, error) {
	if !isVMSyncKind(kind) {
		return nil, false, false, nil
	}
	if limit <= 0 || limit > 1000 {
		limit = 500
	}
	var q string
	if kind == syncKindVirtualMachine {
		pairs := []string{pq.QuoteLiteral("id"), "a.id"}
		for _, c := range vmSyncColumns {
			pairs = append(pairs, pq.QuoteLiteral(c), "a."+pq.QuoteIdentifier(c))
		}
		// The asset a NetBox VM id names is the oldest live one carrying it
		// (PeerAssets' rule for devices), so a duplicate never syncs twice.
		q = fmt.Sprintf(`
			SELECT a.id, jsonb_build_object(%s) || jsonb_build_object('external_ids',
			         CASE WHEN a.metadata ? %[2]s THEN jsonb_build_object('netbox', a.metadata ->> %[2]s) ELSE '{}'::jsonb END),
			       a.updated_at, CASE WHEN a.import_only_sources IS NULL THEN a.last_seen_at END
			  FROM public.assets a
			 WHERE a.tenant_id = $1 AND a.deleted_at IS NULL AND a.id > $2 AND %[3]s
			   AND (NOT a.metadata ? %[2]s OR a.id = (SELECT b.id FROM public.assets b WHERE b.tenant_id = a.tenant_id
			         AND b.deleted_at IS NULL AND b.metadata ->> %[2]s = a.metadata ->> %[2]s ORDER BY b.created_at, b.id LIMIT 1))
			 ORDER BY a.id LIMIT $3`, strings.Join(pairs, ", "), pq.QuoteLiteral(vmPeerKey), vmSideAsset)
	} else {
		key := pq.QuoteLiteral(syncPeerKey("netbox", syncKindVMInterface))
		// The interface row with its peer id moved to the key the connector
		// reads (external_ids.netbox): a device interface's netbox id is never
		// shown as a VM interface's.
		q = fmt.Sprintf(`
			SELECT t.id, (to_jsonb(t) - 'external_ids') || jsonb_build_object('external_ids',
			         CASE WHEN t.external_ids ? %[1]s THEN jsonb_build_object('netbox', t.external_ids ->> %[1]s) ELSE '{}'::jsonb END),
			       t.updated_at, NULL::timestamptz
			  FROM public.interfaces t JOIN public.assets a ON a.tenant_id = t.tenant_id AND a.id = t.asset_id
			 WHERE t.tenant_id = $1 AND t.id > $2 AND t.status <> 'rejected' AND a.deleted_at IS NULL AND %[2]s
			 ORDER BY t.id LIMIT $3`, key, vmSideAsset)
	}
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
			// An interface's observation window is its own row's
			// (syncObjectOf); a VM's is the asset's last sighting by anything
			// but an import (the device rule, listDCIM).
			obj, err := syncObjectOf(nil, kind, raw)
			if err != nil {
				return err
			}
			obj.UpdatedAt = updated
			if kind == syncKindVirtualMachine && observed.Valid {
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
// Changes: deletes
// ---------------------------------------------------------------------------

// vmDeleted lists the VMs deleted here since a time that carried a NetBox id
// (the "deleted here" candidates). An asset's delete records no change row,
// so they are read from the assets themselves.
func vmDeleted(ctx context.Context, tx *sql.Tx, tenant uuid.UUID, since time.Time) ([]SyncDeleted, error) {
	rows, err := tx.QueryContext(ctx, fmt.Sprintf(`
		SELECT a.id, a.metadata ->> %[1]s, COALESCE(a.display_name, a.hostname, a.id::text), a.deleted_at
		  FROM public.assets a
		 WHERE a.tenant_id = $1 AND a.deleted_at > $2 AND a.metadata ? %[1]s AND %[2]s`,
		pq.QuoteLiteral(vmPeerKey), vmSideAsset), tenant, since)
	if err != nil {
		return nil, err
	}
	defer func() { _ = rows.Close() }()
	var out []SyncDeleted
	for rows.Next() {
		var d SyncDeleted
		if err := rows.Scan(&d.ObjectID, &d.PeerID, &d.Label, &d.DeletedAt); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------------------
// Write
// ---------------------------------------------------------------------------

// createVMKind answers a create of a VM kind; handled is false for any other.
// A VM create ADOPTS the asset the identity engine resolved (it.ID): it is
// refused without one, and refused when that asset is not a VM this sync may
// own (a NetBox device's asset, another NetBox VM's).
func (s *DCIMSyncService) createVMKind(ctx context.Context, tenant uuid.UUID, peer string, kind dcim.ObjectKind, it SyncWrite) (uuid.UUID, bool, error) {
	switch kind {
	case syncKindVirtualMachine:
		if peer != "netbox" {
			return uuid.Nil, true, fmt.Errorf("%w: no virtual machine mapping for peer %q", ErrSyncInvalid, peer)
		}
		if it.ID == uuid.Nil {
			return uuid.Nil, true, fmt.Errorf("%w: a virtual machine is brought in by the identity engine; the create names the asset it resolved (id)", ErrSyncInvalid)
		}
		if err := s.claimVM(ctx, tenant, it.ID, it.PeerID); err != nil {
			return uuid.Nil, true, err
		}
		return it.ID, true, s.writeVM(ctx, tenant, it.ID, it.Values)
	case syncKindVMInterface:
		var in InterfaceInput
		values := map[string]any{}
		for k, v := range it.Values {
			values[k] = v
		}
		if _, ok := values["type"]; !ok {
			values["type"] = "virtual" // NetBox's VM interfaces are virtual; NetBox carries no type
		}
		if err := remarshal(values, &in); err != nil {
			return uuid.Nil, true, err
		}
		if err := s.requireVMSide(ctx, tenant, in.AssetID); err != nil {
			return uuid.Nil, true, err
		}
		got, err := s.interfaces.Create(ctx, tenant, uuid.Nil, in)
		if err != nil {
			return uuid.Nil, true, err
		}
		sourceRef := peer + ":" + it.PeerID
		return got.ID, true, s.stampInterface(ctx, tenant, got.ID, syncPeerKey(peer, kind), it.PeerID, &sourceRef)
	}
	return uuid.Nil, false, nil
}

// updateVMKind answers an update of a VM kind; handled is false for any other.
func (s *DCIMSyncService) updateVMKind(ctx context.Context, tenant uuid.UUID, peer string, kind dcim.ObjectKind, it SyncWrite) (bool, error) {
	switch kind {
	case syncKindVirtualMachine:
		if peer != "netbox" {
			return true, fmt.Errorf("%w: no virtual machine mapping for peer %q", ErrSyncInvalid, peer)
		}
		if err := s.writeVM(ctx, tenant, it.ID, it.Values); err != nil {
			return true, err
		}
		if it.Unlink {
			return true, s.setVMPeer(ctx, tenant, it.ID, "")
		}
		if it.PeerID != "" {
			return true, s.claimVM(ctx, tenant, it.ID, it.PeerID)
		}
		return true, nil
	case syncKindVMInterface:
		if len(it.Values) > 0 {
			patch := map[string]json.RawMessage{}
			for k, v := range it.Values {
				b, err := json.Marshal(v)
				if err != nil {
					return true, err
				}
				patch[k] = b
			}
			if _, err := s.interfaces.Patch(ctx, tenant, it.ID, patch); err != nil {
				return true, err
			}
		}
		key := syncPeerKey(peer, kind)
		if it.Unlink {
			return true, s.unlinkInterface(ctx, tenant, it.ID, key)
		}
		return true, s.stampInterface(ctx, tenant, it.ID, key, it.PeerID, nil)
	}
	return false, nil
}

// deleteVMKind answers a delete of a VM kind (a person accepted the "deleted
// in NetBox" proposal); handled is false for any other.
func (s *DCIMSyncService) deleteVMKind(ctx context.Context, tenant uuid.UUID, kind dcim.ObjectKind, id uuid.UUID) (bool, error) {
	switch kind {
	case syncKindVirtualMachine:
		if s.objs == nil || s.objs.sx == nil {
			return true, fmt.Errorf("%w: virtual_machine has no writer", ErrSyncInvalid)
		}
		// The asset delete's own path (a soft delete under the asset lifecycle
		// locks), recorded as the sync's change.
		return true, withAssetLifecycleWriteTx(ctx, s.objs.sx, tenant, []uuid.UUID{id}, func(tx *sqlx.Tx) error {
			var name sql.NullString
			var peerID sql.NullString
			err := tx.QueryRowContext(ctx, fmt.Sprintf(`SELECT COALESCE(a.display_name, a.hostname), a.metadata ->> %s FROM assets a
				WHERE a.tenant_id = $1 AND a.id = $2 AND a.deleted_at IS NULL AND %s`, pq.QuoteLiteral(vmPeerKey), vmSideAsset),
				tenant, id).Scan(&name, &peerID)
			if errors.Is(err, sql.ErrNoRows) {
				return ErrSyncNotFound
			}
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `UPDATE assets SET deleted_at = now() WHERE tenant_id = $1 AND id = $2 AND deleted_at IS NULL`, tenant, id); err != nil {
				return err
			}
			return changes.InTx(tx.Tx).Record(ctx, changes.Change{
				TenantID: tenant, Kind: dcim.ObjectKindAsset, ID: id, Action: changes.ActionDelete,
				Pre: map[string]any{"display_name": name.String, vmPeerKey: peerID.String},
			})
		})
	case syncKindVMInterface:
		return true, s.interfaces.Delete(ctx, tenant, id)
	}
	return false, nil
}

// requireVMSide refuses an asset the VM kinds do not sync (a device, a cloud
// instance, a NetBox device classed as a VM here).
func (s *DCIMSyncService) requireVMSide(ctx context.Context, tenant, asset uuid.UUID) error {
	return shareddb.WithTenantTx(ctx, s.raw, tenant, func(tx *sql.Tx) error {
		var ok bool
		err := tx.QueryRowContext(ctx, `SELECT `+vmSideAsset+` FROM public.assets a WHERE a.tenant_id = $1 AND a.id = $2 AND a.deleted_at IS NULL`,
			tenant, asset).Scan(&ok)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: no such asset %s", ErrSyncNotFound, asset)
		}
		if err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("%w: asset %s is not a virtual machine this sync owns (a NetBox device's asset, or not of the virtual_machine class)", ErrSyncInvalid, asset)
		}
		return nil
	})
}

// claimVM records the NetBox VM id on the asset, refusing an asset that is not
// VM-side or already carries ANOTHER NetBox VM's id (two NetBox VMs resolved
// to one asset: a person merges or splits them, the sync does not choose).
func (s *DCIMSyncService) claimVM(ctx context.Context, tenant, asset uuid.UUID, peerID string) error {
	if err := s.requireVMSide(ctx, tenant, asset); err != nil {
		return err
	}
	if peerID == "" {
		return nil
	}
	if _, err := strconv.Atoi(peerID); err != nil {
		return fmt.Errorf("%w: a NetBox id is a number (%q)", ErrSyncInvalid, peerID)
	}
	return shareddb.WithTenantTx(ctx, s.raw, tenant, func(tx *sql.Tx) error {
		var cur sql.NullString
		if err := tx.QueryRowContext(ctx, `SELECT metadata ->> $3 FROM public.assets WHERE tenant_id = $1 AND id = $2 FOR UPDATE`,
			tenant, asset, vmPeerKey).Scan(&cur); err != nil {
			return err
		}
		if cur.Valid && cur.String != peerID {
			return fmt.Errorf("%w: asset %s is already NetBox virtual machine %s; two NetBox virtual machines resolved to one asset — merge or split them in the inventory", ErrSyncInvalid, asset, cur.String)
		}
		if cur.Valid {
			return nil
		}
		_, err := tx.ExecContext(ctx, `UPDATE public.assets SET metadata = jsonb_set(metadata, ARRAY[$3::text], to_jsonb($4::bigint)), updated_at = now()
			WHERE tenant_id = $1 AND id = $2`, tenant, asset, vmPeerKey, peerID)
		return err
	})
}

// setVMPeer removes (peerID "") the NetBox VM id from an asset: a "deleted in
// NetBox" proposal a person answered keep_ours.
func (s *DCIMSyncService) setVMPeer(ctx context.Context, tenant, asset uuid.UUID, peerID string) error {
	if peerID != "" {
		return s.claimVM(ctx, tenant, asset, peerID)
	}
	return shareddb.WithTenantTx(ctx, s.raw, tenant, func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `UPDATE public.assets SET metadata = metadata - $3::text, updated_at = now() WHERE tenant_id = $1 AND id = $2`,
			tenant, asset, vmPeerKey)
		return err
	})
}

// writeVM applies a sync's write to a VM's synced columns, each group through
// the service that owns it: the cluster and resources (the virtualization
// service: the class and cluster checks), the role, platform and serial (the
// catalogue service), the site (the asset placement rules).
func (s *DCIMSyncService) writeVM(ctx context.Context, tenant, asset uuid.UUID, values map[string]any) error {
	o := s.objs
	if o == nil || o.catalogue == nil || o.raw == nil {
		return fmt.Errorf("%w: virtual_machine has no writer", ErrSyncInvalid)
	}
	vm := VirtualizationPatch{}
	for _, k := range vmColumns {
		if v, ok := values[k]; ok {
			b, err := json.Marshal(v)
			if err != nil {
				return err
			}
			vm[k] = b
		}
	}
	if len(vm) > 0 {
		if _, err := NewVirtualizationService(o.raw).UpdateAssetVirtualization(ctx, tenant, asset, vm); err != nil {
			return mapVMSyncError(err)
		}
	}
	hw := HardwarePatch{}
	for _, k := range []string{"device_role_id", "platform_id", "serial"} {
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
			return mapVMSyncError(err)
		}
	}
	if v, ok := values["site_id"]; ok && o.sx != nil {
		ref := ""
		if s := stringOrNil(v); s != nil {
			ref = *s
		}
		if err := o.setAssetSite(ctx, tenant, asset, &ref, nil); err != nil {
			return err
		}
	}
	return nil
}

// mapVMSyncError maps the virtualization and catalogue services' errors onto
// the sync's.
func mapVMSyncError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, ErrVirtualizationAssetNotFound), errors.Is(err, ErrCatalogueAssetNotFound):
		return fmt.Errorf("%w: %v", ErrSyncNotFound, err)
	}
	return err
}

// vmMatch answers the sync-key matcher for the VM kinds: the object carrying
// the peer id under the kind's own key.
func vmMatch(ctx context.Context, raw *sql.DB, tenant uuid.UUID, peer string, kind dcim.ObjectKind, value string) (uuid.UUID, bool, error) {
	var q string
	switch kind {
	case syncKindVirtualMachine:
		if peer != "netbox" {
			return uuid.Nil, false, nil
		}
		q = fmt.Sprintf(`SELECT a.id FROM public.assets a WHERE a.tenant_id = $1 AND a.deleted_at IS NULL AND a.metadata ->> %s = $2
			AND %s ORDER BY a.created_at, a.id LIMIT 1`, pq.QuoteLiteral(vmPeerKey), vmSideAsset)
	case syncKindVMInterface:
		q = fmt.Sprintf(`SELECT t.id FROM public.interfaces t JOIN public.assets a ON a.tenant_id = t.tenant_id AND a.id = t.asset_id
			WHERE t.tenant_id = $1 AND t.external_ids ->> %s = $2 AND %s ORDER BY t.created_at, t.id LIMIT 1`,
			pq.QuoteLiteral(syncPeerKey(peer, kind)), vmSideAsset)
	default:
		return uuid.Nil, false, nil
	}
	var id uuid.UUID
	err := shareddb.WithTenantTx(ctx, raw, tenant, func(tx *sql.Tx) error {
		return tx.QueryRowContext(ctx, q, tenant, value).Scan(&id)
	})
	if errors.Is(err, sql.ErrNoRows) {
		return uuid.Nil, false, nil
	}
	return id, err == nil, err
}
