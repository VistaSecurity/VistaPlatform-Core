// Per-asset write actions on the asset drawer and the full asset page: soft
// delete, restore, and the Active Scan button. All wired through the typed
// inventory-service client.
//
// Acting on MANY assets — scan, archive, restore, delete, edit, export — is the
// bulk action bar on Inventory → All assets and Stale (bulk-action-bar.tsx,
//), which replaced the Stale lens's old whole-page bar and per-row
// buttons. Approve / Deny stay in Discovery → Approvals (approvals-page.tsx).
//
// Endpoint bodies (verified against api/openapi/inventory-service.openapi.yaml +
// the generated client): restore is POST /{id}/restore (no body); delete is
// DELETE /{id} (204, no body).
import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { clients } from '../../lib/clients';
import { Icon, Modal } from '../../components/ui';
import { activeScanView, type ActiveScanView, type AssetActiveScan } from '../discovery/active-scan-row-state';
import { ScanDialog } from './scan-dialog';

// All inventory list/detail query keys are rooted at ['inventory'] (see
// useAssets/useConfigs/useConnections); detail + child-config keys are by id.
// Invalidate broadly so a stale-action result is reflected everywhere.
function invalidateInventory(qc: ReturnType<typeof useQueryClient>, assetId?: string) {
  qc.invalidateQueries({ queryKey: ['inventory'] });
  if (assetId) {
    qc.invalidateQueries({ queryKey: ['asset-detail', assetId] });
    qc.invalidateQueries({ queryKey: ['asset-configs', assetId] });
  }
}

// ---- asset drawer: soft-delete (danger confirm) --------------------------
// DELETE /infrastructure-assets/{id} → 204. Gated assets.delete. `onDone`
// lets the drawer close itself after a successful delete.
export function DeleteAssetButton({ assetId, hostname, onDone }: { assetId: string; hostname?: string; onDone?: () => void }) {
  const qc = useQueryClient();
  const [confirm, setConfirm] = useState(false);
  const del = useMutation({
    mutationFn: async () => {
      const { error } = await clients.inventory.DELETE('/infrastructure-assets/{id}', { params: { path: { id: assetId } } });
      // 204 No Content → openapi-fetch yields no `data`; only treat a real error as failure.
      if (error) throw new Error('Failed to delete asset');
      return true;
    },
    onSuccess: () => {
      invalidateInventory(qc, assetId);
      setConfirm(false);
      onDone?.();
    },
  });
  return (
    <PermissionGate permission={TENANT_PERMISSIONS.assets.delete}>
      <button className="ui-btn sm ghost" title="Delete asset" onClick={() => setConfirm(true)} style={{ height: 28, padding: '0 9px', color: 'var(--danger-text)' }}>
        <Icon name="x-circle" size={13} />Delete
      </button>
      <Modal
        open={confirm}
        onClose={del.isPending ? undefined : () => setConfirm(false)}
        dismissible={!del.isPending}
        size="sm"
        tone="danger"
        icon="x-circle"
        eyebrow="Inventory"
        title="Delete this asset?"
        description={`${hostname || 'This asset'} will be soft-deleted and removed from active inventory. It can be restored later.`}
        primary={<button className="ui-btn" style={{ background: 'var(--danger)', color: '#1a0707', fontWeight: 600 }} disabled={del.isPending} onClick={() => del.mutate()}>{del.isPending ? 'Deleting…' : 'Delete asset'}</button>}
        secondary={<button className="ui-btn" disabled={del.isPending} onClick={() => setConfirm(false)}>Cancel</button>}
        footerNote={del.isError ? <span style={{ color: 'var(--danger-text)' }}>{(del.error as Error).message}</span> : undefined}
      />
    </PermissionGate>
  );
}

// ---- asset drawer / asset page: Active Scan ------------------------------
// Opens the Active Scan dialog for this one asset: the same dialog the
// Inventory bulk bar opens, so a single scan also gets the "Run from" choice
// and the outside-your-networks question. Gated assets.update.
// `activeScan` is the asset's own scan record (AssetActiveScan, from the asset
// read): while it says `scanning` the button is disabled and says so, and
// afterwards its tooltip says how the last scan ended. The drawer and the page
// poll the asset while the scan runs, so the button changes when it finishes.
export function ScanAssetButton({ assetId, activeScan }: { assetId: string; activeScan?: AssetActiveScan | null }) {
  const view = activeScanView({ active_scan: activeScan });
  const [open, setOpen] = useState(false);
  const running = view.kind === 'scanning';
  return (
    <PermissionGate permission={TENANT_PERMISSIONS.assets.update}>
      <button className="ui-btn sm" title={scanButtonTitle(view)} disabled={running} onClick={() => setOpen(true)} style={{ height: 28, padding: '0 9px' }}>
        <Icon name="radar" size={13} />{running ? 'Scanning…' : 'Active Scan'}
      </button>
      {open && <ScanDialog open selection={{ kind: 'ids', ids: new Set([assetId]) }} onClose={() => setOpen(false)} />}
    </PermissionGate>
  );
}

/** The Active Scan button's tooltip: what it does, and how the last scan went. */
export function scanButtonTitle(view: ActiveScanView, now = Date.now()): string {
  const base = 'Active Scan — probe this asset now and catalog its TLS crypto';
  const ago = (iso?: string) => {
    if (!iso) return '';
    const mins = Math.max(0, Math.round((now - new Date(iso).getTime()) / 60_000));
    return mins < 1 ? ' just now' : mins < 60 ? ` ${mins}m ago` : mins < 1440 ? ` ${Math.round(mins / 60)}h ago` : ` ${Math.round(mins / 1440)}d ago`;
  };
  switch (view.kind) {
    case 'scanning':
      return `A scan of this asset is running (started${ago(view.since)}); results appear once it finishes`;
    case 'completed':
      return `${base}. Last scan finished${ago(view.at)}.`;
    case 'failed':
      return `${base}. Last scan failed${ago(view.at)}: it did not reach this asset.`;
    default:
      return base;
  }
}

// ---- asset drawer: restore a soft-deleted / archived asset ---------------
// POST /infrastructure-assets/{id}/restore (no body) → restored asset. Gated
// assets.update.
export function RestoreAssetButton({ assetId, onDone }: { assetId: string; onDone?: () => void }) {
  const qc = useQueryClient();
  const restore = useMutation({
    mutationFn: async () => {
      const { data, error } = await clients.inventory.POST('/infrastructure-assets/{id}/restore', { params: { path: { id: assetId } } });
      if (error || !data) throw new Error('Failed to restore asset');
      return data.asset;
    },
    onSuccess: () => {
      invalidateInventory(qc, assetId);
      onDone?.();
    },
  });
  return (
    <PermissionGate permission={TENANT_PERMISSIONS.assets.update}>
      <button className="ui-btn sm" title="Restore this asset to active inventory" disabled={restore.isPending} onClick={() => restore.mutate()} style={{ height: 28, padding: '0 9px' }}>
        <Icon name="recycle" size={13} />{restore.isPending ? 'Restoring…' : 'Restore'}
      </button>
    </PermissionGate>
  );
}
