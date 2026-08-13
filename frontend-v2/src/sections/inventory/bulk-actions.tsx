// Inventory bulk / stale write actions — restores the parity surface the rebuild
// dropped (old web-ui had a bulk/stale action menu). All wired through the typed
// inventory-service client. The page has NO row-selection model (rows are
// click-to-open-drawer), so:
//   • the STALE lens gets per-row Rescan / Archive plus a header bar that
//     Revalidates / Archives the whole current page of stale assets;
//   • Delete (soft) and Restore live on the ASSET DRAWER, where a single asset
//     is already in focus (see drawers.tsx).
// Approve / Deny are intentionally NOT here — that bulk surface already exists
// in Discovery → Approvals (approvals-page.tsx); duplicating it would split the
// pending-asset workflow across two pages.
//
// Endpoint bodies (verified against api/openapi/inventory-service.openapi.yaml +
// the generated client): the three bulk actions all take AssetIdsRequest
// (`{ asset_ids: string[] }`); restore is POST /{id}/restore (no body); delete
// is DELETE /{id} (204, no body).
import { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { clients } from '../../lib/clients';
import { Icon, Modal } from '../../components/ui';

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

// ---- bulk stale actions over a set of asset ids --------------------------
// rescan + revalidate share the AssetIdsRequest body and return a job; archive
// returns a count. One mutation keyed by `kind` keeps the call sites tiny.
type BulkKind = 'rescan' | 'archive' | 'revalidate';
const BULK_PATH: Record<BulkKind, '/infrastructure-assets/stale/rescan' | '/infrastructure-assets/stale/archive' | '/infrastructure-assets/revalidate'> = {
  rescan: '/infrastructure-assets/stale/rescan',
  archive: '/infrastructure-assets/stale/archive',
  revalidate: '/infrastructure-assets/revalidate',
};

function useBulkStaleAction() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ kind, ids }: { kind: BulkKind; ids: string[] }) => {
      const { data, error } = await clients.inventory.POST(BULK_PATH[kind], { body: { asset_ids: ids } });
      if (error || !data) throw new Error(`Failed to ${kind} asset${ids.length === 1 ? '' : 's'}`);
      return data;
    },
    onSettled: () => invalidateInventory(qc),
  });
}

// ---- per-row actions on a stale asset ------------------------------------
// Rescan (queues a revalidation job) and Archive (sets lifecycle → archived).
// Both gated assets.update. `stopPropagation` so clicking an action doesn't
// also open the asset drawer (the row's own onClick).
export function StaleRowActions({ assetId }: { assetId: string }) {
  const bulk = useBulkStaleAction();
  const pending = bulk.isPending && (bulk.variables?.ids?.includes(assetId) ?? false);
  const run = (kind: BulkKind, e: React.MouseEvent) => {
    e.stopPropagation();
    bulk.mutate({ kind, ids: [assetId] });
  };
  return (
    <PermissionGate permission={TENANT_PERMISSIONS.assets.update}>
      <div style={{ display: 'flex', gap: 6, justifySelf: 'end' }} onClick={(e) => e.stopPropagation()}>
        <button className="ui-btn sm ghost" title="Rescan — queue a revalidation job for this asset" disabled={pending} onClick={(e) => run('rescan', e)} style={{ height: 26, padding: '0 8px' }}>
          <Icon name="radar" size={13} />
        </button>
        <button className="ui-btn sm ghost" title="Archive — set lifecycle to archived" disabled={pending} onClick={(e) => run('archive', e)} style={{ height: 26, padding: '0 8px', color: 'var(--warn)' }}>
          <Icon name="archive" size={13} />
        </button>
      </div>
    </PermissionGate>
  );
}

// ---- header bar for the stale lens ---------------------------------------
// Acts on the whole CURRENT PAGE of stale assets (the table has no multi-select).
// Revalidate queues jobs; Archive bulk-archives. Gated assets.update.
export function StaleBulkBar({ assetIds }: { assetIds: string[] }) {
  const bulk = useBulkStaleAction();
  const [confirmArchive, setConfirmArchive] = useState(false);
  const n = assetIds.length;
  if (n === 0) return null;
  const busy = bulk.isPending;

  const archiveAll = () => {
    bulk.mutate({ kind: 'archive', ids: assetIds }, { onSettled: () => setConfirmArchive(false) });
  };

  return (
    <PermissionGate permission={TENANT_PERMISSIONS.assets.update}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 9, padding: '8px 16px', borderBottom: '1px solid var(--app-border)', background: 'var(--app-panel2)' }}>
        <Icon name="clock-alert" size={14} style={{ color: 'var(--warn-strong)' }} />
        <span style={{ fontSize: 12, color: 'var(--app-t3)' }}>{n} stale asset{n === 1 ? '' : 's'} on this page</span>
        <div style={{ flex: 1 }} />
        <button className="ui-btn sm" title="Queue a revalidation job for every stale asset on this page" disabled={busy} onClick={() => bulk.mutate({ kind: 'revalidate', ids: assetIds })} style={{ height: 28, padding: '0 10px', fontSize: 12 }}>
          <Icon name="radar" size={13} />{busy && bulk.variables?.kind === 'revalidate' ? 'Revalidating…' : 'Revalidate all'}
        </button>
        <button className="ui-btn sm" title="Archive every stale asset on this page" disabled={busy} onClick={() => setConfirmArchive(true)} style={{ height: 28, padding: '0 10px', fontSize: 12, color: 'var(--warn)' }}>
          <Icon name="archive" size={13} />Archive all
        </button>
      </div>
      <Modal
        open={confirmArchive}
        onClose={busy ? undefined : () => setConfirmArchive(false)}
        dismissible={!busy}
        size="sm"
        tone="danger"
        icon="archive"
        eyebrow="Inventory"
        title={`Archive ${n} stale asset${n === 1 ? '' : 's'}?`}
        description="Archived assets drop out of active inventory and reporting. Discovery can resurface them; you can restore individually from the asset drawer."
        primary={<button className="ui-btn" style={{ background: 'var(--warn)', color: 'var(--accent-fg)', fontWeight: 600 }} disabled={busy} onClick={archiveAll}>{busy ? 'Archiving…' : `Archive ${n}`}</button>}
        secondary={<button className="ui-btn" disabled={busy} onClick={() => setConfirmArchive(false)}>Cancel</button>}
        footerNote={bulk.isError ? <span style={{ color: 'var(--danger-text)' }}>{(bulk.error as Error).message}</span> : undefined}
      />
    </PermissionGate>
  );
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

// ---- asset drawer: Active Scan (on-demand crypto scan) -------------------
// POST /infrastructure-assets/scan { asset_ids:[id] } (). Approves the
// asset and dispatches an active TLS probe whose results flow back through the
// discovery pipeline to catalog its certificates + cipher configs. Gated
// assets.update.
export function ScanAssetButton({ assetId }: { assetId: string }) {
  const qc = useQueryClient();
  const scan = useMutation({
    mutationFn: async () => {
      const { data, error } = await clients.inventory.POST('/infrastructure-assets/scan', { body: { asset_ids: [assetId] } });
      if (error || !data) throw new Error('Failed to start active scan');
      return data;
    },
    // The scan is dispatched asynchronously (a job the discovery pipeline picks
    // up), so the drawer has nothing to re-render on success — without a toast
    // the click looked like a no-op. Mirrors Discovery → Active Scan.
    onSuccess: () => toast.success('Active scan started — results appear once the probe completes'),
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Failed to start active scan'),
    onSettled: () => invalidateInventory(qc, assetId),
  });
  return (
    <PermissionGate permission={TENANT_PERMISSIONS.assets.update}>
      <button className="ui-btn sm" title="Active Scan — probe this asset now and catalog its TLS crypto" disabled={scan.isPending} onClick={() => scan.mutate()} style={{ height: 28, padding: '0 9px' }}>
        <Icon name="radar" size={13} />{scan.isPending ? 'Scanning…' : 'Active Scan'}
      </button>
    </PermissionGate>
  );
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
