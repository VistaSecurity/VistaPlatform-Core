import { useMutation, useQueryClient } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { clients } from '../../lib/clients';
import { Icon } from '../../components/ui';
import { DTable, CellMono, CellTxt, PageWrap, queryNote, relTime } from './kit';
import { useUnscannedAssets } from './queries';

// Discovery → Active Scan () — coverage surface for the active inventory:
// monitoring assets that have never been actively scanned. Run a TLS probe per asset (or
// all at once); the scan approves + dispatches, and results flow back through the discovery
// pipeline to catalog/verify their crypto. Pending assets are handled in Approvals;
// just-imported assets get a scan prompt in the import wizard.

const COLS = [
  { label: 'Asset', w: '1.4fr' },
  { label: 'IP', w: '1fr' },
  { label: 'Type', w: '1fr' },
  { label: 'Segment', w: '1fr' },
  { label: 'Status', w: '120px' },
  { label: 'Last seen', w: '100px' },
  { label: '', w: '120px', align: 'right' as const },
];

export function ActiveScanPage() {
  const q = useUnscannedAssets();
  const qc = useQueryClient();
  const assets = q.data ?? [];

  const scan = useMutation({
    mutationFn: async (ids: string[]) => {
      const { data, error } = await clients.inventory.POST('/infrastructure-assets/scan', { body: { asset_ids: ids } });
      if (error || !data) throw new Error(`Failed to scan asset${ids.length === 1 ? '' : 's'}`);
      return data;
    },
    onSuccess: (r) => toast.success(`Active scan started for ${r.count ?? ''} asset${(r.count ?? 2) === 1 ? '' : 's'}`),
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Scan failed'),
    onSettled: () => {
      qc.invalidateQueries({ queryKey: ['discovery', 'unscanned-assets'] });
      qc.invalidateQueries({ queryKey: ['inventory'] });
    },
  });

  const note = queryNote(q, assets.length === 0, {
    thing: 'unscanned assets',
    emptyTitle: 'Everything has been scanned',
    emptyMessage: 'Every active asset has been actively scanned at least once. New or imported assets appear here until you scan them.',
  });

  return (
    <PageWrap title="Active Scan" count={q.isLoading ? '' : assets.length}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14 }}>
        <p style={{ margin: 0, fontSize: 13, color: 'var(--app-t3)' }}>
          Assets that have never been actively scanned. Run a TLS probe to catalog and verify their cryptography — results flow back through discovery.
        </p>
        <div style={{ flex: 1 }} />
        {assets.length > 0 && (
          <PermissionGate permission={TENANT_PERMISSIONS.assets.update}>
            <button className="ui-btn sm accent" disabled={scan.isPending} onClick={() => scan.mutate(assets.map((a) => a.id))}>
              <Icon name="radar" />{scan.isPending ? 'Scanning…' : `Scan all (${assets.length})`}
            </button>
          </PermissionGate>
        )}
      </div>

      {note ?? (
        <DTable
          cols={COLS}
          rows={assets}
          rowKey={(a) => a.id}
          render={(a) => (
            <>
              <CellMono v={a.hostname} />
              <CellMono v={a.ip_address} c="var(--app-t3)" />
              <CellTxt v={a.asset_type} />
              <CellTxt v={a.network_segment_name || a.business_unit} />
              <CellTxt v={a.asset_status} />
              <CellTxt v={relTime(a.last_seen_at)} c="var(--app-t3)" />
              <span style={{ textAlign: 'right', display: 'inline-flex', gap: 6, justifyContent: 'flex-end' }}>
                <PermissionGate permission={TENANT_PERMISSIONS.assets.update} fallback={<span style={{ fontSize: 11, color: 'var(--app-t3)' }}>—</span>}>
                  <button className="ui-btn sm" disabled={scan.isPending} onClick={() => scan.mutate([a.id])}>
                    <Icon name="radar" />Scan
                  </button>
                </PermissionGate>
              </span>
            </>
          )}
        />
      )}
    </PageWrap>
  );
}
