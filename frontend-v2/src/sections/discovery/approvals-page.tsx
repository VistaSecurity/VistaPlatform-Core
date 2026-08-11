import { useMutation, useQueryClient } from '@tanstack/react-query';
import toast from 'react-hot-toast';
import { PermissionGate, TENANT_PERMISSIONS } from '@vistasecurity/primitives/rbac';
import { clients } from '../../lib/clients';
import { Icon, MiniBar } from '../../components/ui';
import { DTable, CellMono, CellTxt, PageWrap, queryNote, relTime } from './kit';
import { usePendingAssets } from './queries';

// Discovery → Approvals — the mock's `discovery-approvals` view: the hinge
// between Discovery and Inventory. Pending-approval assets with per-row
// accept/reject and bulk accept, driving the live bulk approve/deny endpoints.

const COLS = [
  { label: 'Discovered asset', w: '1.4fr' },
  { label: 'IP', w: '1fr' },
  { label: 'Type', w: '1fr' },
  { label: 'Segment', w: '1fr' },
  { label: 'Confidence', w: '110px' },
  { label: 'Found', w: '100px' },
  { label: '', w: '150px', align: 'right' as const },
];

export function ApprovalsPage() {
  const q = usePendingAssets();
  const qc = useQueryClient();
  const assets = q.data ?? [];

  const decide = useMutation({
    mutationFn: async ({ ids, approve }: { ids: string[]; approve: boolean }) => {
      const path = approve ? '/infrastructure-assets/approve' : '/infrastructure-assets/deny';
      const { data, error } = await clients.inventory.POST(path, { body: { asset_ids: ids } });
      if (error || !data) throw new Error(`Failed to ${approve ? 'approve' : 'deny'} asset${ids.length === 1 ? '' : 's'}`);
      return { ...data, approve };
    },
    onSuccess: (r) => toast.success(`${r.count ?? ''} asset${(r.count ?? 2) === 1 ? '' : 's'} ${r.approve ? 'approved' : 'denied'}`),
    onError: (e) => toast.error(e instanceof Error ? e.message : 'Request failed'),
    onSettled: () => {
      qc.invalidateQueries({ queryKey: ['discovery', 'pending-assets'] });
      qc.invalidateQueries({ queryKey: ['inventory'] });
    },
  });

  const note = queryNote(q, assets.length === 0, {
    thing: 'pending assets',
    emptyTitle: 'Nothing awaiting approval',
    emptyMessage: 'Newly discovered assets land here for review when auto-approval is off.',
  });

  return (
    <PageWrap title="Approvals" count={q.isLoading ? '' : assets.length}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14 }}>
        <p style={{ margin: 0, fontSize: 13, color: 'var(--app-t3)' }}>
          The hinge between Discovery and Inventory — accept or reject newly discovered assets.
        </p>
        <div style={{ flex: 1 }} />
        {assets.length > 0 && (
          <PermissionGate permission={TENANT_PERMISSIONS.assets.update}>
            <button className="ui-btn sm" disabled={decide.isPending} onClick={() => decide.mutate({ ids: assets.map((a) => a.id), approve: true })}>
              <Icon name="check-check" />Accept all
            </button>
          </PermissionGate>
        )}
      </div>

      {note ?? (
        <DTable
          cols={COLS}
          rows={assets}
          rowKey={(a) => a.id}
          render={(a) => {
            const conf = typeof a.confidence_score === 'number' ? Math.round(a.confidence_score <= 1 ? a.confidence_score * 100 : a.confidence_score) : null;
            return (
              <>
                <CellMono v={a.hostname} />
                <CellMono v={a.ip_address} c="var(--app-t3)" />
                <CellTxt v={a.asset_type} />
                <CellTxt v={a.network_segment_name || a.business_unit} />
                {conf != null ? (
                  <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
                    <div style={{ width: 40 }}><MiniBar pct={conf} color={conf >= 70 ? 'var(--ok)' : 'var(--warn)'} /></div>
                    <span className="mono" style={{ fontSize: 11, color: 'var(--app-t3)' }}>{conf}%</span>
                  </div>
                ) : (
                  <CellTxt v="—" c="var(--app-t3)" />
                )}
                <CellTxt v={relTime(a.first_discovered_at || a.created_at)} c="var(--app-t3)" />
                <span style={{ textAlign: 'right', display: 'inline-flex', gap: 6, justifyContent: 'flex-end' }}>
                  <PermissionGate permission={TENANT_PERMISSIONS.assets.update} fallback={<span style={{ fontSize: 11, color: 'var(--app-t3)' }}>—</span>}>
                    <button className="ui-btn sm accent" disabled={decide.isPending} onClick={() => decide.mutate({ ids: [a.id], approve: true })}>
                      <Icon name="check" />Accept
                    </button>
                    <button className="ui-btn sm ghost" title="Reject (suppresses rediscovery)" disabled={decide.isPending} onClick={() => decide.mutate({ ids: [a.id], approve: false })}>
                      <Icon name="x" />
                    </button>
                  </PermissionGate>
                </span>
              </>
            );
          }}
        />
      )}
    </PageWrap>
  );
}
